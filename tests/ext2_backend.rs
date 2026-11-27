//! 在宿主机上用真实 Ext2 镜像验证后端读写和元数据持久性。

extern crate alloc;

#[path = "../kernel/src/fs/ext2/mod.rs"]
mod ext2;

use ext2::{Device, Error, Result, Volume, ROOT_INODE};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

struct Image {
    file: File,
    len: u64,
    fail_write: Option<usize>,
}

impl Image {
    fn open(path: &Path) -> Self {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let len = file.metadata().unwrap().len();
        Self {
            file,
            len,
            fail_write: None,
        }
    }
}

impl Device for Image {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<()> {
        if !matches!(offset.checked_add(dst.len() as u64), Some(end) if end <= self.len) {
            return Err(Error::Range);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| Error::Io)?;
        self.file.read_exact(dst).map_err(|_| Error::Io)
    }

    fn write_at(&mut self, offset: u64, src: &[u8]) -> Result<()> {
        if !matches!(offset.checked_add(src.len() as u64), Some(end) if end <= self.len) {
            return Err(Error::Range);
        }
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| Error::Io)?;
        self.file.write_all(src).map_err(|_| Error::Io)?;
        if let Some(remaining) = self.fail_write.as_mut() {
            *remaining -= 1;
            if *remaining == 0 {
                self.fail_write = None;
                return Err(Error::Io);
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.file.sync_all().map_err(|_| Error::Io)
    }
}

fn check_existing(volume: &mut Volume<Image>, expected: &[u8]) {
    let mut found = false;
    volume
        .read_dir(ROOT_INODE, 0, |entry| {
            found |= entry.name == b"fixture";
            true
        })
        .unwrap();
    assert!(found, "根目录应列出 fixture");
    let ino = volume.lookup(ROOT_INODE, b"fixture").unwrap();
    let mut data = vec![0; expected.len() + 1];
    assert_eq!(volume.read(ino, 0, &mut data).unwrap(), expected.len());
    assert_eq!(&data[..expected.len()], expected);
    assert_eq!(
        volume.read(ino, expected.len() as u64, &mut data).unwrap(),
        0
    );
}

fn check_write_rollback(path: &Path, now: u32) {
    let mut volume = Volume::open(Image::open(path), false).unwrap();
    let ino = volume
        .create(ROOT_INODE, b"rollback", 0o644, (0, 0), now)
        .unwrap();
    volume.write_file(ino, 0, b"before", now).unwrap();
    let free = volume.statfs().unwrap().blocks_free;
    volume.sync().unwrap();
    drop(volume);

    let mut faulty = Image::open(path);
    faulty.fail_write = Some(2);
    let mut volume = Volume::open(faulty, false).unwrap();
    assert_eq!(
        volume.write_file(ino, 0, &[0x41; 1700], now),
        Err(Error::Io)
    );
    assert_eq!(volume.statfs().unwrap().blocks_free, free);
    assert_eq!(volume.metadata(ino).unwrap().size, 6);
    let mut data = [0; 6];
    assert_eq!(volume.read(ino, 0, &mut data).unwrap(), 6);
    assert_eq!(&data, b"before");
    volume.unlink(ROOT_INODE, b"rollback", now).unwrap();
    volume.sync().unwrap();
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let image = args.next().expect("需要 Ext2 镜像路径");
    let fixture = args.next().expect("需要原始 fixture 文件路径");
    let path = Path::new(&image);
    let expected = std::fs::read(fixture).unwrap();
    let now = 1_700_000_000;

    let mut volume = Volume::open(Image::open(path), false).unwrap();
    check_existing(&mut volume, &expected);
    let ino = volume
        .create(ROOT_INODE, b"new", 0o644, (1000, 1001), now)
        .unwrap();
    let data = [0x4a; 1600];
    assert_eq!(volume.write_file(ino, 900, &data, now).unwrap(), data.len());
    assert_eq!(volume.metadata(ino).unwrap().size, 2500);
    volume.link(ROOT_INODE, ino, b"alias", now).unwrap();
    assert_eq!(volume.metadata(ino).unwrap().links, 2);
    volume.unlink(ROOT_INODE, b"new", now).unwrap();
    assert_eq!(volume.lookup(ROOT_INODE, b"alias").unwrap(), ino);
    assert_eq!(volume.lookup(ROOT_INODE, b"new"), Err(Error::NotFound));
    volume.set_readonly().unwrap();
    assert_eq!(volume.write_file(ino, 0, b"x", now), Err(Error::ReadOnly));
    drop(volume);

    let mut volume = Volume::open(Image::open(path), false).unwrap();
    let ino = volume.lookup(ROOT_INODE, b"alias").unwrap();
    let info = volume.metadata(ino).unwrap();
    assert_eq!(
        (info.mode, info.uid, info.gid, info.links),
        (0o100644, 1000, 1001, 1)
    );
    let mut content = [0xff; 2500];
    assert_eq!(volume.read(ino, 0, &mut content).unwrap(), content.len());
    assert_eq!(content[..900], [0; 900]);
    assert_eq!(content[900..], data);
    volume.unlink(ROOT_INODE, b"alias", now).unwrap();
    assert_eq!(volume.lookup(ROOT_INODE, b"alias"), Err(Error::NotFound));
    volume.sync().unwrap();
    check_existing(&mut volume, &expected);
    drop(volume);
    check_write_rollback(path, now);
    println!("Ext2 后端回归通过");
}
