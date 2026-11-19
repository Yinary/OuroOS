//! 宿主端重命名故障注入；通过 fs_rename_backend.py 构造镜像并执行。
use rsext4::{
    bmalloc::AbsoluteBN, BlockDevice, Ext4Error, Ext4Result, Ext4Timestamp, Jbd2Dev, MountOptions,
};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    sync::{
        atomic::{AtomicIsize, Ordering},
        Arc,
    },
};
struct Disk {
    file: std::fs::File,
    blocks: u64,
    clock: Arc<AtomicIsize>,
}
impl BlockDevice for Disk {
    fn read(&mut self, out: &mut [u8], block: AbsoluteBN, count: u32) -> Ext4Result<()> {
        self.file
            .seek(SeekFrom::Start(block.raw() * 4096))
            .map_err(|_| Ext4Error::io())?;
        self.file
            .read_exact(&mut out[..count as usize * 4096])
            .map_err(|_| Ext4Error::io())
    }
    fn write(&mut self, data: &[u8], block: AbsoluteBN, count: u32) -> Ext4Result<()> {
        self.file
            .seek(SeekFrom::Start(block.raw() * 4096))
            .map_err(|_| Ext4Error::io())?;
        self.file
            .write_all(&data[..count as usize * 4096])
            .map_err(|_| Ext4Error::io())
    }
    fn open(&mut self) -> Ext4Result<()> {
        Ok(())
    }
    fn close(&mut self) -> Ext4Result<()> {
        Ok(())
    }
    fn total_blocks(&self) -> u64 {
        self.blocks
    }
    fn block_size(&self) -> u32 {
        4096
    }
    fn current_time(&self) -> Ext4Result<Ext4Timestamp> {
        let n = self.clock.load(Ordering::Relaxed);
        if n >= 0 {
            self.clock.store(n - 1, Ordering::Relaxed);
            if n == 0 {
                return Err(Ext4Error::io());
            }
        }
        Ok(Ext4Timestamp::new(1700000000, 0))
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let path = &args[1];
    let fault: isize = args[2].parse().unwrap();
    let directory = args[3] == "dir";
    let missing = matches!(args[3].as_str(), "missing" | "growth");
    let growth = args[3] == "growth";
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let blocks = file.metadata().unwrap().len() / 4096;
    let clock = Arc::new(AtomicIsize::new(-1));
    let mut dev = Jbd2Dev::initial_jbd2dev(
        0,
        Disk {
            file,
            blocks,
            clock: clock.clone(),
        },
        false,
    );
    let mut fs = rsext4::mount_with_options(
        &mut dev,
        MountOptions {
            readonly: false,
            replay_journal: false,
        },
    )
    .unwrap();
    let (old_path, new_path) = if directory {
        ("/p/moving", "/q/target")
    } else if growth {
        ("/a", "/full/new-name-long-enough-to-grow")
    } else if missing {
        ("/a", "/new-name")
    } else {
        ("/a", "/b")
    };
    let lookup = |fs: &mut rsext4::Ext4FileSystem, dev: &mut Jbd2Dev<Disk>, path| {
        rsext4::loopfile::get_file_inode(fs, dev, path)
            .unwrap()
            .unwrap()
    };
    let (source, source_before) = lookup(&mut fs, &mut dev, old_path);
    let target_before = if missing {
        None
    } else {
        Some(lookup(&mut fs, &mut dev, new_path))
    };
    let (old, new, name, dest) = if directory {
        (
            lookup(&mut fs, &mut dev, "/p").0,
            lookup(&mut fs, &mut dev, "/q").0,
            "moving",
            "target",
        )
    } else if growth {
        (
            fs.root_inode,
            lookup(&mut fs, &mut dev, "/full").0,
            "a",
            "new-name-long-enough-to-grow",
        )
    } else if missing {
        (fs.root_inode, fs.root_inode, "a", "new-name")
    } else {
        (fs.root_inode, fs.root_inode, "a", "b")
    };
    let parents_before = [
        fs.get_inode_by_num(&mut dev, old).unwrap().i_links_count,
        fs.get_inode_by_num(&mut dev, new).unwrap().i_links_count,
    ];
    clock.store(fault, Ordering::Relaxed);
    let result = rsext4::file::rename_entry(&mut fs, &mut dev, old, name, new, dest, false);
    assert_eq!(clock.load(Ordering::Relaxed), -1, "故障点未触发");
    assert_eq!(result.unwrap_err().code, rsext4::Errno::EIO);
    let (ino, inode) = lookup(&mut fs, &mut dev, old_path);
    assert_eq!(ino, source);
    assert_eq!(inode.i_links_count, source_before.i_links_count);
    if let Some((target, before)) = target_before {
        let (ino, inode) = lookup(&mut fs, &mut dev, new_path);
        assert_eq!(ino, target);
        assert_eq!(inode.i_links_count, before.i_links_count);
    } else {
        assert!(
            rsext4::loopfile::get_file_inode(&mut fs, &mut dev, new_path)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!(
        parents_before,
        [
            fs.get_inode_by_num(&mut dev, old).unwrap().i_links_count,
            fs.get_inode_by_num(&mut dev, new).unwrap().i_links_count
        ]
    );
    if directory {
        assert_eq!(lookup(&mut fs, &mut dev, "/p/moving/..").0, old);
        assert_eq!(lookup(&mut fs, &mut dev, "/q/target/..").0, new);
    }
    fs.umount(&mut dev).unwrap();
    println!(
        "RENAME ROLLBACK PASS: {} at metadata update {}",
        args[3], fault
    );
}
