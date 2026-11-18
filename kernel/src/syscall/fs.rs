//! 文件系统调用的参数检查、用户缓冲区访问与 Linux 返回结构编码。
//! FD、文件偏移和管道状态由 fs::context 管理。
#![deny(unsafe_code)]

use super::{sysnr, Errno};
use crate::{
    fs::{
        self,
        context::{parent, Context},
    },
    mm::{address_space::UserAddressSpace, user_access},
};
use alloc::{string::String, vec::Vec};

/// 从用户内存读取 NUL 结尾 UTF-8 字符串；不可访问或过长时返回错误。
pub(crate) fn user_string(space: &UserAddressSpace, ptr: usize) -> Result<String, Errno> {
    let mut bytes = Vec::new();
    bytes.try_reserve(4096).map_err(|_| Errno::NoMem)?;
    for n in 0..4096 {
        let mut b = [0];
        user_access::copy_from_user(space, ptr.checked_add(n).ok_or(Errno::Fault)?, &mut b)
            .map_err(|_| Errno::Fault)?;
        if b[0] == 0 {
            return String::from_utf8(bytes).map_err(|_| Errno::Invalid);
        }
        bytes.push(b[0]);
    }
    Err(Errno::NameTooLong)
}
/// Linux 文件调用，所有用户缓冲区经 user_access 复制。
pub fn dispatch(
    nr: usize,
    a: [usize; 6],
    space: &UserAddressSpace,
    ctx: &mut Context,
) -> Result<usize, Errno> {
    match nr {
        sysnr::GETCWD => {
            if a[1] < ctx.cwd().len() + 1 {
                return Err(Errno::Range);
            }
            user_access::copy_to_user(space, a[0], ctx.cwd().as_bytes())
                .map_err(|_| Errno::Fault)?;
            user_access::copy_to_user(
                space,
                a[0].checked_add(ctx.cwd().len()).ok_or(Errno::Fault)?,
                &[0],
            )
            .map_err(|_| Errno::Fault)?;
            Ok(ctx.cwd().len() + 1)
        }
        sysnr::DUP => ctx.install(ctx.get(a[0])?, false),
        sysnr::DUP3 => {
            if a[2] & !0x80000 != 0 || a[0] == a[1] {
                return Err(Errno::Invalid);
            }
            ctx.dup_to(a[0], a[1], a[2] & 0x80000 != 0)
        }
        sysnr::MKDIRAT => {
            let path = ctx.path(a[0], &user_string(space, a[1])?)?;
            match fs::lookup(&path) {
                Ok(_) => Err(Errno::Exists),
                Err(Errno::NoEntry) => {
                    let (p, name) = parent(&path)?;
                    fs::create(p, name, 0x4000 | (a[2] as u16 & 0o777))?;
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        }
        sysnr::MOUNT => {
            if a[3] != 0 {
                return Err(Errno::NotSupported);
            }
            let source = user_string(space, a[0])?;
            let target = ctx.path((-100isize) as usize, &user_string(space, a[1])?)?;
            let kind = user_string(space, a[2])?;
            if kind != "vfat" && kind != "fat" {
                return Err(Errno::NoDevice);
            }
            if fs::stat(fs::lookup(&target)?)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            fs::fat::mount(&source, &target)?;
            Ok(0)
        }
        sysnr::UMOUNT2 => {
            if a[1] != 0 {
                return Err(Errno::NotSupported);
            }
            let target = ctx.path((-100isize) as usize, &user_string(space, a[0])?)?;
            fs::fat::unmount(&target)?;
            Ok(0)
        }
        sysnr::UNLINKAT => {
            if a[2] != 0 {
                return Err(Errno::NotSupported);
            }
            let path = ctx.path(a[0], &user_string(space, a[1])?)?;
            let ino = fs::lookup(&path)?;
            let (p, name) = parent(&path)?;
            fs::unlink(p, ino, name)?;
            Ok(0)
        }
        sysnr::PIPE2 => {
            if a[1] & !(0x80000 | 0x800) != 0 {
                return Err(Errno::Invalid);
            }
            let (rfd, wfd) = ctx.pipe(a[1])?;
            let mut pair = [0; 8];
            pair[..4].copy_from_slice(&(rfd as u32).to_ne_bytes());
            pair[4..].copy_from_slice(&(wfd as u32).to_ne_bytes());
            if user_access::copy_to_user(space, a[0], &pair).is_err() {
                ctx.close(rfd)?;
                ctx.close(wfd)?;
                return Err(Errno::Fault);
            }
            Ok(0)
        }
        sysnr::GETDENTS64 => {
            let handle = ctx.get(a[0])?;
            let mut f = handle.lock();
            let ino = f.directory()?;
            let mut out = [0u8; 4096];
            let cap = a[2].min(out.len());
            let mut used = 0;
            use fs::DirEntryKind;

            let mut full = false;
            let offset = fs::read_dir(ino, f.offset(), |entry| {
                let len = (19 + entry.name.len() + 1 + 7) & !7;
                if used + len > cap {
                    full = true;
                    return false;
                }
                let d = &mut out[used..used + len];
                d[..8].copy_from_slice(&(entry.inode as u64).to_ne_bytes());
                d[8..16].copy_from_slice(&(entry.next as u64).to_ne_bytes());
                d[16..18].copy_from_slice(&(len as u16).to_ne_bytes());
                d[18] = match entry.kind {
                    DirEntryKind::Fifo => 1,
                    DirEntryKind::Character => 2,
                    DirEntryKind::Directory => 4,
                    DirEntryKind::Block => 6,
                    DirEntryKind::File => 8,
                    DirEntryKind::Symlink => 10,
                    DirEntryKind::Socket => 12,
                    DirEntryKind::Unknown => 0,
                };
                d[19..19 + entry.name.len()].copy_from_slice(entry.name);
                used += len;
                true
            })?;
            if full && used == 0 {
                return Err(Errno::Invalid);
            }
            user_access::copy_to_user(space, a[1], &out[..used]).map_err(|_| Errno::Fault)?;
            f.set_offset(offset);
            Ok(used)
        }
        sysnr::CHDIR => {
            let path = ctx.path((-100isize) as usize, &user_string(space, a[0])?)?;
            if fs::stat(fs::lookup(&path)?)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            ctx.set_cwd(path);
            Ok(0)
        }
        sysnr::OPENAT => {
            if a[2] & 3 == 3 {
                return Err(Errno::Invalid);
            }
            if a[2] & 0x10000 != 0 && a[2] & 64 != 0 {
                return Err(Errno::Invalid);
            }
            let path = ctx.path(a[0], &user_string(space, a[1])?)?;
            let ino = match fs::lookup(&path) {
                Ok(ino) => {
                    if a[2] & 0xc0 == 0xc0 {
                        return Err(Errno::Exists);
                    }
                    ino
                }
                Err(Errno::NoEntry) if a[2] & 64 != 0 => {
                    let (p, name) = parent(&path)?;
                    fs::create(p, name, 0x8000 | (a[3] as u16 & 0o777))?
                }
                Err(e) => return Err(e),
            };
            let mode = fs::stat(ino)?.0;
            if a[2] & 0x10000 != 0 && mode & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            if mode & 0xf000 == 0x4000 && a[2] & 3 != 0 {
                return Err(Errno::IsDir);
            }
            if a[2] & 0x200 != 0 && a[2] & 3 != 0 {
                fs::truncate(ino)?;
            }
            ctx.open_inode(ino, path, a[2], a[2] & 0x80000 != 0)
        }
        #[cfg(not(feature = "rsext4-readonly"))]
        sysnr::FSYNC => {
            let handle = ctx.get(a[0])?;
            let ino = handle.lock().inode()?;
            fs::sync_inode(ino)?;
            Ok(0)
        }
        sysnr::CLOSE => {
            ctx.close(a[0])?;
            Ok(0)
        }
        sysnr::LSEEK => {
            let handle = ctx.get(a[0])?;
            let result = handle.lock().seek(a[1] as isize, a[2]);
            result
        }
        sysnr::READ | sysnr::WRITE => rw(nr, a, space, ctx),
        sysnr::STATX => {
            let path = user_string(space, a[1])?;
            if a[2] & !(0x1000 | 0x100 | 0x800 | 0x6000) != 0 {
                return Err(Errno::Invalid);
            }
            let (ino, mode, size, links, blocks) = if path.is_empty() && a[2] & 0x1000 != 0 {
                let handle = ctx.get(a[0])?;
                let f = handle.lock();
                f.metadata()?
            } else {
                let ino = fs::lookup(&ctx.path(a[0], &path)?)?;
                let (m, s, l, b) = fs::stat(ino)?;
                (ino as u64, m, s, l, b)
            };
            let mut data = [0u8; 256];
            data[0..4].copy_from_slice(&0x307u32.to_ne_bytes());
            data[4..8].copy_from_slice(&4096u32.to_ne_bytes());
            data[16..20].copy_from_slice(&(links as u32).to_ne_bytes());
            data[28..30].copy_from_slice(&mode.to_ne_bytes());
            data[32..40].copy_from_slice(&ino.to_ne_bytes());
            data[40..48].copy_from_slice(&size.to_ne_bytes());
            data[48..56].copy_from_slice(&blocks.to_ne_bytes());
            user_access::copy_to_user(space, a[4], &data).map_err(|_| Errno::Fault)?;
            Ok(0)
        }
        sysnr::FSTAT => {
            let handle = ctx.get(a[0])?;
            let f = handle.lock();
            let (ino, mode, size, links, blocks) = f.metadata()?;
            let mut data = [0u8; 128];
            data[8..16].copy_from_slice(&ino.to_ne_bytes());
            data[16..20].copy_from_slice(&(mode as u32).to_ne_bytes());
            data[20..24].copy_from_slice(&(links as u32).to_ne_bytes());
            data[48..56].copy_from_slice(&size.to_ne_bytes());
            data[56..60].copy_from_slice(&4096u32.to_ne_bytes());
            data[64..72].copy_from_slice(&blocks.to_ne_bytes());
            user_access::copy_to_user(space, a[1], &data).map_err(|_| Errno::Fault)?;
            Ok(0)
        }
        _ => Err(Errno::NoSys),
    }
}

/// read/write 使用 4 KiB 缓冲区；已有进展时返回短读或短写。
fn rw(nr: usize, a: [usize; 6], space: &UserAddressSpace, ctx: &Context) -> Result<usize, Errno> {
    let reading = nr == sysnr::READ;
    let handle = ctx.get(a[0])?;
    let mut f = handle.lock();
    f.check_access(reading)?;
    let total = a[2];
    if total == 0 {
        return Ok(0);
    }
    let mut chunk = [0u8; 4096];
    let mut done = 0;
    while done < total {
        let want = (total - done).min(chunk.len());
        let part: Result<usize, Errno> = (|| {
            if reading {
                f.read_chunk(&mut chunk[..want], done == 0, |data| {
                    user_access::copy_to_user(space, a[1] + done, data).map_err(|_| Errno::Fault)
                })
            } else {
                user_access::copy_from_user(space, a[1] + done, &mut chunk[..want])
                    .map_err(|_| Errno::Fault)?;
                f.write_chunk(&chunk[..want], done == 0)
            }
        })();
        match part {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) => return if done != 0 { Ok(done) } else { Err(e) },
        }
    }
    Ok(done)
}
