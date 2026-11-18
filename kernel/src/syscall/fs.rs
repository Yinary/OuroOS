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
        sysnr::FSTATAT | sysnr::STATX => {
            let extended = nr == sysnr::STATX;
            let flags = if extended { a[2] } else { a[3] };
            let allowed = 0x1000 | 0x100 | 0x800 | if extended { 0x6000 } else { 0 };
            if flags & !allowed != 0
                || (extended && (flags & 0x6000 == 0x6000 || a[3] & 0x8000_0000 != 0))
            {
                return Err(Errno::Invalid);
            }
            let path = if a[1] == 0 && flags & 0x1000 != 0 {
                String::new()
            } else {
                user_string(space, a[1])?
            };
            let info = ctx.query(a[0], &path, flags & 0x1000 != 0, flags & 0x100 == 0)?;
            if extended {
                user_access::copy_to_user(space, a[4], &encode_statx(&info))
                    .map_err(|_| Errno::Fault)?;
            } else {
                user_access::copy_to_user(space, a[2], &encode_stat(&info))
                    .map_err(|_| Errno::Fault)?;
            }
            Ok(0)
        }
        sysnr::FSTAT => {
            let handle = ctx.get(a[0])?;
            let info = handle.lock().metadata()?;
            user_access::copy_to_user(space, a[1], &encode_stat(&info))
                .map_err(|_| Errno::Fault)?;
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

/// 编码 rv64/la64 共用的 asm-generic 128 字节 stat 布局。
fn encode_stat(m: &fs::Metadata) -> [u8; 128] {
    let mut out = [0; 128];
    out[0..8].copy_from_slice(&m.dev.to_ne_bytes());
    out[8..16].copy_from_slice(&m.ino.to_ne_bytes());
    out[16..20].copy_from_slice(&(m.mode as u32).to_ne_bytes());
    out[20..24].copy_from_slice(&m.links.to_ne_bytes());
    out[24..28].copy_from_slice(&m.uid.to_ne_bytes());
    out[28..32].copy_from_slice(&m.gid.to_ne_bytes());
    out[32..40].copy_from_slice(&m.rdev.to_ne_bytes());
    out[48..56].copy_from_slice(&m.size.to_ne_bytes());
    out[56..60].copy_from_slice(&m.block_size.to_ne_bytes());
    out[64..72].copy_from_slice(&m.blocks.to_ne_bytes());
    for (offset, time) in [(72, m.atime), (88, m.mtime), (104, m.ctime)] {
        if let Some(t) = time {
            out[offset..offset + 8].copy_from_slice(&t.sec.to_ne_bytes());
            out[offset + 8..offset + 16].copy_from_slice(&(t.nsec as u64).to_ne_bytes());
        }
    }
    out
}

/// 编码 statx；仅为后端实际提供的时间设置有效位。
fn encode_statx(m: &fs::Metadata) -> [u8; 256] {
    let mut out = [0; 256];
    // 类型、权限、链接数、所有者、inode、长度和块数始终可用。
    let mut mask = 0x71fu32;
    out[4..8].copy_from_slice(&m.block_size.to_ne_bytes());
    out[16..20].copy_from_slice(&m.links.to_ne_bytes());
    out[20..24].copy_from_slice(&m.uid.to_ne_bytes());
    out[24..28].copy_from_slice(&m.gid.to_ne_bytes());
    out[28..30].copy_from_slice(&m.mode.to_ne_bytes());
    out[32..40].copy_from_slice(&m.ino.to_ne_bytes());
    out[40..48].copy_from_slice(&m.size.to_ne_bytes());
    out[48..56].copy_from_slice(&m.blocks.to_ne_bytes());
    for (offset, bit, time) in [
        (64, 0x20, m.atime),
        (80, 0x800, m.btime),
        (96, 0x80, m.ctime),
        (112, 0x40, m.mtime),
    ] {
        if let Some(t) = time {
            mask |= bit;
            out[offset..offset + 8].copy_from_slice(&t.sec.to_ne_bytes());
            out[offset + 8..offset + 12].copy_from_slice(&t.nsec.to_ne_bytes());
        }
    }
    out[0..4].copy_from_slice(&mask.to_ne_bytes());
    for (offset, dev) in [(128, m.rdev), (136, m.dev)] {
        // Linux dev_t 的低 8 位和 12 位以上共同编码次设备号。
        let major = ((dev >> 8) & 0xfff) as u32;
        let minor = ((dev & 0xff) | ((dev >> 12) & 0xfffff00)) as u32;
        out[offset..offset + 4].copy_from_slice(&major.to_ne_bytes());
        out[offset + 4..offset + 8].copy_from_slice(&minor.to_ne_bytes());
    }
    out
}
