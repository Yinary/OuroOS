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
        sysnr::UMASK => Ok(ctx.set_umask(a[0])),
        sysnr::UTIMENSAT => utimensat(ctx, space, a),
        sysnr::RENAMEAT | sysnr::RENAMEAT2 => renameat(nr, ctx, space, a),
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
        sysnr::FCNTL => fcntl(ctx, a[0] as u32 as usize, a[1] as u32, a[2] as u32),
        sysnr::STATFS | sysnr::FSTATFS => statfs(nr, ctx, space, a),
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
                    fs::create(p, name, 0x4000 | ctx.creation_mode(a[2]))?;
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
        sysnr::GETDENTS64 => getdents64(ctx, space, a[0], a[1], a[2]),
        sysnr::CHDIR => {
            let path = ctx.path((-100isize) as usize, &user_string(space, a[0])?)?;
            if fs::stat(fs::lookup(&path)?)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            ctx.set_cwd(path)?;
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
                    fs::create(p, name, 0x8000 | ctx.creation_mode(a[3]))?
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
            ctx.open_inode(
                ino,
                path,
                a[2],
                a[2] & 0x80000 != 0,
                mode & 0xf000 == 0x4000,
            )
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
        sysnr::READ
        | sysnr::WRITE
        | sysnr::READV
        | sysnr::WRITEV
        | sysnr::PREAD64
        | sysnr::PWRITE64
        | sysnr::PREADV
        | sysnr::PWRITEV => rw(nr, a, space, ctx),
        sysnr::READLINKAT => readlinkat(ctx, space, a),
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

/// Linux getdents64：按后端续读位置打包目录项，缓冲区不足时返回 EINVAL。
#[inline(never)]
fn getdents64(
    ctx: &Context,
    space: &UserAddressSpace,
    fd: usize,
    output: usize,
    count: usize,
) -> Result<usize, Errno> {
    let handle = ctx.get(fd)?;
    let mut f = handle.lock();
    let ino = f.directory()?;
    let mut out = [0u8; 4096];
    let cap = count.min(out.len());
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
    user_access::copy_to_user(space, output, &out[..used]).map_err(|_| Errno::Fault)?;
    f.set_offset(offset);
    Ok(used)
}

/// Linux renameat/renameat2：支持普通改名及 NOREPLACE；交换和 whiteout 暂不支持。
fn renameat(
    nr: usize,
    ctx: &Context,
    space: &UserAddressSpace,
    a: [usize; 6],
) -> Result<usize, Errno> {
    let flags = if nr == sysnr::RENAMEAT2 {
        a[4] as u32
    } else {
        0
    };
    if flags & !1 != 0 {
        return Err(Errno::Invalid);
    }
    let old = user_string(space, a[1])?;
    let new = user_string(space, a[3])?;
    ctx.rename(
        a[0] as u32 as i32 as isize as usize,
        &old,
        a[2] as u32 as i32 as isize as usize,
        &new,
        flags & 1 != 0,
    )?;
    Ok(0)
}

/// Linux utimensat：支持路径、FD、NOW/OMIT 和末项不跟随；权限检查沿用现有模型。
fn utimensat(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    use fs::{TimeUpdate, Timestamp};
    let mut raw = [0; 32];
    if a[2] != 0 {
        user_access::copy_from_user(space, a[2], &mut raw).map_err(|_| Errno::Fault)?;
    }
    let values: [i64; 4] =
        core::array::from_fn(|i| i64::from_ne_bytes(core::array::from_fn(|j| raw[i * 8 + j])));
    let omit = (1 << 30) - 2;
    if a[2] != 0 && values[1] == omit && values[3] == omit {
        return Ok(0);
    }
    let flags = a[3] as u32;
    if flags & !(0x100 | 0x1000) != 0 {
        return Err(Errno::Invalid);
    }
    let parse = |sec, nsec| match nsec {
        n if n == omit => Ok(TimeUpdate::Omit),
        n if n == omit + 1 => Ok(TimeUpdate::Now),
        0..=999_999_999 => Ok(TimeUpdate::Set(Timestamp {
            sec,
            nsec: nsec as u32,
        })),
        _ => Err(Errno::Invalid),
    };
    let times = if a[2] == 0 {
        [TimeUpdate::Now; 2]
    } else {
        [parse(values[0], values[1])?, parse(values[2], values[3])?]
    };
    let dir = a[0] as u32 as i32 as isize as usize;
    if a[1] == 0 && dir as isize != -100 {
        if flags != 0 {
            return Err(Errno::Invalid);
        }
        return ctx.get(dir)?.lock().update_times(times).map(|_| 0);
    }
    let path = user_string(space, a[1])?;
    if path.is_empty() && flags & 0x1000 != 0 && dir as isize != -100 {
        return ctx.get(dir)?.lock().update_times(times).map(|_| 0);
    }
    let info = ctx.query(dir, &path, flags & 0x1000 != 0, flags & 0x100 == 0)?;
    fs::update_times(info.ino as u32, times)?;
    Ok(0)
}

/// Linux statfs/fstatfs：查询路径或 FD 所属卷，写回 120 字节的统计结构。
fn statfs(
    nr: usize,
    ctx: &Context,
    space: &UserAddressSpace,
    a: [usize; 6],
) -> Result<usize, Errno> {
    let stats = if nr == sysnr::STATFS {
        let path = user_string(space, a[0])?;
        let info = ctx.query((-100isize) as usize, &path, false, true)?;
        fs::filesystem_stats(info.ino as u32)?
    } else {
        ctx.get(a[0] as u32 as usize)?.lock().filesystem_stats()?
    };
    let mut out = [0; 120];
    for (i, value) in [
        stats.kind,
        stats.block_size,
        stats.blocks,
        stats.free_blocks,
        stats.available_blocks,
        stats.files,
        stats.free_files,
        stats.id,
        255,
        stats.block_size,
        stats.flags,
    ]
    .iter()
    .enumerate()
    {
        out[i * 8..i * 8 + 8].copy_from_slice(&value.to_ne_bytes());
    }
    user_access::copy_to_user(space, a[1], &out).map_err(|_| Errno::Fault)?;
    Ok(0)
}

/// Linux readlinkat：读取末项链接，不补 NUL；缓冲区不足时返回截断长度。
fn readlinkat(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    let capacity = a[3] as u32 as i32;
    if capacity <= 0 {
        return Err(Errno::Invalid);
    }
    let path = user_string(space, a[1])?;
    let dir = a[0] as u32 as i32 as isize as usize;
    let info = ctx.query(dir, &path, true, false)?;
    if info.mode & 0xf000 != 0xa000 {
        return Err(if path.is_empty() {
            Errno::NoEntry
        } else {
            Errno::Invalid
        });
    }
    let target = fs::read_link(info.ino as u32)?;
    let n = target.len().min(capacity as usize);
    user_access::copy_to_user(space, a[2], &target.as_bytes()[..n]).map_err(|_| Errno::Fault)?;
    Ok(n)
}

/// Linux fcntl 基础 FD 控制；未知命令返回 EINVAL，未实现文件锁及异步 I/O。
fn fcntl(ctx: &mut Context, fd: usize, command: u32, argument: u32) -> Result<usize, Errno> {
    let handle = ctx.get(fd)?;
    match command {
        0 | 1030 => ctx.install_from(handle, argument as usize, command == 1030),
        1 => ctx.descriptor_flags(fd),
        2 => ctx.set_descriptor_flags(fd, argument as usize),
        3 => Ok(handle.lock().status_flags()),
        4 => handle.lock().set_status_flags(argument as usize),
        _ => Err(Errno::Invalid),
    }
}

const MAX_IOV: usize = 1024;
const MAX_RW_COUNT: usize = 0x7fff_f000;

#[derive(Clone, Copy)]
struct UserBuffer {
    address: usize,
    len: usize,
}

/// 在复制数据前校验数值范围，实际映射和权限由 user_access 逐页检查。
fn buffer(address: usize, len: usize) -> Result<UserBuffer, Errno> {
    if len != 0
        && address.checked_add(len).ok_or(Errno::Fault)? > crate::mm::address_space::USER_TOP
    {
        return Err(Errno::Fault);
    }
    Ok(UserBuffer { address, len })
}

/// 先复制全部 iovec 描述符，避免用户缓冲区覆盖尚未导入的描述符。
fn import_iov(
    space: &UserAddressSpace,
    address: usize,
    count: usize,
) -> Result<Vec<UserBuffer>, Errno> {
    if count > MAX_IOV {
        return Err(Errno::Invalid);
    }
    let mut buffers = Vec::new();
    buffers.try_reserve_exact(count).map_err(|_| Errno::NoMem)?;
    let mut total = 0usize;
    for i in 0..count {
        let mut pair = [0u8; 16];
        let pointer = address.checked_add(i * 16).ok_or(Errno::Fault)?;
        user_access::copy_from_user(space, pointer, &mut pair).map_err(|_| Errno::Fault)?;
        let base = usize::from_ne_bytes(pair[..8].try_into().map_err(|_| Errno::Invalid)?);
        let len = usize::from_ne_bytes(pair[8..].try_into().map_err(|_| Errno::Invalid)?);
        total = total
            .checked_add(len)
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(Errno::Invalid)?;
        buffers.push(buffer(base, len)?);
    }
    Ok(buffers)
}

struct UserIo<'a> {
    buffers: &'a [UserBuffer],
    index: usize,
    offset: usize,
}
impl UserIo<'_> {
    fn copy(
        &mut self,
        len: usize,
        mut copy: impl FnMut(usize, usize, usize) -> Result<(), Errno>,
    ) -> Result<usize, Errno> {
        let mut done = 0;
        while done < len && self.index < self.buffers.len() {
            let b = self.buffers[self.index];
            if self.offset == b.len {
                self.index += 1;
                self.offset = 0;
                continue;
            }
            let address = b.address.checked_add(self.offset).ok_or(Errno::Fault)?;
            let n = (b.len - self.offset)
                .min(len - done)
                .min(4096 - address % 4096);
            if let Err(error) = copy(address, done, n) {
                return if done != 0 { Ok(done) } else { Err(error) };
            }
            self.offset += n;
            done += n;
        }
        Ok(done)
    }
}

/// 普通与定位、单缓冲区与向量 I/O 共用搬运流程；定位偏移不写入打开文件对象。
fn rw(nr: usize, a: [usize; 6], space: &UserAddressSpace, ctx: &Context) -> Result<usize, Errno> {
    let reading = matches!(
        nr,
        sysnr::READ | sysnr::READV | sysnr::PREAD64 | sysnr::PREADV
    );
    let vector = matches!(
        nr,
        sysnr::READV | sysnr::WRITEV | sysnr::PREADV | sysnr::PWRITEV
    );
    let positioned = matches!(
        nr,
        sysnr::PREAD64 | sysnr::PWRITE64 | sysnr::PREADV | sysnr::PWRITEV
    );
    // rv64/la64 的 pos_l 已容纳完整 64 位偏移，原始 preadv/pwritev 的 pos_h 不参与取值。
    let offset = if positioned {
        if (a[3] as isize) < 0 {
            return Err(Errno::Invalid);
        }
        Some(a[3])
    } else {
        None
    };
    let handle = ctx.get(a[0])?;
    let mut file = handle.lock();
    if positioned {
        file.check_positioned()?;
    }
    file.check_access(reading)?;
    if vector {
        let buffers = import_iov(space, a[1], a[2])?;
        transfer(space, &mut file, &buffers, reading, offset)
    } else {
        let b = buffer(a[1], a[2])?;
        transfer(space, &mut file, &[b], reading, offset)
    }
}

/// 复用可失败分配的 4 KiB 缓冲区；发生部分传输后返回已完成长度。
#[inline(never)]
fn transfer(
    space: &UserAddressSpace,
    file: &mut fs::context::OpenFile,
    buffers: &[UserBuffer],
    reading: bool,
    mut position: Option<usize>,
) -> Result<usize, Errno> {
    let total = buffers
        .iter()
        .fold(0usize, |sum, b| sum.saturating_add(b.len))
        .min(MAX_RW_COUNT);
    let mut user = UserIo {
        buffers,
        index: 0,
        offset: 0,
    };
    if total == 0 {
        return Ok(0);
    }
    let mut chunk = Vec::new();
    chunk.try_reserve_exact(4096).map_err(|_| Errno::NoMem)?;
    chunk.resize(4096, 0);
    let mut done = 0;
    while done < total {
        let want = (total - done).min(chunk.len());
        let part: Result<usize, Errno> = (|| {
            if reading {
                let deliver = |data: &[u8]| {
                    user.copy(data.len(), |address, start, len| {
                        user_access::copy_to_user(space, address, &data[start..start + len])
                            .map_err(|_| Errno::Fault)
                    })
                };
                if let Some(pos) = position {
                    file.read_at(pos, &mut chunk[..want], done == 0, deliver)
                } else {
                    file.read_chunk(&mut chunk[..want], done == 0, deliver)
                }
            } else {
                let copied = user.copy(want, |address, start, len| {
                    user_access::copy_from_user(space, address, &mut chunk[start..start + len])
                        .map_err(|_| Errno::Fault)
                })?;
                if let Some(pos) = position {
                    file.write_at(pos, &chunk[..copied], done == 0)
                } else {
                    file.write_chunk(&chunk[..copied], done == 0)
                }
            }
        })();
        match part {
            Ok(0) => break,
            Ok(n) => {
                done += n;
                if let Some(pos) = &mut position {
                    *pos = pos.checked_add(n).ok_or(Errno::Invalid)?;
                }
                if n < want {
                    break;
                }
            }
            Err(error) => return if done != 0 { Ok(done) } else { Err(error) },
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
