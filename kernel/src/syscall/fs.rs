//! 文件系统调用的参数检查、用户缓冲区访问与 Linux 返回结构编码。
//! FD、文件偏移和管道状态由 fs::context 管理。
#![deny(unsafe_code)]

use super::{sysnr, Errno};
use crate::{
    fs::{self, context::Context},
    mm::{address_space::UserAddressSpace, user_access},
    task::Credentials,
};
use alloc::{string::String, vec::Vec};

/// 从用户内存读取 NUL 结尾 UTF-8 字符串；不可访问或过长时返回错误。
pub(crate) fn user_string(space: &UserAddressSpace, ptr: usize) -> Result<String, Errno> {
    user_access::read_cstr(space, ptr, 4096).map_err(|e| match e {
        user_access::CStrError::Fault => Errno::Fault,
        user_access::CStrError::TooLong => Errno::NameTooLong,
        user_access::CStrError::NoMem => Errno::NoMem,
        user_access::CStrError::InvalidUtf8 => Errno::Invalid,
    })
}
/// Linux 文件调用，所有用户缓冲区经 user_access 复制。
pub fn dispatch(
    nr: usize,
    a: [usize; 6],
    space: &UserAddressSpace,
    ctx: &mut Context,
    credentials: &Credentials,
    tgid: u32,
) -> Result<usize, Errno> {
    match nr {
        sysnr::UMASK => Ok(ctx.set_umask(a[0])),
        sysnr::UTIMENSAT => utimensat(ctx, space, a),
        sysnr::TRUNCATE | sysnr::FTRUNCATE => truncate(nr, ctx, space, a),
        sysnr::RENAMEAT | sysnr::RENAMEAT2 => renameat(nr, ctx, space, a),
        sysnr::GETCWD => {
            let cwd = ctx.cwd()?;
            if a[1] < cwd.len() + 1 {
                return Err(Errno::Range);
            }
            user_access::copy_to_user(space, a[0], cwd.as_bytes()).map_err(|_| Errno::Fault)?;
            user_access::copy_to_user(
                space,
                a[0].checked_add(cwd.len()).ok_or(Errno::Fault)?,
                &[0],
            )
            .map_err(|_| Errno::Fault)?;
            Ok(cwd.len() + 1)
        }
        sysnr::DUP => ctx.install(ctx.get(a[0])?, false),
        sysnr::FCNTL => fcntl(ctx, space, a[0] as u32 as usize, a[1] as u32, a[2], tgid),
        sysnr::FLOCK => flock_call(ctx, a[0] as u32 as usize, a[1] as u32),
        sysnr::STATFS | sysnr::FSTATFS => statfs(nr, ctx, space, a),
        sysnr::DUP3 => {
            if a[2] & !0x80000 != 0 || a[0] == a[1] {
                return Err(Errno::Invalid);
            }
            ctx.dup_to(a[0], a[1], a[2] & 0x80000 != 0, tgid)
        }
        sysnr::MKDIRAT => {
            let input = user_string(space, a[1])?;
            let dirfd = a[0] as u32 as i32 as isize as usize;
            let (canonical, p, name) = ctx.resolve_parent_entry(dirfd, &input, Errno::Exists)?;
            match fs::query(&canonical, false) {
                Ok(_) => Err(Errno::Exists),
                Err(Errno::NoEntry) => {
                    fs::create(p, &name, 0x4000 | ctx.creation_mode(a[2]))?;
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
        sysnr::FACCESSAT => faccessat(ctx, space, a),
        sysnr::FCHOWNAT | sysnr::FCHOWN => chown(nr, ctx, space, a, credentials),
        sysnr::FCHMOD => fchmod(ctx, space, a),
        sysnr::FCHMODAT => fchmodat(ctx, space, a),
        sysnr::MKNODAT => mknodat(ctx, space, a),
        sysnr::FACCESSAT2 => faccessat2(ctx, space, a),
        sysnr::IOCTL => ioctl(ctx, space, a),

        sysnr::UMOUNT2 => {
            if a[1] != 0 {
                return Err(Errno::NotSupported);
            }
            let target = ctx.path((-100isize) as usize, &user_string(space, a[0])?)?;
            fs::fat::unmount(&target)?;
            Ok(0)
        }
        sysnr::SYMLINKAT => {
            let target = user_string(space, a[0])?;
            let linkpath = user_string(space, a[2])?;
            let dirfd = a[1] as u32 as i32 as isize as usize;
            ctx.symlink(dirfd, &linkpath, &target)?;
            Ok(0)
        }
        sysnr::LINKAT => {
            const AT_SYMLINK_FOLLOW: u32 = 0x400;
            const AT_EMPTY_PATH: u32 = 0x1000;
            let flags = a[4] as u32;
            if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
                return Err(Errno::Invalid);
            }
            let old = user_string(space, a[1])?;
            let new = user_string(space, a[3])?;
            let old_dir = a[0] as u32 as i32 as isize as usize;
            let new_dir = a[2] as u32 as i32 as isize as usize;
            ctx.link(
                old_dir,
                &old,
                new_dir,
                &new,
                flags & AT_SYMLINK_FOLLOW != 0,
                flags & AT_EMPTY_PATH != 0,
            )?;
            Ok(0)
        }
        sysnr::SENDFILE => sendfile(ctx, space, a),
        sysnr::UNLINKAT => {
            if a[2] & !0x200 != 0 {
                return Err(Errno::Invalid);
            }
            let input = user_string(space, a[1])?;
            let dirfd = a[0] as u32 as i32 as isize as usize;
            if a[2] & 0x200 != 0 {
                match input.trim_end_matches('/').rsplit('/').next() {
                    Some(".") => return Err(Errno::Invalid),
                    Some("..") => return Err(Errno::NotEmpty),
                    _ => {}
                }
                let (path, p, name) = ctx.resolve_parent_entry(dirfd, &input, Errno::Busy)?;
                let info = fs::query(&path, false)?;
                if info.mode & 0xf000 != 0x4000 {
                    return Err(Errno::NotDir);
                }
                if path == "/" || fs::contains_mount(&path) {
                    return Err(Errno::Busy);
                }
                fs::rmdir(p, info.ino as u32, &name)?;
                return Ok(0);
            }
            if input.ends_with('/') {
                let (path, _, _) = ctx.resolve_parent_entry(dirfd, &input, Errno::IsDir)?;
                let info = fs::query(&path, false)?;
                return Err(if info.mode & 0xf000 == 0x4000 {
                    Errno::IsDir
                } else {
                    Errno::NotDir
                });
            }
            let (path, p, name) = ctx.resolve_parent_entry(dirfd, &input, Errno::IsDir)?;
            let info = fs::query(&path, false)?;
            fs::unlink(p, info.ino as u32, &name)?;
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
                ctx.close(rfd, 0)?;
                ctx.close(wfd, 0)?;
                return Err(Errno::Fault);
            }
            Ok(0)
        }
        sysnr::GETDENTS64 => getdents64(ctx, space, a[0], a[1], a[2]),
        sysnr::CHDIR => {
            let joined = ctx.join_raw((-100isize) as usize, &user_string(space, a[0])?)?;
            let (resolved, info) = fs::resolve(&joined, true)?;
            if info.mode & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            ctx.set_cwd(resolved, info.ino as u32)?;
            Ok(0)
        }
        sysnr::OPENAT => {
            const O_CREAT: usize = 0x40;
            const O_EXCL: usize = 0x80;
            const O_TRUNC: usize = 0x200;
            const O_DIRECTORY: usize = 0x10000;
            const O_NOFOLLOW: usize = 0x20000;
            const O_CLOEXEC: usize = 0x80000;
            const O_PATH: usize = 0x200000;
            if a[2] & 3 == 3 {
                return Err(Errno::Invalid);
            }
            if a[2] & O_DIRECTORY != 0 && a[2] & O_CREAT != 0 {
                return Err(Errno::Invalid);
            }
            let raw_input = user_string(space, a[1])?;
            let dirfd = a[0] as u32 as i32 as isize as usize;
            let joined = ctx.join_raw(dirfd, &raw_input)?;
            if joined.starts_with("/proc") || joined.starts_with("/dev") {
                if let Ok(path) = ctx.path(dirfd, &raw_input) {
                    if path == "/proc/meminfo" {
                        return ctx.open_meminfo(a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if path == "/proc/mounts"
                        || path == "/proc/sys/kernel/pid_max"
                        || path == "/proc/sys/kernel/tainted"
                        || path == "/proc/sys/fs/pipe-max-size"
                        || path == "/proc/version"
                    {
                        let text = fs::procfs_text(&path)?;
                        return ctx.open_proc_text(text, a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if path == "/proc/self/maps" {
                        let text = fs::procfs_maps(space)?;
                        return ctx.open_proc_text(text, a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if path == "/proc/self/fd" {
                        return ctx.open_proc_fd_dir(a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if let Some(rest) = path.strip_prefix("/proc/") {
                        if rest
                            .split_once('/')
                            .is_some_and(|(_, f)| f == "stat" || f == "cmdline" || f == "status")
                        {
                            let text = fs::procfs_text(&path)?;
                            return ctx.open_proc_text(text, a[2], a[2] & O_CLOEXEC != 0);
                        }
                    }
                    if path == "/dev/null" {
                        return ctx.open_devnull(a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if path == "/dev/zero" {
                        return ctx.open_devzero(a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if path == "/dev/urandom" {
                        return ctx.open_devrandom(true, a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if path == "/dev/random" {
                        return ctx.open_devrandom(false, a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if path == "/dev/misc/rtc" {
                        return ctx.open_rtc(a[2], a[2] & O_CLOEXEC != 0);
                    }
                    if let Some((disk, part)) = fs::lookup_blk_node(&path) {
                        if let Ok((start, len)) = crate::drivers::partition(disk, part) {
                            return ctx.open_devblk(
                                disk,
                                start,
                                len as u64,
                                a[2],
                                a[2] & O_CLOEXEC != 0,
                            );
                        }
                        return Err(Errno::NoDevice);
                    }
                }
            }
            let creat = a[2] & O_CREAT != 0;
            let excl = a[2] & O_EXCL != 0;
            let nofollow = a[2] & O_NOFOLLOW != 0;
            let o_path = a[2] & O_PATH != 0;
            let trailing_slash = raw_input.ends_with('/');
            let (ino, mode, open_path) = if creat && excl {
                if trailing_slash {
                    return Err(Errno::IsDir);
                }
                let (canonical, p, name) =
                    ctx.resolve_parent_entry(dirfd, &raw_input, Errno::Exists)?;
                match fs::query(&canonical, false) {
                    Ok(_) => return Err(Errno::Exists),
                    Err(Errno::NoEntry) => {
                        let new_mode = 0x8000 | ctx.creation_mode(a[3]);
                        let ino = fs::create(p, &name, new_mode)?;
                        (ino, new_mode, canonical)
                    }
                    Err(e) => return Err(e),
                }
            } else {
                let follow = !nofollow || trailing_slash;
                match fs::resolve(&joined, follow) {
                    Ok((resolved, info)) => {
                        if info.mode & 0xf000 == 0xa000 && !o_path {
                            return Err(Errno::Loop);
                        }
                        if trailing_slash && info.mode & 0xf000 != 0x4000 {
                            return Err(Errno::NotDir);
                        }
                        (info.ino as u32, info.mode, resolved)
                    }
                    Err(Errno::NoEntry) if creat => {
                        if trailing_slash {
                            return Err(Errno::IsDir);
                        }
                        let new_mode = 0x8000 | ctx.creation_mode(a[3]);
                        // 悬空符号链接 + O_CREAT（无 O_EXCL）：按 Linux open(2) 跟随链接并创建目标文件。
                        if let Ok((sym_path, sym_info)) = fs::resolve(&joined, false) {
                            if sym_info.mode & 0xf000 == 0xa000 {
                                if nofollow {
                                    return Err(Errno::Loop);
                                }
                                let target = fs::read_link(sym_info.ino as u32)?;
                                let target_joined = if target.starts_with('/') {
                                    target
                                } else {
                                    let sym_parent = match sym_path.rfind('/') {
                                        Some(0) | None => "/",
                                        Some(i) => &sym_path[..i],
                                    };
                                    let mut full = String::new();
                                    full.try_reserve(sym_parent.len() + target.len() + 1)
                                        .map_err(|_| Errno::NoMem)?;
                                    full.push_str(sym_parent);
                                    if sym_parent != "/" {
                                        full.push('/');
                                    }
                                    full.push_str(&target);
                                    full
                                };
                                let (canonical, p, name) = ctx.resolve_parent_entry(
                                    (-100isize) as usize,
                                    &target_joined,
                                    Errno::Exists,
                                )?;
                                let ino = fs::create(p, &name, new_mode)?;
                                (ino, new_mode, canonical)
                            } else {
                                let (canonical, p, name) =
                                    ctx.resolve_parent_entry(dirfd, &raw_input, Errno::Exists)?;
                                let ino = fs::create(p, &name, new_mode)?;
                                (ino, new_mode, canonical)
                            }
                        } else {
                            let (canonical, p, name) =
                                ctx.resolve_parent_entry(dirfd, &raw_input, Errno::Exists)?;
                            let ino = fs::create(p, &name, new_mode)?;
                            (ino, new_mode, canonical)
                        }
                    }
                    Err(e) => return Err(e),
                }
            };
            if a[2] & O_DIRECTORY != 0 && mode & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            if mode & 0xf000 == 0x4000 && a[2] & 3 != 0 && !o_path {
                return Err(Errno::IsDir);
            }
            if a[2] & O_TRUNC != 0 && a[2] & 3 != 0 && !o_path {
                fs::truncate(ino, 0)?;
            }
            ctx.open_inode(
                ino,
                open_path,
                a[2],
                a[2] & O_CLOEXEC != 0,
                mode & 0xf000 == 0x4000,
            )
        }
        sysnr::SYNC => {
            let _ = fs::sync();
            Ok(0)
        }
        #[cfg(not(feature = "rsext4-readonly"))]
        sysnr::FSYNC => {
            let handle = ctx.get(a[0])?;
            let ino = handle.lock().inode()?;
            fs::sync_inode(ino)?;
            Ok(0)
        }
        sysnr::CLOSE => {
            ctx.close(a[0], tgid)?;
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
        sysnr::EVENTFD2 => ctx.open_eventfd(a[0] as u32, a[1] as u32 as usize),
        sysnr::EPOLL_CREATE1 => ctx.open_epoll(a[0] as u32 as usize),
        sysnr::EPOLL_CTL => epoll_ctl(ctx, space, a),
        sysnr::TIMERFD_CREATE => ctx.open_timerfd(a[0] as u32 as i32, a[1] as u32 as usize),
        sysnr::TIMERFD_SETTIME => timerfd_settime(ctx, space, a),
        sysnr::TIMERFD_GETTIME => timerfd_gettime(ctx, space, a),
        _ => Err(Errno::NoSys),
    }
}

/// epoll_ctl(2)：解析 16 字节非紧凑 struct epoll_event（rv64/la64 布局）并操作 epoll 兴趣表。
fn epoll_ctl(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    let epfd = a[0] as u32 as i32;
    let op = a[1] as u32 as i32;
    let fd = a[2] as u32 as i32;
    if epfd < 0 || fd < 0 {
        return Err(Errno::BadF);
    }
    let event = if op == fs::event::EPOLL_CTL_DEL {
        None
    } else if a[3] == 0 {
        return Err(Errno::Fault);
    } else {
        let mut raw = [0u8; 16];
        user_access::copy_from_user(space, a[3], &mut raw).map_err(|_| Errno::Fault)?;
        let events = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let data = u64::from_ne_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        Some((events, data))
    };
    ctx.epoll_ctl(epfd as usize, op, fd as usize, event)?;
    Ok(0)
}

/// 解码 32 字节 struct itimerspec（interval + value）。
fn read_itimerspec(
    space: &UserAddressSpace,
    ptr: usize,
) -> Result<(core::time::Duration, core::time::Duration), Errno> {
    if ptr == 0 {
        return Err(Errno::Fault);
    }
    let mut raw = [0u8; 32];
    user_access::copy_from_user(space, ptr, &mut raw).map_err(|_| Errno::Fault)?;
    let parse_ts = |chunk: &[u8]| -> Result<core::time::Duration, Errno> {
        let sec = i64::from_ne_bytes(chunk[0..8].try_into().unwrap_or([0; 8]));
        let nsec = i64::from_ne_bytes(chunk[8..16].try_into().unwrap_or([0; 8]));
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return Err(Errno::Invalid);
        }
        Ok(core::time::Duration::new(sec as u64, nsec as u32))
    };
    Ok((parse_ts(&raw[0..16])?, parse_ts(&raw[16..32])?))
}

/// 编码并写回 32 字节 struct itimerspec。
fn write_itimerspec(
    space: &UserAddressSpace,
    ptr: usize,
    interval: core::time::Duration,
    value: core::time::Duration,
) -> Result<(), Errno> {
    let mut raw = [0u8; 32];
    raw[0..8].copy_from_slice(&(interval.as_secs() as i64).to_ne_bytes());
    raw[8..16].copy_from_slice(&(interval.subsec_nanos() as i64).to_ne_bytes());
    raw[16..24].copy_from_slice(&(value.as_secs() as i64).to_ne_bytes());
    raw[24..32].copy_from_slice(&(value.subsec_nanos() as i64).to_ne_bytes());
    user_access::copy_to_user(space, ptr, &raw).map_err(|_| Errno::Fault)
}

/// timerfd_settime(2)：先校验 fd 类型，再读取新值与写回旧值，最后更新定时器状态。
fn timerfd_settime(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    let fd = a[0] as u32 as i32;
    if fd < 0 {
        return Err(Errno::BadF);
    }
    let flags = a[1] as u32 as usize;
    let old = ctx.timerfd_gettime(fd as usize)?;
    let (interval, value) = read_itimerspec(space, a[2])?;
    if a[3] != 0 {
        write_itimerspec(space, a[3], old.0, old.1)?;
    }
    let _ = ctx.timerfd_settime(fd as usize, flags, interval, value)?;
    Ok(0)
}

/// timerfd_gettime(2)：先校验 fd 是否为 timerfd（EBADF/EINVAL），再写回 curr_value（EFAULT）。
fn timerfd_gettime(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    let fd = a[0] as u32 as i32;
    if fd < 0 {
        return Err(Errno::BadF);
    }
    let (interval, value) = ctx.timerfd_gettime(fd as usize)?;
    if a[1] == 0 {
        return Err(Errno::Fault);
    }
    write_itimerspec(space, a[1], interval, value)?;
    Ok(0)
}

/// Linux truncate/ftruncate：检查有符号长度，按路径或可写 FD 调整普通文件长度。
fn truncate(
    nr: usize,
    ctx: &Context,
    space: &UserAddressSpace,
    a: [usize; 6],
) -> Result<usize, Errno> {
    let length = a[1] as i64;
    if length < 0 {
        return Err(Errno::Invalid);
    }
    if nr == sysnr::TRUNCATE {
        let path = user_string(space, a[0])?;
        let info = ctx.query((-100isize) as usize, &path, false, true)?;
        fs::truncate(info.ino as u32, length as u64)?;
    } else {
        ctx.get(a[0] as u32 as usize)?
            .lock()
            .truncate(length as u64)?;
    }
    Ok(0)
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
    if let Some(entries) = f.proc_fd_entries() {
        let mut out = [0u8; 4096];
        let cap = count.min(out.len());
        let mut used = 0;
        let mut full = false;
        let mut pos = f.offset();
        let total = 2 + entries.len();
        while pos < total {
            let mut num_buf = [0u8; 20];
            let (ino_val, dtype, name): (u64, u8, &[u8]) = if pos == 0 {
                (u64::from(u32::MAX - 17), 4, b".")
            } else if pos == 1 {
                (u64::from(u32::MAX - 15), 4, b"..")
            } else {
                let mut v = entries[pos - 2];
                let mut i = num_buf.len();
                if v == 0 {
                    i -= 1;
                    num_buf[i] = b'0';
                } else {
                    while v > 0 {
                        i -= 1;
                        num_buf[i] = b'0' + (v % 10) as u8;
                        v /= 10;
                    }
                }
                (u64::from(u32::MAX - 17) + (pos as u64), 10, &num_buf[i..])
            };
            let len = (19 + name.len() + 1 + 7) & !7;
            if used + len > cap {
                full = true;
                break;
            }
            let d = &mut out[used..used + len];
            d[..8].copy_from_slice(&ino_val.to_ne_bytes());
            d[8..16].copy_from_slice(&((pos + 1) as u64).to_ne_bytes());
            d[16..18].copy_from_slice(&(len as u16).to_ne_bytes());
            d[18] = dtype;
            d[19..19 + name.len()].copy_from_slice(name);
            used += len;
            pos += 1;
        }
        if full && used == 0 {
            return Err(Errno::Invalid);
        }
        user_access::copy_to_user(space, output, &out[..used]).map_err(|_| Errno::Fault)?;
        f.set_offset(pos);
        return Ok(used);
    }
    let ino = f.directory()?;
    if f.detached_directory() {
        return Ok(0);
    }
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

/// Linux fchown/fchownat：按 FD 或路径修改 Ext4 对象的归属。
fn chown(
    nr: usize,
    ctx: &Context,
    space: &UserAddressSpace,
    a: [usize; 6],
    credentials: &Credentials,
) -> Result<usize, Errno> {
    const AT_FDCWD: isize = -100;
    const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
    const AT_EMPTY_PATH: u32 = 0x1000;
    const O_PATH: usize = 0x200000;

    let id = |raw: usize| {
        let value = raw as u32;
        (value != u32::MAX).then_some(value)
    };
    let fd_inode = |fd, allow_path: bool| {
        let file = ctx.get(fd)?;
        let file = file.lock();
        if !allow_path && file.status_flags() & O_PATH != 0 {
            return Err(Errno::BadF);
        }
        file.inode().map_err(|_| Errno::NotSupported)
    };

    let (ino, uid, gid) = if nr == sysnr::FCHOWN {
        (fd_inode(a[0] as u32 as usize, false)?, id(a[1]), id(a[2]))
    } else {
        let flags = a[4] as u32;
        if flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
            return Err(Errno::Invalid);
        }
        let dir = a[0] as u32 as i32 as isize;
        let path = user_string(space, a[1])?;
        let empty = flags & AT_EMPTY_PATH != 0;
        let ino = if empty && path.is_empty() && dir != AT_FDCWD {
            fd_inode(dir as usize, true)?
        } else {
            ctx.query(dir as usize, &path, empty, flags & AT_SYMLINK_NOFOLLOW == 0)?
                .ino as u32
        };
        (ino, id(a[2]), id(a[3]))
    };
    fs::set_owner(ino, uid, gid, credentials)?;
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

/// Linux flock(2)：按打开文件描述（OFD）施加共享锁、独占锁或解锁。
fn flock_call(ctx: &Context, fd: usize, operation: u32) -> Result<usize, Errno> {
    let handle = ctx.get(fd)?;
    let (key, ofd_id, flags) = {
        let f = handle.lock();
        (f.lock_key(), f.ofd_id(), f.status_flags())
    };
    if flags & 0x200000 != 0 {
        return Err(Errno::BadF);
    }
    fs::locks::flock(key, ofd_id, operation)?;
    Ok(0)
}

/// Linux fcntl：基础 FD 控制、管道容量与 POSIX/OFD 字节区间记录锁。
fn fcntl(
    ctx: &mut Context,
    space: &UserAddressSpace,
    fd: usize,
    command: u32,
    argument: usize,
    tgid: u32,
) -> Result<usize, Errno> {
    const F_GETLK: u32 = 5;
    const F_SETLK: u32 = 6;
    const F_SETLKW: u32 = 7;
    const F_OFD_GETLK: u32 = 36;
    const F_OFD_SETLK: u32 = 37;
    const F_OFD_SETLKW: u32 = 38;

    let handle = ctx.get(fd)?;
    match command {
        0 | 1030 => ctx.install_from(handle, argument as u32 as usize, command == 1030),
        1 => ctx.descriptor_flags(fd),
        2 => ctx.set_descriptor_flags(fd, argument as u32 as usize),
        3 => Ok(handle.lock().status_flags()),
        4 => handle.lock().set_status_flags(argument as u32 as usize),
        1031 => handle.lock().set_pipe_size(argument as u32 as usize),
        1032 => handle.lock().pipe_size(),
        F_GETLK | F_SETLK | F_SETLKW | F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => {
            let ofd_cmd = matches!(command, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
            let mut raw = [0u8; 32];
            user_access::copy_from_user(space, argument, &mut raw).map_err(|_| Errno::Fault)?;
            let l_type = i16::from_ne_bytes([raw[0], raw[1]]);
            let l_whence = i16::from_ne_bytes([raw[2], raw[3]]);
            let l_start = i64::from_ne_bytes([
                raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
            ]);
            let l_len = i64::from_ne_bytes([
                raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
            ]);
            let l_pid = i32::from_ne_bytes([raw[24], raw[25], raw[26], raw[27]]);

            if ofd_cmd && l_pid != 0 {
                return Err(Errno::Invalid);
            }
            let (key, ofd_id, flags, base) = {
                let f = handle.lock();
                let flags = f.status_flags();
                if flags & 0x200000 != 0 {
                    return Err(Errno::BadF);
                }
                let base: i64 = match l_whence {
                    0 => 0,
                    1 => i64::try_from(f.offset()).map_err(|_| Errno::Invalid)?,
                    2 => i64::try_from(f.lock_file_size()?).map_err(|_| Errno::Invalid)?,
                    _ => return Err(Errno::Invalid),
                };
                (f.lock_key(), f.ofd_id(), flags, base)
            };

            let origin = base.checked_add(l_start).ok_or(Errno::Invalid)?;
            let (start, end) = if l_len == 0 {
                if origin < 0 {
                    return Err(Errno::Invalid);
                }
                (origin as u64, u64::MAX)
            } else if l_len > 0 {
                if origin < 0 {
                    return Err(Errno::Invalid);
                }
                let hi = origin.checked_add(l_len - 1).ok_or(Errno::Invalid)?;
                (origin as u64, hi as u64)
            } else {
                let lo = origin.checked_add(l_len).ok_or(Errno::Invalid)?;
                if lo < 0 || origin <= 0 {
                    return Err(Errno::Invalid);
                }
                (lo as u64, (origin - 1) as u64)
            };

            let owner = if ofd_cmd {
                fs::locks::LockOwner::Ofd(ofd_id)
            } else {
                fs::locks::LockOwner::Process(tgid)
            };

            if matches!(command, F_GETLK | F_OFD_GETLK) {
                let exclusive = match l_type {
                    0 => false,
                    1 => true,
                    _ => return Err(Errno::Invalid),
                };
                if let Some(c) = fs::locks::get_record_lock(key, owner, exclusive, start, end) {
                    let c_type: i16 = if c.exclusive { 1 } else { 0 };
                    let c_len: i64 = if c.end == u64::MAX {
                        0
                    } else {
                        i64::try_from(c.end - c.start + 1).unwrap_or(0)
                    };
                    raw[0..2].copy_from_slice(&c_type.to_ne_bytes());
                    raw[2..4].copy_from_slice(&0i16.to_ne_bytes());
                    raw[8..16].copy_from_slice(&(c.start as i64).to_ne_bytes());
                    raw[16..24].copy_from_slice(&c_len.to_ne_bytes());
                    raw[24..28].copy_from_slice(&c.pid.to_ne_bytes());
                } else {
                    raw[0..2].copy_from_slice(&2i16.to_ne_bytes());
                }
                user_access::copy_to_user(space, argument, &raw).map_err(|_| Errno::Fault)?;
                return Ok(0);
            }

            let exclusive = match l_type {
                0 => {
                    if flags & 3 == 1 {
                        return Err(Errno::BadF);
                    }
                    Some(false)
                }
                1 => {
                    if flags & 3 == 0 {
                        return Err(Errno::BadF);
                    }
                    Some(true)
                }
                2 => None,
                _ => return Err(Errno::Invalid),
            };
            let blocking = matches!(command, F_SETLKW | F_OFD_SETLKW);
            fs::locks::set_record_lock(key, owner, exclusive, start, end, blocking)?;
            Ok(0)
        }
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

/// 小读写直接走栈上 256 字节缓冲，避免自旋锁与堆池开销。
const STACK_IO_BUF: usize = 256;
/// `transfer` 复用的单槽 64 KiB 堆暂存池，大幅降低大块文件/管道读写的加锁与分块次数。
const POOL_IO_BUF: usize = 65536;
static IO_SCRATCH: spin::Mutex<Option<Vec<u8>>> = spin::Mutex::new(None);

struct ScratchBuf(Vec<u8>);

impl ScratchBuf {
    fn acquire(cap: usize) -> Result<Self, Errno> {
        let need = cap.max(4096);
        if let Some(mut buf) = IO_SCRATCH.lock().take() {
            if buf.len() >= need {
                return Ok(Self(buf));
            }
            let target = POOL_IO_BUF.max(need);
            buf.clear();
            buf.try_reserve_exact(target).map_err(|_| Errno::NoMem)?;
            buf.resize(target, 0);
            return Ok(Self(buf));
        }
        let alloc_len = POOL_IO_BUF.max(need);
        let mut buf = Vec::new();
        buf.try_reserve_exact(alloc_len).map_err(|_| Errno::NoMem)?;
        buf.resize(alloc_len, 0);
        Ok(Self(buf))
    }
}

impl Drop for ScratchBuf {
    fn drop(&mut self) {
        if self.0.len() == POOL_IO_BUF {
            let mut pool = IO_SCRATCH.lock();
            if pool.is_none() {
                *pool = Some(core::mem::take(&mut self.0));
            }
        }
    }
}

/// 小读写走 256 字节栈缓冲，大读写复用 64 KiB 堆池；发生部分传输后返回已完成长度。
#[inline(never)]
fn transfer(
    space: &UserAddressSpace,
    file: &mut fs::context::OpenFile,
    buffers: &[UserBuffer],
    reading: bool,
    position: Option<usize>,
) -> Result<usize, Errno> {
    let total = buffers
        .iter()
        .fold(0usize, |sum, b| sum.saturating_add(b.len))
        .min(MAX_RW_COUNT);
    if total == 0 {
        return file.check_zero_rw(reading);
    }
    if total <= STACK_IO_BUF {
        let mut stack_buf = [0u8; STACK_IO_BUF];
        return transfer_with_buf(
            space,
            file,
            buffers,
            total,
            reading,
            position,
            &mut stack_buf[..total],
        );
    }
    let cap = total.min(POOL_IO_BUF);
    let mut scratch = ScratchBuf::acquire(cap)?;
    transfer_with_buf(
        space,
        file,
        buffers,
        total,
        reading,
        position,
        &mut scratch.0[..cap],
    )
}

fn transfer_with_buf(
    space: &UserAddressSpace,
    file: &mut fs::context::OpenFile,
    buffers: &[UserBuffer],
    total: usize,
    reading: bool,
    mut position: Option<usize>,
    chunk: &mut [u8],
) -> Result<usize, Errno> {
    let mut user = UserIo {
        buffers,
        index: 0,
        offset: 0,
    };
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
/// faccessat(2)（dirfd, path, mode, 无 flags）：glibc 在某些版本会把
/// 第 4 寄存器残留为任意值，raw 入口不得读取第 4 参数（否则非零残留
/// 被误判为非法 flags，RV glibc which 即因此失败）。
fn faccessat(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    access_check_common(ctx, space, a, true)
}

/// faccessat2(2)（dirfd, path, mode, flags）：flags 接受 AT_EACCESS(0x200)/
/// AT_SYMLINK_NOFOLLOW(0x100)；AT_EACCESS 在无凭证模型下与默认等价。
fn faccessat2(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    access_check_common(ctx, space, a, false)
}

/// access 系列共用主体；`raw` 为 true 时忽略第 4 参数（faccessat 的 ABI）。
fn access_check_common(
    ctx: &Context,
    space: &UserAddressSpace,
    a: [usize; 6],
    raw: bool,
) -> Result<usize, Errno> {
    if !raw && a[3] & !0x300 != 0 {
        return Err(Errno::Invalid);
    }
    let path = ctx.path(a[0], &user_string(space, a[1])?)?;
    let ino = fs::lookup(&path)?;
    let (st_mode, ..) = fs::stat(ino)?;
    let mode = a[2];
    if mode & !0x7 != 0 {
        return Err(Errno::Invalid);
    }
    if mode & 1 != 0 && st_mode & 0o111 == 0 {
        return Err(Errno::Access);
    }
    Ok(0)
}

/// fchmod(2)（fd, mode）：按已打开对象改权限位。fd 以 inode 身份生效，
/// rename/unlink 后仍有效；目标无后备 inode（管道/procfs）时 ENOENT。
fn fchmod(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    ctx.fchmod_fd(a[0], a[1], space)
}

/// fchmodat(2)（dirfd, path, mode）：按路径改权限位，跟随符号链接。
/// 第四个参数不读取；FAT 卷返回 ENOTSUP。
fn fchmodat(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    let path = ctx.path(a[0], &user_string(space, a[1])?)?;
    let ino = fs::lookup(&path)?;
    apply_chmod(path.as_str(), ino, a[2])
}

/// chmod 公共实现：mode 保留 07777（含 setuid/setgid/sticky），类型位由
/// inode 持有；仅普通文件与目录可改。
fn apply_chmod(path: &str, ino: u32, mode: usize) -> Result<usize, Errno> {
    let (cur_mode, ..) = fs::stat(ino)?;
    if cur_mode & 0xf000 != 0x8000 && cur_mode & 0xf000 != 0x4000 {
        return Err(Errno::Invalid); // 仅普通文件与目录可 chmod
    }
    fs::chmod_by_ino(ino, path, mode as u16 & 0o7777)?;
    Ok(0)
}

/// mknodat(2)：仅支持 S_IFBLK 节点注册（授权清单在用户态启动器维护），
/// 登记 (盘, 分区) 身份供 mount 与通用块访问解析；其余类型 EOPNOTSUPP。
fn mknodat(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    // mknodat(dirfd, pathname, mode, dev)：mode 在 a[2]
    let mode = a[2];
    if mode & 0xf000 != 0o060000 {
        return Err(Errno::NotSupported); // 非 S_IFBLK
    }
    let path = ctx.path(a[0], &user_string(space, a[1])?)?;
    if !path.starts_with("/dev/") {
        return Err(Errno::Invalid); // 设备节点必须在 /dev 下
    }
    fs::mknod_blk(&path, mode, a[3] as u64)?;
    Ok(0)
}
/// ioctl(2)：转发到 FD 层按设备类型分派（见 Context::ioctl）。
fn ioctl(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    ctx.ioctl(a[0], a[1], a[2], space)
}

/// Linux sendfile(2)：在两个文件描述符间直接搬运字节，支持可选 offset 指针与阻塞写端。
fn sendfile(ctx: &Context, space: &UserAddressSpace, a: [usize; 6]) -> Result<usize, Errno> {
    const MAX_RW_COUNT: usize = 0x7fff_f000;
    const O_APPEND: usize = 0x400;
    let out_fd = a[0];
    let in_fd = a[1];
    let offset_ptr = a[2];
    let count = a[3].min(MAX_RW_COUNT);

    let out_handle = ctx.get(out_fd)?;
    let in_handle = ctx.get(in_fd)?;
    let same_file = alloc::sync::Arc::ptr_eq(&out_handle, &in_handle);

    // 校验输入/输出描述符读写模式与类型（避免对同一句柄重复加锁死锁）。
    {
        let in_f = in_handle.lock();
        in_f.check_access(true)?;
        if in_f.is_directory() {
            return Err(Errno::Invalid);
        }
        in_f.check_positioned().map_err(|e| match e {
            Errno::SeekPipe => Errno::Invalid,
            other => other,
        })?;
        if same_file {
            in_f.check_access(false)?;
            if in_f.status_flags() & O_APPEND != 0 {
                return Err(Errno::Invalid);
            }
        }
    }
    if !same_file {
        let out_f = out_handle.lock();
        out_f.check_access(false)?;
        if out_f.is_directory() || out_f.status_flags() & O_APPEND != 0 {
            return Err(Errno::Invalid);
        }
    }

    let mut cur_offset = if offset_ptr != 0 {
        let mut raw = [0u8; 8];
        user_access::copy_from_user(space, offset_ptr, &mut raw).map_err(|_| Errno::Fault)?;
        let off = i64::from_ne_bytes(raw);
        if off < 0 {
            return Err(Errno::Invalid);
        }
        Some(off as usize)
    } else {
        None
    };

    if count == 0 {
        if let Some(off) = cur_offset {
            user_access::copy_to_user(space, offset_ptr, &(off as i64).to_ne_bytes())
                .map_err(|_| Errno::Fault)?;
        }
        return Ok(0);
    }

    let mut scratch = ScratchBuf::acquire(count.min(POOL_IO_BUF))?;
    let mut done = 0usize;
    while done < count {
        let chunk = (count - done).min(scratch.0.len());
        let read_n = {
            let mut in_f = in_handle.lock();
            in_f.read_into_buf(cur_offset, &mut scratch.0[..chunk], done == 0)
        };
        let n = match read_n {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if done > 0 => {
                let _ = e;
                break;
            }
            Err(e) => return Err(e),
        };
        let written = {
            let mut out_f = out_handle.lock();
            out_f.write_chunk(&scratch.0[..n], done == 0)
        };
        match written {
            Ok(w) => {
                done += w;
                if let Some(off) = cur_offset.as_mut() {
                    *off = off.saturating_add(w);
                }
                if w < n {
                    // 短写回退输入偏移，避免丢失未写入目标的字节。
                    if cur_offset.is_none() {
                        let mut in_f = in_handle.lock();
                        let pos = in_f.offset().saturating_sub(n - w);
                        in_f.set_offset(pos);
                    }
                    break;
                }
            }
            Err(e) => {
                if cur_offset.is_none() {
                    let mut in_f = in_handle.lock();
                    let pos = in_f.offset().saturating_sub(n);
                    in_f.set_offset(pos);
                }
                if done > 0 {
                    break;
                }
                return Err(e);
            }
        }
    }

    if let Some(off) = cur_offset {
        user_access::copy_to_user(space, offset_ptr, &(off as i64).to_ne_bytes())
            .map_err(|_| Errno::Fault)?;
    }
    Ok(done)
}
