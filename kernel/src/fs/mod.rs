//! 文件系统入口，按路径和 inode 将操作转交对应的卷。
use crate::syscall::Errno;
use alloc::sync::Arc;

#[path = "ext4_rsext4.rs"]
mod ext4;

pub use ext4::mounted;

pub mod cache;
pub mod context;
mod ext2;
mod ext2_mount;
pub mod fat;
pub mod mapping;
mod metadata;
pub mod procfs;

pub(crate) use metadata::{query, Metadata, ResolvedEntry, Timestamp};

/// 文件时间的更新方式；Omit 保留对应字段。
#[derive(Clone, Copy)]
pub(crate) enum TimeUpdate {
    Set(Timestamp),
    Now,
    Omit,
}

/// 按 inode 更新访问、修改时间；FAT 时间字段尚未接通。
pub(crate) fn update_times(ino: u32, times: [TimeUpdate; 2]) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 || ext2_mount::is_handle(ino) {
        Err(Errno::NotSupported)
    } else {
        ext4::update_times(ino, times)
    }
}

/// 更新 Ext4 inode 的属主和属组。None 保留对应字段。
pub(crate) fn set_owner(
    ino: u32,
    uid: Option<u32>,
    gid: Option<u32>,
    credentials: &crate::task::Credentials,
) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 || ext2_mount::is_handle(ino) || procfs::pid_ino_parts(ino).is_some() {
        return Err(Errno::NotSupported);
    }
    let info = ext4::metadata(ino)?;
    if credentials.euid != 0 {
        let changes_owner = uid.is_some_and(|uid| uid != info.uid);
        let forbidden_group = gid.is_some_and(|gid| {
            gid != info.gid && gid != credentials.fsgid && !credentials.groups.contains(&gid)
        });
        if credentials.fsuid != info.uid || changes_owner || forbidden_group {
            return Err(Errno::Perm);
        }
    }
    ext4::set_owner(ino, uid, gid)
}

/// 已挂载文件系统的容量快照，块数以 block_size 字节为单位。
pub(crate) struct FileSystemStats {
    pub kind: u64,
    pub block_size: u64,
    pub blocks: u64,
    pub free_blocks: u64,
    pub available_blocks: u64,
    pub files: u64,
    pub free_files: u64,
    pub id: u64,
    pub flags: u64,
}

const FAT_INODE: u32 = 0x8000_0000;

/// 文件系统返回的目录项类型。
pub(crate) enum DirEntryKind {
    Unknown,
    File,
    Directory,
    Character,
    Block,
    Fifo,
    Socket,
    Symlink,
}

/// 目录项及其后端提供的续读位置。
pub(crate) struct DirEntry<'a> {
    pub(crate) inode: u32,
    pub(crate) kind: DirEntryKind,
    pub(crate) name: &'a [u8],
    pub(crate) next: usize,
}

/// 初始化 Ext4 根卷；无磁盘时允许继续启动。
pub fn init() -> Result<(), Errno> {
    ext4::init()
}

/// 写回 inode 的共享页和 Ext4 卷缓存。
#[cfg(not(feature = "rsext4-readonly"))]
pub(crate) fn sync_inode(ino: u32) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 {
        return Err(Errno::NotSupported);
    }
    cache::sync_inode(ino)?;
    if ext2_mount::is_handle(ino) {
        ext2_mount::sync(Some(ino))
    } else {
        ext4::sync()
    }
}

/// 同步全部已挂载可写文件系统缓存。
pub(crate) fn sync() -> Result<(), Errno> {
    #[cfg(not(feature = "rsext4-readonly"))]
    {
        ext4::sync()?;
        ext2_mount::sync(None)?;
    }
    Ok(())
}

/// 在任务退出后同步并卸载可写 Ext4 根卷。
#[cfg(not(feature = "rsext4-readonly"))]
pub fn shutdown() -> Result<(), Errno> {
    ext2_mount::shutdown()?;
    ext4::unmount()
}

/// 挂载辅助卷，或把已挂载的 Ext2 卷切换到只读模式。
pub(crate) fn mount(source: &str, target: &str, kind: &str, flags: usize) -> Result<(), Errno> {
    const MS_RDONLY: usize = 1;
    const MS_REMOUNT: usize = 32;

    match kind {
        "ext2" => {
            let (target, info) = metadata::resolve(target, true)?;
            if info.mode & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            if flags == (MS_REMOUNT | MS_RDONLY) {
                return ext2_mount::remount_readonly(&target);
            }
            if flags & !MS_RDONLY != 0 {
                return Err(Errno::NotSupported);
            }
            if target == "/"
                || target.starts_with("/proc/")
                || target == "/proc"
                || target == "/dev"
                || target.starts_with("/dev/")
                || context::directory_busy(&target)
                || contains_mount(&target)
                || info.dev != 1
            {
                return Err(Errno::Busy);
            }
            let (disk, part) = fat::resolve_source(source)?;
            if ext4::uses_disk(disk) || fat::uses_disk(disk) || ext2_mount::uses_disk(disk) {
                return Err(Errno::Busy);
            }
            let (start, len) =
                crate::drivers::partition(disk, part).map_err(|_| Errno::NoDevice)?;
            let readonly = flags & MS_RDONLY != 0 || cfg!(feature = "rsext4-readonly");
            ext2_mount::mount(source, &target, disk, start, len, readonly)
        }
        "fat" | "vfat" => {
            if flags != 0 {
                return Err(Errno::NotSupported);
            }
            let ino = lookup(target)?;
            if stat(ino)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            let (disk, _) = fat::resolve_source(source)?;
            if ext2_mount::is_handle(ino)
                || ext2_mount::contains_mount(target)
                || ext2_mount::uses_disk(disk)
            {
                return Err(Errno::Busy);
            }
            fat::mount(source, target)
        }
        _ => Err(Errno::NoDevice),
    }
}

/// 卸载指定挂载点。Ext2 有存活引用时返回 EBUSY。
pub(crate) fn unmount(target: &str, privileged: bool) -> Result<(), Errno> {
    let resolved;
    let ext2_target = if ext2_mount::is_mountpoint(target) {
        Some(target)
    } else if let Ok((path, _)) = metadata::resolve(target, true) {
        resolved = path;
        ext2_mount::is_mountpoint(&resolved).then_some(resolved.as_str())
    } else {
        None
    };
    if let Some(path) = ext2_target {
        return if privileged {
            ext2_mount::unmount(path)
        } else {
            Err(Errno::Perm)
        };
    }
    fat::unmount(target)
}

/// 用户态 mknodat 注册的块设备节点：(节点名, 盘号, 分区号)。
/// 节点由授权清单显式创建（mknodat S_IFBLK），绑定真实总线设备身份；
/// mount 与通用块访问按节点记录的身份解析。同名注册返回 EEXIST。
static DEVICE_NODES: crate::sync::DebugMutex<
    alloc::vec::Vec<(alloc::string::String, usize, usize)>,
> = crate::sync::DebugMutex::new("DEVICE_NODES", alloc::vec::Vec::new());

/// mknodat(2) 的 S_IFBLK 分支：注册块设备节点。
/// `dev` 编码目标身份：minor = (盘号 << 4) | 分区号；major 校验须为本内
/// 核分配的块设备 major（254）。盘号/分区号必须真实存在（总线枚举取
/// 得），否则 ENODEV。
pub fn mknod_blk(name: &str, mode: usize, dev: u64) -> Result<(), Errno> {
    if name == "zero" {
        return Err(Errno::Exists);
    }
    let major = (dev >> 8) & 0xfff;
    let minor = dev & 0xff; // minor ≤ 255 场景（本内核盘数/分区数远小于）
                            // 本内核所有 virtio-blk 固定 major 254（自分配块设备号空间）
    const BLK_MAJOR: u64 = 254;
    if mode & 0xf000 != 0o060000 {
        return Err(Errno::Invalid);
    }
    let disk = (minor >> 4) as usize;
    let part = (minor & 0xf) as usize;
    if major != BLK_MAJOR {
        return Err(Errno::NoDevice);
    }
    if crate::drivers::partition(disk, part).is_err() {
        return Err(Errno::NoDevice);
    }
    let mut nodes = DEVICE_NODES.lock();
    if nodes.iter().any(|(n, ..)| n == name) {
        return Err(Errno::Exists);
    }
    nodes.try_reserve(1).map_err(|_| Errno::NoMem)?;
    nodes.push((alloc::string::String::from(name), disk, part));
    Ok(())
}

/// 按名字查块设备节点身份（mount 与通用块访问用）。
pub fn lookup_blk_node(name: &str) -> Option<(usize, usize)> {
    DEVICE_NODES
        .lock()
        .iter()
        .find(|(n, ..)| n == name)
        .map(|&(_, d, p)| (d, p))
}

/// 按绝对路径查找 inode。
pub fn lookup(path: &str) -> Result<u32, Errno> {
    if path == "/dev/null" {
        return Ok(procfs::DEVNULL);
    }
    if path == "/dev/zero" {
        return Ok(procfs::DEVZERO);
    }
    if path == "/dev/urandom" {
        return Ok(procfs::DEVURANDOM);
    }
    if path == "/dev/random" {
        return Ok(procfs::DEVRANDOM);
    }
    if path == "/dev" {
        return Ok(ext4::lookup("/dev").unwrap_or(procfs::DEVDIR));
    }
    if path == "/dev/misc" {
        return Ok(procfs::MISC_DIR);
    }
    if path == "/dev/misc/rtc" {
        return Ok(procfs::RTC);
    }
    if path.starts_with("/dev/") {
        // mknodat 注册的块设备节点（如 /dev/vda2）优先；其余路径（如 /dev/shm）交由后端解析。
        if lookup_blk_node(path).is_some() {
            return Ok(procfs::DEVBLK);
        }
    }
    if path == "/proc" {
        return Ok(procfs::DIR);
    }
    if path == "/proc/meminfo" {
        return Ok(procfs::MEMINFO);
    }
    if path == "/proc/cpuinfo" {
        return Ok(procfs::CPUINFO);
    }
    if path == "/proc/mounts" {
        return Ok(procfs::MOUNTS);
    }
    if let Some(rest) = path.strip_prefix("/proc/") {
        // /proc/<pid> 与 /proc/<pid>/{stat,cmdline}；只接受纯数字 pid
        let (pid, file) = match rest.split_once('/') {
            Some((p, f)) => (p, f),
            None => (rest, ""),
        };
        if !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) {
            let Ok(pid) = pid.parse::<u32>() else {
                return Err(Errno::NoEntry);
            };
            let base = procfs::pid_dir_ino(pid);
            return match file {
                "" => Ok(base),
                "stat" => Ok(base + 1),
                "cmdline" => Ok(base + 2),
                "status" => Ok(base + 3),
                _ => Err(Errno::NoEntry),
            };
        }
        return Err(Errno::NoEntry);
    }
    if let Some(ino) = ext2_mount::lookup(path)? {
        return Ok(ino);
    }
    match fat::lookup(path)? {
        Some(ino) => Ok(ino),
        None => ext4::lookup(path),
    }
}

/// 返回 inode 类型、长度、链接数和磁盘占用。
pub fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    if matches!(
        ino,
        procfs::DEVNULL | procfs::DEVZERO | procfs::DEVURANDOM | procfs::DEVRANDOM
    ) {
        return Ok((0o020666, 0, 1, 0));
    }
    if ino == procfs::DEVDIR || ino == procfs::MISC_DIR {
        return Ok((0o040555, 0, 2, 0));
    }
    if ino == procfs::RTC {
        return Ok((0o020600, 0, 1, 0));
    }
    if ino == procfs::MOUNTS {
        return Ok((0o100444, procfs::mounts()?.len() as u64, 1, 0));
    }
    if ino == procfs::CPUINFO {
        return Ok((0o100444, procfs::cpuinfo()?.len() as u64, 1, 0));
    }
    if let Some((pid, file)) = procfs::pid_ino_parts(ino) {
        return match file {
            0 => Ok((0o040555, 0, 2, 0)),
            1 => Ok((0o100444, procfs::pid_stat(pid)?.len() as u64, 1, 0)),
            2 => Ok((0o100444, procfs::pid_cmdline(pid)?.len() as u64, 1, 0)),
            _ => Ok((0o100444, procfs::pid_status(pid)?.len() as u64, 1, 0)),
        };
    }
    if ino == procfs::DIR {
        return Ok((0o040555, 0, 2, 0));
    }
    if ext2_mount::is_handle(ino) {
        ext2_mount::stat(ino)
    } else if ino & FAT_INODE != 0 {
        fat::stat(ino)
    } else {
        ext4::stat(ino)
    }
}

/// 查询 inode 所属卷的容量；失败返回对应后端错误。
pub(crate) fn filesystem_stats(ino: u32) -> Result<FileSystemStats, Errno> {
    if ext2_mount::is_handle(ino) {
        ext2_mount::filesystem_stats(ino)
    } else if ino & FAT_INODE != 0 {
        fat::filesystem_stats(ino)
    } else {
        ext4::filesystem_stats()
    }
}

/// 读取符号链接的目标文本；非链接返回 EINVAL，FAT 不提供链接。
pub(crate) fn read_link(ino: u32) -> Result<alloc::string::String, Errno> {
    if ext2_mount::is_handle(ino) {
        ext2_mount::read_link(ino)
    } else if ino & FAT_INODE != 0 {
        Err(Errno::Invalid)
    } else {
        ext4::link_target(ino)
    }
}

/// 在指定父目录下创建新对象。
pub fn create(parent: u32, name: &str, mode: u16) -> Result<u32, Errno> {
    if parent == procfs::DEVDIR {
        let dev_ino = match ext4::lookup("/dev") {
            Ok(ino) => ino,
            Err(Errno::NoEntry) => {
                let root = ext4::lookup("/")?;
                ext4::create(root, "dev", 0o040755)?
            }
            Err(e) => return Err(e),
        };
        return ext4::create(dev_ino, name, mode);
    }
    if ext2_mount::is_handle(parent) {
        return Err(Errno::NotSupported);
    }
    if parent & FAT_INODE != 0 {
        fat::create(parent, name, mode)
    } else {
        ext4::create(parent, name, mode)
    }
}

/// 创建普通文件，Ext2 使用调用进程的文件系统凭证。
pub(crate) fn create_regular(
    parent: u32,
    name: &str,
    mode: u16,
    owner: (u32, u32),
) -> Result<u32, Errno> {
    if ext2_mount::is_handle(parent) {
        ext2_mount::create(parent, name, mode, owner)
    } else {
        create(parent, name, mode)
    }
}

/// 拒绝以可写模式打开只读辅助卷上的文件。
pub(crate) fn check_write_open(ino: u32) -> Result<(), Errno> {
    if ext2_mount::is_handle(ino) && ext2_mount::readonly(ino)? {
        return Err(Errno::ReadOnly);
    }
    Ok(())
}

/// 在 Ext4 上创建命名管道节点，权限已由调用方应用 umask。
pub(crate) fn create_fifo(
    parent: u32,
    name: &str,
    mode: u16,
    owner: (u32, u32),
) -> Result<(), Errno> {
    if parent & FAT_INODE != 0
        || ext2_mount::is_handle(parent)
        || procfs::pid_ino_parts(parent).is_some()
    {
        return Err(Errno::NotSupported);
    }
    ext4::create_fifo(parent, name, mode, owner)
}

/// 确认块设备当前没有已挂载卷，供原始写入路径检查。
pub(crate) fn check_raw_disk_write(disk: usize) -> Result<(), Errno> {
    if cfg!(feature = "rsext4-readonly") {
        return Err(Errno::ReadOnly);
    }
    if ext4::uses_disk(disk) || fat::uses_disk(disk) || ext2_mount::uses_disk(disk) {
        return Err(Errno::Busy);
    }
    Ok(())
}

/// 在 Ext4 父目录中添加符号链接。
pub(crate) fn symlink(
    parent: u32,
    name: &str,
    target: &str,
    uid: u32,
    gid: u32,
) -> Result<(), Errno> {
    if parent & FAT_INODE != 0
        || ext2_mount::is_handle(parent)
        || procfs::pid_ino_parts(parent).is_some()
    {
        return Err(Errno::Perm);
    }
    ext4::symlink(parent, name, target, uid, gid)
}

/// 在同一 Ext4 挂载内为普通文件或符号链接添加硬链接。
pub(crate) fn link(source: &Metadata, parent: u32, name: &str) -> Result<(), Errno> {
    if source.dev != metadata::metadata(parent)?.dev {
        return Err(Errno::CrossDevice);
    }
    let ino = source.inode_handle();
    if ext2_mount::is_handle(parent) {
        return ext2_mount::link(ino, parent, name);
    }
    if ino & FAT_INODE != 0
        || procfs::pid_ino_parts(ino).is_some()
        || !matches!(source.mode & 0xf000, 0x8000 | 0xa000 | 0x1000)
    {
        return Err(Errno::Perm);
    }
    ext4::link(ino, parent, name)
}

/// 在同一挂载内改名；FAT 暂不支持，跨挂载返回 EXDEV。
pub(crate) fn rename(
    old: u32,
    name: &str,
    new: u32,
    target: &str,
    no_replace: bool,
) -> Result<(), Errno> {
    if metadata::metadata(old)?.dev != metadata::metadata(new)?.dev {
        return Err(Errno::CrossDevice);
    }
    if ext2_mount::is_handle(old) || ext2_mount::is_handle(new) {
        return Err(Errno::NotSupported);
    }
    if old & FAT_INODE != 0 {
        return Err(Errno::NotSupported);
    }
    ext4::rename(old, name, new, target, no_replace)
}

/// 读取文件指定偏移，EOF 返回零。
pub fn read_raw(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    if ext2_mount::is_handle(ino) {
        ext2_mount::read_raw(ino, offset, data)
    } else if ino & FAT_INODE != 0 {
        fat::read(ino, offset, data)
    } else {
        ext4::read_raw(ino, offset, data)
    }
}

/// 遍历目录项，回调返回 false 时保留该项供下次读取。
pub(crate) fn read_dir(
    ino: u32,
    offset: usize,
    mut visit: impl FnMut(DirEntry<'_>) -> bool,
) -> Result<usize, Errno> {
    // /proc 与 /proc/<pid>：条目来自 Task 的独立快照表（PROC_TABLE 专用
    // 锁，锁序 REGISTRY→PROC_TABLE 单向；FS 读路径在此处已持 REGISTRY，
    // 同向取内层锁无环）。分配失败向上传播。
    if ino == procfs::DIR || procfs::pid_ino_parts(ino).is_some() {
        let mut out: alloc::vec::Vec<(u32, &'static [u8], u32)> = alloc::vec::Vec::new();
        out.try_reserve_exact(8).map_err(|_| Errno::NoMem)?;
        if ino == procfs::DIR {
            out.push((procfs::DIR, b"self", procfs::DIR));
            out.push((procfs::MEMINFO, b"meminfo", procfs::MEMINFO));
            out.push((procfs::MOUNTS, b"mounts", procfs::MOUNTS));
            out.push((procfs::CPUINFO, b"cpuinfo", procfs::CPUINFO));
            for (pid, ..) in crate::task::proc_table_snapshot() {
                let ino = procfs::pid_dir_ino(pid);
                let name = alloc::format!("{}", pid);
                out.try_reserve_exact(1).map_err(|_| Errno::NoMem)?;
                let leaked: &'static [u8] =
                    alloc::boxed::Box::leak(name.into_bytes().into_boxed_slice());
                out.push((ino, leaked, ino));
            }
        } else {
            let Some((pid, _)) = procfs::pid_ino_parts(ino) else {
                return Ok(offset);
            };
            let Some((_, _, _, Some(cmdline))) = crate::task::proc_table_lookup(pid) else {
                return Ok(offset);
            };
            let _ = cmdline;
            out.push((ino + 1, b"stat", ino + 1));
            out.push((ino + 2, b"cmdline", ino + 2));
            out.push((ino + 3, b"status", ino + 3));
        }
        let mut next = offset;
        for (entry_ino, name, _) in out.iter().skip(offset) {
            let kind = if procfs::pid_ino_parts(*entry_ino).is_some_and(|(_, f)| f == 0)
                || *entry_ino == procfs::DIR
                || *entry_ino == procfs::DEVDIR
            {
                DirEntryKind::Directory
            } else {
                DirEntryKind::File
            };
            next += 1;
            if !visit(DirEntry {
                inode: *entry_ino,
                kind,
                name,
                next,
            }) {
                break;
            }
        }
        return Ok(next);
    }
    if ext2_mount::is_handle(ino) {
        ext2_mount::read_dir(ino, offset, visit)
    } else if ino & FAT_INODE != 0 {
        Err(Errno::NotSupported)
    } else {
        ext4::read_dir(ino, offset, visit)
    }
}

/// 写入文件指定偏移，返回实际字节数。
pub fn write_raw(ino: u32, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    if ext2_mount::is_handle(ino) {
        ext2_mount::write_raw(ino, offset, data)
    } else if ino & FAT_INODE != 0 {
        fat::write(ino, offset, data)
    } else {
        ext4::write_raw(ino, offset, data)
    }
}

/// 调整普通文件长度；有 MM hooks 时通知其撤销映射，否则拒绝存活共享页。
pub fn truncate(ino: u32, length: u64) -> Result<(), Errno> {
    let (mode, current, _, _) = stat(ino)?;
    if mode & 0xf000 == 0x4000 {
        return Err(Errno::IsDir);
    }
    if mode & 0xf000 != 0x8000 {
        return Err(Errno::Invalid);
    }
    if ext2_mount::is_handle(ino) {
        check_write_open(ino)?;
        return if current == length {
            Ok(())
        } else {
            Err(Errno::NotSupported)
        };
    }
    if current != length {
        if cache::has_live(ino) && !mapping::registered() {
            return Err(Errno::NotSupported);
        }
        mapping::prepare_resize(ino, current, length)?;
    }
    let result = if ino & FAT_INODE != 0 {
        if length == 0 {
            fat::truncate(ino)
        } else {
            Err(Errno::NotSupported)
        }
    } else {
        ext4::truncate(ino, length)
    };
    if result.is_ok() && current != length {
        cache::resize_inode(ino, current as usize, length as usize);
        mapping::commit_resize(ino, current, length);
    }
    result
}

/// 同步指定 inode 的共享文件页范围。
#[cfg(not(feature = "rsext4-readonly"))]
pub fn sync_mapping(ino: u32, offset: usize, length: usize) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 {
        return Err(Errno::NotSupported);
    }
    cache::sync_span(ino, offset, length)?;
    if ext2_mount::is_handle(ino) {
        ext2_mount::sync(Some(ino))
    } else {
        ext4::sync()
    }
}

/// 只读构建没有可写回的后端。
#[cfg(feature = "rsext4-readonly")]
pub fn sync_mapping(_ino: u32, _offset: usize, _length: usize) -> Result<(), Errno> {
    Err(Errno::ReadOnly)
}

/// 持有 inode 的打开引用。
pub fn retain(ino: u32) -> Result<(), Errno> {
    // procfs 虚拟节点（/proc、/proc/<pid>、/dev/*）无后端引用计数
    if ino == procfs::CPUINFO || ino >= procfs::MISC_DIR || procfs::pid_ino_parts(ino).is_some() {
        return Ok(());
    }
    if ext2_mount::is_handle(ino) {
        ext2_mount::retain(ino)
    } else if ino & FAT_INODE != 0 {
        fat::retain(ino)
    } else {
        ext4::retain(ino)
    }
}

/// 释放 inode 的打开引用。
pub fn release(ino: u32) {
    if ino == procfs::CPUINFO || ino >= procfs::MISC_DIR || procfs::pid_ino_parts(ino).is_some() {
        return;
    }
    if ext2_mount::is_handle(ino) {
        ext2_mount::release(ino);
    } else if ino & FAT_INODE != 0 {
        fat::release(ino);
    } else {
        ext4::release(ino);
    }
}

/// 删除目录中的文件名，已打开的 inode 仍可访问。
pub fn unlink(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    if ext2_mount::is_handle(ino) || ext2_mount::is_handle(parent) {
        ext2_mount::unlink(parent, ino, name)
    } else if ino & FAT_INODE != 0 {
        fat::unlink(ino)
    } else {
        ext4::unlink(parent, ino, name)
    }
}

/// procfs 只读文本文件的内容快照（open 时捕获一次）。
pub fn procfs_text(path: &str) -> Result<alloc::string::String, Errno> {
    if path == "/proc/cpuinfo" {
        return procfs::cpuinfo();
    }
    if path == "/proc/mounts" {
        return procfs::mounts();
    }
    if let Some(rest) = path.strip_prefix("/proc/") {
        if let Some((pid, file)) = rest.split_once('/') {
            if !pid.bytes().all(|b| b.is_ascii_digit()) || pid.is_empty() {
                return Err(Errno::NoEntry);
            }
            let Ok(pid) = pid.parse::<u32>() else {
                return Err(Errno::NoEntry);
            };
            return match file {
                "stat" => procfs::pid_stat(pid),
                "cmdline" => procfs::pid_cmdline(pid),
                "status" => procfs::pid_status(pid),
                _ => Err(Errno::NoEntry),
            };
        }
    }
    Err(Errno::NoEntry)
}

/// 路径本身或其子目录是否存在辅助卷挂载点。
pub fn contains_mount(path: &str) -> bool {
    fat::contains_mount(path) || ext2_mount::contains_mount(path)
}

/// chmod 公共校验与执行：仅普通文件与目录，mode 保留 07777；space 仅
/// 用于最终的用户拷贝路径（当前实现无数据交付，预留签名一致性）。
pub fn chmod_apply(
    path: &str,
    ino: u32,
    mode: usize,
    _space: &crate::mm::address_space::UserAddressSpace,
) -> Result<usize, Errno> {
    let (cur_mode, ..) = stat(ino)?;
    if cur_mode & 0xf000 != 0x8000 && cur_mode & 0xf000 != 0x4000 {
        return Err(Errno::Invalid); // 仅普通文件与目录可 chmod
    }
    chmod_by_ino(ino, path, mode as u16 & 0o7777)?;
    Ok(0)
}

/// chmod(2) 底层：按 inode 身份更新权限位（fd 与路径解析殊途同归到
/// inode）；FAT 卷不支持（权限位为固定 0777 合成）。
pub fn chmod_by_ino(ino: u32, path: &str, mode: u16) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 || ext2_mount::is_handle(ino) {
        return Err(Errno::NotSupported);
    }
    ext4::chmod_by_ino(ino, path, mode)
}

/// 删除空目录（rmdir 语义）；FAT 未接入目录删除，返回 ENOTSUP。
pub fn rmdir(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    if (parent | ino) & FAT_INODE != 0
        || ext2_mount::is_handle(parent)
        || ext2_mount::is_handle(ino)
        || procfs::pid_ino_parts(ino).is_some()
    {
        return Err(Errno::NotSupported);
    }
    ext4::rmdir(parent, ino, name)?;
    context::detach_directory(ino);
    Ok(())
}

/// 读取文件并叠加尚未写回的共享页。
pub fn read(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    offset.checked_add(data.len()).ok_or(Errno::Invalid)?;
    let n = read_raw(ino, offset, data)?;
    cache::coherent(ino, offset, &mut data[..n], false);
    Ok(n)
}
/// 写磁盘后同步共享页。
pub fn write(ino: u32, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    let old = stat(ino)?.1 as usize;
    let n = write_raw(ino, offset, data)?;
    let end = offset.checked_add(n).ok_or(Errno::Invalid)?;
    if end > old {
        cache::resize_inode(ino, old, end);
        mapping::commit_resize(ino, old as u64, end as u64);
    }
    let mut buf = [0; 4096];
    let mut done = 0;
    while done < n {
        let k = (n - done).min(buf.len());
        buf[..k].copy_from_slice(&data[done..done + k]);
        cache::coherent(ino, offset + done, &mut buf[..k], true);
        done += k;
    }
    Ok(n)
}

/// 用户路径使用可失败的引用计数分配。
pub fn try_arc<T>(value: T) -> Result<Arc<T>, Errno> {
    Arc::try_new(value).map_err(|_| Errno::NoMem)
}
