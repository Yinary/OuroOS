//! 文件系统入口，按路径和 inode 将操作转交 Ext4 或 FAT。
use crate::syscall::Errno;
use alloc::sync::Arc;

#[path = "ext4_rsext4.rs"]
mod ext4;

pub mod cache;
pub mod context;
pub mod fat;
pub mod mapping;
mod metadata;
pub mod procfs;

pub(crate) use metadata::{query, Metadata, Timestamp};

/// 文件时间的更新方式；Omit 保留对应字段。
#[derive(Clone, Copy)]
pub(crate) enum TimeUpdate {
    Set(Timestamp),
    Now,
    Omit,
}

/// 按 inode 更新访问、修改时间；FAT 时间字段尚未接通。
pub(crate) fn update_times(ino: u32, times: [TimeUpdate; 2]) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 {
        Err(Errno::NotSupported)
    } else {
        ext4::update_times(ino, times)
    }
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
    ext4::sync()
}

/// 在任务退出后同步并卸载可写 Ext4 根卷。
#[cfg(not(feature = "rsext4-readonly"))]
pub fn shutdown() -> Result<(), Errno> {
    ext4::unmount()
}

/// 按绝对路径查找 inode。
pub fn lookup(path: &str) -> Result<u32, Errno> {
    if path == "/proc" {
        return Ok(procfs::DIR);
    }
    if path == "/proc/meminfo" {
        return Ok(procfs::MEMINFO);
    }
    if path.starts_with("/proc/") {
        return Err(Errno::NoEntry);
    }
    match fat::lookup(path)? {
        Some(ino) => Ok(ino),
        None => ext4::lookup(path),
    }
}

/// 返回 inode 类型、长度、链接数和磁盘占用。
pub fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    if ino == procfs::DIR {
        return Ok((0o040555, 0, 2, 0));
    }
    if ino == procfs::MEMINFO {
        return Ok((0o100444, procfs::meminfo()?.len() as u64, 1, 0));
    }
    if ino & FAT_INODE != 0 {
        fat::stat(ino)
    } else {
        ext4::stat(ino)
    }
}

/// 查询 inode 所属卷的容量；失败返回对应后端错误。
pub(crate) fn filesystem_stats(ino: u32) -> Result<FileSystemStats, Errno> {
    if ino & FAT_INODE != 0 {
        fat::filesystem_stats(ino)
    } else {
        ext4::filesystem_stats()
    }
}

/// 读取符号链接的目标文本；非链接返回 EINVAL，FAT 不提供链接。
pub(crate) fn read_link(ino: u32) -> Result<alloc::string::String, Errno> {
    if ino & FAT_INODE != 0 {
        Err(Errno::Invalid)
    } else {
        ext4::link_target(ino)
    }
}

/// 在指定父目录下创建新对象。
pub fn create(parent: u32, name: &str, mode: u16) -> Result<u32, Errno> {
    if parent & FAT_INODE != 0 {
        fat::create(parent, name, mode)
    } else {
        ext4::create(parent, name, mode)
    }
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
    if old & FAT_INODE != 0 {
        return Err(Errno::NotSupported);
    }
    ext4::rename(old, name, new, target, no_replace)
}

/// 读取文件指定偏移，EOF 返回零。
pub fn read_raw(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    if ino & FAT_INODE != 0 {
        fat::read(ino, offset, data)
    } else {
        ext4::read_raw(ino, offset, data)
    }
}

/// 遍历目录项，回调返回 false 时保留该项供下次读取。
pub(crate) fn read_dir(
    ino: u32,
    offset: usize,
    visit: impl FnMut(DirEntry<'_>) -> bool,
) -> Result<usize, Errno> {
    if ino & FAT_INODE != 0 {
        Err(Errno::NotSupported)
    } else {
        ext4::read_dir(ino, offset, visit)
    }
}

/// 写入文件指定偏移，返回实际字节数。
pub fn write_raw(ino: u32, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    if ino & FAT_INODE != 0 {
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
#[allow(dead_code)] // MM msync 在后续 PR 接入
pub fn sync_mapping(ino: u32, offset: usize, length: usize) -> Result<(), Errno> {
    cache::sync_span(ino, offset, length)?;
    ext4::sync()
}

/// 只读构建没有可写回的后端。
#[cfg(feature = "rsext4-readonly")]
#[allow(dead_code)] // MM msync 在后续 PR 接入
pub fn sync_mapping(_ino: u32, _offset: usize, _length: usize) -> Result<(), Errno> {
    Err(Errno::ReadOnly)
}

/// 持有 inode 的打开引用。
pub fn retain(ino: u32) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 {
        fat::retain(ino)
    } else {
        ext4::retain(ino)
    }
}

/// 释放 inode 的打开引用。
pub fn release(ino: u32) {
    if ino & FAT_INODE != 0 {
        fat::release(ino);
    } else {
        ext4::release(ino);
    }
}

/// 删除目录中的文件名，已打开的 inode 仍可访问。
pub fn unlink(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 {
        fat::unlink(ino)
    } else {
        ext4::unlink(parent, ino, name)
    }
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
