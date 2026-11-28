//! 非根 Ext2 卷的挂载、分区访问和 inode 句柄。
#![deny(unsafe_code)]

use super::{
    ext2::{self, Device, Error, Volume, ROOT_INODE},
    DirEntry, DirEntryKind, FileSystemStats, Metadata, Timestamp,
};
use crate::{drivers, syscall::Errno};
use alloc::{string::String, vec::Vec};
use spin::Mutex;

pub(super) const FIRST_HANDLE: u32 = 0x2000_0000;
const END_HANDLE: u32 = 0x4000_0000;

static MOUNTS: Mutex<Mounts> = Mutex::new(Mounts {
    volumes: Vec::new(),
    next_handle: FIRST_HANDLE,
    next_dev: 0x1_0000_0000,
});

struct Mounts {
    volumes: Vec<Mount>,
    next_handle: u32,
    next_dev: u64,
}

struct Mount {
    volume: Volume<Partition>,
    disk: usize,
    source: String,
    target: String,
    dev: u64,
    nodes: Vec<Node>,
}

struct Node {
    handle: u32,
    ino: u32,
    refs: usize,
}

struct Partition {
    disk: usize,
    start: usize,
    len: usize,
}

impl Partition {
    fn offset(&self, offset: u64, len: usize) -> ext2::Result<usize> {
        let offset = usize::try_from(offset).map_err(|_| Error::Range)?;
        if offset
            .checked_add(len)
            .filter(|end| *end <= self.len)
            .is_none()
        {
            return Err(Error::Range);
        }
        self.start.checked_add(offset).ok_or(Error::Range)
    }
}

impl Device for Partition {
    fn len(&self) -> u64 {
        self.len as u64
    }

    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> ext2::Result<()> {
        let offset = self.offset(offset, dst.len())?;
        drivers::read_bytes(self.disk, offset, dst).map_err(|_| Error::Io)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> ext2::Result<()> {
        let offset = self.offset(offset, data.len())?;
        drivers::write_bytes(self.disk, offset, data).map_err(|_| Error::Io)
    }

    fn flush(&mut self) -> ext2::Result<()> {
        drivers::flush(self.disk).map_err(|_| Error::Io)
    }
}

fn error(err: Error) -> Errno {
    match err {
        Error::Io => Errno::Io,
        Error::Invalid => Errno::Invalid,
        Error::Unsupported => Errno::NotSupported,
        Error::ReadOnly => Errno::ReadOnly,
        Error::NotFound => Errno::NoEntry,
        Error::Exists => Errno::Exists,
        Error::NotDir => Errno::NotDir,
        Error::IsDir => Errno::IsDir,
        Error::NoSpace => Errno::NoSpace,
        Error::TooManyLinks => Errno::TooManyLinks,
        Error::Range => Errno::Range,
        Error::NoMemory => Errno::NoMem,
    }
}

fn string(text: &str) -> Result<String, Errno> {
    let mut out = String::new();
    out.try_reserve_exact(text.len())
        .map_err(|_| Errno::NoMem)?;
    out.push_str(text);
    Ok(out)
}

fn within(path: &str, target: &str) -> bool {
    target == "/"
        || path == target
        || path
            .strip_prefix(target)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn node_index(mount: &Mount, handle: u32) -> Result<usize, Errno> {
    mount
        .nodes
        .iter()
        .position(|node| node.handle == handle)
        .ok_or(Errno::NoEntry)
}

fn reserve_handle(mount: &mut Mount, next: u32) -> Result<(), Errno> {
    if next == END_HANDLE {
        return Err(Errno::TooManyFiles);
    }
    mount.nodes.try_reserve(1).map_err(|_| Errno::NoMem)
}

fn insert_node(mount: &mut Mount, next: &mut u32, ino: u32) -> u32 {
    let handle = *next;
    *next += 1;
    mount.nodes.push(Node {
        handle,
        ino,
        refs: 0,
    });
    handle
}

fn access<T>(
    handle: u32,
    f: impl FnOnce(&mut Mount, usize) -> Result<T, Errno>,
) -> Result<T, Errno> {
    let mut mounts = MOUNTS.lock();
    let (mount, index) = mounts
        .volumes
        .iter_mut()
        .find_map(|mount| node_index(mount, handle).ok().map(|index| (mount, index)))
        .ok_or(Errno::NoEntry)?;
    f(mount, index)
}

/// 判断内核 inode 句柄是否属于 Ext2。
pub(super) fn is_handle(ino: u32) -> bool {
    (FIRST_HANDLE..END_HANDLE).contains(&ino)
}

/// 打开分区并验证 Ext2 卷，成功后登记挂载点。
pub(super) fn mount(
    source: &str,
    target: &str,
    disk: usize,
    start: usize,
    len: usize,
    readonly: bool,
) -> Result<(), Errno> {
    if target == "/" {
        return Err(Errno::Busy);
    }
    let capacity = drivers::capacity(disk)
        .map_err(|_| Errno::NoDevice)?
        .checked_mul(512)
        .ok_or(Errno::Range)?;
    if start
        .checked_add(len)
        .filter(|end| *end as u64 <= capacity)
        .is_none()
    {
        return Err(Errno::Range);
    }

    let mut mounts = MOUNTS.lock();
    if mounts
        .volumes
        .iter()
        .any(|m| m.disk == disk || within(target, &m.target) || within(&m.target, target))
    {
        return Err(Errno::Busy);
    }
    mounts.volumes.try_reserve(1).map_err(|_| Errno::NoMem)?;
    let source = string(source)?;
    let target = string(target)?;
    let dev = mounts.next_dev;
    let next_dev = dev.checked_add(1).ok_or(Errno::TooManyFiles)?;
    let volume = Volume::open(Partition { disk, start, len }, readonly).map_err(error)?;
    mounts.volumes.push(Mount {
        volume,
        disk,
        source,
        target,
        dev,
        nodes: Vec::new(),
    });
    mounts.next_dev = next_dev;
    Ok(())
}

/// 当前是否存在辅助 Ext2 挂载，供根卷快速查询判断路径归属。
pub(super) fn has_mounts() -> bool {
    !MOUNTS.lock().volumes.is_empty()
}

/// 判断路径是否正好是 Ext2 挂载点。
pub(super) fn is_mountpoint(path: &str) -> bool {
    MOUNTS.lock().volumes.iter().any(|m| m.target == path)
}

/// 判断路径或其子目录是否包含 Ext2 挂载点。
pub(super) fn contains_mount(path: &str) -> bool {
    MOUNTS
        .lock()
        .volumes
        .iter()
        .any(|m| within(&m.target, path))
}

/// 判断磁盘是否有挂载中的 Ext2 分区。
pub(super) fn uses_disk(disk: usize) -> bool {
    MOUNTS.lock().volumes.iter().any(|m| m.disk == disk)
}

/// 复制挂载源、挂载点和只读状态供 /proc/mounts 使用。
pub(super) fn mount_list() -> Result<Vec<(String, String, bool)>, Errno> {
    let mounts = MOUNTS.lock();
    let mut list = Vec::new();
    list.try_reserve_exact(mounts.volumes.len())
        .map_err(|_| Errno::NoMem)?;
    for mount in &mounts.volumes {
        list.push((
            string(&mount.source)?,
            string(&mount.target)?,
            mount.volume.readonly(),
        ));
    }
    Ok(list)
}

/// 解析 Ext2 卷内路径。命中挂载点后的查找错误直接返回。
pub(super) fn lookup(path: &str) -> Result<Option<u32>, Errno> {
    let mut mounts = MOUNTS.lock();
    let Mounts {
        volumes,
        next_handle,
        ..
    } = &mut *mounts;
    let Some(mount) = volumes.iter_mut().find(|m| within(path, &m.target)) else {
        return Ok(None);
    };
    let mut ino = ROOT_INODE;
    for name in path[mount.target.len()..]
        .split('/')
        .filter(|name| !name.is_empty())
    {
        ino = mount.volume.lookup(ino, name.as_bytes()).map_err(error)?;
    }
    if let Some(node) = mount.nodes.iter().find(|n| n.ino == ino) {
        return Ok(Some(node.handle));
    }
    reserve_handle(mount, *next_handle)?;
    Ok(Some(insert_node(mount, next_handle, ino)))
}

/// 检查卷是否仍有文件或目录引用。
fn require_idle(mount: &Mount) -> Result<(), Errno> {
    if mount.nodes.iter().any(|node| node.refs != 0) {
        return Err(Errno::Busy);
    }
    Ok(())
}

/// 刷写无打开引用的卷，切换为只读挂载。
pub(super) fn remount_readonly(target: &str) -> Result<(), Errno> {
    let mut mounts = MOUNTS.lock();
    let mount = mounts
        .volumes
        .iter_mut()
        .find(|m| m.target == target)
        .ok_or(Errno::Invalid)?;
    if mount.volume.readonly() {
        return Ok(());
    }
    require_idle(mount)?;
    mount.volume.set_readonly().map_err(error)
}

/// 若卷无存活引用，刷写成功后移除其挂载记录。
pub(super) fn unmount(target: &str) -> Result<(), Errno> {
    let mut mounts = MOUNTS.lock();
    let index = mounts
        .volumes
        .iter()
        .position(|m| m.target == target)
        .ok_or(Errno::Invalid)?;
    let mount = &mut mounts.volumes[index];
    require_idle(mount)?;
    mount.volume.sync().map_err(error)?;
    mounts.volumes.remove(index);
    Ok(())
}

/// 同步句柄所属的卷，或同步所有 Ext2 卷。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn sync(ino: Option<u32>) -> Result<(), Errno> {
    if let Some(ino) = ino {
        return access(ino, |m, _| m.volume.sync().map_err(error));
    }
    for mount in &mut MOUNTS.lock().volumes {
        mount.volume.sync().map_err(error)?;
    }
    Ok(())
}

/// 按卷刷写，并在确认所有卷均无存活引用后清除挂载记录。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn shutdown() -> Result<(), Errno> {
    let mut mounts = MOUNTS.lock();
    for mount in &mounts.volumes {
        require_idle(mount)?;
    }
    for mount in &mut mounts.volumes {
        mount.volume.sync().map_err(error)?;
    }
    mounts.volumes.clear();
    Ok(())
}

/// 查询句柄所在卷的只读状态。
pub(super) fn readonly(ino: u32) -> Result<bool, Errno> {
    access(ino, |mount, _| Ok(mount.volume.readonly()))
}

/// 返回类型、长度、链接数和以 512 字节计的块数。
pub(super) fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    access(ino, |mount, index| {
        let info = mount
            .volume
            .metadata(mount.nodes[index].ino)
            .map_err(error)?;
        Ok((info.mode, info.size, info.links, info.blocks))
    })
}

/// 查询 Ext2 属性，将盘上 inode 号与内核句柄分别记录。
pub(super) fn metadata(ino: u32) -> Result<Metadata, Errno> {
    access(ino, |mount, index| {
        let disk_ino = mount.nodes[index].ino;
        let info = mount.volume.metadata(disk_ino).map_err(error)?;
        let time = |sec| {
            Some(Timestamp {
                sec: i64::from(sec as i32),
                nsec: 0,
            })
        };
        Ok(Metadata {
            handle: Some(ino),
            ino: disk_ino.into(),
            dev: mount.dev,
            mode: info.mode,
            links: info.links.into(),
            uid: info.uid,
            gid: info.gid,
            size: info.size,
            blocks: info.blocks,
            block_size: 1024,
            atime: time(info.atime),
            mtime: time(info.mtime),
            ctime: time(info.ctime),
            ..Default::default()
        })
    })
}

/// 返回句柄所属 Ext2 卷的容量和 inode 用量。
pub(super) fn filesystem_stats(ino: u32) -> Result<FileSystemStats, Errno> {
    access(ino, |mount, _| {
        let stats = mount.volume.statfs().map_err(error)?;
        Ok(FileSystemStats {
            kind: 0xef53,
            block_size: 1024,
            blocks: stats.blocks,
            free_blocks: stats.blocks_free,
            available_blocks: stats.blocks_available,
            files: stats.inodes,
            free_files: stats.inodes_free,
            id: mount.dev,
            flags: u64::from(mount.volume.readonly()),
        })
    })
}

/// 读取符号链接目标。
pub(super) fn read_link(ino: u32) -> Result<String, Errno> {
    access(ino, |mount, index| {
        mount
            .volume
            .read_link(mount.nodes[index].ino)
            .map_err(error)
    })
}

/// 从指定偏移读取文件内容，返回实际读取量。
pub(super) fn read_raw(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    access(ino, |mount, index| {
        mount
            .volume
            .read(mount.nodes[index].ino, offset as u64, data)
            .map_err(error)
    })
}

/// 从指定偏移枚举目录项，返回下一次读取的位置。
pub(super) fn read_dir(
    ino: u32,
    offset: usize,
    mut visit: impl FnMut(DirEntry<'_>) -> bool,
) -> Result<usize, Errno> {
    access(ino, |mount, index| {
        mount
            .volume
            .read_dir(mount.nodes[index].ino, offset, |entry| {
                let kind = match entry.file_type {
                    1 => DirEntryKind::File,
                    2 => DirEntryKind::Directory,
                    3 => DirEntryKind::Character,
                    4 => DirEntryKind::Block,
                    5 => DirEntryKind::Fifo,
                    6 => DirEntryKind::Socket,
                    7 => DirEntryKind::Symlink,
                    _ => DirEntryKind::Unknown,
                };
                visit(DirEntry {
                    inode: entry.ino,
                    kind,
                    name: entry.name,
                    next: entry.next,
                })
            })
            .map_err(error)
    })
}

fn now() -> u32 {
    crate::time::realtime().as_secs().min(i32::MAX as u64) as u32
}

/// 创建常规文件并返回已分配的 inode 句柄。
pub(super) fn create(parent: u32, name: &str, mode: u16, owner: (u32, u32)) -> Result<u32, Errno> {
    let mut mounts = MOUNTS.lock();
    let Mounts {
        volumes,
        next_handle,
        ..
    } = &mut *mounts;
    let (mount, index) = volumes
        .iter_mut()
        .find_map(|mount| node_index(mount, parent).ok().map(|index| (mount, index)))
        .ok_or(Errno::NoEntry)?;
    reserve_handle(mount, *next_handle)?;
    let ino = mount
        .volume
        .create(mount.nodes[index].ino, name.as_bytes(), mode, owner, now())
        .map_err(error)?;
    Ok(insert_node(mount, next_handle, ino))
}

/// 从指定偏移写入文件，返回实际写入量。
pub(super) fn write_raw(ino: u32, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    access(ino, |mount, index| {
        mount
            .volume
            .write_file(mount.nodes[index].ino, offset as u64, data, now())
            .map_err(error)
    })
}

/// 为同卷 inode 在父目录中创建硬链接。
pub(super) fn link(ino: u32, parent: u32, name: &str) -> Result<(), Errno> {
    access(parent, |mount, index| {
        let source = node_index(mount, ino).map_err(|_| Errno::CrossDevice)?;
        mount
            .volume
            .link(
                mount.nodes[index].ino,
                mount.nodes[source].ino,
                name.as_bytes(),
                now(),
            )
            .map_err(error)
    })
}

/// 删除硬链接。最后一个名字移除前需先释放该 inode 的引用。
pub(super) fn unlink(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    access(parent, |mount, index| {
        if mount.volume.readonly() {
            return Err(Errno::ReadOnly);
        }
        let parent = mount.nodes[index].ino;
        let index = node_index(mount, ino).map_err(|_| Errno::CrossDevice)?;
        let node = &mount.nodes[index];
        if mount
            .volume
            .lookup(parent, name.as_bytes())
            .map_err(error)?
            != node.ino
        {
            return Err(Errno::NoEntry);
        }
        let last = mount.volume.metadata(node.ino).map_err(error)?.links == 1;
        if last && node.refs != 0 {
            return Err(Errno::Busy);
        }
        mount
            .volume
            .unlink(parent, name.as_bytes(), now())
            .map_err(error)?;
        if last {
            mount.nodes.swap_remove(index);
        }
        Ok(())
    })
}

/// 保留文件描述符、工作目录或映射持有的引用。
pub(super) fn retain(ino: u32) -> Result<(), Errno> {
    access(ino, |mount, index| {
        let refs = &mut mount.nodes[index].refs;
        *refs = refs.checked_add(1).ok_or(Errno::TooManyFiles)?;
        Ok(())
    })
}

/// 释放一个已保留的 inode 引用。
pub(super) fn release(ino: u32) {
    let _ = access(ino, |mount, index| {
        let refs = &mut mount.nodes[index].refs;
        *refs = refs.saturating_sub(1);
        Ok(())
    });
}
