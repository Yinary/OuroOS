//! 文件系统入口，按路径和 inode 将操作转交 Ext4 或 FAT。
use crate::syscall::Errno;
use alloc::sync::Arc;

#[path = "ext4_rsext4.rs"]
mod ext4;

pub mod cache;
pub mod context;
pub mod fat;

const FAT_INODE: u32 = 0x8000_0000;
const EXT4_BLOCK_SIZE: usize = 4096;

/// 初始化 Ext4 根卷；无磁盘时允许继续启动。
pub fn init() -> Result<(), Errno> {
    ext4::init()
}

/// 写回 inode 的共享页和 Ext4 卷缓存。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn sync_inode(ino: u32) -> Result<(), Errno> {
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
    match fat::lookup(path)? {
        Some(ino) => Ok(ino),
        None => ext4::lookup(path),
    }
}

/// 返回 inode 类型、长度、链接数和磁盘占用。
pub fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    if ino & FAT_INODE != 0 {
        fat::stat(ino)
    } else {
        ext4::stat(ino)
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

/// 读取文件指定偏移，EOF 返回零。
pub fn read_raw(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    if ino & FAT_INODE != 0 {
        fat::read(ino, offset, data)
    } else {
        ext4::read_raw(ino, offset, data)
    }
}

/// 为目录遍历读取当前块中的目录项字节。
pub(super) fn read_dir_at(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    if ino & FAT_INODE != 0 {
        fat::read(ino, offset, data)
    } else {
        let len = data.len().min(EXT4_BLOCK_SIZE - offset % EXT4_BLOCK_SIZE);
        ext4::read_dir_at(ino, offset, &mut data[..len])
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

/// 将普通文件截断到零字节。
pub fn truncate(ino: u32) -> Result<(), Errno> {
    if ino & FAT_INODE != 0 {
        fat::truncate(ino)
    } else {
        ext4::truncate(ino)
    }
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
    let n = write_raw(ino, offset, data)?;
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
