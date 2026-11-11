//! EXT4 卷适配与路径→inode 查找（先 FAT 挂载后 EXT4 根，见 §6 契约），
//! 对上层提供 inode 级读写/创建/截断/回收。
//! 使用 ext4_rs 1.3.3（MIT，含本地补丁，见 docs/third-party.md）。
use crate::{drivers, syscall::Errno};
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use ext4_rs::{BlockDevice, Ext4};
use spin::Mutex;

static ROOT: Mutex<Option<Volume>> = Mutex::new(None);
struct Device {
    id: usize,
    base: usize,
    failed: AtomicBool,
}
struct Volume {
    opens: Vec<(u32, usize)>,
    fs: Ext4,
    device: Arc<Device>,
}

impl BlockDevice for Device {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        let mut data = vec![0; 4096];
        if drivers::read_bytes(self.id, self.base + offset, &mut data).is_err() {
            self.failed.store(true, Ordering::Relaxed);
        }
        data
    }
    fn write_offset(&self, offset: usize, data: &[u8]) {
        if drivers::write_bytes(self.id, self.base + offset, data).is_err() {
            self.failed.store(true, Ordering::Relaxed);
        }
    }
}
/// 启动时读取 EXT4 超级块；没有设备时返回 Ok，不创建虚构磁盘。
pub fn init() -> Result<(), Errno> {
    let capacity = match drivers::capacity(0) {
        Ok(n) => n,
        Err(drivers::Error::NoDevice) => return Ok(()),
        Err(_) => return Err(Errno::Io),
    };
    let (base, _) = drivers::partition(0, 1).unwrap_or((0, capacity as usize * 512));
    let mut sb = [0; 1024];
    drivers::read_bytes(0, base + 1024, &mut sb).map_err(|_| Errno::Io)?;
    let u16at = |n| u16::from_le_bytes([sb[n], sb[n + 1]]);
    let u32at = |n| u32::from_le_bytes([sb[n], sb[n + 1], sb[n + 2], sb[n + 3]]);
    log::debug!(
        "super: magic={:x} log={} desc={} ipg={} isize={}",
        u16at(56),
        u32at(24),
        u16at(254),
        u32at(40),
        u16at(88)
    );
    // 验证超级块几何：固定 4 KiB 数据块。
    if u16at(56) != 0xef53
        || u32at(24) != 2
        || u32at(32) == 0
        || u16at(254) != 64
        || u32at(40) == 0
        || ![128, 256].contains(&u16at(88))
        || u64::from(u32at(4)) * 8 > capacity
    {
        return Err(Errno::Invalid);
    }
    let device = crate::fs::try_arc(Device {
        id: 0,
        base,
        failed: AtomicBool::new(false),
    })?;
    let fs = Ext4::open(device.clone());
    if device.failed.load(Ordering::Relaxed) {
        return Err(Errno::Io);
    }
    let inode = fs.get_inode_ref(2);
    log::debug!(
        "root: mode={:x} size={}",
        inode.inode.mode(),
        inode.inode.size()
    );
    if !inode.inode.is_dir() {
        return Err(Errno::Invalid);
    }
    log::info!("EXT4 root mounted: {} bytes", inode.inode.size());
    *ROOT.lock() = Some(Volume {
        fs,
        device,
        opens: Vec::new(),
    });
    Ok(())
}

fn access<T>(f: impl FnOnce(&Ext4) -> Result<T, Errno>) -> Result<T, Errno> {
    let guard = ROOT.lock();
    let volume = guard.as_ref().ok_or(Errno::NoDevice)?;
    if volume.device.failed.load(Ordering::Relaxed) {
        return Err(Errno::Io);
    }
    let result = f(&volume.fs);
    if volume.device.failed.load(Ordering::Relaxed) {
        Err(Errno::Io)
    } else {
        result
    }
}
fn error(e: ext4_rs::Ext4Error) -> Errno {
    match e.error() {
        ext4_rs::Errno::ENOENT => Errno::NoEntry,
        ext4_rs::Errno::ENOSPC => Errno::NoSpace,
        ext4_rs::Errno::EEXIST => Errno::Exists,
        ext4_rs::Errno::ENOTDIR => Errno::NotDir,
        _ => Errno::Io,
    }
}
/// 按绝对路径查找 inode；根目录为 EXT4 的 inode 2。
pub fn lookup(path: &str) -> Result<u32, Errno> {
    if let Some(ino) = fat::lookup(path)? {
        return Ok(ino);
    }
    if path == "/" {
        return access(|_| Ok(2));
    }
    access(|fs| {
        let mut ino = 2;
        for name in path.split('/').filter(|s| !s.is_empty()) {
            if !fs.get_inode_ref(ino).inode.is_dir() {
                return Err(Errno::NotDir);
            }
            ino = fs
                .generic_open(name, &mut ino, false, 0, &mut 0)
                .map_err(error)?;
        }
        Ok(ino)
    })
}
/// inode 的类型、长度、链接数和磁盘占用。
pub fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    if ino & 0x8000_0000 != 0 {
        return fat::stat(ino);
    }
    access(|fs| {
        let inode = fs.get_inode_ref(ino).inode;
        Ok((
            inode.mode(),
            inode.size(),
            inode.links_count(),
            inode.blocks_count(),
        ))
    })
}
/// 创建父目录下的新对象；不会隐式创建缺失的中间目录。
pub fn create(parent: u32, name: &str, mode: u16) -> Result<u32, Errno> {
    if parent & 0x8000_0000 != 0 {
        return fat::create(parent, name, mode);
    }
    access(|fs| {
        if !fs.get_inode_ref(parent).inode.is_dir() {
            return Err(Errno::NotDir);
        }
        fs.create(parent, name, mode)
            .map(|r| r.inode_num)
            .map_err(error)
    })
}
/// 读文件指定偏移，EOF 返回零。
pub fn read_raw(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    if ino & 0x8000_0000 != 0 {
        return fat::read(ino, offset, data);
    }
    access(|fs| fs.read_at(ino, offset, data).map_err(error))
}
/// 写文件指定偏移并返回实际字节数。
pub fn write_raw(ino: u32, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    if ino & 0x8000_0000 != 0 {
        return fat::write(ino, offset, data);
    }
    offset.checked_add(data.len()).ok_or(Errno::Invalid)?;
    access(|fs| fs.write_at(ino, offset, data).map_err(error))
}
/// 截断普通文件。
pub fn truncate(ino: u32) -> Result<(), Errno> {
    if ino & 0x8000_0000 != 0 {
        return fat::truncate(ino);
    }
    access(|fs| {
        let mut inode = fs.get_inode_ref(ino);
        if inode.inode.size() == 0 {
            return Ok(());
        }
        fs.truncate_inode(&mut inode, 0).map(|_| ()).map_err(error)
    })
}
pub mod context;

/// 打开引用计数独立于链接数，unlink 后最后一个句柄关闭才回收。
pub fn retain(ino: u32) -> Result<(), Errno> {
    if ino & 0x8000_0000 != 0 {
        return fat::retain(ino);
    }
    let mut guard = ROOT.lock();
    let v = guard.as_mut().ok_or(Errno::NoDevice)?;
    if let Some((_, n)) = v.opens.iter_mut().find(|(i, _)| *i == ino) {
        *n = n.checked_add(1).ok_or(Errno::TooManyFiles)?;
    } else {
        v.opens.try_reserve(1).map_err(|_| Errno::NoMem)?;
        v.opens.push((ino, 1));
    }
    Ok(())
}
fn reclaim(fs: &Ext4, ino: u32) -> Result<(), Errno> {
    let mut inode = fs.get_inode_ref(ino);
    if inode.inode.size() != 0 {
        fs.truncate_inode(&mut inode, 0).map_err(error)?;
    }
    // 无 RTC，以根目录 ctime 加当前秒作 dtime。
    inode.inode.set_dtime(
        fs.get_inode_ref(2)
            .inode
            .ctime()
            .saturating_add(polyhal::timer::current_time().as_secs() as u32),
    );
    fs.write_back_inode(&mut inode);
    fs.ialloc_free_inode(ino, inode.inode.is_dir());
    Ok(())
}
/// 释放打开引用；磁盘失败保留错误状态，后续操作返回 EIO。
pub fn release(ino: u32) {
    if ino & 0x8000_0000 != 0 {
        return fat::release(ino);
    }
    let mut guard = ROOT.lock();
    if let Some(v) = guard.as_mut() {
        if let Some(i) = v.opens.iter().position(|(n, _)| *n == ino) {
            v.opens[i].1 -= 1;
            if v.opens[i].1 == 0 {
                v.opens.swap_remove(i);
                if v.fs.get_inode_ref(ino).inode.links_count() == 0 && reclaim(&v.fs, ino).is_err()
                {
                    v.device.failed.store(true, Ordering::Relaxed);
                }
            }
        }
    }
}
/// 删除普通文件名，打开的 inode 保持有效。
pub fn unlink(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    if ino & 0x8000_0000 != 0 {
        return fat::unlink(ino);
    }
    let mut guard = ROOT.lock();
    let v = guard.as_mut().ok_or(Errno::NoDevice)?;
    if v.device.failed.load(Ordering::Relaxed) {
        return Err(Errno::Io);
    }
    let mut child = v.fs.get_inode_ref(ino);
    if child.inode.is_dir() {
        return Err(Errno::IsDir);
    }
    let links = child.inode.links_count().checked_sub(1).ok_or(Errno::Io)?;
    v.fs.dir_remove_entry(&mut v.fs.get_inode_ref(parent), name)
        .map_err(error)?;
    child.inode.set_links_count(links);
    v.fs.write_back_inode(&mut child);
    if links == 0 && !v.opens.iter().any(|(i, _)| *i == ino) {
        reclaim(&v.fs, ino)?;
    }
    if v.device.failed.load(Ordering::Relaxed) {
        Err(Errno::Io)
    } else {
        Ok(())
    }
}
pub mod cache;
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

pub mod fat;

/// 用户路径使用可失败的引用计数分配。
pub fn try_arc<T>(value: T) -> Result<Arc<T>, Errno> {
    Arc::try_new(value).map_err(|_| Errno::NoMem)
}
