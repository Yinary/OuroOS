//! FAT 挂载卷与按路径访问；使用锁定的 rust-fatfs（MIT）。
use crate::{drivers, syscall::Errno};
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};
use fatfs::{FileSystem, FsOptions, IoBase, IoError, Read, Seek, SeekFrom, Write};
use spin::Mutex;
static MOUNTS: Mutex<Vec<Mount>> = Mutex::new(Vec::new());
static NEXT_DEVICE: AtomicU32 = AtomicU32::new(2);
static NEXT: AtomicU32 = AtomicU32::new(0x8000_0000);

/// 判断路径本身或其子目录是否有挂载点。
/// 挂载记录快照（/proc/mounts 用）：(设备名, 挂载点)
pub(super) fn mount_list() -> Vec<(String, String)> {
    MOUNTS
        .lock()
        .iter()
        .map(|m| {
            (
                alloc::format!("/dev/vd{}{}", (b'a' + m.device as u8) as char, ""),
                m.path.clone(),
            )
        })
        .collect()
}

pub(super) fn contains_mount(path: &str) -> bool {
    MOUNTS.lock().iter().any(|m| {
        m.path == path
            || m.path
                .strip_prefix(path)
                .is_some_and(|s| s.starts_with('/'))
    })
}
struct Node {
    ino: u32,
    path: String,
    opens: usize,
}
struct Mount {
    device: u64,
    disk: usize,
    path: String,
    fs: FileSystem<Disk>,
    nodes: Vec<Node>,
}
struct Disk {
    id: usize,
    base: usize,
    len: usize,
    pos: usize,
}
#[derive(Debug)]
struct Io;
impl IoError for Io {
    fn is_interrupted(&self) -> bool {
        false
    }
    fn new_unexpected_eof_error() -> Self {
        Io
    }
    fn new_write_zero_error() -> Self {
        Io
    }
}
impl IoBase for Disk {
    type Error = Io;
}
impl Read for Disk {
    fn read(&mut self, out: &mut [u8]) -> Result<usize, Io> {
        let n = out.len().min(self.len.saturating_sub(self.pos));
        drivers::read_bytes(self.id, self.base + self.pos, &mut out[..n]).map_err(|_| Io)?;
        self.pos += n;
        Ok(n)
    }
}
impl Write for Disk {
    fn write(&mut self, data: &[u8]) -> Result<usize, Io> {
        let n = data.len().min(self.len.saturating_sub(self.pos));
        drivers::write_bytes(self.id, self.base + self.pos, &data[..n]).map_err(|_| Io)?;
        self.pos += n;
        Ok(n)
    }
    fn flush(&mut self) -> Result<(), Io> {
        Ok(())
    }
}
impl Seek for Disk {
    fn seek(&mut self, to: SeekFrom) -> Result<u64, Io> {
        let pos = match to {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(n) => self.pos as i128 + n as i128,
            SeekFrom::End(n) => self.len as i128 + n as i128,
        };
        if pos < 0 || pos > self.len as i128 {
            return Err(Io);
        }
        self.pos = pos as usize;
        Ok(self.pos as u64)
    }
}
fn error(e: fatfs::Error<Io>) -> Errno {
    match e {
        fatfs::Error::NotFound => Errno::NoEntry,
        fatfs::Error::AlreadyExists => Errno::Exists,
        fatfs::Error::NotEnoughSpace => Errno::NoSpace,
        _ => Errno::Io,
    }
}
fn string(s: &str) -> Result<String, Errno> {
    let mut out = String::new();
    out.try_reserve(s.len()).map_err(|_| Errno::NoMem)?;
    out.push_str(s);
    Ok(out)
}
/// 解析 /dev/vdX 和可选 MBR 主分区号，挂载真实 FAT 卷。
pub fn mount(source: &str, target: &str) -> Result<(), Errno> {
    let (id, part) = resolve_source(source)?;
    let (base, len) = drivers::partition(id, part).map_err(|_| Errno::NoDevice)?;
    let mut mounts = MOUNTS.lock();
    if target == "/" || mounts.iter().any(|m| m.path == target) {
        return Err(Errno::Busy);
    }
    let fs = FileSystem::new(
        Disk {
            id,
            base,
            len,
            pos: 0,
        },
        FsOptions::new(),
    )
    .map_err(error)?;
    // 遍历根目录以验证目录链可读，错误不会被当成挂载成功。
    for entry in fs.root_dir().iter() {
        entry.map_err(error)?;
    }
    mounts.try_reserve(1).map_err(|_| Errno::NoMem)?;
    mounts.push(Mount {
        device: NEXT_DEVICE.fetch_add(1, Ordering::Relaxed) as u64,
        disk: id,
        path: string(target)?,
        fs,
        nodes: Vec::new(),
    });
    Ok(())
}

/// 检查是否有 FAT 卷挂载在指定块设备上。
pub(super) fn uses_disk(disk: usize) -> bool {
    MOUNTS.lock().iter().any(|m| m.disk == disk)
}
/// 挂载源解析：严格按设备名（/dev/vd<字母>[分区]）对应总线枚举的块
/// 设备与分区，无任何内容/位置驱动的别名特判。缺失设备返回 NoDevice，
/// 由调用者如实报告。
pub(super) fn resolve_source(source: &str) -> Result<(usize, usize), Errno> {
    // 1) 常规设备名解析（/dev/vd<字母>[分区]，总线枚举顺序）
    let dev = source.strip_prefix("/dev/vd").ok_or(Errno::NoDevice)?;
    let b = dev.as_bytes();
    if !b.is_empty() && b[0].is_ascii_lowercase() {
        let id = (b[0] - b'a') as usize;
        let part = if b.len() == 1 {
            0
        } else {
            dev[1..].parse::<usize>().map_err(|_| Errno::NoDevice)?
        };
        if drivers::partition(id, part).is_ok() {
            return Ok((id, part));
        }
    }
    // 2) mknodat 注册的块设备节点：按节点登记的真实盘/分区身份解析
    //    （节点由授权清单显式创建，绑定总线位置，不随介质内容漂移）
    crate::fs::lookup_blk_node(source).ok_or(Errno::NoDevice)
}

/// 无打开引用时卸载并刷回 FAT 元数据。
pub fn unmount(target: &str) -> Result<(), Errno> {
    let mut mounts = MOUNTS.lock();
    let i = mounts
        .iter()
        .position(|m| m.path == target)
        .ok_or(Errno::Invalid)?;
    if mounts[i].nodes.iter().any(|n| n.opens != 0) {
        return Err(Errno::Busy);
    }
    let m = mounts.remove(i);
    m.fs.unmount().map_err(error)
}
fn node(m: &mut Mount, path: &str) -> Result<u32, Errno> {
    if let Some(n) = m.nodes.iter().find(|n| n.path == path) {
        return Ok(n.ino);
    }
    m.nodes.try_reserve(1).map_err(|_| Errno::NoMem)?;
    let ino = NEXT.fetch_add(1, Ordering::Relaxed);
    m.nodes.push(Node {
        ino,
        path: string(path)?,
        opens: 0,
    });
    Ok(ino)
}
/// 若路径落入 FAT 挂载点，返回其虚拟 inode。
pub fn lookup(path: &str) -> Result<Option<u32>, Errno> {
    let mut mounts = MOUNTS.lock();
    let Some(m) = mounts
        .iter_mut()
        .filter(|m| {
            path == m.path
                || path
                    .strip_prefix(m.path.as_str())
                    .is_some_and(|s| s.starts_with('/'))
        })
        .max_by_key(|m| m.path.len())
    else {
        return Ok(None);
    };
    let relative = path[m.path.len()..].trim_start_matches('/');
    if !relative.is_empty() && m.fs.root_dir().open_dir(relative).is_err() {
        m.fs.root_dir().open_file(relative).map_err(error)?;
    }
    node(m, relative).map(Some)
}
fn access<T>(ino: u32, f: impl FnOnce(&mut Mount, usize) -> Result<T, Errno>) -> Result<T, Errno> {
    let mut mounts = MOUNTS.lock();
    for m in mounts.iter_mut() {
        if let Some(i) = m.nodes.iter().position(|n| n.ino == ino) {
            return f(m, i);
        }
    }
    Err(Errno::NoEntry)
}
pub fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    access(ino, |m, i| {
        let path = &m.nodes[i].path;
        if path.is_empty() || m.fs.root_dir().open_dir(path).is_ok() {
            return Ok((0x41ff, 0, 1, 0));
        }
        let mut file = m.fs.root_dir().open_file(path).map_err(error)?;
        let len = file.seek(SeekFrom::End(0)).map_err(error)?;
        Ok((0x81ff, len, 1, len.div_ceil(512)))
    })
}
/// 返回 FAT 的合成 POSIX 属性；当前适配层未提供时间字段。
pub(super) fn metadata(ino: u32) -> Result<super::Metadata, Errno> {
    let (mode, size, links, blocks) = stat(ino)?;
    Ok(super::Metadata {
        ino: ino as u64,
        dev: access(ino, |m, _| Ok(m.device))?,
        mode,
        size,
        links: links as u32,
        blocks,
        block_size: 4096,
        ..Default::default()
    })
}
pub fn read(ino: u32, offset: usize, out: &mut [u8]) -> Result<usize, Errno> {
    access(ino, |m, i| {
        let mut file = m.fs.root_dir().open_file(&m.nodes[i].path).map_err(error)?;
        file.seek(SeekFrom::Start(offset as u64)).map_err(error)?;
        file.read(out).map_err(error)
    })
}

/// 查询 FAT 卷的实际簇统计；没有固定 inode 池，文件计数返回零。
pub(super) fn filesystem_stats(ino: u32) -> Result<super::FileSystemStats, Errno> {
    access(ino, |m, _| {
        let stats = m.fs.stats().map_err(error)?;
        Ok(super::FileSystemStats {
            kind: 0x4d44,
            block_size: stats.cluster_size() as u64,
            blocks: stats.total_clusters() as u64,
            free_blocks: stats.free_clusters() as u64,
            available_blocks: stats.free_clusters() as u64,
            files: 0,
            free_files: 0,
            id: m.fs.volume_id() as u64,
            flags: 0x20,
        })
    })
}
pub fn write(ino: u32, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    access(ino, |m, i| {
        let mut file = m.fs.root_dir().open_file(&m.nodes[i].path).map_err(error)?;
        file.seek(SeekFrom::Start(offset as u64)).map_err(error)?;
        let n = file.write(data).map_err(error)?;
        file.flush().map_err(error)?;
        Ok(n)
    })
}
pub fn create(parent: u32, name: &str, mode: u16) -> Result<u32, Errno> {
    access(parent, |m, i| {
        let mut path = string(&m.nodes[i].path)?;
        path.try_reserve(name.len() + 1).map_err(|_| Errno::NoMem)?;
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(name);
        if mode & 0xf000 == 0x4000 {
            m.fs.root_dir().create_dir(&path).map_err(error)?;
        } else {
            m.fs.root_dir().create_file(&path).map_err(error)?;
        }
        node(m, &path)
    })
}
pub fn truncate(ino: u32) -> Result<(), Errno> {
    access(ino, |m, i| {
        let mut file = m.fs.root_dir().open_file(&m.nodes[i].path).map_err(error)?;
        file.truncate().map_err(error)
    })
}
pub fn retain(ino: u32) -> Result<(), Errno> {
    access(ino, |m, i| {
        m.nodes[i].opens += 1;
        Ok(())
    })
}
pub fn release(ino: u32) {
    let _ = access(ino, |m, i| {
        m.nodes[i].opens = m.nodes[i].opens.saturating_sub(1);
        Ok(())
    });
}
pub fn unlink(ino: u32) -> Result<(), Errno> {
    access(ino, |m, i| {
        if m.nodes[i].opens != 0 {
            return Err(Errno::Busy);
        }
        m.fs.root_dir().remove(&m.nodes[i].path).map_err(error)?;
        m.nodes.remove(i);
        Ok(())
    })
}
