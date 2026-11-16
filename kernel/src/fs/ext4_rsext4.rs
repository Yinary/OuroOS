//! rsext4 根卷和有界分区块设备适配。
//! 使用 rsext4 0.8.1（Apache-2.0），来源见 docs/third-party.md。
use crate::{drivers, syscall::Errno};
use alloc::vec::Vec;
use rsext4::{
    bmalloc::{AbsoluteBN, InodeNumber},
    superblock::Ext4Superblock,
    BlockDevice, Ext4Error, Ext4FileSystem, Ext4Result, Ext4Timestamp, Jbd2Dev, MountOptions,
    BLOCK_SIZE,
};
use spin::Mutex;

static ROOT: Mutex<Option<Volume>> = Mutex::new(None);
const WRITABLE: bool = !cfg!(feature = "rsext4-readonly");

struct Partition {
    start: usize,
    len: usize,
    time_base: i64,
}

struct Volume {
    fs: Ext4FileSystem,
    device: Jbd2Dev<Partition>,
    opens: Vec<(u32, usize)>,
    failed: bool,
}

impl Volume {
    fn check_io(&self) -> Result<(), Errno> {
        if self.failed {
            Err(Errno::Io)
        } else {
            Ok(())
        }
    }
}

impl Partition {
    fn range(&self, block: AbsoluteBN, count: u32) -> Ext4Result<core::ops::Range<usize>> {
        let offset = block
            .as_usize()?
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(Ext4Error::io)?;
        let len = (count as usize)
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(Ext4Error::io)?;
        let end = offset.checked_add(len).ok_or_else(Ext4Error::io)?;
        if end > self.len {
            return Err(Ext4Error::io());
        }
        Ok(self.start + offset..self.start + end)
    }
}

impl BlockDevice for Partition {
    fn read(&mut self, dst: &mut [u8], block: AbsoluteBN, count: u32) -> Ext4Result<()> {
        let range = self.range(block, count)?;
        let dst = dst.get_mut(..range.len()).ok_or_else(Ext4Error::io)?;
        drivers::read_bytes(0, range.start, dst).map_err(|_| Ext4Error::io())
    }

    fn write(&mut self, data: &[u8], block: AbsoluteBN, count: u32) -> Ext4Result<()> {
        if !WRITABLE {
            return Err(Ext4Error::read_only());
        }
        let range = self.range(block, count)?;
        let data = data.get(..range.len()).ok_or_else(Ext4Error::io)?;
        drivers::write_bytes(0, range.start, data).map_err(|_| Ext4Error::io())
    }

    fn flush(&mut self) -> Ext4Result<()> {
        if WRITABLE {
            drivers::flush(0).map_err(|_| Ext4Error::io())?;
        }
        Ok(())
    }

    fn open(&mut self) -> Ext4Result<()> {
        Ok(())
    }
    fn close(&mut self) -> Ext4Result<()> {
        Ok(())
    }
    fn total_blocks(&self) -> u64 {
        (self.len / BLOCK_SIZE) as u64
    }
    fn block_size(&self) -> u32 {
        BLOCK_SIZE as u32
    }
    fn is_readonly(&self) -> bool {
        !WRITABLE
    }
    fn current_time(&self) -> Ext4Result<Ext4Timestamp> {
        let elapsed = polyhal::timer::current_time();
        Ok(Ext4Timestamp::new(
            self.time_base.saturating_add(elapsed.as_secs() as i64),
            elapsed.subsec_nanos(),
        ))
    }
}

/// 挂载盘首分区或整盘的 4 KiB 块 Ext4；无磁盘时允许继续启动。
pub(super) fn init() -> Result<(), Errno> {
    let whole = match drivers::partition(0, 0) {
        Ok(range) => range,
        Err(drivers::Error::NoDevice) => return Ok(()),
        Err(_) => return Err(Errno::Io),
    };
    let (start, len) = match drivers::partition(0, 1) {
        Ok(range) => range,
        Err(drivers::Error::Range) => whole,
        Err(_) => return Err(Errno::Io),
    };
    if len < BLOCK_SIZE {
        return Err(Errno::Invalid);
    }
    let mut sb = [0; 1024];
    drivers::read_bytes(0, start + 1024, &mut sb).map_err(|_| Errno::Io)?;
    // 超级块中的 magic 和 log_block_size。
    if sb[56..58] != [0x53, 0xef] || sb[24..28] != [2, 0, 0, 0] {
        return Err(Errno::Invalid);
    }
    // 分组几何用于分配缓存，声明的块范围必须落在卷内。
    let lo = u32::from_le_bytes([sb[4], sb[5], sb[6], sb[7]]);
    let hi = u32::from_le_bytes([sb[336], sb[337], sb[338], sb[339]]);
    let blocks = (u64::from(hi) << 32) | u64::from(lo);
    if blocks == 0
        || blocks > (len / BLOCK_SIZE) as u64
        || sb[32..36] == [0; 4]
        || sb[40..44] == [0; 4]
    {
        return Err(Errno::Invalid);
    }
    let u32at = |n: usize| u32::from_le_bytes([sb[n], sb[n + 1], sb[n + 2], sb[n + 3]]);
    let journal = WRITABLE && u32at(92) & Ext4Superblock::EXT4_FEATURE_COMPAT_HAS_JOURNAL != 0;
    if WRITABLE {
        use Ext4Superblock as Sb;
        let supported_incompat = Sb::EXT4_FEATURE_INCOMPAT_FILETYPE
            | Sb::EXT4_FEATURE_INCOMPAT_EXTENTS
            | Sb::EXT4_FEATURE_INCOMPAT_64BIT
            | Sb::EXT4_FEATURE_INCOMPAT_FLEX_BG;
        let supported_ro = Sb::EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER
            | Sb::EXT4_FEATURE_RO_COMPAT_LARGE_FILE
            | Sb::EXT4_FEATURE_RO_COMPAT_HUGE_FILE
            | Sb::EXT4_FEATURE_RO_COMPAT_DIR_NLINK
            | Sb::EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE
            | Sb::EXT4_FEATURE_RO_COMPAT_METADATA_CSUM;
        let state = u16::from_le_bytes([sb[58], sb[59]]);
        if u32at(96) & !supported_incompat != 0
            || u32at(100) & !supported_ro != 0
            || state != Sb::EXT4_VALID_FS
            || (journal && (u32at(224) != 8 || u32at(228) != 0 || blocks > u64::from(u32::MAX) + 1))
        {
            return Err(Errno::NotSupported);
        }
    }
    // 当前无 RTC，从卷上次写入时间起算。
    let partition = Partition {
        start,
        len,
        time_base: i64::from(u32at(48)),
    };
    let mut device = Jbd2Dev::initial_jbd2dev(0, partition, journal);
    let options = MountOptions {
        readonly: !WRITABLE,
        replay_journal: false,
    };
    let mut fs = rsext4::mount_with_options(&mut device, options).map_err(error)?;
    if !fs.get_root(&mut device).map_err(error)?.is_dir() {
        return Err(Errno::Invalid);
    }
    *ROOT.lock() = Some(Volume {
        fs,
        device,
        opens: Vec::new(),
        failed: false,
    });
    log::info!("EXT4 root mounted (rsext4, writable={WRITABLE})");
    Ok(())
}

fn access<T>(f: impl FnOnce(&mut Volume) -> Ext4Result<T>) -> Result<T, Errno> {
    let mut root = ROOT.lock();
    let volume = root.as_mut().ok_or(Errno::NoDevice)?;
    volume.check_io()?;
    f(volume).map_err(error)
}

fn error(err: Ext4Error) -> Errno {
    use rsext4::Errno as Ext4Errno;
    match err.code {
        Ext4Errno::ENOENT => Errno::NoEntry,
        Ext4Errno::ENOTDIR => Errno::NotDir,
        Ext4Errno::EISDIR => Errno::IsDir,
        Ext4Errno::EINVAL => Errno::Invalid,
        Ext4Errno::ENOMEM => Errno::NoMem,
        Ext4Errno::ENOSPC => Errno::NoSpace,
        Ext4Errno::EEXIST => Errno::Exists,
        Ext4Errno::ENAMETOOLONG => Errno::NameTooLong,
        Ext4Errno::EFBIG => Errno::TooBig,
        Ext4Errno::EROFS => Errno::ReadOnly,
        Ext4Errno::EOPNOTSUPP => Errno::NotSupported,
        _ => Errno::Io,
    }
}

/// 查找路径并返回 Ext4 inode 编号。
pub(super) fn lookup(path: &str) -> Result<u32, Errno> {
    access(|v| {
        let (ino, _) = rsext4::loopfile::get_file_inode(&mut v.fs, &mut v.device, path)?
            .ok_or_else(Ext4Error::not_found)?;
        // 高位由上层用于区分 FAT inode。
        if ino.raw() & 0x8000_0000 != 0 {
            return Err(Ext4Error::unsupported());
        }
        Ok(ino.raw())
    })
}

/// 返回 inode 类型、长度、链接数和磁盘占用。
pub(super) fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    access(|v| {
        let inode =
            v.fs.get_inode_by_num(&mut v.device, InodeNumber::new(ino)?)?;
        Ok((
            inode.i_mode,
            inode.size(),
            inode.i_links_count,
            inode.blocks_count(),
        ))
    })
}

/// 读取 inode 指定偏移的内容，EOF 返回零。
pub(super) fn read_raw(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    access(|v| {
        rsext4::file::read_inode_data_into(
            &mut v.device,
            &mut v.fs,
            InodeNumber::new(ino)?,
            offset as u64,
            data,
        )
    })
}

/// 在指定父目录创建空普通文件或目录。
pub(super) fn create(parent: u32, name: &str, mode: u16) -> Result<u32, Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        let parent = InodeNumber::new(parent)?;
        let create = if mode & 0xf000 == 0x4000 {
            rsext4::dir::mkdir_in_parent
        } else {
            rsext4::file::create_regular_inode
        };
        create(&mut v.device, &mut v.fs, parent, name, mode).map(|ino| ino.raw())
    })
}

/// 读取当前目录块中的原始目录项字节。
pub(super) fn read_dir_at(ino: u32, offset: usize, data: &mut [u8]) -> Result<usize, Errno> {
    access(|v| {
        rsext4::dir::read_dir_at(
            &mut v.device,
            &mut v.fs,
            InodeNumber::new(ino)?,
            offset,
            data,
        )
    })
}

/// 将数据写到普通文件的指定偏移。
pub(super) fn write_raw(ino: u32, offset: usize, data: &[u8]) -> Result<usize, Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    offset.checked_add(data.len()).ok_or(Errno::Invalid)?;
    access(|v| {
        let ino = regular_inode(v, ino)?;
        rsext4::file::write_inode_data(&mut v.device, &mut v.fs, ino, offset as u64, data)?;
        Ok(data.len())
    })
}

/// 将普通文件截断到零字节。
pub(super) fn truncate(ino: u32) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        let ino = regular_inode(v, ino)?;
        rsext4::file::truncate_inode(&mut v.device, &mut v.fs, ino, 0)
    })
}

fn regular_inode(v: &mut Volume, ino: u32) -> Ext4Result<InodeNumber> {
    let ino = InodeNumber::new(ino)?;
    let inode = v.fs.get_inode_by_num(&mut v.device, ino)?;
    if inode.is_dir() {
        return Err(Ext4Error::is_dir());
    }
    if !inode.is_file() {
        return Err(Ext4Error::unsupported());
    }
    Ok(ino)
}

/// 同步 Ext4 缓存和分区设备。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn sync() -> Result<(), Errno> {
    access(|v| v.fs.sync_filesystem(&mut v.device))
}

/// 同步并卸载已挂载的根卷。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn unmount() -> Result<(), Errno> {
    let mut root = ROOT.lock();
    if let Some(v) = root.as_mut() {
        v.check_io()?;
        if !v.opens.is_empty() {
            return Err(Errno::Busy);
        }
        v.fs.umount(&mut v.device).map_err(error)?;
        *root = None;
    }
    Ok(())
}

/// 移除普通文件名；没有链接和打开引用时回收 inode。
pub(super) fn unlink(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        let inode = InodeNumber::new(ino)?;
        let links = rsext4::file::unlink_regular_entry(
            &mut v.fs,
            &mut v.device,
            InodeNumber::new(parent)?,
            inode,
            name,
        )
        .inspect_err(|e| {
            use rsext4::Errno as Ext4Errno;
            if matches!(e.code, Ext4Errno::EIO | Ext4Errno::EUCLEAN) {
                v.failed = true;
            }
        })?;
        if links == 0 && !v.opens.iter().any(|&(id, _)| id == ino) {
            reclaim_unlinked(v, ino)?;
        }
        Ok(())
    })
}

fn reclaim_unlinked(v: &mut Volume, ino: u32) -> Ext4Result<()> {
    let result = (|| {
        let ino = InodeNumber::new(ino)?;
        let mut inode = v.fs.get_inode_by_num(&mut v.device, ino)?;
        if inode.i_links_count == 0 {
            rsext4::file::free_inode(&mut v.fs, &mut v.device, ino, &mut inode)?;
        }
        Ok(())
    })();
    if result.is_err() {
        v.failed = true;
    }
    result
}

/// 持有打开文件或共享映射的 inode 引用。
pub(super) fn retain(ino: u32) -> Result<(), Errno> {
    if !WRITABLE {
        return Ok(());
    }
    let mut root = ROOT.lock();
    let v = root.as_mut().ok_or(Errno::NoDevice)?;
    v.check_io()?;
    if let Some((_, refs)) = v.opens.iter_mut().find(|(id, _)| *id == ino) {
        *refs = refs.checked_add(1).ok_or(Errno::TooManyFiles)?;
    } else {
        v.opens.try_reserve(1).map_err(|_| Errno::NoMem)?;
        v.opens.push((ino, 1));
    }
    Ok(())
}

/// 释放引用，最后一个引用关闭时检查 inode 是否可回收。
pub(super) fn release(ino: u32) {
    if !WRITABLE {
        return;
    }
    let mut root = ROOT.lock();
    let Some(v) = root.as_mut() else { return };
    let Some(i) = v.opens.iter().position(|&(id, _)| id == ino) else {
        return;
    };
    v.opens[i].1 -= 1;
    if v.opens[i].1 == 0 {
        v.opens.swap_remove(i);
        if v.failed {
            return;
        }
        if let Err(e) = reclaim_unlinked(v, ino) {
            log::error!("Ext4 inode {ino} reclaim failed: {e}");
        }
    }
}
