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
    /// 所在块设备号（drivers 的 DISKS 下标）
    disk: usize,
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
        drivers::read_bytes(self.disk, range.start, dst).map_err(|_| Ext4Error::io())
    }

    fn write(&mut self, data: &[u8], block: AbsoluteBN, count: u32) -> Ext4Result<()> {
        if !WRITABLE {
            return Err(Ext4Error::read_only());
        }
        let range = self.range(block, count)?;
        let data = data.get(..range.len()).ok_or_else(Ext4Error::io)?;
        drivers::write_bytes(self.disk, range.start, data).map_err(|_| Ext4Error::io())
    }

    fn flush(&mut self) -> Ext4Result<()> {
        if WRITABLE {
            drivers::flush(self.disk).map_err(|_| Ext4Error::io())?;
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
        let now = crate::time::realtime();
        if now.as_secs() > 0 {
            Ok(Ext4Timestamp::new(now.as_secs() as i64, now.subsec_nanos()))
        } else {
            let elapsed = crate::time::monotonic();
            Ok(Ext4Timestamp::new(
                self.time_base.saturating_add(elapsed.as_secs() as i64),
                elapsed.subsec_nanos(),
            ))
        }
    }
}

/// 根卷是否已成功挂载（供启动入口区分"无盘"与"有盘无 /init"）。
pub fn mounted() -> bool {
    ROOT.lock().is_some()
}

/// 挂载盘首分区或整盘的 4 KiB 块 Ext4；无磁盘时允许继续启动。
pub(super) fn init() -> Result<(), Errno> {
    let count = drivers::disk_count();
    if count == 0 {
        return Ok(());
    }
    // 扫描式根卷选择：每块盘先试 MBR 分区 1..=4、再试整盘，取第一个
    // 可挂载的 Ext4 卷。设备命名约定见 drivers（分区盘优先编号），根卷
    // 语义是"第一个可挂载的 Ext4"，与设备名无绑定。
    let mut last = Errno::Io;
    for id in 0..count {
        for part in [1, 2, 3, 4, 0] {
            let Ok((start, len)) = drivers::partition(id, part) else {
                continue;
            };
            match try_mount(id, start, len) {
                Ok(()) => {
                    ROOT_DISK_ID.store(id, core::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                Err(e) => last = e,
            }
        }
    }
    Err(last)
}

/// Ext4 根卷所在的设备号（/proc/mounts 的设备名用），由 init 成功时记录。
static ROOT_DISK_ID: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// 根卷设备的 vda 式名字（vd + 小写字母）。
pub(super) fn root_disk_name() -> char {
    (b'a' + ROOT_DISK_ID.load(core::sync::atomic::Ordering::Relaxed) as u8) as char
}

fn try_mount(id: usize, start: usize, len: usize) -> Result<(), Errno> {
    if len < BLOCK_SIZE {
        return Err(Errno::Invalid);
    }
    let mut sb = [0; 1024];
    drivers::read_bytes(id, start + 1024, &mut sb).map_err(|_| Errno::Io)?;
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
        disk: id,
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
        Ext4Errno::EPERM => Errno::Perm,
        Ext4Errno::ENOENT => Errno::NoEntry,
        Ext4Errno::ENOTDIR => Errno::NotDir,
        Ext4Errno::EISDIR => Errno::IsDir,
        Ext4Errno::EINVAL => Errno::Invalid,
        Ext4Errno::ENOMEM => Errno::NoMem,
        Ext4Errno::ENOSPC => Errno::NoSpace,
        Ext4Errno::EEXIST => Errno::Exists,
        Ext4Errno::ENOTEMPTY => Errno::NotEmpty,
        Ext4Errno::EMLINK => Errno::TooManyLinks,
        Ext4Errno::ENAMETOOLONG => Errno::NameTooLong,
        Ext4Errno::EFBIG => Errno::FileTooBig,
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

/// 读取 inode 的所有者、精确时间及基本属性。
pub(super) fn metadata(ino: u32) -> Result<super::Metadata, Errno> {
    access(|v| {
        let inode =
            v.fs.get_inode_by_num(&mut v.device, InodeNumber::new(ino)?)?;
        let size = v.fs.superblock.s_inode_size;
        let time = |t: Ext4Timestamp| super::Timestamp {
            sec: t.sec,
            nsec: t.nsec,
        };
        let rdev = if matches!(inode.i_mode & 0xf000, 0x2000 | 0x6000) {
            if inode.i_block[0] != 0 {
                inode.i_block[0]
            } else {
                inode.i_block[1]
            }
        } else {
            0
        };
        Ok(super::Metadata {
            ino: ino as u64,
            dev: 1,
            rdev: rdev as u64,
            mode: inode.i_mode,
            links: inode.i_links_count as u32,
            uid: inode.uid(),
            gid: inode.gid(),
            size: inode.size(),
            blocks: inode
                .blocks_count()
                // HUGE_FILE 将 i_blocks 的单位从扇区切换为文件系统块。
                .checked_mul(if inode.i_flags & 0x40000 != 0 {
                    (BLOCK_SIZE / 512) as u64
                } else {
                    1
                })
                .ok_or_else(Ext4Error::io)?,
            block_size: BLOCK_SIZE as u32,
            atime: Some(time(inode.atime_ts(size))),
            mtime: Some(time(inode.mtime_ts(size))),
            ctime: Some(time(inode.ctime_ts(size))),
            btime: inode.crtime_ts(size).map(time),
        })
    })
}

/// 更新 inode 时间，保留后端的时间编码、校验和与日志写回流程。
pub(super) fn update_times(ino: u32, times: [super::TimeUpdate; 2]) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        use rsext4::{disknode::Ext4Inode, Ext4TimeSpec};
        let size = match v.fs.superblock.s_inode_size {
            0 => Ext4Inode::LARGE_INODE_SIZE,
            size => size,
        };
        let convert = |update, field_end| match update {
            super::TimeUpdate::Omit => Ext4TimeSpec::Omit,
            super::TimeUpdate::Now => Ext4TimeSpec::Now,
            super::TimeUpdate::Set(t) => {
                let max = if size >= field_end {
                    0x3_7fff_ffff
                } else {
                    i32::MAX as i64
                };
                let sec = t.sec.clamp(i32::MIN as i64, max);
                Ext4TimeSpec::Set(Ext4Timestamp::new(
                    sec,
                    if sec == t.sec { t.nsec } else { 0 },
                ))
            }
        };
        rsext4::metadata::utimens_inode(
            &mut v.device,
            &mut v.fs,
            InodeNumber::new(ino)?,
            convert(times[0], Ext4Inode::FIELD_END_I_ATIME_EXTRA),
            convert(times[1], Ext4Inode::FIELD_END_I_MTIME_EXTRA),
        )
    })
}

/// 按 inode 更新属主和属组，写入只读卷时返回 EROFS。
pub(super) fn set_owner(ino: u32, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        rsext4::metadata::chown_inode(&mut v.device, &mut v.fs, InodeNumber::new(ino)?, uid, gid)
    })
}

/// 查询根卷容量，空闲计数取自后端当前快照。
pub(super) fn filesystem_stats() -> Result<super::FileSystemStats, Errno> {
    access(|v| {
        let stats = v.fs.statfs();
        let sb = &v.fs.superblock;
        let overhead = (sb.s_overhead_blocks as u64)
            .checked_shl(sb.s_log_cluster_size.saturating_sub(sb.s_log_block_size))
            .ok_or_else(Ext4Error::corrupted)?;
        let blocks = stats
            .total_blocks
            .checked_sub(overhead)
            .ok_or_else(Ext4Error::corrupted)?;
        let u = sb.s_uuid;
        Ok(super::FileSystemStats {
            kind: 0xef53,
            block_size: stats.block_size,
            blocks,
            free_blocks: stats.free_blocks,
            available_blocks: stats.free_blocks.saturating_sub(sb.reserved_blocks_count()),
            files: stats.total_inodes as u64,
            free_files: stats.free_inodes as u64,
            id: u64::from_le_bytes([u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7]]),
            flags: 0x20 | u64::from(!WRITABLE),
        })
    })
}

/// 读取有界的链接目标；不更新访问时间，非 UTF-8 或损坏数据返回 EIO。
pub(super) fn link_target(ino: u32) -> Result<alloc::string::String, Errno> {
    let mut data = Vec::new();
    data.try_reserve_exact(4096).map_err(|_| Errno::NoMem)?;
    access(|v| {
        let mut inode =
            v.fs.get_inode_by_num(&mut v.device, InodeNumber::new(ino)?)?;
        if !inode.is_symlink() {
            return Err(Ext4Error::invalid_input());
        }
        let size = usize::try_from(inode.size()).map_err(|_| Ext4Error::invalid_input())?;
        if size >= 4096 {
            return Err(Ext4Error::new(rsext4::Errno::ENAMETOOLONG));
        }
        let xattr_sectors = if inode.file_acl() == 0 {
            0
        } else {
            (BLOCK_SIZE / 512) as u64
        };
        if size < 60 && inode.blocks_count() == xattr_sectors {
            for word in inode.i_block {
                data.extend_from_slice(&word.to_le_bytes());
            }
            data.truncate(size);
        } else if size != 0 {
            // 一个链接目标小于一块；非 extent 链接使用首个直接块。
            let block = if inode.have_extend_header_and_use_extend() {
                rsext4::loopfile::resolve_inode_block(&mut v.device, &mut inode, 0)?
                    .ok_or_else(Ext4Error::io)?
            } else {
                if inode.i_block[0] == 0 {
                    return Err(Ext4Error::io());
                }
                AbsoluteBN::new(inode.i_block[0] as u64)
            };
            v.device.read_block(block)?;
            data.extend_from_slice(&v.device.buffer()[..size]);
        }
        Ok(())
    })?;
    if data.contains(&0) {
        return Err(Errno::Io);
    }
    alloc::string::String::from_utf8(data).map_err(|_| Errno::Io)
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

/// 按块读取 Ext4 目录，逐项交付解析结果。
pub(super) fn read_dir(
    ino: u32,
    mut offset: usize,
    mut visit: impl FnMut(super::DirEntry<'_>) -> bool,
) -> Result<usize, Errno> {
    use super::{DirEntry, DirEntryKind};

    let mut block = Vec::new();
    block
        .try_reserve_exact(BLOCK_SIZE)
        .map_err(|_| Errno::NoMem)?;
    block.resize(BLOCK_SIZE, 0);
    loop {
        let n = access(|v| {
            rsext4::dir::read_dir_at(
                &mut v.device,
                &mut v.fs,
                InodeNumber::new(ino)?,
                offset,
                &mut block,
            )
        })?;
        if n == 0 {
            return Ok(offset);
        }
        let mut remaining = &block[..n];
        while !remaining.is_empty() {
            let h = remaining.first_chunk::<8>().ok_or(Errno::Io)?;
            let inode = u32::from_le_bytes([h[0], h[1], h[2], h[3]]);
            let len = u16::from_le_bytes([h[4], h[5]]) as usize;
            let name_end = 8 + h[6] as usize;
            if len % 4 != 0 || len < name_end || len > remaining.len() {
                return Err(Errno::Io);
            }
            let next = offset.checked_add(len).ok_or(Errno::Io)?;
            let kind = match h[7] {
                1 => DirEntryKind::File,
                2 => DirEntryKind::Directory,
                3 => DirEntryKind::Character,
                4 => DirEntryKind::Block,
                5 => DirEntryKind::Fifo,
                6 => DirEntryKind::Socket,
                7 => DirEntryKind::Symlink,
                _ => DirEntryKind::Unknown,
            };
            if inode != 0
                && !visit(DirEntry {
                    inode,
                    kind,
                    name: &remaining[8..name_end],
                    next,
                })
            {
                return Ok(offset);
            }
            offset = next;
            remaining = &remaining[len..];
        }
    }
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

/// 按 inode 调整普通文件长度，I/O 或结构错误后停止访问卷。
pub(super) fn truncate(ino: u32, length: u64) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        let ino = regular_inode(v, ino)?;
        rsext4::file::truncate_inode(&mut v.device, &mut v.fs, ino, length).inspect_err(|e| {
            if matches!(e.code, rsext4::Errno::EIO | rsext4::Errno::EUCLEAN) {
                v.failed = true;
            }
        })
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

/// chmod(2) 底层：按 inode 身份更新权限位（保留类型位），经日志事务
/// 提交。path 用于日志队列定位；`ino` 为权威身份，与 path 解析结果
/// 不一致时拒绝（防 fd 身份与路径漂移后改错对象）。
pub fn chmod_by_ino(ino: u32, path: &str, mode: u16) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    // ino 身份校验：与 path 解析结果不一致时拒绝（防 fd 与路径漂移）
    if access(|v| {
        InodeNumber::new(ino).and_then(|num| v.fs.get_inode_by_num(&mut v.device, num).map(|_| ()))
    })
    .is_err()
    {
        return Err(Errno::NoEntry);
    }
    access(|v| {
        rsext4::metadata::chmod(&mut v.device, &mut v.fs, path, mode).inspect_err(|e| {
            if matches!(e.code, rsext4::Errno::EIO | rsext4::Errno::EUCLEAN) {
                v.failed = true;
            }
        })
    })
}

/// 从父目录移除空目录，最后一个引用释放后回收 inode。
pub(super) fn rmdir(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        rsext4::file::unlink_empty_directory(
            &mut v.fs,
            &mut v.device,
            InodeNumber::new(parent)?,
            InodeNumber::new(ino)?,
            name,
        )
        .inspect_err(|e| {
            if matches!(e.code, rsext4::Errno::EIO | rsext4::Errno::EUCLEAN) {
                v.failed = true;
            }
        })?;
        if !v.opens.iter().any(|&(id, _)| id == ino) {
            reclaim_unlinked(v, ino)?;
        }
        Ok(())
    })
}

/// 创建符号链接并保存目标文本。
pub(super) fn symlink(
    parent: u32,
    name: &str,
    target: &str,
    uid: u32,
    gid: u32,
) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        rsext4::file::create_symlink_inode(
            &mut v.fs,
            &mut v.device,
            InodeNumber::new(parent)?,
            name,
            target,
            uid,
            gid,
        )
        .inspect_err(|e| {
            use rsext4::Errno as Ext4Errno;
            if matches!(e.code, Ext4Errno::EIO | Ext4Errno::EUCLEAN) {
                v.failed = true;
            }
        })
    })
}

/// 在父目录中添加指向已有 inode 的名称。
pub(super) fn link(ino: u32, parent: u32, name: &str) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        rsext4::file::link_entry(
            &mut v.fs,
            &mut v.device,
            InodeNumber::new(parent)?,
            InodeNumber::new(ino)?,
            name,
        )
        .inspect_err(|e| {
            use rsext4::Errno as Ext4Errno;
            if matches!(e.code, Ext4Errno::EIO | Ext4Errno::EUCLEAN) {
                v.failed = true;
            }
        })
    })
}

/// 移除普通文件或符号链接的名称；无链接和打开引用时回收 inode。
pub(super) fn unlink(parent: u32, ino: u32, name: &str) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        let inode = InodeNumber::new(ino)?;
        let links = rsext4::file::unlink_file_entry(
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

/// 串行更新目录项，旧目标 inode 无链接且无打开引用时才回收。
pub(super) fn rename(
    old: u32,
    name: &str,
    new: u32,
    target: &str,
    no_replace: bool,
) -> Result<(), Errno> {
    if !WRITABLE {
        return Err(Errno::ReadOnly);
    }
    access(|v| {
        let replaced = rsext4::file::rename_entry(
            &mut v.fs,
            &mut v.device,
            InodeNumber::new(old)?,
            name,
            InodeNumber::new(new)?,
            target,
            no_replace,
        )
        .inspect_err(|e| {
            if matches!(e.code, rsext4::Errno::EIO | rsext4::Errno::EUCLEAN) {
                v.failed = true;
            }
        })?;
        if let Some(ino) = replaced {
            if !v.opens.iter().any(|&(id, _)| id == ino.raw()) {
                reclaim_unlinked(v, ino.raw())?;
            }
        }
        Ok(())
    })
}

fn reclaim_unlinked(v: &mut Volume, ino: u32) -> Ext4Result<()> {
    let result =
        rsext4::file::reclaim_unlinked_inode(&mut v.fs, &mut v.device, InodeNumber::new(ino)?);
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
