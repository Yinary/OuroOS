//! memfd_create(2) 匿名内存文件后端与 F_ADD_SEALS/F_GET_SEALS 封存语义。
//! 分配独立虚拟 inode 区间（0x3000_0000..0x3FFF_FFFF），统一接入 fs::{read,write,stat,truncate}
//! 与 mm::file 共享/私有页映射，不落盘、无目录项、最后引用释放后自动回收。
#![deny(unsafe_code)]

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use crate::{sync::DebugMutex, syscall::Errno};

/// memfd 虚拟 inode 区间（避开 ext4 实际 inode、procfs 0x4000_0000.. 与 FAT 0x8000_0000）。
pub const MEMFD_INODE_BASE: u32 = 0x3000_0000;
pub const MEMFD_INODE_END: u32 = 0x3FFF_FFFF;

/// memfd_create(2) 标志（linux/memfd.h）。
pub const MFD_CLOEXEC: u32 = 0x0001;
pub const MFD_ALLOW_SEALING: u32 = 0x0002;
pub const MFD_HUGETLB: u32 = 0x0004;
pub const MFD_NOEXEC_SEAL: u32 = 0x0008;
pub const MFD_EXEC: u32 = 0x0010;
const MFD_HUGE_SHIFT: u32 = 26;
const MFD_HUGE_MASK: u32 = 0x3f << MFD_HUGE_SHIFT;

/// fcntl(2) 封存标志（linux/fcntl.h）。
pub const F_SEAL_SEAL: u32 = 0x0001;
pub const F_SEAL_SHRINK: u32 = 0x0002;
pub const F_SEAL_GROW: u32 = 0x0004;
pub const F_SEAL_WRITE: u32 = 0x0008;
pub const F_SEAL_FUTURE_WRITE: u32 = 0x0010;
pub const F_SEAL_EXEC: u32 = 0x0020;
pub const F_ALL_SEALS: u32 =
    F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE | F_SEAL_EXEC;

/// 单 memfd 内存上限（受 32 MiB 固定内核堆约束，避免恶意超大 ftruncate 触发堆 OOM）。
const MAX_MEMFD_SIZE: usize = 8 * 1024 * 1024;
/// Linux memfd_create 名称最大长度（NAME_MAX(255) - strlen("memfd:") = 249）。
pub const MAX_MEMFD_NAME: usize = 249;

static NEXT_MEMFD_INO: AtomicU32 = AtomicU32::new(MEMFD_INODE_BASE + 1);

struct MemFdEntry {
    _name: String,
    mode: u16,
    uid: u32,
    gid: u32,
    seals: u32,
    refs: usize,
    writable_shared_maps: usize,
    data: Vec<u8>,
}

static MEMFDS: DebugMutex<BTreeMap<u32, MemFdEntry>> = DebugMutex::new("MEMFDS", BTreeMap::new());

/// 判断 inode 是否属于 memfd 虚拟区间。
#[inline]
pub fn is_memfd_ino(ino: u32) -> bool {
    (MEMFD_INODE_BASE..=MEMFD_INODE_END).contains(&ino)
}

/// 创建一个新的 memfd 匿名内存文件对象，返回分配的虚拟 inode（初始引用计数为 1）。
pub fn create(name: &str, flags: u32, uid: u32, gid: u32) -> Result<u32, Errno> {
    if name.len() > MAX_MEMFD_NAME {
        return Err(Errno::Invalid);
    }
    let known_base = MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_HUGETLB | MFD_NOEXEC_SEAL | MFD_EXEC;
    if flags & MFD_HUGETLB == 0 {
        if flags & !known_base != 0 {
            return Err(Errno::Invalid);
        }
    } else {
        if flags & !(known_base | MFD_HUGE_MASK) != 0 {
            return Err(Errno::Invalid);
        }
        let shift = (flags & MFD_HUGE_MASK) >> MFD_HUGE_SHIFT;
        if shift != 0
            && !matches!(
                shift,
                16 | 18 | 19 | 20 | 21 | 22 | 23 | 24 | 25 | 28 | 29 | 30 | 31 | 34
            )
        {
            return Err(Errno::Invalid);
        }
        // 内核未启用 hugetlbfs，合法大页请求返回 ENODEV（与无大页支持一致）。
        return Err(Errno::NoDevice);
    }
    if flags & (MFD_NOEXEC_SEAL | MFD_EXEC) == (MFD_NOEXEC_SEAL | MFD_EXEC) {
        return Err(Errno::Invalid);
    }

    let mut owned_name = String::new();
    owned_name
        .try_reserve_exact(name.len())
        .map_err(|_| Errno::NoMem)?;
    owned_name.push_str(name);

    let mut seals = if flags & MFD_ALLOW_SEALING != 0 {
        0
    } else {
        F_SEAL_SEAL
    };
    let mode = if flags & MFD_NOEXEC_SEAL != 0 {
        seals |= F_SEAL_EXEC;
        0o100666
    } else {
        0o100777
    };

    let ino = NEXT_MEMFD_INO.fetch_add(1, Ordering::Relaxed);
    if !is_memfd_ino(ino) {
        return Err(Errno::NoSpace);
    }
    let mut table = MEMFDS.lock();
    table.insert(
        ino,
        MemFdEntry {
            _name: owned_name,
            mode,
            uid,
            gid,
            seals,
            refs: 1,
            writable_shared_maps: 0,
            data: Vec::new(),
        },
    );
    Ok(ino)
}

/// 递增 memfd 引用计数（供 OpenFile/MappingFile 持有）。
pub fn retain(ino: u32) -> Result<(), Errno> {
    let mut table = MEMFDS.lock();
    let entry = table.get_mut(&ino).ok_or(Errno::NoEntry)?;
    entry.refs = entry.refs.saturating_add(1);
    Ok(())
}

/// 递减 memfd 引用计数，归零时回收内存与共享缓存页。
pub fn release(ino: u32) {
    let mut removed = false;
    {
        let mut table = MEMFDS.lock();
        if let Some(entry) = table.get_mut(&ino) {
            entry.refs = entry.refs.saturating_sub(1);
            if entry.refs == 0 {
                table.remove(&ino);
                removed = true;
            }
        }
    }
    if removed {
        super::cache::resize_inode(ino, usize::MAX, 0);
    }
}

/// 登记一次可写 MAP_SHARED 映射（供 F_SEAL_WRITE 检测 EBUSY）。
pub fn inc_writable_map(ino: u32) {
    let mut table = MEMFDS.lock();
    if let Some(entry) = table.get_mut(&ino) {
        entry.writable_shared_maps = entry.writable_shared_maps.saturating_add(1);
    }
}

/// 撤销一次可写 MAP_SHARED 映射。
pub fn dec_writable_map(ino: u32) {
    let mut table = MEMFDS.lock();
    if let Some(entry) = table.get_mut(&ino) {
        entry.writable_shared_maps = entry.writable_shared_maps.saturating_sub(1);
    }
}

/// 查询当前封存标志（F_GET_SEALS）。
pub fn get_seals(ino: u32) -> Result<u32, Errno> {
    let table = MEMFDS.lock();
    let entry = table.get(&ino).ok_or(Errno::Invalid)?;
    Ok(entry.seals)
}

/// 追加封存标志（F_ADD_SEALS）；已有 F_SEAL_SEAL 返回 EPERM，
/// 新增 F_SEAL_WRITE 时若存在活跃可写 MAP_SHARED 映射返回 EBUSY。
pub fn add_seals(ino: u32, add: u32) -> Result<(), Errno> {
    if add & !F_ALL_SEALS != 0 {
        return Err(Errno::Invalid);
    }
    let mut table = MEMFDS.lock();
    let entry = table.get_mut(&ino).ok_or(Errno::Invalid)?;
    if entry.seals & F_SEAL_SEAL != 0 {
        return Err(Errno::Perm);
    }
    if add & F_SEAL_WRITE != 0 && entry.seals & F_SEAL_WRITE == 0 && entry.writable_shared_maps > 0
    {
        return Err(Errno::Busy);
    }
    entry.seals |= add;
    Ok(())
}

/// 是否已施加写封存（F_SEAL_WRITE 或 F_SEAL_FUTURE_WRITE）。
pub fn is_write_sealed(ino: u32) -> bool {
    MEMFDS
        .lock()
        .get(&ino)
        .is_some_and(|e| e.seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0)
}

/// 校验用户态写入是否违反写封存或增长封存。
pub fn check_write_seal(ino: u32, offset: usize, len: usize) -> Result<(), Errno> {
    let table = MEMFDS.lock();
    let entry = table.get(&ino).ok_or(Errno::BadF)?;
    if entry.seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
        return Err(Errno::Perm);
    }
    let end = offset.checked_add(len).ok_or(Errno::FileTooBig)?;
    if end > entry.data.len() && entry.seals & F_SEAL_GROW != 0 {
        return Err(Errno::Perm);
    }
    Ok(())
}

/// 查询 memfd stat 元组：(mode, size, links, blocks)。
pub fn stat(ino: u32) -> Result<(u16, u64, u16, u64), Errno> {
    let table = MEMFDS.lock();
    let entry = table.get(&ino).ok_or(Errno::NoEntry)?;
    let size = entry.data.len() as u64;
    let blocks = size.div_ceil(512);
    Ok((entry.mode, size, 1, blocks))
}

/// 查询完整 Metadata（供 fstat/statx）。
pub fn metadata(ino: u32) -> Result<super::Metadata, Errno> {
    let table = MEMFDS.lock();
    let entry = table.get(&ino).ok_or(Errno::NoEntry)?;
    let size = entry.data.len() as u64;
    Ok(super::Metadata {
        ino: u64::from(ino),
        dev: 0x0102_1994, // TMPFS_MAGIC 合成卷号
        mode: entry.mode,
        links: 1,
        uid: entry.uid,
        gid: entry.gid,
        size,
        blocks: size.div_ceil(512),
        block_size: 4096,
        ..Default::default()
    })
}

/// 读取 memfd 原始字节（无封存拦截）。
pub fn read_raw(ino: u32, offset: usize, dst: &mut [u8]) -> Result<usize, Errno> {
    let table = MEMFDS.lock();
    let entry = table.get(&ino).ok_or(Errno::BadF)?;
    let Some(slice) = entry.data.get(offset..) else {
        return Ok(0);
    };
    let n = dst.len().min(slice.len());
    dst[..n].copy_from_slice(&slice[..n]);
    Ok(n)
}

/// 写入 memfd 原始字节（供页缓存回写与 fs::write 共用，返回 `(写入字节数, 旧长度)`）。
pub fn write_raw_with_old_size(
    ino: u32,
    offset: usize,
    data: &[u8],
) -> Result<(usize, usize), Errno> {
    let mut table = MEMFDS.lock();
    let entry = table.get_mut(&ino).ok_or(Errno::BadF)?;
    let old = entry.data.len();
    let end = offset.checked_add(data.len()).ok_or(Errno::FileTooBig)?;
    if end > MAX_MEMFD_SIZE {
        return Err(Errno::NoSpace);
    }
    if end > old {
        entry
            .data
            .try_reserve(end - old)
            .map_err(|_| Errno::NoMem)?;
        entry.data.resize(end, 0);
    }
    entry.data[offset..end].copy_from_slice(data);
    Ok((data.len(), old))
}

/// 调整 memfd 长度；校验 F_SEAL_SHRINK 与 F_SEAL_GROW。
pub fn truncate(ino: u32, length: u64) -> Result<(), Errno> {
    let new_len = usize::try_from(length).map_err(|_| Errno::FileTooBig)?;
    let mut table = MEMFDS.lock();
    let entry = table.get_mut(&ino).ok_or(Errno::BadF)?;
    let cur = entry.data.len();
    if new_len < cur && entry.seals & F_SEAL_SHRINK != 0 {
        return Err(Errno::Perm);
    }
    if new_len > cur && entry.seals & F_SEAL_GROW != 0 {
        return Err(Errno::Perm);
    }
    if new_len > MAX_MEMFD_SIZE {
        return Err(Errno::NoMem);
    }
    if new_len > cur {
        entry
            .data
            .try_reserve(new_len - cur)
            .map_err(|_| Errno::NoMem)?;
    }
    entry.data.resize(new_len, 0);
    Ok(())
}

/// 修改 memfd 权限位；存在 F_SEAL_EXEC 时禁止修改执行位（返回 EPERM）。
pub fn chmod(ino: u32, mode: u16) -> Result<(), Errno> {
    let mut table = MEMFDS.lock();
    let entry = table.get_mut(&ino).ok_or(Errno::BadF)?;
    if entry.seals & F_SEAL_EXEC != 0 && (mode & 0o111) != (entry.mode & 0o111) {
        return Err(Errno::Perm);
    }
    entry.mode = 0o100000 | (mode & 0o7777);
    Ok(())
}

/// fallocate(2) 内存文件处理：支持默认扩展、KEEP_SIZE、PUNCH_HOLE|KEEP_SIZE 与 ZERO_RANGE，
/// 并严格校验 F_SEAL_GROW / F_SEAL_WRITE / F_SEAL_FUTURE_WRITE。
pub fn fallocate(ino: u32, mode: u32, offset: usize, len: usize) -> Result<(), Errno> {
    const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
    const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
    const FALLOC_FL_ZERO_RANGE: u32 = 0x10;

    let end = offset.checked_add(len).ok_or(Errno::FileTooBig)?;
    let (old_len, new_len, zero_range) = {
        let mut table = MEMFDS.lock();
        let entry = table.get_mut(&ino).ok_or(Errno::BadF)?;
        let cur = entry.data.len();
        if mode & FALLOC_FL_PUNCH_HOLE != 0 {
            if entry.seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
                return Err(Errno::Perm);
            }
            let zstart = offset.min(cur);
            let zend = end.min(cur);
            if zstart < zend {
                entry.data[zstart..zend].fill(0);
                (cur, cur, Some((zstart, zend)))
            } else {
                (cur, cur, None)
            }
        } else if mode & FALLOC_FL_ZERO_RANGE != 0 {
            if entry.seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0 {
                return Err(Errno::Perm);
            }
            let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
            if !keep && end > cur && entry.seals & F_SEAL_GROW != 0 {
                return Err(Errno::Perm);
            }
            let target = if !keep && end > cur {
                if end > MAX_MEMFD_SIZE {
                    return Err(Errno::NoSpace);
                }
                entry
                    .data
                    .try_reserve(end - cur)
                    .map_err(|_| Errno::NoMem)?;
                entry.data.resize(end, 0);
                end
            } else {
                cur
            };
            let zstart = offset.min(target);
            let zend = end.min(target);
            if zstart < zend {
                entry.data[zstart..zend].fill(0);
                (cur, target, Some((zstart, zend)))
            } else {
                (cur, target, None)
            }
        } else {
            let keep = mode & FALLOC_FL_KEEP_SIZE != 0;
            if !keep && end > cur {
                if entry.seals & F_SEAL_GROW != 0 {
                    return Err(Errno::Perm);
                }
                if end > MAX_MEMFD_SIZE {
                    return Err(Errno::NoSpace);
                }
                entry
                    .data
                    .try_reserve(end - cur)
                    .map_err(|_| Errno::NoMem)?;
                entry.data.resize(end, 0);
                (cur, end, None)
            } else {
                if keep && end > MAX_MEMFD_SIZE {
                    return Err(Errno::NoSpace);
                }
                (cur, cur, None)
            }
        }
    };
    if new_len != old_len {
        super::cache::resize_inode(ino, old_len, new_len);
        super::mapping::commit_resize(ino, old_len as u64, new_len as u64);
    }
    if let Some((zstart, zend)) = zero_range {
        let zeros = [0u8; 4096];
        let mut pos = zstart;
        while pos < zend {
            let n = (zend - pos).min(zeros.len());
            super::cache::coherent_write(ino, pos, &zeros[..n]);
            pos += n;
        }
    }
    Ok(())
}
