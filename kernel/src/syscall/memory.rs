//! 内存系统调用：映射、权限、区域调整与驻留查询。
//! Linux ABI 依据 man7.org/linux/man-pages/man2/{mmap,mprotect,brk,mremap,mincore}.2.html。
#![deny(unsafe_code)]
use super::Errno;
use crate::mm::address_space::{AreaKind, MapError, UserAddressSpace};
use polyhal::pagetable::{MappingFlags as F, PAGE_SIZE};

fn error(e: MapError) -> Errno {
    match e {
        MapError::FileFault => Errno::Fault,
        MapError::FileIo => Errno::Io,
        MapError::PermissionDenied => Errno::Access,
        MapError::UnsupportedPermissions => Errno::NotSupported,
        MapError::InvalidPermissions => Errno::Invalid,
        _ => Errno::NoMem,
    }
}
fn pages(len: usize) -> Result<usize, Errno> {
    if len == 0 {
        return Err(Errno::Invalid);
    }
    len.checked_add(PAGE_SIZE - 1)
        .map(|n| n / PAGE_SIZE)
        .ok_or(Errno::NoMem)
}
fn flags(prot: usize) -> Result<F, Errno> {
    if prot & !7 != 0 {
        return Err(Errno::Invalid);
    }
    let mut f = F::U;
    if prot & 1 != 0 {
        f |= F::R;
    }
    // Sv39 不支持仅写页；本实现两架构统一 W 蕴含 R。
    if prot & 2 != 0 {
        f |= F::R | F::W;
    }
    if prot & 4 != 0 {
        f |= F::X;
    }
    Ok(f)
}
/// mmap(2)：私有/共享匿名映射与文件映射，支持 FIXED。
/// 匿名 fd 被忽略；offset 仍必须页对齐；MAP_DENYWRITE、MAP_EXECUTABLE 与 MAP_STACK 被忽略。
pub(super) fn mmap(
    space: &mut UserAddressSpace,
    a: [usize; 6],
    ctx: &crate::fs::context::Context,
) -> Result<usize, Errno> {
    const LOCKED: usize = 0x2000;
    const NORESERVE: usize = 0x4000;
    const POPULATE: usize = 0x8000;
    const NONBLOCK: usize = 0x10000;
    const DENYWRITE: usize = 0x800;
    const EXECUTABLE: usize = 0x1000;
    const STACK: usize = 0x20000;
    let mut request = a;
    request[3] &= !(LOCKED | NORESERVE | POPULATE | NONBLOCK | DENYWRITE | EXECUTABLE | STACK);
    let lock = a[3] & LOCKED != 0;
    let start = if lock {
        space.with_map_lock(|s| mmap_region(s, request, ctx))
    } else {
        mmap_region(space, request, ctx)
    }?;
    // MAP_POPULATE 是尽力预取；EOF、内存不足不会撤销已经建立的 VMA。
    if (lock || a[3] & (POPULATE | NONBLOCK) == POPULATE) && a[2] != 0 {
        for i in 0..a[1].div_ceil(PAGE_SIZE) {
            if space.ensure_access(start + i * PAGE_SIZE, F::U).is_err() {
                break;
            }
        }
    }
    Ok(start)
}

fn mmap_region(
    space: &mut UserAddressSpace,
    a: [usize; 6],
    ctx: &crate::fs::context::Context,
) -> Result<usize, Errno> {
    let [addr, len, prot, map_flags, _fd, offset] = a;
    let n = pages(len)?;
    let f = flags(prot)?;
    if offset % PAGE_SIZE != 0 {
        return Err(Errno::Invalid);
    }
    if map_flags & 3 == 0 || (map_flags & 3 == 3 && map_flags & 0x20 != 0) {
        return Err(Errno::Invalid);
    }
    let noreplace = map_flags & 0x100000 != 0;
    let fixed = noreplace || map_flags & 0x10 != 0;
    if fixed && addr % PAGE_SIZE != 0 {
        return Err(Errno::Invalid);
    }
    if noreplace && space.overlaps(addr, n).map_err(error)? {
        return Err(Errno::Exists);
    }
    if map_flags & 0x20 == 0 {
        use crate::mm::address_space::Backing;
        use alloc::vec::Vec;
        if map_flags & !0x100013 != 0 {
            return Err(Errno::NotSupported);
        }
        let shared = matches!(map_flags & 3, 1 | 3);
        let (ino, writable) = crate::fs::context::mapping(ctx, _fd, shared && prot & 2 != 0)?;
        offset
            .checked_add(len - 1)
            .filter(|n| *n <= i64::MAX as usize)
            .ok_or(Errno::Invalid)?;
        if fixed && addr % PAGE_SIZE != 0 {
            return Err(Errno::Invalid);
        }
        let start = if fixed {
            addr
        } else {
            space.find_free(addr, n).map_err(error)?
        };
        use crate::mm::file::{FilePage, MappingFile, Mode};
        let file = MappingFile::new(ino)?;
        let mode = if shared {
            Mode::Shared { writable }
        } else {
            Mode::Private
        };
        let mut frames = Vec::new();
        frames.try_reserve(n).map_err(|_| Errno::NoMem)?;
        for i in 0..n {
            frames.push(Backing::File(FilePage::new(
                file.clone(),
                offset + i * PAGE_SIZE,
                mode,
            )));
        }
        space.map_backed(start, frames, f, fixed).map_err(error)?;
        crate::mm::fence_icache();
        return Ok(start);
    }
    if map_flags & !0x100033 != 0 {
        return Err(Errno::NotSupported);
    }
    if map_flags & 3 == 1 {
        if fixed && addr % PAGE_SIZE != 0 {
            return Err(Errno::Invalid);
        }
        let start = if fixed {
            addr
        } else {
            space.find_free(addr, n).map_err(error)?
        };
        space
            .map_shared_anonymous(start, n, f, fixed)
            .map_err(error)?;
        return Ok(start);
    }
    if fixed {
        if addr % PAGE_SIZE != 0 {
            return Err(Errno::Invalid);
        }
        space.reserve_fixed(addr, n, f).map_err(error)?;
        Ok(addr)
    } else {
        let start = space.find_free(addr, n).map_err(error)?;
        space
            .reserve_region(start, n, f, AreaKind::Anonymous)
            .map_err(error)?;
        Ok(start)
    }
}
/// munmap(2)：起址必须页对齐，长度向上取整；空洞允许。
pub(super) fn munmap(
    space: &mut UserAddressSpace,
    addr: usize,
    len: usize,
) -> Result<usize, Errno> {
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::Invalid);
    }
    let n = pages(len)?;
    space.unmap(addr, n).map_err(|e| match e {
        MapError::OutOfUserRange => Errno::Invalid,
        other => error(other),
    })?;
    Ok(0)
}
/// mprotect(2)：修改整段映射的读写权限；W 隐含 R，可访问页在两架构上均可执行。
/// 长度为零不改变任何映射。
pub(super) fn mprotect(
    space: &mut UserAddressSpace,
    addr: usize,
    len: usize,
    prot: usize,
) -> Result<usize, Errno> {
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::Invalid);
    }
    let f = flags(prot)?;
    if len == 0 {
        return Ok(0);
    }
    space.protect(addr, pages(len)?, f).map_err(error)?;
    Ok(0)
}

/// mincore(2)：查询驻留数据页，包括其他映射已调入的同一文件页；不触发缺页。
pub(super) fn mincore(
    space: &UserAddressSpace,
    addr: usize,
    len: usize,
    out: usize,
) -> Result<usize, Errno> {
    use alloc::vec::Vec;
    if addr % PAGE_SIZE != 0 {
        return Err(Errno::Invalid);
    }
    let end = addr.checked_add(len).ok_or(Errno::NoMem)?;
    if end > crate::mm::address_space::USER_TOP {
        return Err(Errno::NoMem);
    }
    let n = len.div_ceil(PAGE_SIZE);
    let mut result = Vec::new();
    result.try_reserve_exact(n).map_err(|_| Errno::Again)?;
    for i in 0..n {
        result.push(space.resident(addr + i * PAGE_SIZE).map_err(error)? as u8);
    }
    crate::mm::user_access::copy_to_user(space, out, &result).map_err(|_| Errno::Fault)?;
    Ok(0)
}

/// mremap(2)：单区域扩缩、MAYMOVE/FIXED；可保留源地址，零长源可复制共享映射。
pub(super) fn mremap(space: &mut UserAddressSpace, a: [usize; 5]) -> Result<usize, Errno> {
    let [addr, old_len, new_len, flags, dest] = a;
    if addr % PAGE_SIZE != 0
        || flags & !7 != 0
        || flags & 2 != 0 && (flags & 1 == 0 || dest % PAGE_SIZE != 0)
    {
        return Err(Errno::Invalid);
    }
    let old = if old_len == 0 { 0 } else { pages(old_len)? };
    let new = pages(new_len)?;
    let target = (flags & 2 != 0).then_some(dest);
    (if flags & 4 != 0 {
        space.remap_mode(addr, old, new, flags & 1 != 0, target, true)
    } else {
        space.remap(addr, old, new, flags & 1 != 0, target)
    })
    .map_err(|e| match e {
        MapError::NotMapped => Errno::Fault,
        MapError::OutOfUserRange | MapError::HitsStack => Errno::Invalid,
        other => error(other),
    })
}

#[cfg(debug_assertions)]
pub(super) fn self_test() {
    use crate::mm::user_access::{copy_from_user, copy_to_user};
    let mut s = UserAddressSpace::new().expect("mincore root");
    s.map_region(0x20000, 2, F::U, AreaKind::Anonymous)
        .expect("none mapping");
    s.map_region(0x30000, 1, F::URW, AreaKind::Anonymous)
        .expect("result mapping");
    assert_eq!(mincore(&s, 0x20000, PAGE_SIZE + 1, 0x30000), Ok(0));
    let mut bytes = [0; 2];
    copy_from_user(&s, 0x30000, &mut bytes).expect("residency");
    assert_eq!(bytes, [1, 1]);
    assert_eq!(mincore(&s, 0x20001, 1, 0x30000), Err(Errno::Invalid));
    assert_eq!(mincore(&s, 0x20000, usize::MAX, 0x30000), Err(Errno::NoMem));
    assert_eq!(mincore(&s, 0x20000, 1, 0x20000), Err(Errno::Fault));
    copy_to_user(&s, 0x30fff, &[99]).expect("output sentinel");
    assert_eq!(
        mincore(&s, 0x20000, PAGE_SIZE + 1, 0x30fff),
        Err(Errno::Fault)
    );
    let mut byte = [0];
    copy_from_user(&s, 0x30fff, &mut byte).expect("unchanged output");
    assert_eq!(byte, [99]);
    s.unmap(0x21000, 1).expect("hole");
    assert_eq!(
        mincore(&s, 0x20000, PAGE_SIZE + 1, 0x30000),
        Err(Errno::NoMem)
    );
    assert_eq!(
        mremap(&mut s, [0x20001, PAGE_SIZE, PAGE_SIZE, 0, 0]),
        Err(Errno::Invalid)
    );
    assert_eq!(
        mremap(&mut s, [0x20000, PAGE_SIZE, PAGE_SIZE, 2, 0x50000]),
        Err(Errno::Invalid)
    );
    assert_eq!(
        mremap(&mut s, [0x20000, PAGE_SIZE, PAGE_SIZE, 3, 0x20000]),
        Err(Errno::Invalid)
    );
    assert_eq!(
        mremap(&mut s, [0x21000, PAGE_SIZE, PAGE_SIZE, 0, 0]),
        Err(Errno::Fault)
    );
    assert_eq!(
        mremap(&mut s, [0x20000, PAGE_SIZE, PAGE_SIZE, 3, 0x30000]),
        Ok(0x30000)
    );
    assert_eq!(s.resident(0x20000), Err(MapError::NotMapped));
    assert_eq!(s.resident(0x30000), Ok(true));
}

/// madvise(2)：支持常规访问建议及私有匿名 DONTNEED；高级建议明确拒绝。
pub(super) fn madvise(
    space: &mut UserAddressSpace,
    addr: usize,
    len: usize,
    advice: usize,
) -> Result<usize, Errno> {
    if addr % PAGE_SIZE != 0 || !matches!(advice, 0..=4 | 8 | 10 | 11 | 18 | 19 | 22 | 23) {
        return Err(Errno::Invalid);
    }
    if len == 0 {
        return Ok(0);
    }
    let n = pages(len)?;
    if matches!(advice, 8 | 22 | 23) {
        space.advise(addr, n, false).map_err(error)?;
        let end = addr + n * PAGE_SIZE;
        for a in space
            .areas()
            .iter()
            .filter(|a| a.start < end && addr < a.end)
        {
            if (advice == 8
                && (a.locked
                    || !matches!(
                        a.kind,
                        AreaKind::Anonymous | AreaKind::Stack | AreaKind::Heap
                    )))
                || (advice == 22 && !a.flags.contains(F::R))
                || (advice == 23 && !a.flags.contains(F::W))
            {
                return Err(Errno::Invalid);
            }
        }
        if advice == 8 {
            // 无交换/回收线程：选择立即收回可丢弃的私有匿名页。
            space.advise(addr, n, true).map_err(error)?;
        } else {
            let need = F::U | if advice == 22 { F::R } else { F::W };
            for va in (addr..end).step_by(PAGE_SIZE) {
                space.ensure_access(va, need).map_err(error)?;
            }
        }
    } else if advice >= 10 {
        space.fork_advice(addr, n, advice).map_err(error)?;
    } else {
        space.advise(addr, n, advice == 4).map_err(error)?;
    }
    Ok(0)
}

/// mlock/munlock/mlock2：范围按页扩展；ONFAULT 延迟物理分配。
pub(super) fn mlock(
    space: &mut UserAddressSpace,
    addr: usize,
    len: usize,
    lock: bool,
    flags: usize,
) -> Result<usize, Errno> {
    if flags & !1 != 0 {
        return Err(Errno::Invalid);
    }
    if len == 0 {
        return Ok(0);
    }
    let start = addr / PAGE_SIZE * PAGE_SIZE;
    let span = len.checked_add(addr - start).ok_or(Errno::Invalid)?;
    space
        .lock_range(start, pages(span)?, lock, flags & 1 != 0)
        .map_err(error)?;
    Ok(0)
}

/// msync(2)：同步共享文件映射；当前异步请求也等待已有后端同步完成。
pub(super) fn msync(
    space: &mut UserAddressSpace,
    addr: usize,
    len: usize,
    flags: usize,
) -> Result<usize, Errno> {
    if addr % PAGE_SIZE != 0 || flags & !7 != 0 || flags & 5 == 5 {
        return Err(Errno::Invalid);
    }
    if len == 0 {
        return Ok(0);
    }
    space.sync_range(addr, pages(len)?, flags & 2 != 0)?;
    Ok(0)
}

/// getrlimit/setrlimit/prlimit64：支持内存限额（DATA/STACK/MEMLOCK/AS）与 RLIMIT_NOFILE(7)。
pub(super) fn limit(
    space: &mut UserAddressSpace,
    fs: &mut crate::fs::context::Context,
    credentials: &crate::task::Credentials,
    resource: usize,
    new_ptr: usize,
    old_ptr: usize,
) -> Result<usize, Errno> {
    const RLIMIT_NOFILE: usize = 7;
    let old = if resource == RLIMIT_NOFILE {
        fs.nofile_limit()
    } else {
        space.memory_limit(resource).ok_or(Errno::Invalid)?
    };
    let mut next = None;
    if new_ptr != 0 {
        let mut bytes = [0; 16];
        crate::mm::user_access::copy_from_user(space, new_ptr, &mut bytes)
            .map_err(|_| Errno::Fault)?;
        let soft = usize::from_ne_bytes(bytes[..8].try_into().map_err(|_| Errno::Invalid)?);
        let hard = usize::from_ne_bytes(bytes[8..].try_into().map_err(|_| Errno::Invalid)?);
        if soft > hard {
            return Err(Errno::Invalid);
        }
        next = Some([soft, hard]);
    }
    if old_ptr != 0 {
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&old[0].to_ne_bytes());
        bytes[8..].copy_from_slice(&old[1].to_ne_bytes());
        crate::mm::user_access::copy_to_user(space, old_ptr, &bytes).map_err(|_| Errno::Fault)?;
    }
    if let Some(next) = next {
        if resource == RLIMIT_NOFILE {
            fs.set_nofile_limit(next, credentials.euid == 0)?;
        } else {
            space.set_memory_limit(resource, next).map_err(error)?;
        }
    }
    Ok(0)
}

/// 普通文件的有界预读建议。通过存储后端读入，不占用调用者文件游标。
pub(super) fn readahead(
    ctx: &crate::fs::context::Context,
    fd: usize,
    offset: usize,
    count: usize,
) -> Result<usize, Errno> {
    let (ino, _) = crate::fs::context::mapping(ctx, fd, false).map_err(|e| match e {
        Errno::Access => Errno::BadF,
        Errno::NoDevice => Errno::Invalid,
        other => other,
    })?;
    if offset > i64::MAX as usize {
        return Err(Errno::Invalid);
    }
    let size = crate::fs::stat(ino)?.1 as usize;
    if count == 0 || offset >= size {
        return Ok(0);
    }
    let mut pos = offset & !(PAGE_SIZE - 1);
    let end = size
        .min(offset.saturating_add(count))
        .min(pos.saturating_add(32 * PAGE_SIZE));
    let mut buf = alloc::vec::Vec::new();
    buf.try_reserve_exact(PAGE_SIZE).map_err(|_| Errno::NoMem)?;
    buf.resize(PAGE_SIZE, 0);
    while pos < end {
        let n = (end - pos).min(PAGE_SIZE);
        let read = crate::fs::read(ino, pos, &mut buf[..n])?;
        if read == 0 {
            break;
        }
        pos += read;
    }
    Ok(0)
}
