//! 内存系统调用：mmap/munmap/mprotect 的参数检查与实现。
//! Linux ABI 依据 man7.org/linux/man-pages/man2/{mmap,mprotect,brk}.2.html。
use super::Errno;
use crate::mm::address_space::{AreaKind, MapError, UserAddressSpace};
use polyhal::pagetable::{MappingFlags as F, PAGE_SIZE};

fn error(e: MapError) -> Errno {
    match e {
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
/// mmap(2) 子集：PRIVATE|ANONYMOUS，支持 FIXED；其余标志明确拒绝。
/// 匿名 fd 被忽略；offset 仍必须页对齐。
pub(super) fn mmap(
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
    if map_flags & 3 == 0 || map_flags & 3 == 3 {
        return Err(Errno::Invalid);
    }
    if map_flags & 0x20 == 0 {
        use crate::mm::{
            address_space::{phys_to_kernel_vaddr, Backing},
            frame::OwnedFrame,
        };
        use alloc::vec::Vec;
        if map_flags & !0x13 != 0 {
            return Err(Errno::NotSupported);
        }
        let shared = map_flags & 3 == 1;
        let (ino, writable) = crate::fs::context::mapping(ctx, _fd, shared && prot & 2 != 0)?;
        let file_size = crate::fs::stat(ino)?.1 as usize;
        let end = offset.checked_add(len).ok_or(Errno::Invalid)?;
        // 超出文件 EOF 的整页范围直接拒绝。
        if end > file_size.div_ceil(PAGE_SIZE) * PAGE_SIZE {
            return Err(Errno::NotSupported);
        }
        let fixed = map_flags & 0x10 != 0;
        let start = if fixed {
            addr
        } else {
            space.find_free(addr, n).map_err(error)?
        };
        let mut frames = Vec::new();
        frames.try_reserve(n).map_err(|_| Errno::NoMem)?;
        for i in 0..n {
            let pos = offset + i * PAGE_SIZE;
            if shared {
                frames.push(Backing::Shared(crate::fs::cache::page(ino, pos)?, writable));
            } else {
                let frame = OwnedFrame::new().map_err(|_| Errno::NoMem)?;
                let mut data = [0u8; PAGE_SIZE];
                crate::fs::read(ino, pos, &mut data)?;
                // SAFETY: 新分配的私有页独占，写入不超过一页。
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        phys_to_kernel_vaddr(frame.addr()) as *mut u8,
                        PAGE_SIZE,
                    );
                }
                frames.push(Backing::Private(frame));
            }
        }
        space.map_backed(start, frames, f, fixed).map_err(error)?;
        crate::mm::fence_icache();
        return Ok(start);
    }
    if map_flags & !0x32 != 0 || map_flags & 0x22 != 0x22 {
        return Err(Errno::NotSupported);
    }
    if map_flags & 0x10 != 0 {
        if addr % PAGE_SIZE != 0 {
            return Err(Errno::Invalid);
        }
        space.replace_region(addr, n, f).map_err(error)?;
        Ok(addr)
    } else {
        let start = space.find_free(addr, n).map_err(error)?;
        space
            .map_region(start, n, f, AreaKind::Anonymous)
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
/// mprotect(2) 子集：完整区间修改；明确拒绝可访问但禁止执行的请求。
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
