//! 用户内存访问：内核与用户地址空间之间的数据复制——地址范围校验、
//! 逐页翻译与权限校验、经内核直映窗口复制；用户指针不构造为 Rust 引用。

use polyhal::pagetable::{MappingFlags, PAGE_SIZE};

use super::address_space::{phys_to_kernel_vaddr, UserAddressSpace, USER_TOP};

/// 复制到内核缓冲区的分块大小上限。
const KERNEL_CHUNK: usize = 256;

/// 用户缓冲区访问失败原因
#[derive(Debug)]
pub enum AccessError {
    /// 地址溢出、越界、未映射、非用户页或权限不符 → EFAULT
    Fault,
}

/// 两架构统一检查用户位与读权限。
fn page_readable(flags: MappingFlags) -> bool {
    flags.contains(MappingFlags::U | MappingFlags::R)
}
/// 两架构统一检查用户位与写权限。
fn page_writable(flags: MappingFlags) -> bool {
    flags.contains(MappingFlags::U | MappingFlags::W)
}
/// 把用户缓冲区 `[vaddr, vaddr+len)` 的内容分块交给 `consume`。
///
/// 先对整段做权限检查，全部通过后才复制；失败时不产生部分输出。
/// 每个分块不跨页边界，长度不超过 [`KERNEL_CHUNK`]。
pub fn read_user_bytes<F>(
    space: &UserAddressSpace,
    vaddr: usize,
    len: usize,
    mut consume: F,
) -> Result<(), AccessError>
where
    F: FnMut(&[u8]),
{
    let end = check_span(vaddr, len)?;
    // 第一遍：整段映射与权限检查
    let mut va = vaddr;
    while va < end {
        let (_, flags) = space.translate(va).ok_or(AccessError::Fault)?;
        if !page_readable(flags) {
            return Err(AccessError::Fault);
        }
        va = (va / PAGE_SIZE + 1) * PAGE_SIZE;
    }
    // 第二遍：经内核直接映射分块复制
    let mut buf = [0u8; KERNEL_CHUNK];
    let mut pos = vaddr;
    while pos < end {
        let page_end = ((pos / PAGE_SIZE + 1) * PAGE_SIZE).min(end);
        // translate 返回的物理地址含页内偏移
        let (paddr, _) = space.translate(pos).ok_or(AccessError::Fault)?;
        let mut copied = 0usize;
        while copied < page_end - pos {
            // SAFETY: 上一循环已确认本页映射存在且可读；src 为本页的
            // 内核直接映射地址，n 不超过页内剩余长度。
            let src = phys_to_kernel_vaddr(paddr) + copied;
            let n = (page_end - pos - copied).min(KERNEL_CHUNK);
            let chunk = unsafe { core::slice::from_raw_parts(src as *const u8, n) };
            buf[..n].copy_from_slice(chunk);
            consume(&buf[..n]);
            copied += n;
        }
        pos = page_end;
    }
    Ok(())
}

/// 把 `src` 写入用户地址 `[vaddr, vaddr+src.len())`。
///
/// 先对整段做可写检查，全部通过后才写入；失败时不产生部分写入。
/// 按页切分，每页单独翻译；用户虚拟地址连续不要求物理连续。
pub fn copy_to_user(space: &UserAddressSpace, vaddr: usize, src: &[u8]) -> Result<(), AccessError> {
    let end = check_span(vaddr, src.len())?;
    let mut va = vaddr;
    while va < end {
        let (_, flags) = space.translate(va).ok_or(AccessError::Fault)?;
        if !page_writable(flags) {
            return Err(AccessError::Fault);
        }
        va = (va / PAGE_SIZE + 1) * PAGE_SIZE;
    }
    let mut pos = vaddr;
    let mut done = 0usize;
    while pos < end {
        let (paddr, _) = space.translate(pos).ok_or(AccessError::Fault)?;
        let n = ((pos / PAGE_SIZE + 1) * PAGE_SIZE).min(end) - pos;
        // SAFETY: 上一循环已确认本页属于用户且可写；dst 为本页的内核
        // 直接映射地址，n 不越过页尾，src 与 dst 不重叠。
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(done),
                phys_to_kernel_vaddr(paddr) as *mut u8,
                n,
            );
        }
        done += n;
        pos += n;
    }
    Ok(())
}

/// 从用户地址 `[vaddr, vaddr+dst.len())` 读出到 `dst`。
///
/// 先对整段做可读检查，全部通过后才复制：失败时 `dst` 不被修改。
pub fn copy_from_user(
    space: &UserAddressSpace,
    vaddr: usize,
    dst: &mut [u8],
) -> Result<(), AccessError> {
    let end = check_span(vaddr, dst.len())?;
    let mut va = vaddr;
    while va < end {
        let (_, flags) = space.translate(va).ok_or(AccessError::Fault)?;
        if !page_readable(flags) {
            return Err(AccessError::Fault);
        }
        va = (va / PAGE_SIZE + 1) * PAGE_SIZE;
    }
    let mut pos = vaddr;
    let mut done = 0usize;
    while pos < end {
        let (paddr, _) = space.translate(pos).ok_or(AccessError::Fault)?;
        let n = ((pos / PAGE_SIZE + 1) * PAGE_SIZE).min(end) - pos;
        // SAFETY: 上一循环已确认本页属于用户且可读；src 为本页的内核
        // 直接映射地址，n 不越过页尾，src 与 dst 不重叠。
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_kernel_vaddr(paddr) as *const u8,
                dst.as_mut_ptr().add(done),
                n,
            );
        }
        done += n;
        pos += n;
    }
    Ok(())
}

/// 检查 `[vaddr, vaddr+len)` 的溢出与用户地址范围，返回结束地址。
fn check_span(vaddr: usize, len: usize) -> Result<usize, AccessError> {
    let end = vaddr.checked_add(len).ok_or(AccessError::Fault)?;
    if end > USER_TOP {
        return Err(AccessError::Fault);
    }
    Ok(end)
}
