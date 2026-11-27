//! 用户内存访问：内核与用户地址空间之间的数据复制——地址范围校验、
//! 逐页翻译与权限校验、经内核直映窗口复制；用户指针不构造为 Rust 引用。

use alloc::vec::Vec;
use polyhal::{
    pagetable::{MappingFlags, PAGE_SIZE},
    PhysAddr,
};

use super::address_space::{phys_to_kernel_vaddr, UserAddressSpace, USER_TOP};

/// 用户缓冲区访问失败原因
#[derive(Debug)]
pub enum AccessError {
    /// 地址溢出、越界、未映射、非用户页或权限不符 → EFAULT
    Fault,
    /// 用户态直接访存需报告 SIGBUS；系统调用复制仍转换为 EFAULT。
    FileFault,
    FileIo,
    OutOfMemory,
}

impl From<super::address_space::MapError> for AccessError {
    fn from(error: super::address_space::MapError) -> Self {
        match error {
            super::address_space::MapError::FileFault => Self::FileFault,
            super::address_space::MapError::FileIo => Self::FileIo,
            super::address_space::MapError::OutOfMemory => Self::OutOfMemory,
            _ => Self::Fault,
        }
    }
}

/// 栈上小页表缓存上限：覆盖 4 页（≤12 KiB 跨越），避免常规 1~4 KiB 读写每轮堆分配。
const INLINE_PAGES: usize = 4;

/// 第一遍校验整段并记录物理页与页内长度；短传输直接落栈数组（零堆分配），
/// 长传输退回 `Vec` 或两遍慢路径。缓存内容不跨调用保存。
enum PreparedPages {
    Inline {
        entries: [(PhysAddr, usize); INLINE_PAGES],
        len: usize,
    },
    Heap(Vec<(PhysAddr, usize)>),
}

impl PreparedPages {
    #[inline]
    fn as_slice(&self) -> &[(PhysAddr, usize)] {
        match self {
            Self::Inline { entries, len } => &entries[..*len],
            Self::Heap(vec) => vec.as_slice(),
        }
    }
}

fn prepare_pages(
    space: &UserAddressSpace,
    vaddr: usize,
    len: usize,
    required: MappingFlags,
) -> Result<Option<PreparedPages>, AccessError> {
    let end = check_span(vaddr, len)?;
    if len == 0 {
        return Ok(Some(PreparedPages::Inline {
            entries: [(PhysAddr::new(0), 0); INLINE_PAGES],
            len: 0,
        }));
    }
    let first = vaddr / PAGE_SIZE;
    let last = (end - 1) / PAGE_SIZE;
    let pages = last - first + 1;
    if pages <= INLINE_PAGES {
        let mut entries = [(PhysAddr::new(0), 0); INLINE_PAGES];
        let mut va = vaddr;
        let mut count = 0usize;
        while va < end {
            let paddr = space.ensure_and_translate(va, required)?;
            let n = ((va / PAGE_SIZE + 1) * PAGE_SIZE).min(end) - va;
            entries[count] = (paddr, n);
            count += 1;
            va += n;
        }
        return Ok(Some(PreparedPages::Inline {
            entries,
            len: count,
        }));
    }
    let mut cache = Vec::new();
    if cache.try_reserve(pages).is_err() {
        return Ok(None);
    }
    let mut va = vaddr;
    while va < end {
        let paddr = space.ensure_and_translate(va, required)?;
        let n = ((va / PAGE_SIZE + 1) * PAGE_SIZE).min(end) - va;
        cache.push((paddr, n));
        va += n;
    }
    Ok(Some(PreparedPages::Heap(cache)))
}

/// 把 `src` 写入用户地址 `[vaddr, vaddr+src.len())`。
///
/// 先对整段做可写检查，全部通过后才写入；失败时不产生部分写入。
pub fn copy_to_user(space: &UserAddressSpace, vaddr: usize, src: &[u8]) -> Result<(), AccessError> {
    if let Some(cache) = prepare_pages(space, vaddr, src.len(), MappingFlags::U | MappingFlags::W)?
    {
        let mut done = 0usize;
        for &(paddr, n) in cache.as_slice() {
            // SAFETY: prepare_pages 已确认本页属于用户且可写；dst 为本页的
            // 内核直接映射地址，n 不越过页尾，src 与 dst 不重叠。
            unsafe {
                core::ptr::copy_nonoverlapping(
                    src.as_ptr().add(done),
                    phys_to_kernel_vaddr(paddr) as *mut u8,
                    n,
                );
            }
            done += n;
        }
        return Ok(());
    }
    copy_to_user_slow(space, vaddr, src)
}

fn copy_to_user_slow(
    space: &UserAddressSpace,
    vaddr: usize,
    src: &[u8],
) -> Result<(), AccessError> {
    let end = check_span(vaddr, src.len())?;
    let mut va = vaddr;
    while va < end {
        space.ensure_access(va, MappingFlags::U | MappingFlags::W)?;
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
    copy_from_user_with_flags(space, vaddr, dst, MappingFlags::U | MappingFlags::R)
}

/// 从用户可执行映射读取指令字节；允许仅 X 而不可 R 的代码页。
#[cfg(target_arch = "loongarch64")]
pub fn copy_user_instruction(
    space: &UserAddressSpace,
    vaddr: usize,
    dst: &mut [u8],
) -> Result<(), AccessError> {
    copy_from_user_with_flags(space, vaddr, dst, MappingFlags::U | MappingFlags::X)
}

fn copy_from_user_with_flags(
    space: &UserAddressSpace,
    vaddr: usize,
    dst: &mut [u8],
    required: MappingFlags,
) -> Result<(), AccessError> {
    if let Some(cache) = prepare_pages(space, vaddr, dst.len(), required)? {
        let mut done = 0usize;
        for &(paddr, n) in cache.as_slice() {
            // SAFETY: prepare_pages 已确认本页属于用户且可读；src 为本页的
            // 内核直接映射地址，n 不越过页尾，src 与 dst 不重叠。
            unsafe {
                core::ptr::copy_nonoverlapping(
                    phys_to_kernel_vaddr(paddr) as *const u8,
                    dst.as_mut_ptr().add(done),
                    n,
                );
            }
            done += n;
        }
        return Ok(());
    }
    copy_from_user_slow(space, vaddr, dst, required)
}

fn copy_from_user_slow(
    space: &UserAddressSpace,
    vaddr: usize,
    dst: &mut [u8],
    required: MappingFlags,
) -> Result<(), AccessError> {
    let end = check_span(vaddr, dst.len())?;
    let mut va = vaddr;
    while va < end {
        space.ensure_access(va, required)?;
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
