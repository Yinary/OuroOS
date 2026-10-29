//! 用户内存访问：把用户缓冲区内容分块复制进内核固定缓冲区。
//!
//! 安全前提（本轮成立，须随并发功能引入时重新审视）：全局只有一个用户
//! 任务，且系统调用处理期间没有 munmap、没有其他 CPU 触发地址空间变化，
//! 因此“逐页检查 → 复制”期间映射保持稳定。
//!
//! 不把用户指针直接当作 Rust 切片引用，而是：
//! 1. 检查地址 + 长度是否溢出、是否在用户地址范围内；
//! 2. 逐页走用户页表翻译，检查映射存在、属于用户（U 位）且可读；
//! 3. 经物理页的内核直接映射窗口复制到固定大小的内核栈缓冲区；
//! 4. 由调用方分块消费原始字节，不把任意字节当 UTF-8。

use polyhal::pagetable::{MappingFlags, PAGE_SIZE};

use super::address_space::{phys_to_kernel_vaddr, UserAddressSpace, USER_BASE, USER_TOP};

/// 复制到内核缓冲区的分块大小。按用户长度直接申请同样大的堆缓冲既浪费
/// 又可能被用户以超大长度勒索内核，故固定为小分块。
const KERNEL_CHUNK: usize = 256;

/// 用户缓冲区访问失败原因
#[derive(Debug)]
pub enum AccessError {
    /// 地址溢出、越出用户范围、未映射、非用户页或不可读 → EFAULT
    Fault,
}

/// 检查 `[vaddr, vaddr+len)` 中一页的用户映射是否可读。
///
/// riscv64：要求 U|R。loongarch64：PTE 无独立的 R 位（映射即可读，
/// polyhal 未暴露 NR），只能检查 U 位——权限表达限制见地址空间模块注释。
fn page_readable(flags: MappingFlags) -> bool {
    if !flags.contains(MappingFlags::U) {
        return false;
    }
    #[cfg(target_arch = "riscv64")]
    {
        flags.contains(MappingFlags::R)
    }
    // loongarch64：polyhal 的 MappingFlags 转换不产生 R 位（见上方说明）
    #[cfg(target_arch = "loongarch64")]
    {
        true
    }
}

/// 把用户缓冲区 `[vaddr, vaddr+len)` 的内容分块交给 `consume`。
///
/// 先对整段做映射检查，全部通过后才真正复制输出：出错时不产生部分写出
/// （Linux 的 write 允许先写成功部分再返回 EFAULT，本轮未实现该语义）。
/// 每个分块最长 [`KERNEL_CHUNK`] 字节，且不跨物理页边界。
pub fn read_user_bytes<F>(
    space: &UserAddressSpace,
    vaddr: usize,
    len: usize,
    mut consume: F,
) -> Result<(), AccessError>
where
    F: FnMut(&[u8]),
{
    let Some(end) = vaddr.checked_add(len) else {
        return Err(AccessError::Fault);
    };
    // 用户指针必须落在用户地址范围内：栈区是合法映射的用户内存，允许；
    // 内核高位地址（rv 经复制的高半区条目、la 经 DMW）在此被拒绝
    if vaddr < USER_BASE || end > USER_TOP {
        return Err(AccessError::Fault);
    }
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
        // translate 返回的物理地址已含页内偏移
        let (paddr, _) = space.translate(pos).ok_or(AccessError::Fault)?;
        let mut copied = 0usize;
        while copied < page_end - pos {
            // SAFETY: 前一循环已确认本页映射存在且可读；src 为该页经内核
            // 直接映射窗口的地址，n 不超过本页剩余长度，读取不会越页。
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
