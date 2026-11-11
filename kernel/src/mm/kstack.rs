//! 内核栈分配：连续物理页 + RAII 回收，经内核直映访问（无保护页，
//! 窗口欠账见 docs/ostd-contracts.md §1）。

use polyhal::{consts::VIRT_ADDR_START, pagetable::PAGE_SIZE, PhysAddr};

use super::frame::{self, FrameError};

/// 连续物理页构成的内核栈，drop 时整块归还帧分配器。
pub struct KernelStack {
    base: PhysAddr,
    pages: usize,
}

impl KernelStack {
    /// 分配 `pages` 页连续内存并清零。
    ///
    /// 连续性是硬要求：栈经内核直映窗口（pa | VIRT_ADDR_START / DMW）
    /// 访问，非连续物理页在直映上不构成连续栈。
    pub fn new(pages: usize) -> Result<Self, FrameError> {
        if pages == 0 {
            return Err(FrameError::InvalidCount);
        }
        let base = frame::frame_alloc(pages)?;
        base.clear_len(pages * PAGE_SIZE);
        Ok(Self { base, pages })
    }

    /// 栈顶虚拟地址（直映窗口地址，16 字节对齐，供 KContext.ksp）。
    pub fn top(&self) -> usize {
        let top = (self.base.raw() | VIRT_ADDR_START) + self.pages * PAGE_SIZE;
        debug_assert_eq!(top % 16, 0, "kernel stack top must be 16-byte aligned");
        top
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        for i in 0..self.pages {
            // SAFETY: 构造时独占分配、类型不可复制，拥有者负责先让
            // 任何执行流离开该栈（调度器只回收已切走且不再调度的任务）。
            unsafe {
                frame::frame_dealloc(PhysAddr::new(self.base.raw() + i * PAGE_SIZE));
            }
        }
    }
}
