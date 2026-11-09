//! 内核栈分配：连续物理页 + RAII 回收，经内核直映窗口访问。
//!
//! 本模块是任务子系统向 mm 要的第一笔订单（见 doc/ostd-contracts.md）。
//! 当前实现为"连续页 + 直映访问"，**没有底部保护页**：rv 直映大页与
//! la DMW 窗口覆盖全部 RAM，直映地址上无法用"不映射"表达保护页，
//! 伪造一个（直映里留一页"不分配"）只会给人安全感，mm 契约明文禁止。
//! 真正受保护的内栈需要独立的虚拟映射窗口（rv 内核共享页表 + la PGDL，
//! 以及窗口条目向既有用户页表的同步协议），作为记录在案的推迟项，
//! 与调度模块一起演进。
//!
//! 已兑现的语义：
//! - 分配即清零：回收后的栈页不向下一个任务泄漏旧数据；
//! - 唯一所有权：KernelStack 不可复制，drop 归还全部页；
//! - 失败可恢复：帧不足返回 OOM，不 panic（用户可触发路径）。

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

    /// 栈顶虚拟地址（16 字节对齐，供 KContext.ksp 使用）。
    ///
    /// 返回的是直映窗口地址：内核栈访问不依赖任何用户页表，
    /// rv 侧用户页表创建时复制的内核半区粗粒度条目、la 侧 DMW
    /// 都天然覆盖它（这正是当前无窗口实现的可行性前提）。
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
