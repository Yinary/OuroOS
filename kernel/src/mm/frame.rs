//! 物理页帧分配器（buddy 系统）。
//!
//! 内存来源：PolyHAL 从 FDT 解析出的可用内存区域（已排除内核镜像与 DTB）。
//!
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal example 目录
//! 原协议：MIT
//! 修改说明：修正了登记区域与内核镜像末尾求交时的起点计算，并补充注释。

use buddy_system_allocator::FrameAllocator;
use polyhal::{pagetable::PAGE_SIZE, PhysAddr};
use spin::Mutex;

static LOCK_FRAME_ALLOCATOR: Mutex<FrameAllocator<32>> = Mutex::new(FrameAllocator::new());

/// 把一段物理内存 [`mm_start`, `mm_end`) 按页登记进分配器。
///
/// 起点取 `max(mm_start, 内核镜像末尾 _end)` 向上对齐到页（防止把内核
/// 占用的区域登记进来），终点向下对齐到页；对齐后起点不小于终点时跳过
/// 这段区域（空区间或不足一页）。
pub fn add_frame_range(mm_start: usize, mm_end: usize) {
    extern "C" {
        fn _end();
    }
    let start_ppn = mm_start.max(_end as usize).div_ceil(PAGE_SIZE);
    let end_ppn = mm_end / PAGE_SIZE;
    if start_ppn >= end_ppn {
        return;
    }
    LOCK_FRAME_ALLOCATOR.lock().add_frame(start_ppn, end_ppn);
}

/// 分配 `count` 个连续物理页，返回起始物理地址。
///
/// # Panics
/// 空闲内存不足时 panic（当前仅内核启动路径使用）。
pub fn frame_alloc(count: usize) -> PhysAddr {
    let ppn = LOCK_FRAME_ALLOCATOR
        .lock()
        .alloc(count)
        .expect("frame_alloc: out of memory");
    PhysAddr::new(ppn << 12)
}

/// 归还单个物理页
pub fn frame_dealloc(paddr: PhysAddr) {
    LOCK_FRAME_ALLOCATOR.lock().dealloc(paddr.raw() >> 12, 1);
}
