//! 物理内存管理。
//!
//! 职责链：FDT 内存区域 → buddy 页帧分配器（mm::frame）→ 注册给 PolyHAL
//! （polyhal::common 需要单页分配器来创建页表）。

pub mod frame;

use polyhal::{
    common::{init as hal_init, PageAlloc},
    mem::get_mem_areas,
    PhysAddr,
};

/// PolyHAL 页表分配所需的单页分配器实现
pub struct PageAllocImpl;

impl PageAlloc for PageAllocImpl {
    fn alloc(&self) -> PhysAddr {
        frame::frame_alloc(1)
    }

    fn dealloc(&self, paddr: PhysAddr) {
        frame::frame_dealloc(paddr)
    }
}

/// 初始化物理内存管理：登记全部可用内存区域，并把页分配器挂给 PolyHAL。
/// 须在堆初始化之后、第一次创建页表之前调用。
pub fn init() {
    // 登记全部可用内存区域（polyhal 已排除内核镜像、DTB、引导期占用）
    get_mem_areas().for_each(|(start, size)| {
        log::info!("memory region: {:#x} - {:#x}", start, start + size);
        frame::add_frame_range(*start, start + size);
    });

    // 把页分配器挂给 PolyHAL（惰性生效，页表创建时才会真正分配）
    hal_init(&PageAllocImpl);
    log::info!("frame allocator ready");
}
