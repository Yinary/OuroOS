//! 物理内存管理。
//!
//! 职责链：FDT 内存区域 → buddy 页帧分配器（mm::frame）→ 注册给 PolyHAL
//! （polyhal::common 需要单页分配器来创建页表）。

pub mod address_space;
pub mod frame;
pub mod user_access;

use polyhal::{
    common::{init as hal_init, PageAlloc},
    mem::get_mem_areas,
    pagetable, PhysAddr,
};

/// PolyHAL 页表分配所需的单页分配器实现
pub struct PageAllocImpl;

impl PageAlloc for PageAllocImpl {
    fn alloc(&self) -> PhysAddr {
        let paddr = frame::frame_alloc(1);
        // 必须清零：polyhal 的 map_page 分配子页表页后不清零，而 PTE 的
        // is_valid/is_table 判定（loongarch64 侧为 `!= 0`）会把页帧里的残留
        // 数据当成有效表项，沿垃圾指针继续走表。所有 polyhal 页表页
        // （PageTableWrapper::alloc 与 map_page 的中间表）都经过本方法。
        paddr.clear_len(pagetable::PAGE_SIZE);
        paddr
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

/// 写入用户代码后同步指令缓存。
///
/// 内核经 `pa | VIRT_ADDR_START` 别名写入用户代码页，而用户态将在用户虚拟
/// 地址上取指，两者在物理上是同一页。riscv64 需要 `fence.i`、loongarch64
/// 需要 `ibar` 才能保证取指看到新代码。PolyHAL 0.4.0 未封装这两条指令，
/// 因此这里出现 `#[cfg(target_arch)]`（AGENTS.md 的例外情况：目标指令无法
/// 用通用抽象表达）。
#[cfg(target_arch = "riscv64")]
pub fn fence_icache() {
    unsafe {
        core::arch::asm!("fence.i");
    }
}

#[cfg(target_arch = "loongarch64")]
pub fn fence_icache() {
    unsafe {
        core::arch::asm!("ibar 0");
    }
}
