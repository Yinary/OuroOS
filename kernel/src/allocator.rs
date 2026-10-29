//! 内核动态内存（堆）。
//!
//! polyhal-boot 的 bstack（引导栈，.bss.bstack 段）与内核堆都位于内核镜像内，
//! polyhal 解析 FDT 时已把 [_skernel, _end) 从可用内存中排除，不会冲突。
//!
//! `static mut HEAP_SPACE` 是 AGENTS.md 禁止事项的一个例外：在帧分配器就绪前，
//! 堆只能来自内核镜像里的一块静态内存。

use buddy_system_allocator::LockedHeap;

use crate::config::KERNEL_HEAP_SIZE;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();

// TODO(yinary): 固定 8 MiB 堆，后续文件系统缓存等会不够用。应改为堆不足时从页帧分配器扩展。
static mut HEAP_SPACE: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

/// 初始化内核堆。须在第一次堆分配之前调用（当前在 `rust_main` 最先调用）。
pub fn init() {
    // SAFETY: 启动单线程阶段调用，此时没有其他代码访问 HEAP_SPACE；
    // 取裸指针只把地址交给分配器，不产生引用别名。
    let ptr = &raw mut HEAP_SPACE;
    unsafe {
        HEAP_ALLOCATOR.lock().init(ptr as usize, KERNEL_HEAP_SIZE);
    }
}
