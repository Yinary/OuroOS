//! 内核全局堆分配器：基于固定静态缓冲提供 `GlobalAlloc`。

use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, Ordering},
};

use buddy_system_allocator::LockedHeap;

use crate::config::KERNEL_HEAP_SIZE;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();

#[repr(align(16))]
struct HeapSpace(UnsafeCell<[u8; KERNEL_HEAP_SIZE]>);

// SAFETY: 底层数组仅在启动期 `init` 中执行一次所有权移交给 `HEAP_ALLOCATOR`，
// 之后全部并发访问均受 `LockedHeap` 互斥锁保护，不再经 `HEAP_SPACE` 访问。
unsafe impl Sync for HeapSpace {}

// TODO(yinary): 固定 32 MiB 堆，后续文件系统缓存等会不够用。应改为堆不足时从页帧分配器扩展。
static HEAP_SPACE: HeapSpace = HeapSpace(UnsafeCell::new([0; KERNEL_HEAP_SIZE]));
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// 初始化内核全局堆分配器；须在首次堆分配之前且仅调用一次。
pub fn init() {
    assert!(
        !INITIALIZED.swap(true, Ordering::AcqRel),
        "kernel heap allocator initialized twice"
    );
    let ptr = HEAP_SPACE.0.get() as usize;
    // SAFETY: `INITIALIZED` 保证只初始化一次；`HEAP_SPACE` 具有 `'static` 生命周期、
    // 16 字节对齐且长度为 `KERNEL_HEAP_SIZE`，此后独占归属 `HEAP_ALLOCATOR`。
    unsafe {
        HEAP_ALLOCATOR.lock().init(ptr, KERNEL_HEAP_SIZE);
    }
}
