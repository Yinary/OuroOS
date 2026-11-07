// 内核堆分配器

use buddy_system_allocator::LockedHeap;

use crate::config::KERNEL_HEAP_SIZE;

#[global_allocator]
static HEAP_ALLOCATOR: LockedHeap<32> = LockedHeap::<32>::empty();

// TODO(yinary): 固定 8 MiB 堆，后续文件系统缓存等会不够用。应改为堆不足时从页帧分配器扩展。
static mut HEAP_SPACE: [u8; KERNEL_HEAP_SIZE] = [0; KERNEL_HEAP_SIZE];

pub fn init() {
    // 取裸指针只把地址交给分配器，不产生引用别名。
    let ptr = &raw mut HEAP_SPACE;
    unsafe {
        HEAP_ALLOCATOR.lock().init(ptr as usize, KERNEL_HEAP_SIZE);
    }
}
