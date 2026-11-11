//! 内存子系统：物理账本 → 帧所有权 → 页表机制 → 用户地址空间 → 用户访存。
//! 完整契约（不变量、语义规范、接入顺序、欠账）见 docs/ostd-contracts.md §1。

pub mod address_space;
mod arch;
pub mod frame;
pub mod kernel_pt;
pub mod kstack;
mod page_table;
pub mod region;
mod self_test;
pub mod user_access;
use core::sync::atomic::{AtomicUsize, Ordering};
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

/// 初始化一次，先完成物理记账，再运行启动期内存自检。
/// 引导数据不可用或元数据分配失败是启动失败，不属于用户系统调用路径。
pub fn init() {
    region::init().expect("physical memory initialization failed");
    let (total, free) = frame::stats();
    assert!(total > 0, "no usable physical memory");
    log::info!(
        "frame allocator: {} pages free / {} registered",
        free,
        total
    );
    // 自检：帧账本守恒——超量申请被拒且不改变空闲数（每次启动）
    assert_eq!(
        frame::frame_alloc(free + 1),
        Err(frame::FrameError::OutOfMemory)
    );
    assert_eq!(frame::stats(), (total, free));
    log::info!("frame allocator oversized allocation: rejected without changing free pages");
    // 顺序约束：kernel_pt::init 先于 KERNEL_ROOT 读取
    kernel_pt::init();
    KERNEL_ROOT.store(arch::current(), Ordering::Relaxed);
    self_test::run();
}
/// 经内核别名写入用户代码后同步指令缓存。PolyHAL 未提供对应封装。
pub fn fence_icache() {
    // SAFETY: 当前运行在内核特权态；指令不访问 Rust 内存，无寄存器破坏。
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("fence.i");
        #[cfg(target_arch = "loongarch64")]
        core::arch::asm!("ibar 0");
    }
}
