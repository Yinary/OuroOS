//! OuroOS 内核入口
#![no_std]
#![no_main]

extern crate alloc;

mod allocator;
mod config;
mod elf;
mod lang_items;
mod mm;
mod syscall;
mod task;
mod trap;
mod user;

use core::{
    hint::spin_loop,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use polyhal::{
    common::get_cpu_num,
    instruction::{ebreak, shutdown},
    irq::IRQ,
    println,
    timer::{current_time, set_next_timer},
};
use polyhal_boot::define_entry;

/// 构建时由 build.rs 生成的内嵌用户 ELF 镜像（user/hello 构建产物）
mod user_images {
    include!(concat!(env!("OUT_DIR"), "/user_images.rs"));
}

/// 当前核的时钟 tick 计数（trap.rs 中累加），启动自检只等待本核时钟。
/// 保留原子访问，避免主流程读取与时钟中断更新之间的普通内存访问冲突。
#[polyhal::percpu]
pub static TIMER_TICKS: AtomicUsize = AtomicUsize::new(0);

/// 当前核在内核态触发断点的次数（trap.rs 中累加），供启动自检断言。
#[polyhal::percpu]
pub static BREAK_TICKS: AtomicUsize = AtomicUsize::new(0);

/// 内核入口（polyhal-boot 完成架构早期初始化后调用）
fn rust_main(hartid: usize) {
    allocator::init();
    mm::init();
    // trap 路径自检
    ebreak();
    assert_eq!(
        BREAK_TICKS.load(Ordering::Relaxed),
        1,
        "trap self-check failed: breakpoint not delivered"
    );

    // 打开中断并启动第一个 tick
    IRQ::int_enable();
    set_next_timer(current_time() + Duration::from_millis(config::TICK_MS));

    while TIMER_TICKS.load(Ordering::Relaxed) < config::BOOT_TICKS {
        spin_loop();
    }

    // 自检（heap/帧分配/trap/时钟）全部通过
    println!(
        "{} v{} · {} · boot hart {} · {} cpus · boot ok",
        config::KERNEL_NAME,
        config::KERNEL_VERSION,
        config::ARCH_NAME,
        hartid,
        get_cpu_num()
    );
    task::run_demo();

    // 依次运行内嵌的用户程序，结束后统一关机
    // hello：write 固定消息 → 校验返回字节数 → exit(0)
    user::run_user_elf("hello", user_images::HELLO_ELF);
    // check：系统调用错误路径检查（EFAULT/EBADF/ENOSYS 等），
    // 最后故意触发一次用户态非法访存，由内核报告并终止
    user::run_user_elf("check", user_images::CHECK_ELF);

    shutdown();
}

// 副核入口，正常运行不会到达；保留以满足 define_entry! 两入口签名
fn secondary_main(hartid: usize) {
    log::debug!("hart {} (secondary) up, parked.", hartid);
    loop {
        spin_loop();
    }
}

define_entry!(rust_main, secondary_main);
