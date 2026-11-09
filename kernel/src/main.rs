//! OuroOS 内核入口
#![no_std]
#![no_main]

extern crate alloc;

mod allocator;
mod config;
mod elf;
mod lang_items;
mod mm;
mod sync;
mod syscall;
mod task;
mod trap;

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

/// 构建时由 build.rs 生成的内嵌用户 ELF 镜像（user/hello 构建产物）。
/// 无文件系统阶段的统一程序来源：所有任务一律从镜像表孵化。
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

    // 打开中断并启动第一个 tick。启动自检阶段保持开中断稳态；
    // 之后的孵化阶段依赖此稳态（rv 初始 TrapFrame 的 sstatus 拷贝，
    // 见 task 契约"孵化时机"），任务时代才关中断。
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

    // 任务时代基线：全部任务退出后帧统计必须回到这里（帧守恒断言）
    let baseline = mm::frame::stats();

    // 调度器就绪后孵化全部任务（见 task 契约"孵化时机"：
    // 必须在 task::run 关中断之前）。
    task::init();
    task::spawn_demo_kthreads();
    for (name, elf) in [
        ("hello", user_images::HELLO_ELF),
        ("sched", user_images::SCHED_ELF),
        ("sched", user_images::SCHED_ELF),
        ("check", user_images::CHECK_ELF),
    ] {
        match task::spawn_user(name, elf) {
            Ok(pid) => println!("[task] spawned {} as pid {}", name, pid),
            // 空镜像（脱离 Makefile 构建时）或加载失败：报告后继续
            Err(task::SpawnError::Load(e)) => {
                println!("[task] spawn {} failed: elf {:?}", name, e)
            }
            Err(task::SpawnError::OutOfMemory) => {
                println!("[task] spawn {} failed: out of memory", name)
            }
        }
    }

    // 进入任务时代：关中断、跑调度器到全部退出、汇总并断言帧守恒
    task::run(baseline);
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
