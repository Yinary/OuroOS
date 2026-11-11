//! OuroOS 内核入口
#![no_std]
#![feature(allocator_api)]
#![no_main]

extern crate alloc;

mod allocator;
mod config;
mod drivers;
mod elf;
mod fs;
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
    drivers::init().expect("block device initialization failed");
    fs::init().expect("root filesystem initialization failed");
    // 自检：trap 回调链路——断点必须恰好送达一次（每次启动）
    ebreak();
    assert_eq!(
        BREAK_TICKS.load(Ordering::Relaxed),
        1,
        "trap self-check failed: breakpoint not delivered"
    );

    // 打开中断并启动第一个 tick；孵化阶段须保持此稳态
    // （rv TrapFrame sstatus 前提，见 docs/ostd-contracts.md §3）
    IRQ::int_enable();
    set_next_timer(current_time() + Duration::from_millis(config::TICK_MS));

    // 自检：时钟中断持续到达——等待 BOOT_TICKS 个 tick（每次启动）
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

    // 孵化须在 task::run 关中断之前（契约"孵化时机"）
    task::init();
    let disk_init = if user_images::TEST_ELF.is_empty() {
        fs::context::Context::new()
            .ok()
            .and_then(|ctx| fs::context::executable(&ctx, "/init").ok())
    } else {
        None
    };
    let images: &[(&str, &[u8])] = if !user_images::TEST_ELF.is_empty() {
        &[("test", user_images::TEST_ELF)]
    } else if let Some(image) = disk_init.as_ref() {
        &[("basic-init", image.as_slice())]
    } else {
        task::spawn_demo_kthreads();
        &[
            ("hello", user_images::HELLO_ELF),
            ("sched", user_images::SCHED_ELF),
            ("sched", user_images::SCHED_ELF),
            ("check", user_images::CHECK_ELF),
            ("ill", user_images::ILL_ELF),
        ]
    };
    for &(name, elf) in images {
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
