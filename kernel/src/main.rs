//! OuroOS 内核入口
#![no_std]
#![feature(allocator_api)]
#![feature(naked_functions)]
#![no_main]

extern crate alloc;

mod allocator;
mod config;
mod dmesg;
mod drivers;
mod elf;
mod entropy;
mod fs;
mod hal;
mod lang_items;
mod mm;
mod sigframe;
mod sync;
mod syscall;
mod task;
mod time;
mod timer;
mod trap;

use core::{
    hint::spin_loop,
    sync::atomic::{AtomicUsize, Ordering},
};

use polyhal::{common::get_cpu_num, instruction::ebreak, irq::IRQ, println};
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
    entropy::init();
    #[cfg(all(debug_assertions, target_arch = "loongarch64"))]
    trap::self_test_unaligned();
    drivers::init().expect("block device initialization failed");
    fs::init().expect("root filesystem initialization failed");
    // 自检：trap 回调链路——断点必须恰好送达一次（每次启动）
    ebreak();
    assert_eq!(
        BREAK_TICKS.load(Ordering::Relaxed),
        1,
        "trap self-check failed: breakpoint not delivered"
    );

    // 打开中断并启动定时器。
    IRQ::int_enable();
    timer::init();

    // 自检：时钟中断持续到达——等待 BOOT_TICKS 个 tick（每次启动）
    while TIMER_TICKS.load(Ordering::Relaxed) < config::BOOT_TICKS {
        spin_loop();
    }

    // 墙钟与 RTC 的秒边界对齐一次。
    time::align_realtime();

    // 自检（heap/帧分配/trap/时钟）全部通过
    let boot_line = alloc::format!(
        "{} v{} · {} · boot hart {} · {} cpus · boot ok",
        config::KERNEL_NAME,
        config::KERNEL_VERSION,
        config::ARCH_NAME,
        hartid,
        get_cpu_num()
    );
    println!("{}", boot_line);
    dmesg::append(&boot_line);

    // 任务时代基线：全部任务退出后帧统计必须回到这里（帧守恒断言）
    let baseline = mm::frame::stats();

    // 孵化用户任务。
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
    } else if fs::mounted() {
        // 根卷已挂载但盘上没有 /init（官方原盘布局）：启动内置用户态
        // 启动器，由它建立解释器/shell 布局并运行盘上的官方组脚本
        if user_images::INIT_ELF.is_empty() {
            println!("[boot] 根卷无 /init 且未内嵌启动器（脱离 Makefile 构建），跳过用户程序");
            task::spawn_demo_kthreads();
            &[]
        } else {
            &[("official-init", user_images::INIT_ELF)]
        }
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
    let mut spawned = 0usize;
    let mut no_entropy = false;
    for &(name, elf) in images {
        match task::spawn_user(name, elf) {
            Ok(pid) => {
                spawned += 1;
                println!("[task] spawned {} as pid {}", name, pid);
            }
            // 空镜像（脱离 Makefile 构建时）或加载失败：报告后继续
            Err(task::SpawnError::Load(e)) => {
                println!("[task] spawn {} failed: elf {:?}", name, e)
            }
            Err(task::SpawnError::OutOfMemory) => {
                println!("[task] spawn {} failed: out of memory", name)
            }
            Err(task::SpawnError::NoEntropy) => {
                no_entropy = true;
                println!("[task] spawn {} failed: no boot entropy", name)
            }
        }
    }
    if spawned == 0 && no_entropy {
        log::error!("no user task spawned: boot entropy is unavailable");
        #[cfg(not(feature = "rsext4-readonly"))]
        if let Err(error) = fs::shutdown() {
            log::error!("Ext4 shutdown failed: {:?}", error);
        }
        hal::shutdown();
    }

    // 进入任务时代：关中断、跑调度器到全部退出、汇总并断言帧守恒
    task::run(baseline);
    #[cfg(not(feature = "rsext4-readonly"))]
    if let Err(error) = fs::shutdown() {
        log::error!("Ext4 shutdown failed: {:?}", error);
    }
    hal::shutdown();
}

// 副核入口，正常运行不会到达；保留以满足 define_entry! 两入口签名
fn secondary_main(hartid: usize) {
    log::debug!("hart {} (secondary) up, parked.", hartid);
    loop {
        spin_loop();
    }
}

define_entry!(rust_main, secondary_main);
