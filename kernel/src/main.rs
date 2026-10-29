//! OuroOS 内核入口：基于 PolyHAL 的双架构（riscv64 / loongarch64）启动骨架。
//!
//! 两个架构共用同一份 Rust 代码，架构差异全部由 PolyHAL / polyhal-boot 吸收：
//!
//! ```text
//! riscv64:    QEMU(-bios default=OpenSBI) -kernel kernel-rv(ELF)
//!             → OpenSBI 以 S 态交接 a0=hartid, a1=dtb，PC=0x80200000
//!             → polyhal-boot 汇编入口：建恒等+高位映射页表，开 MMU，跳入高位
//! loongarch64: QEMU -kernel kernel-la(ELF)
//!             → 所有核从 ELF 入口(0x9000000080000000)启动（DA 模式下高位被截断，
//!               实际取指于物理 0x80000000）
//!             → polyhal-boot 汇编入口：设 DMW 窗口，开 PG，跳入 DMW 映射地址
//!     ↓ 两者汇聚
//! clear_bss → 解析 DTB → polyhal ctor 链（trap/timer/logger 初始化）
//!   → 主核通过 SBI-HSM(riscv) / IPI邮箱(la) 拉起副核 → rust_main / secondary_main
//! ```
//!
//! 本轮新增最小用户态链路：启动自检通过后，主核依次运行内嵌的
//! hello 与 check 用户程序（见 `user/hello/`），通过真实的用户态
//! 系统调用执行 write / exit，exit 或致命异常后回到启动主流程、
//! 报告结果并关机。
#![no_std]
#![no_main]

extern crate alloc;

mod allocator;
mod config;
mod elf;
mod lang_items;
mod mm;
mod syscall;
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

/// 时钟 tick 计数（trap.rs 中累加），用于启动自检
pub static TIMER_TICKS: AtomicUsize = AtomicUsize::new(0);

/// 主核入口（polyhal-boot 完成架构早期初始化并拉起副核后调用）
fn rust_main(hartid: usize) {
    allocator::init();
    mm::init();

    // 触发一次断点异常，验证当前架构的 trap 路径已就绪
    ebreak();

    // 打开中断并启动第一个 tick
    IRQ::int_enable();
    set_next_timer(current_time() + Duration::from_millis(config::TICK_MS));

    while TIMER_TICKS.load(Ordering::Relaxed) < config::BOOT_TICKS {
        spin_loop();
    }

    // 自检（heap/帧分配/trap/时钟/多核）全部通过，打印启动成功信息
    println!(
        "{} v{} · {} · boot hart {} · {} cpus · boot ok",
        config::KERNEL_NAME,
        config::KERNEL_VERSION,
        config::ARCH_NAME,
        hartid,
        get_cpu_num()
    );

    // —— 最小用户态链路：依次运行内嵌的用户程序，结束后统一关机 ——
    // hello：write 固定消息 → 校验返回字节数 → exit(0)
    user::run_user_elf("hello", user_images::HELLO_ELF);
    // check：系统调用错误路径检查（EFAULT/EBADF/ENOSYS 等），
    // 最后故意触发一次用户态非法访存，由内核报告并终止
    user::run_user_elf("check", user_images::CHECK_ELF);

    shutdown();
}

/// 副核入口（riscv64 经 OpenSBI HSM 唤醒，loongarch64 经 IPI 邮箱唤醒）
fn secondary_main(hartid: usize) {
    log::debug!("hart {} (secondary) up, parked.", hartid);
    // 启动骨架阶段副核只驻留；后续调度器就位后在此进入 idle/调度循环
    loop {
        spin_loop();
    }
}

define_entry!(rust_main, secondary_main);
