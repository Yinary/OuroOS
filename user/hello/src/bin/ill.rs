//! ill：用户态"异常类终止"验收程序（polyhal 补丁 #7 的直接验收）。
//!
//! 行为：打印提示 → 故意触发一条架构相关的致命陷阱 → 预期内核报告
//! 异常并终止本任务（退出码 128+11），内核与其余任务不受影响：
//! - riscv64：全零指令字（0x0000 为非法编码）→ IllegalInstruction；
//! - loongarch64：跳转到非规范地址 0x0000_8000_0000_0000（48 位 VA
//!   窗口外的非符号扩展形式）→ 取指地址错误 ADEF，该异常在 polyhal
//!   0.4.0 原版会于 HAL 层直接 panic 整个内核（缺陷 #7），vendor 补丁
//!   后转交内核按 Unhandled 终止任务。
//!
//! 不会执行到 trip 之后；若内核错误放行，则非零退出暴露问题。

#![no_std]
#![no_main]

use hello::{define_user_entry, sys_exit, sys_write};

/// 触发致命陷阱（不返回）。
#[cfg(target_arch = "riscv64")]
unsafe fn trip() -> ! {
    // 0x0000 是 RISC-V 保证的非法指令编码
    core::arch::asm!(".word 0", options(noreturn))
}

/// 触发致命陷阱（不返回）。
#[cfg(target_arch = "loongarch64")]
unsafe fn trip() -> ! {
    // 非规范地址（48 位 VA 窗口外、非符号扩展）：取指必报地址错误。
    // noreturn 选项不允许 asm 输出，临时寄存器不声明输出。
    core::arch::asm!(
        "li.d $t0, {addr}",
        "jirl $zero, $t0, 0",
        addr = const 0x0000_8000_0000_0000usize,
        options(noreturn)
    )
}

/// 用户主函数（由 _start 调用，不返回）
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let _ = sys_write(1, b"ill: tripping now\n");
    // SAFETY: 本程序的唯一目的就是触发该陷阱；内核应终止本任务。
    unsafe { trip() }
}

#[no_mangle]
extern "C" fn _unreachable_after_trip() -> ! {
    // 不应到达：若内核错误地放行陷阱，以非零状态退出暴露问题
    sys_exit(2)
}

define_user_entry!(ouro_main);
