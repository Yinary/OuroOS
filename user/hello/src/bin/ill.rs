//! ill：异常类终止验收程序——rv 触发非法指令、la 跳转非规范地址触发
//! ADEF，预期被内核终止本任务而非 panic。背景见 docs/ostd-contracts.md §2。

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
