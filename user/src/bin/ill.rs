//! ill：异常类终止验收程序——rv 触发非法指令、la 跳转非规范地址触发
//! ADEF，预期被内核终止本任务而非 panic。背景见 docs/ostd-contracts.md §2。

#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write};

#[cfg(target_arch = "riscv64")]
unsafe fn trip() -> ! {
    core::arch::asm!(".word 0", options(noreturn))
}

#[cfg(target_arch = "loongarch64")]
unsafe fn trip() -> ! {
    core::arch::asm!(
        "li.d $t0, {addr}",
        "jirl $zero, $t0, 0",
        addr = const 0x0000_8000_0000_0000usize,
        options(noreturn)
    )
}

#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let _ = sys_write(1, b"ill: tripping now\n");
    unsafe { trip() }
}

#[no_mangle]
extern "C" fn _unreachable_after_trip() -> ! {
    sys_exit(2)
}

define_user_entry!(ouro_main);
