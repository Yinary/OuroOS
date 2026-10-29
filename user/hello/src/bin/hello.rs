//! hello：最小用户程序。
//!
//! 行为：write(1, 消息) → 校验返回字节数 → exit(0)；任何一步不符合
//! 预期则以非零状态退出。程序运行在用户权限级，经 ecall/syscall
//! 进入内核。

#![no_std]
#![no_main]

use hello::{define_user_entry, sys_exit, sys_write};

/// 输出消息（含架构名，便于日志确认运行环境）
#[cfg(target_arch = "riscv64")]
const MSG: &[u8] = b"hello, OuroOS user world (riscv64)\n";
#[cfg(target_arch = "loongarch64")]
const MSG: &[u8] = b"hello, OuroOS user world (loongarch64)\n";

/// 用户主函数（由 _start 调用，不返回）
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let ret = sys_write(1, MSG);
    if ret != MSG.len() as isize {
        // write 返回字节数不符：以非零状态退出
        sys_exit(1);
    }
    sys_exit(0);
}

define_user_entry!(ouro_main);
