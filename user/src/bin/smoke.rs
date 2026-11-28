//! smoke：内核冒烟测试程序（打印欢迎信息后退出）。
//!
//! 行为：write(1, 消息) → 校验返回字节数 → exit(0)；任何一步不符合
//! 预期则以非零状态退出。程序运行在用户权限级，经 ecall/syscall

#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write};

#[cfg(target_arch = "riscv64")]
const MSG: &[u8] = b"hello, OuroOS user world (riscv64)\n";
#[cfg(target_arch = "loongarch64")]
const MSG: &[u8] = b"hello, OuroOS user world (loongarch64)\n";

#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let ret = sys_write(1, MSG);
    if ret != MSG.len() as isize {
        sys_exit(1);
    }
    let p = user::sys_mmap(0, 4096, 3, 0x22, usize::MAX, 0);
    if p < 0 {
        sys_exit(2);
    }
    unsafe {
        (p as *mut u8).write_volatile(0x5a);
        if (p as *const u8).read_volatile() != 0x5a {
            sys_exit(3);
        }
    }
    if user::sys_munmap(p as usize, 4096) != 0 {
        sys_exit(4);
    }
    sys_exit(0);
}

define_user_entry!(ouro_main);
