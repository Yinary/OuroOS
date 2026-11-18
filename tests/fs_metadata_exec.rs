//! 检查 exec 后保留进程创建权限掩码。
#![no_std]
#![no_main]
use hello::{define_user_entry, sys_exit, sys_write, syscall3};
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    if syscall3(166, 0, 0, 0) != 0o077 {
        sys_write(1, b"MASK EXEC FAIL\n");
        sys_exit(1);
    }
    sys_write(1, b"MASK EXEC PASS\n");
    sys_exit(0);
}
define_user_entry!(ouro_main);
