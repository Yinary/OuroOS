//! exec 后验证 FD_CLOEXEC 与未关闭描述符的共享状态。
#![no_std]
#![no_main]
use user::{define_user_entry, sys_exit, sys_write, syscall3};
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let mut byte = [0];
    let ok = syscall3(25, 100, 1, 0) == -9
        && syscall3(25, 102, 1, 0) == -9
        && syscall3(25, 104, 1, 0) == -9
        && syscall3(25, 101, 1, 0) == 0
        && syscall3(25, 103, 1, 0) == 0
        && syscall3(25, 103, 3, 0) == 0x802
        && syscall3(62, 101, 0, 1) == 4
        && syscall3(63, 105, byte.as_mut_ptr() as usize, 1) == 0;
    if !ok {
        sys_write(1, b"FCNTL EXEC FAIL\n");
        sys_exit(1);
    }
    sys_write(1, b"FCNTL EXEC PASS\n");
    sys_exit(0);
}
define_user_entry!(ouro_main);
