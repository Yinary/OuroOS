//! 基础 fcntl 回归；验证 FD 独立标志、共享状态、编号分配及 fork/exec。
#![no_std]
#![no_main]
use hello::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};
const CWD: usize = (-100isize) as usize;
fn check(ok: bool, line: u32) {
    if !ok {
        sys_write(1, b"FCNTL FAIL line ");
        let mut digits = [0; 10];
        let mut i = digits.len();
        let mut n = line;
        loop {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        sys_write(1, &digits[i..]);
        sys_write(1, b"\n");
        sys_exit(1);
    }
}
macro_rules! ck {
    ($e:expr) => {
        check($e, line!());
    };
}
fn ctl(fd: usize, cmd: usize, arg: usize) -> isize {
    syscall3(25, fd, cmd, arg)
}
fn close(fd: usize) {
    ck!(syscall3(57, fd, 0, 0) == 0);
}
fn open(flags: usize) -> usize {
    let fd = syscall3(56, CWD, b"/io-data\0".as_ptr() as usize, flags);
    ck!(fd >= 0);
    fd as usize
}
fn wait(pid: isize) {
    let mut status = -1i32;
    ck!(syscall6(
        260,
        [pid as usize, &mut status as *mut _ as usize, 0, 0, 0, 0]
    ) == pid
        && status == 0);
}
fn pipe(flags: usize) -> [u32; 2] {
    let mut pair = [0; 2];
    ck!(syscall3(59, pair.as_mut_ptr() as usize, flags, 0) == 0);
    pair
}
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    for cmd in [0, 1, 2, 3, 4, 1030, 9999] {
        ck!(ctl(9999, cmd, 0) == -9);
    }
    ck!(ctl(0, 3, 0) == 0 && ctl(1, 3, 0) == 1 && ctl(2, 3, 0) == 1);
    let fd = open(2 | 0x80000 | 0x40 | 0x100);
    let ro = syscall3(56, CWD, b"/readonly\0".as_ptr() as usize, 0);
    if ro >= 0 {
        close(ro as usize);
    }
    ck!(ctl(fd, 1, usize::MAX) == 1 && ctl(fd, 3, 0) == 2);
    ck!(ctl(fd, 0, 1024) == -22 && ctl(fd, 0, usize::MAX) == -22);
    ck!(ctl(fd, 1030, 1024) == -22 && ctl(fd, 9999, 0) == -22);
    let alias = ctl(fd, 0, 20);
    ck!(alias == 20 && ctl(20, 1, 0) == 0 && ctl(fd, 1, 0) == 1);
    ck!(ctl(fd, 1030, 20) == 21 && ctl(21, 1, 0) == 1);
    close(20);
    ck!(ctl(fd, 0, 20) == 20);
    ck!(ctl(20, 2, 3) == 0 && ctl(20, 1, 0) == 1);
    ck!(ctl(20, 2, 2) == 0 && ctl(20, 1, 0) == 0 && ctl(fd, 1, 0) == 1);
    ck!(ctl(20, 4, 0x400 | 0x800 | 0x40 | 0x200 | 0x80000) == 0);
    ck!(ctl(fd, 3, 0) == 2 | 0x400 | 0x800 && ctl(20, 3, 0) == ctl(fd, 3, 0));
    for unsupported in [0x2000, 0x4000, 0x40000] {
        ck!(ctl(fd, 4, unsupported) == -95 && ctl(fd, 3, 0) == 0xc02);
    }
    let independent = open(0x80 | 0x200 | 0x80000);
    ck!(ctl(independent, 3, 0) == 0);
    ck!(ctl(independent, 1, 0) == 1);
    ck!(ctl(independent, 4, 2) == 0 && ctl(independent, 3, 0) == 0);
    ck!(syscall3(64, independent, b"x".as_ptr() as usize, 1) == -9);
    close(independent);
    ck!(syscall3(62, fd, 0, 0) == 0);
    if ro < 0 {
        ck!(syscall3(64, 20, b"Z".as_ptr() as usize, 1) == 1);
        ck!(syscall3(62, fd, 0, 1) == 9);
        let mut byte = [0];
        ck!(syscall6(67, [fd, byte.as_mut_ptr() as usize, 1, 8, 0, 0]) == 1 && byte[0] == b'Z');
    }
    ck!(ctl(20, 4, 0) == 0 && ctl(fd, 3, 0) == 2);
    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    ck!(pid >= 0);
    if pid == 0 {
        ck!(ctl(fd, 1, 0) == 1);
        ck!(ctl(fd, 2, 0) == 0 && ctl(fd, 4, 0x800) == 0);
        ck!(syscall3(62, 20, 4, 0) == 4);
        sys_exit(0);
    }
    wait(pid);
    ck!(ctl(fd, 1, 0) == 1 && ctl(fd, 3, 0) == 0x802);
    ck!(syscall3(62, fd, 0, 1) == 4);
    let p = pipe(0x80000);
    let (r, w) = (p[0] as usize, p[1] as usize);
    ck!(ctl(r, 3, 0) == 0 && ctl(w, 3, 0) == 1 && ctl(r, 1, 0) == 1);
    ck!(ctl(r, 0, 30) == 30 && ctl(30, 1, 0) == 0);
    ck!(ctl(30, 4, 0x800) == 0 && ctl(r, 3, 0) == 0x800 && ctl(w, 3, 0) == 1);
    let mut byte = [0];
    ck!(syscall3(63, r, byte.as_mut_ptr() as usize, 1) == -11);
    ck!(syscall3(64, w, b"P".as_ptr() as usize, 1) == 1);
    ck!(syscall3(63, 30, byte.as_mut_ptr() as usize, 1) == 1 && byte[0] == b'P');
    ck!(ctl(r, 4, 0) == 0 && ctl(30, 3, 0) == 0);
    close(30);
    close(r);
    close(w);
    let p = pipe(0);
    let (r, w) = (p[0] as usize, p[1] as usize);
    ck!(ctl(w, 4, 0x800) == 0);
    let fill = [b'x'; 1024];
    for _ in 0..64 {
        ck!(syscall3(64, w, fill.as_ptr() as usize, fill.len()) == 1024);
    }
    ck!(syscall3(64, w, b"x".as_ptr() as usize, 1) == -11);
    ck!(syscall3(63, r, byte.as_mut_ptr() as usize, 1) == 1);
    ck!(syscall3(64, w, b"x".as_ptr() as usize, 1) == 1);
    close(r);
    close(w);
    // 成功 exec 后由第二个 ELF 检查描述符及管道末端是否真正关闭。
    ck!(ctl(fd, 1030, 100) == 100 && ctl(fd, 0, 101) == 101);
    ck!(ctl(fd, 0, 102) == 102 && ctl(102, 2, 1) == 0);
    ck!(ctl(fd, 1030, 103) == 103 && ctl(103, 2, 0) == 0);
    let p = pipe(0);
    ck!(syscall3(24, p[1] as usize, 104, 0x80000) == 104);
    ck!(syscall3(24, p[0] as usize, 105, 0) == 105);
    close(p[0] as usize);
    close(p[1] as usize);
    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    ck!(pid >= 0);
    if pid == 0 {
        ck!(syscall3(221, b"/absent\0".as_ptr() as usize, 0, 0) == -2 && ctl(100, 1, 0) == 1);
        close(fd);
        close(20);
        close(21);
        syscall3(221, b"/after-exec\0".as_ptr() as usize, 0, 0);
        sys_exit(1);
    }
    for n in 100..106 {
        close(n);
    }
    wait(pid);
    ck!(ctl(fd, 1, 0) == 1 && ctl(fd, 3, 0) == 0x802);
    ck!(ctl(fd, 0, 1023) == 1023 && ctl(fd, 0, 1023) == -24);
    close(1023);
    ck!(ctl(fd, 1030, 1023) == 1023 && ctl(1023, 1, 0) == 1);
    let mut count = 0;
    loop {
        let n = ctl(fd, 0, 0);
        if n < 0 {
            ck!(n == -24);
            break;
        }
        count += 1;
        ck!(count <= 1024);
    }
    ck!(count > 1000);
    ck!(syscall3(23, fd, 0, 0) == -24);
    for n in 3..1024 {
        close(n);
    }
    ck!(ctl(fd, 1, 0) == -9);
    sys_write(
        1,
        b"FCNTL PASS: descriptor flags, shared state, allocation, fork and exec\n",
    );
    sys_exit(0);
}
define_user_entry!(ouro_main);
