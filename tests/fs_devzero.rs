//! 用 fs_stat.py --devzero 验证字符设备和用户缓冲区行为。
#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};

const CWD: usize = -100isize as usize;
const PATH: &[u8] = b"/dev/zero\0";

fn check(ok: bool, what: &[u8]) {
    if !ok {
        sys_write(1, b"DEVZERO FAIL: ");
        sys_write(1, what);
        sys_write(1, b"\n");
        sys_exit(1);
    }
}

fn open(flags: usize) -> isize {
    syscall6(56, [CWD, PATH.as_ptr() as usize, flags, 0, 0, 0])
}

fn run() -> ! {
    let fd = open(0);
    check(fd >= 0, b"open");
    let fd = fd as usize;
    let mut buf = [0x5au8; 8193];
    let addr = buf.as_mut_ptr() as usize;
    check(
        syscall3(63, fd, addr, buf.len()) == buf.len() as isize,
        b"read length",
    );
    check(buf.iter().all(|&b| b == 0), b"read contents");
    check(syscall3(63, fd, 0, 1) == -14, b"invalid buffer");
    check(syscall3(63, fd, 0, 0) == 0, b"empty read");
    check(syscall3(64, fd, addr, 1) == -9, b"read-only FD");

    buf[0] = 0x5a;
    check(
        syscall6(67, [fd, addr, 1, 4096, 0, 0]) == 1 && buf[0] == 0,
        b"pread",
    );
    check(syscall3(62, fd, 123, 0) == 0, b"seek");

    let mut by_fd = [0u8; 128];
    let mut by_path = [0u8; 128];
    check(
        syscall3(80, fd, by_fd.as_mut_ptr() as usize, 0) == 0,
        b"fstat",
    );
    check(
        syscall6(
            79,
            [
                CWD,
                PATH.as_ptr() as usize,
                by_path.as_mut_ptr() as usize,
                0,
                0,
                0,
            ],
        ) == 0,
        b"fstatat",
    );
    check(by_fd == by_path, b"device identity");
    let mode = u32::from_ne_bytes(core::array::from_fn(|i| by_fd[16 + i]));
    let rdev = u64::from_ne_bytes(core::array::from_fn(|i| by_fd[32 + i]));
    check(mode == 0o020666 && rdev == 0x105, b"character device 1:5");

    check(
        open(0xc0) == -17 && open(0x10000) == -20,
        b"invalid open modes",
    );
    let fd = open(2);
    check(fd >= 0, b"read-write open");
    let fd = fd as usize;
    buf[0] = 0x5a;
    check(syscall3(64, fd, addr, 1) == 1, b"write");
    check(syscall6(68, [fd, addr, 1, 4096, 0, 0]) == 1, b"pwrite");
    check(
        syscall3(63, fd, addr, 1) == 1 && buf[0] == 0,
        b"write discarded",
    );

    let fd = open(0x200000);
    check(
        fd >= 0 && syscall3(63, fd as usize, addr, 1) == -9,
        b"O_PATH",
    );
    sys_write(1, b"DEVZERO PASS: character device I/O\n");
    sys_exit(0);
}

define_user_entry!(run);
