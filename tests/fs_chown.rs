//! 用 fs_stat.py --chown 验证属主更新、授权与路径语义。
#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};

const CWD: usize = (-100isize) as usize;
const KEEP: usize = u32::MAX as usize;
const DATA: &[u8] = b"/meta/data\0";

fn check(ok: bool, line: u32) {
    if ok {
        return;
    }
    let mut digits = [0; 10];
    let mut start = digits.len();
    let mut number = line;
    loop {
        start -= 1;
        digits[start] = b'0' + (number % 10) as u8;
        number /= 10;
        if number == 0 {
            break;
        }
    }
    sys_write(1, b"CHOWN FAIL line ");
    sys_write(1, &digits[start..]);
    sys_write(1, b"\n");
    sys_exit(1);
}

macro_rules! ck {
    ($condition:expr) => {
        check($condition, line!())
    };
}

fn chownat(dir: usize, path: &[u8], uid: usize, gid: usize, flags: usize) -> isize {
    syscall6(54, [dir, path.as_ptr() as usize, uid, gid, flags, 0])
}

fn open(path: &[u8], flags: usize) -> usize {
    let fd = syscall6(56, [CWD, path.as_ptr() as usize, flags, 0o600, 0, 0]);
    ck!(fd >= 0);
    fd as usize
}

fn stat(dir: usize, path: &[u8], flags: usize) -> (u32, u32) {
    let mut out = [0u8; 128];
    ck!(syscall6(
        79,
        [
            dir,
            path.as_ptr() as usize,
            out.as_mut_ptr() as usize,
            flags,
            0,
            0
        ],
    ) == 0);
    let field = |offset: usize| u32::from_ne_bytes(core::array::from_fn(|i| out[offset + i]));
    (field(24), field(28))
}

fn main() {
    ck!(stat(CWD, DATA, 0) == (70000, 140000));
    let dir = open(b"/meta\0", 0x10000);
    let fd = open(DATA, 0);
    ck!(syscall3(55, usize::MAX, 1, 2) == -9);
    ck!(chownat(CWD, DATA, 1, 2, 0x4000) == -22);
    ck!(chownat(CWD, b"\0", 1, 2, 0) == -2);
    ck!(syscall6(54, [CWD, 1, 1, 2, 0, 0]) == -14);

    let result = chownat(dir, b"data\0", 70001, KEEP, 0);
    if result == -30 {
        ck!(syscall3(55, fd, KEEP, 1000) == -30);
        ck!(stat(CWD, DATA, 0) == (70000, 140000));
        sys_write(1, b"CHOWN READONLY\n");
        return;
    }
    ck!(result == 0 && stat(CWD, DATA, 0) == (70001, 140000));
    ck!(syscall3(55, fd, KEEP, KEEP) == 0);
    ck!(chownat(CWD, b"/meta/rel\0", KEEP, 140001, 0) == 0);
    ck!(stat(CWD, DATA, 0) == (70001, 140001));
    ck!(chownat(CWD, b"/meta/rel\0", 100, 200, 0x100) == 0);
    ck!(stat(CWD, b"/meta/rel\0", 0x100) == (100, 200));
    ck!(stat(CWD, DATA, 0) == (70001, 140001));

    let path_fd = open(DATA, 0x200000);
    ck!(syscall3(55, path_fd, KEEP, 1000) == -9);
    ck!(chownat(path_fd, b"\0", KEEP, 140002, 0x1000) == 0);

    let unlinked = open(b"/gone\0", 0x42);
    ck!(syscall3(35, CWD, b"/gone\0".as_ptr() as usize, 0) == 0);
    ck!(syscall3(55, unlinked, 11, 12) == 0);
    ck!(stat(unlinked, b"\0", 0x1000) == (11, 12));
    ck!(syscall3(57, unlinked, 0, 0) == 0);

    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    ck!(pid >= 0);
    if pid == 0 {
        ck!(syscall3(144, 1000, 0, 0) == 0);
        ck!(syscall3(146, 70001, 0, 0) == 0);
        ck!(syscall3(55, fd, KEEP, 1000) == 0);
        ck!(chownat(CWD, DATA, 80000, KEEP, 0) == -1);
        ck!(chownat(CWD, DATA, KEEP, 2000, 0) == -1);
        ck!(chownat(CWD, b"/meta/sub\0", KEEP, 1000, 0) == -1);
        sys_exit(0);
    }
    let mut status = -1i32;
    ck!(syscall6(
        260,
        [pid as usize, &mut status as *mut i32 as usize, 0, 0, 0, 0]
    ) == pid);
    ck!(status == 0 && stat(CWD, DATA, 0) == (70001, 1000));
}

fn run() -> ! {
    main();
    sys_write(1, b"CHOWN PASS: inode ownership\n");
    sys_exit(0);
}

define_user_entry!(run);
