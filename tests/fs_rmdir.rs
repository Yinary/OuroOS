//! 用 fs_stat.py --rmdir 验证空目录删除和存活引用。
#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};

const CWD: usize = -100isize as usize;
const HELD: &[u8] = b"/held\0";
const ROOT: &[u8] = b"/\0";

fn number(mut value: u64) {
    let mut digits = [0; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    sys_write(1, &digits[start..]);
    sys_write(1, b"\n");
}

fn check(ok: bool, line: u32) {
    if !ok {
        sys_write(1, b"RMDIR FAIL line ");
        number(line.into());
        sys_exit(1);
    }
}
macro_rules! ck {
    ($condition:expr) => {
        check($condition, line!())
    };
}

fn openat(dir: usize, path: &[u8], flags: usize) -> isize {
    syscall6(56, [dir, path.as_ptr() as usize, flags, 0o644, 0, 0])
}

fn rmdir(path: &[u8]) -> isize {
    syscall3(35, CWD, path.as_ptr() as usize, 0x200)
}

fn chdir(path: &[u8]) -> isize {
    syscall3(49, path.as_ptr() as usize, 0, 0)
}

fn cwd() -> isize {
    let mut buf = [0; 128];
    syscall3(17, buf.as_mut_ptr() as usize, buf.len(), 0)
}

fn metadata(out: &[u8; 128]) -> (u64, u32) {
    (
        u64::from_ne_bytes(core::array::from_fn(|i| out[8 + i])),
        u32::from_ne_bytes(core::array::from_fn(|i| out[20 + i])),
    )
}

fn fstat(fd: usize) -> (u64, u32) {
    let mut buf = [0; 128];
    ck!(syscall3(80, fd, buf.as_mut_ptr() as usize, 0) == 0);
    metadata(&buf)
}

fn main() {
    let created = syscall3(34, CWD, HELD.as_ptr() as usize, 0o755);
    if created == -30 {
        ck!(rmdir(b"/meta/sub\0") == -30);
        ck!(openat(CWD, b"/meta/sub\0", 0x10000) >= 0);
        sys_write(1, b"RMDIR READONLY\n");
        return;
    }
    ck!(created == 0);
    ck!(rmdir(ROOT) == -16);
    ck!(rmdir(b"/meta\0") == -39);
    ck!(rmdir(b"/meta/data\0") == -20);
    let fd = openat(CWD, HELD, 0x10000);
    ck!(fd >= 0);
    let fd = fd as usize;
    let (old, links) = fstat(fd);
    ck!(links == 2);
    ck!(chdir(HELD) == 0);
    ck!(rmdir(b".\0") == -22);
    ck!(rmdir(b"..\0") == -39);
    ck!(rmdir(HELD) == 0);
    ck!(openat(CWD, HELD, 0) == -2);
    ck!(cwd() == -2);
    ck!(fstat(fd) == (old, 0));
    let mut out = [0u8; 128];
    ck!(syscall6(
        79,
        [
            CWD,
            b"\0".as_ptr() as usize,
            out.as_mut_ptr() as usize,
            0x1000,
            0,
            0
        ]
    ) == 0);
    ck!(metadata(&out) == (old, 0));
    ck!(syscall3(61, fd, out.as_mut_ptr() as usize, out.len()) == 0);

    ck!(syscall3(34, CWD, HELD.as_ptr() as usize, 0o755) == 0);
    let replacement = openat(CWD, HELD, 0x10000);
    ck!(replacement >= 0);
    ck!(fstat(replacement as usize).0 != old);
    ck!(openat(fd, b"child\0", 0x42) == -2);
    ck!(openat(CWD, b"child\0", 0x42) == -2);
    ck!(openat(replacement as usize, b"child\0", 0) == -2);

    ck!(chdir(ROOT) == 0);
    ck!(fstat(fd) == (old, 0));
    ck!(syscall3(57, fd, 0, 0) == 0);
    sys_write(1, b"RMDIR FREED INODE: ");
    number(old);
    ck!(syscall3(57, replacement as usize, 0, 0) == 0);
}

fn run() -> ! {
    main();
    sys_write(1, b"RMDIR PASS: directory references\n");
    sys_exit(0);
}

define_user_entry!(run);
