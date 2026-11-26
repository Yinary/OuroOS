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

fn map(fd: usize, prot: usize, flags: usize) -> isize {
    syscall6(222, [0, 4096, prot, flags, fd, 0])
}

fn read_zero_mapping(fd: usize) {
    let mapped = map(fd, 1, 1);
    check(mapped > 0, b"read-only shared mmap");
    let mapped = mapped as usize;
    check(
        syscall3(226, mapped, 4096, 3) == -13,
        b"mprotect write before fault",
    );
    // SAFETY: mmap 返回的首字节仍在可读映射内，由本测试进程持有。
    check(
        unsafe { (mapped as *const u8).read_volatile() } == 0,
        b"shared initial zero",
    );
    check(
        syscall3(226, mapped, 4096, 3) == -13,
        b"mprotect write after fault",
    );
    check(syscall3(215, mapped, 4096, 0) == 0, b"unmap read-only");
    check(map(fd, 3, 1) == -13, b"reject shared write at mmap");

    let private = map(fd, 1, 2);
    check(private > 0, b"private mmap");
    let private = private as usize;
    check(
        syscall3(226, private, 4096, 3) == 0,
        b"private mprotect write",
    );
    // SAFETY: 首字节属于本进程仍持有的私有映射，上一步已授予读写权限。
    unsafe { (private as *mut u8).write_volatile(0x5a) };
    let other = map(fd, 1, 2);
    check(other > 0, b"independent private mmap");
    // SAFETY: 两个地址分别指向两个未解除的私有映射，各自可读一个字节。
    unsafe {
        check(
            (private as *const u8).read_volatile() == 0x5a,
            b"private retains write",
        );
        check(
            (other as *const u8).read_volatile() == 0,
            b"other remains zero",
        );
    }
    check(syscall3(215, private, 4096, 0) == 0, b"unmap private");
    check(
        syscall3(215, other as usize, 4096, 0) == 0,
        b"unmap other private",
    );
}

fn shared_zero_mapping(fd: usize) {
    let mapped = map(fd, 1, 1);
    check(mapped > 0, b"read-write shared mmap");
    let mapped = mapped as usize;
    check(syscall3(226, mapped, 4096, 3) == 0, b"upgrade writable FD");
    // SAFETY: 已将仍存活的共享映射设为可读写，首字节在页内。
    unsafe { (mapped as *mut u8).write_volatile(0x23) };
    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    check(pid >= 0, b"fork shared mapping");
    if pid == 0 {
        // SAFETY: 子进程继承未解除的共享映射及其读写权限。
        unsafe {
            check(
                (mapped as *const u8).read_volatile() == 0x23,
                b"child sees shared byte",
            );
            (mapped as *mut u8).write_volatile(0x42);
        }
        sys_exit(0);
    }
    let mut status = -1i32;
    check(
        syscall6(
            260,
            [pid as usize, &mut status as *mut i32 as usize, 0, 0, 0, 0],
        ) == pid
            && status == 0,
        b"wait shared child",
    );
    // SAFETY: 父进程尚未解除可读共享映射，子进程已退出。
    check(
        unsafe { (mapped as *const u8).read_volatile() } == 0x42,
        b"parent sees child write",
    );
    check(syscall3(215, mapped, 4096, 0) == 0, b"unmap shared");
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
    read_zero_mapping(fd);
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

    shared_zero_mapping(fd);

    let fd = open(0x200000);
    check(
        fd >= 0 && syscall3(63, fd as usize, addr, 1) == -9,
        b"O_PATH",
    );
    sys_write(1, b"DEVZERO PASS: character device I/O and mmap\n");
    sys_exit(0);
}

define_user_entry!(run);
