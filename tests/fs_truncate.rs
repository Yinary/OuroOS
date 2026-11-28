//! truncate/ftruncate 回归；由 fs_stat.py --truncate 构造镜像。
#![no_std]
#![no_main]
use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};
const CWD: usize = (-100isize) as usize;
fn check(ok: bool, line: u32) {
    if !ok {
        sys_write(1, b"TRUNCATE FAIL line ");
        let mut digits = [0; 10];
        let mut i = 10;
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
fn open(path: &[u8], flags: usize) -> usize {
    let fd = syscall6(56, [CWD, path.as_ptr() as usize, flags, 0o666, 0, 0]);
    ck!(fd >= 0);
    fd as usize
}
fn close(fd: usize) {
    ck!(syscall3(57, fd, 0, 0) == 0);
}
fn cut(fd: usize, length: usize) -> isize {
    syscall3(46, fd, length, 0)
}
fn path_cut(path: &[u8], length: usize) -> isize {
    syscall3(45, path.as_ptr() as usize, length, 0)
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(core::array::from_fn(|i| b[at + i]))
}
fn stat(fd: usize) -> [u8; 128] {
    let mut data = [0; 128];
    ck!(syscall3(80, fd, data.as_mut_ptr() as usize, 0) == 0);
    data
}
fn size(fd: usize) -> u64 {
    word(&stat(fd), 48)
}
fn blocks(fd: usize) -> u64 {
    word(&stat(fd), 64)
}
fn free_blocks() -> u64 {
    let mut data = [0; 120];
    ck!(syscall3(43, b"/\0".as_ptr() as usize, data.as_mut_ptr() as usize, 0) == 0);
    word(&data, 24)
}
fn write_at(fd: usize, offset: usize, data: &[u8]) {
    ck!(
        syscall6(68, [fd, data.as_ptr() as usize, data.len(), offset, 0, 0]) == data.len() as isize
    );
}
fn read_at(fd: usize, offset: usize, data: &mut [u8]) -> isize {
    syscall6(
        67,
        [fd, data.as_mut_ptr() as usize, data.len(), offset, 0, 0],
    )
}
fn bytes(fd: usize, offset: usize, expected: &[u8]) {
    let mut data = [0; 64];
    ck!(expected.len() <= data.len());
    ck!(read_at(fd, offset, &mut data[..expected.len()]) == expected.len() as isize);
    ck!(&data[..expected.len()] == expected);
}
fn fill(fd: usize, mut offset: usize, mut len: usize, expected: u8) {
    let mut data = [0; 512];
    while len != 0 {
        let count = len.min(data.len());
        ck!(read_at(fd, offset, &mut data[..count]) == count as isize);
        ck!(data[..count].iter().all(|&b| b == expected));
        offset += count;
        len -= count;
    }
}
fn regular() {
    let fd = open(b"/trunc-data\0", 0x42);
    write_at(fd, 0, b"abcdefghij");
    ck!(syscall3(62, fd, 50, 0) == 50);
    let times = [1i64, 0, 2, 0];
    ck!(syscall6(88, [fd, 0, times.as_ptr() as usize, 0, 0, 0]) == 0);
    ck!(cut(fd, 3) == 0 && size(fd) == 3);
    ck!(syscall3(62, fd, 0, 1) == 50);
    ck!(word(&stat(fd), 88) != 2);
    bytes(fd, 0, b"abc");
    ck!(cut(fd, 10) == 0);
    bytes(fd, 0, b"abc");
    fill(fd, 3, 7, 0);
    let allocated = blocks(fd);
    let free = free_blocks();
    let large = (1usize << 32) + 17;
    ck!(cut(fd, large) == 0 && size(fd) == large as u64);
    ck!(blocks(fd) == allocated && free_blocks() == free);
    fill(fd, large - 16, 16, 0);
    write_at(fd, large - 1, b"z");
    bytes(fd, large - 1, b"z");
    ck!(cut(fd, 2) == 0);
    ck!(blocks(fd) == 8);
    bytes(fd, 0, b"ab");
    ck!(cut(fd, 7) == 0);
    fill(fd, 2, 5, 0);
    let dup = syscall3(23, fd, 0, 0);
    ck!(dup >= 0);
    ck!(cut(dup as usize, 4096) == 0 && size(fd) == 4096);
    ck!(syscall3(62, dup as usize, 0, 1) == 50);
    fill(fd, 7, 4089, 0);
    ck!(cut(fd, 0) == 0 && blocks(fd) == 0);
    ck!(cut(fd, 8192) == 0 && blocks(fd) == 0);
    fill(fd, 0, 8192, 0);
    ck!(cut(fd | (1usize << 32), 1) == 0 && size(fd) == 1);
    ck!(syscall3(35, CWD, b"/trunc-data\0".as_ptr() as usize, 0) == 0);
    ck!(path_cut(b"/trunc-data\0", 0) == -2);
    ck!(cut(fd, 4097) == 0);
    fill(fd, 0, 4097, 0);
    close(dup as usize);
    close(fd);
    let fd = open(b"/meta/data\0", 2);
    ck!(path_cut(b"/meta/chain\0", 3) == 0 && size(fd) == 3);
    bytes(fd, 0, b"tes");
    ck!(syscall3(49, b"/meta\0".as_ptr() as usize, 0, 0) == 0);
    ck!(path_cut(b"data\0", 7) == 0);
    fill(fd, 3, 4, 0);
    ck!(syscall3(49, b"/\0".as_ptr() as usize, 0, 0) == 0);
    close(fd);
}
fn extents() {
    let fd = open(b"/prealloc-zero\0", 2);
    ck!(size(fd) == 0 && blocks(fd) == 64);
    ck!(cut(fd, 0) == 0 && blocks(fd) == 0);
    close(fd);
    let fd = open(b"/prealloc\0", 2);
    ck!(blocks(fd) >= 256);
    ck!(cut(fd, 4097) == 0 && blocks(fd) == 16);
    fill(fd, 0, 4097, 0);
    ck!(cut(fd, 4096) == 0 && blocks(fd) == 8);
    ck!(cut(fd, 0) == 0 && blocks(fd) == 0);
    close(fd);
    let fd = open(b"/fragmented\0", 2);
    ck!(blocks(fd) >= 72);
    ck!(cut(fd, 4 * 4096) == 0 && blocks(fd) == 16);
    fill(fd, 0, 4 * 4096, 0);
    ck!(cut(fd, 0) == 0 && blocks(fd) == 0);
    close(fd);
    let fd = open(b"/reused\0", 0x42);
    for i in 0..10 {
        write_at(fd, i * 8192, &[0x5a; 4096]);
    }
    ck!(cut(fd, 4097) == 0 && blocks(fd) == 8);
    fill(fd, 0, 4096, 0x5a);
    fill(fd, 4096, 1, 0);
    ck!(cut(fd, 0) == 0 && blocks(fd) == 0);
    close(fd);
    let fd = open(b"/after-free\0", 0x42);
    write_at(fd, 0, &[0x33; 4096]);
    ck!(syscall3(82, fd, 0, 0) == 0);
    fill(fd, 0, 4096, 0x33);
    close(fd);
}
fn mappings() {
    let fd = open(b"/mapped\0", 0x42);
    ck!(cut(fd, 8192) == 0);
    let addr = syscall6(222, [0, 8192, 3, 1, fd, 0]);
    ck!(addr >= 0);
    let addr = addr as usize;
    unsafe {
        core::ptr::write_volatile((addr + 100) as *mut u8, 0x7f);
    }
    ck!(cut(fd, 1) == -95 && size(fd) == 8192);
    ck!(path_cut(b"/mapped\0", 0) == -95);
    ck!(syscall6(56, [CWD, b"/mapped\0".as_ptr() as usize, 0x202, 0, 0, 0]) == -95);
    ck!(cut(fd, 8192) == 0);
    bytes(fd, 100, &[0x7f]);
    let mut pipe = [0u32; 2];
    ck!(syscall3(59, pipe.as_mut_ptr() as usize, 0, 0) == 0);
    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    ck!(pid >= 0);
    if pid == 0 {
        close(pipe[1] as usize);
        let mut byte = [0];
        ck!(syscall3(63, pipe[0] as usize, byte.as_mut_ptr() as usize, 1) == 0);
        close(pipe[0] as usize);
        sys_exit(0);
    }
    ck!(syscall3(215, addr, 8192, 0) == 0);
    ck!(cut(fd, 1) == -95);
    close(pipe[1] as usize);
    let mut status = -1i32;
    ck!(syscall6(
        260,
        [pid as usize, &mut status as *mut i32 as usize, 0, 0, 0, 0]
    ) == pid
        && status == 0);
    close(pipe[0] as usize);
    ck!(cut(fd, 101) == 0);
    bytes(fd, 100, &[0x7f]);
    ck!(cut(fd, 8192) == 0);
    fill(fd, 101, 8192 - 101, 0);
    close(fd);
}
fn errors(readonly: bool) {
    ck!(syscall3(45, 0, 0, 0) == -14);
    ck!(path_cut(b"\0", 0) == -2);
    ck!(path_cut(b"/missing\0", 0) == -2);
    ck!(path_cut(b"/meta/loop\0", 0) == -40);
    ck!(path_cut(b"/meta\0", 0) == -21);
    ck!(path_cut(b"/meta/data/child\0", 0) == -20);
    ck!(path_cut(b"/meta/data\0", usize::MAX) == -22);
    ck!(cut(999, 0) == -9);
    ck!(cut(999, usize::MAX) == -22);
    let fd = open(b"/meta/data\0", 0);
    ck!(cut(fd, 0) == -22);
    close(fd);
    let fd = open(b"/meta\0", 0x10000);
    ck!(cut(fd, 0) == -22);
    close(fd);
    ck!(cut(1, 0) == -22);
    let fd = open(b"/meta/data\0", 0x200000);
    ck!(cut(fd, 0) == -9);
    close(fd);
    let mut pair = [0u32; 2];
    ck!(syscall3(59, pair.as_mut_ptr() as usize, 0, 0) == 0);
    ck!(cut(pair[1] as usize, 0) == -22);
    close(pair[0] as usize);
    close(pair[1] as usize);
    let fd = open(b"/meta/data\0", 2);
    let before = size(fd);
    if readonly {
        ck!(path_cut(b"/meta/data\0", 1) == -30);
        ck!(cut(fd, 1) == -30);
    } else {
        ck!(cut(fd, i64::MAX as usize) == -27);
        ck!(path_cut(b"/meta/data\0", i64::MAX as usize) == -27);
        ck!(size(fd) == before);
        let trunc = open(b"/meta/data\0", 0x202);
        ck!(size(fd) == 0);
        close(trunc);
    }
    close(fd);
}
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let mut stats = [0; 120];
    ck!(syscall3(43, b"/\0".as_ptr() as usize, stats.as_mut_ptr() as usize, 0) == 0);
    let readonly = word(&stats, 80) & 1 != 0;
    if readonly {
        sys_write(1, b"TRUNCATE READONLY\n");
    } else {
        regular();
        extents();
        mappings();
    }
    errors(readonly);
    let small = syscall6(56, [CWD, b"/small-inode\0".as_ptr() as usize, 0, 0, 0, 0]);
    if small >= 0 {
        close(small as usize);
    } else {
        ck!(syscall6(
            40,
            [
                b"/dev/vda2\0".as_ptr() as usize,
                b"/mnt\0".as_ptr() as usize,
                b"vfat\0".as_ptr() as usize,
                0,
                0,
                0
            ]
        ) == 0);
        let fd = open(b"/mnt/file\0", 0x42);
        write_at(fd, 0, b"fat");
        ck!(cut(fd, 1) == -95 && size(fd) == 3);
        ck!(cut(fd, 0) == 0 && size(fd) == 0);
        close(fd);
        ck!(syscall3(39, b"/mnt\0".as_ptr() as usize, 0, 0) == 0);
    }
    sys_write(
        1,
        b"TRUNCATE PASS: sparse growth, zero tail, extent reclaim, FD and shared mappings\n",
    );
    sys_exit(0);
}
define_user_entry!(ouro_main);
