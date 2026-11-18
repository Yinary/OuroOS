//! 定位和向量 I/O 回归；由 fs_io.py 生成镜像并运行。
#![no_std]
#![no_main]
use hello::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};
const CWD: usize = (-100isize) as usize;
#[derive(Clone, Copy)]
#[repr(C)]
struct IoVec {
    base: usize,
    len: usize,
}
fn input(b: &[u8]) -> IoVec {
    IoVec {
        base: b.as_ptr() as usize,
        len: b.len(),
    }
}
fn output(b: &mut [u8]) -> IoVec {
    IoVec {
        base: b.as_mut_ptr() as usize,
        len: b.len(),
    }
}
fn check(ok: bool, line: u32) {
    if !ok {
        sys_write(1, b"IOV FAIL line ");
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
fn vector(nr: usize, fd: usize, iov: &[IoVec], pos: usize) -> isize {
    syscall6(nr, [fd, iov.as_ptr() as usize, iov.len(), pos, 0, 0])
}
fn pread(fd: usize, b: &mut [u8], pos: usize) -> isize {
    syscall6(67, [fd, b.as_mut_ptr() as usize, b.len(), pos, 0, 0])
}
fn pwrite(fd: usize, b: &[u8], pos: usize) -> isize {
    syscall6(68, [fd, b.as_ptr() as usize, b.len(), pos, 0, 0])
}
fn seek(fd: usize, off: usize) {
    ck!(syscall3(62, fd, off, 0) == off as isize);
}
fn offset(fd: usize) -> isize {
    syscall3(62, fd, 0, 1)
}
fn close(fd: usize) {
    ck!(syscall3(57, fd, 0, 0) == 0);
}
fn pipe(flags: usize) -> [u32; 2] {
    let mut pair = [0; 2];
    ck!(syscall3(59, pair.as_mut_ptr() as usize, flags, 0) == 0);
    pair
}
fn pipes() {
    let p = pipe(0x800);
    let (r, w) = (p[0] as usize, p[1] as usize);
    ck!(vector(66, w, &[input(b"ab"), input(b"cd")], 0) == 4);
    let mut a = [0; 2];
    let mut b = [0; 4];
    ck!(vector(65, r, &[output(&mut a), output(&mut b)], 0) == 4
        && &a == b"ab"
        && &b[..2] == b"cd");
    ck!(vector(65, r, &[output(&mut a)], 0) == -11);
    ck!(vector(66, w, &[input(b"abcd")], 0) == 4);
    ck!(vector(65, r, &[output(&mut a), IoVec { base: 0, len: 2 }], 0) == 2 && &a == b"ab");
    ck!(vector(65, r, &[IoVec { base: 0, len: 2 }], 0) == -14);
    ck!(syscall3(63, r, b.as_mut_ptr() as usize, 4) == 2 && &b[..2] == b"cd");
    ck!(pread(r, &mut a, 0) == -29 && pwrite(w, b"z", 0) == -29);
    ck!(pread(w, &mut a, 0) == -29 && pwrite(r, b"z", 0) == -29);
    ck!(vector(69, r, &[], 0) == -29 && vector(70, w, &[], 0) == -29);
    close(r);
    ck!(vector(66, w, &[input(b"x")], 0) == -32);
    close(w);
    let p = pipe(0);
    let (r, w) = (p[0] as usize, p[1] as usize);
    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    ck!(pid >= 0);
    if pid == 0 {
        close(r);
        let delay = [0i64, 10_000_000];
        ck!(syscall3(101, delay.as_ptr() as usize, 0, 0) == 0);
        ck!(vector(66, w, &[input(b"ab"), input(b"cd")], 0) == 4);
        close(w);
        sys_exit(0);
    }
    close(w);
    ck!(vector(65, r, &[output(&mut a), output(&mut b)], 0) == 4
        && &a == b"ab"
        && &b[..2] == b"cd");
    ck!(vector(65, r, &[output(&mut a)], 0) == 0);
    close(r);
    let mut status = -1i32;
    ck!(syscall6(
        260,
        [pid as usize, &mut status as *mut _ as usize, 0, 0, 0, 0]
    ) == pid
        && status == 0);
}
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let fd = syscall6(56, [CWD, b"/io-data\0".as_ptr() as usize, 2, 0, 0, 0]);
    ck!(fd >= 0);
    let fd = fd as usize;
    let ro = syscall3(56, CWD, b"/readonly\0".as_ptr() as usize, 0) >= 0;
    let mut a = [0; 2];
    let mut b = [0; 4];
    seek(fd, 3);
    ck!(pread(fd, &mut a, 1) == 2 && &a == b"bc" && offset(fd) == 3);
    ck!(vector(69, fd, &[output(&mut a), output(&mut b)], 2) == 6
        && &a == b"cd"
        && &b == b"efgh"
        && offset(fd) == 3);
    ck!(pread(fd, &mut a, 0x1_0000_0000) == 0);
    ck!(vector(69, fd, &[output(&mut a)], 0x1_0000_0000) == 0);
    let one = [output(&mut a)];
    ck!(syscall6(69, [fd, one.as_ptr() as usize, 1, 0, 1, 0]) == 2 && &a == b"ab");
    ck!(pread(fd, &mut a, usize::MAX) == -22 && vector(69, fd, &one, usize::MAX) == -22);
    ck!(pwrite(fd, b"x", usize::MAX) == -22 && vector(70, fd, &[input(b"x")], usize::MAX) == -22);
    ck!(vector(65, fd, &[], 0) == 0 && syscall6(65, [fd, usize::MAX, 0, 0, 0, 0]) == 0);
    ck!(syscall6(65, [fd, usize::MAX, 1025, 0, 0, 0]) == -22);
    ck!(syscall6(65, [fd, usize::MAX, usize::MAX, 0, 0, 0]) == -22);
    ck!(syscall6(65, [fd, usize::MAX, 1, 0, 0, 0]) == -14);
    ck!(vector(
        65,
        fd,
        &[IoVec {
            base: 1,
            len: usize::MAX
        }],
        0
    ) == -22);
    ck!(vector(65, 999, &[], 0) == -9);
    ck!(vector(
        65,
        fd,
        &[IoVec {
            base: usize::MAX,
            len: 0
        }],
        0
    ) == 0);
    if ro {
        ck!(pwrite(fd, b"x", 0) == -30 && vector(70, fd, &[input(b"x")], 0) == -30);
        close(fd);
        pipes();
        sys_write(1, b"IOV PASS: readonly positioned/vector I/O and pipes\n");
        sys_exit(0);
    }
    let alias = syscall3(23, fd, 0, 0);
    ck!(alias >= 0);
    let alias = alias as usize;
    ck!(pwrite(fd, b"XY", 1) == 2 && offset(alias) == 3);
    ck!(vector(70, fd, &[input(b"12"), input(b"34")], 3) == 4 && offset(alias) == 3);
    ck!(pread(fd, &mut b, 1) == 4 && &b == b"XY12");
    seek(fd, 0);
    ck!(vector(65, fd, &[output(&mut a), output(&mut b)], 0) == 6
        && &a == b"aX"
        && &b == b"Y123"
        && offset(alias) == 6);
    ck!(vector(65, fd, &[output(&mut b)], 0) == 2 && &b[..2] == b"4h" && offset(fd) == 8);
    seek(fd, 0);
    ck!(vector(66, fd, &[input(b"ab"), IoVec { base: 0, len: 2 }], 0) == 2 && offset(fd) == 2);
    seek(fd, 0);
    ck!(
        vector(65, fd, &[output(&mut a), IoVec { base: 0, len: 2 }], 0) == 2
            && &a == b"ab"
            && offset(fd) == 2
    );
    ck!(vector(70, fd, &[input(b"Q"), IoVec { base: 0, len: 1 }], 0) == 1 && offset(fd) == 2);
    ck!(
        vector(69, fd, &[output(&mut a), IoVec { base: 0, len: 1 }], 0) == 2
            && &a == b"Qb"
            && offset(fd) == 2
    );
    let iov_area = syscall6(222, [0, 16384, 3, 0x22, usize::MAX, 0]);
    ck!(iov_area > 0);
    // SAFETY: mmap 成功提供对齐的 16384 字节可写区，恰好容纳 1024 项 IoVec。
    let vectors = unsafe { core::slice::from_raw_parts_mut(iov_area as *mut IoVec, 1024) };
    vectors.fill(input(b"z"));
    seek(fd, 0);
    ck!(vector(66, fd, vectors, 0) == 1024 && offset(fd) == 1024);
    ck!(syscall3(215, iov_area as usize, 16384, 0) == 0);
    let read_only = syscall3(56, CWD, b"/io-data\0".as_ptr() as usize, 0);
    ck!(read_only >= 0);
    ck!(pwrite(read_only as usize, b"z", 0) == -9
        && vector(66, read_only as usize, &[input(b"z")], 0) == -9);
    close(read_only as usize);
    let write_only = syscall3(56, CWD, b"/io-data\0".as_ptr() as usize, 1);
    ck!(write_only >= 0);
    ck!(pread(write_only as usize, &mut a, 0) == -9
        && vector(65, write_only as usize, &[output(&mut a)], 0) == -9);
    close(write_only as usize);
    let dir = syscall3(56, CWD, b"/\0".as_ptr() as usize, 0);
    ck!(dir >= 0);
    ck!(pread(dir as usize, &mut a, 0) == -21
        && vector(65, dir as usize, &[output(&mut a)], 0) == -21);
    close(dir as usize);
    let appended = syscall3(56, CWD, b"/io-data\0".as_ptr() as usize, 0x402);
    ck!(appended >= 0);
    let appended = appended as usize;
    seek(appended, 5);
    ck!(pwrite(appended, b"A", 0) == 1 && offset(appended) == 5);
    ck!(vector(70, appended, &[input(b"B"), input(b"C")], 0) == 2 && offset(appended) == 5);
    ck!(pread(fd, &mut b, 1024) == 3 && &b[..3] == b"ABC");
    close(appended);
    let area = syscall6(222, [0, 73728, 3, 0x22, usize::MAX, 0]);
    ck!(area > 0);
    let area = area as usize;
    // SAFETY: mmap 已成功提供 73728 字节可写用户内存；切片长度在映射范围内。
    let data = unsafe { core::slice::from_raw_parts_mut(area as *mut u8, 65536) };
    for (i, byte) in data.iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    ck!(vector(
        70,
        fd,
        &[input(&data[..5000]), input(&data[5000..10000])],
        0
    ) == 10000);
    data[..10000].fill(0);
    ck!(vector(
        69,
        fd,
        &[
            output(&mut data[..3333]),
            IoVec {
                base: area + 3333,
                len: 6667
            }
        ],
        0
    ) == 10000);
    ck!(data[..10000]
        .iter()
        .enumerate()
        .all(|(i, b)| *b == (i % 251) as u8));
    // 描述符数组跨入未映射页时，应在开始 I/O 前失败。
    ck!(syscall3(215, area + 69632, 4096, 0) == 0);
    // SAFETY: 地址位于仍有效映射内且按 IoVec 对齐；仅写一项。
    unsafe {
        core::ptr::write((area + 69616) as *mut IoVec, input(b"x"));
    }
    seek(fd, 7);
    ck!(syscall6(66, [fd, area + 69616, 2, 0, 0, 0]) == -14 && offset(fd) == 7);
    // 数据跨入未映射页时，只报告实际搬运的前缀。
    ck!(syscall6(68, [fd, area + 69630, 4, 0, 0, 0]) == 2 && offset(fd) == 7);
    ck!(syscall6(67, [fd, area + 69630, 4, 0, 0, 0]) == 2 && offset(fd) == 7);
    // 首个输出缓冲区覆盖描述符数组，后续描述符应仍使用内核快照。
    let descriptor = area + 65536;
    // SAFETY: 两项描述符及输出目标都在仍有效的 mmap 中，地址对齐。
    unsafe {
        core::ptr::write(
            descriptor as *mut IoVec,
            IoVec {
                base: descriptor,
                len: 16,
            },
        );
        core::ptr::write(
            (descriptor + 16) as *mut IoVec,
            IoVec {
                base: area + 66000,
                len: 2,
            },
        );
    }
    ck!(syscall6(69, [fd, descriptor, 2, 0, 0, 0]) == 18);
    let p = pipe(0x800);
    let (r, w) = (p[0] as usize, p[1] as usize);
    ck!(syscall3(64, w, area, 65536) == 65536);
    ck!(syscall3(63, r, area, 2048) == 2048);
    ck!(vector(66, w, &[input(&data[..1024]), input(&data[1024..4096])], 0) == -11);
    ck!(syscall3(63, r, area, 65536) == 63488);
    ck!(vector(66, w, &[input(&data[..4096]), input(&data[4096..8192])], 0) == 8192);
    ck!(syscall3(63, r, area, 8192) == 8192);
    close(r);
    close(w);
    ck!(syscall3(215, area, 69632, 0) == 0);
    ck!(pwrite(fd, b"H", 0x1_0000_0000) == 1);
    ck!(vector(69, fd, &[output(&mut a)], 0x1_0000_0000) == 1 && a[0] == b'H');
    ck!(pwrite(fd, b"X", isize::MAX as usize) == -27);
    close(alias);
    close(fd);
    pipes();
    sys_write(
        1,
        b"IOV PASS: offsets, vectors, faults, aliases, append, pipe atomicity and blocking\n",
    );
    sys_exit(0);
}
define_user_entry!(ouro_main);
