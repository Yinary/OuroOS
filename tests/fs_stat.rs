//! 文件状态、容量与链接查询回归；由 fs_stat.py 生成已知属性的磁盘。
#![no_std]
#![no_main]
use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};
const CWD: usize = (-100isize) as usize;
#[derive(Default, Clone, Copy)]
#[repr(C)]
struct Stat {
    dev: u64,
    ino: u64,
    mode: u32,
    links: u32,
    uid: u32,
    gid: u32,
    rdev: u64,
    pad: u64,
    size: i64,
    blksize: i32,
    pad2: i32,
    blocks: i64,
    atime: i64,
    atime_ns: u64,
    mtime: i64,
    mtime_ns: u64,
    ctime: i64,
    ctime_ns: u64,
    unused: [u32; 2],
}
fn check(ok: bool, line: u32) {
    if !ok {
        sys_write(1, b"STAT FAIL line ");
        let mut digits = [0u8; 10];
        let mut n = line;
        let mut i = digits.len();
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
fn at(dir: usize, path: &[u8], flags: usize, out: &mut Stat) -> isize {
    syscall6(
        79,
        [
            dir,
            path.as_ptr() as usize,
            out as *mut _ as usize,
            flags,
            0,
            0,
        ],
    )
}
fn sx(dir: usize, path: &[u8], flags: usize, mask: usize, out: &mut [u8; 256]) -> isize {
    syscall6(
        291,
        [
            dir,
            path.as_ptr() as usize,
            flags,
            mask,
            out.as_mut_ptr() as usize,
            0,
        ],
    )
}
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_ne_bytes(b[i..i + 4].try_into().unwrap())
}
fn u64at(b: &[u8], i: usize) -> u64 {
    u64::from_ne_bytes(b[i..i + 8].try_into().unwrap())
}
fn open(path: &[u8], flags: usize) -> isize {
    syscall6(56, [CWD, path.as_ptr() as usize, flags, 0o644, 0, 0])
}
fn close(fd: usize) {
    ck!(syscall3(57, fd, 0, 0) == 0);
}

fn readlink(dir: usize, path: &[u8], out: &mut [u8]) -> isize {
    syscall6(
        78,
        [
            dir,
            path.as_ptr() as usize,
            out.as_mut_ptr() as usize,
            out.len(),
            0,
            0,
        ],
    )
}

fn capacity(path: &[u8]) -> [u8; 120] {
    let mut out = [0xa5; 120];
    ck!(syscall3(43, path.as_ptr() as usize, out.as_mut_ptr() as usize, 0) == 0);
    out
}

#[inline(never)]
fn capacities() {
    let expected_fd = open(b"/fs-expected\0", 0);
    ck!(expected_fd >= 0);
    let mut expected = [0; 120];
    ck!(syscall3(
        63,
        expected_fd as usize,
        expected.as_mut_ptr() as usize,
        120
    ) == 120);
    close(expected_fd as usize);
    let before = capacity(b"/\0");
    ck!(before[..80] == expected[..80] && before[88..] == [0; 32]);
    ck!(u64at(&before, 80) & !1 == 0x20);
    let readonly = u64at(&before, 80) & 1 != 0;
    ck!(capacity(b"/meta/abs\0") == before);
    ck!(syscall3(49, b"/meta\0".as_ptr() as usize, 0, 0) == 0);
    ck!(capacity(b"data\0") == before);
    ck!(syscall3(49, b"/\0".as_ptr() as usize, 0, 0) == 0);
    let fd = open(b"/meta/data\0", 0);
    ck!(fd >= 0);
    let fd = fd as usize;
    ck!(syscall3(62, fd, 3, 0) == 3);
    let mut out = [0xa5; 128];
    ck!(syscall3(44, fd, out.as_mut_ptr() as usize, 0) == 0);
    ck!(out[..120] == before && out[120..] == [0xa5; 8]);
    ck!(syscall3(62, fd, 0, 1) == 3);
    ck!(syscall3(44, 999, out.as_mut_ptr() as usize, 0) == -9);
    ck!(syscall3(44, 1, out.as_mut_ptr() as usize, 0) == -95);
    ck!(syscall3(43, 0, out.as_mut_ptr() as usize, 0) == -14);
    for (path, error) in [
        (b"\0".as_slice(), -2),
        (b"/absent\0", -2),
        (b"/meta/dangling\0", -2),
        (b"/meta/loop\0", -40),
        (b"/meta/data/\0", -20),
    ] {
        ck!(syscall3(43, path.as_ptr() as usize, out.as_mut_ptr() as usize, 0) == error);
    }
    ck!(syscall3(43, b"/\0".as_ptr() as usize, usize::MAX, 0) == -14);
    ck!(syscall3(44, fd, usize::MAX, 0) == -14);
    let area = syscall6(222, [0, 8192, 3, 0x22, usize::MAX, 0]);
    ck!(area > 0);
    let area = area as usize;
    ck!(syscall3(43, b"/\0".as_ptr() as usize, area + 4090, 0) == 0);
    ck!(syscall3(215, area + 4096, 4096, 0) == 0);
    ck!(syscall3(43, b"/\0".as_ptr() as usize, area + 4090, 0) == -14);
    ck!(syscall3(44, fd, area + 4090, 0) == -14);
    ck!(syscall3(215, area, 4096, 0) == 0);
    close(fd);
    let probe = open(b"/capacity-probe\0", 0x42);
    if readonly {
        ck!(probe == -30);
    } else {
        ck!(probe >= 0);
        let probe = probe as usize;
        let created = capacity(b"/\0");
        ck!(u64at(&created, 48) + 1 == u64at(&before, 48));
        let data = [7u8; 512];
        for _ in 0..16 {
            ck!(syscall3(64, probe, data.as_ptr() as usize, data.len()) == 512);
        }
        let allocated = capacity(b"/\0");
        ck!(u64at(&allocated, 24) < u64at(&created, 24));
        ck!(u64at(&allocated, 32) <= u64at(&created, 32));
        ck!(syscall3(35, CWD, b"/capacity-probe\0".as_ptr() as usize, 0) == 0);
        ck!(syscall3(44, probe, out.as_mut_ptr() as usize, 0) == 0 && out[..120] == allocated);
        close(probe);
        let reclaimed = capacity(b"/\0");
        ck!(u64at(&reclaimed, 48) == u64at(&before, 48));
        ck!(u64at(&reclaimed, 24) == u64at(&before, 24));
    }
    sys_write(
        1,
        b"STATFS PASS: disk counters, ABI, paths, FD, allocation and faults\n",
    );
}

#[inline(never)]
fn links() {
    let mut out = [0xa5; 128];
    for (path, target) in [
        (b"/meta/abs\0".as_slice(), b"/meta/data".as_slice()),
        (b"/meta/rel\0", b"data"),
        (b"/meta/chain\0", b"rel"),
        (b"/meta/dangling\0", b"missing"),
        (b"/meta/loop\0", b"loop"),
        (b"/meta/sub/up\0", b"../data"),
        (b"/meta/dirlink/rel\0", b"data"),
    ] {
        out.fill(0xa5);
        ck!(readlink(999, path, &mut out) == target.len() as isize);
        ck!(&out[..target.len()] == target && out[target.len()] == 0xa5);
    }
    for (path, prefix) in [
        (b"/meta/sixty\0".as_slice(), 50),
        (b"/meta/long\0".as_slice(), 90),
    ] {
        out.fill(0xa5);
        ck!(readlink(CWD, path, &mut out) == (prefix + 10) as isize);
        ck!(out[..prefix].iter().all(|&c| c == b'/'));
        ck!(&out[prefix..prefix + 10] == b"/meta/data" && out[prefix + 10] == 0xa5);
    }
    out.fill(0xa5);
    ck!(readlink(CWD, b"/meta/rel\0", &mut out[..2]) == 2 && &out[..3] == &[b'd', b'a', 0xa5]);
    ck!(readlink(CWD, b"/meta/rel\0", &mut out[..4]) == 4 && out[4] == 0xa5);
    ck!(readlink(CWD, b"/meta/rel\0", &mut out[..0]) == -22);
    ck!(syscall6(78, [CWD, 0, 0, usize::MAX, 0, 0]) == -22);
    ck!(syscall6(78, [CWD, 0, 0, 4, 0, 0]) == -14);
    ck!(syscall6(
        78,
        [CWD, b"/meta/rel\0".as_ptr() as usize, usize::MAX, 4, 0, 0]
    ) == -14);
    for path in [b"/meta/data\0".as_slice(), b"/meta\0", b"/meta/dirlink/\0"] {
        ck!(readlink(CWD, path, &mut out) == -22);
    }
    ck!(readlink(CWD, b"/meta/missing\0", &mut out) == -2);
    ck!(readlink(CWD, b"/meta/rel/\0", &mut out) == -20);
    ck!(readlink(CWD, b"/meta/loop/sub\0", &mut out) == -40);
    ck!(readlink(CWD, b"\0", &mut out) == -2);
    ck!(readlink(999, b"rel\0", &mut out) == -9 && readlink(999, b"\0", &mut out) == -9);
    let file = open(b"/meta/data\0", 0);
    ck!(file >= 0);
    ck!(readlink(file as usize, b"rel\0", &mut out) == -20);
    ck!(readlink(file as usize, b"\0", &mut out) == -2);
    close(file as usize);
    let dir = open(b"/meta\0", 0x10000);
    ck!(dir >= 0);
    ck!(readlink(dir as usize, b"rel\0", &mut out) == 4 && &out[..4] == b"data");
    ck!(syscall3(49, b"/meta/sub\0".as_ptr() as usize, 0, 0) == 0);
    ck!(readlink(CWD, b"../rel\0", &mut out) == 4 && &out[..4] == b"data");
    ck!(readlink(dir as usize, b"sub/up\0", &mut out) == 7 && &out[..7] == b"../data");
    ck!(syscall3(49, b"/\0".as_ptr() as usize, 0, 0) == 0);
    close(dir as usize);
    let area = syscall6(222, [0, 8192, 3, 0x22, usize::MAX, 0]);
    ck!(area > 0);
    let area = area as usize;
    ck!(syscall6(
        78,
        [CWD, b"/meta/rel\0".as_ptr() as usize, area + 4094, 4, 0, 0]
    ) == 4);
    ck!(syscall3(215, area + 4096, 4096, 0) == 0);
    ck!(syscall6(
        78,
        [CWD, b"/meta/rel\0".as_ptr() as usize, area + 4094, 4, 0, 0]
    ) == -14);
    ck!(syscall3(215, area, 4096, 0) == 0);
    sys_write(
        1,
        b"READLINK PASS: targets, truncation, paths, dirfd and faults\n",
    );
}
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    capacities();
    links();
    ck!(core::mem::size_of::<Stat>() == 128);
    let mut s = Stat::default();
    let mut x = [0xa5; 256];
    let small = at(CWD, b"/small-inode\0", 0, &mut s) == 0;
    ck!(at(CWD, b"/meta/data\0", 0, &mut s) == 0);
    ck!(s.mode == 0x81a0 && s.size == 7 && s.links == 1);
    ck!(s.uid == 70000 && s.gid == 140000 && s.dev == 1 && s.rdev == 0 && s.blksize == 4096);
    ck!(s.atime == if small { -2147483647 } else { 2147483649 });
    ck!(s.atime_ns == if small { 0 } else { 123456789 });
    ck!(s.mtime == 2147483646 && s.mtime_ns == if small { 0 } else { 987654321 });
    ck!(s.ctime == if small { -1 } else { 4294967295 });
    ck!(s.ctime_ns == if small { 0 } else { 999999999 });
    ck!(s.pad == 0 && s.pad2 == 0 && s.unused == [0; 2]);
    let expected = s;
    for flags in [0, 0x100, 0x800, 0x2000, 0x4000] {
        ck!(sx(CWD, b"/meta/data\0", flags, 0xfff, &mut x) == 0);
        ck!(u32at(&x, 0) == if small { 0x7ff } else { 0xfff });
        ck!(u32at(&x, 20) == s.uid && u32at(&x, 24) == s.gid);
        ck!(u64at(&x, 32) == s.ino && u64at(&x, 40) == 7 && u64at(&x, 48) == s.blocks as u64);
        ck!(u64at(&x, 64) as i64 == s.atime && u32at(&x, 72) as u64 == s.atime_ns);
        ck!(u64at(&x, 96) as i64 == s.ctime && u32at(&x, 104) as u64 == s.ctime_ns);
        ck!(u64at(&x, 112) as i64 == s.mtime && u32at(&x, 120) as u64 == s.mtime_ns);
        ck!(u32at(&x, 136) == 0 && u32at(&x, 140) == 1);
        if !small {
            ck!(u64at(&x, 80) == 1700000000 && u32at(&x, 88) == 42);
        }
        ck!(x[144..].iter().all(|b| *b == 0));
    }
    ck!(sx(CWD, b"/meta/data\0", 0, 0, &mut x) == 0);
    ck!(sx(CWD, b"/meta/data\0", 0, 0x4000_0000, &mut x) == 0);
    ck!(sx(CWD, b"/meta/data\0", 0x6000, 0, &mut x) == -22);
    ck!(sx(CWD, b"/meta/data\0", 0, 0x8000_0000, &mut x) == -22);
    ck!(sx(CWD, b"/meta/data\0", 0x200, 0, &mut x) == -22);
    ck!(at(CWD, b"/meta/data\0", 0x2000, &mut s) == -22);
    let fd = open(b"/meta/data\0", 0);
    ck!(fd >= 0);
    let fd = fd as usize;
    ck!(syscall3(62, fd, 3, 0) == 3);
    ck!(syscall3(80, fd, &mut s as *mut _ as usize, 0) == 0
        && s.ino == expected.ino
        && s.atime == expected.atime);
    ck!(syscall3(62, fd, 0, 1) == 3);
    ck!(at(fd, b"\0", 0x1000, &mut s) == 0 && s.ino == expected.ino);
    ck!(sx(fd, b"\0", 0x1000, 0xfff, &mut x) == 0 && u64at(&x, 32) == expected.ino);
    ck!(syscall6(79, [fd, 0, &mut s as *mut _ as usize, 0x1000, 0, 0]) == 0);
    ck!(syscall6(291, [fd, 0, 0x1000, 0, x.as_mut_ptr() as usize, 0]) == 0);
    ck!(at(fd, b"data\0", 0, &mut s) == -20);
    ck!(at(999, b"/meta/data\0", 0, &mut s) == 0);
    ck!(at(999, b"data\0", 0, &mut s) == -9);
    ck!(at(999, b"\0", 0x1000, &mut s) == -9);
    ck!(at(CWD, b"\0", 0, &mut s) == -2);
    ck!(at(CWD, b"\0", 0x1000, &mut s) == 0 && s.mode & 0xf000 == 0x4000);
    let dir = open(b"/meta\0", 0x10000);
    ck!(dir >= 0);
    let dir = dir as usize;
    ck!(at(dir, b"data\0", 0, &mut s) == 0 && s.ino == expected.ino);
    ck!(syscall3(49, b"/meta\0".as_ptr() as usize, 0, 0) == 0);
    ck!(at(CWD, b"data\0", 0, &mut s) == 0 && s.ino == expected.ino);
    ck!(at(CWD, b"/meta/large\0", 0, &mut s) == 0 && s.size == 4294967303);
    for path in [
        b"/meta/abs\0".as_slice(),
        b"/meta/rel\0",
        b"/meta/chain\0",
        b"/meta/dirlink/data\0",
        b"/meta/sub/up\0",
        b"/meta/long\0",
        b"/meta/sixty\0",
    ] {
        ck!(at(CWD, path, 0, &mut s) == 0 && s.ino == expected.ino);
        ck!(sx(CWD, path, 0, 0xfff, &mut x) == 0 && u64at(&x, 32) == expected.ino);
    }
    ck!(at(CWD, b"/meta/rel\0", 0x100, &mut s) == 0 && s.mode & 0xf000 == 0xa000 && s.size == 4);
    ck!(sx(CWD, b"/meta/rel\0", 0x100, 0xfff, &mut x) == 0 && x[29] & 0xf0 == 0xa0);
    ck!(at(CWD, b"/meta/dangling\0", 0x100, &mut s) == 0 && s.mode & 0xf000 == 0xa000);
    ck!(at(CWD, b"/meta/dangling\0", 0, &mut s) == -2);
    ck!(at(CWD, b"/meta/loop\0", 0, &mut s) == -40);
    ck!(at(CWD, b"/meta/loop\0", 0x100, &mut s) == 0);
    ck!(at(CWD, b"/meta/dirlink/sub/../data\0", 0x100, &mut s) == 0 && s.ino == expected.ino);
    ck!(at(CWD, b"/meta/dirlink/\0", 0x100, &mut s) == 0 && s.mode & 0xf000 == 0x4000);
    ck!(at(CWD, b"/meta/data/\0", 0, &mut s) == -20);
    ck!(at(CWD, b"/meta/rel/\0", 0x100, &mut s) == -20);
    ck!(at(CWD, b"/meta/data/../data\0", 0, &mut s) == -20);
    ck!(at(CWD, b"/meta/missing/../data\0", 0, &mut s) == -2);
    ck!(at(CWD, b"/meta/missing\0", 0, &mut s) == -2);
    ck!(syscall3(80, 999, &mut s as *mut _ as usize, 0) == -9);
    ck!(syscall3(80, fd, usize::MAX, 0) == -14);
    ck!(syscall6(79, [CWD, usize::MAX, &mut s as *mut _ as usize, 0, 0, 0]) == -14);
    ck!(syscall6(
        79,
        [CWD, b"/meta/data\0".as_ptr() as usize, usize::MAX, 0, 0, 0]
    ) == -14);
    ck!(syscall6(
        291,
        [CWD, b"/meta/data\0".as_ptr() as usize, 0, 0, usize::MAX, 0]
    ) == -14);
    let mut long = [b'a'; 4096];
    long[4095] = 0;
    ck!(at(CWD, &long, 0, &mut s) == -36);
    long[4095] = b'a';
    ck!(at(CWD, &long, 0, &mut s) == -36);
    let mut pair = [0u32; 2];
    ck!(syscall3(59, pair.as_mut_ptr() as usize, 0, 0) == 0);
    ck!(
        syscall3(80, pair[0] as usize, &mut s as *mut _ as usize, 0) == 0
            && s.mode & 0xf000 == 0x1000
    );
    close(pair[0] as usize);
    close(pair[1] as usize);
    ck!(syscall3(80, 1, &mut s as *mut _ as usize, 0) == 0 && s.mode & 0xf000 == 0x2000);
    let area = syscall6(222, [0, 8192, 3, 0x22, usize::MAX, 0]);
    ck!(area > 0);
    let area = area as usize;
    ck!(syscall3(215, area + 4096, 4096, 0) == 0);
    ck!(syscall6(
        79,
        [CWD, b"/meta/data\0".as_ptr() as usize, area + 4090, 0, 0, 0]
    ) == -14);
    ck!(syscall6(
        291,
        [CWD, b"/meta/data\0".as_ptr() as usize, 0, 0, area + 4090, 0]
    ) == -14);
    ck!(syscall3(215, area, 4096, 0) == 0);
    ck!(at(CWD, b"/meta/char\0", 0, &mut s) == 0 && s.rdev == 0x103 && s.mode & 0xf000 == 0x2000);
    ck!(sx(CWD, b"/meta/char\0", 0, 0xfff, &mut x) == 0
        && u32at(&x, 128) == 1
        && u32at(&x, 132) == 3);
    close(dir);
    close(fd);
    // 小 inode 镜像不提供 FAT 分区，其他镜像验证挂载后的查询。
    if !small {
        let root_capacity = capacity(b"/\0");
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
        let fat_before = capacity(b"/mnt\0");
        let expected_fd = open(b"/fs-expected\0", 0);
        ck!(expected_fd >= 0);
        ck!(syscall3(62, expected_fd as usize, 120, 0) == 120);
        let mut geometry = [0; 32];
        ck!(syscall3(63, expected_fd as usize, geometry.as_mut_ptr() as usize, 32) == 32);
        close(expected_fd as usize);
        ck!(u64at(&fat_before, 0) == 0x4d44 && u64at(&fat_before, 8) == u64at(&geometry, 0));
        ck!(u64at(&fat_before, 16) == u64at(&geometry, 8));
        ck!(u64at(&fat_before, 24) == u64at(&geometry, 16));
        ck!(u64at(&fat_before, 32) == u64at(&geometry, 16));
        ck!(u64at(&fat_before, 56) == u64at(&geometry, 24));
        ck!(fat_before[40..56] == [0; 16] && u64at(&fat_before, 80) == 0x20);
        let fat = open(b"/mnt/file\0", 0x42);
        ck!(fat >= 0);
        let fat = fat as usize;
        let mut stats = [0; 120];
        ck!(syscall3(44, fat, stats.as_mut_ptr() as usize, 0) == 0 && stats == fat_before);
        ck!(syscall3(44, 0, stats.as_mut_ptr() as usize, 0) == -95);
        let data = [7u8; 512];
        for _ in 0..16 {
            ck!(syscall3(64, fat, data.as_ptr() as usize, data.len()) == 512);
        }
        let fat_after = capacity(b"/mnt/file\0");
        ck!(u64at(&fat_after, 24) < u64at(&fat_before, 24));
        ck!(u64at(&fat_after, 16) == u64at(&fat_before, 16));
        ck!(capacity(b"/\0") == root_capacity);
        ck!(at(CWD, b"/mnt/file\0", 0, &mut s) == 0 && s.dev != expected.dev);
        ck!(sx(CWD, b"/mnt/file\0", 0, 0xfff, &mut x) == 0 && u32at(&x, 0) == 0x71f);
        ck!(readlink(CWD, b"/mnt/file\0", &mut x) == -22);
        close(fat);
        ck!(syscall3(39, b"/mnt\0".as_ptr() as usize, 0, 0) == 0);
    }
    sys_write(
        1,
        b"STAT PASS: metadata, ABI, flags, paths, symlinks, errors, FD, FAT\n",
    );
    sys_exit(0);
}
define_user_entry!(ouro_main);
