//! 验证 Ext4 硬链接、符号链接创建与删名及 inode 回收。
#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};

const CWD: usize = -100isize as usize;
const FOLLOW: usize = 0x400;

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

macro_rules! ck {
    ($condition:expr) => {
        if !($condition) {
            sys_write(1, b"LINK FAIL line ");
            number(u64::from(line!()));
            sys_exit(1);
        }
    };
}

fn link(from: usize, old: &[u8], to: usize, new: &[u8], flags: usize) -> isize {
    syscall6(
        37,
        [
            from,
            old.as_ptr() as usize,
            to,
            new.as_ptr() as usize,
            flags,
            0,
        ],
    )
}

fn unlink(path: &[u8]) -> isize {
    syscall3(35, CWD, path.as_ptr() as usize, 0)
}

fn symlink(target: &[u8], dir: usize, path: &[u8]) -> isize {
    syscall3(36, target.as_ptr() as usize, dir, path.as_ptr() as usize)
}

fn open(path: &[u8], flags: usize) -> usize {
    let fd = open_at(CWD, path, flags);
    ck!(fd >= 0);
    fd as usize
}

fn open_at(dir: usize, path: &[u8], flags: usize) -> isize {
    syscall6(56, [dir, path.as_ptr() as usize, flags, 0o644, 0, 0])
}

fn stat(path: &[u8]) -> (u64, u32) {
    let mut out = [0; 128];
    ck!(syscall6(
        79,
        [
            CWD,
            path.as_ptr() as usize,
            out.as_mut_ptr() as usize,
            0x100,
            0,
            0
        ]
    ) == 0);
    (
        u64::from_ne_bytes(core::array::from_fn(|i| out[8 + i])),
        u32::from_ne_bytes(core::array::from_fn(|i| out[20 + i])),
    )
}

fn check_target(path: &[u8], target: &[u8]) {
    let mut out = [0; 128];
    ck!(syscall6(
        78,
        [
            CWD,
            path.as_ptr() as usize,
            out.as_mut_ptr() as usize,
            out.len(),
            0,
            0
        ]
    ) == target.len() as isize);
    ck!(&out[..target.len()] == target);
}

fn regular() {
    let fd = open(b"/original\0", 0x42);
    sys_write(fd, b"shared");
    let dir = open(b"/meta\0", 0x10000);
    ck!(link(999, b"/original\0", dir, b"alias\0", 0) == 0);
    let (ino, count) = stat(b"/original\0");
    ck!(count == 2 && stat(b"/meta/alias\0") == (ino, 2));
    ck!(link(dir, b"alias\0", CWD, b"/original\0", 0) == -17);
    ck!(link(CWD, b"/original\0", CWD, b"/meta/dirlink/new-alias\0", 0) == 0);
    ck!(stat(b"/meta/new-alias\0") == (ino, 3));
    ck!(unlink(b"/meta/dirlink/new-alias\0") == 0);
    ck!(unlink(b"/original\0") == 0 && stat(b"/meta/alias\0") == (ino, 1));

    let alias = open(b"/meta/alias\0", 0);
    let mut data = [0; 6];
    ck!(syscall3(63, alias, data.as_mut_ptr() as usize, data.len()) == 6 && &data == b"shared");
    ck!(unlink(b"/meta/alias\0") == 0);
    ck!(syscall3(62, fd, 0, 0) == 0);
    ck!(syscall3(63, fd, data.as_mut_ptr() as usize, data.len()) == 6 && &data == b"shared");
    ck!(syscall3(57, alias, 0, 0) == 0 && syscall3(57, fd, 0, 0) == 0);
    ck!(syscall3(57, dir, 0, 0) == 0);
    sys_write(1, b"LINK FREED INODE: ");
    number(ino);
}

fn symbolic() {
    // 短目标内嵌于 inode，长目标占用数据块。
    let mut long = [b'/'; 100];
    long[90..].copy_from_slice(b"/meta/data");
    for (old, new, target) in [
        (
            b"/meta/abs\0".as_slice(),
            b"/short-alias\0".as_slice(),
            b"/meta/data".as_slice(),
        ),
        (
            b"/meta/long\0".as_slice(),
            b"/long-alias\0".as_slice(),
            long.as_slice(),
        ),
    ] {
        let (ino, count) = stat(old);
        ck!(count == 1);
        ck!(link(CWD, old, CWD, new, 0) == 0 && stat(new) == (ino, 2));
        ck!(unlink(old) == 0 && stat(new) == (ino, 1));
        check_target(new, target);
        ck!(link(CWD, new, CWD, b"/followed\0", FOLLOW) == 0);
        ck!(stat(b"/followed\0") == stat(b"/meta/data\0"));
        ck!(unlink(new) == 0 && unlink(b"/followed\0") == 0);
        ck!(stat(b"/meta/data\0").1 == 1);
        sys_write(1, b"LINK FREED INODE: ");
        number(ino);
    }
    ck!(link(CWD, b"/meta/dangling\0", CWD, b"/missing-link\0", FOLLOW) == -2);
    ck!(link(CWD, b"/meta/dangling\0", CWD, b"/missing-link\0", 0) == 0);
    check_target(b"/missing-link\0", b"missing");
    ck!(unlink(b"/missing-link\0") == 0);
}

fn cross_mount() {
    let dev = b"/dev/vda2\0".as_ptr() as usize;
    let mnt = b"/mnt\0".as_ptr() as usize;
    ck!(syscall6(33, [CWD, dev, 0o60600, (254 << 8) | 2, 0, 0]) == 0);
    let block = open(b"/dev/vda2\0", 0);
    let mut attrs = [0u8; 128];
    ck!(syscall3(80, block, attrs.as_mut_ptr() as usize, 0) == 0);
    ck!(u32::from_ne_bytes(core::array::from_fn(|i| attrs[16 + i])) & 0xf000 == 0x6000);
    ck!(u64::from_ne_bytes(core::array::from_fn(|i| attrs[32 + i])) == (254 << 8) | 2);
    let mut length = 0u64;
    ck!(syscall3(29, block, 0x8008_1272, &mut length as *mut u64 as usize) == 0);
    ck!(length == 16 * 1024 * 1024);
    ck!(syscall3(29, block, 0x8008_1272, 0) == -14);
    let mut signature = [0u8; 2];
    ck!(syscall6(67, [block, signature.as_mut_ptr() as usize, 2, 510, 0, 0]) == 2);
    ck!(signature == [0x55, 0xaa]);
    ck!(open_at(CWD, b"/dev/vda2\0", 2) == -16);
    ck!(syscall3(57, block, 0, 0) == 0);
    ck!(syscall6(40, [dev, mnt, b"vfat\0".as_ptr() as usize, 0, 0, 0]) == 0);
    ck!(link(CWD, b"/meta/data\0", CWD, b"/mnt/alias\0", 0) == -18);
    ck!(symlink(b"data\0", CWD, b"/mnt/symlink\0") == -1);
    ck!(syscall3(39, mnt, 0, 0) == 0);
}

fn check_procfs() {
    let path = b"/proc/cpuinfo\0";
    let fd = open(path, 0);
    let mut text = [0; 64];
    let count = syscall3(63, fd, text.as_mut_ptr() as usize, text.len());
    ck!(count > 0);
    ck!(text.starts_with(b"processor\t: 0\n"));
    ck!(syscall3(63, fd, text.as_mut_ptr() as usize, text.len()) == 0);
    let mut attrs = [0u8; 128];
    ck!(syscall3(80, fd, attrs.as_mut_ptr() as usize, 0) == 0);
    let ino = u64::from_ne_bytes(core::array::from_fn(|i| attrs[8 + i]));
    let mode = u32::from_ne_bytes(core::array::from_fn(|i| attrs[16 + i]));
    ck!(stat(path).0 == ino && mode == 0o100444);
    ck!(syscall3(57, fd, 0, 0) == 0);
    ck!(open_at(CWD, path, 1) == -30);
    ck!(link(CWD, path, CWD, b"/cpuinfo-link\0", 0) == -18);
}

fn check_open_symlink(dir: usize) {
    let relative = b"relative\0";
    let fd = open_at(dir, relative, 0);
    ck!(fd >= 0);
    let fd = fd as usize;
    let mut buf = [0; 16];
    ck!(syscall3(63, fd, buf.as_mut_ptr() as usize, buf.len()) == 7);
    ck!(&buf[..7] == b"testing");
    ck!(syscall3(57, fd, 0, 0) == 0);
    ck!(open_at(dir, relative, 0x20000) == -40);
    let fd = open_at(dir, relative, 0x220000);
    ck!(fd >= 0);
    let fd = fd as usize;
    ck!(syscall3(63, fd, buf.as_mut_ptr() as usize, buf.len()) == -9);
    ck!(syscall6(
        78,
        [
            fd,
            b"\0".as_ptr() as usize,
            buf.as_mut_ptr() as usize,
            buf.len(),
            0,
            0
        ]
    ) == 7);
    ck!(&buf[..7] == b"../data");
    ck!(syscall3(57, fd, 0, 0) == 0);
    ck!(open_at(CWD, b"/meta/loop\0", 0) == -40);
    ck!(open_at(CWD, b"/meta/data/\0", 0) == -20);
    let fd = open(b"/meta/dirlink/../meta/data\0", 0);
    ck!(syscall3(57, fd, 0, 0) == 0);

    ck!(symlink(b"delayed\0", dir, b"create-through\0") == 0);
    ck!(open_at(dir, b"create-through\0", 0) == -2);
    ck!(open_at(dir, b"create-through\0", 0xc2) == -17);
    let fd = open_at(dir, b"create-through\0", 0x42);
    ck!(fd >= 0 && syscall3(57, fd as usize, 0, 0) == 0);
    ck!(stat(b"/meta/sub/delayed\0").1 == 1);
    check_target(b"/meta/sub/create-through\0", b"delayed");
    ck!(unlink(b"/meta/sub/create-through\0") == 0);
    ck!(unlink(b"/meta/sub/delayed\0") == 0);
}

fn create_symbolic() {
    let dir = open(b"/meta/sub\0", 0x10000);
    ck!(symlink(b"../data\0", dir, b"relative\0") == 0);
    ck!(symlink(b"unused\0", dir, b"relative\0") == -17);
    check_target(b"/meta/sub/relative\0", b"../data");
    check_open_symlink(dir);
    let (short, count) = stat(b"/meta/sub/relative\0");
    ck!(count == 1 && short != stat(b"/meta/data\0").0);
    ck!(link(
        CWD,
        b"/meta/sub/relative\0",
        CWD,
        b"/created-follow\0",
        FOLLOW
    ) == 0);
    ck!(stat(b"/created-follow\0") == stat(b"/meta/data\0"));

    let mut long = [b'a'; 61];
    long[60] = 0;
    ck!(symlink(&long, 999, b"/created-long\0") == 0);
    let (long_ino, count) = stat(b"/created-long\0");
    ck!(count == 1 && long_ino != short);
    check_target(b"/created-long\0", &long[..60]);
    ck!(link(CWD, b"/created-long\0", CWD, b"/created-alias\0", FOLLOW) == -2);
    ck!(link(CWD, b"/created-long\0", CWD, b"/created-alias\0", 0) == 0);
    ck!(stat(b"/created-alias\0") == (long_ino, 2));
    ck!(unlink(b"/created-long\0") == 0);
    check_target(b"/created-alias\0", &long[..60]);
    ck!(unlink(b"/created-alias\0") == 0);
    ck!(unlink(b"/meta/sub/relative\0") == 0);
    ck!(unlink(b"/created-follow\0") == 0 && stat(b"/meta/data\0").1 == 1);
    ck!(syscall3(57, dir, 0, 0) == 0);
    ck!(symlink(b"\0", CWD, b"/bad\0") == -2);
    ck!(symlink(b"x\0", 999, b"bad\0") == -9);
    ck!(symlink(b"x\0", CWD, b"/missing/bad\0") == -2);
    ck!(symlink(b"x\0", CWD, b"/missing/\0") == -2);
    ck!(symlink(b"x\0", CWD, b"/meta/data/\0") == -17);
    for ino in [short, long_ino] {
        sys_write(1, b"SYMLINK FREED INODE: ");
        number(ino);
    }
}

fn run() -> ! {
    let before = stat(b"/meta/data\0");
    ck!(link(CWD, b"/meta\0", CWD, b"/alias\0", 0) == -1);
    ck!(link(CWD, b"/meta/data\0", CWD, b"/alias\0", 1) == -22);
    ck!(link(CWD, b"/meta/data\0", 999, b"alias\0", 0) == -9);
    ck!(link(CWD, b"/meta/data\0", CWD, b"/missing/alias\0", 0) == -2);
    ck!(link(CWD, b"/meta/data\0", CWD, b"/meta/abs\0", 0) == -17);
    ck!(link(CWD, b"/meta/data\0", CWD, b"/alias/\0", 0) == -2);
    ck!(link(CWD, b"/meta/data\0", CWD, b"/meta/data/\0", 0) == -17);
    ck!(link(CWD, b"/meta/data\0", CWD, b"/meta/dangling/\0", 0) == -17);
    ck!(unlink(b"/meta/abs/\0") == -20);
    ck!(stat(b"/meta/data\0") == before);
    if syscall6(56, [CWD, b"/small-inode\0".as_ptr() as usize, 0, 0, 0, 0]) == -2 {
        cross_mount();
    }
    regular();
    symbolic();
    create_symbolic();
    check_procfs();
    let fifo = b"/meta/test-fifo\0";
    let alias = b"/fifo-alias\0";
    let args = [CWD, fifo.as_ptr() as usize, 0o010666, 0, 0, 0];
    ck!(syscall6(33, args) == 0 && syscall6(33, args) == -17);
    let ino = stat(fifo).0;
    ck!(link(CWD, fifo, CWD, alias, 0) == 0);
    ck!(stat(alias) == (ino, 2));
    ck!(unlink(fifo) == 0 && stat(alias) == (ino, 1));
    let fd = open(alias, 0x200000);
    let mut attrs = [0u8; 128];
    ck!(syscall3(80, fd, attrs.as_mut_ptr() as usize, 0) == 0);
    let mode = u32::from_ne_bytes(core::array::from_fn(|i| attrs[16 + i]));
    ck!(mode == 0o010644);
    ck!(syscall3(57, fd, 0, 0) == 0 && unlink(alias) == 0);
    sys_write(1, b"LINK PASS: creation, resolution and reclamation\n");
    sys_exit(0);
}

define_user_entry!(run);
