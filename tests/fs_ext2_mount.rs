//! 验证辅助 Ext2 卷与 Ext4 根卷的 inode 隔离和卸载。
#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};

const CWD: usize = -100isize as usize;
const DISK: &[u8] = b"/dev/vdb\0";
const MOUNT: &[u8] = b"/mnt\0";
const MOUNT_ALIAS: &[u8] = b"/mount-alias\0";
const AUX: &[u8] = b"/mnt/file\0";

macro_rules! ck {
    ($condition:expr) => {
        if !$condition {
            sys_write(1, concat!("EXT2 FAIL line ", line!(), "\n").as_bytes());
            sys_exit(1);
        }
    };
}

fn mount(path: &[u8], flags: usize) -> isize {
    syscall6(
        40,
        [
            DISK.as_ptr() as usize,
            path.as_ptr() as usize,
            b"ext2\0".as_ptr() as usize,
            flags,
            0,
            0,
        ],
    )
}

fn unmount(path: &[u8]) -> isize {
    syscall3(39, path.as_ptr() as usize, 0, 0)
}

fn open(path: &[u8], flags: usize) -> isize {
    syscall6(56, [CWD, path.as_ptr() as usize, flags, 0o644, 0, 0])
}

fn attr(path: &[u8]) -> (u64, u64) {
    let mut stat = [0u8; 128];
    ck!(syscall6(
        79,
        [
            CWD,
            path.as_ptr() as usize,
            stat.as_mut_ptr() as usize,
            0,
            0,
            0
        ]
    ) == 0);
    let dev = u64::from_ne_bytes(core::array::from_fn(|i| stat[i]));
    let ino = u64::from_ne_bytes(core::array::from_fn(|i| stat[8 + i]));
    (dev, ino)
}

fn link(old: &[u8], new: &[u8]) -> isize {
    syscall6(
        37,
        [CWD, old.as_ptr() as usize, CWD, new.as_ptr() as usize, 0, 0],
    )
}

fn run() -> ! {
    let root = attr(b"/\0");
    ck!(mount(MOUNT, 0) == 0);
    let mounted = attr(MOUNT);
    ck!(root.0 != mounted.0 && root.1 == mounted.1);
    ck!(open(b"/mnt/underneath\0", 0) == -2);
    ck!(mount(MOUNT, 0) == -16);
    let dir = open(MOUNT, 0x10000);
    ck!(dir >= 0);
    let mut entries = [0u8; 256];
    let count = syscall3(
        61,
        dir as usize,
        entries.as_mut_ptr() as usize,
        entries.len(),
    );
    ck!(count > 0);
    ck!(entries[..count as usize]
        .windows(10)
        .any(|s| s == b"lost+found"));
    ck!(unmount(MOUNT) == -16);
    ck!(syscall3(57, dir as usize, 0, 0) == 0);

    let fd = open(AUX, 0x42);
    ck!(fd >= 0);
    let fd = fd as usize;
    ck!(syscall3(64, fd, b"aux data".as_ptr() as usize, 8) == 8);
    ck!(syscall3(82, fd, 0, 0) == 0);
    ck!(syscall3(62, fd, 0, 0) == 0);
    let mut buf = [0; 8];
    ck!(syscall3(63, fd, buf.as_mut_ptr() as usize, buf.len()) == 8);
    ck!(&buf == b"aux data");
    ck!(syscall3(57, fd, 0, 0) == 0);
    ck!(link(AUX, b"/mnt/alias\0") == 0);
    ck!(attr(AUX) == attr(b"/mnt/alias\0"));
    ck!(link(AUX, b"/cross\0") == -18);
    ck!(link(b"/init\0", b"/mnt/cross\0") == -18);
    ck!(mount(MOUNT, 32 | 1) == 0);
    ck!(open(AUX, 2) == -30);
    ck!(link(MOUNT, b"/mnt/readonly\0") == -30);
    ck!(unmount(MOUNT) == 0);
    let covered = open(b"/mnt/underneath\0", 0);
    ck!(covered >= 0);
    ck!(syscall3(57, covered as usize, 0, 0) == 0);

    ck!(syscall3(
        36,
        MOUNT.as_ptr() as usize,
        CWD,
        MOUNT_ALIAS.as_ptr() as usize
    ) == 0);
    ck!(mount(MOUNT_ALIAS, 1) == 0);
    let persisted = open(b"/mnt/alias\0", 0);
    ck!(persisted >= 0);
    ck!(syscall3(63, persisted as usize, buf.as_mut_ptr() as usize, buf.len()) == 8);
    ck!(&buf == b"aux data");
    ck!(syscall3(57, persisted as usize, 0, 0) == 0);
    ck!(unmount(MOUNT_ALIAS) == 0);
    sys_write(1, b"EXT2 MOUNT PASS\n");
    sys_exit(0);
}

define_user_entry!(run);
