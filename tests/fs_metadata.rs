//! umask 与 utimensat 回归；由 fs_stat.py --metadata 构造磁盘并运行。
#![no_std]
#![no_main]
use hello::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};
const CWD: usize = (-100isize) as usize;
const OMIT: i64 = (1 << 30) - 2;
const NOW: i64 = OMIT + 1;
fn check(ok: bool, line: u32) {
    if !ok {
        sys_write(1, b"METADATA FAIL line ");
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
fn close(fd: usize) {
    ck!(syscall3(57, fd, 0, 0) == 0);
}
fn open(path: &[u8], flags: usize, mode: usize) -> isize {
    syscall6(56, [CWD, path.as_ptr() as usize, flags, mode, 0, 0])
}
fn stat(path: &[u8], flags: usize) -> [u8; 128] {
    let mut out = [0; 128];
    ck!(syscall6(
        79,
        [
            CWD,
            path.as_ptr() as usize,
            out.as_mut_ptr() as usize,
            flags,
            0,
            0
        ]
    ) == 0);
    out
}
fn word(b: &[u8], offset: usize) -> i64 {
    i64::from_ne_bytes(core::array::from_fn(|i| b[offset + i]))
}
fn mode(path: &[u8]) -> u32 {
    let s = stat(path, 0);
    u32::from_ne_bytes(core::array::from_fn(|i| s[16 + i])) & 0o777
}
fn times(dir: usize, path: &[u8], ts: &[i64; 4], flags: usize) -> isize {
    syscall6(
        88,
        [
            dir,
            path.as_ptr() as usize,
            ts.as_ptr() as usize,
            flags,
            0,
            0,
        ],
    )
}
fn masks(readonly: bool) {
    ck!(syscall3(166, 0o077, 0, 0) == 0o022);
    if !readonly {
        let fd = open(b"/mask-file\0", 0x42, 0o666);
        ck!(fd >= 0);
        close(fd as usize);
        ck!(mode(b"/mask-file\0") == 0o600);
        ck!(syscall3(34, CWD, b"/mask-dir\0".as_ptr() as usize, 0o777) == 0);
        ck!(mode(b"/mask-dir\0") == 0o700);
        ck!(syscall3(166, 0o777, 0, 0) == 0o077);
        let fd = open(b"/mask-file\0", 0x42, 0o777);
        ck!(fd >= 0);
        close(fd as usize);
        ck!(mode(b"/mask-file\0") == 0o600);
    } else {
        ck!(open(b"/mask-file\0", 0x42, 0o666) == -30);
    }
    ck!(syscall3(166, 0o027 | 0x10000, 0, 0) == if readonly { 0o077 } else { 0o777 });
    if !readonly {
        let fd = open(b"/mask-other\0", 0x42, 0o666);
        ck!(fd >= 0);
        close(fd as usize);
        ck!(mode(b"/mask-other\0") == 0o640);
    }
    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    ck!(pid >= 0);
    if pid == 0 {
        ck!(syscall3(166, 0o077, 0, 0) == 0o027);
        if !readonly {
            let fd = open(b"/mask-child\0", 0x42, 0o777);
            ck!(fd >= 0);
            close(fd as usize);
        }
        ck!(syscall3(221, b"/absent\0".as_ptr() as usize, 0, 0) == -2);
        ck!(syscall3(166, 0o077, 0, 0) == 0o077);
        syscall3(221, b"/mask-exec\0".as_ptr() as usize, 0, 0);
        sys_exit(1);
    }
    let mut status = -1i32;
    ck!(syscall6(
        260,
        [pid as usize, &mut status as *mut _ as usize, 0, 0, 0, 0]
    ) == pid
        && status == 0);
    ck!(syscall3(166, 0o022, 0, 0) == 0o027);
    if !readonly {
        ck!(mode(b"/mask-child\0") == 0o700);
    }
}
fn timestamps(readonly: bool, small: bool) {
    let path = b"/meta/data\0";
    let specified = [1700000001, 123456789, -10, 987654321];
    let original = stat(path, 0);
    let fd = open(path, 0, 0);
    ck!(fd >= 0);
    let fd = fd as usize;
    ck!(times(
        999,
        b"/missing\0",
        &[i64::MIN, OMIT, i64::MAX, OMIT],
        usize::MAX
    ) == 0);
    for bad in [-1, 1_000_000_000] {
        ck!(times(CWD, path, &[0, bad, 0, 0], 0) == -22);
        ck!(times(CWD, path, &[0, 0, 0, bad], 0) == -22);
    }
    ck!(stat(path, 0) == original);
    ck!(times(CWD, path, &specified, 0x800) == -22);
    ck!(syscall6(88, [CWD, path.as_ptr() as usize, usize::MAX, 0, 0, 0]) == -14);
    ck!(syscall6(88, [CWD, 0, 0, 0, 0, 0]) == -14);
    ck!(syscall6(88, [999, 0, 0, 0, 0, 0]) == -9);
    ck!(syscall6(88, [fd, 0, 0, 0x100, 0, 0]) == -22);
    ck!(times(CWD, b"\0", &specified, 0) == -2);
    ck!(times(CWD, b"/meta/dangling\0", &specified, 0) == -2);
    ck!(times(CWD, b"/meta/loop\0", &specified, 0) == -40);
    ck!(times(CWD, b"/meta/data/sub\0", &specified, 0) == -20);
    if readonly {
        ck!(times(CWD, path, &specified, 0) == -30);
        ck!(syscall6(88, [fd, 0, 0, 0, 0, 0]) == -30);
        ck!(times(CWD, path, &[0, OMIT, 0, NOW], 0) == -30);
        ck!(stat(path, 0) == original);
        close(fd);
        return;
    }
    ck!(times(999, path, &specified, 0) == 0);
    let s = stat(path, 0);
    ck!(word(&s, 72) == specified[0] && word(&s, 88) == specified[2]);
    ck!(word(&s, 80) == if small { 0 } else { specified[1] });
    ck!(word(&s, 96) == if small { 0 } else { specified[3] });
    ck!(s[..72] == original[..72] && word(&s, 104) > 0);
    let dir = open(b"/meta\0", 0x10000, 0);
    ck!(dir >= 0);
    ck!(times(dir as usize, b"rel\0", &[0, OMIT, 123, 42], 0) == 0);
    let s2 = stat(path, 0);
    ck!(s2[72..88] == s[72..88] && word(&s2, 88) == 123);
    let target = s2;
    ck!(times(CWD, b"/meta/rel\0", &specified, 0x100) == 0);
    ck!(word(&stat(b"/meta/rel\0", 0x100), 72) == specified[0]);
    ck!(stat(path, 0) == target);
    ck!(times(CWD, b"/meta/dangling\0", &specified, 0x100) == 0);
    ck!(times(CWD, b"/meta/sub\0", &specified, 0) == 0);
    ck!(syscall3(49, b"/meta/sub\0".as_ptr() as usize, 0, 0) == 0);
    ck!(times(CWD, b"../rel\0", &[321, 0, 654, 0], 0) == 0);
    ck!(syscall3(49, b"/\0".as_ptr() as usize, 0, 0) == 0);
    ck!(word(&stat(path, 0), 72) == 321);
    ck!(syscall3(62, fd, 3, 0) == 3);
    ck!(syscall6(88, [fd, 0, specified.as_ptr() as usize, 0, 0, 0]) == 0);
    ck!(syscall3(62, fd, 0, 1) == 3);
    ck!(times(fd, b"\0", &specified, 0x1000) == 0);
    ck!(syscall6(88, [fd, 0, 0, 0, 0, 0]) == 0);
    let s = stat(path, 0);
    ck!(word(&s, 72) == word(&s, 88) && word(&s, 88) == word(&s, 104));
    ck!(word(&s, 80) == word(&s, 96) && word(&s, 96) == word(&s, 112));
    ck!(times(CWD, path, &[i64::MIN, 999, i64::MAX, 999], 0) == 0);
    let s = stat(path, 0);
    ck!(word(&s, 72) == i32::MIN as i64 && word(&s, 80) == 0);
    ck!(word(&s, 88)
        == if small {
            i32::MAX as i64
        } else {
            0x3_7fff_ffff
        });
    ck!(word(&s, 96) == 0);
    let area = syscall6(222, [0, 8192, 3, 0x22, usize::MAX, 0]);
    ck!(area > 0);
    let area = area as usize;
    // SAFETY: mmap 成功建立两页可写内存，32 字节目的区间完全位于其中，与栈上源不重叠。
    unsafe {
        core::ptr::copy_nonoverlapping(
            specified.as_ptr() as *const u8,
            (area + 4080) as *mut u8,
            32,
        );
    }
    ck!(syscall6(88, [fd, 0, area + 4080, 0, 0, 0]) == 0);
    ck!(syscall3(215, area + 4096, 4096, 0) == 0);
    let saved = stat(path, 0);
    ck!(syscall6(88, [fd, 0, area + 4080, 0, 0, 0]) == -14);
    ck!(stat(path, 0) == saved);
    ck!(syscall3(215, area, 4096, 0) == 0);
    close(dir as usize);
    close(fd);
    let orphan = open(b"/time-orphan\0", 0x42, 0o600);
    ck!(orphan >= 0);
    let orphan = orphan as usize;
    ck!(syscall3(35, CWD, b"/time-orphan\0".as_ptr() as usize, 0) == 0);
    ck!(syscall6(88, [orphan, 0, specified.as_ptr() as usize, 0, 0, 0]) == 0);
    let mut out = [0; 128];
    ck!(syscall3(80, orphan, out.as_mut_ptr() as usize, 0) == 0 && word(&out, 72) == specified[0]);
    close(orphan);
}
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let mut fs = [0; 120];
    ck!(syscall3(43, b"/\0".as_ptr() as usize, fs.as_mut_ptr() as usize, 0) == 0);
    let readonly = word(&fs, 80) & 1 != 0;
    if readonly {
        sys_write(1, b"METADATA READONLY\n");
    }
    let small = open(b"/small-inode\0", 0, 0);
    if small >= 0 {
        close(small as usize);
    }
    masks(readonly);
    timestamps(readonly, small >= 0);
    if small < 0 {
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
        let fd = open(b"/mnt/file\0", 0x42, 0o600);
        ck!(fd >= 0);
        ck!(times(CWD, b"/mnt/file\0", &[0, NOW, 0, NOW], 0) == -95);
        ck!(mode(b"/mnt/file\0") == 0o777);
        close(fd as usize);
        ck!(syscall3(39, b"/mnt\0".as_ptr() as usize, 0, 0) == 0);
    }
    sys_write(
        1,
        b"METADATA PASS: umask, fork/exec, timestamps, links, FD, readonly and faults\n",
    );
    sys_exit(0);
}
define_user_entry!(ouro_main);
