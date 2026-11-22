//! renameat/renameat2 回归；验证目录项、打开引用及错误路径。
#![no_std]
#![no_main]
use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};
const CWD: usize = (-100isize) as usize;
fn check(ok: bool, line: u32) {
    if !ok {
        sys_write(1, b"RENAME FAIL line ");
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
fn ren(old: &[u8], new: &[u8]) -> isize {
    syscall6(
        38,
        [CWD, old.as_ptr() as usize, CWD, new.as_ptr() as usize, 0, 0],
    )
}
fn ren2(old: &[u8], new: &[u8], flags: usize) -> isize {
    syscall6(
        276,
        [
            CWD,
            old.as_ptr() as usize,
            CWD,
            new.as_ptr() as usize,
            flags,
            0,
        ],
    )
}
fn stat(path: &[u8]) -> [u8; 128] {
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
    out
}
fn word(data: &[u8], at: usize) -> u64 {
    u64::from_ne_bytes(core::array::from_fn(|i| data[at + i]))
}
fn links(path: &[u8]) -> u32 {
    let s = stat(path);
    u32::from_ne_bytes(core::array::from_fn(|i| s[20 + i]))
}
fn absent(path: &[u8]) {
    ck!(syscall6(56, [CWD, path.as_ptr() as usize, 0, 0, 0, 0]) == -2);
}
fn make(path: &[u8], text: &[u8]) -> usize {
    let fd = open(path, 0x42);
    ck!(syscall3(64, fd, text.as_ptr() as usize, text.len()) == text.len() as isize);
    fd
}
fn read(fd: usize, text: &[u8]) {
    let mut out = [0; 16];
    ck!(syscall3(62, fd, 0, 0) == 0);
    ck!(syscall3(63, fd, out.as_mut_ptr() as usize, out.len()) == text.len() as isize);
    ck!(&out[..text.len()] == text);
}
fn mkdir(path: &[u8]) {
    ck!(syscall3(34, CWD, path.as_ptr() as usize, 0o777) == 0);
}
fn chdir(path: &[u8]) {
    ck!(syscall3(49, path.as_ptr() as usize, 0, 0) == 0);
}
fn files() {
    let a = make(b"/rename-a\0", b"source");
    let b = make(b"/rename-b\0", b"target");
    let original = word(&stat(b"/rename-a\0"), 8);
    ck!(ren2(b"/rename-a\0", b"/rename-b\0", 1) == -17);
    ck!(ren(b"/absent\0", b"/rename-b\0") == -2);
    read(b, b"target");
    ck!(ren(b"/rename-a\0", b"/rename-b\0") == 0);
    absent(b"/rename-a\0");
    ck!(word(&stat(b"/rename-b\0"), 8) == original);
    read(a, b"source");
    read(b, b"target");
    let c = open(b"/rename-b\0", 0);
    read(c, b"source");
    let mut old = [0; 128];
    ck!(syscall3(80, b, old.as_mut_ptr() as usize, 0) == 0);
    ck!(u32::from_ne_bytes(core::array::from_fn(|i| old[20 + i])) == 0);
    close(b);
    close(c);
    close(a);
    ck!(ren(b"/rename-b\0", b"/rename-b\0") == 0);
    ck!(ren2(b"/rename-b\0", b"/rename-b\0", 1) == -17);
    ck!(ren2(b"/rename-b\0", b"/rename-c\0", 1) == 0);
    ck!(ren2(b"/rename-c\0", b"/rename-b\0", 0) == 0);
    let hard = word(&stat(b"/hard-a\0"), 8);
    ck!(ren(b"/hard-a\0", b"/hard-b\0") == 0);
    ck!(word(&stat(b"/hard-a\0"), 8) == hard && word(&stat(b"/hard-b\0"), 8) == hard);
    ck!(links(b"/hard-a\0") == 2);
    ck!(ren(b"/meta/rel\0", b"/link-moved\0") == 0);
    let mut out = [0; 16];
    ck!(syscall6(
        78,
        [
            CWD,
            b"/link-moved\0".as_ptr() as usize,
            out.as_mut_ptr() as usize,
            16,
            0,
            0
        ]
    ) == 4);
    ck!(&out[..4] == b"data");
    ck!(ren(b"/rename-b\0", b"/link-moved\0") == 0);
    ck!(ren(b"/link-moved\0", b"/rename-b\0") == 0);
    let f = make(b"/growth-source\0", b"growth");
    close(f);
    let directory_size = word(&stat(b"/full\0"), 48);
    ck!(ren(b"/growth-source\0", b"/full/new-entry-with-a-longer-name\0") == 0);
    ck!(word(&stat(b"/full\0"), 48) > directory_size);
    let f = open(b"/full/new-entry-with-a-longer-name\0", 0);
    read(f, b"growth");
    close(f);
}
fn directories() {
    mkdir(b"/same-source\0");
    mkdir(b"/same-target\0");
    let before = links(b"/\0");
    ck!(ren(b"/same-source\0", b"/same-target\0") == 0);
    ck!(links(b"/\0") == before - 1);
    mkdir(b"/from\0");
    mkdir(b"/to\0");
    mkdir(b"/from/moving\0");
    let file = make(b"/from/moving/data\0", b"inside");
    close(file);
    let before_from = links(b"/from\0");
    let before_to = links(b"/to\0");
    ck!(ren(b"/from/moving\0", b"/to/moved\0") == 0);
    ck!(links(b"/from\0") == before_from - 1 && links(b"/to\0") == before_to + 1);
    ck!(word(&stat(b"/to/moved/..\0"), 8) == word(&stat(b"/to\0"), 8));
    let file = open(b"/to/moved/data\0", 0);
    read(file, b"inside");
    close(file);
    ck!(ren(b"/to\0", b"/to/moved/cycle\0") == -22);
    mkdir(b"/empty-target\0");
    let before = links(b"/\0");
    ck!(ren(b"/to/moved\0", b"/empty-target\0") == 0);
    ck!(links(b"/\0") == before && links(b"/to\0") == before_to);
    mkdir(b"/another-empty\0");
    ck!(ren(b"/another-empty\0", b"/empty-target\0") == -39);
    ck!(ren(b"/rename-b\0", b"/another-empty\0") == -21);
    ck!(ren(b"/another-empty\0", b"/rename-b\0") == -20);
    ck!(ren(b"/rename-b/\0", b"/new\0") == -20);
    let dir = open(b"/empty-target\0", 0x10000);
    ck!(ren(b"/empty-target\0", b"/busy-dir\0") == -16);
    close(dir);
    chdir(b"/empty-target\0");
    ck!(ren(b"/empty-target\0", b"/busy-dir\0") == -16);
    chdir(b"/\0");
    ck!(ren(b"/empty-target\0", b"/final-dir\0") == 0);
    let from = open(b"/from\0", 0x10000);
    let to = open(b"/to\0", 0x10000);
    let file = make(b"/from/relative\0", b"relative");
    close(file);
    ck!(syscall6(
        38,
        [
            from,
            b"relative\0".as_ptr() as usize,
            to,
            b"relative\0".as_ptr() as usize,
            0,
            0
        ]
    ) == 0);
    close(from);
    close(to);
    ck!(ren(b"/meta/dirlink/data\0", b"/via-link\0") == 0);
    ck!(ren(b"/via-link\0", b"/meta/data\0") == 0);
}
fn child_cwd() {
    mkdir(b"/busy-parent\0");
    mkdir(b"/busy-parent/child\0");
    let mut pipe = [0u32; 2];
    ck!(syscall3(59, pipe.as_mut_ptr() as usize, 0, 0) == 0);
    let pid = syscall6(220, [17, 0, 0, 0, 0, 0]);
    ck!(pid >= 0);
    if pid == 0 {
        close(pipe[0] as usize);
        chdir(b"/busy-parent/child\0");
        ck!(syscall3(64, pipe[1] as usize, b"x".as_ptr() as usize, 1) == 1);
        // 等待父进程关闭其读取端，确认期间 cwd 一直存活。
        loop {
            let ret = syscall3(64, pipe[1] as usize, b"x".as_ptr() as usize, 1);
            if ret == -32 {
                break;
            }
            ck!(ret == 1);
            syscall3(124, 0, 0, 0);
        }
        close(pipe[1] as usize);
        sys_exit(0);
    }
    close(pipe[1] as usize);
    let mut byte = [0];
    ck!(syscall3(63, pipe[0] as usize, byte.as_mut_ptr() as usize, 1) == 1);
    ck!(ren(b"/busy-parent\0", b"/child-moved\0") == -16);
    close(pipe[0] as usize);
    let mut status = -1i32;
    ck!(syscall6(
        260,
        [pid as usize, &mut status as *mut i32 as usize, 0, 0, 0, 0]
    ) == pid);
    ck!(status == 0);
    ck!(ren(b"/busy-parent\0", b"/child-moved\0") == 0);
}
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let mut stats = [0; 120];
    ck!(syscall3(43, b"/\0".as_ptr() as usize, stats.as_mut_ptr() as usize, 0) == 0);
    let readonly = word(&stats, 80) & 1 != 0;
    ck!(ren2(b"/meta/data\0", b"/bad\0", 8) == -22);
    ck!(ren2(b"/meta/data\0", b"/bad\0", 2) == -22);
    ck!(ren2(b"/meta/data\0", b"/bad\0", 4) == -22);
    ck!(ren2(b"/meta/data\0", b"/bad\0", 3) == -22);
    ck!(ren(b"\0", b"/bad\0") == -2);
    ck!(ren(b"/\0", b"/bad\0") == -16);
    ck!(syscall6(38, [CWD, 0, CWD, b"/bad\0".as_ptr() as usize, 0, 0]) == -14);
    ck!(syscall6(
        38,
        [
            999,
            b"relative\0".as_ptr() as usize,
            CWD,
            b"/bad\0".as_ptr() as usize,
            0,
            0
        ]
    ) == -9);
    if readonly {
        ck!(ren(b"/meta/data\0", b"/read-only\0") == -30);
        sys_write(1, b"RENAME READONLY\n");
    } else {
        files();
        directories();
        child_cwd();
        ck!(syscall6(
            38,
            [
                999,
                b"/rename-b\0".as_ptr() as usize,
                999,
                b"/absolute\0".as_ptr() as usize,
                0,
                0
            ]
        ) == 0);
    }
    if syscall6(56, [CWD, b"/small-inode\0".as_ptr() as usize, 0, 0, 0, 0]) == -2 {
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
        let fd = make(b"/mnt/a\0", b"fat");
        close(fd);
        ck!(ren(b"/mnt/a\0", b"/mnt/b\0") == -95);
        ck!(ren(b"/meta/data\0", b"/mnt/b\0") == -18);
        ck!(ren(b"/mnt/a\0", b"/fat-to-ext\0") == -18);
        ck!(ren(b"/mnt\0", b"/mount-moved\0") == -16);
        ck!(syscall3(39, b"/mnt\0".as_ptr() as usize, 0, 0) == 0);
    }
    sys_write(
        1,
        b"RENAME PASS: replacement, references, directories, flags and errors\n",
    );
    sys_exit(0);
}
define_user_entry!(ouro_main);
