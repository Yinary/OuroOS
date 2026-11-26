//! 官方盘用户态启动器：盘上无 /init 时由内核内嵌启动。安装测例请求的动态
//! 加载器与库，建立 /tmp 等目录和 /bin/sh、/busybox 入口，再解释官方外层脚本；
//! LTP 组按目录顺序逐例执行并套用逐例时限。全部经通用系统调用完成，不感知用例内容。

#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_mmap, sys_munmap, sys_write, syscall3, syscall6};

// asm-generic 64 位系统调用号（riscv64 / loongarch64 通用 UAPI）
const SYS_OPENAT: usize = 56;
const SYS_FCHMODAT: usize = 53;
const SYS_MKNODAT: usize = 33;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_MKDIRAT: usize = 34;
const SYS_CHDIR: usize = 49;
const SYS_CLONE: usize = 220;
const SYS_EXECVE: usize = 221;
const SYS_WAIT4: usize = 260;
const SYS_GETDENTS64: usize = 61;
const SYS_FSTATAT: usize = 79;
const SYS_NANOSLEEP: usize = 101;
const SYS_CLOCK_GETTIME: usize = 113;
const SYS_KILL: usize = 129;
const SYS_GETPID: usize = 172;
const SYS_SETSID: usize = 157;
const SYS_UNLINKAT: usize = 35;
const SYS_STATFS: usize = 43;

const AT_FDCWD: usize = usize::MAX - 99; // -100
const AT_REMOVEDIR: usize = 0x200;
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_CREAT: usize = 0o100;
const O_TRUNC: usize = 0o1000;
const SIGCHLD: usize = 17;
const SIGKILL: usize = 9;
const WNOHANG: usize = 1;
const CLOCK_MONOTONIC: usize = 1;
const MAP_PRIVATE: usize = 0x02;
const MAP_ANONYMOUS: usize = 0x20;
const PROT_READ_WRITE: usize = 3;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const ENOTDIR: usize = 20;
const ENOTEMPTY: usize = 39;
const SWEEP_MAX_DEPTH: usize = 8;
const SWEEP_MAX_SKIP: usize = 512;
const LTP_SWEEP_MIN_FREE_BYTES: u64 = 268435456;
// LTP 组驱动：目录项缓冲与名字索引缓冲的大小；逐例时限、本组的总预算、
// 超时后等待回收的上限，单位秒。
const LTP_DIR_BYTES: usize = 512 * 1024;
const LTP_INDEX_BYTES: usize = 128 * 1024;
const LTP_TEST_TIMEOUT_SECS: u64 = 2;
const LTP_MUSL_BUDGET_SECS: u64 = 3400;
const LTP_REAP_TIMEOUT_SECS: u64 = 30;

fn sys_openat(path: &[u8], flags: usize, mode: usize) -> isize {
    syscall6(
        SYS_OPENAT,
        [AT_FDCWD, path.as_ptr() as usize, flags, mode, 0, 0],
    )
}

fn sys_openat_at(dirfd: usize, path: &[u8], flags: usize, mode: usize) -> isize {
    syscall6(
        SYS_OPENAT,
        [dirfd, path.as_ptr() as usize, flags, mode, 0, 0],
    )
}

fn sys_read(fd: usize, buf: &mut [u8]) -> isize {
    syscall3(SYS_READ, fd, buf.as_mut_ptr() as usize, buf.len())
}

fn sys_close(fd: usize) -> isize {
    syscall3(SYS_CLOSE, fd, 0, 0)
}

fn sys_mkdir(path: &[u8]) -> isize {
    syscall3(SYS_MKDIRAT, AT_FDCWD, path.as_ptr() as usize, 0o755)
}

fn sys_unlinkat(dirfd: usize, path: &[u8], flags: usize) -> isize {
    syscall3(SYS_UNLINKAT, dirfd, path.as_ptr() as usize, flags)
}

fn sys_chdir(path: &[u8]) -> isize {
    syscall3(SYS_CHDIR, path.as_ptr() as usize, 0, 0)
}

fn sys_getdents64(fd: usize, buf: &mut [u8]) -> isize {
    syscall3(SYS_GETDENTS64, fd, buf.as_mut_ptr() as usize, buf.len())
}

fn sys_fstatat(dirfd: usize, path: &[u8], stat: &mut [u8; 128]) -> isize {
    syscall6(
        SYS_FSTATAT,
        [
            dirfd,
            path.as_ptr() as usize,
            stat.as_mut_ptr() as usize,
            0,
            0,
            0,
        ],
    )
}

fn sys_nanosleep_ms(ms: u64) -> isize {
    let ts = [(ms / 1000) as i64, ((ms % 1000) * 1_000_000) as i64];
    syscall3(SYS_NANOSLEEP, ts.as_ptr() as usize, 0, 0)
}

fn sys_kill(pid: isize, sig: usize) -> isize {
    syscall3(SYS_KILL, pid as usize, sig, 0)
}

fn sys_getpid() -> isize {
    syscall6(SYS_GETPID, [0; 6])
}

/// 单调时钟的整秒数，读取失败记 0。
fn now_secs() -> u64 {
    let mut ts = [0i64; 2];
    let _ = syscall3(
        SYS_CLOCK_GETTIME,
        CLOCK_MONOTONIC,
        ts.as_mut_ptr() as usize,
        0,
    );
    if ts[0] > 0 {
        ts[0] as u64
    } else {
        0
    }
}

fn tmp_free_bytes() -> u64 {
    let mut buf = [0u8; 120];
    let r = syscall3(
        SYS_STATFS,
        b"/tmp\0".as_ptr() as usize,
        buf.as_mut_ptr() as usize,
        0,
    );
    if r < 0 {
        return u64::MAX;
    }
    let block = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    let free = u64::from_le_bytes([
        buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
    ]);
    match block.checked_mul(free) {
        Some(v) => v,
        None => u64::MAX,
    }
}

/// 打印错误后 exit(1)
fn fail(msg: &[u8]) -> ! {
    sys_write(2, msg);
    sys_exit(1)
}

fn note(msg: &[u8]) {
    sys_write(1, msg);
}

/// 把字节缓冲截到首个 NUL，返回长度
fn cstr_len(buf: &[u8]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(buf.len())
}

/// 把 `bytes` 追加到 `out` 的 `*n` 处，写满即止。
fn push_bytes(out: &mut [u8], n: &mut usize, bytes: &[u8]) {
    if *n >= out.len() {
        return;
    }
    let take = (out.len() - *n).min(bytes.len());
    out[*n..*n + take].copy_from_slice(&bytes[..take]);
    *n += take;
}

/// 追加十进制无符号数，写满即止。
fn push_u64(out: &mut [u8], n: &mut usize, mut v: u64) {
    let mut digits = [0u8; 20];
    let mut d = 0usize;
    if v == 0 {
        push_bytes(out, n, b"0");
        return;
    }
    while v > 0 {
        digits[d] = b'0' + (v % 10) as u8;
        v /= 10;
        d += 1;
    }
    while d > 0 {
        d -= 1;
        push_bytes(out, n, &digits[d..d + 1]);
    }
}

/// 解析十进制无符号数，含非数字或溢出时返回 None。
fn parse_u64(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut v = 0usize;
    for &b in bytes {
        if b < b'0' || b > b'9' {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(v)
}

/// 在 `out`（NUL 结尾）后追加一段路径分量与 NUL，返回失败与否
fn push_path(out: &mut [u8; 320], out_len: usize, part: &[u8]) -> bool {
    let end = out_len
        .checked_add(part.len())
        .map_or(false, |e| e + 1 < out.len());
    if !end {
        return false;
    }
    out[out_len..out_len + part.len()].copy_from_slice(part);
    out[out_len + part.len()] = 0;
    true
}

/// 复制文件（4 KiB 栈缓冲循环）。成功返回 true。
fn cp(src: &[u8], dst: &[u8]) -> bool {
    let sfd = sys_openat(src, O_RDONLY, 0);
    if sfd < 0 {
        return false;
    }
    let dfd = sys_openat(dst, O_WRONLY | O_CREAT | O_TRUNC, 0o755);
    if dfd < 0 {
        return false;
    }
    let mut buf = [0u8; 4096];
    loop {
        let n = sys_read(sfd as usize, &mut buf);
        if n == 0 {
            break; // EOF
        }
        if n < 0 {
            let _ = sys_write(2, b"[official-init] cp: read error\n");
            sys_close(sfd as usize);
            sys_close(dfd as usize);
            return false;
        }
        let mut off = 0usize;
        while off < n as usize {
            let w = syscall3(
                64,
                dfd as usize,
                buf[off..].as_ptr() as usize,
                n as usize - off,
            );
            if w <= 0 {
                sys_close(sfd as usize);
                sys_close(dfd as usize);
                return false;
            }
            off += w as usize;
        }
    }
    sys_close(sfd as usize);
    sys_close(dfd as usize);
    true
}

/// 授权安装清单（构建期常量，非运行时探测）：(目标绝对路径, 盘上来源)。
/// 目标是测例请求的动态加载器及其默认搜索路径下的库，来源是对应 libc 目录内的文件。
static INSTALL_LIST: &[(&[u8], &[u8])] = &[
    // riscv64 glibc 的加载器与库
    (
        b"/lib/ld-linux-riscv64-lp64d.so.1\0",
        b"/glibc/lib/ld-linux-riscv64-lp64d.so.1\0",
    ),
    (b"/lib/libc.so.6\0", b"/glibc/lib/libc.so.6\0"),
    (b"/lib/libm.so.6\0", b"/glibc/lib/libm.so.6\0"),
    // loongarch64 glibc 的加载器与库，库装在 /usr/lib64
    (
        b"/lib64/ld-linux-loongarch-lp64d.so.1\0",
        b"/glibc/lib/ld-linux-loongarch-lp64d.so.1\0",
    ),
    (b"/usr/lib64/libc.so.6\0", b"/glibc/lib/libc.so.6\0"),
    (b"/usr/lib64/libm.so.6\0", b"/glibc/lib/libm.so.6\0"),
    // loongarch64 musl 的加载器
    (
        b"/lib64/ld-musl-loongarch-lp64d.so.1\0",
        b"/musl/lib/libc.so\0",
    ),
    // riscv64 musl 的两个加载器路径
    (b"/lib/ld-musl-riscv64-sf.so.1\0", b"/musl/lib/libc.so\0"),
    (b"/lib/ld-musl-riscv64.so.1\0", b"/musl/lib/libc.so\0"),
    // musl 加载器默认搜索路径下的 libc.so
    (b"/lib/libc.so\0", b"/musl/lib/libc.so\0"),
    // shell 与 applet 入口（busybox 按 argv[0] 分派）
    (b"/bin/sh\0", b"/musl/busybox\0"),
    (b"/busybox\0", b"/musl/busybox\0"),
    (b"/bin/busybox\0", b"/musl/busybox\0"),
    (b"/bin/ls\0", b"/musl/busybox\0"),
    (b"/bin/sleep\0", b"/musl/busybox\0"),
    (b"/bin/basename\0", b"/musl/busybox\0"),
    (b"/bin/true\0", b"/musl/busybox\0"),
];

/// 系统账户数据库：root 与 nobody 两个账户，供按用户名查 UID/GID 的程序使用。
static ETC_PASSWD: &[u8] = b"root:x:0:0:root:/:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n";
/// 系统组数据库：root 与 nobody 两个组，与账户数据库中的 GID 对应。
static ETC_GROUP: &[u8] = b"root:x:0:\nnobody:x:65534:\n";

/// 逐级创建 `dst` 的父目录；已存在不算失败。
fn mkdir_p(dst: &[u8]) {
    let dlen = cstr_len(dst);
    for i in 0..dlen {
        if dst[i] != b'/' || i == 0 {
            continue;
        }
        let mut dir = [0u8; 320];
        dir[..i].copy_from_slice(&dst[..i]);
        dir[i] = 0;
        let r = sys_mkdir(&dir[..i + 1]);
        if r < 0 && r != -17 {
            return;
        }
    }
}

/// 以 `content` 新建或覆盖 `path`，权限 0644。成功返回 true。
fn write_file(path: &[u8], content: &[u8]) -> bool {
    let fd = sys_openat(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644);
    if fd < 0 {
        return false;
    }
    let mut off = 0usize;
    while off < content.len() {
        let w = sys_write(fd as usize, &content[off..]);
        if w <= 0 {
            sys_close(fd as usize);
            return false;
        }
        off += w as usize;
    }
    sys_close(fd as usize);
    true
}

fn prepare_layout() {
    mkdir_p(b"/tmp/\0");
    mkdir_p(b"/var/tmp/\0");
    mkdir_p(b"/dev/shm/\0");
    mkdir_p(b"/etc/\0");
    for (path, content) in [
        (&b"/etc/passwd\0"[..], ETC_PASSWD),
        (&b"/etc/group\0"[..], ETC_GROUP),
    ] {
        if write_file(path, content) {
            note(b"[official-init] wrote ");
            sys_write(1, path);
            note(b"\n");
        } else {
            note(b"[official-init] write FAILED for ");
            sys_write(1, path);
            note(b"\n");
        }
    }
    note(b"[official-init] install list begin\n");
    for (dst, src) in INSTALL_LIST {
        mkdir_p(dst);
        if cp(src, dst) {
            note(b"[official-init] installed ");
            sys_write(1, dst);
            note(b"\n");
        } else {
            note(b"[official-init] install FAILED for ");
            sys_write(1, dst);
            note(b"\n");
        }
    }
    note(b"[official-init] install list end\n");
    for (path, mode, dev) in NODE_ALLOWLIST {
        let r = syscall6(
            SYS_MKNODAT,
            [AT_FDCWD, path.as_ptr() as usize, *mode, *dev, 0, 0],
        );
        if r == 0 {
            note(b"[official-init] node created: ");
            sys_write(1, path);
            note(b"\n");
        } else if r != -17 {
            note(b"[official-init] mknod failed for ");
            sys_write(1, path);
            note(b"\n");
        }
    }
}

/// 在 `libc_dir` 中执行 `busybox sh -c <cmd>` 并等待完成。
#[allow(dead_code)]
fn run_script(libc_dir: &[u8], dir_len: usize, cmd: &[u8]) {
    if syscall3(SYS_CHDIR, libc_dir.as_ptr() as usize, 0, 0) < 0 {
        fail(b"[official-init] chdir libc dir failed\n");
    }
    let mut busybox = [0u8; 320];
    let l = dir_len;
    busybox[..l].copy_from_slice(&libc_dir[..l]);
    if !push_path(&mut busybox, l, b"/busybox\0") {
        fail(b"[official-init] busybox path too long\n");
    }
    let argv0 = b"busybox\0";
    let argv1 = b"sh\0";
    let argv2 = b"-c\0";
    let env = [b"PATH=/bin:/musl:/glibc\0".as_ptr() as usize, 0];
    let mut status = 0usize;
    let pid = syscall3(SYS_CLONE, SIGCHLD, 0, 0);
    if pid < 0 {
        fail(b"[official-init] clone failed\n");
    }
    if pid == 0 {
        let argv = [
            argv0.as_ptr() as usize,
            argv1.as_ptr() as usize,
            argv2.as_ptr() as usize,
            cmd.as_ptr() as usize,
            0,
        ];
        let _ = syscall6(
            SYS_EXECVE,
            [
                busybox.as_ptr() as usize,
                argv.as_ptr() as usize,
                env.as_ptr() as usize,
                0,
                0,
                0,
            ],
        );
        // 127 = shell 约定的"命令未找到"
        sys_write(2, b"[official-init] execve busybox failed\n");
        sys_exit(127)
    }
    let wr = syscall6(
        SYS_WAIT4,
        [pid as usize, &mut status as *mut usize as usize, 0, 0, 0, 0],
    );
    if wr < 0 {
        note(b"[official-init] wait4 failed\n");
    } else if status != 0 {
        let mut line = [0u8; 64];
        let msg = b"[official-init] group script exited abnormally: code=\0";
        let mut n = msg.len() - 1;
        line[..n].copy_from_slice(&msg[..n]);
        let put = |v: usize, buf: &mut [u8], n: &mut usize| {
            let mut digits = [0u8; 4];
            let mut d = 0;
            let mut x = v;
            if x == 0 {
                digits[0] = b'0';
                d = 1;
            }
            while x > 0 && d < 4 {
                digits[d] = b'0' + (x % 10) as u8;
                x /= 10;
                d += 1;
            }
            while d > 0 {
                d -= 1;
                buf[*n] = digits[d];
                *n += 1;
            }
        };
        put((status >> 8) & 0xff, &mut line, &mut n);
        let tail = b" sig=\0";
        let tl = tail.len() - 1;
        line[n..n + tl].copy_from_slice(&tail[..tl]);
        n += tl;
        put(status & 0xff, &mut line, &mut n);
        line[n] = b'\n';
        n += 1;
        let _ = sys_write(2, &line[..n]);
    }
}

/// 打印 LTP 组的开始或结束标记，`kind` 为 START 或 END。
fn write_group_mark(kind: &[u8], tag: &[u8]) {
    let mut line = [0u8; 96];
    let mut n = 0usize;
    push_bytes(&mut line, &mut n, b"#### OS COMP TEST GROUP ");
    push_bytes(&mut line, &mut n, kind);
    push_bytes(&mut line, &mut n, b" ltp-");
    push_bytes(&mut line, &mut n, tag);
    push_bytes(&mut line, &mut n, b" ####\n");
    let _ = sys_write(1, &line[..n]);
}

/// 返回本地评测覆盖的逐例时限（未设置时沿用默认 2 秒）。
fn ltp_case_timeout_secs() -> u64 {
    match option_env!("OUROOS_LTP_TIMEOUT") {
        Some(raw) => parse_u64(raw.as_bytes())
            .filter(|&v| v > 0)
            .map_or(LTP_TEST_TIMEOUT_SECS, |v| v as u64),
        None => LTP_TEST_TIMEOUT_SECS,
    }
}

/// 本地拆例过滤：未设置 `OUROOS_LTP_FILTER` 时全部放行；设置时按逗号分隔的前缀匹配用例名。
fn ltp_name_matches_filter(name: &[u8]) -> bool {
    let Some(filter) = option_env!("OUROOS_LTP_FILTER") else {
        return true;
    };
    let bytes = filter.as_bytes();
    if bytes.is_empty() {
        return true;
    }
    let mut start = 0usize;
    while start <= bytes.len() {
        let mut end = start;
        while end < bytes.len() && bytes[end] != b',' {
            end += 1;
        }
        let pat = &bytes[start..end];
        if !pat.is_empty() && name.len() >= pat.len() && &name[..pat.len()] == pat {
            return true;
        }
        if end == bytes.len() {
            break;
        }
        start = end + 1;
    }
    false
}

/// 驱动一个 libc 目录下的 LTP 组：读出 ltp/testcases/bin 的普通文件并按名字排序，
/// 逐例在独立会话里执行，超过逐例时限就杀掉该会话的全部进程，按官方组脚本的格式
/// 打印 RUN 与 FAIL 行，用例超时或 /tmp 空间不足时清空 /tmp；
/// 到 `group_deadline` 之后不再启动新用例。
fn run_ltp(libc_dir: &[u8], libc_tag: &[u8], group_deadline: u64) {
    let case_timeout = ltp_case_timeout_secs();
    let tag = &libc_tag[..cstr_len(libc_tag)];
    if sys_chdir(libc_dir) < 0 {
        note(b"[official-init] ltp-");
        sys_write(1, tag);
        note(b" chdir libc dir failed\n");
        return;
    }
    let dfd = sys_openat(b"ltp/testcases/bin\0", O_RDONLY, 0);
    if dfd < 0 {
        write_group_mark(b"START", tag);
        note(b"[official-init] ltp-");
        sys_write(1, tag);
        note(b" open ltp/testcases/bin failed\n");
        write_group_mark(b"END", tag);
        return;
    }
    let prot = PROT_READ_WRITE;
    let flags = MAP_PRIVATE | MAP_ANONYMOUS;
    let dir_ptr = sys_mmap(0, LTP_DIR_BYTES, prot, flags, usize::MAX, 0);
    let index_ptr = sys_mmap(0, LTP_INDEX_BYTES, prot, flags, usize::MAX, 0);
    if dir_ptr < 0 || index_ptr < 0 {
        write_group_mark(b"START", tag);
        note(b"[official-init] ltp-");
        sys_write(1, tag);
        note(b" mmap failed\n");
        write_group_mark(b"END", tag);
        let _ = sys_close(dfd as usize);
        return;
    }
    // SAFETY: 地址来自刚成功的匿名 mmap，非空且页对齐，长度与映射一致；
    // 映射刚建立，还没有其他引用。
    let dirbuf =
        unsafe { core::slice::from_raw_parts_mut(dir_ptr as usize as *mut u8, LTP_DIR_BYTES) };
    // SAFETY: 前提同上；长度是 8 字节的整数倍，页对齐满足 (u32, u32) 的对齐。
    let index = unsafe {
        core::slice::from_raw_parts_mut(index_ptr as usize as *mut (u32, u32), LTP_INDEX_BYTES / 8)
    };
    let mut used = 0usize;
    loop {
        if used >= dirbuf.len() {
            break;
        }
        let n = sys_getdents64(dfd as usize, &mut dirbuf[used..]);
        if n <= 0 {
            break;
        }
        used = used.saturating_add(n as usize).min(dirbuf.len());
    }
    let mut count = 0usize;
    let mut off = 0usize;
    let mut stat = [0u8; 128];
    while off + 19 <= used {
        let reclen = u16::from_le_bytes([dirbuf[off + 16], dirbuf[off + 17]]) as usize;
        if reclen == 0 || off + reclen > used {
            break;
        }
        let name_at = off + 19;
        let rec_end = off + reclen;
        let mut name_len = 0usize;
        while name_at + name_len < rec_end && dirbuf[name_at + name_len] != 0 {
            name_len += 1;
        }
        let term = name_at + name_len;
        let dot = (name_len == 1 && dirbuf[name_at] == b'.')
            || (name_len == 2 && dirbuf[name_at] == b'.' && dirbuf[name_at + 1] == b'.');
        if term < rec_end && !dot && count < index.len() {
            if sys_fstatat(dfd as usize, &dirbuf[name_at..=term], &mut stat) == 0 {
                let mode = u32::from_le_bytes([stat[16], stat[17], stat[18], stat[19]]);
                if mode & S_IFMT == S_IFREG {
                    index[count] = (name_at as u32, name_len as u32);
                    count += 1;
                }
            }
        }
        off += reclen;
    }
    index[..count].sort_unstable_by(|a, b| {
        let an = &dirbuf[a.0 as usize..a.0 as usize + a.1 as usize];
        let bn = &dirbuf[b.0 as usize..b.0 as usize + b.1 as usize];
        an.cmp(bn)
    });
    write_group_mark(b"START", tag);
    let mut line = [0u8; 1024];
    let mut path = [0u8; 320];
    let mut env = [0u8; 128];
    let mut done = 0usize;
    while done < count {
        if now_secs() >= group_deadline {
            let mut msg = [0u8; 128];
            let mut mn = 0usize;
            push_bytes(&mut msg, &mut mn, b"[official-init] ltp-");
            push_bytes(&mut msg, &mut mn, tag);
            push_bytes(&mut msg, &mut mn, b" time budget reached, ");
            push_u64(&mut msg, &mut mn, done as u64);
            push_bytes(&mut msg, &mut mn, b" cases run\n");
            let _ = sys_write(1, &msg[..mn]);
            break;
        }
        let name_at = index[done].0 as usize;
        let name_len = index[done].1 as usize;
        done += 1;
        let name = &dirbuf[name_at..name_at + name_len];
        if !ltp_name_matches_filter(name) {
            continue;
        }
        let mut plen = 0usize;
        push_bytes(&mut path, &mut plen, b"ltp/testcases/bin/");
        push_bytes(&mut path, &mut plen, name);
        let mut elen = 0usize;
        push_bytes(&mut env, &mut elen, b"PATH=/bin:/musl:/glibc:");
        push_bytes(&mut env, &mut elen, &libc_dir[..cstr_len(libc_dir)]);
        push_bytes(&mut env, &mut elen, b"/ltp/testcases/bin");
        if plen + 1 > path.len() || elen + 1 > env.len() {
            continue;
        }
        path[plen] = 0;
        env[elen] = 0;
        let mut n = 0usize;
        push_bytes(&mut line, &mut n, b"RUN LTP CASE ");
        push_bytes(&mut line, &mut n, name);
        push_bytes(&mut line, &mut n, b"\n");
        let _ = sys_write(1, &line[..n]);
        let argv = [path.as_ptr() as usize, 0usize];
        let envp = [env.as_ptr() as usize, 0usize];
        let started = now_secs();
        let pid = syscall3(SYS_CLONE, SIGCHLD, 0, 0);
        if pid == 0 {
            let _ = syscall3(SYS_SETSID, 0, 0, 0);
            let _ = syscall6(
                SYS_EXECVE,
                [
                    path.as_ptr() as usize,
                    argv.as_ptr() as usize,
                    envp.as_ptr() as usize,
                    0,
                    0,
                    0,
                ],
            );
            sys_exit(127)
        }
        let mut timed_out = false;
        let code;
        if pid < 0 {
            code = 127usize;
        } else {
            let mut status = 0usize;
            let mut timeout_killed = 0usize;
            loop {
                let wr = syscall6(
                    SYS_WAIT4,
                    [
                        pid as usize,
                        &mut status as *mut usize as usize,
                        WNOHANG,
                        0,
                        0,
                        0,
                    ],
                );
                if wr == pid {
                    break;
                }
                if wr != 0 {
                    break;
                }
                if now_secs().saturating_sub(started) >= case_timeout {
                    timeout_killed = kill_session(pid as usize);
                    let _ = sys_kill(-pid, SIGKILL);
                    timed_out = true;
                    let reap_start = now_secs();
                    loop {
                        let w = syscall6(
                            SYS_WAIT4,
                            [
                                pid as usize,
                                &mut status as *mut usize as usize,
                                WNOHANG,
                                0,
                                0,
                                0,
                            ],
                        );
                        if w == pid || w < 0 {
                            break;
                        }
                        if now_secs().saturating_sub(reap_start) >= LTP_REAP_TIMEOUT_SECS {
                            break;
                        }
                        let _ = sys_nanosleep_ms(20);
                    }
                    break;
                }
                let _ = sys_nanosleep_ms(20);
            }
            let left = kill_session(pid as usize);
            code = if timed_out {
                137usize
            } else {
                let sig = status & 0x7f;
                if sig == 0 {
                    (status >> 8) & 0xff
                } else if sig != 0x7f {
                    128 + sig
                } else {
                    128
                }
            };
            if timed_out {
                let mut n = 0usize;
                push_bytes(&mut line, &mut n, b"[official-init] ltp-");
                push_bytes(&mut line, &mut n, tag);
                push_bytes(&mut line, &mut n, b" ");
                push_bytes(&mut line, &mut n, name);
                push_bytes(&mut line, &mut n, b" timed out, killed ");
                push_u64(&mut line, &mut n, timeout_killed as u64);
                push_bytes(&mut line, &mut n, b" processes in its session\n");
                let _ = sys_write(1, &line[..n]);
            } else if left > 0 {
                let mut n = 0usize;
                push_bytes(&mut line, &mut n, b"[official-init] ltp-");
                push_bytes(&mut line, &mut n, tag);
                push_bytes(&mut line, &mut n, b" ");
                push_bytes(&mut line, &mut n, name);
                push_bytes(&mut line, &mut n, b" left ");
                push_u64(&mut line, &mut n, left as u64);
                push_bytes(&mut line, &mut n, b" processes behind, killed\n");
                let _ = sys_write(1, &line[..n]);
            }
        }
        let mut n = 0usize;
        push_bytes(&mut line, &mut n, b"FAIL LTP CASE ");
        push_bytes(&mut line, &mut n, name);
        push_bytes(&mut line, &mut n, b" : ");
        push_u64(&mut line, &mut n, code as u64);
        push_bytes(&mut line, &mut n, b"\n");
        let _ = sys_write(1, &line[..n]);
        let free = tmp_free_bytes();
        if timed_out || free < LTP_SWEEP_MIN_FREE_BYTES {
            let mut budget = 20000usize;
            let swept = sweep_path(b"/tmp\0", 0, &mut budget);
            if swept > 0 {
                let mut n = 0usize;
                push_bytes(&mut line, &mut n, b"[official-init] ltp-");
                push_bytes(&mut line, &mut n, tag);
                push_bytes(&mut line, &mut n, b" removed ");
                push_u64(&mut line, &mut n, swept as u64);
                push_bytes(&mut line, &mut n, b" leftover entries under /tmp\n");
                let _ = sys_write(1, &line[..n]);
            }
            if budget == 0 {
                let mut n = 0usize;
                push_bytes(&mut line, &mut n, b"[official-init] ltp-");
                push_bytes(&mut line, &mut n, tag);
                push_bytes(&mut line, &mut n, b" tmp sweep budget exhausted\n");
                let _ = sys_write(1, &line[..n]);
            }
        }
    }
    // 用例自建会话里的进程不在按会话清理的范围内，组结束后一并结束，
    // 否则系统等不到全部进程退出。
    let mut n = 0usize;
    if list_processes(&mut line, &mut n) > 0 {
        let mut msg = [0u8; 96];
        let mut mn = 0usize;
        push_bytes(&mut msg, &mut mn, b"[official-init] ltp-");
        push_bytes(&mut msg, &mut mn, tag);
        push_bytes(&mut msg, &mut mn, b" processes outside test sessions:");
        let _ = sys_write(1, &msg[..mn]);
        let _ = sys_write(1, &line[..n]);
        let _ = sys_write(1, b"\n");
        let _ = sys_kill(-1, SIGKILL);
        let reap_start = now_secs();
        while sys_kill(-1, 0) == 0 && now_secs().saturating_sub(reap_start) < LTP_REAP_TIMEOUT_SECS
        {
            let _ = sys_nanosleep_ms(100);
        }
        let mut n = 0usize;
        if list_processes(&mut line, &mut n) > 0 {
            let mut msg = [0u8; 96];
            let mut mn = 0usize;
            push_bytes(&mut msg, &mut mn, b"[official-init] ltp-");
            push_bytes(&mut msg, &mut mn, tag);
            push_bytes(&mut msg, &mut mn, b" processes still alive after SIGKILL:");
            let _ = sys_write(1, &msg[..mn]);
            let _ = sys_write(1, &line[..n]);
            let _ = sys_write(1, b"\n");
        }
    }
    write_group_mark(b"END", tag);
    let _ = sys_close(dfd as usize);
    let _ = sys_munmap(dir_ptr as usize, LTP_DIR_BYTES);
    let _ = sys_munmap(index_ptr as usize, LTP_INDEX_BYTES);
}

/// 把 /proc 里除 init 与自身以外的进程按“pid(名字)”追加到 `out`，返回数量；
/// 名字取自各进程 stat 的括号内。
fn list_processes(out: &mut [u8], n: &mut usize) -> usize {
    let pfd = sys_openat(b"/proc\0", O_RDONLY, 0);
    if pfd < 0 {
        return 0;
    }
    let self_pid = sys_getpid();
    let mut dirbuf = [0u8; 4096];
    let mut count = 0usize;
    loop {
        let got = sys_getdents64(pfd as usize, &mut dirbuf);
        if got <= 0 {
            break;
        }
        let used = (got as usize).min(dirbuf.len());
        let mut off = 0usize;
        while off + 19 <= used {
            let reclen = u16::from_le_bytes([dirbuf[off + 16], dirbuf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > used {
                break;
            }
            let name_at = off + 19;
            let rec_end = off + reclen;
            off += reclen;
            let mut name_len = 0usize;
            while name_at + name_len < rec_end && dirbuf[name_at + name_len] != 0 {
                name_len += 1;
            }
            let Some(pid) = parse_u64(&dirbuf[name_at..name_at + name_len]) else {
                continue;
            };
            if pid <= 1 || pid as isize == self_pid {
                continue;
            }
            let mut path = [0u8; 64];
            let mut plen = 0usize;
            push_bytes(&mut path, &mut plen, &dirbuf[name_at..name_at + name_len]);
            push_bytes(&mut path, &mut plen, b"/stat");
            if plen + 1 > path.len() {
                continue;
            }
            path[plen] = 0;
            let sfd = sys_openat_at(pfd as usize, &path[..plen + 1], O_RDONLY, 0);
            if sfd < 0 {
                continue;
            }
            let mut stat = [0u8; 512];
            let mut total = 0usize;
            loop {
                if total >= stat.len() {
                    break;
                }
                let r = sys_read(sfd as usize, &mut stat[total..]);
                if r <= 0 {
                    break;
                }
                total = (total + r as usize).min(stat.len());
            }
            let _ = sys_close(sfd as usize);
            let mut open_at = total;
            let mut close_at = total;
            for i in 0..total {
                if stat[i] == b'(' && open_at == total {
                    open_at = i;
                }
                if stat[i] == b')' {
                    close_at = i;
                }
            }
            if open_at == total || close_at <= open_at + 1 {
                continue;
            }
            count += 1;
            push_bytes(out, n, b" ");
            push_u64(out, n, pid as u64);
            push_bytes(out, n, b"(");
            push_bytes(out, n, &stat[open_at + 1..close_at]);
            push_bytes(out, n, b")");
        }
    }
    let _ = sys_close(pfd as usize);
    count
}

/// 对会话号为 `sid` 的每个进程发 SIGKILL，返回发出的数量；
/// pid 取自 /proc 的目录项名，会话号取自各进程的 stat。
fn kill_session(sid: usize) -> usize {
    let pfd = sys_openat(b"/proc\0", O_RDONLY, 0);
    if pfd < 0 {
        return 0;
    }
    let blank = |b: u8| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r';
    let mut dirbuf = [0u8; 4096];
    let mut killed = 0usize;
    loop {
        let n = sys_getdents64(pfd as usize, &mut dirbuf);
        if n <= 0 {
            break;
        }
        let used = (n as usize).min(dirbuf.len());
        let mut off = 0usize;
        while off + 19 <= used {
            let reclen = u16::from_le_bytes([dirbuf[off + 16], dirbuf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > used {
                break;
            }
            let name_at = off + 19;
            let rec_end = off + reclen;
            off += reclen;
            let mut name_len = 0usize;
            while name_at + name_len < rec_end && dirbuf[name_at + name_len] != 0 {
                name_len += 1;
            }
            if name_len == 0 || name_at + name_len >= rec_end {
                continue;
            }
            let name = &dirbuf[name_at..name_at + name_len];
            let pid = match parse_u64(name) {
                Some(v) => v,
                None => continue,
            };
            let mut path = [0u8; 64];
            let mut plen = 0usize;
            push_bytes(&mut path, &mut plen, name);
            push_bytes(&mut path, &mut plen, b"/stat");
            if plen + 1 > path.len() {
                continue;
            }
            path[plen] = 0;
            let sfd = sys_openat_at(pfd as usize, &path[..plen + 1], O_RDONLY, 0);
            if sfd < 0 {
                continue;
            }
            let mut stat = [0u8; 512];
            let mut total = 0usize;
            loop {
                if total >= stat.len() {
                    break;
                }
                let r = sys_read(sfd as usize, &mut stat[total..]);
                if r <= 0 {
                    break;
                }
                total = total.saturating_add(r as usize).min(stat.len());
            }
            let _ = sys_close(sfd as usize);
            let mut close_at = total;
            let mut i = total;
            while i > 0 {
                i -= 1;
                if stat[i] == b')' {
                    close_at = i;
                    break;
                }
            }
            if close_at == total {
                continue;
            }
            let mut at = close_at + 1;
            let mut fields = [(0usize, 0usize); 4];
            let mut got = 0usize;
            while got < 4 {
                while at < total && blank(stat[at]) {
                    at += 1;
                }
                if at >= total {
                    break;
                }
                let start = at;
                while at < total && !blank(stat[at]) {
                    at += 1;
                }
                fields[got] = (start, at - start);
                got += 1;
            }
            if got < 4 {
                continue;
            }
            let (sess_at, sess_len) = fields[3];
            if parse_u64(&stat[sess_at..sess_at + sess_len]) == Some(sid) {
                let _ = sys_kill(pid as isize, SIGKILL);
                killed += 1;
            }
        }
    }
    let _ = sys_close(pfd as usize);
    killed
}

/// 删除目录 `path` 下的全部内容，目录本身保留，返回删除的条目数。
/// 每次删除前重新打开目录，删不掉的条目按跳过计数略过；`depth` 限制递归层数。
fn sweep_path(path: &[u8], depth: usize, budget: &mut usize) -> usize {
    let path_len = cstr_len(path);
    let mut removed = 0usize;
    let mut skip = 0usize;
    while skip < SWEEP_MAX_SKIP {
        let dfd = sys_openat(path, O_RDONLY, 0);
        if dfd < 0 {
            return removed;
        }
        let mut dirbuf = [0u8; 512];
        let mut namebuf = [0u8; 256];
        let mut name_len = 0usize;
        let mut found = false;
        loop {
            let n = sys_getdents64(dfd as usize, &mut dirbuf);
            if n <= 0 {
                break;
            }
            let used = (n as usize).min(dirbuf.len());
            let mut off = 0usize;
            while off + 19 <= used {
                let reclen = u16::from_le_bytes([dirbuf[off + 16], dirbuf[off + 17]]) as usize;
                if reclen == 0 || off + reclen > used {
                    break;
                }
                let name_at = off + 19;
                let rec_end = off + reclen;
                off += reclen;
                let mut len = 0usize;
                while name_at + len < rec_end && dirbuf[name_at + len] != 0 {
                    len += 1;
                }
                if name_at + len >= rec_end || len == 0 || len + 1 > namebuf.len() {
                    continue;
                }
                let dot = (len == 1 && dirbuf[name_at] == b'.')
                    || (len == 2 && dirbuf[name_at] == b'.' && dirbuf[name_at + 1] == b'.');
                if dot {
                    continue;
                }
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                namebuf[..len].copy_from_slice(&dirbuf[name_at..name_at + len]);
                namebuf[len] = 0;
                name_len = len;
                found = true;
                break;
            }
            if found {
                break;
            }
        }
        let _ = sys_close(dfd as usize);
        if !found {
            return removed;
        }
        let mut child = [0u8; 512];
        let mut clen = 0usize;
        push_bytes(&mut child, &mut clen, &path[..path_len]);
        push_bytes(&mut child, &mut clen, b"/");
        push_bytes(&mut child, &mut clen, &namebuf[..name_len]);
        if clen + 1 > child.len() {
            skip += 1;
            continue;
        }
        child[clen] = 0;
        if *budget == 0 {
            return removed;
        }
        *budget -= 1;
        let r = sys_unlinkat(AT_FDCWD, &child[..clen + 1], AT_REMOVEDIR);
        if r == 0 {
            removed += 1;
            continue;
        }
        if r == -(ENOTEMPTY as isize) {
            if depth + 1 < SWEEP_MAX_DEPTH {
                removed += sweep_path(&child[..clen + 1], depth + 1, budget);
            }
            if *budget == 0 {
                return removed;
            }
            *budget -= 1;
            let r2 = sys_unlinkat(AT_FDCWD, &child[..clen + 1], AT_REMOVEDIR);
            if r2 == 0 {
                removed += 1;
                continue;
            }
            skip += 1;
            continue;
        }
        if r == -(ENOTDIR as isize) {
            if *budget == 0 {
                return removed;
            }
            *budget -= 1;
            let r2 = sys_unlinkat(AT_FDCWD, &child[..clen + 1], 0);
            if r2 == 0 {
                removed += 1;
                continue;
            }
            skip += 1;
            continue;
        }
        skip += 1;
    }
    removed
}

/// 授权对运行副本的 run-all.sh 补执行位（盘上发布为 0644，exec 需 x 位）。
const CHMOD_ALLOWLIST: &[&[u8]] = &[b"/musl/basic/run-all.sh\0", b"/glibc/basic/run-all.sh\0"];

/// 评测别名节点：(节点路径, S_IFBLK|0644, 设备号)。设备号按 glibc
/// makedev 编码：major=254（本内核块设备空间），minor=(盘<<4)|分区——
/// 辅助盘恒为总线第二块（盘 1）分区 2（FAT32，见 make_official_disk.py）。
const NODE_ALLOWLIST: &[(&[u8], usize, usize)] =
    &[(b"/dev/vda2\0", 0o060640, (254 << 8) | ((1 << 4) | 2))];

fn grant_exec_bit(path: &[u8]) {
    let r = syscall6(
        SYS_FCHMODAT,
        [AT_FDCWD, path.as_ptr() as usize, 0o755, 0, 0, 0],
    );
    if r < 0 {
        note(b"[official-init] grant-exec failed for ");
        sys_write(1, path);
        note(b"\n");
        return;
    }
    note(b"[official-init] grant-exec ok: ");
    sys_write(1, path);
    note(b"\n");
}

/// 本地拆组运行单个指定组；未识别的组名仅打印提示不中止其余组。
fn run_selected_group(group: &[u8], started: u64) {
    match group {
        b"basic-musl" => run_script(b"/musl\0", 5, b". ./basic_testcode.sh\0"),
        b"basic-glibc" => run_script(b"/glibc\0", 6, b". ./basic_testcode.sh\0"),
        b"busybox-musl" => run_script(b"/musl\0", 5, b". ./busybox_testcode.sh\0"),
        b"busybox-glibc" => run_script(b"/glibc\0", 6, b". ./busybox_testcode.sh\0"),
        b"lua-musl" => run_script(b"/musl\0", 5, b". ./lua_testcode.sh\0"),
        b"lua-glibc" => run_script(b"/glibc\0", 6, b". ./lua_testcode.sh\0"),
        b"libcbench-musl" => run_script(b"/musl\0", 5, b". ./libcbench_testcode.sh\0"),
        b"libcbench-glibc" => run_script(b"/glibc\0", 6, b". ./libcbench_testcode.sh\0"),
        // 发布盘 run-static.sh / run-dynamic.sh 缺少 shebang，显式交给当前库自带 busybox sh 解释。
        b"libctest-musl" => run_script(
            b"/musl\0",
            5,
            b"./busybox echo '#### OS COMP TEST GROUP START libctest-musl ####'; ./busybox sh ./run-static.sh; ./busybox sh ./run-dynamic.sh; ./busybox echo '#### OS COMP TEST GROUP END libctest-musl ####'\0",
        ),
        b"libctest-glibc" => run_script(
            b"/glibc\0",
            6,
            b"./busybox echo '#### OS COMP TEST GROUP START libctest-glibc ####'; ./busybox sh ./run-static.sh; ./busybox sh ./run-dynamic.sh; ./busybox echo '#### OS COMP TEST GROUP END libctest-glibc ####'\0",
        ),
        b"lmbench-musl" => {
            mkdir_p(b"/code/lmbench_src/bin/build/\0");
            let _ = cp(b"/musl/busybox\0", b"/bin/cp\0");
            let _ = cp(
                b"/musl/lmbench_all\0",
                b"/code/lmbench_src/bin/build/lmbench_all\0",
            );
            run_script(b"/musl\0", 5, b"./busybox sh ./lmbench_testcode.sh\0");
        }
        b"lmbench-glibc" => {
            mkdir_p(b"/code/lmbench_src/bin/build/\0");
            let _ = cp(b"/musl/busybox\0", b"/bin/cp\0");
            let _ = cp(
                b"/glibc/lmbench_all\0",
                b"/code/lmbench_src/bin/build/lmbench_all\0",
            );
            run_script(b"/glibc\0", 6, b"./busybox sh ./lmbench_testcode.sh\0");
        }
        b"iozone-musl" => run_script(b"/musl\0", 5, b"./busybox sh ./iozone_testcode.sh\0"),
        b"iozone-glibc" => run_script(b"/glibc\0", 6, b"./busybox sh ./iozone_testcode.sh\0"),
        b"iperf-musl" => run_script(b"/musl\0", 5, b"./busybox sh ./iperf_testcode.sh\0"),
        b"iperf-glibc" => run_script(b"/glibc\0", 6, b"./busybox sh ./iperf_testcode.sh\0"),
        b"netperf-musl" => run_script(b"/musl\0", 5, b"./busybox sh ./netperf_testcode.sh\0"),
        b"netperf-glibc" => run_script(b"/glibc\0", 6, b"./busybox sh ./netperf_testcode.sh\0"),
        b"cyclictest-musl" => run_script(b"/musl\0", 5, b"./busybox sh ./cyclictest_testcode.sh\0"),
        b"cyclictest-glibc" => {
            run_script(b"/glibc\0", 6, b"./busybox sh ./cyclictest_testcode.sh\0")
        }
        b"ltp-musl" => run_ltp(b"/musl\0", b"musl\0", started + LTP_MUSL_BUDGET_SECS),
        b"ltp-glibc" => run_ltp(b"/glibc\0", b"glibc\0", started + LTP_MUSL_BUDGET_SECS),
        _ => {
            note(b"[official-init] unknown group in OUROOS_INIT_GROUPS: ");
            sys_write(1, group);
            note(b"\n");
        }
    }
}

/// 按逗号拆分 `OUROOS_INIT_GROUPS` 并依次运行。
fn run_group_list(spec: &[u8], started: u64) {
    let mut start = 0usize;
    while start <= spec.len() {
        let mut end = start;
        while end < spec.len() && spec[end] != b',' {
            end += 1;
        }
        let mut s = start;
        let mut e = end;
        while s < e && (spec[s] == b' ' || spec[s] == b'\t') {
            s += 1;
        }
        while e > s && (spec[e - 1] == b' ' || spec[e - 1] == b'\t') {
            e -= 1;
        }
        if s < e {
            run_selected_group(&spec[s..e], started);
        }
        if end == spec.len() {
            break;
        }
        start = end + 1;
    }
}

#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let started = now_secs();
    note(b"[official-init] preparing runtime layout\n");
    prepare_layout();
    for path in CHMOD_ALLOWLIST {
        grant_exec_bit(path);
    }
    if let Some(groups) = option_env!("OUROOS_INIT_GROUPS") {
        note(b"[official-init] local split mode: ");
        sys_write(1, groups.as_bytes());
        note(b"\n");
        run_group_list(groups.as_bytes(), started);
        note(b"[official-init] all groups finished\n");
        sys_exit(0)
    }
    // 测例选择：取消注释即启用。第 3 参是 sh -c 命令串（组脚本用 `. ./`）
    run_script(b"/musl\0", 5, b". ./basic_testcode.sh\0");
    run_script(b"/musl\0", 5, b". ./busybox_testcode.sh\0");
    run_script(b"/glibc\0", 6, b". ./basic_testcode.sh\0");
    run_script(b"/glibc\0", 6, b". ./busybox_testcode.sh\0");
    run_script(b"/musl\0", 5, b". ./lua_testcode.sh\0");
    run_script(b"/glibc\0", 6, b". ./lua_testcode.sh\0");
    run_script(b"/musl\0", 5, b". ./libcbench_testcode.sh\0");
    run_script(b"/glibc\0", 6, b". ./libcbench_testcode.sh\0");
    // 只在 loongarch64 上评测 LTP，另一个架构立即到点、不启动任何用例。
    // 截止时刻从启动器开始时算起，前面各组用掉的时间计入 LTP 的预算。
    let budget: u64 = if cfg!(target_arch = "loongarch64") {
        LTP_MUSL_BUDGET_SECS
    } else {
        0
    };
    run_ltp(b"/musl\0", b"musl\0", started + budget);
    // glibc 组：实测当前零分，保留调用方式供后续启用。
    // let t1 = now_secs();
    // run_ltp(b"/glibc\0", b"glibc\0", t1 + 550);
    //
    // 其余组（依赖尚未实现的能力，按需启用；ltp/unixbench/lmbench 耗时分钟级）：
    // run_script(b"/musl\0", 5, b"./cyclictest_testcode.sh\0");
    // run_script(b"/musl\0", 5, b"./iozone_testcode.sh\0");
    // run_script(b"/musl\0", 5, b"./iperf_testcode.sh\0");
    // run_script(b"/musl\0", 5, b"./libctest_testcode.sh\0");
    // run_script(b"/musl\0", 5, b"./lmbench_testcode.sh\0");
    // run_script(b"/musl\0", 5, b"./ltp_testcode.sh\0");
    // run_script(b"/musl\0", 5, b"./netperf_testcode.sh\0");
    // run_script(b"/musl\0", 5, b"./unixbench_testcode.sh\0");
    //（glibc 份把第 1 参换为 b"/glibc\0"、长度换 6）
    note(b"[official-init] all groups finished\n");
    sys_exit(0)
}

define_user_entry!(ouro_main);
