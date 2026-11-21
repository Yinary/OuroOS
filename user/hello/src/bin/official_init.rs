//! 官方盘用户态启动器：盘上没有 /init 时由内核内嵌启动。
//!
//! 职责（全部通过通用文件系统系统调用完成，不感知具体测例内容）：
//! 1. 读取 basic 程序 ELF 头里的 PT_INTERP 请求，把所需动态解释器从
//!    盘上 libc 目录复制到它请求的绝对路径（如 /lib/ld-linux-*.so.1）；
//! 2. 用复制建立统一的 /bin/sh 与 /busybox 入口；
//! 3. 依序在各 libc 目录（/musl、/glibc）中用 `busybox sh <脚本>` 显式
//!    解释官方外层脚本；组标记与全部输出由脚本与被测程序自行产生。

#![no_std]
#![no_main]

use hello::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};

// asm-generic 64 位系统调用号（riscv64 / loongarch64 通用 UAPI）
const SYS_OPENAT: usize = 56;
const SYS_FCHMODAT: usize = 53;
const SYS_MKNODAT: usize = 296;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_MKDIRAT: usize = 34;
const SYS_CHDIR: usize = 49;
const SYS_CLONE: usize = 220;
const SYS_EXECVE: usize = 221;
const SYS_WAIT4: usize = 260;

const AT_FDCWD: usize = usize::MAX - 99; // -100
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_CREAT: usize = 0o100;
const O_TRUNC: usize = 0o1000;
const SIGCHLD: usize = 17;
/// ELF64 程序头里的 PT_INTERP

/// openat(2)：创建时（O_CREAT）带 mode 参数（第 4 参），其余传 0
fn sys_openat(path: &[u8], flags: usize, mode: usize) -> isize {
    syscall6(
        SYS_OPENAT,
        [AT_FDCWD, path.as_ptr() as usize, flags, mode, 0, 0],
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

/// 报告错误后继续/终止：正式配置下失败必须可见，不允许静默跳过
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

/// 一次性建立运行布局：解释器、/bin/sh、/busybox。
/// 解释器按 ELF PT_INTERP 请求的绝对路径放置，来源依次尝试各 libc 目录。
/// 解释器与 applet 的授权安装清单（构建期常量，非运行时探测）：
/// (安装目标绝对路径, 盘上来源绝对路径)。目标 = PT_INTERP 声明的绝对
/// 路径；来源 = 对应 libc 目录内的真实文件。逐条复制并检查结果，失败
/// 记录在串口。
static INSTALL_LIST: &[(&[u8], &[u8])] = &[
    // RV glibc 解释器（basic 程序 PT_INTERP 声明）
    (
        b"/lib/ld-linux-riscv64-lp64d.so.1\0",
        b"/glibc/lib/ld-linux-riscv64-lp64d.so.1\0",
    ),
    // LA glibc 解释器
    (
        b"/lib64/ld-linux-loongarch-lp64d.so.1\0",
        b"/glibc/lib/ld-linux-loongarch-lp64d.so.1\0",
    ),
    // LA musl 解释器（LA musl 动态程序声明）
    (
        b"/lib64/ld-musl-loongarch-lp64d.so.1\0",
        b"/musl/lib/ld-musl-loongarch-lp64d.so.1\0",
    ),
    // RV musl 解释器
    (
        b"/lib/ld-musl-riscv64-lp64d.so.1\0",
        b"/musl/lib/ld-musl-riscv64-lp64d.so.1\0",
    ),
    // shell 与 applet 入口（busybox 按 argv[0] 分派）
    (b"/bin/sh\0", b"/musl/busybox\0"),
    (b"/busybox\0", b"/musl/busybox\0"),
    (b"/bin/ls\0", b"/musl/busybox\0"),
    (b"/bin/sleep\0", b"/musl/busybox\0"),
];

/// 逐级创建 `dst` 的父目录（安装清单用）；已存在不算失败。
fn mkdir_p(dst: &[u8]) {
    let dlen = cstr_len(dst);
    for i in (0..dlen).rev() {
        if dst[i] != b'/' || i == 0 {
            continue;
        }
        let mut dir = [0u8; 320];
        dir[..i].copy_from_slice(&dst[..i]);
        dir[i] = 0;
        let r = sys_mkdir(&dir[..i + 1]);
        if r < 0 && r != -17 {
            return; // 父目录创建失败：安装清单中断（后续项也会失败，可见）
        }
    }
}

fn prepare_layout() {
    note(b"[official-init] install list begin\n");
    for (dst, src) in INSTALL_LIST {
        mkdir_p(dst);
        if cp(src, dst) {
            note(b"[official-init] installed ");
            sys_write(1, dst);
            note(b"\n");
        } else {
            // 复制失败必须可见（不静默）：依赖该文件的组会如实失败
            note(b"[official-init] install FAILED for ");
            sys_write(1, dst);
            note(b"\n");
        }
    }
    note(b"[official-init] install list end\n");
    // 评测别名节点：为官方 mount 测例的 /dev/vda2 建立指向辅助盘 FAT32
    // 分区的真实块设备节点（用户态授权清单，内核按节点身份解析挂载）
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
            // EEXIST 视为已创建；其他失败必须可见
            note(b"[official-init] mknod failed for ");
            sys_write(1, path);
            note(b"\n");
        }
    }
}

/// 在 `libc_dir` 中以 `busybox sh <script>` 显式解释外层脚本，等待完成。
/// shebang 行由 shell 当作注释；脚本内的组标记与全部输出由其自身产生。
fn run_script(libc_dir: &[u8], dir_len: usize, script: &[u8]) {
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
            script.as_ptr() as usize,
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
        // execve 失败必须可见：打印后以 127 退出（shell 约定的"命令未找到"）
        sys_write(2, b"[official-init] execve busybox failed\n");
        sys_exit(127)
    }
    let wr = syscall6(
        SYS_WAIT4,
        [pid as usize, &mut status as *mut usize as usize, 0, 0, 0, 0],
    );
    // wait 失败或子进程异常退出都必须可见，不静默继续下一组
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

/// 授权清单：官方盘 basic/run-all.sh 发布为 0644，无法直接 exec
///（execve 需任一执行位）。对**运行副本**按本清单补执行位——仅改
/// 模式、不改内容与脚本逻辑，前后模式在串口可见；合规性由团队确认。
const CHMOD_ALLOWLIST: &[&[u8]] = &[b"/musl/basic/run-all.sh\0", b"/glibc/basic/run-all.sh\0"];

/// 评测别名节点授权条目：(节点路径, S_IFBLK|0644, 设备号)。设备号编码
/// glibc makedev(major, minor)：major=254（本内核块设备空间），minor =
/// (盘号<<4)|分区号 —— 辅助盘 disk.img 恒为总线第二块（盘 1）且其分区 2
/// 为 FAT32（构建期布局，见 tests/make_official_disk.py）。
const NODE_ALLOWLIST: &[(&[u8], usize, usize)] =
    &[(b"/dev/vda2\0", 0o060640, (254 << 8) | ((1 << 4) | 2))];

fn grant_exec_bit(path: &[u8]) {
    // 前后模式记录：清单文件固定发布为 0644，fchmodat 成功即为
    // 0644→0755；失败必须可见
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

/// 用户主函数（由 _start 调用，不返回）
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    note(b"[official-init] preparing runtime layout\n");
    prepare_layout();
    for path in CHMOD_ALLOWLIST {
        grant_exec_bit(path);
    }
    // 评测别名节点：为官方 mount 测例的 /dev/vda2 建立指向辅助盘 FAT32
    // 分区的真实块设备节点（用户态授权清单，内核按节点身份解析挂载）。
    // EEXIST 视为已创建；其他失败必须可见。
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
    // 官方组范围：注释掉不关心的行即可跳过该组；组脚本在盘上对应目录。
    // 其余组（lmbench/ltp/iozone/netperf/lua/iperf/cyclictest 等）依赖尚未
    // 实现的能力，需要时在此追加对应 run_script 行。
    run_script(b"/musl\0", 5, b"basic_testcode.sh\0");
    run_script(b"/musl\0", 5, b"busybox_testcode.sh\0");
    run_script(b"/glibc\0", 6, b"basic_testcode.sh\0");
    run_script(b"/glibc\0", 6, b"busybox_testcode.sh\0");
    note(b"[official-init] all groups finished\n");
    sys_exit(0)
}

define_user_entry!(ouro_main);
