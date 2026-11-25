//! 官方盘用户态启动器：盘上无 /init 时由内核内嵌启动。安装测例请求的动态
//! 加载器与库，建立 /tmp 等目录和 /bin/sh、/busybox 入口，再用 busybox
//! sh 显式解释官方外层脚本；全部经通用文件系统调用完成，不感知测例内容。

#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write, syscall3, syscall6};

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

const AT_FDCWD: usize = usize::MAX - 99; // -100
const O_RDONLY: usize = 0;
const O_WRONLY: usize = 1;
const O_CREAT: usize = 0o100;
const O_TRUNC: usize = 0o1000;
const SIGCHLD: usize = 17;

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
];

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

fn prepare_layout() {
    mkdir_p(b"/tmp/\0");
    mkdir_p(b"/var/tmp/\0");
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

#[no_mangle]
extern "C" fn ouro_main() -> ! {
    note(b"[official-init] preparing runtime layout\n");
    prepare_layout();
    for path in CHMOD_ALLOWLIST {
        grant_exec_bit(path);
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
