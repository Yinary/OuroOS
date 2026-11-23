//! 系统调用分发：通用 UAPI 调用号分发表与进程/文件/内存三类实现入口。
//! 调用号与寄存器约定按 riscv64/loongarch64 通用 UAPI（a7=调用号、
//! a0..=a5=参数、a0=返回值），支持范围与偏差见 docs/ostd-contracts.md §4。

pub(crate) mod fs;
mod memory;
// UAPI 常量集中在本模块定义。
pub(crate) mod signal;

#[cfg(debug_assertions)]
pub(crate) fn memory_self_test() {
    memory::self_test();
}

use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::mm::{address_space::UserAddressSpace, user_access};
use crate::task::signal::{SigInfoSlot, SignalSet, SignalSetExt, SEGV_MAPERR, SIGPIPE, SIGSEGV};
use crate::task::WaitReason;

/// 已实现的通用 UAPI 调用号（asm-generic/unistd.h，rv64/la64 共用）。
/// 少数未实现项一并列入（目录性质，接入时直接引用）。
#[allow(dead_code)]
pub mod sysnr {
    // 文件
    pub const GETCWD: usize = 17;
    pub const DUP: usize = 23;
    pub const DUP3: usize = 24;
    pub const IOCTL: usize = 29;
    pub const FCNTL: usize = 25;
    pub const MKDIRAT: usize = 34;
    pub const UNLINKAT: usize = 35;
    pub const RENAMEAT: usize = 38;
    pub const UMOUNT2: usize = 39;
    pub const MOUNT: usize = 40;
    pub const STATFS: usize = 43;
    pub const FSTATFS: usize = 44;
    pub const TRUNCATE: usize = 45;
    pub const FTRUNCATE: usize = 46;
    pub const CHDIR: usize = 49;
    pub const OPENAT: usize = 56;
    pub const CLOSE: usize = 57;
    pub const PIPE2: usize = 59;
    pub const GETDENTS64: usize = 61;
    pub const LSEEK: usize = 62;
    pub const READ: usize = 63;
    pub const WRITE: usize = 64;
    pub const READV: usize = 65;
    pub const WRITEV: usize = 66;
    pub const PREAD64: usize = 67;
    pub const PWRITE64: usize = 68;
    pub const PREADV: usize = 69;
    pub const PWRITEV: usize = 70;
    pub const READLINKAT: usize = 78;
    pub const FSTATAT: usize = 79;
    pub const FSTAT: usize = 80;
    pub const FSYNC: usize = 82;
    pub const UTIMENSAT: usize = 88;
    pub const UMASK: usize = 166;
    pub const RENAMEAT2: usize = 276;
    pub const STATX: usize = 291;
    // 进程
    pub const EXIT: usize = 93;
    pub const EXIT_GROUP: usize = 94;
    pub const SYSINFO: usize = 179;
    pub const PPOLL: usize = 73;
    pub const NANOSLEEP: usize = 101;
    pub const CLOCK_GETTIME: usize = 113;
    pub const SCHED_YIELD: usize = 124;
    pub const KILL: usize = 129;
    pub const TGKILL: usize = 131;
    // 信号
    pub const SIGALTSTACK: usize = 132;
    pub const RT_SIGSUSPEND: usize = 133;
    pub const RT_SIGACTION: usize = 134;
    pub const RT_SIGPROCMASK: usize = 135;
    pub const RT_SIGPENDING: usize = 136;
    pub const RT_SIGTIMEDWAIT: usize = 137;
    pub const RT_SIGQUEUEINFO: usize = 138;
    pub const RT_SIGRETURN: usize = 139;
    pub const TIMES: usize = 153;
    pub const SET_TID_ADDRESS: usize = 96;
    pub const SETPGID: usize = 154;
    pub const GETPGID: usize = 155;
    pub const GETSID: usize = 156;
    pub const SETSID: usize = 157;
    pub const UNAME: usize = 160;
    pub const GETPID: usize = 172;
    pub const GETPPID: usize = 173;
    pub const GETTIMEOFDAY: usize = 169;
    pub const FACCESSAT: usize = 48;
    pub const FCHMODAT: usize = 53;
    pub const MKNODAT: usize = 296;
    pub const FCHMOD: usize = 52;
    pub const SYSLOG: usize = 116;
    pub const GETRANDOM: usize = 278;
    pub const FACCESSAT2: usize = 439;
    pub const CLONE: usize = 220;
    pub const EXECVE: usize = 221;
    pub const WAIT4: usize = 260;
    // 内存
    pub const READAHEAD: usize = 213;
    pub const BRK: usize = 214;
    pub const MUNMAP: usize = 215;
    pub const MREMAP: usize = 216;
    pub const MMAP: usize = 222;
    pub const MPROTECT: usize = 226;
    pub const MSYNC: usize = 227;
    pub const MLOCK: usize = 228;
    pub const MUNLOCK: usize = 229;
    pub const MLOCKALL: usize = 230;
    pub const MUNLOCKALL: usize = 231;
    pub const MINCORE: usize = 232;
    pub const MADVISE: usize = 233;
    pub const MLOCK2: usize = 284;
}

/// Linux errno（仅当前用到的子集）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    /// EPERM: 操作不被允许。
    Perm,
    Access,
    /// ENOTTY：fd 不支持该 ioctl 命令
    InappropriateIoctl,
    NoChild,
    NoProcess,
    SeekPipe,
    Busy,
    TooBig,
    FileTooBig,
    ExecFormat,
    Again,
    WouldBlock,
    /// EINTR: 阻塞中的系统调用被信号打断时返回。
    Interrupted,
    Pipe,
    Io,
    NoEntry,
    NoSpace,
    Exists,
    NotDir,
    IsDir,
    NoDevice,
    TooManyFiles,
    Range,
    NameTooLong,
    Loop,
    CrossDevice,
    NotEmpty,
    TooManyLinks,
    /// 内存不足。
    NoMem,
    /// 参数无效。
    Invalid,
    /// 不支持的能力。
    NotSupported,
    /// 只读文件系统。
    ReadOnly,
    /// EBADF: fd 不在支持范围
    BadF,
    /// EFAULT: 用户缓冲区地址非法
    Fault,
    /// ENOSYS: 未实现的系统调用
    NoSys,
}

impl Errno {
    /// Linux errno 数值（asm-generic/errno-base.h）
    pub fn as_errno(self) -> isize {
        match self {
            Self::Perm => 1,
            Self::Access => 13,
            Self::InappropriateIoctl => 25,
            Self::NoChild => 10,
            Self::NoProcess => 3,
            Self::SeekPipe => 29,
            Self::Busy => 16,
            Self::TooBig => 7,
            Self::FileTooBig => 27,
            Self::ExecFormat => 8,
            Self::Again | Self::WouldBlock => 11,
            Self::Interrupted => 4,
            Self::Pipe => 32,
            Self::Io => 5,
            Self::NoEntry => 2,
            Self::NoSpace => 28,
            Self::Exists => 17,
            Self::NotDir => 20,
            Self::IsDir => 21,
            Self::NoDevice => 19,
            Self::TooManyFiles => 24,
            Self::Range => 34,
            Self::NameTooLong => 36,
            Self::Loop => 40,
            Self::CrossDevice => 18,
            Self::NotEmpty => 39,
            Self::TooManyLinks => 31,
            Self::NoMem => 12,
            Self::Invalid => 22,
            Self::NotSupported => 95,
            Self::ReadOnly => 30,
            Errno::BadF => 9,
            Errno::Fault => 14,
            Errno::NoSys => 38,
        }
    }
}

/// 一次系统调用之后的执行流去向。
pub enum Flow {
    /// 阻塞等待：保留 syscall PC 挂起，被唤醒后重执行重查条件
    /// （“阻塞即让出”协议，等待/唤醒机制见 task 契约）。
    Wait(WaitReason),
    /// 系统调用完成，返回用户态继续。
    Continue,
    /// 系统调用完成，返回用户态前让出 CPU（sched_yield 等）。
    Yield,
    /// 在解除注册表借用后处理进程操作。
    Process,
    /// rt_sigreturn：现场已从信号帧恢复，SEPC 即真实返回点，
    /// 运行循环不再推进。
    SigReturn,
    /// 任务已退出，携带退出状态。
    Exited(i32),
}

/// 系统调用分发，返回 Flow。返回值写回 a0，PC 推进与执行流决策由调用方处理。
/// `pid` 为调用者标识。调用发生在 REGISTRY 锁内，改其他进程记录的
/// 调用走 Flow::Process 在锁外处理。
pub fn dispatch(
    cx: &mut TrapFrame,
    pid: usize,
    space: &mut UserAddressSpace,
    fs: &mut crate::fs::context::Context,
    signal: &mut crate::task::signal::SignalState,
) -> Flow {
    // 调用号在 a7（TrapFrameArgs::SYSCALL），参数在 a0..；返回值写回 a0
    let nr = cx[TrapFrameArgs::SYSCALL];
    let args = cx.args();
    let (a0, a1, a2) = (args[0], args[1], args[2]);
    match nr {
        sysnr::GETCWD
        | sysnr::DUP
        | sysnr::DUP3
        | sysnr::FCNTL
        | sysnr::MKDIRAT
        | sysnr::UNLINKAT
        | sysnr::RENAMEAT
        | sysnr::RENAMEAT2
        | sysnr::UMOUNT2
        | sysnr::MOUNT
        | sysnr::STATFS
        | sysnr::FSTATFS
        | sysnr::TRUNCATE
        | sysnr::FTRUNCATE
        | sysnr::CHDIR
        | sysnr::OPENAT
        | sysnr::CLOSE
        | sysnr::PIPE2
        | sysnr::GETDENTS64
        | sysnr::LSEEK
        | sysnr::READ
        | sysnr::WRITE
        | sysnr::READV
        | sysnr::WRITEV
        | sysnr::PREAD64
        | sysnr::PWRITE64
        | sysnr::PREADV
        | sysnr::PWRITEV
        | sysnr::READLINKAT
        | sysnr::FSTAT
        | sysnr::FSTATAT
        | sysnr::FSYNC
        | sysnr::UTIMENSAT
        | sysnr::UMASK
        | sysnr::FACCESSAT
        | sysnr::FACCESSAT2
        | sysnr::FCHMODAT
        | sysnr::FCHMOD
        | sysnr::MKNODAT
        | sysnr::IOCTL
        | sysnr::STATX => {
            let ret = self::fs::dispatch(
                nr,
                [args[0], args[1], args[2], args[3], args[4], args[5]],
                space,
                fs,
            );
            // pipe 无数据/无空间且非 O_NONBLOCK：转为阻塞等待
            if ret == Err(Errno::WouldBlock) {
                return Flow::Wait(WaitReason::Pipe);
            }
            // 向无读者的管道写入：SIGPIPE 入队并与 -EPIPE 返回并行。
            if ret == Err(Errno::Pipe) && (nr == sysnr::WRITE || nr == sysnr::WRITEV) {
                signal.generate(
                    SIGPIPE,
                    // code=0 即 SI_USER，发送者为调用进程自身。
                    SigInfoSlot {
                        pid: pid as u32,
                        ..Default::default()
                    },
                );
            }
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::MLOCK | sysnr::MUNLOCK | sysnr::MLOCK2 => {
            cx[TrapFrameArgs::RET] = to_abi(memory::mlock(
                space,
                a0,
                a1,
                nr != sysnr::MUNLOCK,
                if nr == sysnr::MLOCK2 { a2 } else { 0 },
            ));
            Flow::Continue
        }
        sysnr::MSYNC => {
            cx[TrapFrameArgs::RET] = to_abi(memory::msync(space, a0, a1, a2));
            Flow::Continue
        }
        sysnr::MLOCKALL | sysnr::MUNLOCKALL => {
            let flags = if nr == sysnr::MUNLOCKALL { 0 } else { a0 };
            let ret = if nr == sysnr::MLOCKALL && (flags & !7 != 0 || flags & 3 == 0) {
                Err(Errno::Invalid)
            } else {
                space.lock_all(flags).map(|_| 0).map_err(|_| Errno::NoMem)
            };
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        163 | 164 | 261 => {
            let (resource, new_ptr, old_ptr) = match nr {
                163 => (a0, 0, a1),
                164 => (a0, a1, 0),
                _ => (a1, a2, args[3]),
            };
            let ret = if (nr == 163 || nr == 164) && a1 == 0 {
                Err(Errno::Fault)
            } else if nr == 261 && a0 != 0 && a0 != pid {
                Err(Errno::NoProcess)
            } else {
                memory::limit(space, resource, new_ptr, old_ptr)
            };
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::SET_TID_ADDRESS => {
            space.clear_child_tid = a0;
            cx[TrapFrameArgs::RET] = pid;
            Flow::Continue
        }
        sysnr::EXIT | sysnr::EXIT_GROUP => {
            if space.clear_child_tid != 0 {
                let _ = user_access::copy_to_user(space, space.clear_child_tid, &[0; 4]);
            }
            Flow::Exited(a0 as i32)
        }
        sysnr::READAHEAD => {
            cx[TrapFrameArgs::RET] = to_abi(memory::readahead(fs, a0, a1, a2));
            Flow::Continue
        }
        sysnr::BRK => {
            cx[TrapFrameArgs::RET] = space.brk(a0);
            Flow::Continue
        }
        sysnr::MUNMAP
        | sysnr::MMAP
        | sysnr::MPROTECT
        | sysnr::MREMAP
        | sysnr::MINCORE
        | sysnr::MADVISE => {
            let ret = match nr {
                sysnr::MADVISE => memory::madvise(space, a0, a1, a2),
                sysnr::MINCORE => memory::mincore(space, a0, a1, a2),
                sysnr::MREMAP => memory::mremap(space, [a0, a1, a2, args[3], args[4]]),
                sysnr::MUNMAP => memory::munmap(space, a0, a1),
                sysnr::MPROTECT => memory::mprotect(space, a0, a1, a2),
                _ => memory::mmap(
                    space,
                    [args[0], args[1], args[2], args[3], args[4], args[5]],
                    fs,
                ),
            };
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::RT_SIGACTION => {
            // rt_sigaction(2)：单信号处置读改写
            let ret = signal::rt_sigaction(space, a0, a1, a2, args[3], signal);
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::RT_SIGPROCMASK => {
            // rt_sigprocmask(2)：屏蔽集合改读
            let ret = signal::rt_sigprocmask(space, a0, a1, a2, args[3], signal);
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::RT_SIGPENDING => {
            // rt_sigpending(2)：pending 位图回写
            let ret = signal::rt_sigpending(space, a0, a1, signal);
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::SIGALTSTACK => {
            // sigaltstack(2)：备用栈登记的换读；只改调用者自身记录，
            // on_alt/SS_ONSTACK 判定用陷入前的用户 sp。
            let ret = signal::rt_sigaltstack(space, cx[TrapFrameArgs::SP], a0, a1, signal);
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::RT_SIGRETURN => {
            // rt_sigreturn(2)：按 sp 指向的信号帧恢复现场并换回屏蔽集合。
            // 失败按 force SIGSEGV 处置，偏差登记 docs/ostd-contracts.md §4.5。
            match crate::sigframe::restore(cx, space) {
                // 成功：换回帧内保存的屏蔽集合（KILL/STOP 已剥除）。
                Ok(old) => signal.setmask(old),
                Err(_) => {
                    signal.set_disposition(SIGSEGV, Default::default());
                    let mut one: SignalSet = 0;
                    one.add(SIGSEGV);
                    signal.unblock(one);
                    signal.generate(
                        SIGSEGV,
                        SigInfoSlot {
                            code: SEGV_MAPERR,
                            addr: cx[TrapFrameArgs::SP],
                            ..Default::default()
                        },
                    );
                }
            }
            Flow::SigReturn
        }
        sysnr::SCHED_YIELD => {
            // sched_yield(2)：成功返回 0；让出意图交给运行循环
            cx[TrapFrameArgs::RET] = 0;
            Flow::Yield
        }
        // KILL/TGKILL/RT_SIGSUSPEND/RT_SIGTIMEDWAIT/RT_SIGQUEUEINFO/SYSINFO/
        // PPOLL 改目标记录或依赖循环局部等待状态，在锁外（process_call）处理。
        sysnr::KILL
        | sysnr::TGKILL
        | sysnr::RT_SIGSUSPEND
        | sysnr::RT_SIGTIMEDWAIT
        | sysnr::RT_SIGQUEUEINFO
        | sysnr::SYSINFO
        | sysnr::PPOLL
        | sysnr::NANOSLEEP
        | sysnr::TIMES
        | sysnr::GETPPID
        | sysnr::CLONE
        | sysnr::EXECVE
        | sysnr::WAIT4
        | sysnr::SETPGID
        | sysnr::GETPGID
        | sysnr::GETSID
        | sysnr::SETSID => Flow::Process,
        sysnr::GETRANDOM => {
            // getrandom(2)：flags 只认 NONBLOCK(1)/RANDOM(2)（后者与默认
            // 等价）；无种子或熵流耗尽一律 EAGAIN（无合法阻塞唤醒来源），
            // 未知 flags EINVAL
            let ret = if a1 > 0x1_0000 || a1 > isize::MAX as usize {
                // 单次 64 KiB 上限：避免用户以超大 len 逼出大额内核分配
                Err(Errno::Invalid)
            } else if a2 & !0x3 != 0 {
                Err(Errno::Invalid)
            } else if !crate::entropy::ready() {
                Err(Errno::Again)
            } else {
                let mut buf = alloc::vec::Vec::new();
                if buf.try_reserve_exact(a1).is_err() {
                    Err(Errno::NoMem)
                } else {
                    buf.resize(a1, 0);
                    if crate::entropy::fill_random(&mut buf) {
                        user_access::copy_to_user(space, a0, &buf)
                            .map(|_| a1)
                            .map_err(|_| Errno::Fault)
                    } else {
                        // 熵流耗尽：与无种子同为 EAGAIN（不重放、不伪造）
                        Err(Errno::Again)
                    }
                }
            };
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::SYSLOG => {
            // syslog(2)/klogctl 按 man 2 的 action 编码分发到 dmesg 环；
            // 0/1、6/7 无实际设备句柄，返回 0（串口直通）
            // 交付到用户缓冲的公共尾段；环分配失败转 ENOMEM
            let deliver = |t: Option<alloc::string::String>, n_limit: usize| {
                let t = t.ok_or(Errno::NoMem)?;
                let n = n_limit.min(t.len());
                user_access::copy_to_user(space, a1, t.as_bytes()[..n].as_ref())
                    .map(|_| n)
                    .map_err(|_| Errno::Fault)
            };
            let ret = match a0 {
                0 | 1 => Ok(0),
                2 => {
                    // READ：先交付成功再推进游标（交付失败游标不动，
                    // 下次 READ 重取同一段）
                    let Some((text, new_cursor)) = crate::dmesg::read_consume_peek(a2) else {
                        return {
                            cx[TrapFrameArgs::RET] = to_abi(Err(Errno::NoMem));
                            Flow::Continue
                        };
                    };
                    let n = text.len().min(a2);
                    let delivered =
                        user_access::copy_to_user(space, a1, text.as_bytes()[..n].as_ref())
                            .map(|_| n)
                            .map_err(|_| Errno::Fault);
                    if delivered.is_ok() {
                        crate::dmesg::read_consume_commit(new_cursor);
                    }
                    delivered
                }
                3 => deliver(crate::dmesg::read_all(), a2),
                4 => {
                    // READ_CLEAR：先交付，成功后才清空（失败不清）
                    let r = deliver(crate::dmesg::read_all(), a2);
                    if r.is_ok() {
                        crate::dmesg::clear();
                    }
                    r
                }
                5 => {
                    crate::dmesg::clear();
                    Ok(0)
                }
                6 | 7 => Ok(0),
                8 if (1..=8).contains(&a1) => {
                    crate::dmesg::set_console_level(a1 as u8);
                    Ok(0)
                }
                9 => Ok(crate::dmesg::unread()),
                10 => Ok(crate::dmesg::capacity()),
                _ => Err(Errno::Invalid),
            };
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::UNAME | sysnr::GETTIMEOFDAY => {
            let ret = if nr == sysnr::UNAME {
                let mut data = [0u8; 390];
                for (i, text) in [
                    crate::config::KERNEL_NAME,
                    "ouro",
                    crate::config::KERNEL_RELEASE,
                    crate::config::KERNEL_NAME,
                    crate::config::ARCH_NAME,
                    "local",
                ]
                .iter()
                .enumerate()
                {
                    data[i * 65..i * 65 + text.len()].copy_from_slice(text.as_bytes());
                }
                user_access::copy_to_user(space, a0, &data)
                    .map(|_| 0)
                    .map_err(|_| Errno::Fault)
            } else {
                let now = polyhal::timer::current_time();
                let mut data = [0u8; 16];
                data[..8].copy_from_slice(&now.as_secs().to_ne_bytes());
                data[8..].copy_from_slice(&(now.subsec_micros() as u64).to_ne_bytes());
                if a0 == 0 {
                    Ok(0)
                } else {
                    user_access::copy_to_user(space, a0, &data)
                        .map(|_| 0)
                        .map_err(|_| Errno::Fault)
                }
            };
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        sysnr::GETPID => {
            // getpid(2)：总成功；pid 由进程注册表分配，见 task 契约
            cx[TrapFrameArgs::RET] = pid;
            Flow::Continue
        }
        _ => {
            cx[TrapFrameArgs::RET] = to_abi(Err(Errno::NoSys));
            Flow::Continue
        }
    }
}

/// Result → Linux ABI 返回值：Ok(n) → n；Err(e) → -errno
pub(crate) fn to_abi(ret: Result<usize, Errno>) -> usize {
    match ret {
        Ok(n) => n,
        Err(e) => (-e.as_errno()) as usize,
    }
}
