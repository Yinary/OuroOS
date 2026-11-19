//! 系统调用分发：通用 UAPI 调用号分发表与进程/文件/内存三类实现入口。
//! 调用号与寄存器约定按 riscv64/loongarch64 通用 UAPI（a7=调用号、
//! a0..=a5=参数、a0=返回值），支持范围与偏差见 docs/ostd-contracts.md §4。

mod memory;
// UAPI 常量集中在本模块定义。
pub(crate) mod signal;

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
    pub const MKDIRAT: usize = 34;
    pub const UNLINKAT: usize = 35;
    pub const UMOUNT2: usize = 39;
    pub const MOUNT: usize = 40;
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
    pub const FSTATAT: usize = 79;
    pub const FSTAT: usize = 80;
    pub const FSYNC: usize = 82;
    pub const STATX: usize = 291;
    // 进程
    pub const EXIT: usize = 93;
    pub const EXIT_GROUP: usize = 94;
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
    pub const UNAME: usize = 160;
    pub const GETPID: usize = 172;
    pub const GETPPID: usize = 173;
    pub const GETTIMEOFDAY: usize = 169;
    pub const CLONE: usize = 220;
    pub const EXECVE: usize = 221;
    pub const WAIT4: usize = 260;
    // 内存
    pub const BRK: usize = 214;
    pub const MUNMAP: usize = 215;
    pub const MMAP: usize = 222;
    pub const MPROTECT: usize = 226;
}

/// Linux errno（仅当前用到的子集）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    /// EPERM: 操作不被允许。
    Perm,
    Access,
    NoChild,
    NoProcess,
    SeekPipe,
    Busy,
    TooBig,
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
            Self::NoChild => 10,
            Self::NoProcess => 3,
            Self::SeekPipe => 29,
            Self::Busy => 16,
            Self::TooBig => 7,
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
        | sysnr::MKDIRAT
        | sysnr::UNLINKAT
        | sysnr::UMOUNT2
        | sysnr::MOUNT
        | sysnr::CHDIR
        | sysnr::OPENAT
        | sysnr::CLOSE
        | sysnr::PIPE2
        | sysnr::GETDENTS64
        | sysnr::LSEEK
        | sysnr::READ
        | sysnr::WRITE
        | sysnr::FSTAT
        | sysnr::FSYNC
        | sysnr::STATX => {
            let ret = crate::fs::context::dispatch(
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
        sysnr::EXIT => Flow::Exited(a0 as i32),
        sysnr::BRK => {
            cx[TrapFrameArgs::RET] = space.brk(a0);
            Flow::Continue
        }
        sysnr::MUNMAP | sysnr::MMAP | sysnr::MPROTECT => {
            let ret = match nr {
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
        // KILL/TGKILL/RT_SIGSUSPEND/RT_SIGTIMEDWAIT/RT_SIGQUEUEINFO 改目标
        // 记录或依赖循环局部等待状态，在锁外（process_call）处理。
        sysnr::KILL
        | sysnr::TGKILL
        | sysnr::RT_SIGSUSPEND
        | sysnr::RT_SIGTIMEDWAIT
        | sysnr::RT_SIGQUEUEINFO
        | sysnr::NANOSLEEP
        | sysnr::TIMES
        | sysnr::GETPPID
        | sysnr::CLONE
        | sysnr::EXECVE
        | sysnr::WAIT4 => Flow::Process,
        sysnr::UNAME | sysnr::GETTIMEOFDAY => {
            let ret = if nr == sysnr::UNAME {
                let mut data = [0u8; 390];
                for (i, text) in [
                    crate::config::KERNEL_NAME,
                    "ouro",
                    crate::config::KERNEL_VERSION,
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
