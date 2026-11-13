//! 系统调用分发：通用 UAPI 调用号分发表与进程/文件/内存三类实现入口。
//! 调用号与寄存器约定按 riscv64/loongarch64 通用 UAPI（a7=调用号、
//! a0..=a5=参数、a0=返回负 errno 或结果）。支持范围与 Linux 语义偏差
//! 见 docs/ostd-contracts.md §4；PC 推进由运行循环统一处理。

mod memory;

use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::mm::{address_space::UserAddressSpace, user_access};
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
    Access,
    NoChild,
    NoProcess,
    SeekPipe,
    Busy,
    TooBig,
    ExecFormat,
    Again,
    WouldBlock,
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
            Self::Access => 13,
            Self::NoChild => 10,
            Self::NoProcess => 3,
            Self::SeekPipe => 29,
            Self::Busy => 16,
            Self::TooBig => 7,
            Self::ExecFormat => 8,
            Self::Again | Self::WouldBlock => 11,
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
    /// 任务已退出，携带退出状态。
    Exited(i32),
}

/// 系统调用分发。寄存器现场由调用方（用户任务运行循环）持有，
/// 返回值写回 a0，PC 推进（syscall_ok）与执行流决策也由调用方统一处理。
/// `pid` 为调用者标识（getpid 返回它）。
pub fn dispatch(
    cx: &mut TrapFrame,
    pid: usize,
    space: &mut UserAddressSpace,
    fs: &mut crate::fs::context::Context,
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
        sysnr::SCHED_YIELD => {
            // sched_yield(2)：成功返回 0；让出意图交给运行循环
            cx[TrapFrameArgs::RET] = 0;
            Flow::Yield
        }
        sysnr::NANOSLEEP
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
