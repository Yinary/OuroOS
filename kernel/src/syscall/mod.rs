//! 最小系统调用分发：write / exit / sched_yield / getpid，其余 ENOSYS。
//! 调用号与寄存器约定按 riscv64/loongarch64 通用 UAPI（a7=调用号、
//! a0..a5=参数、a0=返回负 errno 或结果）。支持范围与 Linux 语义偏差
//! 见 docs/ostd-contracts.md §4；PC 推进由运行循环统一处理。

mod memory;

use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::mm::{address_space::UserAddressSpace, user_access};

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

/// 一次系统调用之后的执行流去向：继续、让出还是退出。
pub enum Flow {
    /// 等待 I/O，保留参数和 PC 后让出。
    Retry,
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
        17 | 23 | 24 | 34 | 35 | 39 | 40 | 49 | 56 | 57 | 59 | 61 | 62 | 63 | 64 | 80 | 82
        | 291 => {
            let ret = crate::fs::context::dispatch(
                nr,
                [args[0], args[1], args[2], args[3], args[4], args[5]],
                space,
                fs,
            );
            if ret == Err(Errno::WouldBlock) {
                return Flow::Retry;
            }
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        93 => Flow::Exited(a0 as i32),
        214 => {
            cx[TrapFrameArgs::RET] = space.brk(a0);
            Flow::Continue
        }
        215 | 222 | 226 => {
            let ret = match nr {
                215 => memory::munmap(space, a0, a1),
                226 => memory::mprotect(space, a0, a1, a2),
                _ => memory::mmap(
                    space,
                    [args[0], args[1], args[2], args[3], args[4], args[5]],
                    fs,
                ),
            };
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        124 => {
            // sched_yield(2)：成功返回 0；让出意图交给运行循环
            cx[TrapFrameArgs::RET] = 0;
            Flow::Yield
        }
        101 | 153 | 173 | 220 | 221 | 260 => Flow::Process,
        160 | 169 => {
            let ret = if nr == 160 {
                let mut data = [0u8; 390];
                for (i, text) in [
                    "OuroOS",
                    "ouro",
                    "0.1.0",
                    "basic",
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
        172 => {
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
