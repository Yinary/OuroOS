//! 最小系统调用分发：write 与 exit。
//!
//! 错误在内核内部用 `Result<_, Errno>` 表达，在 ABI 边界转换成 Linux
//! 负 errno 返回值（a0）。系统调用号与寄存器约定依据 Linux man-pages
//! syscall(2) 及 riscv64 / loongarch64 的通用（generic）UAPI：两者都用
//! a7 传调用号、a0..a5 传参数、a0 返回结果，write=64、exit=93。
//!
//! 支持范围（未支持的部分在此明确列出，不冒充完整 Linux 语义）：
//! - write：仅 fd=1/2，内容直接送内核控制台；不维护文件偏移、不做
//!   部分写（出错时不输出任何字节，Linux 允许先写部分再返回 EFAULT）；
//!   len=0 时只检查 fd，不检查缓冲区，返回 0（与 Linux 一致）；
//! - exit：记录退出状态并结束唯一用户任务，由启动主流程统一关机；
//! - 其余系统调用一律 ENOSYS。fd 表、文件框架、信号均不存在。

use polyhal::debug_console::DebugConsole;
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::mm::{
    address_space::UserAddressSpace,
    user_access::{self, AccessError},
};

/// Linux errno（仅当前用到的子集）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
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
            Errno::BadF => 9,
            Errno::Fault => 14,
            Errno::NoSys => 38,
        }
    }
}

/// exit 之后的流向：告知用户任务运行循环结束
pub enum Flow {
    /// 系统调用完成，返回用户态继续
    Continue,
    /// 用户任务已退出，携带退出状态
    Exited(i32),
}

/// syscall(64) write：把用户缓冲区内容写到控制台。
///
/// fd 只接受 1（stdout）/ 2（stderr）；缓冲区逐页检查用户映射与
/// 所有权后经内核直接映射分块复制，不把用户指针当作内核切片。
fn sys_write(space: &UserAddressSpace, fd: usize, buf: usize, len: usize) -> Result<usize, Errno> {
    if fd != 1 && fd != 2 {
        return Err(Errno::BadF);
    }
    if len == 0 {
        // Linux 语义：count=0 时成功返回 0，不校验缓冲区
        return Ok(0);
    }
    // 分块输出原始字节，不把任意字节强制当 UTF-8
    user_access::read_user_bytes(space, buf, len, |chunk| {
        for &b in chunk {
            DebugConsole::putchar(b);
        }
    })
    .map_err(|AccessError::Fault| Errno::Fault)?;
    Ok(len)
}

/// 系统调用分发。寄存器现场由调用方（用户任务运行循环）持有，
/// 返回值写回 a0，PC 推进（syscall_ok）也由调用方统一处理。
pub fn dispatch(cx: &mut TrapFrame, space: &UserAddressSpace) -> Flow {
    // 调用号在 a7（TrapFrameArgs::SYSCALL），参数在 a0..；返回值写回 a0
    let nr = cx[TrapFrameArgs::SYSCALL];
    let args = cx.args();
    let (a0, a1, a2) = (args[0], args[1], args[2]);
    match nr {
        64 => {
            let ret = sys_write(space, a0, a1, a2);
            cx[TrapFrameArgs::RET] = to_abi(ret);
            Flow::Continue
        }
        93 => Flow::Exited(a0 as i32),
        _ => {
            cx[TrapFrameArgs::RET] = to_abi(Err(Errno::NoSys));
            Flow::Continue
        }
    }
}

/// Result → Linux ABI 返回值：Ok(n) → n；Err(e) → -errno
fn to_abi(ret: Result<usize, Errno>) -> usize {
    match ret {
        Ok(n) => n,
        Err(e) => (-e.as_errno()) as usize,
    }
}
