//! 最小系统调用分发：write / exit / sched_yield / getpid，其余 ENOSYS。
//! 调用号与寄存器约定按 riscv64/loongarch64 通用 UAPI（a7=调用号、
//! a0..a5=参数、a0=返回负 errno 或结果）。支持范围与 Linux 语义偏差
//! 见 docs/ostd-contracts.md §4；PC 推进由运行循环统一处理。

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

/// 一次系统调用之后的执行流去向：继续、让出还是退出。
pub enum Flow {
    /// 系统调用完成，返回用户态继续。
    Continue,
    /// 系统调用完成，返回用户态前让出 CPU（sched_yield 等）。
    Yield,
    /// 任务已退出，携带退出状态。
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
/// 返回值写回 a0，PC 推进（syscall_ok）与执行流决策也由调用方统一处理。
/// `pid` 为调用者标识（getpid 返回它）。
pub fn dispatch(cx: &mut TrapFrame, pid: usize, space: &UserAddressSpace) -> Flow {
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
        124 => {
            // sched_yield(2)：成功返回 0；让出意图交给运行循环
            cx[TrapFrameArgs::RET] = 0;
            Flow::Yield
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
fn to_abi(ret: Result<usize, Errno>) -> usize {
    match ret {
        Ok(n) => n,
        Err(e) => (-e.as_errno()) as usize,
    }
}
