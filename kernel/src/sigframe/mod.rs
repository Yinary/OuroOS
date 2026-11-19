//! 信号帧：handler 建帧投递（build_deliver）与 rt_sigreturn 恢复（restore）。
//! 帧布局天然 per-arch（rv64 为 arm64 形状 ucontext + 帧尾 sigreturn_code，
//! la64 为自带 extcontext 链），cfg 仅在下方重导出点出现一次；两架构共享
//! 的只有 siginfo 组装。各布局依据见 per-arch 文件头（Linux 源文件）。
#![deny(unsafe_code)]

#[cfg(target_arch = "loongarch64")]
mod loongarch64;
#[cfg(target_arch = "riscv64")]
mod riscv64;

#[cfg(target_arch = "loongarch64")]
pub use loongarch64::{build_deliver, restore};
#[cfg(target_arch = "riscv64")]
pub use riscv64::{build_deliver, restore};

use crate::task::signal::{SigInfoSlot, SIGCHLD};

/// 帧构造/恢复失败。
#[derive(Debug)]
pub enum FrameError {
    /// 用户内存不可读/不可写（对应 Linux access_ok/__copy 失败的 EFAULT 路径）。
    Access,
    /// 帧校验不符（魔数/保留字段），对应 Linux restore 的 badframe。
    BadFrame,
}

/// 用户栈指针 sp 是否落在备用栈区间内。公式同 Linux on_sig_stack
///（include/linux/sched/signal.h 向下增长分支）：sp 严格大于基址且
/// 偏移不超过 size（含上边界）。
pub(super) fn on_alt_stack(sp: usize, base: usize, size: usize) -> bool {
    sp > base && sp - base <= size
}

/// 组装 128 字节 siginfo 写入 `out`。字段偏移取自 Linux
/// include/uapi/asm-generic/siginfo.h（本机以抓取头文件静态断言核验）：
/// si_signo@0 si_errno@4 si_code@8；union 自偏移 16（对齐 8 产生 4 字节
/// 填充）——si_pid@16 si_uid@20 si_addr@16 si_status@24 si_value@24。
/// uid 恒 0（无 uid 概念）。union 按 si_code 选形：SI_USER（=0，
/// kill/tgkill/SIGPIPE）用 _kill{pid}；CLD_*（SIGCHLD）用
/// _sigchld{pid,status}；SI_QUEUE（rt_sigqueueinfo）用 _rt{pid,value}，
/// 槽把 si_value 存在 addr 字段；其余正值（硬件异常码）用 _sigfault{addr}。
pub(super) fn fill_siginfo(out: &mut [u8], sig: u8, slot: &SigInfoSlot) {
    debug_assert_eq!(out.len(), 128);
    out[0..4].copy_from_slice(&(sig as i32).to_ne_bytes());
    out[4..8].copy_from_slice(&slot.errno.to_ne_bytes());
    out[8..12].copy_from_slice(&slot.code.to_ne_bytes());
    match slot.code {
        c if c > 0 && sig == SIGCHLD => {
            out[16..20].copy_from_slice(&slot.pid.to_ne_bytes());
            out[24..28].copy_from_slice(&slot.status.to_ne_bytes());
        }
        c if c > 0 => {
            out[16..24].copy_from_slice(&slot.addr.to_ne_bytes());
        }
        crate::task::signal::SI_QUEUE => {
            out[16..20].copy_from_slice(&slot.pid.to_ne_bytes());
            out[24..32].copy_from_slice(&slot.addr.to_ne_bytes());
        }
        _ => {
            out[16..20].copy_from_slice(&slot.pid.to_ne_bytes());
        }
    }
}
