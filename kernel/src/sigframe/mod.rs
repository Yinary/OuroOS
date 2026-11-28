//! 信号帧：handler 建帧投递（build_deliver）与 rt_sigreturn 恢复（restore）。
//! 各架构帧布局依据见 riscv64.rs / loongarch64.rs 文件头（Linux 源文件）。
//! 契约见 docs/ostd-contracts.md §4.5。
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
    /// 用户内存不可读/不可写。
    Access,
    /// 帧校验不符（魔数/保留字段）。
    BadFrame,
}

/// 合成帧内字段地址 `base + off`；溢出返回 [`FrameError::Access`]。
pub(super) fn frame_addr(base: usize, off: usize) -> Result<usize, FrameError> {
    base.checked_add(off).ok_or(FrameError::Access)
}

/// 用户栈指针 sp 是否落在备用栈区间内。
pub(super) fn on_alt_stack(sp: usize, base: usize, size: usize) -> bool {
    sp > base && sp - base <= size
}

/// 组装 128 字节 siginfo 写入 `out`（字段偏移见 asm-generic/siginfo.h）。
/// union 按 si_code 选择 _kill/_sigchld/_rt/_sigfault 形状。
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
        crate::task::signal::SI_QUEUE | crate::task::signal::SI_MESGQ => {
            out[16..20].copy_from_slice(&slot.pid.to_ne_bytes());
            out[24..32].copy_from_slice(&slot.addr.to_ne_bytes());
        }
        crate::task::signal::SI_TIMER => {
            out[16..20].copy_from_slice(&slot.timer_id.to_ne_bytes());
            out[20..24].copy_from_slice(&slot.overrun.to_ne_bytes());
            out[24..32].copy_from_slice(&slot.addr.to_ne_bytes());
        }
        _ => {
            out[16..20].copy_from_slice(&slot.pid.to_ne_bytes());
        }
    }
}
