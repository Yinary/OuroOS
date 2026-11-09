//! Define and initialize the trap handler.
//!
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal-trap 0.4.0
//! 原协议：MIT
//! 修改说明（OuroOS vendor 补丁，清单见 third_party/polyhal-trap/README.md）：
//! - TrapType 新增 Absorbed（HAL 已内部消化，如 la 非对齐模拟成功）与
//!   Unhandled(code)（未分类异常，交 OS 决策而非 HAL panic）；
//! - run_user_task 各架构改为返回完整 TrapType，不再降维成 EscapeReason
//!   （OuroOS 缺陷记录 #5：降维丢失缺页地址等完整信息）。
//!
//!

use super::trapframe::TrapFrame;
use polyhal::{ctor::CtorType, irq::IRQVector, ph_ctor};

polyhal_macro::define_arch_mods!();

#[derive(Debug, Clone, Copy)]
pub enum TrapType {
    Breakpoint,
    SysCall,
    Timer,
    /// 事件已在 HAL 内部消化（如 loongarch64 非对齐访问模拟成功），
    /// 调用方应恢复原执行流，不视为异常。0.4.0 原版以 Unknown 表达，
    /// 与"未分类异常"无法区分。
    Absorbed,
    /// 未分类异常（携架构异常码，loongarch64 为 ecode<<16|esubcode）。
    /// 0.4.0 原版在 loongarch64 侧对此直接 panic，用户态异常会带走
    /// 整个内核（OuroOS 缺陷记录 #7）。正确语义：来自用户态由 OS
    /// 终止任务，来自内核态由 OS 判定为内核 bug。
    Unhandled(usize),
    Unknown,
    SupervisorExternal,
    StorePageFault(usize),
    LoadPageFault(usize),
    InstructionPageFault(usize),
    IllegalInstruction(usize),
    Irq(IRQVector),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeReason {
    NoReason,
    IRQ,
    Timer,
    SysCall,
}

// TODO: Add more trap types as needed
impl From<TrapType> for EscapeReason {
    fn from(value: TrapType) -> Self {
        match value {
            TrapType::SysCall => EscapeReason::SysCall,
            TrapType::Timer => EscapeReason::Timer,
            TrapType::Irq(_) => EscapeReason::IRQ,
            _ => EscapeReason::NoReason,
        }
    }
}

extern "Rust" {
    pub(crate) fn _interrupt_for_arch(ctx: &mut TrapFrame, trap_type: TrapType, token: usize);
}

ph_ctor!(TRAP_INIT, CtorType::Cpu, init);
