//! Define and initialize the trap handler.
//!
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal-trap 0.4.0（MIT）。
//! 修改说明：OuroOS vendor 补丁，清单见本目录 README.md。
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
    /// 事件已在 HAL 内部消化（如 la 非对齐模拟成功），恢复执行，非异常。
    Absorbed,
    /// 未分类异常（loongarch64 为 ecode<<16|esubcode）：用户态→终止任务，内核态→内核 bug。
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
