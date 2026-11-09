//! 中断/异常回调：时钟记账与续设、启动自检、内核态异常执法；
//! 用户态陷阱由任务运行循环按完整 TrapType 处置。
//! 职责划分依据见 docs/ostd-contracts.md §2/§3。

use core::{sync::atomic::Ordering, time::Duration};

use polyhal::timer::{current_time, set_next_timer};
use polyhal_trap::{
    trap::TrapType,
    trapframe::{TrapFrame, TrapFrameArgs},
};

use crate::{config, BREAK_TICKS, TIMER_TICKS};

/// 用户异常的种类（对应用户程序可能触发的 TrapType 子集）。
#[derive(Debug, Clone, Copy)]
pub enum UserFaultKind {
    StorePageFault,
    LoadPageFault,
    InstructionPageFault,
    IllegalInstruction,
    Breakpoint,
    /// HAL 无法分类的异常（polyhal-trap 补丁新增，见其 README；
    /// la 上如取指地址错误 ADEF）。
    Unhandled,
}

/// 一次用户态异常的信息。
#[derive(Debug, Clone, Copy)]
pub struct UserFault {
    pub kind: UserFaultKind,
    /// 出错地址 / 指令编码 / 架构异常码（Unhandled 时）。
    pub info: usize,
    /// 异常发生时的用户 PC。
    pub pc: usize,
}

/// 把用户态来源的陷阱分类为致命异常；非致命（时钟/中断/已消化等）
/// 返回 None，由运行循环继续执行。
pub fn fatal_fault(trap_type: TrapType) -> Option<(UserFaultKind, usize)> {
    match trap_type {
        TrapType::Breakpoint => Some((UserFaultKind::Breakpoint, 0)),
        TrapType::StorePageFault(addr) => Some((UserFaultKind::StorePageFault, addr)),
        TrapType::LoadPageFault(addr) => Some((UserFaultKind::LoadPageFault, addr)),
        TrapType::InstructionPageFault(addr) => Some((UserFaultKind::InstructionPageFault, addr)),
        TrapType::IllegalInstruction(ins) => Some((UserFaultKind::IllegalInstruction, ins)),
        TrapType::Unhandled(code) => Some((UserFaultKind::Unhandled, code)),
        // Timer / Irq / SysCall / Absorbed（la 非对齐模拟成功）/ Unknown：
        // 非致命
        _ => None,
    }
}

/// 统一的中断/异常入口（两种架构共用），由 polyhal-trap 分发调用。
#[polyhal::arch_interrupt]
fn kernel_interrupt(ctx: &mut TrapFrame, trap_type: TrapType) {
    match trap_type {
        TrapType::Timer => {
            TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
            set_next_timer(current_time() + Duration::from_millis(config::TICK_MS));
        }
        TrapType::Breakpoint => {
            // 用户态断点由运行循环按致命异常处置；内核态断点是启动自检
            if !ctx.from_user() {
                BREAK_TICKS.fetch_add(1, Ordering::Relaxed);
            }
        }
        TrapType::SysCall | TrapType::Absorbed | TrapType::Unknown => {}
        TrapType::Irq(_) | TrapType::SupervisorExternal => {
            log::warn!("unhandled irq: {:?}", trap_type);
        }
        TrapType::StorePageFault(_)
        | TrapType::LoadPageFault(_)
        | TrapType::InstructionPageFault(_)
        | TrapType::IllegalInstruction(_)
        | TrapType::Unhandled(_) => {
            // 用户来源由运行循环处置；内核来源是内核 bug，不容忍
            if !ctx.from_user() {
                panic!(
                    "kernel-origin trap {:?} @ pc {:#x}",
                    trap_type,
                    ctx[TrapFrameArgs::SEPC]
                );
            }
        }
    }
}
