//! 中断/异常处理。
//!
//! polyhal-trap 在 ctor（Cpu 阶段）自动完成架构初始化：
//! - riscv64:     设 stvec、sie、timer
//! - loongarch64: 设 eentry、ecfg、tlb 填充回调、timer
//!
//! 内核侧只需通过 `#[polyhal::arch_interrupt]` 挂接统一回调。

use core::{sync::atomic::Ordering, time::Duration};

use polyhal::timer::{current_time, set_next_timer};
use polyhal_trap::trap::TrapType;
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::{config, TIMER_TICKS};

/// 统一的中断/异常入口（两种架构共用），由 polyhal-trap 分发调用。
#[polyhal::arch_interrupt]
fn kernel_interrupt(ctx: &mut TrapFrame, trap_type: TrapType) {
    match trap_type {
        TrapType::Breakpoint => {
            log::debug!("breakpoint @ {:#x}", ctx[TrapFrameArgs::SEPC]);
        }
        TrapType::Timer => {
            TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
            set_next_timer(current_time() + Duration::from_millis(config::TICK_MS));
        }
        TrapType::StorePageFault(p)
        | TrapType::LoadPageFault(p)
        | TrapType::InstructionPageFault(p) => {
            panic!("page fault @ {:#x}", p);
        }
        TrapType::IllegalInstruction(ins) => {
            panic!("illegal instruction {:#x}", ins);
        }
        other => {
            log::warn!("unhandled trap: {:?}", other);
        }
    }
}
