//! 中断/异常处理。
//!
//! polyhal-trap 在 ctor（Cpu 阶段）自动完成架构初始化：
//! - riscv64:     设 stvec、sie、timer
//! - loongarch64: 设 eentry、ecfg、tlb 填充回调、timer
//!
//! 内核侧只需通过 `#[polyhal::arch_interrupt]` 挂接统一回调。
//!
//! 本模块新增的职责：用户态来源的异常与系统调用不在这里完成处理，
//! 只做来源判定与事件登记，由用户任务运行循环（user.rs）消费：
//! TrapType 携带完整的异常信息（缺页地址等），EscapeReason 则是有损
//! 的（只剩 NoReason）。

use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use polyhal::timer::{current_time, set_next_timer};
use polyhal_trap::trap::TrapType;
use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};
use spin::Mutex;

use crate::{config, TIMER_TICKS};

/// 用户异常的种类（对应用户程序可能触发的 TrapType 子集）
#[derive(Debug, Clone, Copy)]
pub enum UserFaultKind {
    StorePageFault,
    LoadPageFault,
    InstructionPageFault,
    IllegalInstruction,
    Breakpoint,
}

/// 一次用户态异常的信息
#[derive(Debug, Clone, Copy)]
pub struct UserFault {
    pub kind: UserFaultKind,
    /// 出错地址（非法指令时为指令编码）
    pub info: usize,
    /// 异常发生时的用户 PC
    pub pc: usize,
}

/// 回调登记的“来自用户的系统调用”事件。
/// riscv64 上内核自身的 SBI ecall 同样表现为 TrapType::SysCall，
/// 因此不能用 EscapeReason 单独区分，必须带来源判定。
static PENDING_USER_SYSCALL: AtomicBool = AtomicBool::new(false);

/// 回调登记的用户异常（None 表示当前没有未消费的异常）
static PENDING_USER_FAULT: Mutex<Option<UserFault>> = Mutex::new(None);

/// 判断异常是否来自用户权限级。
///
/// riscv64：trap 时硬件把先前特权级写入 sstatus.SPP，polyhal-trap 已把
/// sstatus 存入 TrapFrame（TrapFrame::from_user）。loongarch64：prmd.PPLV
/// 字段（bit 1:0）记录先前特权级。polyhal-trap 未提供 loongarch64 侧的
/// 封装，这里出现 `#[cfg(target_arch)]`（CSR 语义无法通用表达）。
fn is_from_user(ctx: &TrapFrame) -> bool {
    #[cfg(target_arch = "riscv64")]
    {
        ctx.from_user()
    }
    #[cfg(target_arch = "loongarch64")]
    {
        ctx.prmd & 0x3 != 0
    }
}

/// 登记用户异常（后到的覆盖先到的：任务在首个致命异常后即被终止，
/// 不会积累多个）。
fn record_user_fault(kind: UserFaultKind, info: usize, pc: usize) {
    *PENDING_USER_FAULT.lock() = Some(UserFault { kind, info, pc });
}

/// 取走“来自用户的系统调用”事件（有则清除并返回 true）
pub fn take_user_syscall() -> bool {
    PENDING_USER_SYSCALL.swap(false, Ordering::SeqCst)
}

/// 取走登记的用户异常（如果有）
pub fn take_user_fault() -> Option<UserFault> {
    PENDING_USER_FAULT.lock().take()
}

/// 缺页异常的分发：来自用户则登记异常信息，来自内核则维持现有 panic 策略
fn handle_page_fault(ctx: &TrapFrame, from_user: bool, kind: UserFaultKind, addr: usize) {
    if from_user {
        record_user_fault(kind, addr, ctx[TrapFrameArgs::SEPC]);
    } else {
        panic!("page fault @ {:#x}", addr);
    }
}

/// 统一的中断/异常入口（两种架构共用），由 polyhal-trap 分发调用。
#[polyhal::arch_interrupt]
fn kernel_interrupt(ctx: &mut TrapFrame, trap_type: TrapType) {
    let from_user = is_from_user(ctx);
    match trap_type {
        TrapType::Breakpoint => {
            if from_user {
                // 用户态断点视为异常终止（内核侧 ebreak 仍是启动自检）
                record_user_fault(UserFaultKind::Breakpoint, 0, ctx[TrapFrameArgs::SEPC]);
            } else {
                log::debug!("breakpoint @ {:#x}", ctx[TrapFrameArgs::SEPC]);
            }
        }
        TrapType::SysCall => {
            // 只登记来自用户态的系统调用；内核态 ecall（如 riscv64 SBI）
            // 不是用户请求，交由 polyhal/SBI 自身路径处理
            if from_user {
                PENDING_USER_SYSCALL.store(true, Ordering::SeqCst);
            }
        }
        TrapType::Timer => {
            TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
            set_next_timer(current_time() + Duration::from_millis(config::TICK_MS));
        }
        TrapType::StorePageFault(p) => {
            handle_page_fault(ctx, from_user, UserFaultKind::StorePageFault, p)
        }
        TrapType::LoadPageFault(p) => {
            handle_page_fault(ctx, from_user, UserFaultKind::LoadPageFault, p)
        }
        TrapType::InstructionPageFault(p) => {
            handle_page_fault(ctx, from_user, UserFaultKind::InstructionPageFault, p)
        }
        TrapType::IllegalInstruction(ins) => {
            if from_user {
                record_user_fault(
                    UserFaultKind::IllegalInstruction,
                    ins,
                    ctx[TrapFrameArgs::SEPC],
                );
            } else {
                panic!("illegal instruction {:#x}", ins);
            }
        }
        other => {
            log::warn!("unhandled trap: {:?}", other);
        }
    }
}
