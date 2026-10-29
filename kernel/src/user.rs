//! 用户现场与运行循环：加载、进入用户态、消费 trap 事件、退出与清理。
//!
//! 本轮只有一个用户任务，在启动主核上同步运行；副核继续原地驻留。
//! 不引入调度队列、全局进程管理器。

use polyhal::println;
use polyhal_trap::{
    trap::{run_user_task, EscapeReason},
    trapframe::{TrapFrame, TrapFrameArgs},
};

use crate::{
    elf::{self, ElfError},
    mm::address_space::{UserAddressSpace, USER_STACK_TOP},
    syscall::{self, Flow},
    trap::{self, UserFault},
};

/// 一次用户程序的运行结果
pub enum TaskOutcome {
    /// 程序调用 exit(n) 正常结束
    Exited(i32),
    /// 程序触发致命用户异常（缺页/非法指令/用户态断点），被内核终止
    Faulted(UserFault),
    /// ELF 加载失败，程序从未运行
    LoadFailed(ElfError),
}

/// 运行一个内嵌的用户 ELF：创建地址空间 → 加载 → 进入用户态循环 →
/// 清理 → 返回结果。调用前提：当前 CPU 处于内核页表（riscv64 侧
/// `UserAddressSpace::new` 要从当前 satp 复制内核高位条目）。
pub fn run_user_elf(name: &str, elf: &[u8]) -> TaskOutcome {
    // —— 构建地址空间与加载 ——
    let mut space = UserAddressSpace::new();
    let entry = match elf::load_elf(&mut space, elf) {
        Ok(entry) => entry,
        Err(e) => {
            let outcome = TaskOutcome::LoadFailed(e);
            report(name, &outcome);
            return outcome;
        }
    };
    if let Err(e) = space.map_stack() {
        let outcome = TaskOutcome::LoadFailed(ElfError::MapFailed);
        log::error!("map user stack failed: {:?}", e);
        report(name, &outcome);
        return outcome;
    }

    // —— 用户现场：入口与栈 ——
    let mut cx = TrapFrame::new();
    cx[TrapFrameArgs::SEPC] = entry;
    cx[TrapFrameArgs::SP] = USER_STACK_TOP;
    // riscv64 侧 TrapFrame::new 拷贝当前 sstatus，进入用户态依赖
    // SPP=0（先前特权级为用户）+ SPIE=1（用户态开中断）；启动路径上
    // 这由启动自检后的中断状态保证，这里显式校验，防止未来改动引入
    // 静默错误。loongarch64 侧 TrapFrame::new 显式设 prmd=PLV3|PIE。
    #[cfg(target_arch = "riscv64")]
    assert!(
        cx.from_user(),
        "user TrapFrame must re-enter U-mode (check sstatus SPP/SPIE)"
    );

    // —— 运行循环 ——
    space.activate();
    let mut exit_code = None;
    let mut fault: Option<UserFault> = None;
    loop {
        let reason = run_user_task(&mut cx);
        match reason {
            EscapeReason::SysCall => {
                // 只处理来自用户的系统调用（take 会清除事件；
                // riscv64 内核 SBI ecall 同样产生 SysCall 原因）
                if trap::take_user_syscall() {
                    match syscall::dispatch(&mut cx, &space) {
                        Flow::Continue => {
                            // 恰好推进一次 syscall PC：polyhal 对 SysCall
                            // 不推进，重复/遗漏都会破坏用户执行流
                            cx.syscall_ok();
                        }
                        Flow::Exited(code) => {
                            exit_code = Some(code);
                            break;
                        }
                    }
                }
            }
            EscapeReason::Timer | EscapeReason::IRQ | EscapeReason::NoReason => {
                // 时钟在回调里已处理；NoReason 可能是用户异常（事件在
                // trap.rs 登记）或 loongarch64 非对齐访问模拟，继续之前
                // 先看是否有致命异常
                if let Some(f) = trap::take_user_fault() {
                    fault = Some(f);
                    break;
                }
            }
        }
    }

    // —— 清理：先切回内核页表（内含全量 TLB flush，此后 TLB 不再引用
    // 用户页表内容），再 drop 地址空间（释放用户数据页与页表页）——
    space.deactivate();
    drop(space);

    let outcome = match (&exit_code, &fault) {
        (Some(code), _) => TaskOutcome::Exited(*code),
        (None, Some(f)) => TaskOutcome::Faulted(*f),
        (None, None) => unreachable!("user loop must end with exit or fault"),
    };
    report(name, &outcome);
    outcome
}

/// 向启动控制台报告一次用户程序运行结果
fn report(name: &str, outcome: &TaskOutcome) {
    match outcome {
        TaskOutcome::Exited(code) => {
            println!("[user] {}: exited with status {}", name, code);
        }
        TaskOutcome::Faulted(f) => {
            println!(
                "[user] {}: killed by {:?} @ {:#x}, pc {:#x}",
                name, f.kind, f.info, f.pc
            );
        }
        TaskOutcome::LoadFailed(e) => {
            println!("[user] {}: load failed: {:?}", name, e);
        }
    }
}
