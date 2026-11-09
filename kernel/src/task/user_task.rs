//! 用户任务的孵化与运行循环：原 user.rs 的全部职责迁入此处。
//!
//! 孵化（spawn_user）：建地址空间 → 加载 ELF → 建栈 → 初始 TrapFrame
//! → 建任务 → 登记注册表 → 入队。所有可失败步骤在提交（登记+入队）
//! 之前完成，失败不留下半成品（pid 允许出现空洞，见注册表说明）。
//!
//! 运行循环（user_task_entry）：运行在任务自己的内核栈上——这是
//! run_user_task 续体机制的落点，也是"每任务一栈"不变性的消费者：
//! 进用户态前激活本任务页表，逃逸回来按完整 TrapType 消费
//! syscall/异常事件（vendor 补丁后信息不再降维），在逃逸点做时间片
//! 判定，exit/fault 走统一的退出路径。
//!
//! rv 侧构造初始 TrapFrame 的时机约束：TrapFrame::new 拷贝当前
//! sstatus，回用户态依赖 SPP=0/SPIE=1（用户态开中断）稳态；因此
//! spawn 必须发生在进入任务时代（关中断）之前的开中断阶段，
//! 见 doc/ostd-contracts.md task 契约"孵化时机"。

use alloc::boxed::Box;

use polyhal_trap::{
    trap::{run_user_task, TrapType},
    trapframe::{TrapFrame, TrapFrameArgs},
};

use crate::{
    elf::{self, ElfError},
    mm::address_space::{UserAddressSpace, USER_STACK_TOP},
    syscall::{self, Flow},
    trap::{self, UserFault},
};

use super::{
    sched::{self, current_ptr},
    task::{Pid, Task, TaskBody},
    ExitInfo, REGISTRY,
};

/// 被用户态致命异常杀死时的退出码。Linux 将死亡原因编码进 wait
/// status 位域；当前以 128+11（SIGSEGV 的 shell 惯例值）作简化占位，
/// 偏差记录在 doc/ostd-contracts.md，wait 语义实现时统一编码。
pub const FAULT_EXIT_CODE: i32 = 128 + 11;

/// 孵化失败原因。
#[derive(Debug)]
pub enum SpawnError {
    /// 内核栈、数据页、页表页或管理元数据不足。
    OutOfMemory,
    /// ELF 解析/加载失败（程序从未运行）。
    Load(ElfError),
}

/// 孵化一个用户任务并加入就绪队列，返回 pid。
///
/// 调用前提：内核页表活动（rv 侧新空间复制内核半区需要内核根）；
/// 调用时机见模块头（rv sstatus 稳态约束）。
pub fn spawn_user(name: &'static str, elf: &[u8]) -> Result<Pid, SpawnError> {
    if elf.is_empty() {
        return Err(SpawnError::Load(ElfError::Truncated));
    }
    // pid 先分配（失败路径会产生空洞，仅要求唯一性，见注册表说明）
    let pid = super::registry::alloc_pid();

    // —— 可失败段 ——
    let mut space = UserAddressSpace::new().map_err(|_| SpawnError::OutOfMemory)?;
    let entry = elf::load_elf(&mut space, elf).map_err(SpawnError::Load)?;
    space.map_stack().map_err(|_| SpawnError::OutOfMemory)?;
    let mut frame = TrapFrame::new();
    frame[TrapFrameArgs::SEPC] = entry;
    frame[TrapFrameArgs::SP] = USER_STACK_TOP;
    // rv：TrapFrame::new 拷贝当前 sstatus，必须保证回用户态时
    // SPP=0 + SPIE=1（用户态开中断）；loongarch64 侧 new 显式
    // 设 prmd=PLV3|PIE，无此约束。
    #[cfg(target_arch = "riscv64")]
    assert!(
        frame.from_user(),
        "user TrapFrame must re-enter U-mode (check sstatus SPP/SPIE)"
    );
    let task = Task::new_user(pid, name, frame).map_err(|_| SpawnError::OutOfMemory)?;

    // —— 提交段：此后不再失败 ——
    super::registry::register(pid, name, Some(crate::mm::address_space::LocalSpace(space)));
    sched::enqueue(Box::new(task));
    Ok(pid)
}

/// 一轮循环结束后的去向。
enum Action {
    /// 回用户态继续。
    Continue,
    /// 让出 CPU（主动 yield 或时间片用尽）。
    Yield,
    /// 任务终止（exit 或致命异常）。
    Exit(ExitInfo),
}

/// 用户任务入口：在自己（任务）的内核栈上运行，直到 exit/被杀。
pub fn user_task_entry() -> ! {
    let pid = {
        let task = current_ptr();
        // SAFETY: 入口只在调度器切入后执行，current 有效且独占。
        unsafe {
            match (*task).body {
                TaskBody::User { pid, .. } => pid,
                TaskBody::Kernel(_) => panic!("kernel task entered user entry"),
            }
        }
    };

    loop {
        // 一轮 = 激活页表 → 进用户态 → 消费一次逃逸。
        // 对当前任务的 &mut 借用不跨 yield/exit（切换会经调度器改任务）。
        let action = {
            let task = current_ptr();
            // SAFETY: 本任务是 current，单核关中断下独占；借用止于本块。
            unsafe {
                let TaskBody::User { frame, .. } = &mut (*task).body else {
                    panic!("user task lost its body");
                };
                // 每轮激活本任务页表：上次 yield 后其他任务的表可能上过。
                // REGISTRY 锁不跨 run_user_task（用户态执行期间不持锁）。
                {
                    let reg = REGISTRY.lock();
                    let rec = reg
                        .records
                        .iter()
                        .find(|r| r.pid == pid)
                        .expect("user task unregistered");
                    rec.space
                        .as_ref()
                        .expect("running user task lost its space")
                        .as_space()
                        .activate();
                }
                let trap_type = run_user_task(frame);
                match trap_type {
                    TrapType::SysCall => {
                        // 只处理来自用户的系统调用；riscv64 内核自身 SBI
                        // ecall 理论上不会逃逸到此处，防御性忽略
                        if frame.from_user() {
                            let flow = {
                                let reg = REGISTRY.lock();
                                let rec = reg
                                    .records
                                    .iter()
                                    .find(|r| r.pid == pid)
                                    .expect("user task unregistered");
                                let space = rec
                                    .space
                                    .as_ref()
                                    .expect("running user task lost its space");
                                syscall::dispatch(frame, pid, space.as_space())
                            };
                            // 恰好推进一次 syscall PC：polyhal 对 SysCall
                            // 不推进，重复/遗漏都会破坏用户执行流
                            frame.syscall_ok();
                            match flow {
                                Flow::Continue => Action::Continue,
                                Flow::Yield => Action::Yield,
                                Flow::Exited(code) => Action::Exit(ExitInfo::exited(code)),
                            }
                        } else {
                            Action::Continue
                        }
                    }
                    TrapType::Timer
                    | TrapType::Irq(_)
                    | TrapType::SupervisorExternal
                    | TrapType::Absorbed  // la 非对齐模拟成功，恢复执行
                    | TrapType::Unknown => Action::Continue,
                    fatal => {
                        // 用户态致命异常（含 vendor 补丁后的 Unhandled）：
                        // 终止任务而不是带走内核
                        if !frame.from_user() {
                            panic!("kernel-origin trap escaped to user loop: {:?}", fatal);
                        }
                        let (kind, info) =
                            trap::fatal_fault(fatal).expect("fatal_fault covers fatal traps");
                        Action::Exit(ExitInfo {
                            code: FAULT_EXIT_CODE,
                            fault: Some(UserFault {
                                kind,
                                info,
                                pc: frame[TrapFrameArgs::SEPC],
                            }),
                        })
                    }
                }
            }
        };

        // 借用已结束，在此做调度决策
        match action {
            Action::Exit(info) => sched::exit_current(info),
            Action::Yield => sched::yield_now(),
            Action::Continue => {
                // 时间片判定：tick 前进即让出；切入侧 promote 刷新
                // slice_tick，这里只比较（固定 1 tick 轮转）
                let now = crate::TIMER_TICKS.load(core::sync::atomic::Ordering::Relaxed);
                let slice_tick = {
                    let task = current_ptr();
                    // SAFETY: 短只读借用，不跨任何切换。
                    unsafe { (*task).slice_tick }
                };
                if now != slice_tick {
                    sched::yield_now();
                }
            }
        }
    }
}
