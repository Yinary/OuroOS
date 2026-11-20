//! 用户任务的孵化（ELF → 地址空间 → 初始现场 → 入队）与运行循环
//! （run_user_task + TrapType 消费 + 时间片判定）。契约见 docs/ostd-contracts.md §3。
#![deny(unsafe_code)]

use alloc::boxed::Box;

use polyhal_trap::{
    trap::{run_user_task, TrapType},
    trapframe::{TrapFrame, TrapFrameArgs},
};

use crate::{
    elf::{self, ElfError},
    mm::{address_space::UserAddressSpace, user_access},
    sigframe::fill_siginfo,
    syscall::{signal::SA_RESTART, signal::SIGSETSIZE, sysnr, Errno, Flow},
    trap::{self, UserFault},
};

use super::{
    sched,
    signal::{
        default_action, fault_siginfo, force_signal, send_signal, DefaultAction, SigInfoSlot,
        SignalDisposition, SignalSet, SignalSetExt, SIGKILL, SIGSEGV, SIGSTOP, SIG_DFL, SIG_IGN,
        SI_TKILL,
    },
    task::{Pid, Task, TaskBody, WaitReason},
    ExitInfo, REGISTRY,
};

/// 孵化失败原因。
#[derive(Debug)]
pub enum SpawnError {
    /// 内核栈、数据页、页表页或管理元数据不足。
    OutOfMemory,
    /// ELF 解析/加载失败（程序从未运行）。
    Load(ElfError),
    /// 没有可信启动熵，拒绝构造可预测的 AT_RANDOM。
    NoEntropy,
}

/// 孵化一个用户任务并加入就绪队列，返回 pid。
///
/// 调用前提：内核页表活动（rv 侧新空间复制内核半区需要内核根）；
pub fn spawn_user(name: &'static str, elf: &[u8]) -> Result<Pid, SpawnError> {
    if elf.is_empty() {
        return Err(SpawnError::Load(ElfError::Truncated));
    }
    // pid 先分配（失败路径会产生空洞，仅要求唯一性，见注册表说明）
    let pid = super::registry::alloc_pid();

    // —— 可失败段 ——
    let mut space = UserAddressSpace::new().map_err(|_| SpawnError::OutOfMemory)?;
    let entry = elf::load_elf(&mut space, elf).map_err(SpawnError::Load)?;
    space.init_heap();
    space.map_stack().map_err(|_| SpawnError::OutOfMemory)?;
    let mut frame = TrapFrame::new();
    frame[TrapFrameArgs::SEPC] = entry.entry;
    let mut arg0 = alloc::string::String::new();
    arg0.try_reserve_exact(name.len())
        .map_err(|_| SpawnError::OutOfMemory)?;
    arg0.push_str(name);
    let sp = super::exec::stack(&space, &[arg0], &[], &entry, None, name).map_err(|e| {
        if e == Errno::Io {
            SpawnError::NoEntropy
        } else {
            SpawnError::OutOfMemory
        }
    })?;
    frame[TrapFrameArgs::SP] = sp;
    let task = Task::new_user(pid, name, frame).map_err(|_| SpawnError::OutOfMemory)?;

    let fs = crate::fs::context::Context::new().map_err(|_| SpawnError::OutOfMemory)?;
    let task = Box::try_new(task).map_err(|_| SpawnError::OutOfMemory)?;
    super::registry::reserve()?;
    sched::reserve_task().map_err(|_| SpawnError::OutOfMemory)?;
    super::proc_table_reserve().map_err(|_| SpawnError::OutOfMemory)?;
    // —— 提交段：此后不再失败 ——
    super::registry::register(pid, name, Some(crate::mm::address_space::LocalSpace(space)));
    {
        let mut reg = REGISTRY.lock();
        if let Some(r) = reg.records.iter_mut().find(|r| r.pid == pid) {
            r.fs = Some(fs);
            r.parent = super::INIT_PID.load(core::sync::atomic::Ordering::Relaxed);
        }
    }
    super::proc_table_push(
        pid,
        name,
        super::INIT_PID.load(core::sync::atomic::Ordering::Relaxed),
        true,
    );
    sched::enqueue(task);
    Ok(pid)
}

/// 一轮循环结束后的去向。
enum Action {
    /// 回用户态继续。
    Continue,
    /// 让出 CPU（主动 yield 或时间片用尽）。
    Yield,
    /// 挂起等待，醒来后重执行当前系统调用。
    Wait(WaitReason),
    /// 任务终止（exit 或致命异常）。
    Exit(ExitInfo),
}

/// 用户任务入口：在自己（任务）的内核栈上运行，直到 exit/被杀。
pub fn user_task_entry() -> ! {
    sched::reap_switched();
    let (pid, mut frame) = match sched::take_body() {
        TaskBody::User { frame, pid } => (pid, frame),
        TaskBody::Kernel(_) => panic!("kernel task entered user entry"),
    };
    let mut sleep_deadline = None;
    // 循环局部等待状态：sigsuspend 的旧屏蔽集合、sigtimedwait 的等待集与截止。
    let mut sigsuspend_saved: Option<SignalSet> = None;
    let mut timedwait: Option<(SignalSet, core::time::Duration)> = None;
    // 最近一次等待的 syscall 是否尚未完成（PC 停在 ecall），供
    // sigsuspend 期间的投递检查点补 -EINTR 完成。
    let mut wait_uncompleted = false;

    loop {
        // 一轮 = 激活页表 + 投递检查点 → 进用户态 → 消费一次逃逸。
        let kernel_start;
        let action = {
            // 每轮激活本任务页表；REGISTRY 锁不跨 run_user_task。
            // 致命信号在此记下，锁释放后跳过用户态直接退出。
            let signal_exit = {
                let mut reg = REGISTRY.lock();
                let rec = reg
                    .records
                    .iter_mut()
                    .find(|r| r.pid == pid)
                    .expect("user task unregistered");
                rec.space
                    .as_ref()
                    .expect("running user task lost its space")
                    .as_space()
                    .activate();
                // 投递检查点：每次回用户态至多处理一个信号；handler 在此建帧。
                let blocked_now = rec.signal.blocked();
                match rec.signal.take_deliverable(blocked_now) {
                    None => None,
                    Some((sig, slot)) => {
                        let d = rec.signal.disposition(sig);
                        if d.handler == SIG_DFL || d.handler == SIG_IGN {
                            delivery_verdict(sig, slot, d)
                        } else {
                            // 真投递：同一锁段内建帧并换入 handler 期间的屏蔽集合；
                            // 失败按 Signaled{SIGSEGV} 锁外退出。
                            if sigsuspend_saved.is_some() && wait_uncompleted {
                                frame.syscall_ok();
                                frame[TrapFrameArgs::RET] =
                                    crate::syscall::to_abi(Err(Errno::Interrupted));
                                wait_uncompleted = false;
                            }
                            // 帧内 uc_sigmask 存 save_mask，sigreturn 恢复；
                            // 建帧时取走 saved。
                            let save_mask = sigsuspend_saved.take().unwrap_or(blocked_now);
                            let space = rec
                                .space
                                .as_ref()
                                .expect("running user task lost its space")
                                .as_space();
                            match crate::sigframe::build_deliver(
                                &mut frame,
                                space,
                                sig,
                                &slot,
                                &d,
                                blocked_now,
                                save_mask,
                                // SA_ONSTACK 选栈依据：当前登记的备用栈。
                                rec.signal.alt_stack(),
                            ) {
                                Ok(new_blocked) => {
                                    rec.signal.setmask(new_blocked);
                                    None
                                }
                                Err(_) => Some(ExitInfo::Signaled {
                                    sig: SIGSEGV,
                                    fault: None,
                                }),
                            }
                        }
                    }
                }
            };
            if let Some(info) = signal_exit {
                sched::exit_current(info);
            }
            let user_start = polyhal::timer::current_time();
            let trap_type = run_user_task(&mut frame);
            kernel_start = polyhal::timer::current_time();
            {
                let mut reg = REGISTRY.lock();
                if let Some(rec) = reg.records.iter_mut().find(|r| r.pid == pid) {
                    rec.user_ns = rec.user_ns.saturating_add(
                        kernel_start
                            .saturating_sub(user_start)
                            .as_nanos()
                            .min(u64::MAX as u128) as u64,
                    );
                }
            }
            match trap_type {
                TrapType::SysCall => {
                    // 只处理来自用户的系统调用，其余防御性忽略
                    if frame.from_user() {
                        // dispatch 在 REGISTRY 锁内取空间与 fs 上下文；
                        // 进程级调用（process_call 会再取 REGISTRY）
                        // 必须在锁外执行，非重入锁不可重入。
                        let flow = {
                            let mut reg = REGISTRY.lock();
                            let rec = reg
                                .records
                                .iter_mut()
                                .find(|r| r.pid == pid)
                                .expect("user task unregistered");
                            let space = rec
                                .space
                                .as_mut()
                                .expect("running user task lost its space");
                            crate::syscall::dispatch(
                                &mut frame,
                                pid,
                                &mut space.0,
                                rec.fs.as_mut().expect("user fs context"),
                                &mut rec.signal,
                            )
                        };
                            // 恰好推进一次 syscall PC；Wait 不推（醒来重执行重查），
                            // SigReturn 现场已恢复，SEPC 无需推进。
                            let outcome = match flow {
                                Flow::Process => process_call(
                                    pid,
                                    &mut frame,
                                    &mut sleep_deadline,
                                    &mut sigsuspend_saved,
                                    &mut timedwait,
                                    &mut wait_uncompleted,
                                ),
                                Flow::Wait(reason) => ProcessResult::Wait(reason),
                                Flow::SigReturn => ProcessResult::Restored,
                                _ => ProcessResult::Done,
                            };
                            if matches!(outcome, ProcessResult::Done) {
                                frame.syscall_ok();
                            }
                            // 挂起等待：不持任何借用与锁，切走直到被唤醒；
                            // 醒来后从 syscall 指令重新执行（Mesa 风格重查）
                            let wait_reason = match (&flow, &outcome) {
                                (Flow::Wait(reason), _) => Some(*reason),
                                (Flow::Process, ProcessResult::Wait(reason)) => Some(*reason),
                                _ => None,
                            };
                            if let Some(reason) = wait_reason {
                                Action::Wait(reason)
                            } else {
                                match flow {
                                    Flow::Continue | Flow::Process | Flow::Wait(_)
                                    | Flow::SigReturn => Action::Continue,
                                    Flow::Yield => Action::Yield,
                                    Flow::Exited(code) => Action::Exit(ExitInfo::exited(code)),
                                }
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
                    TrapType::AddressNotAligned(addr) => {
                        if !frame.from_user() {
                            panic!("kernel-origin misaligned trap @ {:#x}", addr);
                        }
                        let result = {
                            let reg = REGISTRY.lock();
                            let space = reg
                                .records
                                .iter()
                                .find(|r| r.pid == pid)
                                .and_then(|r| r.space.as_ref())
                                .expect("running user task lost its space");
                            trap::emulate_unaligned(&mut frame, space.as_space(), addr)
                        };
                        match result {
                            Ok(()) => Action::Continue,
                            Err(error) => {
                                let kind = error.fault_kind();
                                // force 投递：不可屏蔽，由下一轮检查点消费。
                                let (sig, code) = fault_siginfo(kind);
                                force_signal(
                                    pid,
                                    sig,
                                    SigInfoSlot {
                                        code,
                                        addr,
                                        fault: Some(UserFault {
                                            kind,
                                            info: addr,
                                            pc: frame[TrapFrameArgs::SEPC],
                                        }),
                                        ..Default::default()
                                    },
                                );
                                Action::Continue
                            }
                        }
                    }
                    fault @ (TrapType::StorePageFault(_) | TrapType::LoadPageFault(_) | TrapType::InstructionPageFault(_)) => {
                        if !frame.from_user() { panic!("kernel-origin page fault: {:?}", fault); }
                        let (kind, addr) = trap::fatal_fault(fault).expect("page fault classification");
                        let access = match fault {
                            TrapType::StorePageFault(_) => polyhal::pagetable::MappingFlags::W,
                            TrapType::LoadPageFault(_) => polyhal::pagetable::MappingFlags::R,
                            _ => polyhal::pagetable::MappingFlags::X,
                        } | polyhal::pagetable::MappingFlags::U;
                        let result = {
                            let reg = REGISTRY.lock();
                            reg.records.iter().find(|r| r.pid == pid)
                                .and_then(|r| r.space.as_ref())
                                .ok_or(crate::mm::address_space::MapError::NotMapped)
                                .and_then(|s| { let space = s.as_space(); if space.translate(addr).is_some() { return Err(crate::mm::address_space::MapError::PermissionDenied); } space.ensure_access(addr, access) })
                        };
                        if result.is_ok() { Action::Continue } else {
                            use crate::mm::address_space::MapError;
                            let kind = match result {
                                Err(MapError::FileFault) => trap::UserFaultKind::FileBusError,
                                Err(MapError::FileIo) => trap::UserFaultKind::FileIoError,
                                Err(MapError::OutOfMemory) => trap::UserFaultKind::UserFaultOom,
                                _ => kind,
                            };
                            // force 投递：不可屏蔽，由下一轮检查点消费。
                            let (sig, code) = fault_siginfo(kind);
                            force_signal(
                                pid,
                                sig,
                                SigInfoSlot {
                                    code,
                                    addr,
                                    fault: Some(UserFault {
                                        kind,
                                        info: addr,
                                        pc: frame[TrapFrameArgs::SEPC],
                                    }),
                                    ..Default::default()
                                },
                            );
                            Action::Continue
                        }
                    }
                    fatal => {
                        // 用户态致命异常（含 vendor 补丁后的 Unhandled）：
                        // 终止任务而不是带走内核
                        if !frame.from_user() {
                            panic!("kernel-origin trap escaped to user loop: {:?}", fatal);
                        }
                        let (kind, info) =
                            trap::fatal_fault(fatal).expect("fatal_fault covers fatal traps");
                        // force 投递同上：由下一轮循环顶检查点消费。
                        let (sig, code) = fault_siginfo(kind);
                        force_signal(
                            pid,
                            sig,
                            SigInfoSlot {
                                code,
                                addr: info,
                                fault: Some(UserFault {
                                    kind,
                                    info,
                                    pc: frame[TrapFrameArgs::SEPC],
                                }),
                                ..Default::default()
                            },
                        );
                        Action::Continue
                    }
                }
        };

        {
            let spent = polyhal::timer::current_time()
                .saturating_sub(kernel_start)
                .as_nanos()
                .min(u64::MAX as u128) as u64;
            let mut reg = REGISTRY.lock();
            if let Some(rec) = reg.records.iter_mut().find(|r| r.pid == pid) {
                rec.system_ns = rec.system_ns.saturating_add(spent);
            }
        }
        // 借用已结束，在此做调度决策
        match action {
            Action::Exit(info) => sched::exit_current(info),
            Action::Yield => sched::yield_now(),
            // Wait：先做可落睡的 park 检查，睡醒后补一次不落睡的重查。
            Action::Wait(reason) => {
                let outcome = park_check_signals(
                    pid,
                    reason,
                    &mut frame,
                    &mut sleep_deadline,
                    &mut timedwait,
                    true,
                );
                wait_uncompleted = outcome != ParkOutcome::Completed;
                if outcome == ParkOutcome::Parked {
                    // 睡醒后的不落睡重查。
                    let outcome = park_check_signals(
                        pid,
                        reason,
                        &mut frame,
                        &mut sleep_deadline,
                        &mut timedwait,
                        false,
                    );
                    wait_uncompleted = outcome != ParkOutcome::Completed;
                }
            }
            Action::Continue => {
                // 时间片起点由切入侧刷新。
                if sched::slice_expired() {
                    sched::yield_now();
                }
            }
        }
    }
}

/// DFL/IGN 处置信号的投递判定：Term/Core 返回 Signaled 死因，
/// Ign/Cont/Stop 丢弃；用户 handler 不经过本函数。
fn delivery_verdict(sig: u8, slot: SigInfoSlot, d: SignalDisposition) -> Option<ExitInfo> {
    if d.handler == SIG_IGN {
        return None;
    }
    match default_action(sig) {
        DefaultAction::Term | DefaultAction::Core => Some(ExitInfo::Signaled {
            sig,
            fault: slot.fault,
        }),
        DefaultAction::Ign | DefaultAction::Cont | DefaultAction::Stop => None,
    }
}

/// 信号是否具有投递后果：用户 handler，或 DFL 且默认动作 Term/Core；
/// SIG_IGN 与 DFL 的 Ign/Cont/Stop 类无后果。
fn has_consequence(sig: u8, d: SignalDisposition) -> bool {
    if d.handler == SIG_DFL {
        matches!(
            default_action(sig),
            DefaultAction::Term | DefaultAction::Core
        )
    } else {
        d.handler != SIG_IGN
    }
}

/// park 快路径一次调用后被等待 syscall 的完成状态（PC 是否停在 ecall）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ParkOutcome {
    /// 发生了一次真实挂起，醒来返回（PC 停在 ecall）。
    Parked,
    /// 未挂起，syscall 未完成（快路径丢弃/重启臂，PC 停在 ecall）。
    Incomplete,
    /// syscall 已完成（EINTR/TwHit 等完成臂，PC 已推进）。
    Completed,
}

/// park 快路径对 peek 到的信号的去向。
enum ParkPeek {
    /// 无可投递信号。
    Empty,
    /// sigtimedwait 等待集内的信号：已 take 消费，以信号号完成。
    TwHit { sig: u8, slot: SigInfoSlot },
    /// 用户 handler（≠DFL/IGN）：不消费，留给循环顶检查点。
    Handler(SignalDisposition),
    /// DFL/IGN：已在锁内 take 消费，按默认动作处置（IGN 为防御分支）。
    Default {
        sig: u8,
        slot: SigInfoSlot,
        d: SignalDisposition,
    },
}

/// park 信号决策：等待集内信号直接完成，用户 handler 不消费并留给
/// 循环顶检查点，DFL/IGN 消费后终止或丢弃。
/// `allow_park` 控制是否落睡；返回 [`ParkOutcome`] 供调用方维护完成状态。
fn park_check_signals(
    pid: Pid,
    reason: WaitReason,
    frame: &mut TrapFrame,
    sleep_deadline: &mut Option<core::time::Duration>,
    timedwait: &mut Option<(SignalSet, core::time::Duration)>,
    allow_park: bool,
) -> ParkOutcome {
    // sigtimedwait 的等待集；Some 即本次挂起属于 rt_sigtimedwait。
    let tw_set = timedwait.map(|(set, _)| set);
    let peeked = {
        let mut reg = REGISTRY.lock();
        let rec = reg
            .records
            .iter_mut()
            .find(|r| r.pid == pid)
            .expect("user task unregistered");
        let blocked = rec.signal.blocked();
        // 先查等待集内信号：命中即消费，不经处置。
        let tw_hit = tw_set.and_then(|set| {
            let mut hidden = blocked;
            hidden |= !set;
            rec.signal.take_deliverable(hidden)
        });
        match tw_hit {
            Some((sig, slot)) => ParkPeek::TwHit { sig, slot },
            None => match rec.signal.peek_deliverable(blocked) {
                None => ParkPeek::Empty,
                Some((sig, _)) => {
                    let d = rec.signal.disposition(sig);
                    if d.handler != SIG_DFL && d.handler != SIG_IGN {
                        // handler 分支不消费；DFL/IGN 分支经 take_deliverable 另取槽。
                        ParkPeek::Handler(d)
                    } else {
                        // IGN 为防御分支。
                        let (sig, slot) = rec
                            .signal
                            .take_deliverable(blocked)
                            .expect("peeked signal still deliverable");
                        ParkPeek::Default { sig, slot, d }
                    }
                }
            },
        }
    };
    match peeked {
        ParkPeek::Empty => {
            if allow_park {
                // 无可投递信号：挂起，醒来后由调用方补一次不落睡的重查。
                sched::park(reason);
                ParkOutcome::Parked
            } else {
                ParkOutcome::Incomplete
            }
        }
        ParkPeek::TwHit { sig, slot } => {
            // uinfo 写失败返回 -EFAULT（信号已消费，不回队）。
            *timedwait = None;
            let ret = match write_uinfo(pid, frame.args()[1], sig, &slot) {
                Ok(()) => sig as usize,
                Err(e) => crate::syscall::to_abi(Err(e)),
            };
            // Wait 路径原欠一次 syscall_ok，完成恰好补上。
            frame.syscall_ok();
            frame[TrapFrameArgs::RET] = ret;
            ParkOutcome::Completed
        }
        ParkPeek::Handler(d) => match reason {
            WaitReason::Deadline(until) => {
                // sigtimedwait 被集合外 handler 信号打断：以 -EINTR 完成。
                if tw_set.is_some() {
                    *timedwait = None;
                    // Wait 路径原欠一次 syscall_ok，EINTR 完成恰好补上。
                    frame.syscall_ok();
                    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Interrupted));
                } else {
                    // nanosleep：清截止时间、回写剩余时间后以 -EINTR 完成。
                    *sleep_deadline = None;
                    let rem_ptr = frame.args()[1];
                    if rem_ptr != 0 {
                        // 剩余时间 timespec：16 字节 secs/nsecs（小端）。
                        let left = until.saturating_sub(polyhal::timer::current_time());
                        let mut rem = [0u8; 16];
                        rem[..8].copy_from_slice(&left.as_secs().to_ne_bytes());
                        rem[8..].copy_from_slice(&(left.subsec_nanos() as u64).to_ne_bytes());
                        // 写失败忽略（不改变返回值）。
                        let reg = REGISTRY.lock();
                        if let Some(rec) = reg.records.iter().find(|r| r.pid == pid) {
                            if let Some(space) = rec.space.as_ref() {
                                let _ = crate::mm::user_access::copy_to_user(
                                    space.as_space(),
                                    rem_ptr,
                                    &rem,
                                );
                            }
                        }
                    }
                    // Wait 路径原欠一次 syscall_ok，EINTR 完成恰好补上。
                    frame.syscall_ok();
                    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Interrupted));
                }
                ParkOutcome::Completed
            }
            // SA_RESTART：不完成不睡，信号留给循环顶检查点。
            WaitReason::Pipe | WaitReason::Children if d.flags & SA_RESTART != 0 => {
                ParkOutcome::Incomplete
            }
            // 其余：完成 syscall 返回 -EINTR；信号留给循环顶检查点。
            _ => {
                frame.syscall_ok();
                frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Interrupted));
                ParkOutcome::Completed
            }
        },
        ParkPeek::Default { sig, slot, d } => {
            if let Some(info) = delivery_verdict(sig, slot, d) {
                // Term/Core：已消费，按默认动作终止。
                sched::exit_current(info);
            }
            // 丢弃即可，由 syscall 重执行重查决定是否继续等。
            ParkOutcome::Incomplete
        }
    }
}

/// 进程级系统调用的处理结果；等待未完成时挂起并保留 syscall PC。
enum ProcessResult {
    Done,
    Wait(WaitReason),
    Replaced,
    /// rt_sigreturn：SEPC 已从信号帧恢复为真实返回点，不再推进。
    Restored,
}
fn process_call(
    parent: Pid,
    frame: &mut TrapFrame,
    sleep_deadline: &mut Option<core::time::Duration>,
    sigsuspend_saved: &mut Option<SignalSet>,
    timedwait: &mut Option<(SignalSet, core::time::Duration)>,
    wait_uncompleted: &mut bool,
) -> ProcessResult {
    let args = frame.args();
    let nr = frame[TrapFrameArgs::SYSCALL];
    let result: Result<usize, Errno> = match nr {
        sysnr::RT_SIGSUSPEND => {
            // rt_sigsuspend(2)：换入新屏蔽集合，睡到出现有后果的信号；
            // handler/DFL-Term/Core 以 -EINTR 完成并留给检查点处置。
            if sigsuspend_saved.is_none() {
                // 首次：读 mask（剥 KILL/STOP）→ 存旧集合 → 换入 → 等。
                if args[1] != SIGSETSIZE {
                    Err(Errno::Invalid)
                } else {
                    match read_sigset(parent, args[0]) {
                        Err(e) => Err(e),
                        Ok(mut new) => {
                            new.del(SIGKILL);
                            new.del(SIGSTOP);
                            let mut reg = REGISTRY.lock();
                            match reg.records.iter_mut().find(|r| r.pid == parent) {
                                Some(rec) => {
                                    *sigsuspend_saved = Some(rec.signal.blocked());
                                    rec.signal.setmask(new);
                                    drop(reg);
                                    return ProcessResult::Wait(WaitReason::Signal);
                                }
                                None => Err(Errno::NoProcess),
                            }
                        }
                    }
                }
            } else {
                // 重入决策：Ign/Cont/Stop 类信号锁内消费丢弃后继续查；
                // 有后果的信号保留，以 -EINTR 完成，交检查点投递/终止。
                let consequence = {
                    let mut reg = REGISTRY.lock();
                    let rec = reg
                        .records
                        .iter_mut()
                        .find(|r| r.pid == parent)
                        .expect("user task unregistered");
                    loop {
                        let blocked = rec.signal.blocked();
                        let Some((sig, _)) = rec.signal.peek_deliverable(blocked) else {
                            break false;
                        };
                        if has_consequence(sig, rec.signal.disposition(sig)) {
                            break true;
                        }
                        // 无后果：不当投递，消费丢弃（同 Linux get_signal）。
                        rec.signal
                            .take_deliverable(blocked)
                            .expect("peeked signal still deliverable");
                    }
                };
                if consequence {
                    // PC 由 Done 路径推进，检查点不再补完成。
                    *wait_uncompleted = false;
                    Err(Errno::Interrupted)
                } else {
                    // 无可投递信号：保留 saved 与临时 mask，重新挂起。
                    return ProcessResult::Wait(WaitReason::Signal);
                }
            }
        }
        sysnr::RT_SIGTIMEDWAIT => {
            // rt_sigtimedwait(2)：等待集合内未屏蔽信号，命中即取出返回
            // 信号号（不经处置）；超时 EAGAIN，集合外 handler 信号打断 -EINTR。
            // 偏差登记 docs/ostd-contracts.md §4.5。
            if let Some((set, deadline)) = *timedwait {
                // 重入：先查命中（Mesa），再查截止。
                let taken = {
                    let mut reg = REGISTRY.lock();
                    reg.records
                        .iter_mut()
                        .find(|r| r.pid == parent)
                        .and_then(|rec| {
                            let mut hidden = rec.signal.blocked();
                            hidden |= !set;
                            rec.signal.take_deliverable(hidden)
                        })
                };
                if let Some((sig, slot)) = taken {
                    *timedwait = None;
                    write_uinfo(parent, args[1], sig, &slot).map(|_| sig as usize)
                } else if polyhal::timer::current_time() >= deadline {
                    *timedwait = None;
                    Err(Errno::Again)
                } else {
                    // 未到截止被假唤醒：带剩余时间重新挂起。
                    return ProcessResult::Wait(WaitReason::Deadline(deadline));
                }
            } else {
                // 首次：读集合与超时；已命中立即返回，否则挂起。
                if args[3] != SIGSETSIZE {
                    Err(Errno::Invalid)
                } else {
                    match read_sigset(parent, args[0]) {
                        Err(e) => Err(e),
                        Ok(mut set) => {
                            set.del(SIGKILL);
                            set.del(SIGSTOP);
                            let taken = {
                                let mut reg = REGISTRY.lock();
                                reg.records
                                    .iter_mut()
                                    .find(|r| r.pid == parent)
                                    .and_then(|rec| {
                                        let mut hidden = rec.signal.blocked();
                                        hidden |= !set;
                                        rec.signal.take_deliverable(hidden)
                                    })
                            };
                            if let Some((sig, slot)) = taken {
                                write_uinfo(parent, args[1], sig, &slot).map(|_| sig as usize)
                            } else {
                                match timedwait_deadline(parent, args[2]) {
                                    Err(e) => Err(e),
                                    Ok(deadline) => {
                                        *timedwait = Some((set, deadline));
                                        return ProcessResult::Wait(WaitReason::Deadline(deadline));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        sysnr::RT_SIGQUEUEINFO => queue_info(parent, args),
        sysnr::SYSINFO => {
            // asm-generic 64 位 struct sysinfo。内存以 KiB 为单位；未统计负载均值。
            let reg = REGISTRY.lock();
            let mut data = [0u8; 112];
            let mem = crate::mm::frame::memory_snapshot();
            data[..8].copy_from_slice(&polyhal::timer::current_time().as_secs().to_ne_bytes());
            data[32..40].copy_from_slice(&mem.total_kib.to_ne_bytes());
            data[40..48].copy_from_slice(&mem.free_kib.to_ne_bytes());
            data[80..82].copy_from_slice(
                &(reg
                    .records
                    .iter()
                    .filter(|r| r.exit.is_none())
                    .count()
                    .min(u16::MAX as usize) as u16)
                    .to_ne_bytes(),
            );
            data[104..108].copy_from_slice(&1024u32.to_ne_bytes());
            reg.records
                .iter()
                .find(|r| r.pid == parent)
                .and_then(|r| r.space.as_ref())
                .ok_or(Errno::NoProcess)
                .and_then(|s| {
                    crate::mm::user_access::copy_to_user(s.as_space(), args[0], &data)
                        .map_err(|_| Errno::Fault)
                })
                .map(|()| 0)
        }
        sysnr::PPOLL => {
            let reg = REGISTRY.lock();
            let checked = (|| {
                let rec = reg
                    .records
                    .iter()
                    .find(|r| r.pid == parent)
                    .ok_or(Errno::NoProcess)?;
                let space = rec.space.as_ref().ok_or(Errno::Invalid)?.as_space();
                if args[3] != 0 {
                    return Err(Errno::NotSupported);
                }
                if args[2] != 0 && sleep_deadline.is_none() {
                    let mut ts = [0; 16];
                    crate::mm::user_access::copy_from_user(space, args[2], &mut ts)
                        .map_err(|_| Errno::Fault)?;
                    let mut bytes = [0; 8];
                    bytes.copy_from_slice(&ts[..8]);
                    let sec = i64::from_ne_bytes(bytes);
                    bytes.copy_from_slice(&ts[8..]);
                    let ns = i64::from_ne_bytes(bytes);
                    if sec < 0 || !(0..1_000_000_000).contains(&ns) {
                        return Err(Errno::Invalid);
                    }
                    *sleep_deadline = Some(
                        polyhal::timer::current_time()
                            .checked_add(core::time::Duration::new(sec as u64, ns as u32))
                            .ok_or(Errno::Invalid)?,
                    );
                }
                crate::fs::context::poll(
                    rec.fs.as_ref().ok_or(Errno::Invalid)?,
                    space,
                    args[0],
                    args[1],
                )
            })();
            if checked == Ok(0) {
                match *sleep_deadline {
                    None => return ProcessResult::Wait(WaitReason::Pipe),
                    Some(d) if polyhal::timer::current_time() < d => {
                        return ProcessResult::Wait(WaitReason::PollUntil(d))
                    }
                    _ => {}
                }
            }
            *sleep_deadline = None;
            checked
        }
        sysnr::NANOSLEEP => {
            // nanosleep(2)：到期返回 0；被打断时回写剩余时间并返回 -EINTR。
            if let Some(until) = *sleep_deadline {
                if polyhal::timer::current_time() < until {
                    return ProcessResult::Wait(WaitReason::Deadline(until));
                }
                *sleep_deadline = None;
                Ok(0)
            } else {
                let reg = REGISTRY.lock();
                let mut request = [0u8; 16];
                let valid = reg
                    .records
                    .iter()
                    .find(|r| r.pid == parent)
                    .and_then(|r| r.space.as_ref())
                    .is_some_and(|s| {
                        crate::mm::user_access::copy_from_user(s.as_space(), args[0], &mut request)
                            .is_ok()
                    });
                if !valid {
                    Err(Errno::Fault)
                } else {
                    let sec = i64::from_ne_bytes(request[..8].try_into().unwrap_or([0; 8]));
                    let ns = i64::from_ne_bytes(request[8..].try_into().unwrap_or([0; 8]));
                    if sec < 0 || !(0..1_000_000_000).contains(&ns) {
                        Err(Errno::Invalid)
                    } else {
                        let until = polyhal::timer::current_time()
                            .checked_add(core::time::Duration::new(sec as u64, ns as u32));
                        if let Some(until) = until {
                            *sleep_deadline = Some(until);
                            return ProcessResult::Wait(WaitReason::Deadline(until));
                        } else {
                            Err(Errno::Invalid)
                        }
                    }
                }
            }
        }
        sysnr::TIMES => {
            let reg = REGISTRY.lock();
            if let Some(rec) = reg.records.iter().find(|r| r.pid == parent) {
                let mut data = [0; 32];
                for (i, ns) in [
                    rec.user_ns,
                    rec.system_ns,
                    rec.child_user_ns,
                    rec.child_system_ns,
                ]
                .iter()
                .enumerate()
                {
                    data[i * 8..i * 8 + 8].copy_from_slice(&(ns / 10_000_000).to_ne_bytes());
                }
                if args[0] != 0
                    && !rec.space.as_ref().is_some_and(|s| {
                        crate::mm::user_access::copy_to_user(s.as_space(), args[0], &data).is_ok()
                    })
                {
                    Err(Errno::Fault)
                } else {
                    Ok((polyhal::timer::current_time().as_millis() / 10) as usize)
                }
            } else {
                Err(Errno::NoProcess)
            }
        }
        sysnr::GETPPID => Ok(REGISTRY
            .lock()
            .records
            .iter()
            .find(|r| r.pid == parent)
            .map_or(0, |r| r.parent)),
        sysnr::EXECVE => match super::exec::exec(parent, [args[0], args[1], args[2]], frame) {
            Ok(()) => return ProcessResult::Replaced,
            Err(e) => Err(e),
        },
        // clone(2) 的 child_tid 参数序是架构 ABI 的一部分：RV64 为
        // (flags, stack, ptid, tls, ctid)，LA64 为 (flags, stack, ptid,
        // ctid, tls)（对照两架构 clone.s 与 Linux fork.c 的拷贝语义）。
        // 归一化为具名参数后再进通用 fork。
        sysnr::CLONE => {
            #[cfg(target_arch = "riscv64")]
            let (tls, child_tid) = (args[3], args[4]);
            #[cfg(target_arch = "loongarch64")]
            let (child_tid, tls) = (args[3], args[4]);
            let _ = tls; // 本内核不支持 CLONE_SET_TLS，参数仅按 ABI 接收
            fork_user(parent, frame, args[0], args[1], child_tid)
        }
        sysnr::WAIT4 => {
            // wait4(2)：wanted <= 0 等任意孩子（无进程组概念，0 与 -1
            // 等价）；>0 指定 pid；其余负值 EINVAL。无可收割孩子时挂起，
            // 无孩子 ECHILD。收割即从注册表删除（生命周期见 mod.rs）。
            // 可请求停止、恢复事件；当前没有产生这两种状态的信号接口。
            if args[2] & !(1 | 2 | 8) != 0 {
                Err(Errno::Invalid)
            } else {
                let wanted = args[0] as i32;
                if wanted < -1 {
                    Err(Errno::Invalid)
                } else {
                    let matches = |r: &super::ProcessRecord| {
                        r.parent == parent && (wanted <= 0 || r.pid == wanted as usize)
                    };
                    let (ready, has_children, status, reaped_pid) = {
                        let reg = REGISTRY.lock();
                        let ready = reg
                            .records
                            .iter()
                            .position(|r| matches(r) && r.exit.is_some());
                        let has_children = reg.records.iter().any(matches);
                        let status = ready.map(|i| {
                            let info = reg.records[i].exit;
                            info.map_or(0, |e| match e {
                                // WEXITSTATUS：exit 码占高 8 位
                                ExitInfo::Exited(n) => (n as u32 & 255) << 8,
                                // WTERMSIG：死于信号时低位为信号号
                                ExitInfo::Signaled { sig, .. } => sig as u32,
                            })
                        });
                        (
                            ready,
                            has_children,
                            status,
                            ready.map(|i| reg.records[i].pid),
                        )
                    };
                    if ready.is_some() {
                        let child_pid = reaped_pid.expect("ready implies pid");
                        let copied = args[1] == 0 || {
                            let reg = REGISTRY.lock();
                            reg.records
                                .iter()
                                .find(|r| r.pid == parent)
                                .and_then(|r| r.space.as_ref())
                                .is_some_and(|s| {
                                    crate::mm::user_access::copy_to_user(
                                        s.as_space(),
                                        args[1],
                                        &status.expect("ready implies status").to_ne_bytes(),
                                    )
                                    .is_ok()
                                })
                        };
                        if !copied {
                            // 状态指针非法：孩子已收割（Linux 也是收割优先）
                            Err(Errno::Fault)
                        } else {
                            // 收割即删，运行时间累计归父进程
                            let (user, system) = super::registry::reap_child(parent, child_pid)
                                .expect("child exists");
                            let mut reg = REGISTRY.lock();
                            if let Some(rec) = reg.records.iter_mut().find(|r| r.pid == parent) {
                                rec.child_user_ns = rec.child_user_ns.saturating_add(user);
                                rec.child_system_ns = rec.child_system_ns.saturating_add(system);
                            }
                            Ok(child_pid)
                        }
                    } else if has_children {
                        if args[2] & 1 != 0 {
                            Ok(0)
                        } else {
                            return ProcessResult::Wait(WaitReason::Children);
                        }
                    } else {
                        Err(Errno::NoChild)
                    }
                }
            }
        }
        sysnr::KILL | sysnr::TGKILL => kill_or_tgkill(parent, nr, args),
        _ => Err(Errno::NoSys),
    };
    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(result);
    ProcessResult::Done
}

/// 读用户空间 8 字节 sigset_t，失败返回 EFAULT。
fn read_sigset(parent: Pid, ptr: usize) -> Result<SignalSet, Errno> {
    let mut raw = [0u8; SIGSETSIZE];
    let ok = REGISTRY
        .lock()
        .records
        .iter()
        .find(|r| r.pid == parent)
        .and_then(|r| r.space.as_ref())
        .is_some_and(|s| user_access::copy_from_user(s.as_space(), ptr, &mut raw).is_ok());
    if ok {
        Ok(SignalSet::from_ne_bytes(raw))
    } else {
        Err(Errno::Fault)
    }
}

/// rt_sigtimedwait 命中后的 siginfo 回写；uinfo 为 0 不写，
/// 写失败返回 EFAULT（信号已消费，不回队）。
fn write_uinfo(parent: Pid, uinfo: usize, sig: u8, slot: &SigInfoSlot) -> Result<(), Errno> {
    if uinfo == 0 {
        return Ok(());
    }
    let mut buf = [0u8; 128];
    fill_siginfo(&mut buf, sig, slot);
    let ok = REGISTRY
        .lock()
        .records
        .iter()
        .find(|r| r.pid == parent)
        .and_then(|r| r.space.as_ref())
        .is_some_and(|s| user_access::copy_to_user(s.as_space(), uinfo, &buf).is_ok());
    if ok {
        Ok(())
    } else {
        Err(Errno::Fault)
    }
}

/// 解析 rt_sigtimedwait 的相对超时（timespec 16 字节；NULL 表示永等）。
/// 校验规则同 nanosleep。
fn timedwait_deadline(parent: Pid, ts_ptr: usize) -> Result<core::time::Duration, Errno> {
    if ts_ptr == 0 {
        return Ok(core::time::Duration::MAX);
    }
    let mut raw = [0u8; 16];
    let ok = REGISTRY
        .lock()
        .records
        .iter()
        .find(|r| r.pid == parent)
        .and_then(|r| r.space.as_ref())
        .is_some_and(|s| user_access::copy_from_user(s.as_space(), ts_ptr, &mut raw).is_ok());
    if !ok {
        return Err(Errno::Fault);
    }
    let sec = i64::from_ne_bytes(raw[..8].try_into().unwrap_or([0; 8]));
    let ns = i64::from_ne_bytes(raw[8..].try_into().unwrap_or([0; 8]));
    if sec < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(Errno::Invalid);
    }
    polyhal::timer::current_time()
        .checked_add(core::time::Duration::new(sec as u64, ns as u32))
        .ok_or(Errno::Invalid)
}

/// rt_sigqueueinfo(2)：向目标进程发送携带 siginfo 的信号。
/// 校验保留 si_code、sig 范围与目标存在性；siginfo 按 _rt 布局解析。
/// 标准信号与实时信号统一位图登记（偏差登记 docs/ostd-contracts.md §4.5）。
fn queue_info(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    // pid_t 32 位：截断后按符号解释。
    let pid = args[0] as u32 as i32;
    let sig = args[1] as u32;
    let mut raw = [0u8; 128];
    let ok = REGISTRY
        .lock()
        .records
        .iter()
        .find(|r| r.pid == parent)
        .and_then(|r| r.space.as_ref())
        .is_some_and(|s| user_access::copy_from_user(s.as_space(), args[2], &mut raw).is_ok());
    if !ok {
        return Err(Errno::Fault);
    }
    let code = i32::from_ne_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
    // 内核保留 si_code 只能对自身使用。
    if (code >= 0 || code == SI_TKILL) && pid != parent as i32 {
        return Err(Errno::Perm);
    }
    if sig > 64 {
        return Err(Errno::Invalid);
    }
    let target = pid as usize;
    if sig == 0 {
        let exists = REGISTRY
            .lock()
            .records
            .iter()
            .any(|r| r.pid == target && r.exit.is_none());
        return if exists { Ok(0) } else { Err(Errno::NoProcess) };
    }
    send_signal(
        target,
        sig as u8,
        SigInfoSlot {
            code,
            errno: i32::from_ne_bytes(raw[4..8].try_into().unwrap_or([0; 4])),
            pid: u32::from_ne_bytes(raw[16..20].try_into().unwrap_or([0; 4])),
            addr: usize::from_ne_bytes(raw[24..32].try_into().unwrap_or([0; 8])),
            ..Default::default()
        },
    )
    .map(|_| 0)
}

/// kill(2)/tgkill(2)：解析目标与信号并发送。pid>0 为目标，
/// pid==0 为自身，pid<0 为 EINVAL；sig==0 仅做存在性检查。
/// 偏差登记 docs/ostd-contracts.md §4.5。
fn kill_or_tgkill(parent: Pid, nr: usize, args: [usize; 6]) -> Result<usize, Errno> {
    let (pid_arg, sig_arg) = if nr == sysnr::KILL {
        (args[0], args[1])
    } else {
        // tgkill(tgid, tid, sig)：两者须 > 0 且相等（单线程模型）。
        let tgid = args[0] as u32 as i32;
        let tid = args[1] as u32 as i32;
        if tgid <= 0 || tgid != tid {
            return Err(Errno::Invalid);
        }
        (args[1], args[2])
    };
    // pid_t 为 32 位：截断后再按符号解释，兼容寄存器零扩展/符号扩展。
    let pid = pid_arg as u32 as i32;
    if pid < 0 {
        return Err(Errno::Invalid);
    }
    let target = if pid == 0 { parent } else { pid as usize };
    // 负信号按 u32 解释为大值，落入 EINVAL。
    let sig = sig_arg as u32;
    if sig > 64 {
        return Err(Errno::Invalid);
    }
    if sig == 0 {
        let exists = REGISTRY
            .lock()
            .records
            .iter()
            .any(|r| r.pid == target && r.exit.is_none());
        return if exists { Ok(0) } else { Err(Errno::NoProcess) };
    }
    send_signal(
        target,
        sig as u8,
        SigInfoSlot {
            // kill(2) 恒 SI_USER(=0)；tgkill 发内核保留码 SI_TKILL。
            code: if nr == sysnr::KILL { 0 } else { SI_TKILL },
            pid: parent as u32,
            ..Default::default()
        },
    )
    .map(|_| 0)
}
/// 创建独立地址空间的子进程，保留父现场，子进程从下一条指令返回零。
/// fork(2)/clone(2) 支持的标志：退出信号必须是 SIGCHLD（纯进程 fork），
/// 另接受 NPTL fork 使用的 CLONE_CHILD_CLEARTID/CLONE_CHILD_SETTID（仅对
/// 子进程生效；见 clone(2)），其余标志（线程/共享）不支持。
const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
const CLONE_CHILD_SETTID: usize = 0x0100_0000;

fn fork_user(
    parent: Pid,
    frame: &TrapFrame,
    flags: usize,
    stack: usize,
    child_tid: usize,
) -> Result<usize, Errno> {
    let allowed = 17 | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID;
    if flags & !allowed != 0 || flags & 0xff != 17 {
        return Err(Errno::Invalid);
    }
    let mut space = {
        let reg = REGISTRY.lock();
        let source = reg
            .records
            .iter()
            .find(|r| r.pid == parent)
            .and_then(|r| r.space.as_ref())
            .ok_or(Errno::NoProcess)?;
        source.as_space().deep_copy().map_err(|_| Errno::NoMem)?
    };
    let fs = {
        let reg = REGISTRY.lock();
        reg.records
            .iter()
            .find(|r| r.pid == parent)
            .and_then(|r| r.fs.as_ref())
            .ok_or(Errno::NoProcess)?
            .fork()?
    };
    // 两架构 TrapFrame 的 Copy 派生不同，Clone 是共同接口。
    #[allow(clippy::clone_on_copy)]
    let mut child_frame = frame.clone();
    child_frame.syscall_ok();
    child_frame[TrapFrameArgs::RET] = 0;
    if stack != 0 {
        child_frame[TrapFrameArgs::SP] = stack;
    }
    let pid = super::registry::alloc_pid();
    // CLONE_CHILD_SETTID：在子进程地址空间写入其 tid；CLONE_CHILD_CLEARTID：
    // 子进程退出时清零该地址（退出路径已按 clear_child_tid 处理）。
    if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 && child_tid != 0 {
        if flags & CLONE_CHILD_SETTID != 0 {
            // 写入经 user_access 完成，目标是子进程自身的用户内存；地址来自
            // 父进程参数，子进程尚未运行，无并发访问。
            let _ = crate::mm::user_access::copy_to_user(
                &space,
                child_tid,
                &(pid as u32).to_ne_bytes(),
            );
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            space.clear_child_tid = child_tid;
        }
    }
    let task = Task::new_user(pid, "child", child_frame).map_err(|_| Errno::NoMem)?;
    let task = Box::try_new(task).map_err(|_| Errno::NoMem)?;
    super::registry::reserve().map_err(|_| Errno::NoMem)?;
    sched::reserve_task().map_err(|_| Errno::NoMem)?;
    super::proc_table_reserve().map_err(|_| Errno::NoMem)?;
    super::registry::register(
        pid,
        "child",
        Some(crate::mm::address_space::LocalSpace(space)),
    );
    {
        let mut reg = REGISTRY.lock();
        // 先取父子记录下标，再以 split_at_mut 就地 fork_from。
        let parent_index = reg.records.iter().position(|r| r.pid == parent);
        let child_index = reg.records.iter().position(|r| r.pid == pid);
        if let (Some(pi), Some(ci)) = (parent_index, child_index) {
            debug_assert_ne!(pi, ci, "fork parent and child share a record");
            match pi.cmp(&ci) {
                core::cmp::Ordering::Less => {
                    let (head, tail) = reg.records.split_at_mut(ci);
                    tail[0].signal.fork_from(&head[pi].signal);
                }
                core::cmp::Ordering::Greater => {
                    let (head, tail) = reg.records.split_at_mut(pi);
                    head[ci].signal.fork_from(&tail[0].signal);
                }
                core::cmp::Ordering::Equal => {}
            }
            // 子进程继承备用栈，pending/info 清零。
            let child = &mut reg.records[ci];
            child.parent = parent;
            child.fs = Some(fs);
        }
    }
    super::proc_table_push(pid, "child", parent, true);
    sched::enqueue(task);
    Ok(pid)
}
