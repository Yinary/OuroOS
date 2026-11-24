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
    futex_call, sched,
    signal::{
        default_action, fault_siginfo, force_signal, send_signal, DefaultAction, SigInfoSlot,
        SignalDisposition, SignalSet, SignalSetExt, SIGKILL, SIGSEGV, SIGSTOP, SIG_DFL, SIG_IGN,
        SI_TKILL,
    },
    task::{FutexKey, Pid, Task, TaskBody, WaitReason},
    ExitInfo, FutexStep, REGISTRY,
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
    let ids = [0; 4];
    let sp = super::exec::stack(&space, &[arg0], &[], &entry, None, name, ids).map_err(|e| {
        if e == Errno::Io {
            SpawnError::NoEntropy
        } else {
            SpawnError::OutOfMemory
        }
    })?;
    frame[TrapFrameArgs::SP] = sp;
    let task = Task::new_user(pid, pid, name, frame).map_err(|_| SpawnError::OutOfMemory)?;

    let fs = crate::fs::context::Context::new().map_err(|_| SpawnError::OutOfMemory)?;
    let task = Box::try_new(task).map_err(|_| SpawnError::OutOfMemory)?;
    super::registry::reserve()?;
    sched::reserve_task().map_err(|_| SpawnError::OutOfMemory)?;
    super::proc_table_reserve().map_err(|_| SpawnError::OutOfMemory)?;
    // —— 提交段：此后不再失败 ——
    super::registry::register(pid, name, Some(crate::mm::address_space::LocalSpace(space)));
    let (init_pgid, init_sid) = {
        let reg = REGISTRY.lock();
        let init = super::INIT_PID.load(core::sync::atomic::Ordering::Relaxed);
        match reg.records.iter().find(|r| r.pid == init) {
            Some(r) => (r.pgid, r.sid),
            None => (init, init),
        }
    };
    {
        let mut reg = REGISTRY.lock();
        if let Some(r) = reg.records.iter_mut().find(|r| r.pid == pid) {
            r.fs = Some(fs);
            r.parent = super::INIT_PID.load(core::sync::atomic::Ordering::Relaxed);
            r.pgid = init_pgid;
            r.sid = init_sid;
        }
    }
    super::proc_table_push(
        pid,
        name,
        super::INIT_PID.load(core::sync::atomic::Ordering::Relaxed),
        true,
    );
    {
        let reg = REGISTRY.lock();
        proc_sync_holding(&reg.records, pid);
    }
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
    /// 线程组终止（exit_group）。
    ExitGroup(ExitInfo),
}

/// 用户任务入口：在自己（任务）的内核栈上运行，直到 exit/被杀。
pub fn user_task_entry() -> ! {
    sched::reap_switched();
    let (pid, mut frame) = match sched::take_body() {
        TaskBody::User { frame, pid } => (pid, frame),
        TaskBody::Kernel(_) => panic!("kernel task entered user entry"),
    };
    let mut sleep_deadline = None;
    let mut futex_wait = None;
    let mut vfork_child: Option<Pid> = None;
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
                let mut locked = REGISTRY.lock();
                let reg = &mut *locked;
                let index = reg.group_index(pid).expect("user task unregistered");
                let rec = &mut reg.records[index];
                let thread = reg
                    .threads
                    .iter_mut()
                    .find(|t| t.tid == pid)
                    .expect("user task unregistered");
                rec.space
                    .as_ref()
                    .expect("running user task lost its space")
                    .as_space()
                    .activate();
                // 投递检查点：每次回用户态至多处理一个信号；handler 在此建帧。
                let blocked_now = thread.signal.blocked();
                match super::signal::take_any(&mut rec.signal, &mut thread.signal, blocked_now) {
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
                                thread.signal.alt_stack(),
                            ) {
                                Ok(new_blocked) => {
                                    thread.signal.setmask(new_blocked);
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
            let user_start = crate::time::monotonic();
            let trap_type = run_user_task(&mut frame);
            kernel_start = crate::time::monotonic();
            {
                let mut reg = REGISTRY.lock();
                if let Some(rec) = reg.group_mut(pid) {
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
                            let mut locked = REGISTRY.lock();
                            let reg = &mut *locked;
                            let index = reg.group_index(pid).expect("user task unregistered");
                            let rec = &mut reg.records[index];
                            let space = rec
                                .space
                                .as_mut()
                                .expect("running user task lost its space");
                            match reg.threads.iter_mut().find(|t| t.tid == pid) {
                                Some(thread) => crate::syscall::dispatch(
                                    &mut frame,
                                    pid,
                                    &mut space.0,
                                    rec.fs.as_mut().expect("user fs context"),
                                    &mut rec.signal,
                                    thread,
                                ),
                                None => Flow::Continue,
                            }
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
                                    &mut futex_wait,
                                    &mut vfork_child,
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
                                    Flow::ExitedGroup(code) => {
                                        Action::ExitGroup(ExitInfo::exited(code))
                                    }
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
                                .group(pid)
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
                            reg.group(pid)
                                .and_then(|r| r.space.as_ref())
                                .ok_or(crate::mm::address_space::MapError::NotMapped)
                                .and_then(|s| {
                                    let space = s.as_space();
                                    if let Some((_, flags)) = space.translate(addr) {
                                        if flags.contains(access) {
                                            return Err(
                                                crate::mm::address_space::MapError::PermissionDenied,
                                            );
                                        }
                                    }
                                    space.ensure_access(addr, access)?;
                                    match space.translate(addr) {
                                        Some((_, flags)) if flags.contains(access) => Ok(()),
                                        _ => Err(crate::mm::address_space::MapError::PermissionDenied),
                                    }
                                })
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
                        let info = match kind {
                            trap::UserFaultKind::Breakpoint => frame[TrapFrameArgs::SEPC],
                            _ => info,
                        };
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
            let spent = crate::time::monotonic()
                .saturating_sub(kernel_start)
                .as_nanos()
                .min(u64::MAX as u128) as u64;
            let mut reg = REGISTRY.lock();
            if let Some(rec) = reg.group_mut(pid) {
                rec.system_ns = rec.system_ns.saturating_add(spent);
            }
        }
        // 借用已结束，在此做调度决策
        match action {
            Action::Exit(info) => sched::exit_current(info),
            Action::ExitGroup(info) => sched::exit_group_current(info),
            Action::Yield => sched::yield_now(),
            // Wait：先做可落睡的 park 检查，睡醒后补一次不落睡的重查。
            Action::Wait(reason) => {
                let outcome = park_check_signals(
                    pid,
                    reason,
                    &mut frame,
                    &mut sleep_deadline,
                    &mut timedwait,
                    &mut futex_wait,
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
                        &mut futex_wait,
                        false,
                    );
                    wait_uncompleted = outcome != ParkOutcome::Completed;
                }
            }
            Action::Continue => sched::resume_check(),
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
    futex_wait: &mut Option<(FutexKey, u32, Option<core::time::Duration>, u32)>,
    allow_park: bool,
) -> ParkOutcome {
    // sigtimedwait 的等待集；Some 即本次挂起属于 rt_sigtimedwait。
    let tw_set = timedwait.map(|(set, _)| set);
    let peeked = {
        let mut locked = REGISTRY.lock();
        let reg = &mut *locked;
        let index = reg.group_index(pid).expect("user task unregistered");
        let rec = &mut reg.records[index];
        let thread = reg
            .threads
            .iter_mut()
            .find(|t| t.tid == pid)
            .expect("user task unregistered");
        let blocked = thread.signal.blocked();
        // 先查等待集内信号：命中即消费，不经处置。
        let tw_hit = tw_set.and_then(|set| {
            let mut hidden = blocked;
            hidden |= !set;
            super::signal::take_any(&mut rec.signal, &mut thread.signal, hidden)
        });
        match tw_hit {
            Some((sig, slot)) => ParkPeek::TwHit { sig, slot },
            None => match super::signal::peek_any(&rec.signal, &thread.signal, blocked) {
                None => ParkPeek::Empty,
                Some((sig, _)) => {
                    let d = rec.signal.disposition(sig);
                    if d.handler != SIG_DFL && d.handler != SIG_IGN {
                        // handler 分支不消费；DFL/IGN 分支经 take_any 另取槽。
                        ParkPeek::Handler(d)
                    } else {
                        // IGN 为防御分支。
                        let (sig, slot) =
                            super::signal::take_any(&mut rec.signal, &mut thread.signal, blocked)
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
                    ParkOutcome::Completed
                } else if is_absolute_nanosleep(frame) {
                    // clock_nanosleep 的绝对期限：清截止时间，不回写剩余时间，以 -EINTR 完成。
                    *sleep_deadline = None;
                    // Wait 路径原欠一次 syscall_ok，EINTR 完成恰好补上。
                    frame.syscall_ok();
                    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Interrupted));
                    ParkOutcome::Completed
                } else {
                    // nanosleep 与相对期限的 clock_nanosleep：清截止时间、回写剩余时间，以 -EINTR 完成。
                    *sleep_deadline = None;
                    let rem_ptr = nanosleep_rem_ptr(frame);
                    if rem_ptr != 0 {
                        // 剩余时间 timespec：16 字节 secs/nsecs（小端）。
                        let left = until.saturating_sub(crate::time::monotonic());
                        let mut rem = [0u8; 16];
                        rem[..8].copy_from_slice(&left.as_secs().to_ne_bytes());
                        rem[8..].copy_from_slice(&(left.subsec_nanos() as u64).to_ne_bytes());
                        // 写失败忽略（不改变返回值）。
                        let reg = REGISTRY.lock();
                        if let Some(rec) = reg.group(pid) {
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
                    ParkOutcome::Completed
                }
            }
            // SA_RESTART：pipe 读写与 wait 的等待不完成不睡，信号留给循环顶检查点。
            // ppoll 被 handler 信号打断一律以 -EINTR 完成。
            WaitReason::Pipe | WaitReason::Children
                if d.flags & SA_RESTART != 0 && frame[TrapFrameArgs::SYSCALL] != sysnr::PPOLL =>
            {
                ParkOutcome::Incomplete
            }
            // 其余：完成 syscall 返回 -EINTR；信号留给循环顶检查点。
            _ => {
                *futex_wait = None;
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
    futex_wait: &mut Option<(FutexKey, u32, Option<core::time::Duration>, u32)>,
    vfork_child: &mut Option<Pid>,
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
                            match reg.thread_mut(parent) {
                                Some(thread) => {
                                    *sigsuspend_saved = Some(thread.signal.blocked());
                                    thread.signal.setmask(new);
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
                    let mut locked = REGISTRY.lock();
                    let reg = &mut *locked;
                    let index = reg.group_index(parent).expect("user task unregistered");
                    let rec = &mut reg.records[index];
                    let thread = reg
                        .threads
                        .iter_mut()
                        .find(|t| t.tid == parent)
                        .expect("user task unregistered");
                    let blocked = thread.signal.blocked();
                    loop {
                        let Some((sig, _)) =
                            super::signal::peek_any(&rec.signal, &thread.signal, blocked)
                        else {
                            break false;
                        };
                        if has_consequence(sig, rec.signal.disposition(sig)) {
                            break true;
                        }
                        // 无后果：不当投递，消费丢弃（同 Linux get_signal）。
                        super::signal::take_any(&mut rec.signal, &mut thread.signal, blocked)
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
                    let mut locked = REGISTRY.lock();
                    let reg = &mut *locked;
                    match (
                        reg.group_index(parent),
                        reg.threads.iter_mut().find(|t| t.tid == parent),
                    ) {
                        (Some(index), Some(thread)) => {
                            let rec = &mut reg.records[index];
                            let mut hidden = thread.signal.blocked();
                            hidden |= !set;
                            super::signal::take_any(&mut rec.signal, &mut thread.signal, hidden)
                        }
                        _ => None,
                    }
                };
                if let Some((sig, slot)) = taken {
                    *timedwait = None;
                    write_uinfo(parent, args[1], sig, &slot).map(|_| sig as usize)
                } else if crate::time::monotonic() >= deadline {
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
                                let mut locked = REGISTRY.lock();
                                let reg = &mut *locked;
                                match (
                                    reg.group_index(parent),
                                    reg.threads.iter_mut().find(|t| t.tid == parent),
                                ) {
                                    (Some(index), Some(thread)) => {
                                        let rec = &mut reg.records[index];
                                        let mut hidden = thread.signal.blocked();
                                        hidden |= !set;
                                        super::signal::take_any(
                                            &mut rec.signal,
                                            &mut thread.signal,
                                            hidden,
                                        )
                                    }
                                    _ => None,
                                }
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
            data[..8].copy_from_slice(&crate::time::monotonic().as_secs().to_ne_bytes());
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
            reg.group(parent)
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
                let rec = reg.group(parent).ok_or(Errno::NoProcess)?;
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
                        crate::time::monotonic()
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
                    Some(d) if crate::time::monotonic() < d => {
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
                if crate::time::monotonic() < until {
                    return ProcessResult::Wait(WaitReason::Deadline(until));
                }
                *sleep_deadline = None;
                Ok(0)
            } else {
                let reg = REGISTRY.lock();
                let mut request = [0u8; 16];
                let valid = reg
                    .group(parent)
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
                        let until = crate::time::monotonic()
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
        sysnr::CLOCK_GETTIME => clock_gettime(parent, args),
        sysnr::CLOCK_GETRES => clock_getres(parent, args),
        sysnr::CLOCK_NANOSLEEP => match clock_nanosleep(parent, sleep_deadline, args) {
            SleepStep::Done(result) => result,
            SleepStep::Wait(until) => return ProcessResult::Wait(WaitReason::Deadline(until)),
        },
        sysnr::TIMES => {
            let reg = REGISTRY.lock();
            if let Some(rec) = reg.group(parent) {
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
                    Ok((crate::time::monotonic().as_millis() / 10) as usize)
                }
            } else {
                Err(Errno::NoProcess)
            }
        }
        sysnr::GETPPID => Ok(REGISTRY.lock().group(parent).map_or(0, |r| r.parent)),
        sysnr::GETUID => credential(parent, |c| c.ruid),
        sysnr::GETEUID => credential(parent, |c| c.euid),
        sysnr::GETGID => credential(parent, |c| c.rgid),
        sysnr::GETEGID => credential(parent, |c| c.egid),
        // gettid(2)：单线程下线程号就是进程号。
        sysnr::GETTID => Ok(parent),
        sysnr::GETRESUID => get_res_id(parent, args, false),
        sysnr::GETRESGID => get_res_id(parent, args, true),
        sysnr::GETGROUPS => get_groups(parent, args),
        sysnr::SETREGID => set_re_id(parent, args, true),
        sysnr::SETGID => set_id(parent, args, true),
        sysnr::SETREUID => set_re_id(parent, args, false),
        sysnr::SETUID => set_id(parent, args, false),
        sysnr::SETRESUID => set_res_id(parent, args, false),
        sysnr::SETRESGID => set_res_id(parent, args, true),
        sysnr::SETFSUID => set_fs_id(parent, args, false),
        sysnr::SETFSGID => set_fs_id(parent, args, true),
        sysnr::SETGROUPS => set_groups(parent, args),
        sysnr::EXECVE => match super::exec::exec(parent, [args[0], args[1], args[2]], frame) {
            Ok(()) => return ProcessResult::Replaced,
            Err(e) => Err(e),
        },
        // clone(2) 的 child_tid 参数序是架构 ABI 的一部分：RV64 为
        // (flags, stack, ptid, tls, ctid)，LA64 为 (flags, stack, ptid,
        // ctid, tls)（对照两架构 clone.s 与 Linux fork.c 的拷贝语义）。
        // 归一化为具名参数后再按 CLONE_THREAD 分流。
        sysnr::CLONE => {
            log::debug!("DBG clone flags {:#x} stack {:#x}", args[0], args[1]);
            #[cfg(target_arch = "riscv64")]
            let (tls, child_tid) = (args[3], args[4]);
            #[cfg(target_arch = "loongarch64")]
            let (child_tid, tls) = (args[3], args[4]);
            if let Some(done) = vfork_child.take() {
                Ok(done)
            } else if args[0] & CLONE_THREAD != 0 {
                fork_thread(parent, frame, args[0], args[1], args[2], tls, child_tid)
            } else if args[0] & CLONE_VFORK != 0 {
                match fork_vfork(parent, frame, args[0], args[1], child_tid) {
                    Ok(pid) => {
                        *vfork_child = Some(pid);
                        return ProcessResult::Wait(WaitReason::Vfork(pid));
                    }
                    Err(e) => Err(e),
                }
            } else {
                fork_user(parent, frame, args[0], args[1], child_tid)
            }
        }
        sysnr::FUTEX => {
            let step = {
                let reg = REGISTRY.lock();
                match reg.group(parent).and_then(|r| r.space.as_ref()) {
                    Some(record) => futex_call(record.as_space(), args, futex_wait),
                    None => FutexStep::Done(Err(Errno::NoProcess)),
                }
            };
            match step {
                FutexStep::Done(result) => result,
                FutexStep::Wait(reason) => return ProcessResult::Wait(reason),
                FutexStep::Wake { key, n, bitset } => Ok(super::sched::wake_futex(key, n, bitset)),
                FutexStep::Requeue {
                    from,
                    to,
                    nr_wake,
                    nr_requeue,
                } => Ok(super::sched::requeue_futex(from, to, nr_wake, nr_requeue)),
            }
        }
        sysnr::WAIT4 => {
            // wait4(2)：pid > 0 指定孩子，-1 等任意孩子，0 等本进程组，
            // 其余负值等进程组 -pid 的孩子；无可收割孩子时挂起，无孩子 ECHILD。
            // 收割即从注册表删除；可请求停止、恢复事件，当前不产生这两种状态。
            if args[2] & !(1 | 2 | 8) != 0 {
                Err(Errno::Invalid)
            } else {
                let wanted = args[0] as i32;
                if wanted == i32::MIN {
                    Err(Errno::NoChild)
                } else {
                    let caller_pgid = REGISTRY.lock().group(parent).map_or(0, |r| r.pgid);
                    let wanted_pgid = (-(wanted as i64)) as usize;
                    let matches = |r: &super::ProcessRecord| {
                        r.parent == parent
                            && if wanted == -1 {
                                true
                            } else if wanted == 0 {
                                r.pgid == caller_pgid
                            } else if wanted < -1 {
                                r.pgid == wanted_pgid
                            } else {
                                r.pid == wanted as usize
                            }
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
                            reg.group(parent)
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
                            if let Some(rec) = reg.group_mut(parent) {
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
        sysnr::WAITID => return waitid(parent, frame, args),
        sysnr::GETRUSAGE => get_rusage(parent, args),
        sysnr::SCHED_GETSCHEDULER => sched_getscheduler(parent, args[0]),
        sysnr::SCHED_GETPARAM => sched_getparam(parent, args[0], args[1]),
        sysnr::SCHED_GET_PRIORITY_MAX => sched_priority_limit(args[0], true),
        sysnr::SCHED_GET_PRIORITY_MIN => sched_priority_limit(args[0], false),
        sysnr::SCHED_RR_GET_INTERVAL => sched_rr_get_interval(parent, args[0], args[1]),
        sysnr::SCHED_GETAFFINITY => sched_getaffinity(parent, args[0], args[1], args[2]),
        sysnr::SCHED_SETAFFINITY => sched_setaffinity(parent, args[0], args[1], args[2]),
        sysnr::SETPGID => set_pg_id(parent, args),
        sysnr::GETPGID => get_pg_or_sid(parent, args[0], false),
        sysnr::GETSID => get_pg_or_sid(parent, args[0], true),
        sysnr::SETSID => set_sid(parent),
        sysnr::KILL | sysnr::TKILL | sysnr::TGKILL => kill_or_tgkill(parent, nr, args),
        _ => Err(Errno::NoSys),
    };
    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(result);
    ProcessResult::Done
}

/// 取调用进程凭证中的一个号：getuid(2)、geteuid(2)、getgid(2)、getegid(2) 共用。
fn credential(parent: Pid, pick: impl Fn(&super::Credentials) -> u32) -> Result<usize, Errno> {
    let reg = REGISTRY.lock();
    reg.group(parent)
        .map(|r| pick(&r.creds) as usize)
        .ok_or(Errno::NoProcess)
}

/// 调用方已持 REGISTRY 锁时，把一个进程的身份同步到 procfs 快照。
fn proc_sync_holding(records: &[super::ProcessRecord], pid: Pid) {
    if let Some(r) = records.iter().find(|r| r.pid == pid) {
        let c = &r.creds;
        super::proc_table_sync(
            r.pid,
            r.pgid,
            r.sid,
            [
                c.ruid, c.euid, c.suid, c.fsuid, c.rgid, c.egid, c.sgid, c.fsgid,
            ],
        );
    }
}

/// 读用户空间 8 字节 sigset_t，失败返回 EFAULT。
fn read_sigset(parent: Pid, ptr: usize) -> Result<SignalSet, Errno> {
    let mut raw = [0u8; SIGSETSIZE];
    let ok = REGISTRY
        .lock()
        .group(parent)
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
        .group(parent)
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
        .group(parent)
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
    crate::time::monotonic()
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
        .group(parent)
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

/// kill(2)/tgkill(2)：解析目标与信号并发送。pid>0 为目标进程，
/// pid==0 为调用者所在进程组，pid<0 为进程组或全体进程；sig==0 仅查存在性。
/// 偏差登记 docs/ostd-contracts.md §4.5。
fn kill_or_tgkill(parent: Pid, nr: usize, args: [usize; 6]) -> Result<usize, Errno> {
    let sig_arg = if nr == sysnr::KILL || nr == sysnr::TKILL {
        args[1]
    } else {
        args[2]
    };
    // 负信号按 u32 解释为大值，落入 EINVAL。
    let sig = sig_arg as u32;
    if sig > 64 {
        return Err(Errno::Invalid);
    }
    let slot = SigInfoSlot {
        // kill(2) 恒 SI_USER(=0)；tgkill 发内核保留码 SI_TKILL。
        code: if nr == sysnr::KILL { 0 } else { SI_TKILL },
        pid: parent as u32,
        ..Default::default()
    };
    let mut locked = REGISTRY.lock();
    let reg = &mut *locked;
    if nr == sysnr::TKILL {
        let tid = args[0] as u32 as i32;
        if tid <= 0 {
            return Err(Errno::Invalid);
        }
        let tid = tid as usize;
        let Some(tid_index) = reg.threads.iter().position(|t| t.tid == tid) else {
            return Err(Errno::NoProcess);
        };
        let index = reg.group_index(tid).ok_or(Errno::NoProcess)?;
        if reg.records[index].exit.is_some() {
            return Err(Errno::NoProcess);
        }
        if sig == 0 {
            return Ok(0);
        }
        let group = &reg.records[index];
        let thread = &mut reg.threads[tid_index];
        super::signal::generate_thread(&group.signal, &mut thread.signal, sig as u8, slot);
        return Ok(0);
    }
    if nr == sysnr::TGKILL {
        let tgid = args[0] as u32 as i32;
        let tid = args[1] as u32 as i32;
        if tgid <= 0 || tid <= 0 {
            return Err(Errno::Invalid);
        }
        let tid = tid as usize;
        let index = reg.group_index(tid).ok_or(Errno::NoProcess)?;
        if reg.records[index].pid != tgid as usize || reg.thread(tid).is_none() {
            return Err(Errno::NoProcess);
        }
        if sig == 0 {
            return Ok(0);
        }
        let group = &reg.records[index];
        let thread = reg
            .threads
            .iter_mut()
            .find(|t| t.tid == tid)
            .ok_or(Errno::NoProcess)?;
        super::signal::generate_thread(&group.signal, &mut thread.signal, sig as u8, slot);
        return Ok(0);
    }
    // pid_t 为 32 位：截断后再按符号解释，兼容寄存器零扩展/符号扩展。
    let pid = args[0] as u32 as i32;
    if pid == i32::MIN {
        return Err(Errno::NoProcess);
    }
    let init = super::INIT_PID.load(core::sync::atomic::Ordering::Relaxed);
    if pid > 0 {
        let target = pid as usize;
        let index = reg
            .group_index(target)
            .filter(|i| reg.records[*i].exit.is_none())
            .ok_or(Errno::NoProcess)?;
        if sig == 0 {
            return Ok(0);
        }
        if let Some(tid_index) = reg.threads.iter().position(|t| t.tid == target) {
            let group = &reg.records[index];
            let thread = &mut reg.threads[tid_index];
            super::signal::generate_thread(&group.signal, &mut thread.signal, sig as u8, slot);
        } else {
            let blocked = reg
                .threads
                .iter()
                .find(|t| t.tgid == target)
                .map_or(0, |t| t.signal.blocked());
            reg.records[index].signal.generate(sig as u8, slot, blocked);
        }
        return Ok(0);
    }
    let caller_pgid = reg.group(parent).map(|r| r.pgid).ok_or(Errno::NoProcess)?;
    let mut hits = 0usize;
    for r in reg.records.iter_mut() {
        if r.exit.is_some() {
            continue;
        }
        let matched = if pid == 0 {
            r.pgid == caller_pgid
        } else if pid == -1 {
            r.pid != init && r.pid != parent
        } else {
            r.pgid == -(pid as i64) as usize
        };
        if matched {
            hits += 1;
            if sig != 0 {
                let blocked = reg
                    .threads
                    .iter()
                    .find(|t| t.tgid == r.pid)
                    .map_or(0, |t| t.signal.blocked());
                r.signal.generate(sig as u8, slot, blocked);
            }
        }
    }
    if hits == 0 {
        Err(Errno::NoProcess)
    } else {
        Ok(0)
    }
}

fn set_pg_id(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let pgid = args[1] as u32 as i32;
    if pgid < 0 {
        return Err(Errno::Invalid);
    }
    let pid = args[0] as u32 as i32;
    if pid < 0 {
        return Err(Errno::NoProcess);
    }
    let target = if pid == 0 { parent } else { pid as usize };
    let mut reg = REGISTRY.lock();
    let target_index = reg
        .records
        .iter()
        .position(|r| r.pid == target)
        .ok_or(Errno::NoProcess)?;
    let target_sid = reg.records[target_index].sid;
    if target != parent {
        if reg.records[target_index].parent != parent {
            return Err(Errno::NoProcess);
        }
        let caller_sid = reg.group(parent).map(|r| r.sid).ok_or(Errno::NoProcess)?;
        if target_sid != caller_sid {
            return Err(Errno::Perm);
        }
        if reg.records[target_index].did_exec {
            return Err(Errno::Access);
        }
    }
    if target_sid == reg.records[target_index].pid {
        return Err(Errno::Perm);
    }
    let pgid = if pgid == 0 { target } else { pgid as usize };
    if pgid != target
        && !reg
            .records
            .iter()
            .any(|r| r.pgid == pgid && r.sid == target_sid)
    {
        return Err(Errno::Perm);
    }
    reg.records[target_index].pgid = pgid;
    proc_sync_holding(&reg.records, target);
    Ok(0)
}

fn get_pg_or_sid(parent: Pid, pid_arg: usize, want_sid: bool) -> Result<usize, Errno> {
    let pid = pid_arg as u32 as i32;
    if pid < 0 {
        return Err(Errno::NoProcess);
    }
    let target = if pid == 0 { parent } else { pid as usize };
    let reg = REGISTRY.lock();
    let rec = reg
        .records
        .iter()
        .find(|r| r.pid == target)
        .ok_or(Errno::NoProcess)?;
    Ok(if want_sid { rec.sid } else { rec.pgid })
}

fn set_sid(parent: Pid) -> Result<usize, Errno> {
    let mut reg = REGISTRY.lock();
    if reg.records.iter().any(|r| r.pgid == parent) {
        return Err(Errno::Perm);
    }
    let rec = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
    rec.pgid = parent;
    rec.sid = parent;
    proc_sync_holding(&reg.records, parent);
    Ok(parent)
}

fn waitid(parent: Pid, frame: &mut TrapFrame, args: [usize; 6]) -> ProcessResult {
    const WNOHANG: u32 = 0x1;
    const WSTOPPED: u32 = 0x2;
    const WEXITED: u32 = 0x4;
    const WCONTINUED: u32 = 0x8;
    const WNOWAIT: u32 = 0x0100_0000;
    const __WNOTHREAD: u32 = 0x2000_0000;
    const __WALL: u32 = 0x4000_0000;
    const __WCLONE: u32 = 0x8000_0000;
    let allowed =
        WNOHANG | WSTOPPED | WEXITED | WCONTINUED | WNOWAIT | __WNOTHREAD | __WALL | __WCLONE;
    let idtype = args[0] as u32 as i32;
    if !(0..=2).contains(&idtype) {
        frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Invalid));
        return ProcessResult::Done;
    }
    let options = args[3] as u32;
    if options & !allowed != 0 || options & (WEXITED | WSTOPPED | WCONTINUED) == 0 {
        frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Invalid));
        return ProcessResult::Done;
    }
    let infop = args[2];
    let id = args[1] as u32 as usize;
    let (ready, any) = {
        let reg = REGISTRY.lock();
        let caller_pgid = match reg.group(parent) {
            Some(r) => r.pgid,
            None => {
                frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::NoProcess));
                return ProcessResult::Done;
            }
        };
        let matches = |r: &super::ProcessRecord| {
            r.parent == parent
                && match idtype {
                    0 => true,
                    1 => r.pid == id,
                    _ => r.pgid == if id == 0 { caller_pgid } else { id },
                }
        };
        let ready = reg
            .records
            .iter()
            .position(|r| matches(r) && r.exit.is_some());
        let any = reg.records.iter().any(matches);
        let ready = ready.and_then(|i| {
            let rec = reg.records.get(i)?;
            Some((
                rec.pid,
                rec.exit?,
                rec.user_ns.saturating_add(rec.child_user_ns),
                rec.system_ns.saturating_add(rec.child_system_ns),
            ))
        });
        (ready, any)
    };
    if let Some((child_pid, exit, user_ns, system_ns)) = ready {
        let mut data = [0u8; 128];
        data[0..4].copy_from_slice(&17u32.to_ne_bytes());
        let (code, status) = match exit {
            ExitInfo::Exited(n) => (1u32, n as u32 & 255),
            ExitInfo::Signaled { sig, .. } => (2u32, sig as u32),
        };
        data[8..12].copy_from_slice(&code.to_ne_bytes());
        data[16..20].copy_from_slice(&(child_pid as u32).to_ne_bytes());
        data[24..28].copy_from_slice(&status.to_ne_bytes());
        data[32..40].copy_from_slice(&(user_ns / 10_000_000).to_ne_bytes());
        data[40..48].copy_from_slice(&(system_ns / 10_000_000).to_ne_bytes());
        if infop != 0 {
            let copied = REGISTRY
                .lock()
                .group(parent)
                .and_then(|r| r.space.as_ref())
                .is_some_and(|s| {
                    crate::mm::user_access::copy_to_user(s.as_space(), infop, &data).is_ok()
                });
            if !copied {
                frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Fault));
                return ProcessResult::Done;
            }
        }
        if options & WNOWAIT == 0 {
            match super::registry::reap_child(parent, child_pid) {
                Some((user, system)) => {
                    let mut reg = REGISTRY.lock();
                    if let Some(rec) = reg.group_mut(parent) {
                        rec.child_user_ns = rec.child_user_ns.saturating_add(user);
                        rec.child_system_ns = rec.child_system_ns.saturating_add(system);
                    }
                }
                None => {
                    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::NoChild));
                    return ProcessResult::Done;
                }
            }
        }
        frame[TrapFrameArgs::RET] =
            crate::syscall::to_abi(Ok(if infop == 0 { child_pid } else { 0 }));
        return ProcessResult::Done;
    }
    if !any {
        frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::NoChild));
        return ProcessResult::Done;
    }
    if options & WNOHANG != 0 {
        if infop != 0 {
            let copied = REGISTRY
                .lock()
                .group(parent)
                .and_then(|r| r.space.as_ref())
                .is_some_and(|s| {
                    crate::mm::user_access::copy_to_user(s.as_space(), infop, &[0u8; 128]).is_ok()
                });
            if !copied {
                frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Fault));
                return ProcessResult::Done;
            }
        }
        frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Ok(0));
        return ProcessResult::Done;
    }
    ProcessResult::Wait(WaitReason::Children)
}

/// clock_nanosleep(2) 一次处理的结果。
enum SleepStep {
    /// 系统调用完成，所带的值即返回值。
    Done(Result<usize, Errno>),
    /// 尚未到期，挂起到该单调时刻后重执行。
    Wait(core::time::Duration),
}

/// clock_nanosleep(2) 的 TIMER_ABSTIME：期限是所在时钟上的绝对时间。
const TIMER_ABSTIME: usize = 1;

/// 读用户态的 16 字节 timespec，返回秒与纳秒；读不到返回 EFAULT。
fn read_timespec(parent: Pid, ptr: usize) -> Result<[i64; 2], Errno> {
    let mut data = [0u8; 16];
    let valid = REGISTRY
        .lock()
        .group(parent)
        .and_then(|r| r.space.as_ref())
        .is_some_and(|s| {
            crate::mm::user_access::copy_from_user(s.as_space(), ptr, &mut data).is_ok()
        });
    if !valid {
        return Err(Errno::Fault);
    }
    Ok([
        i64::from_ne_bytes(data[..8].try_into().unwrap_or([0; 8])),
        i64::from_ne_bytes(data[8..].try_into().unwrap_or([0; 8])),
    ])
}

/// 把时间写成用户态的 16 字节 timespec。
fn write_timespec(parent: Pid, ptr: usize, value: core::time::Duration) -> Result<usize, Errno> {
    let mut data = [0u8; 16];
    data[..8].copy_from_slice(&(value.as_secs() as i64).to_ne_bytes());
    data[8..].copy_from_slice(&(value.subsec_nanos() as i64).to_ne_bytes());
    REGISTRY
        .lock()
        .group(parent)
        .and_then(|r| r.space.as_ref())
        .ok_or(Errno::NoProcess)
        .and_then(|s| {
            crate::mm::user_access::copy_to_user(s.as_space(), ptr, &data).map_err(|_| Errno::Fault)
        })
        .map(|()| 0)
}

/// clock_gettime(2)：按 clockid 取时间并写入 timespec。支持 REALTIME、MONOTONIC、
/// BOOTTIME 三类时钟与进程、线程的 CPU 时间，未知 clockid 返回 EINVAL。
fn clock_gettime(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let cpu = {
        let reg = REGISTRY.lock();
        let rec = reg.group(parent).ok_or(Errno::NoProcess)?;
        core::time::Duration::from_nanos(rec.user_ns.saturating_add(rec.system_ns))
    };
    let now = crate::time::lookup(args[0] as u32 as i32, cpu)?;
    write_timespec(parent, args[1], now)
}

/// clock_getres(2)：写入时钟分辨率；地址为 0 时只检查 clockid。
fn clock_getres(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    crate::time::validate(args[0] as u32 as i32)?;
    if args[1] == 0 {
        Ok(0)
    } else {
        write_timespec(parent, args[1], crate::time::RESOLUTION)
    }
}

/// clock_nanosleep(2)：睡到期限。相对期限与 REALTIME 上的绝对期限都换算成单调时刻，
/// 再交给与 nanosleep 共用的到期等待。
fn clock_nanosleep(
    parent: Pid,
    sleep_deadline: &mut Option<core::time::Duration>,
    args: [usize; 6],
) -> SleepStep {
    if let Some(until) = *sleep_deadline {
        if crate::time::monotonic() < until {
            return SleepStep::Wait(until);
        }
        *sleep_deadline = None;
        return SleepStep::Done(Ok(0));
    }
    let clock = match crate::time::sleepable(args[0] as u32 as i32) {
        Ok(clock) => clock,
        Err(e) => return SleepStep::Done(Err(e)),
    };
    let [sec, nsec] = match read_timespec(parent, args[2]) {
        Ok(value) => value,
        Err(e) => return SleepStep::Done(Err(e)),
    };
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return SleepStep::Done(Err(Errno::Invalid));
    }
    let amount = core::time::Duration::new(sec as u64, nsec as u32);
    let until = if args[1] & TIMER_ABSTIME == 0 {
        crate::time::monotonic().checked_add(amount)
    } else {
        match clock {
            crate::time::ClockKind::Monotonic => Some(amount),
            crate::time::ClockKind::Realtime => {
                Some(crate::time::monotonic() + amount.saturating_sub(crate::time::realtime()))
            }
            crate::time::ClockKind::Process => None,
        }
    };
    match until {
        Some(until) if crate::time::monotonic() < until => {
            *sleep_deadline = Some(until);
            SleepStep::Wait(until)
        }
        Some(_) => SleepStep::Done(Ok(0)),
        None => SleepStep::Done(Err(Errno::Invalid)),
    }
}

/// 当前等待的调用是否为绝对期限的 clock_nanosleep。
fn is_absolute_nanosleep(frame: &TrapFrame) -> bool {
    frame[TrapFrameArgs::SYSCALL] == sysnr::CLOCK_NANOSLEEP && frame.args()[1] & TIMER_ABSTIME != 0
}

/// 被打断的睡眠调用的剩余时间地址：nanosleep 是第二参数，clock_nanosleep 是第四参数。
fn nanosleep_rem_ptr(frame: &TrapFrame) -> usize {
    if frame[TrapFrameArgs::SYSCALL] == sysnr::CLOCK_NANOSLEEP {
        frame.args()[3]
    } else {
        frame.args()[1]
    }
}

fn get_rusage(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let who = args[0] as u32 as i32;
    let reg = REGISTRY.lock();
    let rec = reg.group(parent).ok_or(Errno::NoProcess)?;
    let (user, system) = match who {
        0 | 1 => (rec.user_ns, rec.system_ns),
        -1 => (rec.child_user_ns, rec.child_system_ns),
        _ => return Err(Errno::Invalid),
    };
    let mut data = [0u8; 144];
    data[0..8].copy_from_slice(&(user / 1_000_000_000).to_ne_bytes());
    data[8..16].copy_from_slice(&((user % 1_000_000_000) / 1000).to_ne_bytes());
    data[16..24].copy_from_slice(&(system / 1_000_000_000).to_ne_bytes());
    data[24..32].copy_from_slice(&((system % 1_000_000_000) / 1000).to_ne_bytes());
    rec.space
        .as_ref()
        .ok_or(Errno::NoProcess)
        .and_then(|s| {
            crate::mm::user_access::copy_to_user(s.as_space(), args[1], &data)
                .map_err(|_| Errno::Fault)
        })
        .map(|()| 0)
}

/// getresuid(2) 与 getresgid(2)：把真实、有效、保存的号写成三个 32 位整数；
/// 任一处写失败返回 EFAULT。
fn get_res_id(parent: Pid, args: [usize; 6], want_gid: bool) -> Result<usize, Errno> {
    let reg = REGISTRY.lock();
    let rec = reg.group(parent).ok_or(Errno::NoProcess)?;
    let (real, effective, saved) = if want_gid {
        (rec.creds.rgid, rec.creds.egid, rec.creds.sgid)
    } else {
        (rec.creds.ruid, rec.creds.euid, rec.creds.suid)
    };
    let space = rec.space.as_ref().ok_or(Errno::NoProcess)?.as_space();
    for (ptr, value) in [(args[0], real), (args[1], effective), (args[2], saved)] {
        user_access::copy_to_user(space, ptr, &value.to_ne_bytes()).map_err(|_| Errno::Fault)?;
    }
    Ok(0)
}

/// getgroups(2)：size 为 0 时只返回补充组的个数，否则写入并返回个数；
/// size 为负或装不下返回 EINVAL。
fn get_groups(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let size = args[0] as u32 as i32;
    if size < 0 {
        return Err(Errno::Invalid);
    }
    let reg = REGISTRY.lock();
    let rec = reg.group(parent).ok_or(Errno::NoProcess)?;
    let groups = &rec.creds.groups;
    let n = groups.len();
    if size == 0 {
        return Ok(n);
    }
    if n > size as usize {
        return Err(Errno::Invalid);
    }
    let space = rec.space.as_ref().ok_or(Errno::NoProcess)?.as_space();
    for (i, g) in groups.iter().enumerate() {
        let ptr = args[1].checked_add(i * 4).ok_or(Errno::Fault)?;
        user_access::copy_to_user(space, ptr, &g.to_ne_bytes()).map_err(|_| Errno::Fault)?;
    }
    Ok(n)
}

/// 一组身份号：真实、有效、保存与文件系统用的号；用户号与组号共用。
#[derive(Clone, Copy)]
struct IdSet {
    real: u32,
    effective: u32,
    saved: u32,
    fs: u32,
}

impl IdSet {
    fn load(creds: &super::Credentials, gid: bool) -> Self {
        if gid {
            Self {
                real: creds.rgid,
                effective: creds.egid,
                saved: creds.sgid,
                fs: creds.fsgid,
            }
        } else {
            Self {
                real: creds.ruid,
                effective: creds.euid,
                saved: creds.suid,
                fs: creds.fsuid,
            }
        }
    }

    fn store(&self, creds: &mut super::Credentials, gid: bool) {
        if gid {
            creds.rgid = self.real;
            creds.egid = self.effective;
            creds.sgid = self.saved;
            creds.fsgid = self.fs;
        } else {
            creds.ruid = self.real;
            creds.euid = self.effective;
            creds.suid = self.saved;
            creds.fsuid = self.fs;
        }
    }
}

/// setuid(2) 与 setgid(2)：有特权时真实号与保存号一起设为该值，否则只能设为真实号或保存号。
fn set_id(parent: Pid, args: [usize; 6], gid: bool) -> Result<usize, Errno> {
    let value = args[0] as u32;
    let mut reg = REGISTRY.lock();
    let rec = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
    let mut ids = IdSet::load(&rec.creds, gid);
    let privileged = rec.creds.euid == 0;
    if privileged {
        ids.real = value;
        ids.saved = value;
    } else if value != ids.real && value != ids.saved {
        return Err(Errno::Perm);
    }
    ids.effective = value;
    ids.fs = value;
    ids.store(&mut rec.creds, gid);
    proc_sync_holding(&reg.records, parent);
    Ok(0)
}

/// setreuid(2) 与 setregid(2)：-1 表示不修改；真实号改变或有效号不等于原真实号时，
/// 保存号跟随新的有效号。
fn set_re_id(parent: Pid, args: [usize; 6], gid: bool) -> Result<usize, Errno> {
    let real_arg = args[0] as u32;
    let effective_arg = args[1] as u32;
    let mut reg = REGISTRY.lock();
    let rec = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
    let old = IdSet::load(&rec.creds, gid);
    let privileged = rec.creds.euid == 0;
    if real_arg != u32::MAX && real_arg != old.real && real_arg != old.effective && !privileged {
        return Err(Errno::Perm);
    }
    if effective_arg != u32::MAX
        && effective_arg != old.real
        && effective_arg != old.effective
        && effective_arg != old.saved
        && !privileged
    {
        return Err(Errno::Perm);
    }
    let real = if real_arg != u32::MAX {
        real_arg
    } else {
        old.real
    };
    let effective = if effective_arg != u32::MAX {
        effective_arg
    } else {
        old.effective
    };
    let saved = if real_arg != u32::MAX || (effective_arg != u32::MAX && effective_arg != old.real)
    {
        effective
    } else {
        old.saved
    };
    IdSet {
        real,
        effective,
        saved,
        fs: effective,
    }
    .store(&mut rec.creds, gid);
    proc_sync_holding(&reg.records, parent);
    Ok(0)
}

/// setresuid(2) 与 setresgid(2)：-1 表示不修改；无特权时每个新值须是原有三个号之一。
fn set_res_id(parent: Pid, args: [usize; 6], gid: bool) -> Result<usize, Errno> {
    let requested = [args[0] as u32, args[1] as u32, args[2] as u32];
    let mut reg = REGISTRY.lock();
    let rec = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
    let old = IdSet::load(&rec.creds, gid);
    if rec.creds.euid != 0 {
        for value in requested {
            if value != u32::MAX
                && value != old.real
                && value != old.effective
                && value != old.saved
            {
                return Err(Errno::Perm);
            }
        }
    }
    let real = if requested[0] != u32::MAX {
        requested[0]
    } else {
        old.real
    };
    let effective = if requested[1] != u32::MAX {
        requested[1]
    } else {
        old.effective
    };
    let saved = if requested[2] != u32::MAX {
        requested[2]
    } else {
        old.saved
    };
    IdSet {
        real,
        effective,
        saved,
        fs: effective,
    }
    .store(&mut rec.creds, gid);
    proc_sync_holding(&reg.records, parent);
    Ok(0)
}

/// setfsuid(2) 与 setfsgid(2)：不允许的值不生效；返回原来的文件系统用号。
fn set_fs_id(parent: Pid, args: [usize; 6], gid: bool) -> Result<usize, Errno> {
    let value = args[0] as u32;
    let mut reg = REGISTRY.lock();
    let rec = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
    let old = IdSet::load(&rec.creds, gid);
    if rec.creds.euid == 0
        || value == old.real
        || value == old.effective
        || value == old.saved
        || value == old.fs
    {
        IdSet { fs: value, ..old }.store(&mut rec.creds, gid);
        proc_sync_holding(&reg.records, parent);
    }
    Ok(old.fs as usize)
}

/// setgroups(2)：只有有特权的进程可用；个数不在 0 到 65536 之间返回 EINVAL。
fn set_groups(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let size = args[0] as u32 as i32;
    let mut reg = REGISTRY.lock();
    let rec = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
    if rec.creds.euid != 0 {
        return Err(Errno::Perm);
    }
    if !(0..=65536).contains(&size) {
        return Err(Errno::Invalid);
    }
    let space = rec.space.as_ref().ok_or(Errno::NoProcess)?.as_space();
    let mut groups = alloc::vec::Vec::new();
    groups
        .try_reserve_exact(size as usize)
        .map_err(|_| Errno::NoMem)?;
    for i in 0..size as usize {
        let ptr = args[1].checked_add(i * 4).ok_or(Errno::Fault)?;
        let mut raw = [0u8; 4];
        user_access::copy_from_user(space, ptr, &mut raw).map_err(|_| Errno::Fault)?;
        groups.push(u32::from_ne_bytes(raw));
    }
    rec.creds.groups = groups;
    proc_sync_holding(&reg.records, parent);
    Ok(0)
}

fn sched_target(parent: Pid, pid_arg: usize) -> Result<usize, Errno> {
    let pid = pid_arg as u32 as i32;
    if pid < 0 {
        return Err(Errno::NoProcess);
    }
    Ok(if pid == 0 { parent } else { pid as usize })
}

fn sched_getscheduler(parent: Pid, pid_arg: usize) -> Result<usize, Errno> {
    let target = sched_target(parent, pid_arg)?;
    let reg = REGISTRY.lock();
    reg.records
        .iter()
        .find(|r| r.pid == target)
        .ok_or(Errno::NoProcess)?;
    Ok(0)
}

fn sched_getparam(parent: Pid, pid_arg: usize, param: usize) -> Result<usize, Errno> {
    if (pid_arg as u32 as i32) < 0 {
        return Err(Errno::Invalid);
    }
    if param == 0 {
        return Err(Errno::Invalid);
    }
    let target = sched_target(parent, pid_arg)?;
    let reg = REGISTRY.lock();
    let rec = reg
        .records
        .iter()
        .find(|r| r.pid == target)
        .ok_or(Errno::NoProcess)?;
    let space = rec.space.as_ref().ok_or(Errno::NoProcess)?.as_space();
    crate::mm::user_access::copy_to_user(space, param, &[0u8; 4]).map_err(|_| Errno::Fault)?;
    Ok(0)
}

fn sched_priority_limit(policy_arg: usize, is_max: bool) -> Result<usize, Errno> {
    let policy = policy_arg as u32 as i32;
    match policy {
        1 | 2 => Ok(if is_max { 99 } else { 1 }),
        0 | 3 | 5 | 6 => Ok(0),
        _ => Err(Errno::Invalid),
    }
}

fn sched_rr_get_interval(parent: Pid, pid_arg: usize, tp: usize) -> Result<usize, Errno> {
    if (pid_arg as u32 as i32) < 0 {
        return Err(Errno::Invalid);
    }
    let target = sched_target(parent, pid_arg)?;
    let reg = REGISTRY.lock();
    let rec = reg
        .records
        .iter()
        .find(|r| r.pid == target)
        .ok_or(Errno::NoProcess)?;
    let space = rec.space.as_ref().ok_or(Errno::NoProcess)?.as_space();
    let mut data = [0u8; 16];
    data[8..16].copy_from_slice(&(crate::config::TICK_MS * 1_000_000).to_ne_bytes());
    crate::mm::user_access::copy_to_user(space, tp, &data).map_err(|_| Errno::Fault)?;
    Ok(0)
}

fn sched_getaffinity(parent: Pid, pid_arg: usize, len: usize, mask: usize) -> Result<usize, Errno> {
    let target = sched_target(parent, pid_arg)?;
    let reg = REGISTRY.lock();
    let rec = reg
        .records
        .iter()
        .find(|r| r.pid == target)
        .ok_or(Errno::NoProcess)?;
    let space = rec.space.as_ref().ok_or(Errno::NoProcess)?.as_space();
    let n = len.min(8);
    let bits = 1u64.to_ne_bytes();
    if n > 0 {
        crate::mm::user_access::copy_to_user(space, mask, &bits[..n]).map_err(|_| Errno::Fault)?;
    }
    Ok(n)
}

fn sched_setaffinity(parent: Pid, pid_arg: usize, len: usize, mask: usize) -> Result<usize, Errno> {
    let target = sched_target(parent, pid_arg)?;
    let reg = REGISTRY.lock();
    let rec = reg
        .records
        .iter()
        .find(|r| r.pid == target)
        .ok_or(Errno::NoProcess)?;
    if len == 0 {
        return Err(Errno::Invalid);
    }
    let space = rec.space.as_ref().ok_or(Errno::NoProcess)?.as_space();
    let n = len.min(8);
    let mut data = [0u8; 8];
    crate::mm::user_access::copy_from_user(space, mask, &mut data[..n])
        .map_err(|_| Errno::Fault)?;
    if data[0] & 1 == 0 {
        Err(Errno::Invalid)
    } else {
        Ok(0)
    }
}
const CLONE_CHILD_CLEARTID: usize = 0x0020_0000;
const CLONE_CHILD_SETTID: usize = 0x0100_0000;
const CLONE_VM: usize = 0x0000_0100;
const CLONE_FS: usize = 0x0000_0200;
const CLONE_FILES: usize = 0x0000_0400;
const CLONE_SIGHAND: usize = 0x0000_0800;
const CLONE_THREAD: usize = 0x0001_0000;
const CLONE_SYSVSEM: usize = 0x0004_0000;
const CLONE_SETTLS: usize = 0x0008_0000;
const CLONE_PARENT_SETTID: usize = 0x0010_0000;
const CLONE_VFORK: usize = 0x0000_4000;
const CLONE_DETACHED: usize = 0x0040_0000;

/// 创建独立地址空间的子进程，保留父现场，子进程从下一条指令返回零。
/// 退出信号必须是 SIGCHLD；另接受 NPTL fork 使用的 CLONE_CHILD_CLEARTID 与
/// CLONE_CHILD_SETTID。带 CLONE_THREAD 的调用走 [`fork_thread`]。
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
    let (space, creds) = {
        let mut reg = REGISTRY.lock();
        let source = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
        let creds = source.creds.try_clone().map_err(|_| Errno::NoMem)?;
        let space = source
            .space
            .as_mut()
            .ok_or(Errno::NoProcess)?
            .0
            .deep_copy()
            .map_err(|_| Errno::NoMem)?;
        (space, creds)
    };
    let fs = {
        let reg = REGISTRY.lock();
        reg.group(parent)
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
    // CLONE_CHILD_SETTID：在子进程地址空间写入其 tid。
    if flags & CLONE_CHILD_SETTID != 0 && child_tid != 0 {
        // 写入经 user_access 完成，目标是子进程自身的用户内存；地址来自
        // 父进程参数，子进程尚未运行，无并发访问。
        let _ =
            crate::mm::user_access::copy_to_user(&space, child_tid, &(pid as u32).to_ne_bytes());
    }
    let task = Task::new_user(pid, pid, "child", child_frame).map_err(|_| Errno::NoMem)?;
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
        let mut locked = REGISTRY.lock();
        let reg = &mut *locked;
        // 先取父子记录下标，再以 split_at_mut 就地 fork_from。
        let parent_index = reg.group_index(parent);
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
            let (pgid, sid) = (reg.records[pi].pgid, reg.records[pi].sid);
            // 子进程继承备用栈，pending/info 清零。
            let child = &mut reg.records[ci];
            child.parent = parent;
            child.fs = Some(fs);
            child.pgid = pgid;
            child.sid = sid;
            child.creds = creds;
        }
        let parent_thread = reg.threads.iter().position(|t| t.tid == parent);
        let child_thread = reg.threads.iter().position(|t| t.tid == pid);
        if let (Some(pi), Some(ci)) = (parent_thread, child_thread) {
            match pi.cmp(&ci) {
                core::cmp::Ordering::Less => {
                    let (head, tail) = reg.threads.split_at_mut(ci);
                    tail[0].signal.fork_from(&head[pi].signal);
                }
                core::cmp::Ordering::Greater => {
                    let (head, tail) = reg.threads.split_at_mut(pi);
                    head[ci].signal.fork_from(&tail[0].signal);
                }
                core::cmp::Ordering::Equal => {}
            }
        }
    }
    super::proc_table_push(pid, "child", parent, true);
    {
        let mut locked = REGISTRY.lock();
        let reg = &mut *locked;
        proc_sync_holding(&reg.records, pid);
        if flags & CLONE_CHILD_CLEARTID != 0 && child_tid != 0 {
            if let Some(thread) = reg.thread_mut(pid) {
                thread.clear_child_tid = child_tid;
            }
        }
    }
    sched::enqueue(task);
    Ok(pid)
}

/// 创建共享地址空间与文件表的新线程：退出信号必须为 0，必须同时带 CLONE_THREAD、
/// CLONE_SIGHAND 与 CLONE_VM；另接受 CLONE_FS、CLONE_FILES、CLONE_SYSVSEM、
/// CLONE_SETTLS 与三个 tid 标志，CLONE_DETACHED 按 Linux 忽略。
/// vfork：子进程按复制地址空间创建，父进程挂起到子进程 exec 或退出。
fn fork_vfork(
    parent: Pid,
    frame: &TrapFrame,
    flags: usize,
    stack: usize,
    child_tid: usize,
) -> Result<Pid, Errno> {
    let allowed = 17
        | CLONE_VM
        | CLONE_VFORK
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_CHILD_SETTID;
    if flags & 0xff != 17
        || flags & (CLONE_VM | CLONE_VFORK) != (CLONE_VM | CLONE_VFORK)
        || flags & !allowed != 0
    {
        return Err(Errno::Invalid);
    }
    let inner = 17 | (flags & (CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID));
    fork_user(parent, frame, inner, stack, child_tid)
}

fn fork_thread(
    parent: Pid,
    frame: &TrapFrame,
    flags: usize,
    stack: usize,
    ptid: usize,
    tls: usize,
    child_tid: usize,
) -> Result<usize, Errno> {
    let allowed = CLONE_VM
        | CLONE_FS
        | CLONE_FILES
        | CLONE_SIGHAND
        | CLONE_THREAD
        | CLONE_SYSVSEM
        | CLONE_SETTLS
        | CLONE_PARENT_SETTID
        | CLONE_CHILD_CLEARTID
        | CLONE_DETACHED
        | CLONE_CHILD_SETTID;
    if flags & 0xff != 0
        || flags & (CLONE_SIGHAND | CLONE_VM) != (CLONE_SIGHAND | CLONE_VM)
        || flags & !allowed != 0
    {
        return Err(Errno::Invalid);
    }
    let tgid = {
        let reg = REGISTRY.lock();
        reg.thread(parent).map_or(parent, |t| t.tgid)
    };
    let mut child_frame = TrapFrame::new();
    child_frame.clone_from(frame);
    child_frame.syscall_ok();
    child_frame[TrapFrameArgs::RET] = 0;
    if stack != 0 {
        child_frame[TrapFrameArgs::SP] = stack;
    }
    if flags & CLONE_SETTLS != 0 {
        child_frame[TrapFrameArgs::TLS] = tls;
    }
    let tid = super::registry::alloc_pid();
    let task = Task::new_user(tid, tgid, "thread", child_frame).map_err(|_| Errno::NoMem)?;
    let task = Box::try_new(task).map_err(|_| Errno::NoMem)?;
    super::registry::reserve().map_err(|_| Errno::NoMem)?;
    sched::reserve_task().map_err(|_| Errno::NoMem)?;
    {
        let mut locked = REGISTRY.lock();
        super::registry::register_thread(&mut locked, tid, tgid, parent);
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        let copied = {
            let reg = REGISTRY.lock();
            reg.group(parent)
                .and_then(|r| r.space.as_ref())
                .is_some_and(|s| {
                    crate::mm::user_access::copy_to_user(
                        s.as_space(),
                        ptid,
                        &(tid as u32).to_ne_bytes(),
                    )
                    .is_ok()
                })
        };
        if !copied {
            REGISTRY.lock().remove_thread(tid);
            return Err(Errno::Fault);
        }
    }
    if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 && child_tid != 0 {
        let mut locked = REGISTRY.lock();
        if flags & CLONE_CHILD_SETTID != 0 {
            if let Some(space) = locked.group(parent).and_then(|r| r.space.as_ref()) {
                let _ = crate::mm::user_access::copy_to_user(
                    space.as_space(),
                    child_tid,
                    &(tid as u32).to_ne_bytes(),
                );
            }
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            if let Some(thread) = locked.thread_mut(tid) {
                thread.clear_child_tid = child_tid;
            }
        }
    }
    sched::enqueue(task);
    Ok(tid)
}
