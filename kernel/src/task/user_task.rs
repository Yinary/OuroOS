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
    mm::{
        address_space::{UserAddressSpace, USER_STACK_TOP},
        user_access,
    },
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
    frame[TrapFrameArgs::SEPC] = entry;
    // 初始栈包含 argc=0、argv/envp 终止项和 AT_NULL。
    let sp = USER_STACK_TOP - 48;
    crate::mm::user_access::copy_to_user(&space, sp, &[0u8; 48])
        .map_err(|_| SpawnError::OutOfMemory)?;
    frame[TrapFrameArgs::SP] = sp;
    let task = Task::new_user(pid, name, frame).map_err(|_| SpawnError::OutOfMemory)?;

    let fs = crate::fs::context::Context::new().map_err(|_| SpawnError::OutOfMemory)?;
    let task = Box::try_new(task).map_err(|_| SpawnError::OutOfMemory)?;
    super::registry::reserve()?;
    sched::reserve_task().map_err(|_| SpawnError::OutOfMemory)?;
    // —— 提交段：此后不再失败 ——
    super::registry::register(pid, name, Some(crate::mm::address_space::LocalSpace(space)));
    {
        let mut reg = REGISTRY.lock();
        if let Some(r) = reg.records.iter_mut().find(|r| r.pid == pid) {
            r.fs = Some(fs);
            r.parent = super::INIT_PID.load(core::sync::atomic::Ordering::Relaxed);
        }
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
}

/// 用户任务入口：在自己（任务）的内核栈上运行，直到 exit/被杀。
pub fn user_task_entry() -> ! {
    sched::reap_switched();
    let (pid, mut frame) = match sched::take_body() {
        TaskBody::User { frame, pid } => (pid, frame),
        TaskBody::Kernel(_) => panic!("kernel task entered user entry"),
    };
    let mut sleep_deadline = None;
    // 循环局部等待状态（跨同一系统调用的重执行保持，Wait 决议时清空）：
    // sigsuspend 存换入前的旧屏蔽集合；sigtimedwait 存等待集与绝对截止。
    let mut sigsuspend_saved: Option<SignalSet> = None;
    let mut timedwait: Option<(SignalSet, core::time::Duration)> = None;
    // 最近一次等待的 syscall 是否尚未完成（PC 停在 ecall）。sigsuspend
    // 存续期间检查点投递 handler 帧前据此补一次 -EINTR 完成（见循环顶
    // 检查点注释），否则 sigreturn 回到 ecall 会让 sigsuspend 重启而非
    // 返回。仅在 saved 非空时被消费，不会误伤其他 syscall。
    let mut wait_uncompleted = false;

    loop {
        // 一轮 = 激活页表 + 投递检查点 → 进用户态 → 消费一次逃逸。
        let kernel_start;
        let action = {
            // 每轮激活本任务页表：上次 yield 后其他任务的表可能上过。
            // REGISTRY 锁不跨 run_user_task（用户态执行期间不持锁）。
            // 同一锁段内做信号投递检查点；致命信号记下死因，锁释放后
            // 跳过用户态直接退出（exit_current 不返回且要求无锁）。
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
                // 投递检查点：每次回用户态至多处理一个信号（Linux 每次回
                // 用户态只完成一个信号，剩余 pending 下次陷入再投）。
                // park 快路径 handler 分支留下的信号已处于 pending，由本
                // 检查点消费；用户 handler（≠DFL/IGN）在此建帧投递。
                let blocked_now = rec.signal.blocked();
                match rec.signal.take_deliverable(blocked_now) {
                    None => None,
                    Some((sig, slot)) => {
                        let d = rec.signal.disposition(sig);
                        if d.handler == SIG_DFL || d.handler == SIG_IGN {
                            delivery_verdict(sig, slot, d)
                        } else {
                            // 真投递（Linux handle_signal → setup_rt_frame）：
                            // 同一锁段内拿任务地址空间建帧并换入 handler
                            // 期间屏蔽集合。失败简化为 Signaled{SIGSEGV}
                            // 锁外 exit_current——Linux force_sigsegv 会把
                            // 处置复位后重试投递，此处不递归重试（偏差
                            // 登记 docs/ostd-contracts.md）。
                            //
                            // 帧内 uc_sigmask 存 save_mask：sigsuspend 存续
                            // 期间是换入临时集合之前的旧集合（Linux
                            // saved_sigmask），sigreturn 恢复；其余场景与
                            // blocked_now 相同。仅在建帧时取走 saved，
                            // DFL/IGN 等无帧去向留给 RT_SIGSUSPEND 重入
                            // 分支恢复，避免旧集合过早生效把信号永久屏蔽。
                            //
                            // sigsuspend 等待被同批更高号 handler 信号打断且
                            // syscall 尚未完成（PC 停在 ecall，例如低号
                            // DFL/Ign 信号刚被快路径丢弃）：按 Linux
                            // ERESTARTNOHAND 先以 -EINTR 完成再建帧，保证
                            // handler 返回后用户态见到的是 -EINTR 而非重启。
                            if sigsuspend_saved.is_some() && wait_uncompleted {
                                frame.syscall_ok();
                                frame[TrapFrameArgs::RET] =
                                    crate::syscall::to_abi(Err(Errno::Interrupted));
                                wait_uncompleted = false;
                            }
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
                            // 恰好推进一次 syscall PC：polyhal 对 SysCall
                            // 不推进，重复/遗漏都会破坏用户执行流。
                            // 阻塞（Wait）不推 PC，挂起醒来后重执行重查；
                            // SigReturn 现场已整体恢复，SEPC 无需推进。
                            let outcome = match flow {
                                Flow::Process => process_call(
                                    pid,
                                    &mut frame,
                                    &mut sleep_deadline,
                                    &mut sigsuspend_saved,
                                    &mut timedwait,
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
                                // force 投递：硬件信号不可屏蔽/忽略
                                //（force_signal 重置 IGN 并解蔽），入队后
                                // 由下一轮循环顶检查点消费——本指令不会
                                // 先于投递重执行，无 handler 时按 DFL 终止
                                // 且 fault 保留给终态报告。
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
                    fatal => {
                        // 用户态致命异常（含 vendor 补丁后的 Unhandled）：
                        // 终止任务而不是带走内核
                        if !frame.from_user() {
                            panic!("kernel-origin trap escaped to user loop: {:?}", fatal);
                        }
                        let (kind, info) =
                            trap::fatal_fault(fatal).expect("fatal_fault covers fatal traps");
                        // force 投递同 AddressNotAligned：下一轮循环顶
                        // 检查点消费，出错指令不会先于投递重执行。
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
            // park 前后两次信号决策（决策表见 park_check_signals）：第一次
            // 可落睡，返回 true 表示真实睡过一觉；睡醒后补一次不落睡的
            // 重查，把睡中到达的信号在唤醒点按 Linux 语义处理完（否则要
            // 等到循环顶检查点，sigtimedwait 集合内信号会被按 DFL 杀掉、
            // nanosleep/sigsuspend 被打断后静默续等），随后才回循环顶
            // 检查点——彼时已无可投递信号，检查点不会越权消费。
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
                    // 睡醒后的不落睡重查（决策表同上）：睡中到达的信号在
                    // 唤醒点处理完，随后才回循环顶检查点。
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

/// DFL/IGN 处置信号的投递判定（循环顶检查点与 park 快路径共用）。
/// 用户 handler（≠DFL/IGN）不经过本函数：循环顶检查点对 handler 分支
/// 直接建帧投递（sigframe::build_deliver）。IGN 理论上不可达（产生侧
/// 已过滤，仅屏蔽后改处置可残留），防御性丢弃。Term/Core 返回 Signaled
/// 死因（fault 槽透传终态报告）；Ign/Cont 丢弃；Stop 无停止态，降级
/// 为丢弃（登记 docs）。
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

/// park 快路径一次调用后，被等待 syscall 的完成状态（PC 是否仍停在
/// ecall）。检查点在 sigsuspend 存续期间投递 handler 帧前据此决定是否
/// 先以 -EINTR 完成（见循环顶注释）。
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
    /// sigtimedwait 等待集内的信号：已在锁内 take 消费，由本调用不经
    /// 处置地以信号号完成。Linux do_sigtimedwait 的出队只按
    /// pending & 等待集判定，handler 与默认动作都不走——这正是该调用
    /// 存在的意义（首次入口命中路径同此语义）。
    TwHit { sig: u8, slot: SigInfoSlot },
    /// 用户 handler（≠DFL/IGN）：不消费，信号留在 pending，留给循环顶
    /// 检查点；携带处置供 SA_RESTART 判定。
    Handler(SignalDisposition),
    /// DFL/IGN：已在锁内 take 消费，按默认动作处置（IGN 为防御分支）。
    Default {
        sig: u8,
        slot: SigInfoSlot,
        d: SignalDisposition,
    },
}

/// park 信号决策：看有无可投递信号并按真实处置分岔。peek 对 handler
/// 不消费：
/// - 等待集内（sigtimedwait）：同一锁内 take 消费，回写 uinfo 并以
///   信号号完成，处置（handler/默认动作）一律不走；
/// - handler（≠DFL/IGN）：信号留在 pending，按 reason 分岔——Deadline
///   下按挂起归属（sigtimedwait 无 rem 回写的 -EINTR / nanosleep 例外）/
///   SA_RESTART 不完成不睡 / 其余完成 -EINTR——随后不 park 直接返回，
///   信号由循环顶检查点建帧投递；
/// - DFL/IGN：同一锁内 take 消费，Term/Core 终止，Ign/Cont/Stop 丢弃。
///
/// `allow_park` 控制落睡，配合运行循环对同一 Wait 的两次调用：第一次
/// allow_park=true 在挂起前决策，无可投递信号才 `sched::park`，返回即
/// 已被唤醒；第二次 allow_park=false 只决策不落睡，把睡中到达的信号
/// 在唤醒点处理完（此前这些信号要等循环顶检查点，会把 sigtimedwait
/// 集合内信号按 DFL 杀掉、令 nanosleep/sigsuspend 被打断后静默续等，
/// 均为 Linux 语义偏差）。返回 [`ParkOutcome`]：Parked 时调用方补第二
/// 次调用（快路径完成臂已推进 PC，二次进入会重复 syscall_ok）；调用方
/// 另以 Completed/Incomplete 维护"syscall 未完成"标志，供检查点在
/// sigsuspend 投递前补 -EINTR 完成。
///
/// DFL/IGN 丢弃臂不在此重挂起：返回后由 syscall 重执行的 Mesa 重查
/// 决定是否继续等。盲目 re-park 会吞掉与本次丢弃同时到达的 children/
/// pipe 唤醒事件——等待条件可能已满足，只有重查才能发现。
///
/// nanosleep 的 EINTR+rem 必须在决策点完成——循环顶检查点只会投递/
/// 杀，handler 返回后 sigreturn 会重执行 ecall，nanosleep 将重读用户
/// 参数从零睡，违反 Linux 语义（对应 Linux ERESTART_RESTARTBLOCK，
/// 禁止朴素重启）。sigtimedwait 同理在决策点完成，但无 rem 回写
///（Linux do_sigtimedwait 的 -EINTR 分支）。
///
/// Flow::Wait（pipe）与 ProcessResult::Wait（wait4/nanosleep/
/// rt_sigsuspend/rt_sigtimedwait）到达此处时 PC/RET 均未推进，EINTR
/// 完成方式相同。
fn park_check_signals(
    pid: Pid,
    reason: WaitReason,
    frame: &mut TrapFrame,
    sleep_deadline: &mut Option<core::time::Duration>,
    timedwait: &mut Option<(SignalSet, core::time::Duration)>,
    allow_park: bool,
) -> ParkOutcome {
    // sigtimedwait 的等待集；Some 即本次挂起属于 rt_sigtimedwait
    //（与 nanosleep 的 Deadline 归属互斥：同一挂起至多一个 Some）。
    let tw_set = timedwait.map(|(set, _)| set);
    let peeked = {
        let mut reg = REGISTRY.lock();
        let rec = reg
            .records
            .iter_mut()
            .find(|r| r.pid == pid)
            .expect("user task unregistered");
        let blocked = rec.signal.blocked();
        // 先查等待集内：Linux dequeue_signal 只在等待集内出队，若先按
        // 全局最低选信号，集合外的低号信号会抢在集合内命中之前被
        // handler/默认动作处理（例如 SIGUSR1 干扰等待 SIGUSR2 的
        // sigtimedwait）。命中即消费，不经处置。
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
                        // handler 分支不消费，peek 的槽不取用；DFL/IGN
                        // 分支经 take_deliverable 另取槽。
                        ParkPeek::Handler(d)
                    } else {
                        // IGN 为防御分支（产生侧已过滤，仅屏蔽后改处置
                        // 可残留）。
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
                // 无可投递信号：挂起（保留 syscall PC，醒来后由调用方
                // 补一次不落睡的重查）。
                sched::park(reason);
                ParkOutcome::Parked
            } else {
                ParkOutcome::Incomplete
            }
        }
        ParkPeek::TwHit { sig, slot } => {
            // uinfo 写失败按 Linux copy_siginfo_to_user 返回 -EFAULT
            //（信号已消费，不回队）。
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
                // sigtimedwait 被集合外 handler 信号打断：清等待状态，
                // 以 -EINTR 完成（无 rem 回写），信号留给循环顶检查点。
                if tw_set.is_some() {
                    *timedwait = None;
                    // Wait 路径原欠一次 syscall_ok，EINTR 完成恰好补上。
                    frame.syscall_ok();
                    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Interrupted));
                } else {
                    // nanosleep 例外：永远走 EINTR 分支（Linux
                    // ERESTART_RESTARTBLOCK，禁止朴素重启——重启即重读
                    // 用户参数从零睡）：清截止时间、回写剩余时间，再以
                    // -EINTR 完成。
                    *sleep_deadline = None;
                    let rem_ptr = frame.args()[1];
                    if rem_ptr != 0 {
                        // 剩余时间 timespec：16 字节 secs/nsecs，rv64/la64
                        // 均小端（与请求解析的字节序一致）。
                        let left = until.saturating_sub(polyhal::timer::current_time());
                        let mut rem = [0u8; 16];
                        rem[..8].copy_from_slice(&left.as_secs().to_ne_bytes());
                        rem[8..].copy_from_slice(&(left.subsec_nanos() as u64).to_ne_bytes());
                        // 新锁段拿地址空间回写；写失败忽略——Linux 不因
                        // rem 写失败改变返回值。
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
            // SA_RESTART：不完成不睡，PC 留在 ecall；信号留在 pending，
            // 循环顶检查点投递 handler，sigreturn 后重执行重查（Linux
            // ERESTARTSYS 重启语义）。
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
            // Ign/Cont/Stop（含防御 IGN）：丢弃即可，不在此重挂起——
            // 由 syscall 重执行的 Mesa 重查决定是否继续等（理由见函数
            // 注释）。syscall 未完成（PC 停在 ecall），据此报 Incomplete。
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
) -> ProcessResult {
    let args = frame.args();
    let nr = frame[TrapFrameArgs::SYSCALL];
    let result: Result<usize, Errno> = match nr {
        sysnr::RT_SIGSUSPEND => {
            // rt_sigsuspend(2)（sys_rt_sigsuspend/sigsuspend）：换入新
            // 屏蔽集合并睡到有可投递信号。旧集合存循环局部
            // sigsuspend_saved（跨重执行保持），由循环顶检查点建 handler
            // 帧时写入帧内 uc_sigmask，sigreturn 自然恢复——handler 期间
            // 运行在换入的临时集合下（Linux saved_sigmask 语义）。对应
            // Linux ERESTARTNOHAND：有 handler 时 -EINTR、无 handler 才
            // 重启；本内核有 handler 时按 -EINTR 完成（偏差登记 docs）。
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
                // 防御性兜底：正常 handler 投递由循环顶检查点取走 saved
                // 并建帧，不会到达本分支。若等待中的信号被 park 快路径
                // 按 DFL/Ign 丢弃（信号已消费、没有帧可建），syscall
                // 重执行会落到这里；恢复换入前的旧集合后以 -EINTR 完成，
                // 保证 saved 不泄漏、临时屏蔽集合不残留。
                if let Some(old) = sigsuspend_saved.take() {
                    let mut reg = REGISTRY.lock();
                    if let Some(rec) = reg.records.iter_mut().find(|r| r.pid == parent) {
                        rec.signal.setmask(old);
                    }
                }
                Err(Errno::Interrupted)
            }
        }
        sysnr::RT_SIGTIMEDWAIT => {
            // rt_sigtimedwait(2)（do_sigtimedwait）：同步等待集合内未
            // 屏蔽信号，命中即取出并返回信号号——不经处置（不建
            // handler 帧、不按默认动作终止，这是它与 sigsuspend 的差
            // 别）；uinfo≠0 时回写 siginfo（写失败 EFAULT，Linux
            // copy_siginfo_to_user 同）；超时 EAGAIN；集合外 handler
            // 信号打断 -EINTR（无 uinfo 写）。等待集与绝对截止时间存
            // 循环局部 timedwait，挂起复用 Deadline 唤醒通道；睡中到
            // 达的信号（含集合内命中与集合外打断）由 Wait 臂睡醒后的
            // 不落睡重查（park_check_signals 第二次调用）按同款语义
            // 完成。drain 不感知等待集：集合外信号也会假唤醒，无害。
            // Linux 的等待集不对当前屏蔽位做交集过滤（内部临时放宽
            // blocked），本实现按"set ∩ 未屏蔽"判定，偏差登记
            // docs/ostd-contracts.md。
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
                // 首次：sigsetsize==8；读集合剥 KILL/STOP；已命中立即
                // 取出返回；未命中读超时（NULL 永等）后挂起。
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
        sysnr::NANOSLEEP => {
            // nanosleep(2)：首次设定绝对截止时间并挂起，到期后重执行
            // 返回 0；正常完成不回写 rem（被信号打断时由 park 快路径
            // 回写剩余时间并返回 -EINTR）。
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
        sysnr::CLONE => fork_user(parent, frame, args[0], args[1]),
        sysnr::WAIT4 => {
            // wait4(2)：wanted <= 0 等任意孩子（无进程组概念，0 与 -1
            // 等价）；>0 指定 pid；其余负值 EINVAL。无可收割孩子时挂起，
            // 无孩子 ECHILD。收割即从注册表删除（生命周期见 mod.rs）。
            if args[2] & !1 != 0 {
                Err(Errno::Invalid)
            } else {
                let wanted = args[0] as isize;
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

/// 从用户空间读 8 字节 sigset_t（sigsuspend/sigtimedwait 共用），
/// 失败折叠为 EFAULT。
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

/// rt_sigtimedwait 命中后的 siginfo 回写（对应 Linux
/// copy_siginfo_to_user）；指针为 0 视作 uinfo==NULL 不写，写失败
/// 返回 EFAULT（信号已消费，不回队）。
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

/// 解析 rt_sigtimedwait 的相对超时（timespec 16 字节；NULL →
/// Duration::MAX 表示永等，Deadline 通道对 MAX 永不到期）。校验与
/// nanosleep 同款：负秒数/纳秒越界 EINVAL，加法溢出 EINVAL。
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

/// rt_sigqueueinfo(2)（sys_rt_sigqueueinfo / do_rt_sigqueueinfo）：
/// 向目标进程发送携带 siginfo 的信号。校验链对应 Linux：读 128 字节
/// siginfo_t（EFAULT）→ si_code 为内核保留码（≥0 或 SI_TKILL，
/// si_code_reserved_to_kernel）且目标非自身 → EPERM → sig>64 EINVAL、
/// sig==0 存在性检查（check_kill_permission / kill 家族同款）。槽映射
/// 按 _rt{pid, uid, value} 布局：errno→si_errno、pid→si_pid@16、
/// value→si_value@24（fill_siginfo 的 SI_QUEUE 臂回写）。标准信号与
/// 实时信号统一位图登记（RT 无排队，偏差登记 docs/ostd-contracts.md）。
fn queue_info(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    // pid_t 32 位：截断后按符号解释；负 pid 回绕为大值，查无此进程
    // 自然落 ESRCH（Linux find_vpid 同果）。
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
    // 内核保留 si_code 只能对自身使用（Linux 允许进程给自己发保留码
    // 信号）；KILL/STOP 与其他信号一样允许排队（kill 家族语义）。
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

/// kill(2)/tgkill(2)（process_call 内、REGISTRY 锁外运行，可自由取
/// 锁）。目标解析：pid>0 → 该 pid；pid==0 → 调用者自身（无进程组概念
/// 的近似）；pid<0 → EINVAL（无进程组，-1 广播不支持）。tgkill 要求
/// tgid==tid（单线程模型）。sig 合法域 0..=64：sig==0 仅做存在性检查
///（目标活跃返回 0，否则 ESRCH）；SIGKILL/SIGSTOP 合法且正常发送。
/// 偏差统一登记 docs/ostd-contracts.md。
fn kill_or_tgkill(parent: Pid, nr: usize, args: [usize; 6]) -> Result<usize, Errno> {
    let (pid_arg, sig_arg) = if nr == sysnr::KILL {
        (args[0], args[1])
    } else {
        // tgkill(tgid, tid, sig)：两者须 > 0 且相等（Linux 校验 >0 且
        // 同一线程组；相等性为本模型的单线程约束）。
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
    // 负信号按 u32 解释为大值，落入 EINVAL（同 Linux valid_signal）。
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
fn fork_user(parent: Pid, frame: &TrapFrame, flags: usize, stack: usize) -> Result<usize, Errno> {
    if flags & !255 != 0 || flags & 255 != 17 {
        return Err(Errno::Invalid);
    }
    let space = {
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
    let task = Task::new_user(pid, "child", child_frame).map_err(|_| Errno::NoMem)?;
    let task = Box::try_new(task).map_err(|_| Errno::NoMem)?;
    super::registry::reserve().map_err(|_| Errno::NoMem)?;
    sched::reserve_task().map_err(|_| Errno::NoMem)?;
    super::registry::register(
        pid,
        "child",
        Some(crate::mm::address_space::LocalSpace(space)),
    );
    {
        let mut reg = REGISTRY.lock();
        // 两段式查找：先取父、子记录下标（各自借用已结束），再以
        // split_at_mut 取得不相交借用，在子记录上就地 fork_from。
        // 不整体 clone 父状态：SignalState 约 4.7 KiB，16 KiB 内核栈
        // 承受不起整表临时值。
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
            // fork 继承备用栈（execve 才清除）；pending/info 由
            // fork_from 清零（Linux copy_signal）。
            let child = &mut reg.records[ci];
            child.parent = parent;
            child.fs = Some(fs);
        }
    }
    sched::enqueue(task);
    Ok(pid)
}
