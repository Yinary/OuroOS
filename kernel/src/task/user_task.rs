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
    mm::address_space::{UserAddressSpace, USER_STACK_TOP},
    syscall::{signal::SA_RESTART, sysnr, Errno, Flow},
    trap::{self, UserFault},
};

use super::{
    sched,
    signal::{
        default_action, fault_siginfo, force_signal, send_signal, DefaultAction, SigInfoSlot,
        SignalDisposition, SIG_DFL, SIG_IGN,
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
                // 检查点消费；commit 6 在此建帧投递。handler 临时映射：
                // 用户 handler 本轮按 DFL 判定（见 delivery_verdict）。
                let blocked = rec.signal.blocked();
                rec.signal
                    .take_deliverable(blocked)
                    .and_then(|(sig, slot)| {
                        let d = rec.signal.disposition(sig);
                        delivery_verdict(sig, slot, d)
                    })
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
                            // 阻塞（Wait）不推 PC，挂起醒来后重执行重查。
                            let outcome = match flow {
                                Flow::Process => {
                                    process_call(pid, &mut frame, &mut sleep_deadline)
                                }
                                Flow::Wait(reason) => ProcessResult::Wait(reason),
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
                                    Flow::Continue | Flow::Process | Flow::Wait(_) => {
                                        Action::Continue
                                    }
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
            // park 前快路径：信号决策表见 park_check_signals。
            Action::Wait(reason) => {
                park_check_signals(pid, reason, &mut frame, &mut sleep_deadline)
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

/// 单个已取出信号的投递判定（循环顶检查点与 park 快路径共用）。
/// handler 临时映射：用户 handler（≠DFL/IGN）本轮按 DFL 判定——真实
/// 建帧投递由后续 commit 接入（偏差登记 docs/ostd-contracts.md）；
/// IGN 理论上不可达（产生侧已过滤，仅屏蔽后改处置可残留），防御性
/// 丢弃。Term/Core 返回 Signaled 死因（fault 槽透传终态报告）；
/// Ign/Cont 丢弃；Stop 无停止态，降级为丢弃（登记 docs）。
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

/// park 快路径对 peek 到的信号的去向。
enum ParkPeek {
    /// 无可投递信号。
    Empty,
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

/// park 快路径：挂起前先看有无可投递信号，按真实处置分岔。peek 不消费：
/// - handler（≠DFL/IGN）：信号留在 pending，按 reason 分岔——nanosleep
///   例外 / SA_RESTART 不完成不睡 / 其余完成 -EINTR——随后不 park 直接
///   返回，信号由循环顶检查点消费（commit 5 临时映射按 DFL，commit 6
///   在该检查点建帧投递）；
/// - DFL/IGN：同一锁内 take 消费，Term/Core 终止，Ign/Cont/Stop 丢弃
///   后照旧 park。
///
/// nanosleep 的 EINTR+rem 必须在 park 前完成——循环顶检查点只会投递/
/// 杀，handler 返回后 sigreturn 会重执行 ecall，nanosleep 将重读用户
/// 参数从零睡，违反 Linux 语义（对应 Linux ERESTART_RESTARTBLOCK，
/// 禁止朴素重启）。
///
/// Flow::Wait（pipe）与 ProcessResult::Wait（wait4/nanosleep）到达此处
/// 时 PC/RET 均未推进，EINTR 完成方式相同。
fn park_check_signals(
    pid: Pid,
    reason: WaitReason,
    frame: &mut TrapFrame,
    sleep_deadline: &mut Option<core::time::Duration>,
) {
    let peeked = {
        let mut reg = REGISTRY.lock();
        let rec = reg
            .records
            .iter_mut()
            .find(|r| r.pid == pid)
            .expect("user task unregistered");
        let blocked = rec.signal.blocked();
        match rec.signal.peek_deliverable(blocked) {
            None => ParkPeek::Empty,
            // handler 分支不消费，peek 的槽不取用；DFL/IGN 分支经
            // take_deliverable 另取槽。
            Some((sig, _)) => {
                let d = rec.signal.disposition(sig);
                if d.handler != SIG_DFL && d.handler != SIG_IGN {
                    ParkPeek::Handler(d)
                } else {
                    // DFL/IGN：同一锁内 take 消费——锁未放开状态不变，
                    // take 与 peek 必为同一最低信号；IGN 为防御分支
                    //（产生侧已过滤，仅屏蔽后改处置可残留）。
                    let (sig, slot) = rec
                        .signal
                        .take_deliverable(blocked)
                        .expect("peeked signal still deliverable");
                    ParkPeek::Default { sig, slot, d }
                }
            }
        }
    };
    match peeked {
        ParkPeek::Empty => {
            // 无可投递信号：照旧挂起（保留 syscall PC，醒来后重执行）。
            sched::park(reason);
        }
        ParkPeek::Handler(d) => match reason {
            // nanosleep 例外：永远走 EINTR 分支（Linux
            // ERESTART_RESTARTBLOCK，禁止朴素重启——重启即重读用户参数
            // 从零睡）：清截止时间、回写剩余时间，再以 -EINTR 完成。
            WaitReason::Deadline(until) => {
                *sleep_deadline = None;
                let rem_ptr = frame.args()[1];
                if rem_ptr != 0 {
                    // 剩余时间 timespec：16 字节 secs/nsecs，rv64/la64
                    // 均小端（与请求解析的字节序一致）。
                    let left = until.saturating_sub(polyhal::timer::current_time());
                    let mut rem = [0u8; 16];
                    rem[..8].copy_from_slice(&left.as_secs().to_ne_bytes());
                    rem[8..].copy_from_slice(&(left.subsec_nanos() as u64).to_ne_bytes());
                    // 新锁段拿地址空间回写；写失败忽略——Linux 不因 rem
                    // 写失败改变返回值。
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
            // SA_RESTART：不完成不睡，PC 留在 ecall；信号留在 pending，
            // 循环顶检查点投递 handler，sigreturn 后重执行重查（Linux
            // ERESTARTSYS 重启语义）。
            WaitReason::Pipe | WaitReason::Children if d.flags & SA_RESTART != 0 => {}
            // 其余：完成 syscall 返回 -EINTR；信号留给循环顶检查点。
            _ => {
                frame.syscall_ok();
                frame[TrapFrameArgs::RET] = crate::syscall::to_abi(Err(Errno::Interrupted));
            }
        },
        ParkPeek::Default { sig, slot, d } => match delivery_verdict(sig, slot, d) {
            // Term/Core：已消费，按默认动作终止。
            Some(info) => sched::exit_current(info),
            // Ign/Cont/Stop（含防御 IGN）：丢弃后照旧挂起。
            None => sched::park(reason),
        },
    }
}

/// 进程级系统调用的处理结果；等待未完成时挂起并保留 syscall PC。
enum ProcessResult {
    Done,
    Wait(WaitReason),
    Replaced,
}
fn process_call(
    parent: Pid,
    frame: &mut TrapFrame,
    sleep_deadline: &mut Option<core::time::Duration>,
) -> ProcessResult {
    let args = frame.args();
    let nr = frame[TrapFrameArgs::SYSCALL];
    let result: Result<usize, Errno> = match nr {
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
        // fork 继承：子进程整体拷贝父进程的信号状态（同一次锁内完成）
        let parent_signal = reg
            .records
            .iter()
            .find(|r| r.pid == parent)
            .map(|r| r.signal.clone());
        if let Some(r) = reg.records.iter_mut().find(|r| r.pid == pid) {
            r.parent = parent;
            r.fs = Some(fs);
            if let Some(sig_state) = parent_signal {
                r.signal = sig_state;
            }
        }
    }
    sched::enqueue(task);
    Ok(pid)
}
