//! 用户任务的孵化（ELF → 地址空间 → 初始现场 → 入队）与运行循环
//! （run_user_task + TrapType 消费 + 时间片判定）。契约与孵化时机
//! 约束见 docs/ostd-contracts.md §3。

use alloc::boxed::Box;

use polyhal_trap::{
    trap::{run_user_task, TrapType},
    trapframe::{TrapFrame, TrapFrameArgs},
};

use crate::{
    elf::{self, ElfError},
    mm::address_space::{UserAddressSpace, USER_STACK_TOP},
    syscall::{sysnr, Errno, Flow},
    trap::{self, UserFault},
};

use super::{
    sched::{self, current_ptr},
    task::{Pid, Task, TaskBody, WaitReason},
    ExitInfo, REGISTRY,
};

/// 被用户态致命异常杀死时的退出码。Linux 将死亡原因编码进 wait
/// status 位域；当前以 128+11（SIGSEGV 的 shell 惯例值）作简化占位，
/// 偏差记录在 docs/ostd-contracts.md，wait 语义实现时统一编码。
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
    space.init_heap();
    space.map_stack().map_err(|_| SpawnError::OutOfMemory)?;
    let mut frame = TrapFrame::new();
    frame[TrapFrameArgs::SEPC] = entry;
    // 初始栈包含 argc=0、argv/envp 终止项和 AT_NULL。
    let sp = USER_STACK_TOP - 48;
    crate::mm::user_access::copy_to_user(&space, sp, &[0u8; 48])
        .map_err(|_| SpawnError::OutOfMemory)?;
    frame[TrapFrameArgs::SP] = sp;
    // rv：TrapFrame::new 拷贝当前 sstatus，必须保证回用户态时
    // SPP=0 + SPIE=1（用户态开中断）；loongarch64 侧 new 显式
    // 设 prmd=PLV3|PIE，无此约束。
    #[cfg(target_arch = "riscv64")]
    assert!(
        frame.from_user(),
        "user TrapFrame must re-enter U-mode (check sstatus SPP/SPIE)"
    );
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
        let kernel_start;
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
                let user_start = polyhal::timer::current_time();
                let trap_type = run_user_task(frame);
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
                                    frame,
                                    pid,
                                    &mut space.0,
                                    rec.fs.as_mut().expect("user fs context"),
                                )
                            };
                            // 恰好推进一次 syscall PC：polyhal 对 SysCall
                            // 不推进，重复/遗漏都会破坏用户执行流。
                            // 阻塞（Wait）不推 PC，挂起醒来后重执行重查。
                            let outcome = match flow {
                                Flow::Process => process_call(pid, frame),
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
                                sched::park(reason);
                                continue;
                            }
                            match flow {
                                Flow::Continue | Flow::Process | Flow::Wait(_) => Action::Continue,
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

/// 进程级系统调用的处理结果；等待未完成时挂起并保留 syscall PC。
enum ProcessResult {
    Done,
    Wait(WaitReason),
    Replaced,
}
fn process_call(parent: Pid, frame: &mut TrapFrame) -> ProcessResult {
    let args = frame.args();
    let nr = frame[TrapFrameArgs::SYSCALL];
    let result: Result<usize, Errno> = match nr {
        sysnr::NANOSLEEP => {
            // nanosleep(2)：首次设定绝对截止时间并挂起，到期后重执行
            // 返回 0；剩余时间报告（rem 参数）未支持。
            let task = current_ptr();
            // SAFETY: 当前任务独占字段，短借用不跨调度；挂起前释放。
            let deadline = unsafe { (*task).sleep_deadline };
            if let Some(until) = deadline {
                if polyhal::timer::current_time() < until {
                    return ProcessResult::Wait(WaitReason::Deadline(until));
                }
                // SAFETY: 当前任务尚未切换，字段独占。
                unsafe {
                    (*task).sleep_deadline = None;
                }
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
                            // SAFETY: 当前任务独占该字段，外层释放所有借用后才切换。
                            unsafe {
                                (*task).sleep_deadline = Some(until);
                            }
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
                        let has_children = reg.records.iter().any(|r| matches(r));
                        let status = ready.map(|i| {
                            let info = reg.records[i].exit;
                            info.map_or(0, |e| {
                                if e.fault.is_some() {
                                    11u32
                                } else {
                                    (e.code as u32 & 255) << 8
                                }
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
        _ => Err(Errno::NoSys),
    };
    frame[TrapFrameArgs::RET] = crate::syscall::to_abi(result);
    ProcessResult::Done
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
        if let Some(r) = reg.records.iter_mut().find(|r| r.pid == pid) {
            r.parent = parent;
            r.fs = Some(fs);
        }
    }
    sched::enqueue(task);
    Ok(pid)
}
