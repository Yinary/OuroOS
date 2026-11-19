//! 任务与调度子系统：统一任务抽象（内核/用户任务）、进程注册表
//!（收割即删，见 §3 生命周期）、协作 + 时间片调度与等待/唤醒。
//! 完整契约见 docs/ostd-contracts.md §3。

pub mod sched;
pub mod signal;
// Issue 指定的 `task/mod.rs` + `task/task.rs` 布局会自然形成同名子模块。
#[allow(clippy::module_inception)]
mod task;
pub mod user_task;

use alloc::vec::Vec;

use polyhal::{irq::IRQ, println};

use crate::{
    mm, mm::address_space::LocalSpace, sync::DebugMutex, syscall::signal::SA_NOCLDWAIT,
    trap::UserFault,
};

use signal::{SigInfoSlot, SignalState, CLD_EXITED, CLD_KILLED, SIGCHLD, SIG_IGN};

pub use sched::yield_now;
pub use task::{Pid, WaitReason};
pub use user_task::{spawn_user, SpawnError};

/// 一次任务终止的完整记录。
#[derive(Debug, Clone, Copy)]
pub enum ExitInfo {
    /// exit(n) 或等效正常退出。
    Exited(i32),
    /// 死于信号 sig；fault 携带硬件异常细节供终态报告（被 kill 杀死时为 None）。
    Signaled { sig: u8, fault: Option<UserFault> },
}

impl ExitInfo {
    /// 正常退出。
    pub fn exited(code: i32) -> Self {
        Self::Exited(code)
    }
}

/// 进程注册表条目：Task 之外的全部资源与终态。
/// 生命周期：wait 成功收割即从表中删除；孤儿过继内核 init，
/// 已退出者立即删除，活孤儿随后退出时删除，运行时间累归丢弃。
/// 因此表内只存活跃进程与未被收割的僵尸，终态输出在任务时代结束时完成。
pub struct ProcessRecord {
    user_ns: u64,
    system_ns: u64,
    child_user_ns: u64,
    child_system_ns: u64,
    fs: Option<crate::fs::context::Context>,
    /// 信号状态（模型见 signal 模块；投递逻辑由后续 commit 接入）。
    pub signal: SignalState,
    pub pid: Pid,
    pub name: &'static str,
    /// 用户任务的地址空间（单核凭证包装，见 mm::address_space::
    /// LocalSpace）；内核任务与已退出任务为 None。
    /// 放注册表不放 Task 的原因见模块契约“数据模型”。
    pub space: Option<LocalSpace>,
    pub exit: Option<ExitInfo>,
    pub parent: Pid,
}

/// 注册表本体。pid 0 保留（"无任务"标识）。
struct Registry {
    next_pid: Pid,
    records: Vec<ProcessRecord>,
}

static REGISTRY: DebugMutex<Registry> = DebugMutex::new(
    "REGISTRY",
    Registry {
        next_pid: 1,
        records: Vec::new(),
    },
);

/// 终态行积攒表：收割即删后注册表不留历史，输出推迟到时代结束，
/// 避免混入用户程序的测试输出块（官方 oracle 按 START/END 判定）。
static EXIT_REPORTS: DebugMutex<Vec<(Pid, &'static str, ExitInfo)>> =
    DebugMutex::new("EXIT_REPORTS", Vec::new());

/// 注册表访问（调度器登记退出、用户循环取空间共用）。
mod registry {
    use super::*;

    /// 分配下一个 pid。失败路径会产生空洞（只要求唯一性）。
    pub fn alloc_pid() -> Pid {
        let mut reg = REGISTRY.lock();
        let pid = reg.next_pid;
        reg.next_pid += 1;
        pid
    }

    /// 登记前预留容量，错误不会留下半注册的任务。
    pub fn reserve() -> Result<(), SpawnError> {
        REGISTRY
            .lock()
            .records
            .try_reserve(1)
            .map_err(|_| SpawnError::OutOfMemory)
    }
    /// 登记一个进程记录（孵化提交段）。
    pub fn register(pid: Pid, name: &'static str, space: Option<LocalSpace>) {
        let mut reg = REGISTRY.lock();
        reg.records.push(ProcessRecord {
            pid,
            name,
            space,
            exit: None,
            parent: 0,
            user_ns: 0,
            system_ns: 0,
            child_user_ns: 0,
            child_system_ns: 0,
            fs: None,
            signal: SignalState::new(),
        });
    }

    /// 任务退出的唯一登记点：记录终态并释放地址空间。
    /// 终态行积攒到时代末统一输出（不混入用户程序的测试输出块，官方
    /// oracle 按 START/END 块判定）；孤儿过继内核 init，已退出的孤儿
    /// 即收（无消费者，运行时间累归丢弃）。向活跃父进程产生 SIGCHLD
    ///（父 IGN/SA_NOCLDWAIT 时自动收割，语义见 docs/ostd-contracts.md）。
    /// space/fs 的 Drop（页释放、fd 关闭、可能的磁盘回收）在锁外完成，
    /// 避免 REGISTRY 锁内嵌套磁盘 I/O 与反向取锁。
    pub fn record_exit(pid: Pid, exit: ExitInfo) {
        let taken = {
            let mut reg = REGISTRY.lock();
            let rec = reg
                .records
                .iter_mut()
                .find(|r| r.pid == pid)
                .expect("exiting task is not registered");
            rec.exit = Some(exit);
            // 积攒终态行；容量不足时丢弃（打印非关键路径）
            {
                let mut reports = EXIT_REPORTS.lock();
                if reports.try_reserve(1).is_ok() {
                    reports.push((pid, rec.name, exit));
                }
            }
            if let Some(local) = rec.space.as_ref() {
                local.as_space().deactivate();
            }
            let init = INIT_PID.load(core::sync::atomic::Ordering::Relaxed);
            let orphan = rec.parent == init;
            // SIGCHLD 挂接要用的字段先复制出来：父记录要在同一锁作用域
            // 内另行 find（可变借用），不能与 rec 的借用重叠。
            let parent_pid = rec.parent;
            let (own_user, own_system, child_user, child_system) = (
                rec.user_ns,
                rec.system_ns,
                rec.child_user_ns,
                rec.child_system_ns,
            );
            let chld_slot = SigInfoSlot {
                code: match exit {
                    ExitInfo::Exited(_) => CLD_EXITED,
                    ExitInfo::Signaled { .. } => CLD_KILLED,
                },
                pid: pid as u32,
                status: match exit {
                    ExitInfo::Exited(n) => n,
                    ExitInfo::Signaled { sig, .. } => sig as i32,
                },
                ..Default::default()
            };
            let taken = (rec.space.take(), rec.fs.take());
            // SIGCHLD 通知（对应 Linux do_notify_parent/exit_notify）：
            // 父处置 IGN 或 SA_NOCLDWAIT 时自动收割——不产生僵尸，本次
            // 退出的记录在下方 retain 一并移除，运行时间累计并入父（与
            // reap_child 口径一致）；否则向父入队 SIGCHLD。全程持
            // REGISTRY 锁内联完成，禁止嵌套取锁；孤儿路径不通知（父为
            // init，已即收）。
            let auto_reap = if orphan {
                false
            } else {
                match reg
                    .records
                    .iter_mut()
                    .find(|r| r.pid == parent_pid && r.exit.is_none())
                {
                    Some(parent) => {
                        let d = parent.signal.disposition(SIGCHLD);
                        if d.handler == SIG_IGN || d.flags & SA_NOCLDWAIT != 0 {
                            parent.child_user_ns = parent
                                .child_user_ns
                                .saturating_add(own_user.saturating_add(child_user));
                            parent.child_system_ns = parent
                                .child_system_ns
                                .saturating_add(own_system.saturating_add(child_system));
                            true
                        } else {
                            parent.signal.generate(SIGCHLD, chld_slot);
                            false
                        }
                    }
                    // 父记录不在表（如内核任务父为 0）：维持现状，不通知。
                    None => false,
                }
            };
            // 孤儿即收：清理已退出孩子及退出时已过继 init 的任务；
            // 自动收割的记录在此一并移除。
            reg.records.retain(|r| {
                !(r.parent == pid && r.exit.is_some() || (r.pid == pid && (orphan || auto_reap)))
            });
            for child in reg.records.iter_mut().filter(|r| r.parent == pid) {
                child.parent = init;
            }
            // 自检：父进程退出清理僵尸孩子，孤儿退出清理自身。
            debug_assert!(reg.records.iter().all(|r| r.parent != pid));
            debug_assert!(!orphan || reg.records.iter().all(|r| r.pid != pid));
            taken
        };
        // 锁外 Drop：页表/页释放、fd 关闭，可能触发磁盘回收写
        drop(taken);
    }

    /// wait 成功后收割：从表中删除记录并返回子进程的时间累计归属。
    /// 返回（pid, user_ns, system_ns）。
    pub fn reap_child(parent: Pid, target: Pid) -> Option<(u64, u64)> {
        let mut reg = REGISTRY.lock();
        let i = reg
            .records
            .iter()
            .position(|r| r.pid == target && r.parent == parent && r.exit.is_some())?;
        let rec = reg.records.remove(i);
        Some((
            rec.user_ns.saturating_add(rec.child_user_ns),
            rec.system_ns.saturating_add(rec.child_system_ns),
        ))
    }

    /// 注册表是否还有活跃（未退出）进程（init 自身除外）。
    pub fn any_alive() -> bool {
        let reg = REGISTRY.lock();
        reg.records.iter().any(|r| {
            r.pid != INIT_PID.load(core::sync::atomic::Ordering::Relaxed) && r.exit.is_none()
        })
    }

    /// 注册表条目数（自检用，仅 debug 构建调用）。
    #[cfg(debug_assertions)]
    pub fn records_len() -> usize {
        REGISTRY.lock().records.len()
    }

    /// 启动自检：注册表内不应再有未退出的任务（每次启动）。
    /// 终态报告在退出时积攒，这里统一输出。
    pub fn report_all() {
        for (pid, name, exit) in EXIT_REPORTS.lock().iter() {
            match exit {
                ExitInfo::Exited(code) => {
                    println!("[task] pid {} ({}): exited with status {}", pid, name, code)
                }
                ExitInfo::Signaled { sig, fault } => match fault {
                    Some(f) => println!(
                        "[task] pid {} ({}): killed by {:?} @ {:#x}, pc {:#x}",
                        pid, name, f.kind, f.info, f.pc
                    ),
                    None => println!("[task] pid {} ({}): killed by signal {}", pid, name, sig),
                },
            }
        }
    }
}

/// 孵化一个内核任务：入口函数在自己的内核栈上运行，返回即退出(0)。
pub fn spawn_kernel(name: &'static str, entry: fn()) -> Result<Pid, SpawnError> {
    let pid = registry::alloc_pid();
    let task = task::Task::new_kernel(pid, name, entry).map_err(|_| SpawnError::OutOfMemory)?;
    let task = alloc::boxed::Box::try_new(task).map_err(|_| SpawnError::OutOfMemory)?;
    registry::reserve()?;
    sched::reserve_task().map_err(|_| SpawnError::OutOfMemory)?;
    registry::register(pid, name, None);
    sched::enqueue(task);
    Ok(pid)
}

/// 初始化调度器；必须在任何 spawn 之前调用（spawn 会入队）。
pub fn init() {
    sched::init();
    let pid = spawn_kernel("init", init_task).expect("init allocation failed");
    INIT_PID.store(pid, core::sync::atomic::Ordering::Relaxed);
}
static INIT_PID: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
fn init_task() {
    // 孤儿退出时请求唤醒；每次醒来重查是否还有活跃进程。
    while registry::any_alive() {
        sched::park(WaitReason::Children);
    }
}

/// 孵化两个协作内核任务（独立内核栈、主动让出、正常退出）。
pub fn spawn_demo_kthreads() {
    for (name, body) in [("kthread-a", thread_a as fn()), ("kthread-b", thread_b)] {
        match spawn_kernel(name, body) {
            Ok(pid) => println!("[task] spawned {} as pid {}", name, pid),
            Err(e) => println!("[task] spawn {} failed: {:?}", name, e),
        }
    }
}

fn thread_a() {
    for i in 0..5 {
        println!("[kthread] A {}", i);
        if i != 4 {
            yield_now();
        }
    }
}

fn thread_b() {
    for i in 0..5 {
        println!("[kthread] B {}", i);
        if i != 4 {
            yield_now();
        }
    }
}

/// 自检：孵化 OOM 无副作用——零预算下孵化必须失败，且不改帧数、
/// 不登记注册表（仅 selftest 档运行）。
#[cfg(debug_assertions)]
fn spawn_oom_probe() {
    let before = mm::frame::stats();
    let before_len = registry::records_len();
    mm::frame::set_test_budget(Some(0));
    let result = spawn_kernel("oom-probe", || {});
    mm::frame::set_test_budget(None);
    assert!(
        matches!(result, Err(SpawnError::OutOfMemory)),
        "spawn under zero budget must fail"
    );
    assert_eq!(
        mm::frame::stats(),
        before,
        "failed spawn must not change frame stats"
    );
    assert_eq!(
        registry::records_len(),
        before_len,
        "failed spawn must not register"
    );
    log::info!("task: spawn OOM rejected without side effects");
}

#[cfg(not(debug_assertions))]
fn spawn_oom_probe() {}

/// 进入任务时代并运行到全部任务退出，返回前完成回收与帧守恒断言。
/// 返回后由调用方关机（main）。
///
/// `baseline` 是任务时代开始前的帧统计（含已加载镜像、堆等固定开销），
/// 全部退出后必须回到同一数值——kstack 与用户空间的释放被它覆盖。
pub fn run(baseline: (usize, usize)) {
    // 任务时代开始：内核关中断（用户态与 idle 等待两处例外，见契约）
    IRQ::int_disable();
    spawn_oom_probe();
    sched::run_loop();
    // 走到这里 = idle 判定全部退出，dead 已回收
    // 自检：帧守恒——全部任务退出后帧统计必须回到任务时代前的基线，
    // 覆盖内核栈与用户地址空间的回收（每次启动）
    assert_eq!(
        mm::frame::stats(),
        baseline,
        "frame conservation violated after all tasks exited"
    );
    log::info!("task: all tasks exited, frame conservation holds");
    registry::report_all();
    println!("[task] all tasks done");
}

mod exec;
