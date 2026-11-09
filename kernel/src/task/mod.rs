//! 任务与调度子系统：统一任务抽象、进程注册表、协作+时间片调度。
//!
//! # 契约（ostd 式，全文与背景见 doc/ostd-contracts.md）
//!
//! ## 执行模型
//! - 用户态的唯一入口是 run_user_task（polyhal-trap）：任务在自己的
//!   内核栈上调用它，续体（内核 sp）暂存于每核槽（rv sscratch /
//!   la SAVE0）。不变量一：**进用户态的内核栈在整个用户态期间存活**，
//!   由"任务未销毁、内核栈不回收"保证。
//! - 不变量二：**每核同时至多一个用户态会话**，由暂存槽唯一指向当前
//!   任务保证；栈的转移只发生在 trap 返回与 context_switch 两处。
//! - PC 推进语义由 HAL 分走：rv 断点 +2 在 polyhal 回调前做，syscall
//!   由 `TrapFrame::syscall_ok()`（rv sepc+4 / la era+4）恰好推进一次。
//! - EscapeReason 有损（polyhal 缺陷 5），用户异常完整信息经 trap.rs
//!   的 percpu 事件槽带出；NoReason 不等于无事发生（la 非对齐模拟）。
//!
//! ## 中断与抢占
//! - 内核态一律关中断；中断只在两处开启：用户态执行期间（TrapFrame
//!   的 SPIE/PIE 管理）、idle 等待（wait_for_interrupt 短暂开中断）。
//! - 抢占只发生在用户态逃逸点（run_user_task 返回后）；内核路径不可
//!   抢占。内核任务靠协作 yield，必须在有限步内让出或退出。
//! - 时钟信号不丢失：内核处理期间到期的 tick 挂起，回用户态立即送达。
//! - trap 回调不取锁（当前模型下中断本进不了内核，此条为冗余保险）。
//!
//! ## 数据模型
//! - Task = 调度单元（内核栈 + KContext + 身体 + 状态 + pid）；
//!   Process 记录 = 资源容器（地址空间 + 退出信息），住在静态注册表。
//!   两者从第一天分离，为线程（多 Task 共享一个 Process）预留。
//! - **地址空间只能住在注册表，不进 Task**：UserAddressSpace 为 !Send
//!   （mm 契约：TLB shootdown 未实现），静态就绪队列要求元素 Send。
//!   经 pid 查表取用，SMP 化时欠账集中在查表路径。
//! - pid 递增不复用；孵化失败产生空洞（只要求唯一性）。
//! - CURRENT（percpu）是"我是谁"的唯一事实来源，trampoline 与运行
//!   循环经它取自身。
//!
//! ## 生命周期
//! - 本轮无 fork ⇒ 无父子 ⇒ 无 wait/僵尸：**退出即全回收**（记录退出
//!   信息供启动汇总，地址空间与内核栈全部释放）。fork 引入后再升级
//!   为"退出转僵尸"。
//! - exit(n) 退出码为 n；被致命异常杀死的任务用 128+11 占位（Linux
//!   编码进 wait status 位域，偏差记录于 doc/ostd-contracts.md）。
//!
//! ## 时间片
//! - 固定 tick 轮转，无优先级；切入时刷新 slice_tick，用户任务在
//!   逃逸点比较 TIMER_TICKS 决定让出。
//!
//! ## 孵化时机
//! - rv 的 TrapFrame::new 拷贝当前 sstatus，初始用户现场依赖
//!   SPP=0/SPIE=1 的开中断稳态：**spawn 必须发生在进入任务时代
//!   （int_disable）之前**。spawn 内有断言兜底。
//!
//! ## 已知妥协与欠账（记录在案）
//! - polyhal 未打补丁（本轮明确不改依赖）：EscapeReason 有损 → 事件
//!   侧信道（trap.rs percpu 槽）暂留；la 用户非法指令等未分类异常在
//!   polyhal 层直接 panic（缺陷 7）——进程设计立项 patch 时一并解决。
//! - 内核栈经直映访问、无保护页（mm/kstack.rs 头部说明），虚拟窗口
//!   与 guard page 为欠账。
//! - 阻塞/唤醒原语、锁序图、SMP（TLB shootdown、percpu 队列）欠账。

pub mod sched;
// Issue 指定的 `task/mod.rs` + `task/task.rs` 布局会自然形成同名子模块。
#[allow(clippy::module_inception)]
mod task;
pub mod user_task;

use alloc::vec::Vec;

use polyhal::{irq::IRQ, println};

use crate::{mm, mm::address_space::LocalSpace, sync::DebugMutex, trap::UserFault};

pub use sched::yield_now;
pub use task::Pid;
pub use user_task::{spawn_user, SpawnError};

/// 一次任务终止的完整记录。
#[derive(Debug, Clone, Copy)]
pub struct ExitInfo {
    /// 退出码：exit(n) 为 n；被杀为 128+11 占位（见模块契约）。
    pub code: i32,
    /// 致命用户异常（死因）；正常 exit 为 None。
    pub fault: Option<UserFault>,
}

impl ExitInfo {
    /// 正常退出。
    pub fn exited(code: i32) -> Self {
        Self { code, fault: None }
    }
}

/// 进程注册表条目：Task 之外的全部资源与终态。
pub struct ProcessRecord {
    pub pid: Pid,
    pub name: &'static str,
    /// 用户任务的地址空间（单核凭证包装，见 mm::address_space::
    /// LocalSpace）；内核任务与已退出任务为 None。
    /// 放注册表不放 Task 的原因见模块契约"数据模型"。
    pub space: Option<LocalSpace>,
    pub exit: Option<ExitInfo>,
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

    /// 登记一个进程记录（孵化提交段）。
    pub fn register(pid: Pid, name: &'static str, space: Option<LocalSpace>) {
        let mut reg = REGISTRY.lock();
        reg.records.push(ProcessRecord {
            pid,
            name,
            space,
            exit: None,
        });
    }

    /// 任务退出的唯一登记点：记录终态并释放地址空间。
    /// 先显式切回内核页表再置 None 触发释放（Drop 兜底同款逻辑），
    /// 顺序与旧 user.rs 一致；锁序 REGISTRY → FRAME（见 sync.rs 契约）。
    pub fn record_exit(pid: Pid, exit: ExitInfo) {
        let mut reg = REGISTRY.lock();
        let rec = reg
            .records
            .iter_mut()
            .find(|r| r.pid == pid)
            .expect("exiting task is not registered");
        rec.exit = Some(exit);
        if let Some(local) = rec.space.as_ref() {
            local.as_space().deactivate();
        }
        // take+drop 在锁内完成：空间释放不可再失败
        rec.space = None;
    }

    /// 注册表条目数（自检用，仅 debug 构建调用）。
    #[cfg(debug_assertions)]
    pub fn records_len() -> usize {
        REGISTRY.lock().records.len()
    }

    /// 启动汇总：逐进程报告终态。运行在 boot 栈（全部任务退出后）。
    pub fn report_all() {
        let reg = REGISTRY.lock();
        for rec in reg.records.iter() {
            match &rec.exit {
                Some(info) => match &info.fault {
                    None => println!(
                        "[task] pid {} ({}): exited with status {}",
                        rec.pid, rec.name, info.code
                    ),
                    Some(f) => println!(
                        "[task] pid {} ({}): killed by {:?} @ {:#x}, pc {:#x}",
                        rec.pid, rec.name, f.kind, f.info, f.pc
                    ),
                },
                None => println!(
                    "[task] pid {} ({}): still running (scheduler bug)",
                    rec.pid, rec.name
                ),
            }
        }
    }
}

/// 孵化一个内核任务：入口函数在自己的内核栈上运行，返回即退出(0)。
pub fn spawn_kernel(name: &'static str, entry: fn()) -> Result<Pid, SpawnError> {
    let pid = registry::alloc_pid();
    let task = task::Task::new_kernel(pid, name, entry).map_err(|_| SpawnError::OutOfMemory)?;
    registry::register(pid, name, None);
    sched::enqueue(alloc::boxed::Box::new(task));
    Ok(pid)
}

/// 初始化调度器；必须在任何 spawn 之前调用（spawn 会入队）。
pub fn init() {
    sched::init();
}

/// 孵化两个协作内核任务，延续旧 run_demo 的行为自检覆盖
/// （独立内核栈、主动让出、正常退出、栈回收）。
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

/// 孵化失败路径自检（debug 构建）：帧预算清零后孵化必须失败且无副作用。
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
    // 走到这里 = idle 判定全部退出，dead 已由 idle 回收
    assert_eq!(
        mm::frame::stats(),
        baseline,
        "frame conservation violated after all tasks exited"
    );
    log::info!("task: all tasks exited, frame conservation holds");
    registry::report_all();
    println!("[task] all tasks done");
}
