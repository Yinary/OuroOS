//! 任务描述符：内核栈、KContext、身体（内核入口 / 用户现场+pid）与调度状态。
//! 内核/用户任务差异收敛在 [`TaskBody`]。契约见 docs/ostd-contracts.md §3。

use polyhal::kcontext::{KContext, KContextArgs};
use polyhal_trap::trapframe::TrapFrame;

use crate::{
    config,
    mm::{frame::FrameError, kstack::KernelStack},
};

use super::{sched, user_task};

/// 进程标识；由注册表分配，递增不复用（复用推迟到 wait 语义出现）。
pub type Pid = usize;

/// 任务的执行身体。
///
/// 用户身体携带完整 TrapFrame，与内核身体大小差异大；不用 Box 包裹
/// 是为了避免引入分配失败路径（spawn 的 OOM 语义要求全部可失败步骤
/// 显式返回错误），Task 本身已由调度器装箱，差异可接受。
#[allow(clippy::large_enum_variant)]
pub enum TaskBody {
    /// 内核任务：入口函数运行在自己的内核栈上，返回即退出（码 0）。
    Kernel(fn()),
    /// 用户任务：TrapFrame 是全部用户现场；pid 经注册表解析地址空间。
    User { frame: TrapFrame, pid: Pid },
}

/// 调度状态。本轮没有阻塞语义（阻塞原语是下一阶段工作），
/// Exited 任务进入调度器的待回收表，由 idle 回收内核栈。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Exited,
}

/// 单个任务。
pub struct Task {
    /// 内核上下文：切换的唯一载体。地址稳定性由 Box<Task> 保证。
    pub context: KContext,
    pub body: TaskBody,
    pub state: TaskState,
    pub pid: Pid,
    /// 调试与日志用名。
    pub name: &'static str,
    /// 本时间片起点的 tick；由调度器在切入（promote）时刷新，
    /// 用户任务在逃逸点比较 [`crate::TIMER_TICKS`] 与它决定让出。
    pub slice_tick: usize,
    /// 内核栈（纯所有权字段，仅 Drop 生效，无读取方；下划线豁免
    /// dead_code 检查）。任务回收（idle 的 reap）时最终释放。
    _kstack: KernelStack,
}

impl Task {
    /// 创建内核任务。trampoline 从调度器读取 current 任务后调用入口。
    pub fn new_kernel(pid: Pid, name: &'static str, entry: fn()) -> Result<Self, FrameError> {
        let kstack = KernelStack::new(config::KSTACK_PAGES)?;
        let mut context = KContext::blank();
        context[KContextArgs::KSP] = kstack.top();
        context[KContextArgs::KTP] = read_current_tp();
        context[KContextArgs::KPC] = sched::kernel_trampoline as usize;
        Ok(Self {
            context,
            body: TaskBody::Kernel(entry),
            state: TaskState::Ready,
            pid,
            name,
            slice_tick: 0,
            _kstack: kstack,
        })
    }

    /// 创建用户任务。`frame` 必须已设置好入口 PC 与用户栈顶
    /// （构造时机受 rv sstatus 稳态约束，见 [`super::user_task`]）。
    pub fn new_user(pid: Pid, name: &'static str, frame: TrapFrame) -> Result<Self, FrameError> {
        let kstack = KernelStack::new(config::KSTACK_PAGES)?;
        let mut context = KContext::blank();
        context[KContextArgs::KSP] = kstack.top();
        context[KContextArgs::KTP] = read_current_tp();
        context[KContextArgs::KPC] = user_task::user_task_entry as usize;
        Ok(Self {
            context,
            body: TaskBody::User { frame, pid },
            state: TaskState::Ready,
            pid,
            name,
            slice_tick: 0,
            _kstack: kstack,
        })
    }
}

/// 读取 PolyHAL `context_switch` 实际保存的 `tp` 寄存器。
///
/// PolyHAL 将 percpu 基址放在 riscv64 `gp` / loongarch64 `$r21`，与此处的
/// 任务 `tp` 不是同一寄存器。架构差异因此仅限制在这个辅助函数中。
#[cfg(target_arch = "riscv64")]
fn read_current_tp() -> usize {
    let tp;
    // SAFETY: 只读取当前 CPU 的 `tp`，不修改寄存器、内存或控制流。
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) tp);
    }
    tp
}

/// 读取 PolyHAL `context_switch` 实际保存的 `tp` 寄存器（loongarch64）。
#[cfg(target_arch = "loongarch64")]
fn read_current_tp() -> usize {
    let tp;
    // SAFETY: 只读取当前 CPU 的 `$tp`，不修改寄存器、内存或控制流。
    unsafe {
        core::arch::asm!("move {}, $tp", out(reg) tp);
    }
    tp
}
