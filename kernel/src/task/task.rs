//! 任务描述符：内核栈、KContext、身体（内核入口 / 用户现场+pid）与调度状态。
//! 内核/用户任务差异收敛在 [`TaskBody`]。契约见 docs/ostd-contracts.md §3。
#![deny(unsafe_code)]

use polyhal::kcontext::{KContext, KContextArgs};
use polyhal_trap::trapframe::TrapFrame;

use crate::{
    config,
    mm::{frame::FrameError, kstack::KernelStack},
};

use super::{sched, user_task};

/// 进程标识；由注册表分配，递增不复用。
pub type Pid = usize;

/// 任务的执行身体。
///
/// 用户身体携带初始 TrapFrame，首次入口时移到本任务内核栈；不用 Box
/// 包裹，避免增加孵化的分配失败路径。
#[allow(clippy::large_enum_variant)]
pub enum TaskBody {
    /// 内核任务：入口函数运行在自己的内核栈上，返回即退出（码 0）。
    Kernel(fn()),
    /// 用户任务：TrapFrame 是全部用户现场；pid 经注册表解析地址空间。
    User { frame: TrapFrame, pid: Pid },
}

/// 调度状态。Waiting 任务驻留等待表，由事件唤醒或到期扫描搬回就绪表；
/// Exited 任务进入调度器的待回收表，切到其他栈后回收内核栈。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Waiting,
    Exited,
}

/// 任务挂起的原因；唤醒采用宽松匹配（醒来重查条件）而非精确订阅。
/// 任何 pipe 状态变化唤醒全部 Pipe 等待者（单核惊群可忽略），
/// 子进程退出唤醒全部 Children 等待者。
#[derive(Clone, Copy, Debug)]
pub enum WaitReason {
    /// 绝对截止时间（nanosleep / rt_sigtimedwait）。
    Deadline(core::time::Duration),
    /// 等待子进程退出（waitpid 无可收割孩子）。
    Children,
    /// 等待任意 pipe 可读/可写。
    Pipe,
    /// 等待任意可投递信号（rt_sigsuspend）。仅经 WAKE_SIGNALS 通道
    /// 唤醒：其余三条唤醒通道按具体变体 matches! 判定，不会匹配本
    /// 变体（Deadline 只被到期扫描匹配，Children/Pipe 只被各自事件
    /// 标志匹配），天然不冲突。
    Signal,
}

/// 单个任务。
pub struct Task {
    /// 内核上下文：切换的唯一载体。地址稳定性由 Box<Task> 保证。
    context: KContext,
    pub(super) body: Option<TaskBody>,
    pub(super) state: TaskState,
    pub(super) pid: Pid,
    /// 调试与日志用名。
    pub(super) name: &'static str,
    /// 本时间片起点的 tick；由调度器在切入（promote）时刷新，
    /// 用户任务在逃逸点比较 [`crate::TIMER_TICKS`] 与它决定让出。
    pub(super) slice_tick: usize,
    /// 内核栈（纯所有权字段，仅 Drop 生效，无读取方；下划线豁免
    /// dead_code 检查）。任务回收时最终释放。
    _kstack: KernelStack,
}

impl Task {
    /// 返回稳定内核上下文地址，供调度器切换时使用。
    pub(super) fn context_ptr(&mut self) -> *mut KContext {
        &mut self.context
    }

    /// 创建内核任务。trampoline 从调度器读取 current 任务后调用入口。
    pub fn new_kernel(pid: Pid, name: &'static str, entry: fn()) -> Result<Self, FrameError> {
        let kstack = KernelStack::new(config::KSTACK_PAGES)?;
        let mut context = KContext::blank();
        context[KContextArgs::KSP] = kstack.top();
        context[KContextArgs::KTP] = crate::hal::read_current_tp();
        context[KContextArgs::KPC] = sched::kernel_trampoline as usize;
        Ok(Self {
            context,
            body: Some(TaskBody::Kernel(entry)),
            state: TaskState::Ready,
            pid,
            name,
            slice_tick: 0,
            _kstack: kstack,
        })
    }

    /// 创建用户任务。`frame` 必须已设置好入口 PC 与用户栈顶。
    pub fn new_user(pid: Pid, name: &'static str, frame: TrapFrame) -> Result<Self, FrameError> {
        let kstack = KernelStack::new(config::KSTACK_PAGES)?;
        let mut context = KContext::blank();
        context[KContextArgs::KSP] = kstack.top();
        context[KContextArgs::KTP] = crate::hal::read_current_tp();
        context[KContextArgs::KPC] = user_task::user_task_entry as usize;
        Ok(Self {
            context,
            body: Some(TaskBody::User { frame, pid }),
            state: TaskState::Ready,
            pid,
            name,
            slice_tick: 0,
            _kstack: kstack,
        })
    }
}
