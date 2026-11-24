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

/// 任务的执行身体。用户身体携带初始 TrapFrame，首次入口时移到本任务内核栈。
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

/// futex 等待的地址键：物理页帧号与页内字偏移。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexKey {
    pub frame: usize,
    pub offset: usize,
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
    /// 等待任意可投递信号（rt_sigsuspend），仅经 WAKE_SIGNALS 通道唤醒。
    Signal,
    /// ppoll 同时等待管道变化或截止时间。
    PollUntil(core::time::Duration),
    Futex {
        key: FutexKey,
        deadline: Option<core::time::Duration>,
        bitset: u32,
    },
    /// vfork 的父进程等待子进程 exec 或退出。
    Vfork(Pid),
}

impl WaitReason {
    /// 带期限的等待原因返回其到期时刻。
    pub fn deadline(&self) -> Option<core::time::Duration> {
        match self {
            WaitReason::Deadline(d) | WaitReason::PollUntil(d) => Some(*d),
            WaitReason::Futex { deadline, .. } => *deadline,
            _ => None,
        }
    }
}

/// 单个任务。
pub struct Task {
    /// 内核上下文：切换的唯一载体。地址稳定性由 Box<Task> 保证。
    context: KContext,
    pub(super) body: Option<TaskBody>,
    pub(super) state: TaskState,
    pub(super) pid: Pid,
    pub(super) tgid: Pid,
    /// 调试与日志用名。
    pub(super) name: &'static str,
    /// 本时间片的终点；由调度器在切入（promote）时刷新，
    /// 用户任务回用户态前比较当前时间与它决定让出。
    pub(super) slice_end: core::time::Duration,
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
    pub fn new_kernel(
        pid: Pid,
        tgid: Pid,
        name: &'static str,
        entry: fn(),
    ) -> Result<Self, FrameError> {
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
            tgid,
            name,
            slice_end: core::time::Duration::ZERO,
            _kstack: kstack,
        })
    }

    /// 创建用户任务。`frame` 必须已设置好入口 PC 与用户栈顶。
    pub fn new_user(
        pid: Pid,
        tgid: Pid,
        name: &'static str,
        frame: TrapFrame,
    ) -> Result<Self, FrameError> {
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
            tgid,
            name,
            slice_end: core::time::Duration::ZERO,
            _kstack: kstack,
        })
    }
}
