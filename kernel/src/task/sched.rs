//! 调度器核心：就绪/等待/退出三表、当前任务（percpu）、上下文切换、
//! 事件唤醒标志与到期扫描、idle。模型见 docs/ostd-contracts.md §3。

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::{
    cell::Cell,
    ptr::{addr_of, addr_of_mut},
    sync::atomic::{AtomicBool, Ordering},
};

use polyhal::{
    irq::IRQ,
    kcontext::{context_switch, KContext},
};

// polyhal 只在 riscv64 封装了 wfi（hlt）；la 未提供 idle 指令封装，
// 差异收敛在 wait_for_interrupt 一处（见其注释）。
#[cfg(target_arch = "riscv64")]
use polyhal::instruction::hlt;

use crate::{
    sync::{self, DebugMutex},
    TIMER_TICKS,
};

use super::{
    registry,
    task::{Task, TaskBody, TaskState, WaitReason},
    ExitInfo,
};

/// 当前任务地址（0 = idle）。以整数存址而不是裸指针：percpu 槽要求
/// 内容可跨“线程”声明安全，裸指针 !Send 会被静态拒收（与进程注册表
/// 的单核凭证同理，见 mm::address_space::LocalSpace）。
/// 单核 + 内核关中断下仅被调度器与当前任务自身访问。
#[polyhal::percpu]
static CURRENT: Cell<usize> = Cell::new(0);

/// 事件方（fs 层、退出路径）请求唤醒的合并标志；无锁置位，
/// 在下一次调度边界统一消费。避免 fs 层在 REGISTRY 锁内反向取 SCHED。
static WAKE_CHILDREN: AtomicBool = AtomicBool::new(false);
static WAKE_PIPES: AtomicBool = AtomicBool::new(false);

/// 请求唤醒等待子进程的任务（子进程退出时调用）。
pub fn request_children_wake() {
    WAKE_CHILDREN.store(true, Ordering::Release);
}

/// 请求唤醒 pipe 等待者（pipe 读/写/对端关闭时调用）。
pub fn request_pipe_wake() {
    WAKE_PIPES.store(true, Ordering::Release);
}

/// 读取当前任务指针（调用方保证处于任务上下文）。
pub(super) fn current_ptr() -> *mut Task {
    let addr = CURRENT.get();
    assert!(addr != 0, "no current task on this cpu");
    addr as *mut Task
}

/// 写入当前任务地址（0 表示 idle）。仅调度器调用。
fn set_current(ptr: *mut Task) {
    CURRENT.set(ptr as usize);
}

struct Scheduler {
    ready: VecDeque<Box<Task>>,
    current: Option<Box<Task>>,
    /// 等待表：任务与挂起原因同存；唤醒采用宽松匹配，醒来重查条件。
    waiting: Vec<(Box<Task>, WaitReason)>,
    /// 已退出任务；内核栈已无执行流，等 idle 回收。
    #[allow(clippy::vec_box)] // 已退出任务的上下文仍须地址稳定直到切走。
    dead: Vec<Box<Task>>,
    /// idle（boot 栈）的内核上下文；最后一个任务退出时切回这里。
    idle_ctx: KContext,
}

static SCHED: DebugMutex<Option<Scheduler>> = DebugMutex::new("SCHED", None);

/// 当前核时钟 tick（任务全部运行在启动核上）。
fn current_tick() -> usize {
    TIMER_TICKS.load(Ordering::Relaxed)
}

impl Scheduler {
    /// 把任务立为当前任务：置 Running、刷新时间片起点、更新 CURRENT。
    /// 返回其 KContext 地址（Box 保证稳定）。
    fn promote(&mut self, mut task: Box<Task>) -> *const KContext {
        task.state = TaskState::Running;
        task.slice_tick = current_tick();
        let pid = task.pid;
        let ptr: *mut Task = &mut *task;
        self.current = Some(task);
        set_current(ptr);
        sync::set_holder(pid);
        // SAFETY: ptr 指向刚放入 current 的 Box<Task>，存活由调度器保证。
        unsafe { addr_of!((*ptr).context) }
    }

    /// 回收已退出的任务：drop Box → 释放内核栈帧。
    /// 只能在这些任务的内核栈已无执行流时调用（idle 循环内满足）。
    fn reap_dead(&mut self) {
        self.dead.clear();
    }

    /// 消费事件唤醒标志，把匹配的等待者搬回就绪表。
    fn drain_wake_requests(&mut self) {
        if WAKE_CHILDREN.swap(false, Ordering::AcqRel) {
            self.move_waiting(|r| matches!(r, WaitReason::Children));
        }
        if WAKE_PIPES.swap(false, Ordering::AcqRel) {
            self.move_waiting(|r| matches!(r, WaitReason::Pipe));
        }
    }

    /// 到期扫描：Deadline 已到的等待者搬回就绪表。
    fn wake_expired(&mut self) {
        let now = polyhal::timer::current_time();
        self.move_waiting(|r| match r {
            WaitReason::Deadline(d) => now >= *d,
            _ => false,
        });
    }

    fn move_waiting(&mut self, f: impl Fn(&WaitReason) -> bool) {
        let mut i = 0;
        while i < self.waiting.len() {
            if f(&self.waiting[i].1) {
                let (task, _) = self.waiting.swap_remove(i);
                self.ready.push_back(task);
            } else {
                i += 1;
            }
        }
    }
}

/// 初始化调度器（一次）。任务需在此之后入队。
pub(super) fn init() {
    let mut slot = SCHED.lock();
    assert!(slot.is_none(), "scheduler initialized twice");
    *slot = Some(Scheduler {
        ready: VecDeque::new(),
        current: None,
        waiting: Vec::new(),
        dead: Vec::new(),
        idle_ctx: KContext::blank(),
    });
}

/// 孵化提交前预留就绪/等待/退出队列容量；切换、park 与退出本身不再分配。
pub(super) fn reserve_task() -> Result<(), crate::mm::frame::FrameError> {
    let mut slot = SCHED.lock();
    let s = slot.as_mut().expect("scheduler not initialized");
    s.ready
        .try_reserve(2)
        .map_err(|_| crate::mm::frame::FrameError::OutOfMemory)?;
    s.waiting
        .try_reserve(1)
        .map_err(|_| crate::mm::frame::FrameError::OutOfMemory)?;
    let live = s.ready.len() + usize::from(s.current.is_some()) + s.waiting.len() + 1;
    s.dead
        .try_reserve(live)
        .map_err(|_| crate::mm::frame::FrameError::OutOfMemory)?;
    Ok(())
}
/// 任务入就绪队列队尾。
pub(super) fn enqueue(task: Box<Task>) {
    let mut slot = SCHED.lock();
    slot.as_mut()
        .expect("scheduler not initialized")
        .ready
        .push_back(task);
}

/// 当前任务主动让出：回就绪队列队尾，切到队首（只有自己时切回自己）。
/// 切换前统一消费事件唤醒与到期扫描。
pub fn yield_now() {
    sync::assert_no_held("yield_now");
    let cur_ptr = current_ptr();
    let (from, to) = {
        let mut slot = SCHED.lock();
        let s = slot.as_mut().expect("scheduler not initialized");
        let mut cur = s.current.take().expect("yield without current task");
        // SAFETY: cur_ptr 与 cur 指向同一 Box；此处只借用地址，
        // Box 移入队列不影响堆上地址稳定性。
        let from = unsafe { addr_of_mut!((*cur_ptr).context) };
        debug_assert_eq!(cur_ptr, &mut *cur as *mut Task);
        cur.state = TaskState::Ready;
        s.ready.push_back(cur);
        s.drain_wake_requests();
        s.wake_expired();
        let next = s
            .ready
            .pop_front()
            .expect("ready queue must contain the yielding task");
        let to = s.promote(next);
        (from, to)
    };
    switch_context(from, to);
}

/// 当前任务挂起等待：移入等待表并切到下一个就绪任务（或 idle）。
/// 切回点即 park 调用点，syscall PC 由调用方保留以便重执行重查条件；
/// 等待表容量耗尽时退化为就绪让出（不分配、不失败，条件重查仍正确）。
pub fn park(reason: WaitReason) {
    sync::assert_no_held("park");
    let cur_ptr = current_ptr();
    let (from, to) = {
        let mut slot = SCHED.lock();
        let s = slot.as_mut().expect("scheduler not initialized");
        let mut cur = s.current.take().expect("park without current task");
        // SAFETY: 同 yield_now；Box 随后移入等待表或就绪表，地址不变。
        let from = unsafe { addr_of_mut!((*cur_ptr).context) };
        debug_assert_eq!(cur_ptr, &mut *cur as *mut Task);
        s.drain_wake_requests();
        s.wake_expired();
        if s.waiting.len() < s.waiting.capacity() {
            cur.state = TaskState::Waiting;
            s.waiting.push((cur, reason));
        } else {
            cur.state = TaskState::Ready;
            s.ready.push_back(cur);
        }
        let to = match s.ready.pop_front() {
            Some(next) => s.promote(next),
            None => {
                set_current(core::ptr::null_mut());
                sync::set_holder(0);
                addr_of!(s.idle_ctx)
            }
        };
        (from, to)
    };
    switch_context(from, to);
}

/// 当前任务退出：登记退出信息、释放地址空间、移入 dead 表并永久切走。
/// 永不返回。退出信息的登记与空间释放集中在这里，调用方无需善后。
/// 唤醒等待子进程退出的父任务（事件点直接唤醒，此时不持任何锁）。
pub(super) fn exit_current(exit: ExitInfo) -> ! {
    sync::assert_no_held("exit_current");
    let cur_ptr = current_ptr();
    // SAFETY: 指针来自调度器切入时设置的合法 Box<Task>；
    // 单核关中断下该 Box 在此期间不会被移动或释放。
    let pid = unsafe { (*cur_ptr).pid };
    log::debug!(
        "task '{}' (pid {}) exiting",
        unsafe { (*cur_ptr).name },
        pid
    );
    // 登记退出信息并释放地址空间：UserAddressSpace 的 Drop 会先切回
    // 内核页表（若仍活动）再释放数据页/页表页。此刻仍在自己的内核栈上，
    // 内核栈经直映访问，不受页表切换影响。锁序 REGISTRY → FRAME。
    registry::record_exit(pid, exit);
    request_children_wake();
    let (from, to) = {
        let mut slot = SCHED.lock();
        let s = slot.as_mut().expect("scheduler not initialized");
        let mut cur = s.current.take().expect("exit without current task");
        // SAFETY: 同 yield_now；Box 随后移入 dead 表，地址不变。
        let from = unsafe { addr_of_mut!((*cur_ptr).context) };
        debug_assert_eq!(cur_ptr, &mut *cur as *mut Task);
        cur.state = TaskState::Exited;
        s.dead.push(cur);
        s.drain_wake_requests();
        s.wake_expired();
        match s.ready.pop_front() {
            Some(next) => {
                let to = s.promote(next);
                (from, to)
            }
            None => {
                set_current(core::ptr::null_mut());
                sync::set_holder(0);
                (from, addr_of!(s.idle_ctx))
            }
        }
    };
    switch_context(from, to);
    unreachable!("exited task was resumed")
}

/// 内核任务 trampoline：从 current 读取入口，执行完即退出（码 0）。
pub(super) extern "C" fn kernel_trampoline() -> ! {
    let entry = {
        let task = current_ptr();
        // SAFETY: trampoline 只在调度器切入后执行，current 有效；
        // 只读取 body 期间不发生任何切换。
        unsafe {
            match (*task).body {
                TaskBody::Kernel(f) => f,
                TaskBody::User { .. } => panic!("user task entered kernel trampoline"),
            }
        }
    };
    entry();
    exit_current(ExitInfo::exited(0))
}

/// 等待中断：idle 专属。短暂开中断（此时只有时钟源），醒来立即关回。
fn wait_for_interrupt() {
    IRQ::int_enable();
    #[cfg(target_arch = "riscv64")]
    hlt();
    // la 侧自旋等钟（HAL 未封装 idle，见 docs/ostd-contracts.md §2）
    #[cfg(target_arch = "loongarch64")]
    core::hint::spin_loop();
    IRQ::int_disable();
}

/// 调度器主循环，运行在 boot 栈（idle）；返回 = 全部任务已退出。
/// 每轮先回收退出任务、消费唤醒请求与到期扫描；就绪表空而等待表
/// 非空时等时钟推进（等待者中可能有待到期者），两表皆空才算全部结束。
pub(super) fn run_loop() {
    loop {
        let next = {
            let mut slot = SCHED.lock();
            let s = slot.as_mut().expect("scheduler not initialized");
            s.reap_dead();
            s.drain_wake_requests();
            s.wake_expired();
            s.ready.pop_front().map(|task| s.promote(task))
        };
        match next {
            Some(to) => {
                let from = {
                    let mut slot = SCHED.lock();
                    addr_of_mut!(slot.as_mut().expect("scheduler not initialized").idle_ctx)
                };
                switch_context(from, to);
                // 被最后一个任务切回：继续循环（回收、找下一个）
            }
            None => {
                let all_done = {
                    let slot = SCHED.lock();
                    let s = slot.as_ref().expect("scheduler not initialized");
                    s.current.is_none() && s.ready.is_empty() && s.waiting.is_empty()
                };
                if all_done {
                    return;
                }
                // 就绪空、等待非空：等时钟（Deadline 到期者依赖时间推进）
                wait_for_interrupt();
            }
        }
    }
}

/// 上下文切换的唯一出口。from/to 指向稳定的堆或静态 KContext。
fn switch_context(from: *mut KContext, to: *const KContext) {
    // SAFETY:
    // - from/to 均指向 Box<Task> 内或 static 的 KContext，调度期间不移动；
    // - 两指针可指向同一实例（只有自己可让时），保存后恢复同组寄存器；
    // - 单核、关中断执行，无并发进入；调度器锁已在调用前释放，
    //   切入的任务可以再次取锁。
    unsafe { context_switch(from, to) }
}
