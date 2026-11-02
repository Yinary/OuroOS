//! 启动核上的最小协作式内核任务调度器。
//!
//! 调度器固定管理两个任务，通过主动 `yield_now` 轮转。它另外保存
//! 启动流程的上下文，以便在两个任务都退出后返回 `rust_main`。

use core::ptr::{addr_of, addr_of_mut};

use polyhal::kcontext::{context_switch, KContext};
use spin::Mutex;

use super::task::{Task, TaskEntry, TaskState};

const TASK_COUNT: usize = 2;

struct Scheduler {
    boot_context: KContext,
    tasks: [Option<Task>; TASK_COUNT],
    current: Option<usize>,
}

impl Scheduler {
    fn new(entries: [TaskEntry; TASK_COUNT]) -> Self {
        Self {
            boot_context: KContext::blank(),
            tasks: [
                Some(Task::new(entries[0], task_trampoline)),
                Some(Task::new(entries[1], task_trampoline)),
            ],
            current: None,
        }
    }

    fn next_ready(&self, current: usize) -> Option<usize> {
        (1..TASK_COUNT)
            .map(|offset| (current + offset) % TASK_COUNT)
            .find(|&index| {
                self.tasks[index]
                    .as_ref()
                    .is_some_and(|task| task.state == TaskState::Ready)
            })
    }
}

static SCHEDULER: Mutex<Option<Scheduler>> = Mutex::new(None);

/// 创建两个内核任务，并运行到它们全部退出。
pub fn run(entries: [TaskEntry; TASK_COUNT]) {
    let (from, to) = {
        let mut slot = SCHEDULER.lock();
        assert!(slot.is_none(), "kernel task scheduler initialized twice");

        *slot = Some(Scheduler::new(entries));
        let scheduler = slot.as_mut().expect("scheduler was just initialized");
        let first = scheduler.tasks[0]
            .as_mut()
            .expect("kernel task A is missing");
        first.state = TaskState::Running;
        scheduler.current = Some(0);

        (
            addr_of_mut!(scheduler.boot_context),
            addr_of!(first.context),
        )
    };

    switch_context(from, to);

    let slot = SCHEDULER.lock();
    let scheduler = slot.as_ref().expect("scheduler disappeared while running");
    assert!(
        scheduler.current.is_none()
            && scheduler.tasks.iter().all(|task| {
                task.as_ref()
                    .is_some_and(|task| task.state == TaskState::Exited)
            }),
        "kernel task scheduler returned before all tasks exited"
    );
}

/// 当前任务主动让出 CPU，切换到下一个就绪任务。
pub fn yield_now() {
    let (from, to) = {
        let mut slot = SCHEDULER.lock();
        let scheduler = slot.as_mut().expect("scheduler is not initialized");
        let current = scheduler.current.expect("boot context cannot yield");

        scheduler.tasks[current]
            .as_mut()
            .expect("current kernel task is missing")
            .state = TaskState::Ready;

        let Some(next) = scheduler.next_ready(current) else {
            scheduler.tasks[current]
                .as_mut()
                .expect("current kernel task is missing")
                .state = TaskState::Running;
            return;
        };

        scheduler.tasks[next]
            .as_mut()
            .expect("next kernel task is missing")
            .state = TaskState::Running;
        scheduler.current = Some(next);

        let from = addr_of_mut!(
            scheduler.tasks[current]
                .as_mut()
                .expect("current kernel task is missing")
                .context
        );
        let to = addr_of!(
            scheduler.tasks[next]
                .as_ref()
                .expect("next kernel task is missing")
                .context
        );
        (from, to)
    };

    switch_context(from, to);
}

extern "C" fn task_trampoline() -> ! {
    let entry = {
        let slot = SCHEDULER.lock();
        let scheduler = slot.as_ref().expect("scheduler is not initialized");
        let current = scheduler
            .current
            .expect("trampoline entered without a current task");
        scheduler.tasks[current]
            .as_ref()
            .expect("current kernel task is missing")
            .entry
    };

    entry();
    exit_current()
}

fn exit_current() -> ! {
    let (from, to) = {
        let mut slot = SCHEDULER.lock();
        let scheduler = slot.as_mut().expect("scheduler is not initialized");
        let current = scheduler.current.expect("boot context cannot exit");

        scheduler.tasks[current]
            .as_mut()
            .expect("current kernel task is missing")
            .state = TaskState::Exited;

        let from = addr_of_mut!(
            scheduler.tasks[current]
                .as_mut()
                .expect("current kernel task is missing")
                .context
        );

        if let Some(next) = scheduler.next_ready(current) {
            scheduler.tasks[next]
                .as_mut()
                .expect("next kernel task is missing")
                .state = TaskState::Running;
            scheduler.current = Some(next);
            let to = addr_of!(
                scheduler.tasks[next]
                    .as_ref()
                    .expect("next kernel task is missing")
                    .context
            );
            (from, to)
        } else {
            scheduler.current = None;
            (from, addr_of!(scheduler.boot_context))
        }
    };

    switch_context(from, to);
    panic!("exited kernel task was resumed");
}

fn switch_context(from: *mut KContext, to: *const KContext) {
    // SAFETY:
    // - `from` 和 `to` 都指向静态 SCHEDULER 内部、调度期间不会移动的 KContext；
    // - 两个指针指向不同上下文，且目标任务拥有有效、对齐的内核栈；
    // - 只有启动核调用本调度器，副核仍停留在 secondary_main；
    // - 调度器锁已在调用前释放，切入的任务可以再次进入调度器。
    unsafe {
        context_switch(from, to);
    }
}
