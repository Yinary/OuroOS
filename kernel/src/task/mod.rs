//! 内核任务与协作式调度入口。
//!
//! 当前阶段只在启动核上创建两个内核任务，用于验证独立内核栈、
//! 上下文切换、主动让出和正常退出。

mod sched;
// Issue 指定的 `task/mod.rs` + `task/task.rs` 布局会自然形成同名子模块。
#[allow(clippy::module_inception)]
mod task;

use polyhal::println;

/// 运行 A/B 两个内核任务的启动自检。
pub fn run_demo() {
    sched::run([thread_a, thread_b]);
    println!("[kthread] all done");
}

fn thread_a() {
    for i in 0..5 {
        println!("[kthread] A {}", i);
        if i != 4 {
            sched::yield_now();
        }
    }
}

fn thread_b() {
    for i in 0..5 {
        println!("[kthread] B {}", i);
        if i != 4 {
            sched::yield_now();
        }
    }
}
