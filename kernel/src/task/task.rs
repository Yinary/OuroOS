//! 内核任务描述符与初始上下文构造。
//!
//! 每个任务拥有独立内核栈和 PolyHAL `KContext`。本模块只负责任务的
//! 静态资源与初始寄存器状态，调度策略由 `sched` 模块负责。

use core::arch::asm;

use polyhal::{
    kcontext::{KContext, KContextArgs},
    pagetable::PAGE_SIZE,
    PhysAddr,
};

use crate::mm::frame;

/// 每个内核任务占用的页数（4 页 = 16 KiB）。
const KSTACK_PAGES: usize = 4;

/// 内核任务入口函数类型。
pub type TaskEntry = fn();

/// 内核任务的调度状态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    /// 可以被调度。
    Ready,
    /// 正在启动核上执行。
    Running,
    /// 入口函数已返回，不得再次调度。
    Exited,
}

/// 单个内核任务。
pub struct Task {
    /// PolyHAL 保存的内核上下文。
    pub context: KContext,
    /// trampoline 最终调用的 Rust 入口函数。
    pub entry: TaskEntry,
    /// 当前调度状态。
    pub state: TaskState,
    /// 保留栈的物理起始地址，表示任务对这块内存的占用。
    _stack_start: PhysAddr,
}

impl Task {
    /// 创建一个尚未运行的内核任务。
    ///
    /// `trampoline` 必须是一个永不返回的入口：它调用 `entry`，并在入口
    /// 返回后将任务标记为退出并切换到其他上下文。
    pub fn new(
        entry: TaskEntry,
        trampoline: extern "C" fn() -> !,
    ) -> Result<Self, frame::FrameError> {
        // HACK(qzquan): 暂用物理页作为内核栈，待 mm 提供 kstack 后替换。
        let stack_start = frame::frame_alloc(KSTACK_PAGES)?;
        stack_start.clear_len(KSTACK_PAGES * PAGE_SIZE);

        let stack_bottom = stack_start.get_mut_ptr::<u8>() as usize;
        let stack_top = (stack_bottom + KSTACK_PAGES * PAGE_SIZE) & !0xf;

        let mut context = KContext::blank();
        context[KContextArgs::KSP] = stack_top;
        context[KContextArgs::KTP] = read_current_tp();
        context[KContextArgs::KPC] = trampoline as usize;

        Ok(Self {
            context,
            entry,
            state: TaskState::Ready,
            _stack_start: stack_start,
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
        asm!("mv {}, tp", out(reg) tp);
    }
    tp
}

/// 读取 PolyHAL `context_switch` 实际保存的 `tp` 寄存器。
#[cfg(target_arch = "loongarch64")]
fn read_current_tp() -> usize {
    let tp;
    // SAFETY: 只读取当前 CPU 的 `$tp`，不修改寄存器、内存或控制流。
    unsafe {
        asm!("move {}, $tp", out(reg) tp);
    }
    tp
}

impl Drop for Task {
    fn drop(&mut self) {
        for page in 0..KSTACK_PAGES {
            // SAFETY: 任务不可复制，仅初始化失败或恢复启动栈后销毁；
            // exit_current 不释放当前栈，每个独占物理页只归还一次。
            unsafe {
                frame::frame_dealloc(PhysAddr::new(self._stack_start.raw() + page * PAGE_SIZE));
            }
        }
    }
}
