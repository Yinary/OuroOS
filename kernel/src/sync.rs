//! 调试锁（feature `lock_debug`）：持锁者/获取点跟踪、percpu 持锁深度、
//! 调度切换点断言。模型与锁序见 docs/ostd-contracts.md §5。

use core::{
    cell::Cell,
    fmt,
    ops::{Deref, DerefMut},
};

#[cfg(feature = "lock_debug")]
use core::panic::Location;

use spin::mutex::{Mutex, MutexGuard};

/// 持有者 id：任务时代由调度器在切入时更新（当前任务 pid，无任务为 0）。
#[polyhal::percpu]
static HOLDER_ID: Cell<usize> = Cell::new(0);

/// 当前核持锁深度；调度切换入口必须为 0。
#[cfg(feature = "lock_debug")]
#[polyhal::percpu]
static HELD_DEPTH: Cell<usize> = Cell::new(0);

/// 最近一次获取的锁名与位置，报告用。
#[cfg(feature = "lock_debug")]
#[polyhal::percpu]
static LAST_ACQUIRE: Cell<(&'static str, &'static Location<'static>)> =
    Cell::new(("none", Location::caller()));

/// 更新当前执行流的持有者 id（调度器切入/切出时调用）。
pub fn set_holder(id: usize) {
    HOLDER_ID.set(id);
}

/// 断言当前执行流不持任何调试锁；在调度切换入口调用。
///
/// 非零即"持锁跨切换"：目标任务永远无法唤醒持有者，单核上等价死锁。
#[cfg(feature = "lock_debug")]
pub fn assert_no_held(where_: &str) {
    let depth = HELD_DEPTH.get();
    if depth != 0 {
        let (name, loc) = LAST_ACQUIRE.get();
        panic!(
            "lock-debug: {} 时仍持有 {} 把锁（最近一把 '{}'，获取于 {}:{}）——\
             持锁跨 context_switch，单核关中断内核中必然死锁",
            where_,
            depth,
            name,
            loc.file(),
            loc.line()
        );
    }
}

#[cfg(not(feature = "lock_debug"))]
pub fn assert_no_held(_where_: &str) {}

/// 带调试侧栏的互斥锁；feature 关闭时等价于 spin::Mutex。
pub struct DebugMutex<T> {
    inner: Mutex<T>,
    name: &'static str,
}

impl<T> DebugMutex<T> {
    /// 创建未锁定实例。锁名必须是 'static（全局锁直接写字面量）。
    pub const fn new(name: &'static str, value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            name,
        }
    }

    /// 加锁。单核关中断内核中 try_lock 失败即 bug，立即报告。
    #[track_caller]
    pub fn lock(&self) -> DebugGuard<'_, T> {
        // feature 关闭时字段不参与逻辑，显式丢弃避免死字段告警
        let _ = self.name;
        #[cfg(feature = "lock_debug")]
        {
            let Some(inner) = self.inner.try_lock() else {
                // 到达这里说明锁被"别人"持有，而单核关中断内核中
                // 不存在其他执行流——唯一解释是持锁跨越了调度。
                panic!(
                    "lock-debug: 等待 '{}'——单核关中断内核中不存在合法等待，\
                     疑似持锁跨调度（cf. docs/ostd-contracts.md task 契约）",
                    self.name
                );
            };
            HELD_DEPTH.set(HELD_DEPTH.get() + 1);
            LAST_ACQUIRE.set((self.name, Location::caller()));
            return DebugGuard { inner, owner: self };
        }
        #[cfg(not(feature = "lock_debug"))]
        DebugGuard {
            inner: self.inner.lock(),
            #[cfg(feature = "lock_debug")]
            owner: self,
        }
    }

    #[cfg(feature = "lock_debug")]
    fn on_release(&self) {
        HELD_DEPTH.set(HELD_DEPTH.get() - 1);
    }
}

/// DebugMutex 的守卫：释放时递减持锁深度。
pub struct DebugGuard<'a, T> {
    inner: MutexGuard<'a, T>,
    #[cfg(feature = "lock_debug")]
    owner: &'a DebugMutex<T>,
}

impl<T> Drop for DebugGuard<'_, T> {
    fn drop(&mut self) {
        #[cfg(feature = "lock_debug")]
        self.owner.on_release();
    }
}

impl<T> Deref for DebugGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner.deref()
    }
}

impl<T> DerefMut for DebugGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner.deref_mut()
    }
}

// spin::Mutex 的 fmt 实现不可用（需要 T: fmt），这里保持透明。
impl<T: fmt::Debug> fmt::Debug for DebugMutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}
