//! 定时器：维护周期性的拍，并在当前任务的时间片终点与等待表最早的到期时刻触发时钟中断。

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use crate::time::monotonic;

/// 触发时刻与当前时刻的最小间隔，单位纳秒。
const MIN_LEAD_NS: u64 = 200_000;

/// 下一拍的时刻，单位纳秒。
static NEXT_TICK_NS: AtomicU64 = AtomicU64::new(0);
/// 当前任务时间片的终点；没有运行中的用户任务时取 u64::MAX。
static SLICE_END_NS: AtomicU64 = AtomicU64::new(u64::MAX);
/// 等待表里最早的到期时刻；没有带期限的等待者时取 u64::MAX。
static DEADLINE_NS: AtomicU64 = AtomicU64::new(u64::MAX);
/// 上一次装进硬件的触发时刻；相同则不重复装。
static ARMED_NS: AtomicU64 = AtomicU64::new(0);
/// 时钟中断的累计次数。
static EVENTS: AtomicU64 = AtomicU64::new(0);

/// 启动周期性的拍并装上第一次中断。
pub fn init() {
    NEXT_TICK_NS.store(now_ns() + tick_ns(), Ordering::Relaxed);
    arm();
}

/// 登记当前任务时间片的终点；None 表示没有运行中的用户任务。
pub fn set_slice_end(end: Option<Duration>) {
    SLICE_END_NS.store(end.map_or(u64::MAX, nanos), Ordering::Relaxed);
    arm();
}

/// 登记等待表里最早的到期时刻；None 表示没有带期限的等待者。
pub fn set_deadline(deadline: Option<Duration>) {
    DEADLINE_NS.store(deadline.map_or(u64::MAX, nanos), Ordering::Relaxed);
    arm();
}

/// 时钟中断的累计次数。
pub fn events() -> u64 {
    EVENTS.load(Ordering::Relaxed)
}

/// 时钟中断的处理：记一次事件，推进已经过去的拍，重新装定时器。
/// 返回这次中断是否跨过了一拍。
pub fn on_interrupt() -> bool {
    EVENTS.fetch_add(1, Ordering::Relaxed);
    let now = now_ns();
    let mut next = NEXT_TICK_NS.load(Ordering::Relaxed);
    let mut ticked = false;
    while next <= now {
        next += tick_ns();
        ticked = true;
    }
    if ticked {
        NEXT_TICK_NS.store(next, Ordering::Relaxed);
    }
    arm();
    ticked
}

/// 把定时器装到拍、时间片终点与最早到期时刻三者中最早的一个。
/// 已过去的时刻按最小提前量立即触发，使到期者在最近的调度边界被处理。
fn arm() {
    let now = now_ns();
    let earliest = NEXT_TICK_NS
        .load(Ordering::Relaxed)
        .min(SLICE_END_NS.load(Ordering::Relaxed))
        .min(DEADLINE_NS.load(Ordering::Relaxed));
    let target = earliest.max(now + MIN_LEAD_NS);
    if ARMED_NS.swap(target, Ordering::Relaxed) != target {
        polyhal::timer::set_next_timer(Duration::from_nanos(target));
    }
}

fn now_ns() -> u64 {
    monotonic().as_nanos() as u64
}

fn nanos(value: Duration) -> u64 {
    value.as_nanos() as u64
}

fn tick_ns() -> u64 {
    nanos(Duration::from_millis(crate::config::TICK_MS))
}
