//! 时钟源：单调时钟取开机时间，墙钟在启动时与 RTC 的秒边界对齐，之后随单调时钟推进。
//! 系统调用按 clockid 经本模块取时间。

use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;

use crate::syscall::Errno;

/// 各时钟的分辨率。
pub const RESOLUTION: Duration = Duration::from_nanos(1);

/// settimeofday/clock_settime 允许的最大秒数，防止与纳秒换算溢出 i64。
pub const MAX_SETTOD_SEC: i64 = (i64::MAX / 1_000_000_000) - 1;

/// 单调时钟：开机以来经过的时间。
#[inline]
pub fn monotonic() -> Duration {
    polyhal::timer::current_time()
}

/// 墙钟基准的整秒；取 i64::MIN 表示尚未对齐，此时墙钟退化为开机时间。
static BASE_SEC: AtomicI64 = AtomicI64::new(i64::MIN);
/// 墙钟基准的亚秒纳秒部分（0..1_000_000_000）。
static BASE_NSEC: AtomicU32 = AtomicU32::new(0);
/// 墙钟基准对应的单调时刻，单位纳秒。
static BASE_MONO_NS: AtomicU64 = AtomicU64::new(0);

/// 对齐墙钟：每毫秒读一次 RTC，等到读数跨过整秒，把这个整秒出现时的单调时刻记为基准。
/// 读不到 RTC 时保持未对齐；等了一秒多仍未跨秒时以最后一次读数作基准。
pub fn align_realtime() {
    let start = monotonic();
    let Some(mut sec) = crate::drivers::rtc::read_utc_seconds() else {
        return;
    };
    let mut sample = start;
    while monotonic().saturating_sub(start) < Duration::from_millis(1200) {
        let now = monotonic();
        if now.saturating_sub(sample) < Duration::from_millis(1) {
            continue;
        }
        sample = now;
        match crate::drivers::rtc::read_utc_seconds() {
            Some(next) if next == sec => {}
            Some(next) => {
                sec = next;
                break;
            }
            None => break,
        }
    }
    BASE_MONO_NS.store(sample.as_nanos() as u64, Ordering::Relaxed);
    BASE_NSEC.store(0, Ordering::Relaxed);
    BASE_SEC.store(sec.max(0), Ordering::Relaxed);
}

/// 设置墙钟时间；不影响单调时钟，之后墙钟从此基准继续随单调时钟推进。
pub fn set_realtime(target: Duration) {
    let now_mono = monotonic().as_nanos().min(u64::MAX as u128) as u64;
    BASE_MONO_NS.store(now_mono, Ordering::Relaxed);
    BASE_NSEC.store(target.subsec_nanos(), Ordering::Relaxed);
    BASE_SEC.store(
        target.as_secs().min(i64::MAX as u64) as i64,
        Ordering::Relaxed,
    );
}

/// 墙钟，即 UTC 纪元以来的时间。
pub fn realtime() -> Duration {
    let sec = BASE_SEC.load(Ordering::Relaxed);
    if sec == i64::MIN {
        return monotonic();
    }
    let nsec = BASE_NSEC.load(Ordering::Relaxed);
    let base = Duration::from_nanos(BASE_MONO_NS.load(Ordering::Relaxed));
    Duration::new(sec as u64, nsec).saturating_add(monotonic().saturating_sub(base))
}

/// 时钟按取时间的方式分成三类。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ClockKind {
    Realtime,
    Monotonic,
    Process,
}

/// 检查 clockid 能否用于取时间，未知或负数返回 EINVAL。
pub fn validate(clockid: i32) -> Result<(), Errno> {
    match clockid {
        // CLOCK_REALTIME、CLOCK_REALTIME_COARSE、CLOCK_TAI
        0 | 5 | 11 => Ok(()),
        // CLOCK_MONOTONIC、CLOCK_MONOTONIC_RAW、CLOCK_MONOTONIC_COARSE、CLOCK_BOOTTIME
        1 | 4 | 6 | 7 => Ok(()),
        // CLOCK_PROCESS_CPUTIME_ID、CLOCK_THREAD_CPUTIME_ID
        2 | 3 => Ok(()),
        _ => Err(Errno::Invalid),
    }
}

/// clock_nanosleep 可用的时钟。已知但不支持睡眠的时钟返回 EOPNOTSUPP。
pub fn sleepable(clockid: i32) -> Result<ClockKind, Errno> {
    match clockid {
        0 | 11 => Ok(ClockKind::Realtime),
        1 | 7 => Ok(ClockKind::Monotonic),
        2 | 3 | 4 | 5 | 6 => Err(Errno::NotSupported),
        _ => Err(Errno::Invalid),
    }
}

/// 按 clockid 取当前时间；`cpu` 是调用进程已用的 CPU 时间。
pub fn lookup(clockid: i32, cpu: Duration) -> Result<Duration, Errno> {
    validate(clockid)?;
    Ok(match clockid {
        0 | 5 | 11 => realtime(),
        2 | 3 => cpu,
        _ => monotonic(),
    })
}
