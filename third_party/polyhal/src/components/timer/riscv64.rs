use core::time::Duration;
use lazyinit::LazyInit;

// TODO: Get CLOCK_FREQUENCY CLOCK_FREQ
use riscv::register::{sie, time};

/// 设备树没有 timebase-frequency 时沿用的每秒滴答数。
const DEFAULT_CLOCK_FREQ: u64 = 12500000;

// OuroOS 补丁：时钟频率取设备树 /cpus 的 timebase-frequency，不再写死。
static CLOCK_FREQ: LazyInit<u64> = LazyInit::new();

/// 读设备树 /cpus 的 timebase-frequency，即每秒的滴答数。
fn read_timebase_freq() -> u64 {
    crate::mem::get_fdt()
        .ok()
        .and_then(|fdt| fdt.find_nodes("/cpus").next())
        .and_then(|node| node.find_property("timebase-frequency"))
        .and_then(|prop| prop.raw_value().get(..4))
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
        .filter(|freq| *freq > 0)
        .unwrap_or(DEFAULT_CLOCK_FREQ)
}

/// Get ticks from system clock
///
/// # Return
///
/// - [u64] clock ticks
#[inline]
pub fn get_ticks() -> u64 {
    time::read64()
}

/// Get frequency of the system clock
///
/// # Return
///
/// - [u64] n ticks per second
#[inline]
pub fn get_freq() -> u64 {
    if !CLOCK_FREQ.is_inited() {
        let _ = CLOCK_FREQ.init_once(read_timebase_freq());
    }
    *CLOCK_FREQ
}

/// Set the next timer
///
/// # parameters
///
/// - next [Duration] next time from system boot#[inline]
pub fn set_next_timer(next: Duration) {
    let freq = get_freq();
    sbi_rt::set_timer(next.as_secs() * freq + next.subsec_nanos() as u64 * freq / 1_000_000_000);
}

// Initialize the Timer
pub fn init() {
    unsafe {
        sie::set_stimer();
    }
    set_next_timer(Duration::ZERO);
    log::info!("initialize timer interrupt");
}
