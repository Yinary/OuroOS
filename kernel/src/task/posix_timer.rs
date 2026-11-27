//! POSIX 进程级定时器（timer_create / timer_gettime / timer_getoverrun /
//! timer_settime / timer_delete）。
//! 遵循 Linux man 2 与 asm-generic UAPI：timer_t 为 i32，不跨 fork 继承，exec/exit 时清空。
#![deny(unsafe_code)]

use core::time::Duration;

use crate::mm::user_access;
use crate::syscall::Errno;

use super::signal::{SigInfoSlot, SignalSet, SignalSetExt, SIGALRM, SI_TIMER};
use super::task::Pid;
use super::{recompute_next_itimer, sched, ProcessRecord, Registry, REGISTRY};

/// sigevent.sigev_notify：向进程投递信号。
const SIGEV_SIGNAL: i32 = 0;
/// sigevent.sigev_notify：不投递信号（仅跟踪计时）。
const SIGEV_NONE: i32 = 1;
/// sigevent.sigev_notify：向进程内指定线程投递信号（Linux SIGEV_THREAD_ID）。
const SIGEV_THREAD_ID: i32 = 4;

/// timer_settime flags：到期时间为对应时钟的绝对时间。
const TIMER_ABSTIME: i32 = 1;

/// CAP_WAKE_ALARM（能力位 35）：创建 CLOCK_REALTIME_ALARM / CLOCK_BOOTTIME_ALARM 所需能力。
const CAP_WAKE_ALARM: u32 = 35;

/// Linux ktime_t 最大可表示纳秒数（i64::MAX，约 292 年），防止大 tv_sec 算术回绕。
const KTIME_MAX_NS: u64 = i64::MAX as u64;

/// 单进程最多持有的 POSIX 定时器数量上限，避免无界内存增长。
const MAX_TIMERS_PER_PROC: usize = 256;

/// 定时器所绑定的时钟域。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerClock {
    /// CLOCK_REALTIME / CLOCK_REALTIME_ALARM / CLOCK_TAI（随墙钟推进或跳变）。
    Realtime,
    /// CLOCK_MONOTONIC / CLOCK_BOOTTIME / CLOCK_BOOTTIME_ALARM。
    Monotonic,
    /// CLOCK_PROCESS_CPUTIME_ID 与进程动态 CPU 时钟。
    ProcessCpu,
    /// CLOCK_THREAD_CPUTIME_ID 与线程动态 CPU 时钟。
    ThreadCpu,
}

/// 定时器到期通知方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerNotify {
    None,
    Signal { sig: u8 },
    ThreadId { sig: u8, tid: Pid },
}

/// 单个 POSIX 定时器条目（存放在所属进程 ProcessRecord.posix_timers 内）。
#[derive(Debug, Clone)]
pub struct PosixTimer {
    pub id: i32,
    pub clock: TimerClock,
    pub notify: TimerNotify,
    pub sigval: u64,
    /// Some((对应时钟域内的下次到期时刻, 重复周期))；None 表示已撤防。
    pub armed: Option<(Duration, Duration)>,
    /// 信号尚在挂起队列中时累计的额外到期次数（出队时写入 overrun_last 与 si_overrun）。
    pub overrun_pending: u64,
    /// 最近一次已投递/消费信号对应的溢出计数（timer_getoverrun 返回值）。
    pub overrun_last: u64,
}

impl PosixTimer {
    /// 读取本定时器所属时钟域的当前时刻。
    #[inline]
    fn clock_now(&self, now_mono: Duration, now_real: Duration, cpu_ns: u64) -> Duration {
        match self.clock {
            TimerClock::Realtime => now_real,
            TimerClock::Monotonic => now_mono,
            TimerClock::ProcessCpu | TimerClock::ThreadCpu => Duration::from_nanos(cpu_ns),
        }
    }

    /// 换算为单调时钟上的下一次硬件唤醒时刻（供全局 NEXT_ITIMER_NS 调度器定时使用）。
    pub(super) fn monotonic_wakeup(
        &self,
        now_mono: Duration,
        now_real: Duration,
        cpu_ns: u64,
    ) -> Option<Duration> {
        let (deadline, _) = self.armed?;
        Some(match self.clock {
            TimerClock::Monotonic => deadline,
            TimerClock::Realtime => {
                if deadline <= now_real {
                    now_mono
                } else {
                    now_mono.saturating_add(deadline.saturating_sub(now_real))
                }
            }
            TimerClock::ProcessCpu | TimerClock::ThreadCpu => {
                let cpu = Duration::from_nanos(cpu_ns);
                if deadline <= cpu {
                    now_mono
                } else {
                    // CPU 定时器在运行期间推进；挂 2ms 轮询上限确保高分辨率响应。
                    let rem = deadline.saturating_sub(cpu);
                    now_mono.saturating_add(rem.min(Duration::from_millis(2)))
                }
            }
        })
    }
}

/// 校验并解析 timer_create 的 clockid（支持标准时钟与动态负值 CPU 时钟）。
fn parse_clockid(reg: &Registry, rec: &ProcessRecord, clockid: i32) -> Result<TimerClock, Errno> {
    if clockid < 0 {
        // Linux 动态 PID/TID CPU 时钟编码：(~pid << 3) | (perthread << 2) | type
        let kind = clockid & 3;
        if kind == 3 {
            // CPUCLOCK_FD 非法
            return Err(Errno::Invalid);
        }
        let target_pid = !(clockid >> 3);
        if target_pid < 0 {
            return Err(Errno::Invalid);
        }
        let per_thread = (clockid & 4) != 0;
        if target_pid != 0 {
            let pid = target_pid as Pid;
            let exists = if per_thread {
                reg.thread(pid).is_some()
            } else {
                reg.records.iter().any(|r| r.pid == pid && r.exit.is_none())
            };
            if !exists {
                return Err(Errno::Invalid);
            }
        }
        return Ok(if per_thread {
            TimerClock::ThreadCpu
        } else {
            TimerClock::ProcessCpu
        });
    }
    match clockid {
        // CLOCK_REALTIME / CLOCK_TAI
        0 | 11 => Ok(TimerClock::Realtime),
        // CLOCK_MONOTONIC / CLOCK_BOOTTIME
        1 | 7 => Ok(TimerClock::Monotonic),
        // CLOCK_PROCESS_CPUTIME_ID
        2 => Ok(TimerClock::ProcessCpu),
        // CLOCK_THREAD_CPUTIME_ID
        3 => Ok(TimerClock::ThreadCpu),
        // CLOCK_MONOTONIC_RAW / CLOCK_REALTIME_COARSE / CLOCK_MONOTONIC_COARSE：不支持创建定时器
        4..=6 => Err(Errno::NotSupported),
        // CLOCK_REALTIME_ALARM / CLOCK_BOOTTIME_ALARM：需 CAP_WAKE_ALARM
        8 => {
            if !rec.creds.has_cap(CAP_WAKE_ALARM) {
                return Err(Errno::Perm);
            }
            Ok(TimerClock::Realtime)
        }
        9 => {
            if !rec.creds.has_cap(CAP_WAKE_ALARM) {
                return Err(Errno::Perm);
            }
            Ok(TimerClock::Monotonic)
        }
        _ => Err(Errno::Invalid),
    }
}

/// 将用户态 timespec (sec, nsec) 校验并换算为不超过 KTIME_MAX_NS 的 Duration。
fn parse_timespec_clamped(sec: i64, nsec: i64) -> Result<Duration, Errno> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::Invalid);
    }
    let total_ns = (sec as u128)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u128);
    let clamped = total_ns.min(KTIME_MAX_NS as u128) as u64;
    Ok(Duration::from_nanos(clamped))
}

/// 在 ktime_t 上限内累加时间，避免大相对超时回绕。
#[inline]
fn ktime_add(base: Duration, delta: Duration) -> Duration {
    let sum = base
        .as_nanos()
        .saturating_add(delta.as_nanos())
        .min(KTIME_MAX_NS as u128) as u64;
    Duration::from_nanos(sum)
}

/// 编码 32 字节 struct itimerspec（前 16 字节 it_interval，后 16 字节 it_value）。
fn encode_itimerspec(interval: Duration, value: Duration) -> [u8; 32] {
    let mut raw = [0u8; 32];
    raw[0..8].copy_from_slice(&(interval.as_secs() as i64).to_ne_bytes());
    raw[8..16].copy_from_slice(&(interval.subsec_nanos() as i64).to_ne_bytes());
    raw[16..24].copy_from_slice(&(value.as_secs() as i64).to_ne_bytes());
    raw[24..32].copy_from_slice(&(value.subsec_nanos() as i64).to_ne_bytes());
    raw
}

/// 当信号出队（handler 投递、DFL 终止或 rt_sigtimedwait 消费）时，
/// 若为 SI_TIMER，将挂起溢出计数冻结到 timer.overrun_last 与 slot.overrun。
pub(super) fn on_signal_dequeued(rec: &mut ProcessRecord, slot: &mut SigInfoSlot) {
    if slot.code != SI_TIMER {
        return;
    }
    if let Some(timer) = rec.posix_timers.iter_mut().find(|t| t.id == slot.timer_id) {
        let ov = timer.overrun_pending.min(i32::MAX as u64);
        timer.overrun_last = ov;
        timer.overrun_pending = 0;
        slot.overrun = ov as i32;
    }
}

/// 检查并触发单个进程内全部已到期的 POSIX 定时器；返回是否产生了信号通知。
pub(super) fn fire_process_timers(
    reg: &mut Registry,
    idx: usize,
    now_mono: Duration,
    now_real: Duration,
) -> bool {
    if reg.records[idx].exit.is_some() || reg.records[idx].posix_timers.is_empty() {
        return false;
    }
    let tgid = reg.records[idx].pid;
    let cpu_ns = reg.records[idx]
        .user_ns
        .saturating_add(reg.records[idx].system_ns);
    let mut fired = false;

    for t_idx in 0..reg.records[idx].posix_timers.len() {
        let (deadline, interval) = match reg.records[idx].posix_timers[t_idx].armed {
            Some(pair) => pair,
            None => continue,
        };
        let now_clock = reg.records[idx].posix_timers[t_idx].clock_now(now_mono, now_real, cpu_ns);
        if now_clock < deadline {
            continue;
        }
        // 计算本次跨过的到期次数并推进下一次到期时刻。
        let expirations: u64 = if interval.is_zero() {
            reg.records[idx].posix_timers[t_idx].armed = None;
            1
        } else {
            let elapsed_ns = now_clock.saturating_sub(deadline).as_nanos();
            let int_ns = interval.as_nanos().max(1);
            let extra = (elapsed_ns / int_ns).min(i32::MAX as u128) as u64;
            let step_ns = ((extra as u128).saturating_add(1))
                .saturating_mul(int_ns)
                .min(KTIME_MAX_NS as u128) as u64;
            let next_dl = ktime_add(deadline, Duration::from_nanos(step_ns));
            reg.records[idx].posix_timers[t_idx].armed = Some((next_dl, interval));
            extra.saturating_add(1)
        };

        let timer_id = reg.records[idx].posix_timers[t_idx].id;
        let notify = reg.records[idx].posix_timers[t_idx].notify;
        let sigval = reg.records[idx].posix_timers[t_idx].sigval;
        match notify {
            TimerNotify::None => {
                reg.records[idx].posix_timers[t_idx].overrun_last =
                    expirations.saturating_sub(1).min(i32::MAX as u64);
                reg.records[idx].posix_timers[t_idx].overrun_pending = 0;
            }
            TimerNotify::Signal { sig } => {
                let sig_bit: SignalSet = 1u64 << (sig - 1);
                let already_pending = reg.records[idx].signal.pending().has(sig);
                if already_pending {
                    let t = &mut reg.records[idx].posix_timers[t_idx];
                    t.overrun_pending = t
                        .overrun_pending
                        .saturating_add(expirations)
                        .min(i32::MAX as u64);
                } else {
                    let extra = expirations.saturating_sub(1).min(i32::MAX as u64);
                    reg.records[idx].posix_timers[t_idx].overrun_pending = extra;
                    let all_blocked = reg
                        .threads
                        .iter()
                        .filter(|th| th.tgid == tgid)
                        .all(|th| th.signal.blocked() & sig_bit != 0);
                    let blocked = if all_blocked { sig_bit } else { 0 };
                    reg.records[idx].signal.generate(
                        sig,
                        SigInfoSlot {
                            code: SI_TIMER,
                            addr: sigval as usize,
                            timer_id,
                            overrun: extra as i32,
                            ..Default::default()
                        },
                        blocked,
                    );
                    fired = true;
                }
            }
            TimerNotify::ThreadId { sig, tid } => {
                if let Some(th_idx) = reg
                    .threads
                    .iter()
                    .position(|th| th.tid == tid && th.tgid == tgid)
                {
                    let already_pending = reg.threads[th_idx].signal.pending().has(sig);
                    if already_pending {
                        let t = &mut reg.records[idx].posix_timers[t_idx];
                        t.overrun_pending = t
                            .overrun_pending
                            .saturating_add(expirations)
                            .min(i32::MAX as u64);
                    } else {
                        let extra = expirations.saturating_sub(1).min(i32::MAX as u64);
                        reg.records[idx].posix_timers[t_idx].overrun_pending = extra;
                        let slot = SigInfoSlot {
                            code: SI_TIMER,
                            addr: sigval as usize,
                            timer_id,
                            overrun: extra as i32,
                            ..Default::default()
                        };
                        let group_sig = &reg.records[idx].signal;
                        let thread_sig = &mut reg.threads[th_idx].signal;
                        super::signal::generate_thread(group_sig, thread_sig, sig, slot);
                        fired = true;
                    }
                }
            }
        }
    }
    fired
}

/// 墙钟被 clock_settime / settimeofday 修改后，立刻重算定时唤醒并触发已越过新墙钟的定时器。
pub(super) fn on_realtime_changed() {
    let now_mono = crate::time::monotonic();
    let now_real = crate::time::realtime();
    let fired = {
        let mut reg = REGISTRY.lock();
        let mut any = false;
        for idx in 0..reg.records.len() {
            if fire_process_timers(&mut reg, idx, now_mono, now_real) {
                any = true;
            }
        }
        recompute_next_itimer(&reg);
        any
    };
    if fired {
        sched::request_signal_wake();
    }
}

/// timer_create(2)：创建 POSIX 进程定时器，写入 4 字节 timer_t 到用户指针。
pub(super) fn sys_timer_create(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let clockid = args[0] as u32 as i32;
    let sevp = args[1];
    let timerid_ptr = args[2];
    if timerid_ptr == 0 {
        return Err(Errno::Fault);
    }

    let mut reg = REGISTRY.lock();
    let idx = reg.group_index(parent).ok_or(Errno::NoProcess)?;
    let tgid = reg.records[idx].pid;
    let clock = parse_clockid(&reg, &reg.records[idx], clockid)?;

    // 解析可选 struct sigevent（64 字节）。
    let (notify, sigval_opt) = if sevp == 0 {
        (TimerNotify::Signal { sig: SIGALRM }, None)
    } else {
        let space = reg.records[idx]
            .space
            .as_ref()
            .ok_or(Errno::Fault)?
            .as_space();
        let mut raw = [0u8; 64];
        user_access::copy_from_user(space, sevp, &mut raw).map_err(|_| Errno::Fault)?;
        let val = u64::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
        let signo = i32::from_ne_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
        let mode = i32::from_ne_bytes(raw[12..16].try_into().unwrap_or([0; 4]));
        let tid = i32::from_ne_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let notify = match mode {
            SIGEV_NONE => TimerNotify::None,
            SIGEV_SIGNAL => {
                if !(1..=64).contains(&signo) {
                    return Err(Errno::Invalid);
                }
                TimerNotify::Signal { sig: signo as u8 }
            }
            SIGEV_THREAD_ID => {
                if !(1..=64).contains(&signo) || tid <= 0 {
                    return Err(Errno::Invalid);
                }
                let target_tid = tid as Pid;
                let same_group = reg
                    .threads
                    .iter()
                    .any(|t| t.tid == target_tid && t.tgid == tgid);
                if !same_group {
                    return Err(Errno::Invalid);
                }
                TimerNotify::ThreadId {
                    sig: signo as u8,
                    tid: target_tid,
                }
            }
            _ => return Err(Errno::Invalid),
        };
        (notify, Some(val))
    };

    if reg.records[idx].posix_timers.len() >= MAX_TIMERS_PER_PROC {
        return Err(Errno::Again);
    }

    // 分配未使用的非负 timer_t（从 0 起单调递增并跳过占用）。
    let mut candidate = reg.records[idx].next_timer_id;
    let mut found = None;
    for _ in 0..=MAX_TIMERS_PER_PROC {
        if candidate < 0 {
            candidate = 0;
        }
        if !reg.records[idx]
            .posix_timers
            .iter()
            .any(|t| t.id == candidate)
        {
            found = Some(candidate);
            break;
        }
        candidate = candidate.wrapping_add(1);
    }
    let id = found.ok_or(Errno::Again)?;
    let sigval = sigval_opt.unwrap_or(id as u64);

    // 写回用户态 timerid 指针；失败时不登记定时器。
    {
        let space = reg.records[idx]
            .space
            .as_ref()
            .ok_or(Errno::Fault)?
            .as_space();
        user_access::copy_to_user(space, timerid_ptr, &id.to_ne_bytes())
            .map_err(|_| Errno::Fault)?;
    }

    reg.records[idx]
        .posix_timers
        .try_reserve(1)
        .map_err(|_| Errno::NoMem)?;
    reg.records[idx].next_timer_id = if id == i32::MAX { 0 } else { id + 1 };
    reg.records[idx].posix_timers.push(PosixTimer {
        id,
        clock,
        notify,
        sigval,
        armed: None,
        overrun_pending: 0,
        overrun_last: 0,
    });
    Ok(0)
}

/// timer_settime(2)：布防/改期/撤防定时器，并可选返回旧剩余时间与周期。
pub(super) fn sys_timer_settime(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let timer_id = args[0] as u32 as i32;
    let flags = args[1] as u32 as i32;
    let new_ptr = args[2];
    let old_ptr = args[3];

    // Linux 语义：new_value == NULL 返回 EINVAL（非空非法指针才返回 EFAULT）。
    if new_ptr == 0 {
        return Err(Errno::Invalid);
    }

    let now_mono = crate::time::monotonic();
    let now_real = crate::time::realtime();

    let fired = {
        let mut reg = REGISTRY.lock();
        let idx = reg.group_index(parent).ok_or(Errno::NoProcess)?;

        // 读取并校验 new_value（32 字节 itimerspec）。
        let (new_interval, new_value) = {
            let space = reg.records[idx]
                .space
                .as_ref()
                .ok_or(Errno::Fault)?
                .as_space();
            let mut raw = [0u8; 32];
            user_access::copy_from_user(space, new_ptr, &mut raw).map_err(|_| Errno::Fault)?;
            let int_sec = i64::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
            let int_nsec = i64::from_ne_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
            let val_sec = i64::from_ne_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
            let val_nsec = i64::from_ne_bytes(raw[24..32].try_into().unwrap_or([0; 8]));
            let iv = parse_timespec_clamped(int_sec, int_nsec)?;
            let val = parse_timespec_clamped(val_sec, val_nsec)?;
            (iv, val)
        };

        // 先刷新已到期定时器，保证 old_value 准确反映当前剩余时间。
        let mut fired = fire_process_timers(&mut reg, idx, now_mono, now_real);

        let t_idx = reg.records[idx]
            .posix_timers
            .iter()
            .position(|t| t.id == timer_id)
            .ok_or(Errno::Invalid)?;

        let cpu_ns = reg.records[idx]
            .user_ns
            .saturating_add(reg.records[idx].system_ns);
        let now_clock = reg.records[idx].posix_timers[t_idx].clock_now(now_mono, now_real, cpu_ns);

        // 先尝试回写 old_value，若用户指针非法则回滚不修改定时器状态。
        if old_ptr != 0 {
            let (old_iv, old_rem) = match reg.records[idx].posix_timers[t_idx].armed {
                Some((dl, iv)) => (iv, dl.saturating_sub(now_clock)),
                None => (Duration::ZERO, Duration::ZERO),
            };
            let raw = encode_itimerspec(old_iv, old_rem);
            let space = reg.records[idx]
                .space
                .as_ref()
                .ok_or(Errno::Fault)?
                .as_space();
            user_access::copy_to_user(space, old_ptr, &raw).map_err(|_| Errno::Fault)?;
        }

        // 提交新配置。
        let timer = &mut reg.records[idx].posix_timers[t_idx];
        timer.overrun_pending = 0;
        timer.overrun_last = 0;
        if new_value.is_zero() {
            timer.armed = None;
        } else {
            let deadline = if flags & TIMER_ABSTIME != 0 {
                new_value
            } else {
                ktime_add(now_clock, new_value)
            };
            timer.armed = Some((deadline, new_interval));
            if deadline <= now_clock && fire_process_timers(&mut reg, idx, now_mono, now_real) {
                fired = true;
            }
        }
        recompute_next_itimer(&reg);
        fired
    };

    if fired {
        sched::request_signal_wake();
    }
    Ok(0)
}

/// timer_gettime(2)：查询定时器剩余时间与重复周期。
pub(super) fn sys_timer_gettime(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let timer_id = args[0] as u32 as i32;
    let curr_ptr = args[1];
    let now_mono = crate::time::monotonic();
    let now_real = crate::time::realtime();

    let fired = {
        let mut reg = REGISTRY.lock();
        let idx = reg.group_index(parent).ok_or(Errno::NoProcess)?;
        let fired = fire_process_timers(&mut reg, idx, now_mono, now_real);
        let t_idx = reg.records[idx]
            .posix_timers
            .iter()
            .position(|t| t.id == timer_id)
            .ok_or(Errno::Invalid)?;
        if curr_ptr == 0 {
            return Err(Errno::Fault);
        }
        let cpu_ns = reg.records[idx]
            .user_ns
            .saturating_add(reg.records[idx].system_ns);
        let now_clock = reg.records[idx].posix_timers[t_idx].clock_now(now_mono, now_real, cpu_ns);
        let (iv, rem) = match reg.records[idx].posix_timers[t_idx].armed {
            Some((dl, iv)) => (iv, dl.saturating_sub(now_clock)),
            None => (Duration::ZERO, Duration::ZERO),
        };
        let raw = encode_itimerspec(iv, rem);
        let space = reg.records[idx]
            .space
            .as_ref()
            .ok_or(Errno::Fault)?
            .as_space();
        user_access::copy_to_user(space, curr_ptr, &raw).map_err(|_| Errno::Fault)?;
        if fired {
            recompute_next_itimer(&reg);
        }
        fired
    };
    if fired {
        sched::request_signal_wake();
    }
    Ok(0)
}

/// timer_getoverrun(2)：返回最近一次定时器信号投递期间累计的溢出次数。
pub(super) fn sys_timer_getoverrun(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let timer_id = args[0] as u32 as i32;
    let reg = REGISTRY.lock();
    let rec = reg.group(parent).ok_or(Errno::NoProcess)?;
    let timer = rec
        .posix_timers
        .iter()
        .find(|t| t.id == timer_id)
        .ok_or(Errno::Invalid)?;
    Ok(timer.overrun_last.min(i32::MAX as u64) as usize)
}

/// timer_delete(2)：删除指定 POSIX 定时器并重算全局到期时刻。
pub(super) fn sys_timer_delete(parent: Pid, args: [usize; 6]) -> Result<usize, Errno> {
    let timer_id = args[0] as u32 as i32;
    {
        let mut reg = REGISTRY.lock();
        let rec = reg.group_mut(parent).ok_or(Errno::NoProcess)?;
        let pos = rec
            .posix_timers
            .iter()
            .position(|t| t.id == timer_id)
            .ok_or(Errno::Invalid)?;
        rec.posix_timers.swap_remove(pos);
        recompute_next_itimer(&reg);
    }
    Ok(0)
}
