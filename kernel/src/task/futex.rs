use core::time::Duration;

use crate::{
    mm::{address_space::UserAddressSpace, user_access},
    syscall::Errno,
    time::{monotonic, realtime},
};

use super::{
    sched,
    task::{FutexKey, WaitReason},
};

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_REQUEUE: usize = 3;
const FUTEX_CMP_REQUEUE: usize = 4;
const FUTEX_WAIT_BITSET: usize = 9;
const FUTEX_WAKE_BITSET: usize = 10;
const FUTEX_PRIVATE_FLAG: usize = 128;
const FUTEX_CLOCK_REALTIME: usize = 256;
const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;

/// futex 一次处理的结果。
pub enum FutexStep {
    Done(Result<usize, Errno>),
    Wait(WaitReason),
}

/// 处理一次 futex 系统调用；pending 是本线程上一轮挂起留下的等待状态。
pub fn futex_call(
    space: &UserAddressSpace,
    args: [usize; 6],
    pending: &mut Option<(FutexKey, u32, Option<Duration>, u32)>,
) -> FutexStep {
    if let Some((key, val, deadline, bitset)) = *pending {
        return match read_word(space, args[0]) {
            Err(_) => {
                *pending = None;
                FutexStep::Done(Err(Errno::Fault))
            }
            Ok(word) if word != val => {
                *pending = None;
                FutexStep::Done(Ok(0))
            }
            Ok(_) => match deadline {
                Some(deadline) if monotonic() >= deadline => {
                    *pending = None;
                    FutexStep::Done(Err(Errno::TimedOut))
                }
                _ => FutexStep::Wait(WaitReason::Futex {
                    key,
                    deadline,
                    bitset,
                }),
            },
        };
    }
    let cmd = args[1] & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    match cmd {
        FUTEX_WAIT => futex_wait(space, args, pending, FUTEX_BITSET_MATCH_ANY, false),
        FUTEX_WAIT_BITSET => match args[5] as u32 {
            0 => FutexStep::Done(Err(Errno::Invalid)),
            bitset => futex_wait(space, args, pending, bitset, true),
        },
        FUTEX_WAKE => match key_of(space, args[0]) {
            Some(key) => {
                FutexStep::Done(Ok(sched::wake_futex(key, args[2], FUTEX_BITSET_MATCH_ANY)))
            }
            None => FutexStep::Done(Err(Errno::Fault)),
        },
        FUTEX_WAKE_BITSET => match args[5] as u32 {
            0 => FutexStep::Done(Err(Errno::Invalid)),
            bitset => match key_of(space, args[0]) {
                Some(key) => FutexStep::Done(Ok(sched::wake_futex(key, args[2], bitset))),
                None => FutexStep::Done(Err(Errno::Fault)),
            },
        },
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            if cmd == FUTEX_CMP_REQUEUE {
                match read_word(space, args[0]) {
                    Err(_) => return FutexStep::Done(Err(Errno::Fault)),
                    Ok(word) if word != args[5] as u32 => {
                        return FutexStep::Done(Err(Errno::Again))
                    }
                    Ok(_) => {}
                }
            }
            let key = match key_of(space, args[0]) {
                Some(key) => key,
                None => return FutexStep::Done(Err(Errno::Fault)),
            };
            let to = match key_of(space, args[4]) {
                Some(key) => key,
                None => return FutexStep::Done(Err(Errno::Fault)),
            };
            FutexStep::Done(Ok(sched::requeue_futex(key, to, args[2], args[3])))
        }
        _ => FutexStep::Done(Err(Errno::NoSys)),
    }
}

fn futex_wait(
    space: &UserAddressSpace,
    args: [usize; 6],
    pending: &mut Option<(FutexKey, u32, Option<Duration>, u32)>,
    bitset: u32,
    absolute: bool,
) -> FutexStep {
    let val = args[2] as u32;
    let word = match read_word(space, args[0]) {
        Ok(word) => word,
        Err(e) => return FutexStep::Done(Err(e)),
    };
    if word != val {
        return FutexStep::Done(Err(Errno::Again));
    }
    let deadline = match deadline_of(
        space,
        args[3],
        absolute,
        args[1] & FUTEX_CLOCK_REALTIME != 0,
    ) {
        Ok(deadline) => deadline,
        Err(e) => return FutexStep::Done(Err(e)),
    };
    if absolute && deadline.is_some_and(|d| monotonic() >= d) {
        return FutexStep::Done(Err(Errno::TimedOut));
    }
    let key = match key_of(space, args[0]) {
        Some(key) => key,
        None => return FutexStep::Done(Err(Errno::Fault)),
    };
    *pending = Some((key, val, deadline, bitset));
    FutexStep::Wait(WaitReason::Futex {
        key,
        deadline,
        bitset,
    })
}

fn key_of(space: &UserAddressSpace, uaddr: usize) -> Option<FutexKey> {
    space.translate(uaddr).map(|(pa, _)| FutexKey {
        frame: pa.raw() & !0xfff,
        offset: uaddr & 0xfff,
    })
}

fn read_word(space: &UserAddressSpace, uaddr: usize) -> Result<u32, Errno> {
    let mut bytes = [0; 4];
    user_access::copy_from_user(space, uaddr, &mut bytes).map_err(|_| Errno::Fault)?;
    Ok(u32::from_ne_bytes(bytes))
}

fn deadline_of(
    space: &UserAddressSpace,
    ts_ptr: usize,
    absolute: bool,
    realtime_clock: bool,
) -> Result<Option<Duration>, Errno> {
    if ts_ptr == 0 {
        return Ok(None);
    }
    let mut raw = [0; 16];
    user_access::copy_from_user(space, ts_ptr, &mut raw).map_err(|_| Errno::Fault)?;
    let sec = i64::from_ne_bytes(raw[..8].try_into().unwrap_or([0; 8]));
    let ns = i64::from_ne_bytes(raw[8..].try_into().unwrap_or([0; 8]));
    if sec < 0 || !(0..1_000_000_000).contains(&ns) {
        return Err(Errno::Invalid);
    }
    let now = monotonic();
    let span = Duration::new(sec as u64, ns as u32);
    let delta = if absolute {
        let base = if realtime_clock { realtime() } else { now };
        span.saturating_sub(base)
    } else {
        span
    };
    now.checked_add(delta).map(Some).ok_or(Errno::Invalid)
}
