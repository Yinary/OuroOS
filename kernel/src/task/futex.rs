use core::time::Duration;

use crate::{
    mm::{address_space::UserAddressSpace, user_access},
    syscall::Errno,
    time::monotonic,
};

use super::{
    sched,
    task::{FutexKey, WaitReason},
};

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_REQUEUE: usize = 3;
const FUTEX_CMP_REQUEUE: usize = 4;
const FUTEX_PRIVATE_FLAG: usize = 128;
const FUTEX_CLOCK_REALTIME: usize = 256;

/// futex 一次处理的结果。
pub enum FutexStep {
    Done(Result<usize, Errno>),
    Wait(WaitReason),
}

/// 处理一次 futex 系统调用；pending 是本线程上一轮挂起留下的等待状态。
pub fn futex_call(
    space: &UserAddressSpace,
    args: [usize; 6],
    pending: &mut Option<(FutexKey, u32, Option<Duration>)>,
) -> FutexStep {
    if let Some((key, val, deadline)) = *pending {
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
                _ => FutexStep::Wait(WaitReason::Futex { key, deadline }),
            },
        };
    }
    let cmd = args[1] & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    match cmd {
        FUTEX_WAIT => futex_wait(space, args, pending),
        FUTEX_WAKE => match key_of(space, args[0]) {
            Some(key) => FutexStep::Done(Ok(sched::wake_futex(key, args[2]))),
            None => FutexStep::Done(Err(Errno::Fault)),
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
    pending: &mut Option<(FutexKey, u32, Option<Duration>)>,
) -> FutexStep {
    let val = args[2] as u32;
    let word = match read_word(space, args[0]) {
        Ok(word) => word,
        Err(e) => return FutexStep::Done(Err(e)),
    };
    if word != val {
        return FutexStep::Done(Err(Errno::Again));
    }
    let deadline = match deadline_of(space, args[3]) {
        Ok(deadline) => deadline,
        Err(e) => return FutexStep::Done(Err(e)),
    };
    let key = match key_of(space, args[0]) {
        Some(key) => key,
        None => return FutexStep::Done(Err(Errno::Fault)),
    };
    *pending = Some((key, val, deadline));
    FutexStep::Wait(WaitReason::Futex { key, deadline })
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

fn deadline_of(space: &UserAddressSpace, ts_ptr: usize) -> Result<Option<Duration>, Errno> {
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
    monotonic()
        .checked_add(Duration::new(sec as u64, ns as u32))
        .map(Some)
        .ok_or(Errno::Invalid)
}
