//! futex 系统调用：等待字身份、命令分派与截止时间。
//! 键与唤醒动作在此计算，唤醒本体在注册表锁外执行。

use core::time::Duration;

use crate::{
    mm::{
        address_space::{FutexKey, UserAddressSpace},
        user_access,
    },
    syscall::Errno,
    time::{monotonic, realtime},
};

use super::task::{Pid, WaitReason};

const FUTEX_WAIT: usize = 0;
const FUTEX_WAKE: usize = 1;
const FUTEX_REQUEUE: usize = 3;
const FUTEX_CMP_REQUEUE: usize = 4;
const FUTEX_WAIT_BITSET: usize = 9;
const FUTEX_WAKE_BITSET: usize = 10;
const FUTEX_PRIVATE_FLAG: usize = 128;
const FUTEX_CLOCK_REALTIME: usize = 256;
const FUTEX_BITSET_MATCH_ANY: u32 = 0xffff_ffff;
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const ROBUST_LIST_LIMIT: usize = 2048;

/// Linux 64 位 struct robust_list_head 的字节数（list.next、futex_offset、list_op_pending）。
pub const ROBUST_LIST_HEAD_SIZE: usize = 24;

/// 线程退出时遍历其健壮锁链表：把本线程持有的锁置 FUTEX_OWNER_DIED，
/// 并收集需要唤醒等待者的 futex 键（由调用方在释放 REGISTRY 锁后执行唤醒）。
pub fn collect_robust_list_wakes(
    space: &UserAddressSpace,
    tgid: Pid,
    tid: Pid,
    head: usize,
) -> alloc::vec::Vec<FutexKey> {
    let mut wakes = alloc::vec::Vec::new();
    if head == 0 {
        return wakes;
    }
    let mut raw = [0u8; ROBUST_LIST_HEAD_SIZE];
    if user_access::copy_from_user(space, head, &mut raw).is_err() {
        return wakes;
    }
    let mut entry = usize::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let futex_offset = isize::from_ne_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    let pending = usize::from_ne_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
    let pending_addr = pending & !1;

    let mut handle_death = |entry_raw: usize| {
        let pi = (entry_raw & 1) != 0;
        let addr = (entry_raw & !1).wrapping_add_signed(futex_offset);
        if addr == 0 || addr % core::mem::align_of::<u32>() != 0 {
            return;
        }
        let Ok(uval) = read_word(space, addr) else {
            return;
        };
        if (uval & FUTEX_TID_MASK) != (tid as u32) {
            return;
        }
        let nval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        if user_access::copy_to_user(space, addr, &nval.to_ne_bytes()).is_err() {
            return;
        }
        if (uval & FUTEX_WAITERS) != 0 || pi {
            let priv_key = space.futex_key(tgid, addr, true);
            let shared_key = space.futex_key(tgid, addr, false);
            if let Some(k) = priv_key {
                if wakes.try_reserve(1).is_ok() {
                    wakes.push(k);
                }
            }
            if let Some(k) = shared_key {
                if priv_key != Some(k) && wakes.try_reserve(1).is_ok() {
                    wakes.push(k);
                }
            }
        }
    };

    let mut count = 0usize;
    while (entry & !1) != head && (entry & !1) != 0 && count < ROBUST_LIST_LIMIT {
        let entry_addr = entry & !1;
        let mut next_bytes = [0u8; 8];
        if user_access::copy_from_user(space, entry_addr, &mut next_bytes).is_err() {
            break;
        }
        let next = usize::from_ne_bytes(next_bytes);
        if entry_addr != pending_addr {
            handle_death(entry);
        }
        entry = next;
        count += 1;
    }
    if pending_addr != 0 {
        handle_death(pending);
    }
    wakes
}

/// futex 一次处理的结果。
pub enum FutexStep {
    Wait(WaitReason),
    /// 按键唤醒至多 n 个 bitset 有交集的等待者，由调用方在锁外执行。
    Wake {
        key: FutexKey,
        n: usize,
        bitset: u32,
    },
    /// 先唤醒再从 from 键重排队到 to 键，由调用方在锁外执行。
    Requeue {
        from: FutexKey,
        to: FutexKey,
        nr_wake: usize,
        nr_requeue: usize,
    },
}

/// 入队前读取一次比较值；之后由调度器决定唤醒、超时或信号中断。
pub fn futex_call(
    space: &UserAddressSpace,
    tgid: Pid,
    args: [usize; 6],
) -> Result<FutexStep, Errno> {
    let cmd = args[1] & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
    let key_of = |address: usize| -> Result<FutexKey, Errno> {
        if address % core::mem::align_of::<u32>() != 0 {
            return Err(Errno::Invalid);
        }
        space
            .futex_key(tgid, address, args[1] & FUTEX_PRIVATE_FLAG != 0)
            .ok_or(Errno::Fault)
    };
    let bitset = if matches!(cmd, FUTEX_WAIT_BITSET | FUTEX_WAKE_BITSET) {
        let bits = args[5] as u32;
        if bits == 0 {
            return Err(Errno::Invalid);
        }
        bits
    } else {
        FUTEX_BITSET_MATCH_ANY
    };
    match cmd {
        FUTEX_WAIT if args[1] & FUTEX_CLOCK_REALTIME != 0 => Err(Errno::NoSys),
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let key = key_of(args[0])?;
            if read_word(space, args[0])? != args[2] as u32 {
                return Err(Errno::Again);
            }
            let deadline = deadline_of(
                space,
                args[3],
                cmd == FUTEX_WAIT_BITSET,
                args[1] & FUTEX_CLOCK_REALTIME != 0,
            )?;
            if deadline.is_some_and(|d| monotonic() >= d) {
                return Err(Errno::TimedOut);
            }
            Ok(FutexStep::Wait(WaitReason::Futex {
                key,
                deadline,
                bitset,
            }))
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => Ok(FutexStep::Wake {
            key: key_of(args[0])?,
            n: args[2] as u32 as usize,
            bitset,
        }),
        FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
            let from = key_of(args[0])?;
            let to = key_of(args[4])?;
            if cmd == FUTEX_CMP_REQUEUE && read_word(space, args[0])? != args[5] as u32 {
                return Err(Errno::Again);
            }
            let count = |n: usize| usize::try_from(n as i32).map_err(|_| Errno::Invalid);
            Ok(FutexStep::Requeue {
                from,
                to,
                nr_wake: count(args[2])?,
                nr_requeue: count(args[3])?,
            })
        }
        _ => Err(Errno::NoSys),
    }
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
    let span = Duration::new(sec as u64, ns as u32);
    if absolute && !realtime_clock {
        return Ok(Some(span));
    }
    let now = monotonic();
    let delta = if absolute {
        span.saturating_sub(realtime())
    } else {
        span
    };
    now.checked_add(delta).map(Some).ok_or(Errno::Invalid)
}
