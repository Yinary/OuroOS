//! 建议性文件锁表：实现 BSD flock(2) 以及 fcntl(2) 的 POSIX 与 OFD 字节区间记录锁。
//! 契约见 docs/ostd-contracts.md §4.3。
#![deny(unsafe_code)]

use alloc::vec::Vec;
use spin::Mutex;

use crate::syscall::Errno;

/// 字节区间锁的归属者：POSIX 锁归属线程组（tgid），OFD 锁归属打开文件描述（ofd_id）。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockOwner {
    Process(u32),
    Ofd(u64),
}

/// 锁查询结果（供 F_GETLK / F_OFD_GETLK 写回 struct flock）。
#[derive(Clone, Copy)]
pub(crate) struct LockConflict {
    pub(crate) exclusive: bool,
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) pid: i32,
}

struct FlockEntry {
    key: u64,
    ofd_id: u64,
    exclusive: bool,
}

#[derive(Clone, Copy)]
struct RecordLock {
    key: u64,
    owner: LockOwner,
    exclusive: bool,
    start: u64,
    end: u64,
}

struct LockTable {
    flocks: Vec<FlockEntry>,
    records: Vec<RecordLock>,
}

impl LockTable {
    const fn new() -> Self {
        Self {
            flocks: Vec::new(),
            records: Vec::new(),
        }
    }
}

static LOCKS: Mutex<LockTable> = Mutex::new(LockTable::new());

fn wake_waiters() {
    crate::task::sched::request_pipe_wake();
}

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start <= b_end && b_start <= a_end
}

/// flock(2)：按打开文件描述（ofd_id）施加共享锁、独占锁或解锁。
pub(crate) fn flock(key: u64, ofd_id: u64, op: u32) -> Result<(), Errno> {
    const LOCK_SH: u32 = 1;
    const LOCK_EX: u32 = 2;
    const LOCK_NB: u32 = 4;
    const LOCK_UN: u32 = 8;

    let nonblock = op & LOCK_NB != 0;
    let base = op & !LOCK_NB;
    let exclusive = match base {
        LOCK_UN => {
            let mut tbl = LOCKS.lock();
            let before = tbl.flocks.len();
            tbl.flocks.retain(|e| !(e.key == key && e.ofd_id == ofd_id));
            let removed = tbl.flocks.len() != before;
            drop(tbl);
            if removed {
                wake_waiters();
            }
            return Ok(());
        }
        LOCK_SH => false,
        LOCK_EX => true,
        _ => return Err(Errno::Invalid),
    };

    let mut tbl = LOCKS.lock();
    let conflict = tbl
        .flocks
        .iter()
        .any(|e| e.key == key && e.ofd_id != ofd_id && (exclusive || e.exclusive));
    if conflict {
        return Err(if nonblock {
            Errno::Again
        } else {
            Errno::WouldBlock
        });
    }

    let mut downgraded = false;
    if let Some(existing) = tbl
        .flocks
        .iter_mut()
        .find(|e| e.key == key && e.ofd_id == ofd_id)
    {
        if existing.exclusive && !exclusive {
            downgraded = true;
        }
        existing.exclusive = exclusive;
    } else {
        tbl.flocks.try_reserve(1).map_err(|_| Errno::NoMem)?;
        tbl.flocks.push(FlockEntry {
            key,
            ofd_id,
            exclusive,
        });
    }
    drop(tbl);
    if downgraded {
        wake_waiters();
    }
    Ok(())
}

/// 查询是否存在与 `[start, end]` 冲突的他方记录锁（F_GETLK / F_OFD_GETLK）。
/// 与 Linux `posix_test_lock` 一致，多条冲突锁并存时返回起始偏移最小的一条。
pub(crate) fn get_record_lock(
    key: u64,
    owner: LockOwner,
    exclusive: bool,
    start: u64,
    end: u64,
) -> Option<LockConflict> {
    let tbl = LOCKS.lock();
    let best = tbl
        .records
        .iter()
        .filter(|l| {
            l.key == key
                && l.owner != owner
                && overlaps(l.start, l.end, start, end)
                && (exclusive || l.exclusive)
        })
        .min_by_key(|l| l.start)?;
    let pid = match best.owner {
        LockOwner::Process(p) => p as i32,
        LockOwner::Ofd(_) => -1,
    };
    Some(LockConflict {
        exclusive: best.exclusive,
        start: best.start,
        end: best.end,
        pid,
    })
}

/// 从 `owner` 在 `key` 上持有的锁集合中扣除 `[start, end]` 区间（必要时拆分）。
fn subtract_range(
    records: &mut Vec<RecordLock>,
    key: u64,
    owner: LockOwner,
    start: u64,
    end: u64,
) -> Result<bool, Errno> {
    let mut changed = false;
    let mut extra: Option<RecordLock> = None;
    let mut i = 0;
    while i < records.len() {
        let l = records[i];
        if l.key != key || l.owner != owner || !overlaps(l.start, l.end, start, end) {
            i += 1;
            continue;
        }
        changed = true;
        if start <= l.start && l.end <= end {
            records.swap_remove(i);
            continue;
        }
        if l.start < start && end < l.end {
            // 解锁落在一个锁区间正中：前段原地缩短，后段延后插入。
            records.try_reserve(1).map_err(|_| Errno::NoMem)?;
            records[i].end = start - 1;
            extra = Some(RecordLock {
                key: l.key,
                owner: l.owner,
                exclusive: l.exclusive,
                start: end + 1,
                end: l.end,
            });
            break;
        }
        if l.start < start {
            records[i].end = start - 1;
        } else {
            records[i].start = end + 1;
        }
        i += 1;
    }
    if let Some(tail) = extra {
        records.push(tail);
    }
    Ok(changed)
}

/// 合并同一 `(key, owner, exclusive)` 下相邻或重叠的锁区间。
fn coalesce(records: &mut Vec<RecordLock>, key: u64, owner: LockOwner, exclusive: bool) {
    let mut merged = true;
    while merged {
        merged = false;
        let mut i = 0;
        while i < records.len() {
            if records[i].key != key
                || records[i].owner != owner
                || records[i].exclusive != exclusive
            {
                i += 1;
                continue;
            }
            let mut j = i + 1;
            while j < records.len() {
                if records[j].key == key
                    && records[j].owner == owner
                    && records[j].exclusive == exclusive
                {
                    let (a, b) = if records[i].start <= records[j].start {
                        (records[i], records[j])
                    } else {
                        (records[j], records[i])
                    };
                    if a.end == u64::MAX || a.end.saturating_add(1) >= b.start {
                        records[i].start = a.start;
                        records[i].end = a.end.max(b.end);
                        records.swap_remove(j);
                        merged = true;
                        continue;
                    }
                }
                j += 1;
            }
            i += 1;
        }
    }
}

/// 施加或解除字节区间记录锁（F_SETLK / F_SETLKW / F_OFD_SETLK / F_OFD_SETLKW）。
/// `exclusive = None` 表示 `F_UNLCK`。
pub(crate) fn set_record_lock(
    key: u64,
    owner: LockOwner,
    exclusive: Option<bool>,
    start: u64,
    end: u64,
    blocking: bool,
) -> Result<(), Errno> {
    let mut tbl = LOCKS.lock();
    let Some(excl) = exclusive else {
        let changed = subtract_range(&mut tbl.records, key, owner, start, end)?;
        drop(tbl);
        if changed {
            wake_waiters();
        }
        return Ok(());
    };

    let conflict = tbl.records.iter().any(|l| {
        l.key == key
            && l.owner != owner
            && overlaps(l.start, l.end, start, end)
            && (excl || l.exclusive)
    });
    if conflict {
        return Err(if blocking {
            Errno::WouldBlock
        } else {
            Errno::Again
        });
    }

    // 预留插入槽位（最多 1 个拆分尾段 + 1 个新锁），保证修改阶段不因 OOM 半途失败。
    tbl.records.try_reserve(2).map_err(|_| Errno::NoMem)?;
    let had_old = subtract_range(&mut tbl.records, key, owner, start, end)?;
    tbl.records.push(RecordLock {
        key,
        owner,
        exclusive: excl,
        start,
        end,
    });
    coalesce(&mut tbl.records, key, owner, excl);
    drop(tbl);
    if had_old && !excl {
        wake_waiters();
    }
    Ok(())
}

/// 关闭打开文件描述的最后引用时，释放该 OFD 持有的全部 flock 与 OFD 记录锁。
pub(crate) fn release_ofd(ofd_id: u64) {
    let mut tbl = LOCKS.lock();
    let f_before = tbl.flocks.len();
    let r_before = tbl.records.len();
    tbl.flocks.retain(|e| e.ofd_id != ofd_id);
    tbl.records.retain(|l| l.owner != LockOwner::Ofd(ofd_id));
    let removed = tbl.flocks.len() != f_before || tbl.records.len() != r_before;
    drop(tbl);
    if removed {
        wake_waiters();
    }
}

/// POSIX fcntl(2) 语义：进程关闭指向某文件的任意 FD 时，释放该进程在该文件上的全部 POSIX 记录锁。
pub(crate) fn release_posix_for_key(tgid: u32, key: u64) {
    let mut tbl = LOCKS.lock();
    let before = tbl.records.len();
    tbl.records
        .retain(|l| !(l.key == key && l.owner == LockOwner::Process(tgid)));
    let removed = tbl.records.len() != before;
    drop(tbl);
    if removed {
        wake_waiters();
    }
}

/// 进程退出时释放该线程组持有的全部 POSIX 记录锁。
pub(crate) fn release_process_locks(tgid: u32) {
    let mut tbl = LOCKS.lock();
    let before = tbl.records.len();
    tbl.records.retain(|l| l.owner != LockOwner::Process(tgid));
    let removed = tbl.records.len() != before;
    drop(tbl);
    if removed {
        wake_waiters();
    }
}
