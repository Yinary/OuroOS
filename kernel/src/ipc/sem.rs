//! System V 信号量集：semget(190)、semctl(191)、semtimedop(192)、semop(193)。
//! 支持多操作原子执行、相对超时、GETNCNT/GETZCNT 准确计数与进程退出 SEM_UNDO 回滚。
#![deny(unsafe_code)]

use alloc::vec::Vec;
use core::time::Duration;

use crate::{
    mm::{address_space::UserAddressSpace, user_access},
    sync::DebugMutex,
    syscall::Errno,
    task::{sched, Credentials},
};

use super::{
    normalize_cmd, now_secs, sem_wake_key, IpcFlow, IpcPerm, IpcWaitState, IPCMNI, IPC_CREAT,
    IPC_EXCL, IPC_INFO, IPC_NOWAIT, IPC_PRIVATE, IPC_R, IPC_RMID, IPC_SEQ_MASK, IPC_SET, IPC_STAT,
    IPC_W,
};

/// 信号量操作撤销标志：进程退出时回滚本进程对该信号量的净调整量。
const SEM_UNDO: i16 = 0x1000;

/// semctl 控制命令（剥离 IPC_64 后，asm-generic Linux UAPI）。
const GETPID: i32 = 11;
const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const GETNCNT: i32 = 14;
const GETZCNT: i32 = 15;
const SETVAL: i32 = 16;
const SETALL: i32 = 17;
const SEM_STAT: i32 = 18;
const SEM_INFO: i32 = 19;
const SEM_STAT_ANY: i32 = 20;

/// 系统信号量限制常量（与 IPC_INFO/SEM_INFO 及 /proc/sys/kernel/sem 保持一致）。
pub(crate) const SEMMNI: usize = 128;
pub(crate) const SEMMSL: usize = 512;
pub(crate) const SEMMNS: usize = 32000;
pub(crate) const SEMOPM: usize = 500;
const SEMVMX: i32 = 32767;
const SEMAEM: i32 = 32767;
const SEMMAP: i32 = SEMMNS as i32;
const SEMMNU: i32 = SEMMNS as i32;
const SEMUME: i32 = SEMOPM as i32;
const SEMUSZ: i32 = 20;

/// asm-generic 64 位 `struct semid64_ds` 字节长度。
const SEMID_DS_SIZE: usize = 88;
/// `struct seminfo` 字节长度（10 个 i32）。
const SEMINFO_SIZE: usize = 40;
/// `struct sembuf` 字节长度（u16 + i16 + i16）。
const SEMBUF_SIZE: usize = 6;

#[derive(Clone, Copy)]
struct SemEntry {
    val: i32,
    pid: i32,
}

#[derive(Clone, Copy)]
struct SemWaiter {
    tid: usize,
    tgid: usize,
    sem_num: u16,
    /// true 表示等待归零（GETZCNT），false 表示等待增量（GETNCNT）。
    zero: bool,
}

struct SemUndo {
    tgid: usize,
    adj: Vec<i16>,
}

struct SemSet {
    id: usize,
    perm: IpcPerm,
    otime: i64,
    ctime: i64,
    sems: Vec<SemEntry>,
    waiters: Vec<SemWaiter>,
    undos: Vec<SemUndo>,
}

impl SemSet {
    fn encode_ds(&self) -> [u8; SEMID_DS_SIZE] {
        let mut out = [0u8; SEMID_DS_SIZE];
        self.perm.encode(&mut out[0..48]);
        out[48..56].copy_from_slice(&self.otime.to_ne_bytes());
        out[56..64].copy_from_slice(&self.ctime.to_ne_bytes());
        out[64..72].copy_from_slice(&(self.sems.len() as u64).to_ne_bytes());
        out
    }

    fn set_waiter(&mut self, tid: usize, tgid: usize, sem_num: u16, zero: bool) {
        if let Some(w) = self.waiters.iter_mut().find(|w| w.tid == tid) {
            w.tgid = tgid;
            w.sem_num = sem_num;
            w.zero = zero;
            return;
        }
        if self.waiters.try_reserve(1).is_ok() {
            self.waiters.push(SemWaiter {
                tid,
                tgid,
                sem_num,
                zero,
            });
        }
    }

    fn remove_waiter(&mut self, tid: usize) {
        if let Some(pos) = self.waiters.iter().position(|w| w.tid == tid) {
            self.waiters.swap_remove(pos);
        }
    }
}

struct SemTable {
    next_idx: usize,
    next_seq: u16,
    total_sems: usize,
    slots: Vec<Option<SemSet>>,
}

impl SemTable {
    const fn new() -> Self {
        Self {
            next_idx: 0,
            next_seq: 0,
            total_sems: 0,
            slots: Vec::new(),
        }
    }

    fn find_by_key(&self, key: i32) -> Option<&SemSet> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|s| s.perm.key == key)
    }

    fn find_by_id(&self, id: usize) -> Option<&SemSet> {
        let idx = id % IPCMNI;
        self.slots
            .get(idx)
            .and_then(|s| s.as_ref())
            .filter(|s| s.id == id)
    }

    fn find_by_id_mut(&mut self, id: usize) -> Option<&mut SemSet> {
        let idx = id % IPCMNI;
        self.slots
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .filter(|s| s.id == id)
    }

    fn max_used_index(&self) -> usize {
        self.slots.iter().rposition(|s| s.is_some()).unwrap_or(0)
    }

    fn used_sets(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

/// 全局信号量集状态表；纯叶子锁，绝不在持锁期间访问用户页表或调度器锁。
static SEM_TABLE: DebugMutex<SemTable> = DebugMutex::new("SEM_TABLE", SemTable::new());

#[derive(Clone, Copy)]
struct SemOp {
    sem_num: u16,
    sem_op: i16,
    sem_flg: i16,
}

/// 清除指定线程在所有信号量集中的等待登记（信号打断或线程退出时调用）。
pub fn clear_waiter(tid: usize) {
    let mut table = SEM_TABLE.lock();
    for set in table.slots.iter_mut().filter_map(|s| s.as_mut()) {
        set.remove_waiter(tid);
    }
}

/// 线程组退出时回滚其所有 SEM_UNDO 调整量，并唤醒可能解除阻塞的等待者。
pub fn on_process_exit(tgid: usize) {
    let mut wake_keys = Vec::new();
    {
        let mut table = SEM_TABLE.lock();
        let now = now_secs();
        for set in table.slots.iter_mut().filter_map(|s| s.as_mut()) {
            set.waiters.retain(|w| w.tgid != tgid);
            let Some(pos) = set.undos.iter().position(|u| u.tgid == tgid) else {
                continue;
            };
            let undo = set.undos.swap_remove(pos);
            let mut changed = false;
            for (i, &delta) in undo.adj.iter().enumerate() {
                if delta == 0 || i >= set.sems.len() {
                    continue;
                }
                let next = (set.sems[i].val + delta as i32).clamp(0, SEMVMX);
                set.sems[i].val = next;
                set.sems[i].pid = tgid as i32;
                changed = true;
            }
            if changed {
                set.otime = now;
                if wake_keys.try_reserve(1).is_ok() {
                    wake_keys.push(sem_wake_key(set.id));
                }
            }
        }
    }
    for key in wake_keys {
        sched::request_ipc_wake(key);
    }
}

/// /proc/sysvipc/sem 只读快照：按 Linux proc(5) 10 列格式输出所有活动信号量集。
pub fn proc_sysvipc() -> Result<alloc::string::String, Errno> {
    use core::fmt::Write;
    let table = SEM_TABLE.lock();
    let mut out = alloc::string::String::new();
    let header =
        "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n";
    let count = table.used_sets();
    out.try_reserve(header.len() + count * 96)
        .map_err(|_| Errno::NoMem)?;
    out.push_str(header);
    for s in table.slots.iter().filter_map(|s| s.as_ref()) {
        let _ = writeln!(
            out,
            "{:10} {:10}  {:4o} {:10} {:5} {:5} {:5} {:5} {:10} {:10}",
            s.perm.key,
            s.id,
            s.perm.mode,
            s.sems.len(),
            s.perm.uid,
            s.perm.gid,
            s.perm.cuid,
            s.perm.cgid,
            s.otime,
            s.ctime
        );
    }
    Ok(out)
}

/// semget(2)：按 key 查找或新建信号量集，返回非负 semid。
pub fn get(key: i32, nsems: i32, semflg: i32, creds: &Credentials) -> Result<usize, Errno> {
    if nsems < 0 {
        return Err(Errno::Invalid);
    }
    let mut table = SEM_TABLE.lock();
    if key != IPC_PRIVATE {
        if let Some(set) = table.find_by_key(key) {
            if semflg & (IPC_CREAT | IPC_EXCL) == (IPC_CREAT | IPC_EXCL) {
                return Err(Errno::Exists);
            }
            if (nsems as usize) > set.sems.len() {
                return Err(Errno::Invalid);
            }
            set.perm.check_access(semflg & 0o777, creds)?;
            return Ok(set.id);
        }
        if semflg & IPC_CREAT == 0 {
            return Err(Errno::NoEntry);
        }
    }

    let count = nsems as usize;
    if count == 0 || count > SEMMSL {
        return Err(Errno::Invalid);
    }
    if table.total_sems.saturating_add(count) > SEMMNS {
        return Err(Errno::NoSpace);
    }
    let mut wrapped = false;
    let mut found = None;
    for i in table.next_idx..SEMMNI {
        if i >= table.slots.len() || table.slots[i].is_none() {
            found = Some(i);
            break;
        }
    }
    if found.is_none() {
        wrapped = true;
        for i in 0..table.next_idx.min(SEMMNI) {
            if i >= table.slots.len() || table.slots[i].is_none() {
                found = Some(i);
                break;
            }
        }
    }
    let slot_idx = found.ok_or(Errno::NoSpace)?;
    if slot_idx >= table.slots.len() {
        let need = slot_idx + 1 - table.slots.len();
        table.slots.try_reserve(need).map_err(|_| Errno::NoMem)?;
        table.slots.resize_with(slot_idx + 1, || None);
    }

    let mut sems = Vec::new();
    sems.try_reserve_exact(count).map_err(|_| Errno::NoMem)?;
    sems.resize(count, SemEntry { val: 0, pid: 0 });

    if wrapped {
        table.next_seq = table.next_seq.wrapping_add(1) & IPC_SEQ_MASK;
    }
    let seq = table.next_seq;
    table.next_idx = slot_idx + 1;
    let id = (seq as usize) * IPCMNI + slot_idx;
    let perm = IpcPerm::new(key, semflg, seq, creds);

    table.total_sems += count;
    table.slots[slot_idx] = Some(SemSet {
        id,
        perm,
        otime: 0,
        ctime: now_secs(),
        sems,
        waiters: Vec::new(),
        undos: Vec::new(),
    });
    Ok(id)
}

/// semctl(2)：支持 GETVAL/SETVAL/GETPID/GETNCNT/GETZCNT/GETALL/SETALL 与
/// IPC_STAT/IPC_SET/IPC_RMID/IPC_INFO/SEM_INFO/SEM_STAT/SEM_STAT_ANY。
pub fn ctl(
    space: &UserAddressSpace,
    semid: i32,
    semnum: i32,
    raw_cmd: i32,
    arg: usize,
    tgid: usize,
    creds: &Credentials,
) -> Result<usize, Errno> {
    let cmd = normalize_cmd(raw_cmd);
    match cmd {
        IPC_INFO | SEM_INFO => {
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let (raw, max_idx) = {
                let table = SEM_TABLE.lock();
                let mut info = [0u8; SEMINFO_SIZE];
                let (semusz, semaem) = if cmd == SEM_INFO {
                    (
                        table.used_sets().min(i32::MAX as usize) as i32,
                        table.total_sems.min(i32::MAX as usize) as i32,
                    )
                } else {
                    (SEMUSZ, SEMAEM)
                };
                let fields: [i32; 10] = [
                    SEMMAP,
                    SEMMNI as i32,
                    SEMMNS as i32,
                    SEMMNU,
                    SEMMSL as i32,
                    SEMOPM as i32,
                    SEMUME,
                    semusz,
                    SEMVMX,
                    semaem,
                ];
                for (i, v) in fields.iter().enumerate() {
                    info[i * 4..(i + 1) * 4].copy_from_slice(&v.to_ne_bytes());
                }
                (info, table.max_used_index())
            };
            user_access::copy_to_user(space, arg, &raw).map_err(|_| Errno::Fault)?;
            Ok(max_idx)
        }
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            if arg == 0 {
                return Err(Errno::Fault);
            }
            if semid < 0 {
                return Err(Errno::Invalid);
            }
            let (raw, ret_val) = {
                let table = SEM_TABLE.lock();
                let set = if cmd == IPC_STAT {
                    table.find_by_id(semid as usize).ok_or(Errno::Invalid)?
                } else {
                    table
                        .slots
                        .get(semid as usize)
                        .and_then(|s| s.as_ref())
                        .ok_or(Errno::Invalid)?
                };
                if cmd != SEM_STAT_ANY {
                    set.perm.check_access(IPC_R, creds)?;
                }
                (set.encode_ds(), if cmd == IPC_STAT { 0 } else { set.id })
            };
            user_access::copy_to_user(space, arg, &raw).map_err(|_| Errno::Fault)?;
            Ok(ret_val)
        }
        IPC_SET => {
            if semid < 0 {
                return Err(Errno::Invalid);
            }
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let mut raw = [0u8; SEMID_DS_SIZE];
            user_access::copy_from_user(space, arg, &mut raw).map_err(|_| Errno::Fault)?;
            let (uid, gid, mode) = IpcPerm::decode_set(&raw[0..48]);
            let mut table = SEM_TABLE.lock();
            let set = table.find_by_id_mut(semid as usize).ok_or(Errno::Invalid)?;
            set.perm.check_owner(creds)?;
            set.perm.uid = uid;
            set.perm.gid = gid;
            set.perm.mode = mode;
            set.ctime = now_secs();
            Ok(0)
        }
        IPC_RMID => {
            if semid < 0 {
                return Err(Errno::Invalid);
            }
            let id = semid as usize;
            let idx = id % IPCMNI;
            {
                let mut table = SEM_TABLE.lock();
                let count = {
                    let set = table
                        .slots
                        .get(idx)
                        .and_then(|s| s.as_ref())
                        .filter(|s| s.id == id)
                        .ok_or(Errno::Invalid)?;
                    set.perm.check_owner(creds)?;
                    set.sems.len()
                };
                table.slots[idx] = None;
                table.total_sems = table.total_sems.saturating_sub(count);
            }
            sched::request_ipc_wake(sem_wake_key(id));
            Ok(0)
        }
        GETVAL | GETPID | GETNCNT | GETZCNT => {
            if semid < 0 || semnum < 0 {
                return Err(Errno::Invalid);
            }
            let table = SEM_TABLE.lock();
            let set = table.find_by_id(semid as usize).ok_or(Errno::Invalid)?;
            set.perm.check_access(IPC_R, creds)?;
            let idx = semnum as usize;
            if idx >= set.sems.len() {
                return Err(Errno::Invalid);
            }
            let val = match cmd {
                GETVAL => set.sems[idx].val as usize,
                GETPID => set.sems[idx].pid as usize,
                GETNCNT => set
                    .waiters
                    .iter()
                    .filter(|w| w.sem_num as usize == idx && !w.zero)
                    .count(),
                _ => set
                    .waiters
                    .iter()
                    .filter(|w| w.sem_num as usize == idx && w.zero)
                    .count(),
            };
            Ok(val)
        }
        SETVAL => {
            if semid < 0 || semnum < 0 {
                return Err(Errno::Invalid);
            }
            let val = arg as u32 as i32;
            if !(0..=SEMVMX).contains(&val) {
                return Err(Errno::Range);
            }
            let id = semid as usize;
            {
                let mut table = SEM_TABLE.lock();
                let set = table.find_by_id_mut(id).ok_or(Errno::Invalid)?;
                set.perm.check_access(IPC_W, creds)?;
                let idx = semnum as usize;
                if idx >= set.sems.len() {
                    return Err(Errno::Invalid);
                }
                set.sems[idx].val = val;
                set.sems[idx].pid = tgid as i32;
                set.ctime = now_secs();
                // Linux 语义：SETVAL 清除所有进程在该信号量上的 SEM_UNDO 调整值。
                for u in &mut set.undos {
                    if idx < u.adj.len() {
                        u.adj[idx] = 0;
                    }
                }
            }
            sched::request_ipc_wake(sem_wake_key(id));
            Ok(0)
        }
        GETALL => {
            if semid < 0 {
                return Err(Errno::Invalid);
            }
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let raw = {
                let table = SEM_TABLE.lock();
                let set = table.find_by_id(semid as usize).ok_or(Errno::Invalid)?;
                set.perm.check_access(IPC_R, creds)?;
                let mut buf = Vec::new();
                buf.try_reserve_exact(set.sems.len() * 2)
                    .map_err(|_| Errno::NoMem)?;
                for s in &set.sems {
                    buf.extend_from_slice(&(s.val as u16).to_ne_bytes());
                }
                buf
            };
            user_access::copy_to_user(space, arg, &raw).map_err(|_| Errno::Fault)?;
            Ok(0)
        }
        SETALL => {
            if semid < 0 {
                return Err(Errno::Invalid);
            }
            if arg == 0 {
                return Err(Errno::Fault);
            }
            let id = semid as usize;
            let nsems = {
                let table = SEM_TABLE.lock();
                let set = table.find_by_id(id).ok_or(Errno::Invalid)?;
                set.perm.check_access(IPC_W, creds)?;
                set.sems.len()
            };
            let mut raw = Vec::new();
            raw.try_reserve_exact(nsems * 2).map_err(|_| Errno::NoMem)?;
            raw.resize(nsems * 2, 0);
            user_access::copy_from_user(space, arg, &mut raw).map_err(|_| Errno::Fault)?;
            let mut vals = Vec::new();
            vals.try_reserve_exact(nsems).map_err(|_| Errno::NoMem)?;
            for chunk in raw.chunks_exact(2) {
                let v = u16::from_ne_bytes([chunk[0], chunk[1]]) as i32;
                if v > SEMVMX {
                    return Err(Errno::Range);
                }
                vals.push(v);
            }
            {
                let mut table = SEM_TABLE.lock();
                let set = table.find_by_id_mut(id).ok_or(Errno::Invalid)?;
                set.perm.check_access(IPC_W, creds)?;
                if set.sems.len() != vals.len() {
                    return Err(Errno::Invalid);
                }
                for (s, &v) in set.sems.iter_mut().zip(vals.iter()) {
                    s.val = v;
                    s.pid = tgid as i32;
                }
                set.ctime = now_secs();
                // Linux 语义：SETALL 清除该集合下所有进程的 SEM_UNDO 调整值。
                set.undos.clear();
            }
            sched::request_ipc_wake(sem_wake_key(id));
            Ok(0)
        }
        _ => Err(Errno::Invalid),
    }
}

/// semop(2) / semtimedop(2)：原子执行多条信号量操作；无法立即满足时阻塞直至条件满足、
/// 超时（EAGAIN）、被信号打断（EINTR）或集合被删除（EIDRM）。
#[allow(clippy::too_many_arguments)]
pub fn timedop(
    space: &UserAddressSpace,
    semid: i32,
    sops_ptr: usize,
    nsops: usize,
    timeout_ptr: usize,
    tid: usize,
    tgid: usize,
    creds: &Credentials,
    wait_state: Option<IpcWaitState>,
) -> IpcFlow {
    if semid < 0 || nsops == 0 {
        return IpcFlow::Done(Err(Errno::Invalid));
    }
    if nsops > SEMOPM {
        return IpcFlow::Done(Err(Errno::TooBig));
    }
    if sops_ptr == 0 {
        return IpcFlow::Done(Err(Errno::Fault));
    }

    let was_waiting = wait_state.is_some_and(|w| w.is_sem && w.id == semid);
    // 相对超时只在首次进入时换算为绝对单调截止时刻，重入沿用原截止时刻。
    let deadline: Option<Duration> = if was_waiting {
        wait_state.and_then(|w| w.deadline)
    } else if timeout_ptr != 0 {
        let mut ts = [0u8; 16];
        if user_access::copy_from_user(space, timeout_ptr, &mut ts).is_err() {
            return IpcFlow::Done(Err(Errno::Fault));
        }
        let sec = i64::from_ne_bytes(ts[0..8].try_into().unwrap_or([0; 8]));
        let nsec = i64::from_ne_bytes(ts[8..16].try_into().unwrap_or([0; 8]));
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return IpcFlow::Done(Err(Errno::Invalid));
        }
        let Some(d) = crate::time::monotonic().checked_add(Duration::new(sec as u64, nsec as u32))
        else {
            return IpcFlow::Done(Err(Errno::Invalid));
        };
        Some(d)
    } else {
        None
    };

    let bytes_len = match nsops.checked_mul(SEMBUF_SIZE) {
        Some(n) => n,
        None => return IpcFlow::Done(Err(Errno::Fault)),
    };
    let mut raw_ops = Vec::new();
    if raw_ops.try_reserve_exact(bytes_len).is_err() {
        return IpcFlow::Done(Err(Errno::NoMem));
    }
    raw_ops.resize(bytes_len, 0);
    if user_access::copy_from_user(space, sops_ptr, &mut raw_ops).is_err() {
        return IpcFlow::Done(Err(Errno::Fault));
    }
    let mut ops = Vec::new();
    if ops.try_reserve_exact(nsops).is_err() {
        return IpcFlow::Done(Err(Errno::NoMem));
    }
    let mut alter = false;
    let mut has_undo = false;
    for chunk in raw_ops.chunks_exact(SEMBUF_SIZE) {
        let sem_num = u16::from_ne_bytes([chunk[0], chunk[1]]);
        let sem_op = i16::from_ne_bytes([chunk[2], chunk[3]]);
        let sem_flg = i16::from_ne_bytes([chunk[4], chunk[5]]);
        if sem_op != 0 {
            alter = true;
            if sem_flg & SEM_UNDO != 0 {
                has_undo = true;
            }
        }
        ops.push(SemOp {
            sem_num,
            sem_op,
            sem_flg,
        });
    }

    let id = semid as usize;
    let mut table = SEM_TABLE.lock();
    let Some(set) = table.find_by_id_mut(id) else {
        return IpcFlow::Done(Err(if was_waiting {
            Errno::IdRm
        } else {
            Errno::Invalid
        }));
    };
    if let Err(e) = set
        .perm
        .check_access(if alter { IPC_W } else { IPC_R }, creds)
    {
        set.remove_waiter(tid);
        return IpcFlow::Done(Err(e));
    }
    let nsems = set.sems.len();
    for op in &ops {
        if (op.sem_num as usize) >= nsems {
            set.remove_waiter(tid);
            return IpcFlow::Done(Err(Errno::FileTooBig));
        }
    }

    // 原子试算：不修改原值，全部操作满足后再整体提交。
    let mut next_vals = Vec::new();
    if next_vals.try_reserve_exact(nsems).is_err() {
        set.remove_waiter(tid);
        return IpcFlow::Done(Err(Errno::NoMem));
    }
    for s in &set.sems {
        next_vals.push(s.val);
    }
    let mut undo_deltas = Vec::new();
    if has_undo {
        if undo_deltas.try_reserve_exact(nsems).is_err() {
            set.remove_waiter(tid);
            return IpcFlow::Done(Err(Errno::NoMem));
        }
        undo_deltas.resize(nsems, 0i32);
    }

    let mut blocked: Option<(u16, bool)> = None;
    for op in &ops {
        let idx = op.sem_num as usize;
        let delta = op.sem_op as i32;
        if delta > 0 {
            let v = next_vals[idx] + delta;
            if v > SEMVMX {
                set.remove_waiter(tid);
                return IpcFlow::Done(Err(Errno::Range));
            }
            next_vals[idx] = v;
        } else if delta < 0 {
            let need = -delta;
            if next_vals[idx] < need {
                if op.sem_flg & (IPC_NOWAIT as i16) != 0 {
                    set.remove_waiter(tid);
                    return IpcFlow::Done(Err(Errno::Again));
                }
                blocked = Some((op.sem_num, false));
                break;
            }
            next_vals[idx] -= need;
        } else if next_vals[idx] != 0 {
            if op.sem_flg & (IPC_NOWAIT as i16) != 0 {
                set.remove_waiter(tid);
                return IpcFlow::Done(Err(Errno::Again));
            }
            blocked = Some((op.sem_num, true));
            break;
        }
        if has_undo && op.sem_flg & SEM_UNDO != 0 && delta != 0 {
            undo_deltas[idx] = undo_deltas[idx].saturating_sub(delta);
        }
    }

    if let Some((sem_num, zero)) = blocked {
        if let Some(d) = deadline {
            if crate::time::monotonic() >= d {
                set.remove_waiter(tid);
                return IpcFlow::Done(Err(Errno::Again));
            }
        }
        set.set_waiter(tid, tgid, sem_num, zero);
        return IpcFlow::Wait {
            key: sem_wake_key(id),
            deadline,
            state: IpcWaitState {
                id: semid,
                deadline,
                is_sem: true,
            },
        };
    }

    // 校验并准备 SEM_UNDO 记录（失败则整体不生效）。
    if has_undo {
        let existing = set.undos.iter().position(|u| u.tgid == tgid);
        for (i, &d) in undo_deltas.iter().enumerate() {
            if d == 0 {
                continue;
            }
            let cur = existing
                .and_then(|pos| set.undos[pos].adj.get(i).copied())
                .unwrap_or(0) as i32;
            let next = cur + d;
            if !(-SEMAEM..=SEMAEM).contains(&next) {
                set.remove_waiter(tid);
                return IpcFlow::Done(Err(Errno::Range));
            }
        }
        if existing.is_none() {
            if set.undos.try_reserve(1).is_err() {
                set.remove_waiter(tid);
                return IpcFlow::Done(Err(Errno::NoMem));
            }
            let mut adj = Vec::new();
            if adj.try_reserve_exact(nsems).is_err() {
                set.remove_waiter(tid);
                return IpcFlow::Done(Err(Errno::NoMem));
            }
            adj.resize(nsems, 0i16);
            set.undos.push(SemUndo { tgid, adj });
        }
        if let Some(u) = set.undos.iter_mut().find(|u| u.tgid == tgid) {
            for (i, &d) in undo_deltas.iter().enumerate() {
                if d != 0 && i < u.adj.len() {
                    u.adj[i] = (u.adj[i] as i32 + d) as i16;
                }
            }
        }
    }

    // 原子提交。
    for op in &ops {
        let idx = op.sem_num as usize;
        set.sems[idx].val = next_vals[idx];
        set.sems[idx].pid = tgid as i32;
    }
    set.otime = now_secs();
    set.remove_waiter(tid);
    drop(table);
    if alter {
        sched::request_ipc_wake(sem_wake_key(id));
    }
    IpcFlow::Done(Ok(0))
}
