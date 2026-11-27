//! System V 消息队列：msgget(186)、msgctl(187)、msgrcv(188)、msgsnd(189)。
//! 叶子锁 MSG_TABLE，不嵌套 REGISTRY/FRAME/SCHED；阻塞通过定向 IPC 唤醒键协作。
#![deny(unsafe_code)]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::{
    mm::{address_space::UserAddressSpace, user_access},
    sync::DebugMutex,
    syscall::Errno,
    task::{sched, Credentials},
};

use super::{
    msg_wake_key, normalize_cmd, now_secs, IpcFlow, IpcPerm, IpcWaitState, IPCMNI, IPC_CREAT,
    IPC_EXCL, IPC_INFO, IPC_NOWAIT, IPC_PRIVATE, IPC_R, IPC_RMID, IPC_SEQ_MASK, IPC_SET, IPC_STAT,
    IPC_W,
};

/// 接收标志：消息过长时截断而非返回 E2BIG。
const MSG_NOERROR: i32 = 0o10000;
/// 接收标志：当 msgtyp > 0 时接收第一条类型不等于 msgtyp 的消息。
const MSG_EXCEPT: i32 = 0o20000;
/// 接收标志：非破坏性复制第 msgtyp 条消息（须与 IPC_NOWAIT 同用）。
const MSG_COPY: i32 = 0o40000;

/// msgctl 扩展命令（剥离 IPC_64 后）。
const MSG_STAT: i32 = 11;
const MSG_INFO: i32 = 12;
const MSG_STAT_ANY: i32 = 13;

/// 单条消息正文最大字节数（Linux 默认 MSGMAX = 8192）。
pub(crate) const MSGMAX: usize = 8192;
/// 单个队列默认字节上限（Linux 默认 MSGMNB = 16384）。
pub(crate) const MSGMNB: usize = 16384;
/// 特权 IPC_SET 允许提升的单队列字节上限（避免恶意超大配置）。
const MSGMNB_HARD_MAX: usize = 1024 * 1024;
/// 系统同时存在的消息队列上限。
pub(crate) const MSGMNI: usize = 128;
/// 消息段大小常量（供 msginfo 报告）。
const MSGSSZ: i32 = 16;

/// asm-generic 64 位 `struct msqid64_ds` 字节长度。
const MSQID_DS_SIZE: usize = 120;
/// `struct msginfo` 字节长度。
const MSGINFO_SIZE: usize = 32;

struct Message {
    mtype: i64,
    data: Vec<u8>,
}

struct MsgQueue {
    id: usize,
    perm: IpcPerm,
    stime: i64,
    rtime: i64,
    ctime: i64,
    cbytes: usize,
    qbytes: usize,
    lspid: i32,
    lrpid: i32,
    messages: VecDeque<Message>,
}

impl MsgQueue {
    fn encode_ds(&self) -> [u8; MSQID_DS_SIZE] {
        let mut out = [0u8; MSQID_DS_SIZE];
        self.perm.encode(&mut out[0..48]);
        out[48..56].copy_from_slice(&self.stime.to_ne_bytes());
        out[56..64].copy_from_slice(&self.rtime.to_ne_bytes());
        out[64..72].copy_from_slice(&self.ctime.to_ne_bytes());
        out[72..80].copy_from_slice(&(self.cbytes as u64).to_ne_bytes());
        out[80..88].copy_from_slice(&(self.messages.len() as u64).to_ne_bytes());
        out[88..96].copy_from_slice(&(self.qbytes as u64).to_ne_bytes());
        out[96..100].copy_from_slice(&self.lspid.to_ne_bytes());
        out[100..104].copy_from_slice(&self.lrpid.to_ne_bytes());
        out
    }

    fn has_space(&self, msgsz: usize) -> bool {
        // 与 Linux ipc/msg.c 一致：0 字节消息也要求 qnum + 1 <= qbytes。
        msgsz.saturating_add(self.cbytes) <= self.qbytes
            && self.messages.len().saturating_add(1) <= self.qbytes
    }

    fn find_match(&self, msgtyp: i64, msgflg: i32) -> Option<usize> {
        if msgflg & MSG_COPY != 0 {
            if msgtyp < 0 {
                return None;
            }
            let idx = msgtyp as usize;
            return (idx < self.messages.len()).then_some(idx);
        }
        if msgtyp == 0 {
            return (!self.messages.is_empty()).then_some(0);
        }
        if msgtyp > 0 {
            let except = msgflg & MSG_EXCEPT != 0;
            return self.messages.iter().position(|m| {
                if except {
                    m.mtype != msgtyp
                } else {
                    m.mtype == msgtyp
                }
            });
        }
        // msgtyp < 0：找类型 <= |msgtyp| 的最小类型消息（同类型取最早入队者）。
        let limit = msgtyp.unsigned_abs();
        let mut best: Option<(usize, u64)> = None;
        for (i, m) in self.messages.iter().enumerate() {
            if m.mtype > 0 {
                let t = m.mtype as u64;
                if t <= limit && best.is_none_or(|(_, bt)| t < bt) {
                    best = Some((i, t));
                }
            }
        }
        best.map(|(i, _)| i)
    }
}

struct MsgTable {
    next_idx: usize,
    next_seq: u16,
    slots: Vec<Option<MsgQueue>>,
}

impl MsgTable {
    const fn new() -> Self {
        Self {
            next_idx: 0,
            next_seq: 0,
            slots: Vec::new(),
        }
    }

    fn find_by_key(&self, key: i32) -> Option<&MsgQueue> {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|q| q.perm.key == key)
    }

    fn find_by_id(&self, id: usize) -> Option<&MsgQueue> {
        let idx = id % IPCMNI;
        self.slots
            .get(idx)
            .and_then(|s| s.as_ref())
            .filter(|q| q.id == id)
    }

    fn find_by_id_mut(&mut self, id: usize) -> Option<&mut MsgQueue> {
        let idx = id % IPCMNI;
        self.slots
            .get_mut(idx)
            .and_then(|s| s.as_mut())
            .filter(|q| q.id == id)
    }

    fn max_used_index(&self) -> usize {
        self.slots.iter().rposition(|s| s.is_some()).unwrap_or(0)
    }

    fn stats(&self) -> (usize, usize, usize) {
        let mut queues = 0usize;
        let mut msgs = 0usize;
        let mut bytes = 0usize;
        for q in self.slots.iter().filter_map(|s| s.as_ref()) {
            queues += 1;
            msgs = msgs.saturating_add(q.messages.len());
            bytes = bytes.saturating_add(q.cbytes);
        }
        (queues, msgs, bytes)
    }
}

/// 全局消息队列状态表；纯叶子锁，绝不在持锁期间访问用户页表或调度器锁。
static MSG_TABLE: DebugMutex<MsgTable> = DebugMutex::new("MSG_TABLE", MsgTable::new());

/// /proc/sysvipc/msg 只读快照：按 Linux proc(5) 14 列格式输出所有活动消息队列。
pub fn proc_sysvipc() -> Result<alloc::string::String, Errno> {
    use core::fmt::Write;
    let table = MSG_TABLE.lock();
    let mut out = alloc::string::String::new();
    let header = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n";
    let count = table.slots.iter().filter(|s| s.is_some()).count();
    out.try_reserve(header.len() + count * 128)
        .map_err(|_| Errno::NoMem)?;
    out.push_str(header);
    for q in table.slots.iter().filter_map(|s| s.as_ref()) {
        let _ = writeln!(
            out,
            "{:10} {:10}  {:4o}  {:10} {:10} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}",
            q.perm.key,
            q.id,
            q.perm.mode,
            q.cbytes,
            q.messages.len(),
            q.lspid,
            q.lrpid,
            q.perm.uid,
            q.perm.gid,
            q.perm.cuid,
            q.perm.cgid,
            q.stime,
            q.rtime,
            q.ctime
        );
    }
    Ok(out)
}

/// msgget(2)：按 key 查找或新建消息队列，返回非负 msqid。
pub fn get(key: i32, msgflg: i32, creds: &Credentials) -> Result<usize, Errno> {
    let mut table = MSG_TABLE.lock();
    if key != IPC_PRIVATE {
        if let Some(q) = table.find_by_key(key) {
            if msgflg & (IPC_CREAT | IPC_EXCL) == (IPC_CREAT | IPC_EXCL) {
                return Err(Errno::Exists);
            }
            q.perm.check_access(msgflg & 0o777, creds)?;
            return Ok(q.id);
        }
        if msgflg & IPC_CREAT == 0 {
            return Err(Errno::NoEntry);
        }
    }

    let mut wrapped = false;
    let mut found = None;
    for i in table.next_idx..MSGMNI {
        if i >= table.slots.len() || table.slots[i].is_none() {
            found = Some(i);
            break;
        }
    }
    if found.is_none() {
        wrapped = true;
        for i in 0..table.next_idx.min(MSGMNI) {
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
    if wrapped {
        table.next_seq = table.next_seq.wrapping_add(1) & IPC_SEQ_MASK;
    }
    let seq = table.next_seq;
    table.next_idx = slot_idx + 1;
    let id = (seq as usize) * IPCMNI + slot_idx;
    let perm = IpcPerm::new(key, msgflg, seq, creds);

    table.slots[slot_idx] = Some(MsgQueue {
        id,
        perm,
        stime: 0,
        rtime: 0,
        ctime: now_secs(),
        cbytes: 0,
        qbytes: MSGMNB,
        lspid: 0,
        lrpid: 0,
        messages: VecDeque::new(),
    });
    Ok(id)
}

/// msgsnd(2)：向消息队列发送一条消息；队列满时阻塞或按 IPC_NOWAIT 返回 EAGAIN。
#[allow(clippy::too_many_arguments)]
pub fn snd(
    space: &UserAddressSpace,
    msqid: i32,
    msgp: usize,
    msgsz: usize,
    msgflg: i32,
    tgid: usize,
    creds: &Credentials,
    wait_state: Option<IpcWaitState>,
) -> IpcFlow {
    if msqid < 0 || (msgsz as isize) < 0 || msgsz > MSGMAX {
        return IpcFlow::Done(Err(Errno::Invalid));
    }
    if msgp == 0 {
        return IpcFlow::Done(Err(Errno::Fault));
    }
    let mut mtype_raw = [0u8; 8];
    if user_access::copy_from_user(space, msgp, &mut mtype_raw).is_err() {
        return IpcFlow::Done(Err(Errno::Fault));
    }
    let mtype = i64::from_ne_bytes(mtype_raw);
    if mtype < 1 {
        return IpcFlow::Done(Err(Errno::Invalid));
    }
    let payload_ptr = match msgp.checked_add(8) {
        Some(p) => p,
        None => return IpcFlow::Done(Err(Errno::Fault)),
    };
    let mut data = Vec::new();
    if msgsz > 0 {
        if data.try_reserve_exact(msgsz).is_err() {
            return IpcFlow::Done(Err(Errno::NoMem));
        }
        data.resize(msgsz, 0);
        if user_access::copy_from_user(space, payload_ptr, &mut data).is_err() {
            return IpcFlow::Done(Err(Errno::Fault));
        }
    }

    let id = msqid as usize;
    let was_waiting = wait_state.is_some_and(|w| !w.is_sem && w.id == msqid);
    let mut table = MSG_TABLE.lock();
    let Some(q) = table.find_by_id_mut(id) else {
        return IpcFlow::Done(Err(if was_waiting {
            Errno::IdRm
        } else {
            Errno::Invalid
        }));
    };
    if let Err(e) = q.perm.check_access(IPC_W, creds) {
        return IpcFlow::Done(Err(e));
    }
    if !q.has_space(msgsz) {
        if msgflg & IPC_NOWAIT != 0 {
            return IpcFlow::Done(Err(Errno::Again));
        }
        return IpcFlow::Wait {
            key: msg_wake_key(id),
            deadline: None,
            state: IpcWaitState {
                id: msqid,
                deadline: None,
                is_sem: false,
            },
        };
    }
    if q.messages.try_reserve(1).is_err() {
        return IpcFlow::Done(Err(Errno::NoMem));
    }
    q.messages.push_back(Message { mtype, data });
    q.cbytes = q.cbytes.saturating_add(msgsz);
    q.stime = now_secs();
    q.lspid = tgid as i32;
    drop(table);
    sched::request_ipc_wake(msg_wake_key(id));
    IpcFlow::Done(Ok(0))
}

/// msgrcv(2)：从消息队列接收匹配消息；无匹配消息时阻塞或按 IPC_NOWAIT 返回 ENOMSG。
#[allow(clippy::too_many_arguments)]
pub fn rcv(
    space: &UserAddressSpace,
    msqid: i32,
    msgp: usize,
    msgsz: usize,
    msgtyp: i64,
    msgflg: i32,
    tgid: usize,
    creds: &Credentials,
    wait_state: Option<IpcWaitState>,
) -> IpcFlow {
    if msqid < 0 || (msgsz as isize) < 0 {
        return IpcFlow::Done(Err(Errno::Invalid));
    }
    if msgflg & MSG_COPY != 0 && (msgflg & IPC_NOWAIT == 0 || msgflg & MSG_EXCEPT != 0) {
        return IpcFlow::Done(Err(Errno::Invalid));
    }

    let id = msqid as usize;
    let was_waiting = wait_state.is_some_and(|w| !w.is_sem && w.id == msqid);
    // 第一阶段：在 MSG_TABLE 锁内查找匹配消息并克隆待交付内容，释放锁后再写用户缓冲，
    // 保证 MSG_TABLE 为叶子锁且 EFAULT 不丢消息。
    let staged = {
        let table = MSG_TABLE.lock();
        let Some(q) = table.find_by_id(id) else {
            return IpcFlow::Done(Err(if was_waiting {
                Errno::IdRm
            } else {
                Errno::Invalid
            }));
        };
        if let Err(e) = q.perm.check_access(IPC_R, creds) {
            return IpcFlow::Done(Err(e));
        }
        let Some(idx) = q.find_match(msgtyp, msgflg) else {
            if msgflg & IPC_NOWAIT != 0 {
                return IpcFlow::Done(Err(Errno::NoMsg));
            }
            return IpcFlow::Wait {
                key: msg_wake_key(id),
                deadline: None,
                state: IpcWaitState {
                    id: msqid,
                    deadline: None,
                    is_sem: false,
                },
            };
        };
        let msg = &q.messages[idx];
        if msg.data.len() > msgsz && msgflg & MSG_NOERROR == 0 {
            return IpcFlow::Done(Err(Errno::TooBig));
        }
        let copy_len = msg.data.len().min(msgsz);
        let mut copy_buf = Vec::new();
        if copy_len > 0 {
            if copy_buf.try_reserve_exact(copy_len).is_err() {
                return IpcFlow::Done(Err(Errno::NoMem));
            }
            copy_buf.extend_from_slice(&msg.data[..copy_len]);
        }
        (idx, msg.mtype, copy_buf)
    };

    // 第二阶段：写回用户缓冲区；失败直接返回 EFAULT，队列不受影响。
    let (idx, mtype, copy_buf) = staged;
    let payload_ptr = match msgp.checked_add(8) {
        Some(p) if msgp != 0 => p,
        _ => return IpcFlow::Done(Err(Errno::Fault)),
    };
    if user_access::copy_to_user(space, msgp, &mtype.to_ne_bytes()).is_err() {
        return IpcFlow::Done(Err(Errno::Fault));
    }
    if !copy_buf.is_empty() && user_access::copy_to_user(space, payload_ptr, &copy_buf).is_err() {
        return IpcFlow::Done(Err(Errno::Fault));
    }

    // 第三阶段：非 MSG_COPY 时从队列移除该消息并唤醒可能阻塞的发送者。
    if msgflg & MSG_COPY == 0 {
        let mut table = MSG_TABLE.lock();
        if let Some(q) = table.find_by_id_mut(id) {
            if let Some(removed) = q.messages.remove(idx) {
                q.cbytes = q.cbytes.saturating_sub(removed.data.len());
                q.rtime = now_secs();
                q.lrpid = tgid as i32;
            }
        }
        drop(table);
        sched::request_ipc_wake(msg_wake_key(id));
    }
    IpcFlow::Done(Ok(copy_buf.len()))
}

/// msgctl(2)：IPC_STAT/IPC_SET/IPC_RMID/IPC_INFO/MSG_INFO/MSG_STAT/MSG_STAT_ANY。
pub fn ctl(
    space: &UserAddressSpace,
    msqid: i32,
    raw_cmd: i32,
    buf: usize,
    creds: &Credentials,
) -> Result<usize, Errno> {
    let cmd = normalize_cmd(raw_cmd);
    match cmd {
        IPC_INFO | MSG_INFO => {
            if buf == 0 {
                return Err(Errno::Fault);
            }
            let (raw, max_idx) = {
                let table = MSG_TABLE.lock();
                let (queues, msgs, bytes) = table.stats();
                let mut info = [0u8; MSGINFO_SIZE];
                let (msgpool, msgmap, msgtql) = if cmd == MSG_INFO {
                    (
                        queues.min(i32::MAX as usize) as i32,
                        msgs.min(i32::MAX as usize) as i32,
                        bytes.min(i32::MAX as usize) as i32,
                    )
                } else {
                    (
                        ((MSGMNI * MSGMNB) / 1024) as i32,
                        MSGMNB as i32,
                        MSGMNB as i32,
                    )
                };
                info[0..4].copy_from_slice(&msgpool.to_ne_bytes());
                info[4..8].copy_from_slice(&msgmap.to_ne_bytes());
                info[8..12].copy_from_slice(&(MSGMAX as i32).to_ne_bytes());
                info[12..16].copy_from_slice(&(MSGMNB as i32).to_ne_bytes());
                info[16..20].copy_from_slice(&(MSGMNI as i32).to_ne_bytes());
                info[20..24].copy_from_slice(&MSGSSZ.to_ne_bytes());
                info[24..28].copy_from_slice(&msgtql.to_ne_bytes());
                info[28..30].copy_from_slice(&0xffffu16.to_ne_bytes());
                (info, table.max_used_index())
            };
            user_access::copy_to_user(space, buf, &raw).map_err(|_| Errno::Fault)?;
            Ok(max_idx)
        }
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            if buf == 0 {
                return Err(Errno::Fault);
            }
            if msqid < 0 {
                return Err(Errno::Invalid);
            }
            let (raw, ret_val) = {
                let table = MSG_TABLE.lock();
                let q = if cmd == IPC_STAT {
                    table.find_by_id(msqid as usize).ok_or(Errno::Invalid)?
                } else {
                    table
                        .slots
                        .get(msqid as usize)
                        .and_then(|s| s.as_ref())
                        .ok_or(Errno::Invalid)?
                };
                if cmd != MSG_STAT_ANY {
                    q.perm.check_access(IPC_R, creds)?;
                }
                (q.encode_ds(), if cmd == IPC_STAT { 0 } else { q.id })
            };
            user_access::copy_to_user(space, buf, &raw).map_err(|_| Errno::Fault)?;
            Ok(ret_val)
        }
        IPC_SET => {
            if msqid < 0 {
                return Err(Errno::Invalid);
            }
            if buf == 0 {
                return Err(Errno::Fault);
            }
            let mut raw = [0u8; MSQID_DS_SIZE];
            user_access::copy_from_user(space, buf, &mut raw).map_err(|_| Errno::Fault)?;
            let (uid, gid, mode) = IpcPerm::decode_set(&raw[0..48]);
            let new_qbytes = u64::from_ne_bytes(raw[88..96].try_into().unwrap_or([0; 8])) as usize;
            let mut wake = false;
            {
                let mut table = MSG_TABLE.lock();
                let q = table.find_by_id_mut(msqid as usize).ok_or(Errno::Invalid)?;
                q.perm.check_owner(creds)?;
                if new_qbytes > MSGMNB && creds.euid != 0 {
                    return Err(Errno::Perm);
                }
                let clamped = new_qbytes.min(MSGMNB_HARD_MAX);
                if clamped > q.qbytes {
                    wake = true;
                }
                q.perm.uid = uid;
                q.perm.gid = gid;
                q.perm.mode = mode;
                q.qbytes = clamped;
                q.ctime = now_secs();
            }
            if wake {
                sched::request_ipc_wake(msg_wake_key(msqid as usize));
            }
            Ok(0)
        }
        IPC_RMID => {
            if msqid < 0 {
                return Err(Errno::Invalid);
            }
            let id = msqid as usize;
            let idx = id % IPCMNI;
            {
                let mut table = MSG_TABLE.lock();
                let q = table
                    .slots
                    .get(idx)
                    .and_then(|s| s.as_ref())
                    .filter(|q| q.id == id)
                    .ok_or(Errno::Invalid)?;
                q.perm.check_owner(creds)?;
                table.slots[idx] = None;
            }
            sched::request_ipc_wake(msg_wake_key(id));
            Ok(0)
        }
        _ => Err(Errno::Invalid),
    }
}
