//! POSIX 消息队列（mq_open / mq_unlink / mq_timedsend / mq_timedreceive /
//! mq_notify / mq_getsetattr）。
//! 遵循 Linux man 2 与 asm-generic 64 位 UAPI；锁序位于 REGISTRY 之下，绝不反向取锁。
#![deny(unsafe_code)]

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use spin::Mutex;

use crate::{
    mm::{address_space::UserAddressSpace, user_access},
    sync::DebugMutex,
    syscall::Errno,
    task::{
        sched,
        signal::{SigInfoSlot, SI_MESGQ},
        Credentials, Pid, CAP_SYS_RESOURCE,
    },
};

use super::{IpcFlow, IpcWaitState};

/// POSIX 消息队列系统默认上限（对齐 Linux /proc/sys/fs/mqueue/* 默认值）。
const DFLT_QUEUESMAX: usize = 256;
const DFLT_MSGMAX: usize = 10;
const DFLT_MSGSIZEMAX: usize = 8192;
/// 特权进程可设置的硬上限（受 32 MiB 固定内核堆约束，消息体上限取 1 MiB）。
const HARD_MSGMAX: usize = 65536;
const HARD_MSGSIZEMAX: usize = 1024 * 1024;
/// Linux MQ_PRIO_MAX（合法优先级 0..32768）。
const MQ_PRIO_MAX: u32 = 32768;

/// /proc/sys/fs/mqueue/* 运行期可调参数。
static SYSCTL_QUEUES_MAX: AtomicUsize = AtomicUsize::new(DFLT_QUEUESMAX);
static SYSCTL_MSG_MAX: AtomicUsize = AtomicUsize::new(DFLT_MSGMAX);
static SYSCTL_MSGSIZE_MAX: AtomicUsize = AtomicUsize::new(DFLT_MSGSIZEMAX);

/// /proc/sys/fs/mqueue/* 参数项枚举。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MqSysctl {
    QueuesMax,
    MsgMax,
    MsgSizeMax,
}

/// 读取 /proc/sys/fs/mqueue/* 当前值。
pub(crate) fn read_sysctl(field: MqSysctl) -> usize {
    match field {
        MqSysctl::QueuesMax => SYSCTL_QUEUES_MAX.load(Ordering::Relaxed),
        MqSysctl::MsgMax => SYSCTL_MSG_MAX.load(Ordering::Relaxed),
        MqSysctl::MsgSizeMax => SYSCTL_MSGSIZE_MAX.load(Ordering::Relaxed),
    }
}

/// 更新 /proc/sys/fs/mqueue/* 参数值（按 Linux 边界校验，非法输入返回 EINVAL）。
pub(crate) fn write_sysctl(field: MqSysctl, val: usize) -> Result<(), Errno> {
    match field {
        MqSysctl::QueuesMax => {
            if val > HARD_MSGMAX {
                return Err(Errno::Invalid);
            }
            SYSCTL_QUEUES_MAX.store(val, Ordering::Relaxed);
        }
        MqSysctl::MsgMax => {
            if !(1..=HARD_MSGMAX).contains(&val) {
                return Err(Errno::Invalid);
            }
            SYSCTL_MSG_MAX.store(val, Ordering::Relaxed);
        }
        MqSysctl::MsgSizeMax => {
            if !(128..=HARD_MSGSIZEMAX).contains(&val) {
                return Err(Errno::Invalid);
            }
            SYSCTL_MSGSIZE_MAX.store(val, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Linux mqueue SIGEV_THREAD 通知字节（cookie[31]）。
pub(crate) const NOTIFY_WOKENUP: u8 = 1;
const NOTIFY_REMOVED: u8 = 2;

const O_ACCMODE: i32 = 3;
const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_CREAT: i32 = 0x40;
const O_EXCL: i32 = 0x80;
const O_NONBLOCK: i32 = 0x800;

const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const SIGEV_THREAD: i32 = 2;

/// POSIX 消息队列 IPC 唤醒键起始偏移（与 System V msg/sem 键空间隔离）。
static NEXT_MQ_WAKE_KEY: AtomicU64 = AtomicU64::new(0x4000_0000_0000_0001);

/// 单条排队消息（按 prio 降序，同优先级 FIFO）。
struct MqMessage {
    prio: u32,
    data: Vec<u8>,
}

/// mq_notify 登记内容（单次触发后自动清除）。
#[derive(Clone, Debug)]
pub(crate) enum MqNotifyKind {
    None,
    Signal {
        sig: u8,
        sigval: u64,
    },
    Thread {
        sock_id: crate::net::SocketId,
        cookie: [u8; 32],
    },
}

/// 已触发、待由调用方在 REGISTRY 锁下投递的异步通知。
pub(crate) struct PendingNotify {
    pub target_tgid: Pid,
    pub sender_tgid: Pid,
    pub kind: MqNotifyKind,
}

#[derive(Clone, Debug)]
struct MqNotify {
    owner_tgid: Pid,
    kind: MqNotifyKind,
}

/// POSIX 消息队列内核对象（由全局名称表与已打开 FD 共同持有 Arc）。
pub struct PosixMQueue {
    name: String,
    unlinked: bool,
    uid: u32,
    gid: u32,
    mode: u32,
    maxmsg: usize,
    msgsize: usize,
    wake_key: u64,
    poll_id: u64,
    event_gen: u64,
    messages: Vec<MqMessage>,
    wait_receivers: Vec<Pid>,
    notify: Option<MqNotify>,
}

impl PosixMQueue {
    /// poll/epoll 就绪事件计算：非空可读，未满可写。
    pub fn poll_events(&self, requested: u16) -> u16 {
        let mut ev = 0u16;
        if !self.messages.is_empty() {
            ev |= 0x41 & requested; // POLLIN | POLLRDNORM
        }
        if self.messages.len() < self.maxmsg {
            ev |= 0x104 & requested; // POLLOUT | POLLWRNORM
        }
        ev
    }

    /// 边沿触发版本号。
    pub fn event_gen(&self) -> u64 {
        self.event_gen
    }

    /// 供 fstat 返回的权限位与当前字节数。
    pub fn stat_info(&self) -> (u16, u64) {
        let bytes: u64 = self.messages.iter().map(|m| m.data.len() as u64).sum();
        ((0o100000 | (self.mode & 0o777)) as u16, bytes)
    }

    /// 检查给定进程凭证是否满足指定读写访问模式。
    fn check_access(&self, accmode: i32, creds: &Credentials) -> Result<(), Errno> {
        if creds.euid == 0 {
            return Ok(());
        }
        let need_r = accmode == O_RDONLY || accmode == 2;
        let need_w = accmode == O_WRONLY || accmode == 2;
        let bits = if creds.euid == self.uid {
            (self.mode >> 6) & 0o7
        } else if creds.egid == self.gid || creds.groups.contains(&self.gid) {
            (self.mode >> 3) & 0o7
        } else {
            self.mode & 0o7
        };
        if (need_r && bits & 0o4 == 0) || (need_w && bits & 0o2 == 0) {
            Err(Errno::Access)
        } else {
            Ok(())
        }
    }

    /// 若本队列的 notify 归属指定线程组，则撤销登记；SIGEV_THREAD 通知发送 NOTIFY_REMOVED。
    pub fn clear_notify_for(&mut self, tgid: Pid) {
        if self.notify.as_ref().is_some_and(|n| n.owner_tgid == tgid) {
            if let Some(MqNotify {
                kind:
                    MqNotifyKind::Thread {
                        sock_id,
                        mut cookie,
                    },
                ..
            }) = self.notify.take()
            {
                cookie[31] = NOTIFY_REMOVED;
                let _ = crate::net::enqueue_netlink(sock_id, &cookie);
            }
        }
    }

    /// 移除已中断或退出的接收等待者。
    fn remove_receiver(&mut self, tid: Pid) {
        if let Some(pos) = self.wait_receivers.iter().position(|&p| p == tid) {
            self.wait_receivers.swap_remove(pos);
        }
    }
}

/// 全局已命名 POSIX 消息队列注册表（锁序：REGISTRY → MQUEUES → 单队列 Mutex）。
static MQUEUES: DebugMutex<Vec<Arc<Mutex<PosixMQueue>>>> = DebugMutex::new("MQUEUES", Vec::new());

/// 校验 Linux 内核 mq_open/mq_unlink 名称（与 getname + lookup_one_len 一致）。
fn validate_name(name: &str) -> Result<(), Errno> {
    if name.is_empty() {
        return Err(Errno::NoEntry);
    }
    if name.len() > 255 {
        return Err(Errno::NameTooLong);
    }
    if name.contains('/') || name == "." || name == ".." {
        return Err(Errno::Access);
    }
    Ok(())
}

/// 读取用户态 64 字节 struct mq_attr 的 (mq_flags, mq_maxmsg, mq_msgsize)。
fn read_mq_attr(space: &UserAddressSpace, ptr: usize) -> Result<(i64, i64, i64), Errno> {
    let mut raw = [0u8; 64];
    user_access::copy_from_user(space, ptr, &mut raw).map_err(|_| Errno::Fault)?;
    let flags = i64::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let maxmsg = i64::from_ne_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    let msgsize = i64::from_ne_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
    Ok((flags, maxmsg, msgsize))
}

/// 写入用户态 64 字节 struct mq_attr。
fn write_mq_attr(
    space: &UserAddressSpace,
    ptr: usize,
    flags: i64,
    maxmsg: usize,
    msgsize: usize,
    curmsgs: usize,
) -> Result<(), Errno> {
    let mut raw = [0u8; 64];
    raw[0..8].copy_from_slice(&flags.to_ne_bytes());
    raw[8..16].copy_from_slice(&(maxmsg as i64).to_ne_bytes());
    raw[16..24].copy_from_slice(&(msgsize as i64).to_ne_bytes());
    raw[24..32].copy_from_slice(&(curmsgs as i64).to_ne_bytes());
    user_access::copy_to_user(space, ptr, &raw).map_err(|_| Errno::Fault)
}

/// 校验并解析绝对墙钟超时 abs_timeout（NULL 返回 None；非法 timespec 返回 EINVAL）。
fn parse_abs_timeout(space: &UserAddressSpace, ptr: usize) -> Result<Option<Duration>, Errno> {
    if ptr == 0 {
        return Ok(None);
    }
    let mut raw = [0u8; 16];
    user_access::copy_from_user(space, ptr, &mut raw).map_err(|_| Errno::Fault)?;
    let sec = i64::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
    let nsec = i64::from_ne_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::Invalid);
    }
    Ok(Some(Duration::new(sec as u64, nsec as u32)))
}

/// 将绝对墙钟超时换算为单调时钟截止时刻（已过期返回 Err(ETIMEDOUT)）。
fn realtime_to_mono_deadline(abs_rt: Option<Duration>) -> Result<Option<Duration>, Errno> {
    let Some(target) = abs_rt else {
        return Ok(None);
    };
    let now_rt = crate::time::realtime();
    if target <= now_rt {
        return Err(Errno::TimedOut);
    }
    let delta = target.saturating_sub(now_rt);
    Ok(Some(crate::time::monotonic().saturating_add(delta)))
}

/// mq_open(2)：打开或创建 POSIX 消息队列，返回带 FD_CLOEXEC 的描述符。
pub(crate) fn open(
    space: &UserAddressSpace,
    fs: &mut crate::fs::context::Context,
    name_ptr: usize,
    oflag: i32,
    mode: u32,
    attr_ptr: usize,
    creds: &Credentials,
    rlimit_msgqueue: u64,
) -> Result<usize, Errno> {
    let name = user_access::read_cstr(space, name_ptr, 4096).map_err(|e| match e {
        user_access::CStrError::TooLong => Errno::NameTooLong,
        _ => Errno::Fault,
    })?;
    validate_name(&name)?;

    let accmode = oflag & O_ACCMODE;
    if accmode == 3 {
        return Err(Errno::Invalid);
    }
    let creat = oflag & O_CREAT != 0;
    let excl = oflag & O_EXCL != 0;
    let nonblock = oflag & O_NONBLOCK != 0;

    // 读取可选创建属性（仅当 O_CREAT 且 attr_ptr != 0 时校验）。
    let create_attr = if creat && attr_ptr != 0 {
        let (_, maxmsg, msgsize) = read_mq_attr(space, attr_ptr)?;
        if maxmsg <= 0 || msgsize <= 0 {
            return Err(Errno::Invalid);
        }
        let max_msgs = if creds.has_cap(CAP_SYS_RESOURCE) {
            HARD_MSGMAX as i64
        } else {
            SYSCTL_MSG_MAX.load(Ordering::Relaxed) as i64
        };
        let max_size = if creds.has_cap(CAP_SYS_RESOURCE) {
            HARD_MSGSIZEMAX as i64
        } else {
            SYSCTL_MSGSIZE_MAX.load(Ordering::Relaxed) as i64
        };
        if maxmsg > max_msgs || msgsize > max_size {
            return Err(Errno::Invalid);
        }
        Some((maxmsg as usize, msgsize as usize))
    } else {
        None
    };

    let mut created_new = false;
    let queue = {
        let mut table = MQUEUES.lock();
        if let Some(existing) = table.iter().find(|q| {
            let g = q.lock();
            !g.unlinked && g.name == name
        }) {
            if creat && excl {
                return Err(Errno::Exists);
            }
            existing.lock().check_access(accmode, creds)?;
            existing.clone()
        } else {
            if !creat {
                return Err(Errno::NoEntry);
            }
            let queues_max = SYSCTL_QUEUES_MAX.load(Ordering::Relaxed);
            if table.len() >= queues_max {
                return Err(Errno::NoSpace);
            }
            let (maxmsg, msgsize) = create_attr.unwrap_or_else(|| {
                (
                    SYSCTL_MSG_MAX.load(Ordering::Relaxed),
                    SYSCTL_MSGSIZE_MAX.load(Ordering::Relaxed),
                )
            });
            // 校验 RLIMIT_MSGQUEUE（估算队列所需最大字节数，溢出或超限返回 ENOMEM）。
            let est_bytes = (maxmsg as u128).saturating_mul((msgsize as u128).saturating_add(64));
            if !creds.has_cap(CAP_SYS_RESOURCE) && est_bytes > rlimit_msgqueue as u128 {
                return Err(Errno::NoMem);
            }
            let mut owned_name = String::new();
            owned_name
                .try_reserve_exact(name.len())
                .map_err(|_| Errno::NoMem)?;
            owned_name.push_str(&name);
            let wake_key = NEXT_MQ_WAKE_KEY.fetch_add(1, Ordering::Relaxed);
            let poll_id = crate::fs::context::alloc_wake_id();
            let eff_mode = (mode & 0o777) & !(fs.umask() as u32);
            let q = crate::fs::try_arc(Mutex::new(PosixMQueue {
                name: owned_name,
                unlinked: false,
                uid: creds.euid,
                gid: creds.egid,
                mode: eff_mode,
                maxmsg,
                msgsize,
                wake_key,
                poll_id,
                event_gen: 1,
                messages: Vec::new(),
                wait_receivers: Vec::new(),
                notify: None,
            }))?;
            table.try_reserve(1).map_err(|_| Errno::NoMem)?;
            table.push(q.clone());
            created_new = true;
            q
        }
    };

    let file_flags = (accmode as usize) | if nonblock { O_NONBLOCK as usize } else { 0 };
    match fs.open_mqueue(queue.clone(), file_flags) {
        Ok(fd) => Ok(fd),
        Err(e) => {
            if created_new {
                let mut table = MQUEUES.lock();
                if let Some(pos) = table.iter().position(|q| Arc::ptr_eq(q, &queue)) {
                    table.swap_remove(pos);
                }
            }
            Err(e)
        }
    }
}

/// mq_unlink(2)：从全局名称表摘除 POSIX 消息队列；已打开 FD 继续有效。
pub(crate) fn unlink(
    space: &UserAddressSpace,
    name_ptr: usize,
    creds: &Credentials,
) -> Result<usize, Errno> {
    let name = user_access::read_cstr(space, name_ptr, 4096).map_err(|e| match e {
        user_access::CStrError::TooLong => Errno::NameTooLong,
        _ => Errno::Fault,
    })?;
    validate_name(&name)?;

    let mut table = MQUEUES.lock();
    let pos = table
        .iter()
        .position(|q| {
            let g = q.lock();
            !g.unlinked && g.name == name
        })
        .ok_or(Errno::NoEntry)?;
    {
        let g = table[pos].lock();
        if creds.euid != 0 && creds.euid != g.uid {
            return Err(Errno::Access);
        }
    }
    let removed = table.swap_remove(pos);
    removed.lock().unlinked = true;
    Ok(0)
}

/// mq_getsetattr(2)：查询并可选更新队列描述符的非阻塞标志。
pub(crate) fn getsetattr(
    space: &UserAddressSpace,
    fs: &crate::fs::context::Context,
    mqdes: i32,
    newattr_ptr: usize,
    oldattr_ptr: usize,
) -> Result<usize, Errno> {
    if mqdes < 0 {
        return Err(Errno::BadF);
    }
    let new_flags = if newattr_ptr != 0 {
        let (f, _, _) = read_mq_attr(space, newattr_ptr)?;
        Some(f)
    } else {
        None
    };

    let (handle, queue) = fs.mqueue_handle(mqdes as usize)?;
    let mut file = handle.lock();
    let old_flags = if file.status_flags() & (O_NONBLOCK as usize) != 0 {
        O_NONBLOCK as i64
    } else {
        0
    };
    let (maxmsg, msgsize, curmsgs) = {
        let q = queue.lock();
        (q.maxmsg, q.msgsize, q.messages.len())
    };
    if oldattr_ptr != 0 {
        write_mq_attr(space, oldattr_ptr, old_flags, maxmsg, msgsize, curmsgs)?;
    }
    if let Some(nf) = new_flags {
        let cur = file.status_flags();
        let next = if nf & (O_NONBLOCK as i64) != 0 {
            cur | (O_NONBLOCK as usize)
        } else {
            cur & !(O_NONBLOCK as usize)
        };
        file.set_status_flags(next)?;
    }
    Ok(0)
}

/// mq_notify(2)：登记或撤销空队列转非空时的一次性异步通知。
pub(crate) fn notify(
    space: &UserAddressSpace,
    fs: &crate::fs::context::Context,
    mqdes: i32,
    sevp: usize,
    tgid: Pid,
) -> Result<usize, Errno> {
    // 按 Linux do_mq_notify 顺序：先校验 sevp 合法性，再校验 mqdes，
    // 保证非法 sigevent 即使配合非队列 FD 亦返回 EINVAL 而非 EBADF。
    let parsed_kind = if sevp == 0 {
        None
    } else {
        let mut raw = [0u8; 64];
        user_access::copy_from_user(space, sevp, &mut raw).map_err(|_| Errno::Fault)?;
        let sigval = u64::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
        let signo = i32::from_ne_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
        let mode = i32::from_ne_bytes(raw[12..16].try_into().unwrap_or([0; 4]));

        let kind = match mode {
            SIGEV_NONE => MqNotifyKind::None,
            SIGEV_SIGNAL => {
                if !(1..=64).contains(&signo) {
                    return Err(Errno::Invalid);
                }
                MqNotifyKind::Signal {
                    sig: signo as u8,
                    sigval,
                }
            }
            SIGEV_THREAD => {
                if signo < 0 {
                    return Err(Errno::BadF);
                }
                let (sock_id, _) = fs.socket_id(signo as usize).map_err(|_| Errno::BadF)?;
                if !crate::net::is_netlink(sock_id) {
                    return Err(Errno::BadF);
                }
                let mut cookie = [0u8; 32];
                user_access::copy_from_user(space, sigval as usize, &mut cookie)
                    .map_err(|_| Errno::Fault)?;
                MqNotifyKind::Thread { sock_id, cookie }
            }
            _ => return Err(Errno::Invalid),
        };
        Some(kind)
    };

    if mqdes < 0 {
        return Err(Errno::BadF);
    }
    let (_, queue) = fs.mqueue_handle(mqdes as usize)?;
    let Some(kind) = parsed_kind else {
        queue.lock().clear_notify_for(tgid);
        return Ok(0);
    };

    let mut q = queue.lock();
    if q.notify.is_some() {
        return Err(Errno::Busy);
    }
    q.notify = Some(MqNotify {
        owner_tgid: tgid,
        kind,
    });
    Ok(0)
}

/// mq_timedsend(2) 执行结果：除 IpcFlow 外附带可能触发的异步通知。
pub(crate) enum SendOutcome {
    Flow(IpcFlow),
    Sent(Option<PendingNotify>),
}

/// mq_timedsend(2)：按优先级入队消息，满时非阻塞报 EAGAIN，阻塞支持 abs_timeout。
#[allow(clippy::too_many_arguments)]
pub(crate) fn timedsend(
    space: &UserAddressSpace,
    fs: &crate::fs::context::Context,
    mqdes: i32,
    msg_ptr: usize,
    msg_len: usize,
    msg_prio: u32,
    abs_timeout_ptr: usize,
    sender_tgid: Pid,
    cur_wait: Option<IpcWaitState>,
) -> SendOutcome {
    if mqdes < 0 {
        return SendOutcome::Flow(IpcFlow::Done(Err(Errno::BadF)));
    }
    if msg_prio >= MQ_PRIO_MAX {
        return SendOutcome::Flow(IpcFlow::Done(Err(Errno::Invalid)));
    }
    let abs_rt = match parse_abs_timeout(space, abs_timeout_ptr) {
        Ok(t) => t,
        Err(e) => return SendOutcome::Flow(IpcFlow::Done(Err(e))),
    };
    let (handle, queue) = match fs.mqueue_handle(mqdes as usize) {
        Ok(pair) => pair,
        Err(e) => return SendOutcome::Flow(IpcFlow::Done(Err(e))),
    };
    let (writable, nonblock) = {
        let f = handle.lock();
        let flags = f.status_flags();
        ((flags & 3) != 0, (flags & (O_NONBLOCK as usize)) != 0)
    };
    if !writable {
        return SendOutcome::Flow(IpcFlow::Done(Err(Errno::BadF)));
    }

    let (msgsize, full, wake_key) = {
        let q = queue.lock();
        (q.msgsize, q.messages.len() >= q.maxmsg, q.wake_key)
    };
    if msg_len > msgsize {
        return SendOutcome::Flow(IpcFlow::Done(Err(Errno::MsgSize)));
    }
    if full {
        if nonblock {
            return SendOutcome::Flow(IpcFlow::Done(Err(Errno::Again)));
        }
        let mono_dl = match cur_wait.and_then(|w| w.deadline) {
            Some(dl) => {
                if crate::time::monotonic() >= dl {
                    return SendOutcome::Flow(IpcFlow::Done(Err(Errno::TimedOut)));
                }
                Some(dl)
            }
            None => match realtime_to_mono_deadline(abs_rt) {
                Ok(dl) => dl,
                Err(e) => return SendOutcome::Flow(IpcFlow::Done(Err(e))),
            },
        };
        return SendOutcome::Flow(IpcFlow::Wait {
            key: wake_key,
            deadline: mono_dl,
            state: IpcWaitState {
                id: mqdes,
                deadline: mono_dl,
                is_sem: false,
            },
        });
    }

    // 拷贝消息载荷（失败报 EFAULT，不修改队列）。
    let mut data = Vec::new();
    if msg_len > 0 {
        if data.try_reserve_exact(msg_len).is_err() {
            return SendOutcome::Flow(IpcFlow::Done(Err(Errno::NoMem)));
        }
        data.resize(msg_len, 0);
        if user_access::copy_from_user(space, msg_ptr, &mut data).is_err() {
            return SendOutcome::Flow(IpcFlow::Done(Err(Errno::Fault)));
        }
    }

    let (poll_id, pending_notify) = {
        let mut q = queue.lock();
        if q.messages.len() >= q.maxmsg {
            if nonblock {
                return SendOutcome::Flow(IpcFlow::Done(Err(Errno::Again)));
            }
            let mono_dl = match realtime_to_mono_deadline(abs_rt) {
                Ok(dl) => dl,
                Err(e) => return SendOutcome::Flow(IpcFlow::Done(Err(e))),
            };
            return SendOutcome::Flow(IpcFlow::Wait {
                key: q.wake_key,
                deadline: mono_dl,
                state: IpcWaitState {
                    id: mqdes,
                    deadline: mono_dl,
                    is_sem: false,
                },
            });
        }
        if q.messages.try_reserve(1).is_err() {
            return SendOutcome::Flow(IpcFlow::Done(Err(Errno::NoMem)));
        }
        let was_empty = q.messages.is_empty();
        // 按优先级降序插入，同优先级保持 FIFO（插在所有 >= prio 项之后）。
        let pos = q
            .messages
            .iter()
            .position(|m| m.prio < msg_prio)
            .unwrap_or(q.messages.len());
        q.messages.insert(
            pos,
            MqMessage {
                prio: msg_prio,
                data,
            },
        );
        q.event_gen = q.event_gen.wrapping_add(1);
        let notify = if was_empty && q.wait_receivers.is_empty() {
            q.notify.take().map(|n| PendingNotify {
                target_tgid: n.owner_tgid,
                sender_tgid,
                kind: n.kind,
            })
        } else {
            None
        };
        (q.poll_id, notify)
    };

    sched::request_ipc_wake(wake_key);
    sched::request_pipe_id_wake(poll_id);
    SendOutcome::Sent(pending_notify)
}

/// mq_timedreceive(2)：取出最高优先级消息，空时非阻塞报 EAGAIN，阻塞支持 abs_timeout。
#[allow(clippy::too_many_arguments)]
pub(crate) fn timedreceive(
    space: &UserAddressSpace,
    fs: &crate::fs::context::Context,
    mqdes: i32,
    msg_ptr: usize,
    msg_len: usize,
    prio_ptr: usize,
    abs_timeout_ptr: usize,
    tid: Pid,
    cur_wait: Option<IpcWaitState>,
) -> IpcFlow {
    if mqdes < 0 {
        return IpcFlow::Done(Err(Errno::BadF));
    }
    let abs_rt = match parse_abs_timeout(space, abs_timeout_ptr) {
        Ok(t) => t,
        Err(e) => return IpcFlow::Done(Err(e)),
    };
    let (handle, queue) = match fs.mqueue_handle(mqdes as usize) {
        Ok(pair) => pair,
        Err(e) => return IpcFlow::Done(Err(e)),
    };
    let (readable, nonblock) = {
        let f = handle.lock();
        let flags = f.status_flags();
        ((flags & 3) != 1, (flags & (O_NONBLOCK as usize)) != 0)
    };
    if !readable {
        return IpcFlow::Done(Err(Errno::BadF));
    }

    let mut q = queue.lock();
    if msg_len < q.msgsize {
        q.remove_receiver(tid);
        return IpcFlow::Done(Err(Errno::MsgSize));
    }
    if q.messages.is_empty() {
        if nonblock {
            q.remove_receiver(tid);
            return IpcFlow::Done(Err(Errno::Again));
        }
        let mono_dl = match cur_wait.and_then(|w| w.deadline) {
            Some(dl) => {
                if crate::time::monotonic() >= dl {
                    q.remove_receiver(tid);
                    return IpcFlow::Done(Err(Errno::TimedOut));
                }
                Some(dl)
            }
            None => match realtime_to_mono_deadline(abs_rt) {
                Ok(dl) => dl,
                Err(e) => {
                    q.remove_receiver(tid);
                    return IpcFlow::Done(Err(e));
                }
            },
        };
        if !q.wait_receivers.contains(&tid) && q.wait_receivers.try_reserve(1).is_ok() {
            q.wait_receivers.push(tid);
        }
        return IpcFlow::Wait {
            key: q.wake_key,
            deadline: mono_dl,
            state: IpcWaitState {
                id: mqdes,
                deadline: mono_dl,
                is_sem: false,
            },
        };
    }

    // 先拷贝数据与优先级到用户空间，失败不弹队。
    let front = &q.messages[0];
    let len = front.data.len();
    if len > 0 && user_access::copy_to_user(space, msg_ptr, &front.data).is_err() {
        q.remove_receiver(tid);
        return IpcFlow::Done(Err(Errno::Fault));
    }
    if prio_ptr != 0
        && user_access::copy_to_user(space, prio_ptr, &front.prio.to_ne_bytes()).is_err()
    {
        q.remove_receiver(tid);
        return IpcFlow::Done(Err(Errno::Fault));
    }
    q.messages.remove(0);
    q.remove_receiver(tid);
    q.event_gen = q.event_gen.wrapping_add(1);
    let wake_key = q.wake_key;
    let poll_id = q.poll_id;
    drop(q);

    sched::request_ipc_wake(wake_key);
    sched::request_pipe_id_wake(poll_id);
    IpcFlow::Done(Ok(len))
}

/// 进程退出时清理其注册的全部 mq_notify 与接收等待记录（在 REGISTRY 锁外调用）。
pub(crate) fn on_process_exit(tgid: Pid) {
    let table = MQUEUES.lock();
    for q in table.iter() {
        let mut g = q.lock();
        g.clear_notify_for(tgid);
        g.remove_receiver(tgid);
    }
}

/// 信号打断阻塞接收时清理该线程的等待登记。
pub(crate) fn clear_waiter(tid: Pid) {
    let table = MQUEUES.lock();
    for q in table.iter() {
        q.lock().remove_receiver(tid);
    }
}

/// 构造 SI_MESGQ 信号槽，供调用方在 REGISTRY 锁内投递。
pub(crate) fn make_notify_slot(sender_tgid: Pid, sigval: u64) -> SigInfoSlot {
    SigInfoSlot {
        code: SI_MESGQ,
        pid: sender_tgid as u32,
        addr: sigval as usize,
        ..Default::default()
    }
}
