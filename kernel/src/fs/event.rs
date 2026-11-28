//! eventfd、timerfd 与 epoll 核心对象：供 fs::context 与 syscall/task 层复用。
//! 所有用户指针拷贝均在调用方经 user_access 完成；本模块 `#![deny(unsafe_code)]`。
#![deny(unsafe_code)]

use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::time::Duration;
use spin::Mutex;

use crate::{syscall::Errno, task::sched};

use super::context::{fd_poll_events, OpenFile};

/// eventfd2 标志位（asm-generic / musl sys/eventfd.h）。
pub const EFD_SEMAPHORE: usize = 1;
pub const EFD_NONBLOCK: usize = 0x800;
pub const EFD_CLOEXEC: usize = 0x80000;

/// timerfd_create / timerfd_settime 标志位。
pub const TFD_NONBLOCK: usize = 0x800;
pub const TFD_CLOEXEC: usize = 0x80000;
pub const TFD_TIMER_ABSTIME: usize = 1;
pub const TFD_TIMER_CANCEL_ON_SET: usize = 2;

/// epoll 标志、操作码与事件位（rv64/la64 struct epoll_event 为 16 字节非紧凑布局）。
pub const EPOLL_CLOEXEC: usize = 0x80000;
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

pub const EPOLLEXCLUSIVE: u32 = 1 << 28;
pub const EPOLLONESHOT: u32 = 1 << 30;
pub const EPOLLET: u32 = 1 << 31;
/// 始终隐式监听的错误与挂断事件位（EPOLLERR | EPOLLHUP）。
const EPOLL_ALWAYS: u32 = 0x008 | 0x010;
/// 嵌套 epoll 最大深度限制（与 Linux EP_MAX_NESTS = 4 一致；第 5 层返回 EINVAL）。
const EPOLL_MAX_NESTS: usize = 4;

/// 支持 timerfd 的时钟编号（与 kernel/src/time.rs 一致）。
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_BOOTTIME: i32 = 7;

/// eventfd 计数上限（u64::MAX - 1）。
const EFD_MAX: u64 = u64::MAX - 1;

/// eventfd 内部状态。
pub(crate) struct EventFd {
    id: u64,
    count: u64,
    semaphore: bool,
    event_gen: u64,
}

impl EventFd {
    pub fn new(id: u64, initval: u32, semaphore: bool) -> Self {
        Self {
            id,
            count: u64::from(initval),
            semaphore,
            event_gen: 1,
        }
    }

    pub fn event_gen(&self) -> u64 {
        self.event_gen
    }

    pub fn poll_events(&self, requested: u16) -> u16 {
        let mut ev = 0u16;
        if self.count > 0 {
            ev |= 0x41 & requested;
        }
        if self.count < EFD_MAX {
            ev |= 0x104 & requested;
        }
        ev
    }

    /// 读取 8 字节计数；交付成功后再扣减计数并唤醒等待者。
    pub fn read(
        &mut self,
        nonblock: bool,
        deliver: impl FnOnce(&[u8]) -> Result<usize, Errno>,
    ) -> Result<usize, Errno> {
        if self.count == 0 {
            return Err(if nonblock {
                Errno::Again
            } else {
                Errno::WouldBlock
            });
        }
        let val = if self.semaphore { 1 } else { self.count };
        let bytes = val.to_ne_bytes();
        let delivered = deliver(&bytes)?;
        if delivered != 8 {
            return Err(Errno::Invalid);
        }
        self.count -= val;
        self.event_gen = self.event_gen.wrapping_add(1);
        sched::request_pipe_id_wake(self.id);
        Ok(8)
    }

    /// 累加 8 字节计数；写入 u64::MAX 返回 EINVAL，溢出时阻塞或返回 EAGAIN。
    pub fn write(&mut self, data: &[u8], nonblock: bool) -> Result<usize, Errno> {
        if data.len() < 8 {
            return Err(Errno::Invalid);
        }
        let add = u64::from_ne_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        if add == u64::MAX {
            return Err(Errno::Invalid);
        }
        if self.count > EFD_MAX - add {
            return Err(if nonblock {
                Errno::Again
            } else {
                Errno::WouldBlock
            });
        }
        self.count += add;
        if add > 0 {
            self.event_gen = self.event_gen.wrapping_add(1);
            sched::request_pipe_id_wake(self.id);
        }
        Ok(8)
    }
}

/// timerfd 内部状态；到期时刻统一换算为单调时钟，唤醒由硬件定时器驱动，不忙等。
pub(crate) struct TimerFd {
    id: u64,
    clockid: i32,
    deadline: Option<Duration>,
    interval: Duration,
    expirations: u64,
    event_gen: u64,
}

impl TimerFd {
    pub fn new(id: u64, clockid: i32) -> Result<Self, Errno> {
        if !matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME) {
            return Err(Errno::Invalid);
        }
        Ok(Self {
            id,
            clockid,
            deadline: None,
            interval: Duration::ZERO,
            expirations: 0,
            event_gen: 1,
        })
    }

    pub fn event_gen(&mut self) -> u64 {
        let now = crate::time::monotonic();
        self.refresh(now);
        self.event_gen
    }

    /// 推进到期计数（含周期定时器多周期累加）。
    pub fn refresh(&mut self, now: Duration) {
        let Some(dl) = self.deadline else {
            return;
        };
        if now < dl {
            return;
        }
        if self.interval.is_zero() {
            self.expirations = self.expirations.saturating_add(1);
            self.deadline = None;
        } else {
            let elapsed = now.saturating_sub(dl).as_nanos();
            let period = self.interval.as_nanos().max(1);
            let ticks = (elapsed / period).saturating_add(1);
            self.expirations = self
                .expirations
                .saturating_add(ticks.min(u64::MAX as u128) as u64);
            let advance_ns = ticks.saturating_mul(period);
            let advance = Duration::new(
                (advance_ns / 1_000_000_000).min(u64::MAX as u128) as u64,
                (advance_ns % 1_000_000_000) as u32,
            );
            let mut next = dl.saturating_add(advance);
            if next <= now {
                next = now.saturating_add(self.interval);
            }
            self.deadline = Some(next);
        }
        self.event_gen = self.event_gen.wrapping_add(1);
    }

    /// 返回当前下一次到期时刻（若尚未有未读到期且处于武装状态）。
    pub fn next_deadline(&mut self) -> Option<Duration> {
        let now = crate::time::monotonic();
        self.refresh(now);
        if self.expirations > 0 {
            None
        } else {
            self.deadline
        }
    }

    /// 读取当前剩余时间与周期（itimerspec）。
    pub fn gettime(&mut self) -> (Duration, Duration) {
        let now = crate::time::monotonic();
        self.refresh(now);
        let rem = self
            .deadline
            .map_or(Duration::ZERO, |d| d.saturating_sub(now));
        (self.interval, rem)
    }

    /// 设置或撤防定时器，返回旧的 `(interval, remaining)` 并清零历史未读计数。
    pub fn settime(
        &mut self,
        flags: usize,
        interval: Duration,
        value: Duration,
    ) -> Result<(Duration, Duration), Errno> {
        if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
            return Err(Errno::Invalid);
        }
        let now = crate::time::monotonic();
        let old = self.gettime();
        self.expirations = 0;
        if value.is_zero() {
            self.deadline = None;
            self.interval = Duration::ZERO;
        } else {
            let dl = if flags & TFD_TIMER_ABSTIME == 0 {
                now.checked_add(value).ok_or(Errno::Invalid)?
            } else if self.clockid == CLOCK_REALTIME {
                let real = crate::time::realtime();
                if value <= real {
                    now
                } else {
                    now.checked_add(value - real).ok_or(Errno::Invalid)?
                }
            } else {
                value
            };
            self.deadline = Some(dl);
            self.interval = interval;
            self.refresh(now);
        }
        sched::request_pipe_id_wake(self.id);
        Ok(old)
    }

    pub fn poll_events(&mut self, requested: u16) -> u16 {
        let now = crate::time::monotonic();
        self.refresh(now);
        if self.expirations > 0 {
            0x41 & requested
        } else {
            0
        }
    }

    pub fn read(
        &mut self,
        nonblock: bool,
        deliver: impl FnOnce(&[u8]) -> Result<usize, Errno>,
    ) -> Result<usize, Errno> {
        let now = crate::time::monotonic();
        self.refresh(now);
        if self.expirations == 0 {
            return Err(if nonblock {
                Errno::Again
            } else {
                Errno::WouldBlock
            });
        }
        let bytes = self.expirations.to_ne_bytes();
        let delivered = deliver(&bytes)?;
        if delivered != 8 {
            return Err(Errno::Invalid);
        }
        self.expirations = 0;
        self.event_gen = self.event_gen.wrapping_add(1);
        Ok(8)
    }
}

struct EpollEntry {
    fd: usize,
    file: Weak<Mutex<OpenFile>>,
    file_key: usize,
    events: u32,
    data: u64,
    disabled: bool,
    last_ready: u32,
    last_gen: u64,
}

/// epoll 实例：以 `(fd, OpenFile 地址)` 为键，弱引用目标打开文件描述，自动清理已关闭条目。
pub(crate) struct EpollInstance {
    entries: Vec<EpollEntry>,
    /// 指向监视本 epoll 实例的上级 epoll 实例（弱引用），用于反向深度校验。
    parents: Vec<Weak<Mutex<EpollInstance>>>,
}

impl EpollInstance {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            parents: Vec::new(),
        }
    }

    fn prune(&mut self) {
        self.entries.retain(|e| e.file.strong_count() > 0);
        self.parents.retain(|p| p.strong_count() > 0);
    }

    fn find_index(&self, fd: usize, file_key: usize) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.fd == fd && e.file_key == file_key)
    }

    fn add_parent(&mut self, parent: &Arc<Mutex<EpollInstance>>) {
        self.parents.retain(|p| p.strong_count() > 0);
        let ptr = Arc::as_ptr(parent) as usize;
        if self.parents.iter().any(|p| p.as_ptr() as usize == ptr) {
            return;
        }
        if self.parents.try_reserve(1).is_ok() {
            self.parents.push(Arc::downgrade(parent));
        }
    }

    fn remove_parent(&mut self, parent_ptr: usize) {
        self.parents
            .retain(|p| p.strong_count() > 0 && p.as_ptr() as usize != parent_ptr);
    }

    /// 计算从 `node` 向下能到达的最大嵌套深度，同时检测是否包含 `forbid_ptr` 环路。
    fn down_depth(
        node: &Arc<Mutex<EpollInstance>>,
        forbid_ptr: usize,
        budget: usize,
    ) -> Result<usize, Errno> {
        if Arc::as_ptr(node) as usize == forbid_ptr {
            return Err(Errno::Loop);
        }
        if budget == 0 {
            return Ok(EPOLL_MAX_NESTS + 1);
        }
        let children: Vec<Arc<Mutex<EpollInstance>>> = {
            let guard = node.lock();
            let mut list = Vec::new();
            for entry in &guard.entries {
                if let Some(h) = entry.file.upgrade() {
                    if let Some(ep) = h.lock().epoll_instance() {
                        if list.try_reserve(1).is_ok() {
                            list.push(ep);
                        }
                    }
                }
            }
            list
        };
        let mut max_child = 0usize;
        for child in children {
            let d = Self::down_depth(&child, forbid_ptr, budget - 1)?;
            max_child = max_child.max(1 + d);
        }
        Ok(max_child)
    }

    /// 计算到达 `node` 的最长祖先链长度（正/反向建链均受 EP_MAX_NESTS 约束）。
    fn up_depth(node: &Arc<Mutex<EpollInstance>>, budget: usize) -> usize {
        if budget == 0 {
            return EPOLL_MAX_NESTS + 1;
        }
        let parents: Vec<Arc<Mutex<EpollInstance>>> = {
            let mut guard = node.lock();
            guard.parents.retain(|p| p.strong_count() > 0);
            let mut list = Vec::new();
            for w in &guard.parents {
                if let Some(p) = w.upgrade() {
                    if list.try_reserve(1).is_ok() {
                        list.push(p);
                    }
                }
            }
            list
        };
        let mut max_up = 0usize;
        for p in parents {
            max_up = max_up.max(1 + Self::up_depth(&p, budget - 1));
        }
        max_up
    }

    /// 检测向 `parent` 加入 `target` 是否形成环（ELOOP）或超过 EP_MAX_NESTS（EINVAL）。
    pub fn check_nesting(
        parent: &Arc<Mutex<EpollInstance>>,
        target: &Arc<Mutex<EpollInstance>>,
    ) -> Result<(), Errno> {
        let parent_ptr = Arc::as_ptr(parent) as usize;
        let down = Self::down_depth(target, parent_ptr, EPOLL_MAX_NESTS + 2)?;
        let up = Self::up_depth(parent, EPOLL_MAX_NESTS + 2);
        if up + 1 + down > EPOLL_MAX_NESTS {
            return Err(Errno::Invalid);
        }
        Ok(())
    }

    pub fn add(
        &mut self,
        parent: &Arc<Mutex<EpollInstance>>,
        fd: usize,
        handle: &Arc<Mutex<OpenFile>>,
        events: u32,
        data: u64,
        target_ep: Option<&Arc<Mutex<EpollInstance>>>,
    ) -> Result<(), Errno> {
        self.prune();
        if events & EPOLLEXCLUSIVE != 0 && (target_ep.is_some() || events & EPOLLONESHOT != 0) {
            return Err(Errno::Invalid);
        }
        let file_key = Arc::as_ptr(handle) as usize;
        if self.find_index(fd, file_key).is_some() {
            return Err(Errno::Exists);
        }
        self.entries.try_reserve(1).map_err(|_| Errno::NoMem)?;
        self.entries.push(EpollEntry {
            fd,
            file: Arc::downgrade(handle),
            file_key,
            events: events | EPOLL_ALWAYS,
            data,
            disabled: false,
            last_ready: 0,
            last_gen: 0,
        });
        if let Some(child_ep) = target_ep {
            child_ep.lock().add_parent(parent);
        }
        Ok(())
    }

    pub fn modify(
        &mut self,
        fd: usize,
        handle: &Arc<Mutex<OpenFile>>,
        events: u32,
        data: u64,
    ) -> Result<(), Errno> {
        self.prune();
        if events & EPOLLEXCLUSIVE != 0 {
            return Err(Errno::Invalid);
        }
        let file_key = Arc::as_ptr(handle) as usize;
        let idx = self.find_index(fd, file_key).ok_or(Errno::NoEntry)?;
        let e = &mut self.entries[idx];
        if e.events & EPOLLEXCLUSIVE != 0 {
            return Err(Errno::Invalid);
        }
        e.events = events | EPOLL_ALWAYS;
        e.data = data;
        e.disabled = false;
        e.last_ready = 0;
        e.last_gen = 0;
        Ok(())
    }

    pub fn delete(
        &mut self,
        parent_ptr: usize,
        fd: usize,
        handle: &Arc<Mutex<OpenFile>>,
        target_ep: Option<&Arc<Mutex<EpollInstance>>>,
    ) -> Result<(), Errno> {
        self.prune();
        let file_key = Arc::as_ptr(handle) as usize;
        let idx = self.find_index(fd, file_key).ok_or(Errno::NoEntry)?;
        self.entries.remove(idx);
        if let Some(child_ep) = target_ep {
            let still_watched = self.entries.iter().any(|e| e.file_key == file_key);
            if !still_watched {
                child_ep.lock().remove_parent(parent_ptr);
            }
        }
        Ok(())
    }

    /// 扫描当前就绪事件（至多 `maxevents` 条）以及被监视 timerfd 的最早到期时刻。
    /// 返回 `(编码后的 16 字节事件数组, 事件数, 最早 timerfd 截止时刻)`。
    pub fn collect_ready(
        &mut self,
        maxevents: usize,
        depth: usize,
    ) -> Result<(Vec<u8>, usize, Option<Duration>), Errno> {
        self.prune();
        let mut out = Vec::new();
        let mut count = 0usize;
        let mut earliest_timer: Option<Duration> = None;

        for entry in &mut self.entries {
            if entry.disabled {
                continue;
            }
            let Some(handle) = entry.file.upgrade() else {
                continue;
            };
            let (revents, cur_gen, tfd_dl) = {
                let mut f = handle.lock();
                let req = ((entry.events & 0x3fff) | EPOLL_ALWAYS) as u16;
                let rev = if depth <= EPOLL_MAX_NESTS {
                    fd_poll_events(&mut f, req, depth + 1) as u32
                } else {
                    0
                };
                let gen = f.event_gen();
                let dl = if depth <= EPOLL_MAX_NESTS {
                    f.timer_deadline(depth + 1)
                } else {
                    None
                };
                (rev, gen, dl)
            };
            if let Some(d) = tfd_dl {
                earliest_timer = Some(match earliest_timer {
                    Some(cur) => cur.min(d),
                    None => d,
                });
            }

            let is_et = entry.events & EPOLLET != 0;
            let should_report = if revents == 0 {
                if is_et {
                    entry.last_ready = 0;
                    entry.last_gen = cur_gen;
                }
                false
            } else if is_et {
                (revents & !entry.last_ready) != 0 || (cur_gen != 0 && cur_gen != entry.last_gen)
            } else {
                true
            };

            if should_report && count < maxevents {
                if out.try_reserve(16).is_err() {
                    return Err(Errno::NoMem);
                }
                out.extend_from_slice(&revents.to_ne_bytes());
                out.extend_from_slice(&[0u8; 4]);
                out.extend_from_slice(&entry.data.to_ne_bytes());
                count += 1;
                if is_et {
                    entry.last_ready = revents;
                    entry.last_gen = cur_gen;
                }
                if entry.events & EPOLLONESHOT != 0 {
                    entry.disabled = true;
                }
            }
        }
        Ok((out, count, earliest_timer))
    }

    /// 非破坏性检测该 epoll 实例是否已有就绪事件（供 poll/select/嵌套 epoll 查询）。
    pub fn has_ready(&mut self, depth: usize) -> bool {
        if depth > EPOLL_MAX_NESTS + 1 {
            return false;
        }
        self.prune();
        for entry in &self.entries {
            if entry.disabled {
                continue;
            }
            let Some(handle) = entry.file.upgrade() else {
                continue;
            };
            let mut f = handle.lock();
            let req = ((entry.events & 0x3fff) | EPOLL_ALWAYS) as u16;
            let rev = fd_poll_events(&mut f, req, depth + 1) as u32;
            if rev != 0 && (entry.events & EPOLLET == 0 || (rev & !entry.last_ready) != 0) {
                return true;
            }
        }
        false
    }

    /// 递归求本 epoll 实例下所有武装 timerfd 的最早到期时刻。
    pub fn earliest_timer_deadline(&mut self, depth: usize) -> Option<Duration> {
        if depth > EPOLL_MAX_NESTS + 1 {
            return None;
        }
        self.prune();
        let mut earliest: Option<Duration> = None;
        for entry in &self.entries {
            if entry.disabled {
                continue;
            }
            let Some(handle) = entry.file.upgrade() else {
                continue;
            };
            let mut f = handle.lock();
            if let Some(d) = f.timer_deadline(depth + 1) {
                earliest = Some(match earliest {
                    Some(cur) => cur.min(d),
                    None => d,
                });
            }
        }
        earliest
    }
}
