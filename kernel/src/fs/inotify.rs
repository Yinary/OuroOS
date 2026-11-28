//! inotify(7) 文件系统事件监控：inotify_init1 / inotify_add_watch / inotify_rm_watch。
//!
//! 性能设计：无活跃 watch 时所有 VFS 钩子仅做一次 Relaxed 原子读（零加锁、零分配）；
//! 仅文件 watch 时跳过父目录查找；未启用 `IN_EXCL_UNLINK` 时跳过二次路径核验。
//! 锁序：外部可先完成 `fs::lookup`，本模块内部 `INSTANCES` -> 单实例 `Mutex` 单向叶锁。
#![deny(unsafe_code)]

use alloc::{
    collections::VecDeque,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use spin::Mutex;

use crate::{syscall::Errno, task::sched};

/// inotify_init1(2) 标志位（asm-generic / musl sys/inotify.h）。
pub const IN_NONBLOCK: usize = 0x800;
pub const IN_CLOEXEC: usize = 0x80000;

/// inotify(7) 可监听事件位。
pub const IN_ACCESS: u32 = 0x0000_0001;
pub const IN_MODIFY: u32 = 0x0000_0002;
pub const IN_ATTRIB: u32 = 0x0000_0004;
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
pub const IN_OPEN: u32 = 0x0000_0020;
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
pub const IN_MOVED_TO: u32 = 0x0000_0080;
pub const IN_CREATE: u32 = 0x0000_0100;
pub const IN_DELETE: u32 = 0x0000_0200;
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

pub const IN_ALL_EVENTS: u32 = 0x0000_0fff;

/// 内核生成的只读标志位（无需显式订阅）。
pub const IN_UNMOUNT: u32 = 0x0000_2000;
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
pub const IN_IGNORED: u32 = 0x0000_8000;
pub const IN_ISDIR: u32 = 0x4000_0000;

/// add_watch 修饰标志位。
pub const IN_ONLYDIR: u32 = 0x0100_0000;
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;
pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;
pub const IN_MASK_CREATE: u32 = 0x1000_0000;
pub const IN_MASK_ADD: u32 = 0x2000_0000;
pub const IN_ONESHOT: u32 = 0x8000_0000;

const IN_VALID_MODIFIERS: u32 =
    IN_ONLYDIR | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_CREATE | IN_MASK_ADD | IN_ONESHOT;
const IN_STORED_FLAGS: u32 = IN_ALL_EVENTS | IN_EXCL_UNLINK | IN_ONESHOT;

/// Linux 默认限额（通过 `/proc/sys/fs/inotify/*` 导出）。
pub const DEFAULT_MAX_QUEUED_EVENTS: usize = 16384;
pub const DEFAULT_MAX_USER_INSTANCES: usize = 128;
pub const DEFAULT_MAX_USER_WATCHES: usize = 8192;

static MAX_QUEUED_EVENTS: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_QUEUED_EVENTS);
static MAX_USER_INSTANCES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_USER_INSTANCES);
static MAX_USER_WATCHES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_USER_WATCHES);

/// 热路径快速门控计数器：全部零成本 Relaxed 读取。
static ACTIVE_INSTANCES: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_WATCHES: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_DIR_WATCHES: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_EXCL_UNLINK: AtomicUsize = AtomicUsize::new(0);

static NEXT_COOKIE: AtomicU32 = AtomicU32::new(1);

/// 存活 inotify 实例弱引用注册表；Drop 无锁递减原子计数，注册表按需惰性清理。
static INSTANCES: Mutex<Vec<Weak<Mutex<InotifyInstance>>>> = Mutex::new(Vec::new());

/// 是否存在任意活跃 watch（VFS 钩子最外层门控）。
#[inline(always)]
pub fn has_watches() -> bool {
    ACTIVE_WATCHES.load(Ordering::Relaxed) != 0
}

/// 是否存在目录 watch（无目录 watch 时跳过父目录查找）。
#[inline(always)]
pub fn has_dir_watches() -> bool {
    ACTIVE_DIR_WATCHES.load(Ordering::Relaxed) != 0
}

#[inline(always)]
fn has_excl_unlink_watches() -> bool {
    ACTIVE_EXCL_UNLINK.load(Ordering::Relaxed) != 0
}

/// 返回单实例允许排队的最大 inotify 事件数。
pub fn max_queued_events() -> usize {
    MAX_QUEUED_EVENTS.load(Ordering::Relaxed)
}

/// 返回允许创建的最大 inotify 实例数。
pub fn max_user_instances() -> usize {
    MAX_USER_INSTANCES.load(Ordering::Relaxed)
}

/// 返回允许注册的最大 inotify 监视项总数。
pub fn max_user_watches() -> usize {
    MAX_USER_WATCHES.load(Ordering::Relaxed)
}

/// `/proc/sys/fs/inotify/*` 可读写配置项。
#[derive(Clone, Copy)]
#[allow(clippy::enum_variant_names)]
pub enum SysctlKind {
    MaxQueuedEvents,
    MaxUserInstances,
    MaxUserWatches,
}

impl SysctlKind {
    /// 将 `/proc/sys/fs/inotify/*` 路径解析为配置项枚举。
    pub fn from_path(path: &str) -> Option<Self> {
        match path {
            "/proc/sys/fs/inotify/max_queued_events" => Some(Self::MaxQueuedEvents),
            "/proc/sys/fs/inotify/max_user_instances" => Some(Self::MaxUserInstances),
            "/proc/sys/fs/inotify/max_user_watches" => Some(Self::MaxUserWatches),
            _ => None,
        }
    }

    /// 读取该 inotify sysctl 配置项当前值。
    pub fn get(self) -> usize {
        match self {
            Self::MaxQueuedEvents => max_queued_events(),
            Self::MaxUserInstances => max_user_instances(),
            Self::MaxUserWatches => max_user_watches(),
        }
    }

    /// 将该 inotify sysctl 配置项格式化为带换行字符串。
    pub fn format(self) -> Result<String, Errno> {
        use core::fmt::Write;
        let mut out = String::new();
        out.try_reserve(24).map_err(|_| Errno::NoMem)?;
        let _ = writeln!(out, "{}", self.get());
        Ok(out)
    }

    /// 解析用户写入的十进制文本并更新对应 inotify sysctl 上限。
    pub fn parse_and_set(self, data: &[u8]) -> Result<(), Errno> {
        let s = core::str::from_utf8(data).map_err(|_| Errno::Invalid)?;
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(Errno::Invalid);
        }
        let val: usize = trimmed.parse().map_err(|_| Errno::Invalid)?;
        if val == 0 || val > 1_048_576 {
            return Err(Errno::Invalid);
        }
        match self {
            Self::MaxQueuedEvents => MAX_QUEUED_EVENTS.store(val, Ordering::Release),
            Self::MaxUserInstances => MAX_USER_INSTANCES.store(val, Ordering::Release),
            Self::MaxUserWatches => MAX_USER_WATCHES.store(val, Ordering::Release),
        }
        Ok(())
    }
}

struct Watch {
    wd: i32,
    ino: u32,
    is_dir: bool,
    mask: u32,
}

struct InotifyEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    name: String,
}

impl InotifyEvent {
    /// Linux `roundup(name_len + 1, sizeof(struct inotify_event))`（无名时为 0）。
    fn padded_name_len(&self) -> usize {
        if self.name.is_empty() {
            0
        } else {
            (self.name.len() + 1 + 15) & !15
        }
    }

    fn encoded_len(&self) -> usize {
        16 + self.padded_name_len()
    }

    fn encode_into(&self, dst: &mut [u8]) -> usize {
        let name_len = self.padded_name_len();
        let total = 16 + name_len;
        dst[0..4].copy_from_slice(&self.wd.to_ne_bytes());
        dst[4..8].copy_from_slice(&self.mask.to_ne_bytes());
        dst[8..12].copy_from_slice(&self.cookie.to_ne_bytes());
        dst[12..16].copy_from_slice(&(name_len as u32).to_ne_bytes());
        if name_len > 0 {
            let raw = self.name.as_bytes();
            dst[16..16 + raw.len()].copy_from_slice(raw);
            dst[16 + raw.len()..total].fill(0);
        }
        total
    }
}

/// 单个 inotify 实例状态。
pub(crate) struct InotifyInstance {
    id: u64,
    next_wd: i32,
    watches: Vec<Watch>,
    queue: VecDeque<InotifyEvent>,
    queued_bytes: usize,
    event_gen: u64,
}

impl Drop for InotifyInstance {
    fn drop(&mut self) {
        let mut dir_count = 0usize;
        let mut excl_count = 0usize;
        for w in &self.watches {
            if w.is_dir {
                dir_count += 1;
            }
            if w.mask & IN_EXCL_UNLINK != 0 {
                excl_count += 1;
            }
        }
        if !self.watches.is_empty() {
            ACTIVE_WATCHES.fetch_sub(self.watches.len(), Ordering::Release);
        }
        if dir_count != 0 {
            ACTIVE_DIR_WATCHES.fetch_sub(dir_count, Ordering::Release);
        }
        if excl_count != 0 {
            ACTIVE_EXCL_UNLINK.fetch_sub(excl_count, Ordering::Release);
        }
        ACTIVE_INSTANCES.fetch_sub(1, Ordering::Release);
    }
}

impl InotifyInstance {
    /// 创建并登记新的 inotify 实例；超出 `max_user_instances` 返回 EMFILE。
    pub fn create(id: u64) -> Result<Arc<Mutex<Self>>, Errno> {
        let limit = max_user_instances();
        let prev = ACTIVE_INSTANCES.fetch_add(1, Ordering::AcqRel);
        if prev >= limit {
            ACTIVE_INSTANCES.fetch_sub(1, Ordering::Release);
            return Err(Errno::TooManyFiles);
        }
        let inst = match super::try_arc(Mutex::new(Self {
            id,
            next_wd: 1,
            watches: Vec::new(),
            queue: VecDeque::new(),
            queued_bytes: 0,
            event_gen: 1,
        })) {
            Ok(i) => i,
            Err(e) => {
                ACTIVE_INSTANCES.fetch_sub(1, Ordering::Release);
                return Err(e);
            }
        };
        let mut list = INSTANCES.lock();
        list.retain(|w| w.strong_count() > 0);
        if list.try_reserve(1).is_err() {
            drop(list);
            drop(inst);
            return Err(Errno::NoMem);
        }
        list.push(Arc::downgrade(&inst));
        Ok(inst)
    }

    /// 返回该 inotify 实例事件队列是否为空。
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// 返回队列中待读取事件的总字节数。
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// 返回该 inotify 实例的事件变化版本号。
    pub fn event_gen(&self) -> u64 {
        self.event_gen
    }

    /// 格式化 `/proc/<pid>/fdinfo/<fd>` 中的 inotify watch 行（对齐 Linux `fs/notify/fdinfo.c`）。
    pub fn format_fdinfo(&self, out: &mut String) -> Result<(), Errno> {
        use core::fmt::Write;
        for w in &self.watches {
            out.try_reserve(96).map_err(|_| Errno::NoMem)?;
            let _ = writeln!(
                out,
                "inotify wd:{:x} ino:{:x} sdev:1 mask:{:x} ignored_mask:0",
                w.wd as u32, w.ino, w.mask
            );
        }
        Ok(())
    }

    /// 校验 `inotify_add_watch` 掩码合法性。
    pub fn validate_mask(mask: u32) -> Result<(), Errno> {
        if mask & !(IN_ALL_EVENTS | IN_VALID_MODIFIERS | IN_UNMOUNT | IN_Q_OVERFLOW | IN_IGNORED)
            != 0
        {
            return Err(Errno::Invalid);
        }
        if mask & IN_ALL_EVENTS == 0 {
            return Err(Errno::Invalid);
        }
        if (mask & IN_MASK_ADD != 0) && (mask & IN_MASK_CREATE != 0) {
            return Err(Errno::Invalid);
        }
        Ok(())
    }

    /// 添加或更新对 `ino` 的监控，返回 watch descriptor (`wd >= 1`)。
    pub fn add_watch(&mut self, ino: u32, is_dir: bool, mask: u32) -> Result<i32, Errno> {
        Self::validate_mask(mask)?;
        let stored = mask & IN_STORED_FLAGS;
        if let Some(w) = self.watches.iter_mut().find(|w| w.ino == ino) {
            if mask & IN_MASK_CREATE != 0 {
                return Err(Errno::Exists);
            }
            let old_excl = w.mask & IN_EXCL_UNLINK != 0;
            if mask & IN_MASK_ADD != 0 {
                w.mask |= stored;
            } else {
                w.mask = stored;
            }
            let new_excl = w.mask & IN_EXCL_UNLINK != 0;
            if !old_excl && new_excl {
                ACTIVE_EXCL_UNLINK.fetch_add(1, Ordering::Release);
            } else if old_excl && !new_excl {
                ACTIVE_EXCL_UNLINK.fetch_sub(1, Ordering::Release);
            }
            return Ok(w.wd);
        }

        let limit = max_user_watches();
        let prev = ACTIVE_WATCHES.fetch_add(1, Ordering::AcqRel);
        if prev >= limit {
            ACTIVE_WATCHES.fetch_sub(1, Ordering::Release);
            return Err(Errno::NoSpace);
        }
        if self.watches.try_reserve(1).is_err() {
            ACTIVE_WATCHES.fetch_sub(1, Ordering::Release);
            return Err(Errno::NoMem);
        }

        // 分配未占用的正 wd。
        let wd = loop {
            let candidate = self.next_wd;
            self.next_wd = if candidate == i32::MAX {
                1
            } else {
                candidate + 1
            };
            if !self.watches.iter().any(|w| w.wd == candidate) {
                break candidate;
            }
        };

        self.watches.push(Watch {
            wd,
            ino,
            is_dir,
            mask: stored,
        });
        if is_dir {
            ACTIVE_DIR_WATCHES.fetch_add(1, Ordering::Release);
        }
        if stored & IN_EXCL_UNLINK != 0 {
            ACTIVE_EXCL_UNLINK.fetch_add(1, Ordering::Release);
        }
        Ok(wd)
    }

    /// 移除指定 `wd` 的监控并入队 `IN_IGNORED`；无效 `wd` 返回 EINVAL。
    pub fn rm_watch(&mut self, wd: i32) -> Result<(), Errno> {
        if wd <= 0 {
            return Err(Errno::Invalid);
        }
        let Some(pos) = self.watches.iter().position(|w| w.wd == wd) else {
            return Err(Errno::Invalid);
        };
        let removed = self.watches.swap_remove(pos);
        Self::dec_watch_counters(&removed);
        self.push_event(removed.wd, IN_IGNORED, 0, "");
        Ok(())
    }

    fn dec_watch_counters(w: &Watch) {
        ACTIVE_WATCHES.fetch_sub(1, Ordering::Release);
        if w.is_dir {
            ACTIVE_DIR_WATCHES.fetch_sub(1, Ordering::Release);
        }
        if w.mask & IN_EXCL_UNLINK != 0 {
            ACTIVE_EXCL_UNLINK.fetch_sub(1, Ordering::Release);
        }
    }

    fn push_event(&mut self, wd: i32, mask: u32, cookie: u32, name: &str) {
        let limit = max_queued_events();
        if let Some(last) = self.queue.back() {
            if last.wd == wd
                && last.mask == mask
                && last.cookie == cookie
                && last.name.as_str() == name
            {
                return;
            }
        }
        if self.queue.len() >= limit {
            let already_overflow = self
                .queue
                .back()
                .is_some_and(|e| e.wd == -1 && e.mask == IN_Q_OVERFLOW);
            if !already_overflow && self.queue.try_reserve(1).is_ok() {
                let ev = InotifyEvent {
                    wd: -1,
                    mask: IN_Q_OVERFLOW,
                    cookie: 0,
                    name: String::new(),
                };
                self.queued_bytes += ev.encoded_len();
                self.queue.push_back(ev);
                self.event_gen = self.event_gen.wrapping_add(1);
                sched::request_pipe_id_wake(self.id);
            }
            return;
        }
        let mut owned = String::new();
        if !name.is_empty() {
            if owned.try_reserve_exact(name.len()).is_err() {
                return;
            }
            owned.push_str(name);
        }
        if self.queue.try_reserve(1).is_err() {
            return;
        }
        let ev = InotifyEvent {
            wd,
            mask,
            cookie,
            name: owned,
        };
        self.queued_bytes += ev.encoded_len();
        self.queue.push_back(ev);
        self.event_gen = self.event_gen.wrapping_add(1);
        sched::request_pipe_id_wake(self.id);
    }

    fn deliver_inode(&mut self, ino: u32, mask: u32, cookie: u32, name: &str, unlinked: bool) {
        let Some(pos) = self.watches.iter().position(|w| w.ino == ino) else {
            return;
        };
        let wmask = self.watches[pos].mask;
        if unlinked && !name.is_empty() && (wmask & IN_EXCL_UNLINK != 0) {
            return;
        }
        if (wmask & mask & IN_ALL_EVENTS) == 0 {
            return;
        }
        let wd = self.watches[pos].wd;
        let oneshot = wmask & IN_ONESHOT != 0;
        self.push_event(wd, mask, cookie, name);
        if oneshot {
            let removed = self.watches.swap_remove(pos);
            Self::dec_watch_counters(&removed);
            self.push_event(removed.wd, IN_IGNORED, 0, "");
        }
    }

    fn deliver_delete_self(&mut self, ino: u32) {
        let Some(pos) = self.watches.iter().position(|w| w.ino == ino) else {
            return;
        };
        let removed = self.watches.swap_remove(pos);
        Self::dec_watch_counters(&removed);
        if removed.mask & IN_DELETE_SELF != 0 {
            self.push_event(removed.wd, IN_DELETE_SELF, 0, "");
        }
        self.push_event(removed.wd, IN_IGNORED, 0, "");
    }

    /// 读取尽可能多的完整事件；缓冲不足以容纳首条事件返回 EINVAL，空队列按阻塞模式返回。
    pub fn read(
        &mut self,
        buf: &mut [u8],
        nonblock: bool,
        deliver: impl FnOnce(&[u8]) -> Result<usize, Errno>,
    ) -> Result<usize, Errno> {
        let Some(front) = self.queue.front() else {
            return Err(if nonblock {
                Errno::Again
            } else {
                Errno::WouldBlock
            });
        };
        let first_len = front.encoded_len();
        if buf.len() < first_len {
            return Err(Errno::Invalid);
        }
        let mut written = 0usize;
        let mut count = 0usize;
        for ev in &self.queue {
            let need = ev.encoded_len();
            if written + need > buf.len() {
                break;
            }
            ev.encode_into(&mut buf[written..written + need]);
            written += need;
            count += 1;
        }
        let delivered = deliver(&buf[..written])?;
        if delivered != written {
            return Err(Errno::Fault);
        }
        for _ in 0..count {
            if let Some(ev) = self.queue.pop_front() {
                self.queued_bytes = self.queued_bytes.saturating_sub(ev.encoded_len());
            }
        }
        self.event_gen = self.event_gen.wrapping_add(1);
        Ok(written)
    }
}

fn for_each_instance(mut f: impl FnMut(&mut InotifyInstance)) {
    let mut list = INSTANCES.lock();
    let mut has_dead = false;
    for weak in list.iter() {
        if let Some(arc) = weak.upgrade() {
            f(&mut arc.lock());
        } else {
            has_dead = true;
        }
    }
    if has_dead {
        list.retain(|w| w.strong_count() > 0);
    }
}

fn next_cookie() -> u32 {
    loop {
        let c = NEXT_COOKIE.fetch_add(1, Ordering::Relaxed);
        if c != 0 {
            return c;
        }
    }
}

/// 拆分规范路径为 `(父目录路径, 子文件名)`；根目录返回 `None`。
fn split_parent_child(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.rsplit_once('/') {
        Some(("", name)) if !name.is_empty() => Some(("/", name)),
        Some((parent, name)) if !name.is_empty() => Some((parent, name)),
        _ => None,
    }
}

/// 仅向指定 inode 投递事件（如 `ftruncate`/`utimensat`/`chown`/`link` 的属性变化）。
pub fn notify_inode(ino: u32, event: u32, is_dir: bool) {
    if !has_watches() {
        return;
    }
    let mask = event | if is_dir { IN_ISDIR } else { 0 };
    for_each_instance(|inst| inst.deliver_inode(ino, mask, 0, "", false));
}

/// 向父目录投递子项事件（如 `IN_CREATE` / `IN_DELETE`）。
pub fn notify_dir_child(parent_ino: u32, name: &str, is_dir: bool, event: u32) {
    if !has_dir_watches() {
        return;
    }
    let mask = event | if is_dir { IN_ISDIR } else { 0 };
    for_each_instance(|inst| inst.deliver_inode(parent_ino, mask, 0, name, false));
}

/// 同时通知文件自身与父目录（open / read / write / close / chmod）。
/// 无目录 watch 时跳过 `fs::lookup`，无 `IN_EXCL_UNLINK` 时跳过二次路径核验。
pub fn notify_path_event(ino: u32, path: &str, is_dir: bool, event: u32) {
    if !has_watches() {
        return;
    }
    let mask = event | if is_dir { IN_ISDIR } else { 0 };
    let parent_info = if has_dir_watches() {
        split_parent_child(path).and_then(|(parent_path, child_name)| {
            let parent_ino = super::lookup(parent_path).ok()?;
            let unlinked = if has_excl_unlink_watches() {
                super::lookup(path).ok() != Some(ino)
            } else {
                false
            };
            Some((parent_ino, child_name, unlinked))
        })
    } else {
        None
    };
    for_each_instance(|inst| {
        if let Some((parent_ino, child_name, unlinked)) = parent_info {
            inst.deliver_inode(parent_ino, mask, 0, child_name, unlinked);
        }
        inst.deliver_inode(ino, mask, 0, "", false);
    });
}

/// 仅通知路径的父目录（用于已由底层发过 `notify_inode` 的路径型调用，如 `truncate`/`chown`/`utimensat`）。
pub fn notify_parent_path(ino: u32, path: &str, is_dir: bool, event: u32) {
    if !has_dir_watches() {
        return;
    }
    let Some((parent_path, child_name)) = split_parent_child(path) else {
        return;
    };
    let Ok(parent_ino) = super::lookup(parent_path) else {
        return;
    };
    let unlinked = if has_excl_unlink_watches() {
        super::lookup(path).ok() != Some(ino)
    } else {
        false
    };
    let mask = event | if is_dir { IN_ISDIR } else { 0 };
    for_each_instance(|inst| inst.deliver_inode(parent_ino, mask, 0, child_name, unlinked));
}

/// 重命名事件：同一 cookie 关联 `IN_MOVED_FROM` / `IN_MOVED_TO`，并通知被移动对象 `IN_MOVE_SELF`。
pub fn notify_rename(
    old_parent: u32,
    old_name: &str,
    new_parent: u32,
    new_name: &str,
    moved_ino: u32,
    is_dir: bool,
) {
    if !has_watches() {
        return;
    }
    let cookie = next_cookie();
    let dir_bit = if is_dir { IN_ISDIR } else { 0 };
    for_each_instance(|inst| {
        inst.deliver_inode(old_parent, IN_MOVED_FROM | dir_bit, cookie, old_name, false);
        inst.deliver_inode(new_parent, IN_MOVED_TO | dir_bit, cookie, new_name, false);
        inst.deliver_inode(moved_ino, IN_MOVE_SELF, 0, "", false);
    });
}

/// 目标 inode 已彻底移除：向监控它的实例发送 `IN_DELETE_SELF` 并移除 watch（伴随 `IN_IGNORED`）。
pub fn notify_delete_self(ino: u32) {
    if !has_watches() {
        return;
    }
    for_each_instance(|inst| inst.deliver_delete_self(ino));
}
