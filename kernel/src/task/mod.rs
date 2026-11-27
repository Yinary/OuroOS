//! 任务与调度子系统：统一任务抽象（内核/用户任务）、进程注册表
//!（收割即删，见 §3 生命周期）、协作 + 时间片调度与等待/唤醒。
//! 完整契约见 docs/ostd-contracts.md §3。

pub(crate) mod futex;
pub mod sched;
pub mod signal;
// Issue 指定的 `task/mod.rs` + `task/task.rs` 布局会自然形成同名子模块。
#[allow(clippy::module_inception)]
mod task;
pub mod user_task;

use alloc::{collections::VecDeque, vec::Vec};

use polyhal::{irq::IRQ, println};

use crate::{
    mm, mm::address_space::LocalSpace, sync::DebugMutex, syscall::signal::SA_NOCLDWAIT,
    trap::UserFault,
};

use signal::{SigInfoSlot, SignalGroup, ThreadSig, CLD_EXITED, CLD_KILLED, SIGCHLD, SIG_IGN};

pub use futex::{futex_call, FutexStep};
pub use sched::yield_now;
pub use task::{Pid, WaitReason};
pub use user_task::{spawn_user, SpawnError};

/// 一次任务终止的完整记录。
#[derive(Debug, Clone, Copy)]
pub enum ExitInfo {
    /// exit(n) 或等效正常退出。
    Exited(i32),
    /// 死于信号 sig；fault 为硬件异常细节。
    Signaled { sig: u8, fault: Option<UserFault> },
}

impl ExitInfo {
    /// 正常退出。
    pub fn exited(code: i32) -> Self {
        Self::Exited(code)
    }
}

/// Linux 能力位编号（include/uapi/linux/capability.h）。
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_RESOURCE: u32 = 24;
pub const CAP_SYS_TIME: u32 = 25;

/// 进程凭证：真实、有效、保存的用户号与组号，文件系统访问用的号，补充组与能力集。
/// init 从全 0 与全能力集开始，fork 继承，exec 保留。
pub struct Credentials {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub groups: Vec<u32>,
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
}

impl Credentials {
    /// 全 0 的凭证，即 root（携带完整能力集）。
    pub fn root() -> Self {
        Self {
            ruid: 0,
            euid: 0,
            suid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsuid: 0,
            fsgid: 0,
            groups: Vec::new(),
            cap_effective: CAP_FULL_SET,
            cap_permitted: CAP_FULL_SET,
            cap_inheritable: 0,
        }
    }

    /// 检查当前有效能力集中是否具备指定能力位。
    pub fn has_cap(&self, cap: u32) -> bool {
        cap <= CAP_LAST_CAP && ((self.cap_effective >> cap) & 1 != 0)
    }

    /// UID 切换时按 Linux `cap_emulate_setxuid` 同步有效/允许能力集。
    pub fn sync_uid_transition(
        &mut self,
        old_ruid: u32,
        old_euid: u32,
        old_suid: u32,
        keepcaps: bool,
    ) {
        if (old_ruid == 0 || old_euid == 0 || old_suid == 0)
            && self.ruid != 0
            && self.euid != 0
            && self.suid != 0
            && !keepcaps
        {
            self.cap_permitted = 0;
            self.cap_effective = 0;
        }
        if old_euid == 0 && self.euid != 0 {
            self.cap_effective = 0;
        } else if old_euid != 0 && self.euid == 0 {
            self.cap_effective = self.cap_permitted;
        }
    }

    /// 复制凭证；补充组的内存预留失败时返回 Err。
    pub fn try_clone(&self) -> Result<Self, ()> {
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(self.groups.len())
            .map_err(|_| ())?;
        groups.extend_from_slice(&self.groups);
        Ok(Self {
            ruid: self.ruid,
            euid: self.euid,
            suid: self.suid,
            rgid: self.rgid,
            egid: self.egid,
            sgid: self.sgid,
            fsuid: self.fsuid,
            fsgid: self.fsgid,
            groups,
            cap_effective: self.cap_effective,
            cap_permitted: self.cap_permitted,
            cap_inheritable: self.cap_inheritable,
        })
    }
}

/// Linux 6.12 资源限额种类总数（RLIMIT_CPU=0 .. RLIMIT_RTTIME=15）。
pub const RLIM_NLIMITS: usize = 16;

/// Linux 默认线程定时器松弛值（50 微秒，见 kernel/fork.c TIMER_SLACK_NS_DEFAULT）。
pub const DEFAULT_TIMER_SLACK_NS: u64 = 50_000;

/// Linux 6.12 最大能力位编号（CAP_CHECKPOINT_RESTORE = 40）。
pub const CAP_LAST_CAP: u32 = 40;

/// 全能力边界集掩码（位 0..=40）。
pub const CAP_FULL_SET: u64 = (1u64 << (CAP_LAST_CAP + 1)) - 1;

/// 构造默认 16 项资源限额表（其中 DATA/STACK/MEMLOCK/AS 实际以地址空间为准，
/// NOFILE 以文件系统上下文为准）。
pub fn default_rlimits() -> [[u64; 2]; RLIM_NLIMITS] {
    let mut lim = [[u64::MAX; 2]; RLIM_NLIMITS];
    // RLIMIT_CORE(4)：Linux 默认软限额 0、硬限额无限
    lim[4] = [0, u64::MAX];
    // RLIMIT_NPROC(6)
    lim[6] = [4096, 4096];
    // RLIMIT_NOFILE(7)：与 fs/context 默认一致
    lim[7] = [1024, 4096];
    // RLIMIT_SIGPENDING(11)
    lim[11] = [4096, 4096];
    // RLIMIT_MSGQUEUE(12)：Linux MQ_BYTES_MAX = 819200
    lim[12] = [819_200, 819_200];
    // RLIMIT_NICE(13) / RLIMIT_RTPRIO(14)
    lim[13] = [0, 0];
    lim[14] = [0, 0];
    lim
}

/// 把字节串截断并补 NUL 编码为 16 字节线程名（PR_SET_NAME / TASK_COMM_LEN=16）。
pub fn comm_from_bytes(src: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = src
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(src.len())
        .min(15);
    out[..n].copy_from_slice(&src[..n]);
    out
}

/// 取路径末段文件名并编码为 16 字节线程名（execve 更新 comm 语义）。
pub fn comm_from_path(path: &str) -> [u8; 16] {
    let base = path.rsplit('/').next().unwrap_or(path);
    comm_from_bytes(base.as_bytes())
}

/// 进程注册表条目：Task 之外的全部资源与终态。
/// 生命周期：wait 成功收割即删除；孤儿过继 init，运行时间累归丢弃。
/// 表内只存活跃进程与未被收割的僵尸。
pub struct ProcessRecord {
    user_ns: u64,
    system_ns: u64,
    child_user_ns: u64,
    child_system_ns: u64,
    fs: Option<crate::fs::context::Context>,
    /// 信号状态（模型见 signal 模块）。
    pub signal: SignalGroup,
    pub pid: Pid,
    pub name: &'static str,
    /// 用户任务的地址空间（单核凭证包装，见 mm::address_space::
    /// LocalSpace）；内核任务与已退出任务为 None。
    /// 放注册表不放 Task 的原因见模块契约“数据模型”。
    pub space: Option<LocalSpace>,
    pub exit: Option<ExitInfo>,
    pub parent: Pid,
    /// 进程组标识与会话标识；fork 继承，exec 保留。
    pub pgid: Pid,
    pub sid: Pid,
    /// 是否执行过 execve；setpgid 据此拒绝修改子进程的进程组。
    pub did_exec: bool,
    /// 凭证；fork 继承，exec 保留。
    pub creds: Credentials,
    /// ITIMER_REAL 定时器：(下次单调触发时刻, 重复周期)；fork 清零，exec 保留。
    pub itimer_real: Option<(core::time::Duration, core::time::Duration)>,
    /// POSIX 进程定时器（timer_create）；不跨 fork 继承，exec/exit 时清空。
    pub posix_timers: Vec<posix_timer::PosixTimer>,
    /// 下一个待分配的 POSIX 定时器 ID（timer_t，非负递增）。
    pub next_timer_id: i32,
    /// 16 项 POSIX 资源限额（DATA/STACK/MEMLOCK/AS 与 space 同步，NOFILE 与 fs 同步）。
    pub rlimits: [[u64; 2]; RLIM_NLIMITS],
    /// PR_SET_DUMPABLE / PR_GET_DUMPABLE（0=不可转储，1=可转储；fork 继承，exec 重置为 1）。
    pub dumpable: u8,
    /// PR_SET_KEEPCAPS / PR_GET_KEEPCAPS（fork 继承，exec 清零）。
    pub keepcaps: bool,
    /// PR_SET_CHILD_SUBREAPER / PR_GET_CHILD_SUBREAPER（fork 清零，exec 保留）。
    pub child_subreaper: bool,
    /// PR_SET_THP_DISABLE / PR_GET_THP_DISABLE（fork 继承，exec 保留）。
    pub thp_disable: bool,
    /// PR_CAPBSET_READ / PR_CAPBSET_DROP 能力边界集（fork 继承，exec 保留）。
    pub cap_bset: u64,
    /// PR_SET_SECUREBITS / PR_GET_SECUREBITS（fork 继承，exec 保留）。
    pub securebits: u32,
}

/// 线程记录：线程私有的信号状态与 prctl 属性。地址空间等组级资源在 ProcessRecord。
pub struct ThreadRecord {
    pub tid: Pid,
    /// 所属线程组；单线程进程里与 tid 相同。
    pub tgid: Pid,
    /// 屏蔽字与备用栈；处置表与进程定向挂起在组记录里。
    pub signal: ThreadSig,
    pub clear_child_tid: usize,
    /// set_robust_list(2) 登记的用户态健壮互斥锁链表头地址，0 表示未登记。
    pub robust_list: usize,
    /// PR_SET_NAME / PR_GET_NAME 线程名（最长 15 字节加末尾 NUL）。
    pub comm: [u8; 16],
    /// PR_SET_PDEATHSIG：父进程退出时发送的信号号（0 表示未设置；fork/clone 清零）。
    pub pdeath_signal: u8,
    /// PR_SET_TIMERSLACK / PR_GET_TIMERSLACK（纳秒；fork/exec 继承）。
    pub timer_slack_ns: u64,
    /// 默认定时器松弛值（PR_SET_TIMERSLACK(0) 的恢复目标；fork/clone 继承父当前值）。
    pub default_timer_slack_ns: u64,
    /// PR_SET_NO_NEW_PRIVS：置位后不可撤销，跨 fork/clone/exec 继承。
    pub no_new_privs: bool,
}

/// 注册表本体。pid 0 保留（"无任务"标识）。
struct Registry {
    next_pid: Pid,
    records: Vec<ProcessRecord>,
    threads: Vec<ThreadRecord>,
}

static REGISTRY: DebugMutex<Registry> = DebugMutex::new(
    "REGISTRY",
    Registry {
        next_pid: 1,
        records: Vec::new(),
        threads: Vec::new(),
    },
);

impl Registry {
    /// 按 tid 取线程记录。
    pub(crate) fn thread(&self, tid: Pid) -> Option<&ThreadRecord> {
        self.threads.iter().find(|t| t.tid == tid)
    }

    /// 按 tid 取可变的线程记录。
    pub(crate) fn thread_mut(&mut self, tid: Pid) -> Option<&mut ThreadRecord> {
        self.threads.iter_mut().find(|t| t.tid == tid)
    }

    /// 按 tid 删除线程记录。
    pub(crate) fn remove_thread(&mut self, tid: Pid) {
        self.threads.retain(|t| t.tid != tid);
    }

    /// 删除某线程组下全部线程记录。
    pub(crate) fn remove_group_threads(&mut self, tgid: Pid) {
        self.threads.retain(|t| t.tgid != tgid);
    }

    /// 把线程号或进程号解析为线程组下标：先按 tid 查线程记录取其 tgid，找不到时按组记录自身的 pid 匹配。
    pub(crate) fn group_index(&self, pid: Pid) -> Option<usize> {
        let tgid = match self.thread(pid) {
            Some(thread) => thread.tgid,
            None => pid,
        };
        self.records.iter().position(|r| r.pid == tgid)
    }

    /// 按线程号或进程号取所属线程组记录。
    pub(crate) fn group(&self, pid: Pid) -> Option<&ProcessRecord> {
        self.records.get(self.group_index(pid)?)
    }

    /// 按线程号或进程号取所属线程组记录的可变引用。
    pub(crate) fn group_mut(&mut self, pid: Pid) -> Option<&mut ProcessRecord> {
        let index = self.group_index(pid)?;
        self.records.get_mut(index)
    }
}

/// `EXIT_REPORTS` 环形缓冲容量上限。
const MAX_EXIT_REPORTS: usize = 512;

/// 终态行积攒表：收割即删后注册表不留历史，输出推迟到时代结束，
/// 避免混入用户程序的测试输出块（官方 oracle 按 START/END 判定）。
static EXIT_REPORTS: DebugMutex<VecDeque<(Pid, &'static str, ExitInfo)>> =
    DebugMutex::new("EXIT_REPORTS", VecDeque::new());

/// 元素数远小于容量时缩容，分配失败则保留原缓冲。
fn maybe_shrink_vec<T>(v: &mut Vec<T>, min_cap: usize) {
    if v.capacity() > min_cap * 2 && v.len() * 4 <= v.capacity() {
        let target = v.len().max(min_cap);
        let mut compact = Vec::new();
        if compact.try_reserve_exact(target).is_ok() {
            compact.append(v);
            *v = compact;
        }
    }
}

/// procfs 的独立进程快照表：Task 在注册/退出/收割的提交点同步维护，
/// FS 读路径只取本表（不回调 REGISTRY——syscall 分发已持有该锁，
/// 重入会自旋死锁）。锁序 REGISTRY → PROC_TABLE 单向（见契约 §5）。
pub(crate) struct ProcEntry {
    pub pid: u32,
    pub name: &'static str,
    /// PR_SET_NAME / execve 维护的 16 字节进程名（NUL 结尾）。
    pub comm: [u8; 16],
    /// execve 提交后的真实 argv（NUL 分隔、末尾 NUL）；未 exec 过为 None
    pub cmdline: Option<alloc::vec::Vec<u8>>,
    /// b'R' 用户任务运行中 / b'S' 内核任务 / b'Z' 已退出未收割
    pub state: u8,
    pub ppid: u32,
    /// 进程组与会话。
    pub pgid: u32,
    pub sid: u32,
    /// 真实、有效、保存、文件系统用的用户号在前，组号在后。
    pub ids: [u32; 8],
    /// PR_SET_NO_NEW_PRIVS 状态（/proc/<pid>/status 的 NoNewPrivs 字段）。
    pub no_new_privs: bool,
    /// PR_SET_TIMERSLACK 当前值（/proc/<pid>/timerslack_ns）。
    pub timer_slack_ns: u64,
}
static PROC_TABLE: DebugMutex<alloc::vec::Vec<ProcEntry>> =
    DebugMutex::new("PROC_TABLE", alloc::vec::Vec::new());

/// 注册段预留一个快照条目（可失败段调用；提交段的 push 不会再分配）。
pub(crate) fn proc_table_reserve() -> Result<(), crate::syscall::Errno> {
    PROC_TABLE
        .lock()
        .try_reserve(1)
        .map_err(|_| crate::syscall::Errno::NoMem)
}

/// 提交段写入快照条目（预留已成功，push 不再分配）。
pub(crate) fn proc_table_push(pid: Pid, name: &'static str, ppid: Pid, user: bool) {
    let state = if user { b'R' } else { b'S' };
    PROC_TABLE.lock().push(ProcEntry {
        pid: pid as u32,
        name,
        comm: comm_from_bytes(name.as_bytes()),
        cmdline: None,
        state,
        ppid: ppid as u32,
        pgid: pid as u32,
        sid: pid as u32,
        ids: [0; 8],
        no_new_privs: false,
        timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
    });
}

/// 更新快照中的进程名（PR_SET_NAME / execve / fork 继承时同步）。
pub(crate) fn proc_table_set_comm(pid: Pid, comm: [u8; 16]) {
    if let Some(e) = PROC_TABLE.lock().iter_mut().find(|e| e.pid as Pid == pid) {
        e.comm = comm;
    }
}

/// 更新快照中的 NoNewPrivs 标志。
pub(crate) fn proc_table_set_no_new_privs(pid: Pid, value: bool) {
    if let Some(e) = PROC_TABLE.lock().iter_mut().find(|e| e.pid as Pid == pid) {
        e.no_new_privs = value;
    }
}

/// 更新快照中的 timer_slack_ns。
pub(crate) fn proc_table_set_timer_slack(pid: Pid, value: u64) {
    if let Some(e) = PROC_TABLE.lock().iter_mut().find(|e| e.pid as Pid == pid) {
        e.timer_slack_ns = value;
    }
}

/// 孤儿或 subreaper 过继时同步子进程快照的父 pid。
pub(crate) fn proc_table_reparent(old_parent: Pid, new_parent: Pid) {
    let mut table = PROC_TABLE.lock();
    for e in table.iter_mut() {
        if e.ppid as Pid == old_parent {
            e.ppid = new_parent as u32;
        }
    }
}

/// FS 读接口：按 pid 取 16 字节 comm。
pub fn proc_table_comm(pid: u32) -> Option<[u8; 16]> {
    PROC_TABLE
        .lock()
        .iter()
        .find(|e| e.pid == pid)
        .map(|e| e.comm)
}

/// FS 读接口：按 pid 取 NoNewPrivs 状态。
pub fn proc_table_no_new_privs(pid: u32) -> bool {
    PROC_TABLE
        .lock()
        .iter()
        .find(|e| e.pid == pid)
        .is_some_and(|e| e.no_new_privs)
}

/// FS 读接口：按 pid 取 timer_slack_ns。
pub fn proc_table_timer_slack(pid: u32) -> Option<u64> {
    PROC_TABLE
        .lock()
        .iter()
        .find(|e| e.pid == pid)
        .map(|e| e.timer_slack_ns)
}

/// 把进程组、会话与凭证写入 procfs 快照；调用方须已持 REGISTRY 锁。
pub(crate) fn proc_table_sync(pid: Pid, pgid: Pid, sid: Pid, ids: [u32; 8]) {
    if let Some(e) = PROC_TABLE.lock().iter_mut().find(|e| e.pid as Pid == pid) {
        e.pgid = pgid as u32;
        e.sid = sid as u32;
        e.ids = ids;
    }
}

/// FS 读接口：按 pid 取进程组、会话与八个身份号，不存在返回 None。
pub fn proc_table_identity(pid: u32) -> Option<(u32, u32, [u32; 8])> {
    PROC_TABLE
        .lock()
        .iter()
        .find(|e| e.pid == pid)
        .map(|e| (e.pgid, e.sid, e.ids))
}

/// execve 发布段更新真实 argv（cmdline）。
pub(crate) fn proc_table_set_cmdline(pid: Pid, cmdline: alloc::vec::Vec<u8>) {
    if let Some(e) = PROC_TABLE.lock().iter_mut().find(|e| e.pid as Pid == pid) {
        e.cmdline = Some(cmdline);
    }
}

/// 退出时置僵尸态（EXIT_REPORTS 积攒点调用）。
pub(crate) fn proc_table_mark_zombie(pid: Pid) {
    if let Some(e) = PROC_TABLE.lock().iter_mut().find(|e| e.pid as Pid == pid) {
        e.state = b'Z';
    }
}

/// 调度器挂起/唤醒主线程时同步 procfs 进程状态（b'S' / b'R'；不覆盖已置位的 b'Z'）。
/// 锁序：SCHED → PROC_TABLE（叶子锁，无环）。
pub(crate) fn proc_table_set_state(pid: Pid, state: u8) {
    if let Some(e) = PROC_TABLE.lock().iter_mut().find(|e| e.pid as Pid == pid) {
        if e.state != b'Z' {
            e.state = state;
        }
    }
}

/// 收割时移除快照（wait 收割 / 孤儿即收 / 父退出清理，均在 REGISTRY 段）。
pub(crate) fn proc_table_remove_all<F: Fn(u32) -> bool>(pred: F) {
    let mut table = PROC_TABLE.lock();
    table.retain(|e| !pred(e.pid));
    maybe_shrink_vec(&mut table, 32);
}

/// procfs 快照条目：(pid, 登记名, 状态字符, 父 pid, exec 后 argv)
pub type ProcRow = (u32, &'static str, u8, u32, Option<alloc::vec::Vec<u8>>);

/// FS 读接口：有界快照（克隆必要字段）。
pub fn proc_table_snapshot() -> alloc::vec::Vec<ProcRow> {
    let table = PROC_TABLE.lock();
    let mut out = alloc::vec::Vec::new();
    for e in table.iter() {
        if out.try_reserve_exact(1).is_err() {
            break; // 分配失败：返回已有部分并丢弃余量（上限 = 表长）
        }
        out.push((e.pid, e.name, e.state, e.ppid, e.cmdline.clone()));
    }
    out
}

/// procfs 属性读取：按 pid 查快照（不存在 → None，新打开报 ENOENT）。
pub fn proc_table_lookup(pid: u32) -> Option<(&'static str, u8, u32, Option<alloc::vec::Vec<u8>>)> {
    PROC_TABLE
        .lock()
        .iter()
        .find(|e| e.pid == pid)
        .map(|e| (e.name, e.state, e.ppid, e.cmdline.clone()))
}

/// 最早到期的 ITIMER_REAL 单调时刻（纳秒；u64::MAX 表示当前无活动定时器）。
static NEXT_ITIMER_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);

/// 在持 REGISTRY 锁下重算全局最早 ITIMER_REAL / POSIX 定时器触发时刻。
fn recompute_next_itimer(reg: &Registry) {
    let now_mono = crate::time::monotonic();
    let now_real = crate::time::realtime();
    let mut min_ns = u64::MAX;
    for r in reg.records.iter().filter(|r| r.exit.is_none()) {
        if let Some((d, _)) = r.itimer_real {
            min_ns = min_ns.min(d.as_nanos().min(u64::MAX as u128) as u64);
        }
        if !r.posix_timers.is_empty() {
            let cpu_ns = r.user_ns.saturating_add(r.system_ns);
            for t in &r.posix_timers {
                if let Some(d) = t.monotonic_wakeup(now_mono, now_real, cpu_ns) {
                    min_ns = min_ns.min(d.as_nanos().min(u64::MAX as u128) as u64);
                }
            }
        }
    }
    NEXT_ITIMER_NS.store(min_ns, core::sync::atomic::Ordering::Release);
}

/// 返回全局最早的 ITIMER_REAL / POSIX 定时器触发时刻（无活动定时器时返回 None）。
pub(super) fn next_itimer_deadline() -> Option<core::time::Duration> {
    let ns = NEXT_ITIMER_NS.load(core::sync::atomic::Ordering::Acquire);
    (ns != u64::MAX).then(|| core::time::Duration::from_nanos(ns))
}

/// 检查并触发所有已到期的 ITIMER_REAL 与 POSIX 定时器。
/// 仅在已到最早触发时刻时才加 REGISTRY 锁（调用方持有 SCHED 锁，满足 SCHED→REGISTRY 锁序）。
pub(super) fn fire_expired_itimers(now: core::time::Duration) -> bool {
    let now_ns = now.as_nanos().min(u64::MAX as u128) as u64;
    if now_ns < NEXT_ITIMER_NS.load(core::sync::atomic::Ordering::Acquire) {
        return false;
    }
    let now_real = crate::time::realtime();
    let mut reg = REGISTRY.lock();
    let mut fired = false;
    let sig_bit: signal::SignalSet = 1u64 << (signal::SIGALRM - 1);
    for idx in 0..reg.records.len() {
        if reg.records[idx].exit.is_some() {
            reg.records[idx].itimer_real = None;
            reg.records[idx].posix_timers.clear();
            continue;
        }
        if let Some((deadline, interval)) = reg.records[idx].itimer_real {
            if now >= deadline {
                let tgid = reg.records[idx].pid;
                let all_blocked = reg
                    .threads
                    .iter()
                    .filter(|t| t.tgid == tgid)
                    .all(|t| t.signal.blocked() & sig_bit != 0);
                let blocked = if all_blocked { sig_bit } else { 0 };
                let next = if !interval.is_zero() {
                    let mut d = deadline.saturating_add(interval);
                    if d <= now {
                        d = now.saturating_add(interval);
                    }
                    Some((d, interval))
                } else {
                    None
                };
                reg.records[idx].itimer_real = next;
                reg.records[idx].signal.generate(
                    signal::SIGALRM,
                    SigInfoSlot {
                        code: 0x80, // SI_KERNEL
                        ..Default::default()
                    },
                    blocked,
                );
                fired = true;
            }
        }
        if posix_timer::fire_process_timers(&mut reg, idx, now, now_real) {
            fired = true;
        }
    }
    recompute_next_itimer(&reg);
    fired
}

/// 注册表访问（调度器登记退出、用户循环取空间共用）。
mod registry {
    use super::*;

    /// 分配下一个 pid。失败路径会产生空洞（只要求唯一性）。
    pub fn alloc_pid() -> Pid {
        let mut reg = REGISTRY.lock();
        let pid = reg.next_pid;
        reg.next_pid += 1;
        pid
    }

    /// 登记前预留容量，错误不会留下半注册的任务。
    pub fn reserve() -> Result<(), SpawnError> {
        let mut reg = REGISTRY.lock();
        reg.records
            .try_reserve(1)
            .map_err(|_| SpawnError::OutOfMemory)?;
        reg.threads
            .try_reserve(1)
            .map_err(|_| SpawnError::OutOfMemory)
    }
    /// 登记一个进程记录（孵化提交段）。
    pub fn register(pid: Pid, name: &'static str, space: Option<LocalSpace>) {
        let mut reg = REGISTRY.lock();
        let comm = comm_from_bytes(name.as_bytes());
        reg.records.push(ProcessRecord {
            pid,
            name,
            space,
            exit: None,
            parent: 0,
            pgid: pid,
            sid: pid,
            did_exec: false,
            creds: Credentials::root(),
            itimer_real: None,
            posix_timers: Vec::new(),
            next_timer_id: 0,
            rlimits: default_rlimits(),
            dumpable: 1,
            keepcaps: false,
            child_subreaper: false,
            thp_disable: false,
            cap_bset: CAP_FULL_SET,
            securebits: 0,
            user_ns: 0,
            system_ns: 0,
            child_user_ns: 0,
            child_system_ns: 0,
            fs: None,
            signal: SignalGroup::new(),
        });
        reg.threads.push(ThreadRecord {
            tid: pid,
            tgid: pid,
            signal: ThreadSig::new(),
            clear_child_tid: 0,
            robust_list: 0,
            comm,
            pdeath_signal: 0,
            timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
            default_timer_slack_ns: DEFAULT_TIMER_SLACK_NS,
            no_new_privs: false,
        });
    }

    /// 登记一个新线程：信号状态与线程级 prctl 属性从父线程继承，pdeath_signal 清零。
    /// 调用方须持 REGISTRY 锁。
    pub fn register_thread(reg: &mut Registry, tid: Pid, tgid: Pid, parent_tid: Pid) {
        let mut signal = ThreadSig::new();
        let mut comm = comm_from_bytes(b"thread");
        let mut timer_slack_ns = DEFAULT_TIMER_SLACK_NS;
        let mut no_new_privs = false;
        if let Some(parent) = reg.thread(parent_tid) {
            signal.fork_from(&parent.signal);
            comm = parent.comm;
            timer_slack_ns = parent.timer_slack_ns;
            no_new_privs = parent.no_new_privs;
        }
        reg.threads.push(ThreadRecord {
            tid,
            tgid,
            signal,
            clear_child_tid: 0,
            robust_list: 0,
            comm,
            pdeath_signal: 0,
            timer_slack_ns,
            default_timer_slack_ns: timer_slack_ns,
            no_new_privs,
        });
    }

    /// 删除线程记录并判断线程组是否已全部退出。
    /// 返回 Some 表示这是组内最后一个线程，调用方接着按组退出处理。
    pub fn record_thread_exit(tid: Pid, exit: ExitInfo) -> Option<ExitInfo> {
        let mut reg = REGISTRY.lock();
        let tgid = reg.thread(tid)?.tgid;
        reg.remove_thread(tid);
        let remaining = reg.threads.iter().filter(|t| t.tgid == tgid).count();
        if remaining == 0 {
            return Some(exit);
        }
        None
    }

    /// 任务退出的唯一登记点：记录终态、释放地址空间并通知父进程。
    /// 终态行积攒到时代末统一输出；父 IGN/SA_NOCLDWAIT 时自动收割（通知不受影响）。
    /// space/fs 的 Drop 在锁外完成。
    pub fn record_exit(pid: Pid, exit: ExitInfo) {
        let taken = {
            let mut reg = REGISTRY.lock();
            let rec = reg.group_mut(pid).expect("exiting task is not registered");
            rec.exit = Some(exit);
            let had_itimer = rec.itimer_real.take().is_some() || !rec.posix_timers.is_empty();
            rec.posix_timers.clear();
            // 快照置僵尸（procfs 可见的存活规则与注册表一致）
            proc_table_mark_zombie(pid);
            // 积攒终态行；满容淘汰最旧条目，分配失败则丢弃。
            {
                let mut reports = EXIT_REPORTS.lock();
                if reports.len() >= MAX_EXIT_REPORTS {
                    reports.pop_front();
                }
                if reports.len() < MAX_EXIT_REPORTS && reports.try_reserve(1).is_ok() {
                    reports.push_back((pid, rec.name, exit));
                }
            }
            if let Some(local) = rec.space.as_ref() {
                local.as_space().deactivate();
            }
            let init = INIT_PID.load(core::sync::atomic::Ordering::Relaxed);
            let orphan = rec.parent == init;
            // 先复制出后续要用的字段，避免与 rec 借用重叠。
            let parent_pid = rec.parent;
            let (own_user, own_system, child_user, child_system) = (
                rec.user_ns,
                rec.system_ns,
                rec.child_user_ns,
                rec.child_system_ns,
            );
            let chld_slot = SigInfoSlot {
                code: match exit {
                    ExitInfo::Exited(_) => CLD_EXITED,
                    ExitInfo::Signaled { .. } => CLD_KILLED,
                },
                pid: pid as u32,
                status: match exit {
                    // wait4 口径：si_status 只保留低 8 位。
                    ExitInfo::Exited(n) => n & 255,
                    ExitInfo::Signaled { sig, .. } => sig as i32,
                },
                ..Default::default()
            };
            let taken = (rec.space.take(), rec.fs.take());
            if had_itimer {
                recompute_next_itimer(&reg);
            }
            // 自动收割（IGN/SA_NOCLDWAIT）与 SIGCHLD 通知解耦：前者决定
            // 是否留僵尸并入父时间，通知统一经 generate 按处置过滤。
            // 全程持 REGISTRY 锁内联完成。
            let auto_reap = if orphan {
                false
            } else {
                let parent_tgid = reg.thread(parent_pid).map_or(parent_pid, |t| t.tgid);
                let parent_blocked = reg.thread(parent_pid).map_or(0, |t| t.signal.blocked());
                match reg
                    .records
                    .iter_mut()
                    .find(|r| r.pid == parent_tgid && r.exit.is_none())
                {
                    Some(parent) => {
                        let d = parent.signal.disposition(SIGCHLD);
                        let auto_reap = d.handler == SIG_IGN || d.flags & SA_NOCLDWAIT != 0;
                        if auto_reap {
                            parent.child_user_ns = parent
                                .child_user_ns
                                .saturating_add(own_user.saturating_add(child_user));
                            parent.child_system_ns = parent
                                .child_system_ns
                                .saturating_add(own_system.saturating_add(child_system));
                        }
                        // SIGCHLD 生产点 IGN 无条件丢弃（do_notify_parent 的
                        // sig=0，屏蔽也不例外）；其余经 generate 过滤入队。
                        if d.handler != SIG_IGN {
                            parent.signal.generate(SIGCHLD, chld_slot, parent_blocked);
                        }
                        auto_reap
                    }
                    // 父记录不在表（如内核任务父为 0）：维持现状，不通知。
                    None => false,
                }
            };
            // 向上寻找最近的存活 child_subreaper 祖先；找不到则过继 init。
            let mut reparent_to = init;
            let mut cursor = reg.thread(parent_pid).map_or(parent_pid, |t| t.tgid);
            for _ in 0..reg.records.len() {
                if cursor == 0 || cursor == init || cursor == pid {
                    break;
                }
                let Some(ancestor) = reg
                    .records
                    .iter()
                    .find(|r| r.pid == cursor && r.exit.is_none())
                else {
                    break;
                };
                if ancestor.child_subreaper {
                    reparent_to = ancestor.pid;
                    break;
                }
                cursor = ancestor.parent;
            }
            // PR_SET_PDEATHSIG：向每个设置了父亡信号的存活子进程投递信号。
            let mut sent_pdeath = false;
            let reg_ref = &mut *reg;
            for child in reg_ref
                .records
                .iter_mut()
                .filter(|r| r.parent == pid && r.exit.is_none())
            {
                let child_tgid = child.pid;
                for thread in reg_ref
                    .threads
                    .iter()
                    .filter(|t| t.tgid == child_tgid && t.pdeath_signal != 0)
                {
                    child.signal.generate(
                        thread.pdeath_signal,
                        SigInfoSlot {
                            code: 0x80, // SI_KERNEL
                            pid: pid as u32,
                            ..Default::default()
                        },
                        thread.signal.blocked(),
                    );
                    sent_pdeath = true;
                }
            }
            if sent_pdeath {
                sched::request_signal_wake();
            }
            // 孤儿即收：无 subreaper 时清理已退出孩子及过继 init 的任务；
            // 有 subreaper 时将所有孩子（含僵尸）过继给 subreaper 并补发 SIGCHLD。
            let reap_zombies = reparent_to == init;
            let removed: alloc::vec::Vec<u32> = reg
                .records
                .iter()
                .filter(|r| {
                    (reap_zombies && r.parent == pid && r.exit.is_some())
                        || (r.pid == pid && (orphan || auto_reap))
                })
                .map(|r| r.pid as u32)
                .collect();
            reg.records.retain(|r| {
                !((reap_zombies && r.parent == pid && r.exit.is_some())
                    || (r.pid == pid && (orphan || auto_reap)))
            });
            for pid in &removed {
                reg.remove_thread(*pid as Pid);
            }
            maybe_shrink_vec(&mut reg.records, 32);
            maybe_shrink_vec(&mut reg.threads, 32);
            proc_table_remove_all(|p| removed.contains(&p));
            let mut adopted_zombie: Option<(Pid, ExitInfo)> = None;
            for child in reg.records.iter_mut().filter(|r| r.parent == pid) {
                child.parent = reparent_to;
                if let Some(info) = child.exit {
                    adopted_zombie = Some((child.pid, info));
                }
            }
            proc_table_reparent(pid, reparent_to);
            if reparent_to != init {
                if let Some((zpid, zexit)) = adopted_zombie {
                    let sub_blocked = reg
                        .threads
                        .iter()
                        .find(|t| t.tgid == reparent_to)
                        .map_or(0, |t| t.signal.blocked());
                    if let Some(sub) = reg
                        .records
                        .iter_mut()
                        .find(|r| r.pid == reparent_to && r.exit.is_none())
                    {
                        let d = sub.signal.disposition(SIGCHLD);
                        if d.handler != SIG_IGN {
                            sub.signal.generate(
                                SIGCHLD,
                                SigInfoSlot {
                                    code: match zexit {
                                        ExitInfo::Exited(_) => CLD_EXITED,
                                        ExitInfo::Signaled { .. } => CLD_KILLED,
                                    },
                                    pid: zpid as u32,
                                    status: match zexit {
                                        ExitInfo::Exited(n) => n & 255,
                                        ExitInfo::Signaled { sig, .. } => sig as i32,
                                    },
                                    ..Default::default()
                                },
                                sub_blocked,
                            );
                        }
                    }
                    sched::request_children_wake();
                }
            }
            // 自检：父进程退出清理或过继全部孩子，孤儿退出清理自身。
            debug_assert!(reg.records.iter().all(|r| r.parent != pid));
            debug_assert!(!orphan || reg.records.iter().all(|r| r.pid != pid));
            taken
        };
        // 锁外释放该进程持有的全部 POSIX 记录锁，再 Drop 地址空间与 FD 表。
        crate::fs::locks::release_process_locks(pid as u32);
        drop(taken);
    }

    /// wait 成功后收割：从表中删除记录并返回子进程的时间累计归属。
    /// 返回（pid, user_ns, system_ns）。
    pub fn reap_child(parent: Pid, target: Pid) -> Option<(u64, u64)> {
        let mut reg = REGISTRY.lock();
        let i = reg
            .records
            .iter()
            .position(|r| r.pid == target && r.parent == parent && r.exit.is_some())?;
        let rec = reg.records.remove(i);
        reg.remove_thread(target);
        maybe_shrink_vec(&mut reg.records, 32);
        maybe_shrink_vec(&mut reg.threads, 32);
        proc_table_remove_all(|p| p == target as u32);
        Some((
            rec.user_ns.saturating_add(rec.child_user_ns),
            rec.system_ns.saturating_add(rec.child_system_ns),
        ))
    }

    /// 注册表是否还有活跃（未退出）进程（init 自身除外）。
    pub fn any_alive() -> bool {
        let reg = REGISTRY.lock();
        reg.records.iter().any(|r| {
            r.pid != INIT_PID.load(core::sync::atomic::Ordering::Relaxed) && r.exit.is_none()
        })
    }

    /// 注册表条目数（自检用，仅 debug 构建调用）。
    #[cfg(debug_assertions)]
    pub fn records_len() -> usize {
        REGISTRY.lock().records.len()
    }

    /// 启动自检：注册表内不应再有未退出的任务（每次启动）。
    /// 终态报告在退出时积攒，这里统一输出。
    pub fn report_all() {
        for (pid, name, exit) in EXIT_REPORTS.lock().iter() {
            let line = match exit {
                ExitInfo::Exited(code) => {
                    alloc::format!("[task] pid {} ({}): exited with status {}", pid, name, code)
                }
                ExitInfo::Signaled { sig, fault } => match fault {
                    Some(f) => alloc::format!(
                        "[task] pid {} ({}): killed by {:?} @ {:#x}, pc {:#x}",
                        pid,
                        name,
                        f.kind,
                        f.info,
                        f.pc
                    ),
                    None => {
                        alloc::format!("[task] pid {} ({}): killed by signal {}", pid, name, sig)
                    }
                },
            };
            println!("{}", line);
            crate::dmesg::append(&line);
        }
    }
}

/// 孵化一个内核任务：入口函数在自己的内核栈上运行，返回即退出(0)。
pub fn spawn_kernel(name: &'static str, entry: fn()) -> Result<Pid, SpawnError> {
    let pid = registry::alloc_pid();
    let task =
        task::Task::new_kernel(pid, pid, name, entry).map_err(|_| SpawnError::OutOfMemory)?;
    let task = alloc::boxed::Box::try_new(task).map_err(|_| SpawnError::OutOfMemory)?;
    registry::reserve()?;
    sched::reserve_task().map_err(|_| SpawnError::OutOfMemory)?;
    registry::register(pid, name, None);
    proc_table_push(pid, name, 0, false);
    sched::enqueue(task);
    Ok(pid)
}

/// 初始化调度器；必须在任何 spawn 之前调用（spawn 会入队）。
pub fn init() {
    sched::init();
    let pid = spawn_kernel("init", init_task).expect("init allocation failed");
    INIT_PID.store(pid, core::sync::atomic::Ordering::Relaxed);
}
static INIT_PID: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
fn init_task() {
    // 孤儿退出时请求唤醒；每次醒来重查是否还有活跃进程。
    while registry::any_alive() {
        sched::park(WaitReason::Children);
    }
}

/// 孵化两个协作内核任务（独立内核栈、主动让出、正常退出）。
pub fn spawn_demo_kthreads() {
    for (name, body) in [("kthread-a", thread_a as fn()), ("kthread-b", thread_b)] {
        match spawn_kernel(name, body) {
            Ok(pid) => println!("[task] spawned {} as pid {}", name, pid),
            Err(e) => println!("[task] spawn {} failed: {:?}", name, e),
        }
    }
}

fn thread_a() {
    for i in 0..5 {
        println!("[kthread] A {}", i);
        if i != 4 {
            yield_now();
        }
    }
}

fn thread_b() {
    for i in 0..5 {
        println!("[kthread] B {}", i);
        if i != 4 {
            yield_now();
        }
    }
}

/// 自检：孵化 OOM 无副作用——零预算下孵化必须失败，且不改帧数、
/// 不登记注册表（仅 selftest 档运行）。
#[cfg(debug_assertions)]
fn spawn_oom_probe() {
    let before = mm::frame::stats();
    let before_len = registry::records_len();
    mm::frame::set_test_budget(Some(0));
    let result = spawn_kernel("oom-probe", || {});
    mm::frame::set_test_budget(None);
    assert!(
        matches!(result, Err(SpawnError::OutOfMemory)),
        "spawn under zero budget must fail"
    );
    assert_eq!(
        mm::frame::stats(),
        before,
        "failed spawn must not change frame stats"
    );
    assert_eq!(
        registry::records_len(),
        before_len,
        "failed spawn must not register"
    );
    log::info!("task: spawn OOM rejected without side effects");
}

#[cfg(not(debug_assertions))]
fn spawn_oom_probe() {}

/// 进入任务时代并运行到全部任务退出，返回前完成回收与帧守恒断言；
/// 返回后由调用方关机。
/// `baseline` 为任务时代前的帧统计，全部退出后必须回到同一数值。
pub fn run(baseline: (usize, usize)) {
    // 任务时代开始：内核关中断（用户态与 idle 等待两处例外，见契约）
    IRQ::int_disable();
    spawn_oom_probe();
    sched::run_loop();
    // 走到这里 = idle 判定全部退出，dead 已回收
    // 自检：帧守恒——全部任务退出后帧统计必须回到任务时代前的基线，
    // 覆盖内核栈与用户地址空间的回收（每次启动）
    if let Err(e) = crate::fs::cache::flush(None) {
        log::error!("shared page writeback pending at task exit: {:?}", e);
    }
    // 回收关机时仍驻留的 System V 共享内存段。
    mm::shm::clear_all();
    let (total, free) = mm::frame::stats();
    assert_eq!(
        (total, free + crate::fs::retained_frames()),
        baseline,
        "frame conservation violated after all tasks exited"
    );
    log::info!("task: all tasks exited, frame conservation holds");
    registry::report_all();
    println!("[task] all tasks done");
}

mod exec;
mod posix_timer;

#[cfg(debug_assertions)]
pub(crate) fn exec_self_test() {
    exec::self_test();
}
