//! 信号状态模型：每信号处置表、pending/blocked 集合与信息槽。
//! 契约见 docs/ostd-contracts.md §4.5。
#![deny(unsafe_code)]

use super::task::Pid;
use super::REGISTRY;
use crate::syscall::Errno;
use crate::trap::{UserFault, UserFaultKind};

/// 信号位图：位 (sig-1) 对应信号 sig，合法域 1..=64。
pub type SignalSet = u64;

/// 默认处置。
pub const SIG_DFL: usize = 0;
/// 忽略处置。
pub const SIG_IGN: usize = 1;

/// SIGILL：非法指令。
pub const SIGILL: u8 = 4;
/// SIGTRAP：断点陷阱。
pub const SIGTRAP: u8 = 5;
/// SIGBUS：非对齐访存等总线错误。
pub const SIGBUS: u8 = 7;
/// SIGFPE：算术异常。
pub const SIGFPE: u8 = 8;
/// SIGSEGV：无效内存访问。
pub const SIGSEGV: u8 = 11;
/// SIGPIPE：向无读者的管道写入。
pub const SIGPIPE: u8 = 13;
/// SIGKILL：不可捕获、不可屏蔽的终止信号。
pub const SIGKILL: u8 = 9;
/// SIGCHLD：子进程终止。
pub const SIGCHLD: u8 = 17;
/// SIGSTOP：不可捕获、不可屏蔽的停止信号。
pub const SIGSTOP: u8 = 19;
/// SIGSYS：非法系统调用（同步信号）。
pub const SIGSYS: u8 = 31;

/// 同步异常信号掩码（SYNCHRONOUS_MASK）。
const SYNCHRONOUS_MASK: SignalSet = (1u64 << (SIGILL - 1))
    | (1u64 << (SIGTRAP - 1))
    | (1u64 << (SIGBUS - 1))
    | (1u64 << (SIGFPE - 1))
    | (1u64 << (SIGSEGV - 1))
    | (1u64 << (SIGSYS - 1));

/// siginfo si_code：SEGV_MAPERR，地址未映射（SIGSEGV）。
pub const SEGV_MAPERR: i32 = 1;
/// siginfo si_code：ILL_ILLOPC，非法操作码（SIGILL）。
pub const ILL_ILLOPC: i32 = 1;
/// siginfo si_code：BUS_ADRALN，地址未对齐（SIGBUS）。
pub const BUS_ADRALN: i32 = 1;
/// siginfo si_code：BUS_ADRERR，访问不存在/损坏的映射对象（SIGBUS）。
pub const BUS_ADRERR: i32 = 2;
/// siginfo si_code：TRAP_BRKPT，断点陷阱（SIGTRAP）。
pub const TRAP_BRKPT: i32 = 1;

/// 致命用户异常对应的 (信号号, si_code)。
pub fn fault_siginfo(kind: UserFaultKind) -> (u8, i32) {
    match kind {
        UserFaultKind::StorePageFault
        | UserFaultKind::LoadPageFault
        | UserFaultKind::InstructionPageFault => (SIGSEGV, SEGV_MAPERR),
        UserFaultKind::IllegalInstruction | UserFaultKind::Unhandled => (SIGILL, ILL_ILLOPC),
        UserFaultKind::AddressNotAligned => (SIGBUS, BUS_ADRALN),
        UserFaultKind::Breakpoint => (SIGTRAP, TRAP_BRKPT),
        UserFaultKind::FileBusError | UserFaultKind::FileIoError => (SIGBUS, BUS_ADRERR),
        UserFaultKind::UserFaultOom => (SIGKILL, 0),
    }
}

/// 信号的默认动作类别（signal(7) 默认处置表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    /// 终止进程。
    Term,
    /// 终止并核心转储。
    Core,
    /// 忽略。
    Ign,
    /// 停止进程。
    Stop,
    /// 继续执行。
    Cont,
}

/// 返回信号 sig 的默认动作类别（signal(7) 默认处置表）。
pub fn default_action(sig: u8) -> DefaultAction {
    match sig {
        3..=8 | 11 | 24 | 25 | 31 => DefaultAction::Core,
        17 | 23 | 28 => DefaultAction::Ign,
        18 => DefaultAction::Cont,
        19..=22 => DefaultAction::Stop,
        _ => DefaultAction::Term,
    }
}

/// SignalSet 的操作扩展 trait。
pub trait SignalSetExt {
    /// 置入信号 sig；sig 不在 1..=64 时保持不变。
    fn add(&mut self, sig: u8);
    /// 移除信号 sig；sig 不在 1..=64 时保持不变。
    fn del(&mut self, sig: u8);
    /// 信号 sig 是否在集合中；sig 不在 1..=64 时返回 false。
    fn has(self, sig: u8) -> bool;
    /// 取集合中优先出队的信号号；空集合返回 None。
    fn lowest(self) -> Option<u8>;
}

impl SignalSetExt for SignalSet {
    fn add(&mut self, sig: u8) {
        if !(1..=64).contains(&sig) {
            return;
        }
        *self |= 1u64 << (sig - 1);
    }

    fn del(&mut self, sig: u8) {
        if !(1..=64).contains(&sig) {
            return;
        }
        *self &= !(1u64 << (sig - 1));
    }

    fn has(self, sig: u8) -> bool {
        (1..=64).contains(&sig) && self & (1u64 << (sig - 1)) != 0
    }

    fn lowest(self) -> Option<u8> {
        if self == 0 {
            return None;
        }
        // 同步异常信号优先。
        let synchronous = self & SYNCHRONOUS_MASK;
        let chosen = if synchronous != 0 { synchronous } else { self };
        Some(chosen.trailing_zeros() as u8 + 1)
    }
}

/// 单个信号的处置：handler（SIG_DFL/SIG_IGN 或用户函数地址）、
/// sa_flags 与 sa_mask。
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalDisposition {
    /// 处理函数地址或 SIG_DFL/SIG_IGN。
    pub handler: usize,
    /// sa_flags（sigaction 传入）。
    pub flags: u32,
    /// sa_mask：建帧投递时并入 handler 期间的屏蔽集合。
    pub mask: SignalSet,
}

/// siginfo si_code：CLD_EXITED，子进程正常退出。
pub const CLD_EXITED: i32 = 1;
/// siginfo si_code：子进程死于信号。
pub const CLD_KILLED: i32 = 2;
/// siginfo si_code：SI_QUEUE，sigqueue 类发送。
pub const SI_QUEUE: i32 = -1;
/// siginfo si_code：SI_TKILL，tkill/tgkill 发送。
pub const SI_TKILL: i32 = -6;

/// stack_t ss_flags：SS_ONSTACK，当前在备用栈上执行。
pub(crate) const SS_ONSTACK: i32 = 1;
/// stack_t ss_flags：SS_DISABLE，备用栈未启用。
pub(crate) const SS_DISABLE: i32 = 2;

/// 每信号一个信息槽（信号号由槽位下标隐含）：siginfo 字段子集。
#[derive(Debug, Clone, Copy, Default)]
pub struct SigInfoSlot {
    /// si_code。
    pub code: i32,
    /// si_errno。
    pub errno: i32,
    /// 出错地址（SIGSEGV/SIGBUS 等填充）。
    pub addr: usize,
    /// 发送方 pid。
    pub pid: u32,
    /// 子进程退出状态（SIGCHLD 用）。
    pub status: i32,
    /// 硬件异常细节（force 投递填写）。
    pub fault: Option<UserFault>,
}

/// 信号备用栈登记（sigaltstack(2)）；enabled=false 时 sp/size 不解释。
#[derive(Debug, Clone, Copy, Default)]
pub struct AltStack {
    /// 栈基址（低地址端；用户栈向下增长）。
    sp: usize,
    /// 字节数；为 0 即未启用。
    size: usize,
    /// 是否启用（对应 sas_ss_size != 0）。
    enabled: bool,
}

impl AltStack {
    /// 用户栈指针 sp 是否落在备用栈区间内。
    fn on_stack(&self, sp: usize) -> bool {
        self.enabled && sp > self.sp && sp - self.sp <= self.size
    }

    /// sas_ss_flags 取值：未启用 SS_DISABLE、在栈上 SS_ONSTACK、否则 0。
    fn flags(&self, sp: usize) -> i32 {
        if !self.enabled {
            SS_DISABLE
        } else if self.on_stack(sp) {
            SS_ONSTACK
        } else {
            0
        }
    }
}

/// 信号组的信号状态。
#[derive(Debug)]
pub struct SignalGroup {
    /// 每信号处置表，下标即信号号；[0] 恒为默认值。
    disposition: [SignalDisposition; 65],
    /// 已到达未投递的信号位图。
    pending: SignalSet,
    /// 与 pending 对应的信息槽，仅在对应 pending 位有效时解释。
    info: [SigInfoSlot; 65],
}

impl Clone for SignalGroup {
    fn clone(&self) -> Self {
        Self {
            disposition: self.disposition,
            pending: self.pending,
            info: self.info,
        }
    }

    /// 就地拷贝各字段。
    fn clone_from(&mut self, source: &Self) {
        self.disposition.copy_from_slice(&source.disposition);
        self.pending = source.pending;
        self.info.copy_from_slice(&source.info);
    }
}

impl SignalGroup {
    /// 全部处置为 DFL、pending 为空的新状态。
    pub fn new() -> Self {
        Self {
            disposition: [SignalDisposition::default(); 65],
            pending: 0,
            info: [SigInfoSlot::default(); 65],
        }
    }

    /// execve 后的状态重置：处置恢复 DFL（SIG_IGN 保持）、flags/mask
    /// 清除；pending/info 保持不变。
    pub fn reset_for_exec(&mut self) {
        // 下标 0 不是合法信号，不在重置范围。
        for d in &mut self.disposition[1..] {
            let keep_ign = d.handler == SIG_IGN;
            *d = SignalDisposition {
                handler: if keep_ign { SIG_IGN } else { SIG_DFL },
                flags: 0,
                mask: 0,
            };
        }
    }
}

impl SignalGroup {
    /// 将信号 sig 置为 pending 并写入信息槽；sig 不在 1..=64 时
    /// 不修改状态，标准信号已在 pending 时不更新信息槽。
    pub fn queue(&mut self, sig: u8, slot: SigInfoSlot) {
        if !(1..=64).contains(&sig) {
            return;
        }
        if sig >= 32 || !self.pending.has(sig) {
            self.info[sig as usize] = slot;
        }
        self.pending.add(sig);
    }

    /// 同锁信号产生入口：按屏蔽字与处置过滤后将 sig 入队并请求信号唤醒。
    /// 调用方须已持 REGISTRY 锁；sig 须在 1..=64。
    pub fn generate(&mut self, sig: u8, slot: SigInfoSlot, blocked: SignalSet) {
        if !blocked.has(sig) {
            let d = self.disposition(sig);
            let ignored = d.handler == SIG_IGN
                || (d.handler == SIG_DFL
                    && matches!(
                        default_action(sig),
                        DefaultAction::Ign | DefaultAction::Cont
                    ));
            if ignored {
                return;
            }
        }
        self.queue(sig, slot);
        super::sched::request_signal_wake();
    }

    /// 设置信号 sig 的处置；sig 不在 1..=64 时不修改任何状态。
    pub fn set_disposition(&mut self, sig: u8, d: SignalDisposition) {
        if (1..=64).contains(&sig) {
            self.disposition[sig as usize] = d;
        }
    }

    /// 返回信号 sig 的处置；sig 不在 1..=64 时返回 DFL。
    pub fn disposition(&self, sig: u8) -> SignalDisposition {
        if (1..=64).contains(&sig) {
            self.disposition[sig as usize]
        } else {
            SignalDisposition::default()
        }
    }

    /// 当前 pending 位图（rt_sigpending 回写用）。
    pub fn pending(&self) -> SignalSet {
        self.pending
    }

    /// fork(2) 后子进程的信号组状态：处置继承自父进程，
    /// pending/info 清零。
    pub fn fork_from(&mut self, parent: &SignalGroup) {
        self.clone_from(parent);
        self.pending = 0;
        for slot in &mut self.info {
            *slot = SigInfoSlot::default();
        }
    }

    /// 清除信号 sig 的 pending 位与信息槽；域外信号不修改状态。
    pub fn flush(&mut self, sig: u8) {
        if (1..=64).contains(&sig) {
            self.pending.del(sig);
            self.info[sig as usize] = SigInfoSlot::default();
        }
    }

    /// 返回最低的可投递信号与信息槽拷贝，不清除 pending 位；
    /// 无信号返回 None。
    pub fn peek_deliverable(&self, blocked: SignalSet) -> Option<(u8, SigInfoSlot)> {
        let sig = (self.pending & !blocked).lowest()?;
        Some((sig, self.info[sig as usize]))
    }

    /// 取出最低的可投递信号：清除 pending 位并返回信号号与信息槽；
    /// 无信号返回 None。
    pub fn take_deliverable(&mut self, blocked: SignalSet) -> Option<(u8, SigInfoSlot)> {
        let sig = (self.pending & !blocked).lowest()?;
        let slot = self.info[sig as usize];
        self.pending.del(sig);
        Some((sig, slot))
    }
}

/// 单线程的信号状态。
#[derive(Debug)]
pub struct ThreadSig {
    /// 线程定向的已到达未投递信号位图。
    pending: SignalSet,
    /// 与 pending 对应的信息槽。
    info: [SigInfoSlot; 65],
    /// 屏蔽位图。
    blocked: SignalSet,
    /// 信号备用栈（sigaltstack），默认禁用。
    alt_stack: AltStack,
}

impl Clone for ThreadSig {
    fn clone(&self) -> Self {
        Self {
            pending: self.pending,
            info: self.info,
            blocked: self.blocked,
            alt_stack: self.alt_stack,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.pending = source.pending;
        self.info.copy_from_slice(&source.info);
        self.blocked = source.blocked;
        self.alt_stack = source.alt_stack;
    }
}

impl ThreadSig {
    /// 无挂起信号、屏蔽集合为空、备用栈禁用的新状态。
    pub fn new() -> Self {
        Self {
            pending: 0,
            info: [SigInfoSlot::default(); 65],
            blocked: 0,
            alt_stack: AltStack::default(),
        }
    }

    /// execve 后的状态重置：挂起与备用栈登记恢复默认。
    pub fn reset_for_exec(&mut self) {
        self.pending = 0;
        self.info = [SigInfoSlot::default(); 65];
        self.alt_stack = AltStack::default();
    }

    /// 把信号 sig 置为挂起并写入信息槽；标准信号已在挂起时不更新信息槽。
    pub fn queue(&mut self, sig: u8, slot: SigInfoSlot) {
        if !(1..=64).contains(&sig) {
            return;
        }
        if sig >= 32 || !self.pending.has(sig) {
            self.info[sig as usize] = slot;
        }
        self.pending.add(sig);
    }

    /// 清除信号 sig 的挂起位与信息槽。
    pub fn flush(&mut self, sig: u8) {
        if (1..=64).contains(&sig) {
            self.pending.del(sig);
            self.info[sig as usize] = SigInfoSlot::default();
        }
    }

    /// 当前线程挂起位图。
    pub fn pending(&self) -> SignalSet {
        self.pending
    }

    /// 返回最低的可投递信号与信息槽拷贝；mask 为不予投递的集合。
    pub fn peek_deliverable(&self, mask: SignalSet) -> Option<(u8, SigInfoSlot)> {
        let sig = (self.pending & !mask).lowest()?;
        Some((sig, self.info[sig as usize]))
    }

    /// 取出最低的可投递信号并清除挂起位。
    pub fn take_deliverable(&mut self, mask: SignalSet) -> Option<(u8, SigInfoSlot)> {
        let sig = (self.pending & !mask).lowest()?;
        let slot = self.info[sig as usize];
        self.pending.del(sig);
        Some((sig, slot))
    }

    /// 把 add 中的信号加入屏蔽集合。
    pub fn block(&mut self, add: SignalSet) {
        self.blocked |= add;
    }

    /// 把 remove 中的信号移出屏蔽集合。
    pub fn unblock(&mut self, remove: SignalSet) {
        self.blocked &= !remove;
    }

    /// 整体替换屏蔽集合。
    pub fn setmask(&mut self, mask: SignalSet) {
        self.blocked = mask;
    }

    /// 当前屏蔽集合（rt_sigprocmask 回写 oldset 用）。
    pub fn blocked(&self) -> SignalSet {
        self.blocked
    }

    /// 备用栈登记；启用时返回 (基址, 字节数)。
    pub fn alt_stack(&self) -> Option<(usize, usize)> {
        self.alt_stack
            .enabled
            .then_some((self.alt_stack.sp, self.alt_stack.size))
    }

    /// 当前用户栈指针 sp 是否在备用栈区间内。
    pub fn on_alt_stack(&self, sp: usize) -> bool {
        self.alt_stack.on_stack(sp)
    }

    /// sas_ss_flags 的当前取值（old stack_t 的 ss_flags 回写）。
    pub fn alt_stack_flags(&self, sp: usize) -> i32 {
        self.alt_stack.flags(sp)
    }

    /// 设置备用栈登记。
    pub fn set_alt_stack(&mut self, sp: usize, size: usize, enabled: bool) {
        self.alt_stack = AltStack { sp, size, enabled };
    }

    /// fork(2) 后子线程的信号状态：屏蔽与备用栈继承自父线程，挂起清零。
    pub fn fork_from(&mut self, parent: &ThreadSig) {
        self.blocked = parent.blocked;
        self.alt_stack = parent.alt_stack;
        self.pending = 0;
        self.info = [SigInfoSlot::default(); 65];
    }
}

/// 组定向与线程定向挂起里最低的可投递信号；mask 为不予投递的集合。
pub fn peek_any(
    group: &SignalGroup,
    thread: &ThreadSig,
    mask: SignalSet,
) -> Option<(u8, SigInfoSlot)> {
    let sig = ((group.pending() | thread.pending()) & !mask).lowest()?;
    Some((sig, slot_of(group, thread, sig)))
}

fn slot_of(group: &SignalGroup, thread: &ThreadSig, sig: u8) -> SigInfoSlot {
    if thread.pending().has(sig) {
        thread.info[sig as usize]
    } else {
        group.info[sig as usize]
    }
}

/// 取出组定向与线程定向挂起里最低的可投递信号。
pub fn take_any(
    group: &mut SignalGroup,
    thread: &mut ThreadSig,
    mask: SignalSet,
) -> Option<(u8, SigInfoSlot)> {
    let sig = ((group.pending() | thread.pending()) & !mask).lowest()?;
    let slot = slot_of(group, thread, sig);
    if thread.pending().has(sig) {
        thread.pending.del(sig);
    } else {
        group.flush(sig);
    }
    Some((sig, slot))
}

/// 线程定向入队：按线程屏蔽字与组处置过滤后写入线程挂起集合。
pub fn generate_thread(group: &SignalGroup, thread: &mut ThreadSig, sig: u8, slot: SigInfoSlot) {
    if !thread.blocked().has(sig) {
        let d = group.disposition(sig);
        let ignored = d.handler == SIG_IGN
            || (d.handler == SIG_DFL
                && matches!(
                    default_action(sig),
                    DefaultAction::Ign | DefaultAction::Cont
                ));
        if ignored {
            return;
        }
    }
    thread.queue(sig, slot);
    super::sched::request_signal_wake();
}

/// 锁外信号产生入口（kill/tgkill）：取 REGISTRY 锁并调用 generate。
/// 目标不存在或已退出返回 ESRCH；已持锁调用方须改用 generate。
pub fn send_signal(target: Pid, sig: u8, slot: SigInfoSlot) -> Result<(), Errno> {
    let mut reg = REGISTRY.lock();
    let blocked = reg.thread(target).map_or(0, |t| t.signal.blocked());
    let rec = reg
        .group_mut(target)
        .filter(|r| r.exit.is_none())
        .ok_or(Errno::NoProcess)?;
    rec.signal.generate(sig, slot, blocked);
    Ok(())
}

/// force 语义的信号产生入口：重置 IGN 处置并解蔽后入队，
/// 同步信号因此不可屏蔽或忽略。
/// 调用方不得持 REGISTRY 锁。
pub fn force_signal(target: Pid, sig: u8, slot: SigInfoSlot) {
    let mut locked = REGISTRY.lock();
    let reg = &mut *locked;
    if reg.group(target).is_none_or(|r| r.exit.is_some()) {
        return;
    }
    let mut one: SignalSet = 0;
    one.add(sig);
    let blocked = match reg.threads.iter_mut().find(|t| t.tid == target) {
        Some(thread) => {
            thread.signal.unblock(one);
            thread.signal.blocked()
        }
        None => 0,
    };
    if let Some(rec) = reg.group_mut(target) {
        if rec.signal.disposition(sig).handler == SIG_IGN {
            rec.signal
                .set_disposition(sig, SignalDisposition::default());
        }
        rec.signal.generate(sig, slot, blocked);
    }
}

impl Default for SignalGroup {
    /// 见 [`SignalGroup::new`]。
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ThreadSig {
    fn default() -> Self {
        Self::new()
    }
}
