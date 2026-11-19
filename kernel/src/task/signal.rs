//! 信号状态模型：每信号 disposition 表、pending/blocked 集合与信息槽。
//! 存放位置与线程化形状依据见 docs/ostd-contracts.md。
//! 消费侧：投递检查点（含建帧投递）/ park 快路径 / 信号登记类系统调用。
#![deny(unsafe_code)]

use super::task::Pid;
use super::REGISTRY;
use crate::syscall::Errno;
use crate::trap::{UserFault, UserFaultKind};

/// 信号位图：位 (sig-1) 对应信号 sig，合法信号 1..=64
///（标准 1..=31，实时 32..=64）。
pub type SignalSet = u64;

/// 默认处置（Linux UAPI 值）。
pub const SIG_DFL: usize = 0;
/// 忽略处置（Linux UAPI 值）。
pub const SIG_IGN: usize = 1;

/// SIGILL：非法指令。
pub const SIGILL: u8 = 4;
/// SIGTRAP：断点陷阱。
pub const SIGTRAP: u8 = 5;
/// SIGBUS：非对齐访存等总线错误。
pub const SIGBUS: u8 = 7;
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

/// siginfo si_code 子集（来源：Linux include/uapi/asm-generic/siginfo.h）：
/// SEGV_MAPERR，地址未映射（SIGSEGV）。
pub const SEGV_MAPERR: i32 = 1;
/// siginfo si_code：ILL_ILLOPC，非法操作码（SIGILL）。
pub const ILL_ILLOPC: i32 = 1;
/// siginfo si_code：BUS_ADRALN，地址未对齐（SIGBUS）。
pub const BUS_ADRALN: i32 = 1;
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
    }
}

/// 信号的默认动作类别（signal(7) 默认处置表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAction {
    /// 终止进程。
    Term,
    /// 终止并核心转储（消费方：投递阶段）。
    Core,
    /// 忽略。
    Ign,
    /// 停止进程（消费方：投递阶段）。
    Stop,
    /// 被停止的进程继续执行（消费方：投递阶段）。
    Cont,
}

/// 默认动作表，信号号为 asm-generic UAPI（rv64/la64，SIGRTMIN=32）：
/// Core = 3/4/5/6/7/8/11/24/25/31，Ign = 17/23/28，Cont = 18，
/// Stop = 19..=22，其余标准信号与实时信号 32..=64 为 Term。
/// 取值与 man7.org signal(7) 表逐项核对，并同内核 include/linux/signal.h
/// 的 SIG_KERNEL_{COREDUMP,IGNORE,STOP}_MASK 三组掩码一致。
pub fn default_action(sig: u8) -> DefaultAction {
    match sig {
        3..=8 | 11 | 24 | 25 | 31 => DefaultAction::Core,
        17 | 23 | 28 => DefaultAction::Ign,
        18 => DefaultAction::Cont,
        19..=22 => DefaultAction::Stop,
        _ => DefaultAction::Term,
    }
}

/// SignalSet 的最小操作集：u64 别名无法定义固有方法（E0390），
/// 以扩展 trait 提供，调用形式不变。
pub trait SignalSetExt {
    /// 置入信号 sig；sig 不在 1..=64 时保持不变。
    fn add(&mut self, sig: u8);
    /// 移除信号 sig；sig 不在 1..=64 时保持不变。
    fn del(&mut self, sig: u8);
    /// 信号 sig 是否在集合中；sig 不在 1..=64 时返回 false。
    fn has(self, sig: u8) -> bool;
    /// 取集合中最小的信号号（按信号号从小到大取出，与 Linux 一致）；
    /// 空集合返回 None。
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
            None
        } else {
            Some(self.trailing_zeros() as u8 + 1)
        }
    }
}

/// 单个信号的处置：handler 为 SIG_DFL/SIG_IGN 或用户函数地址。
/// flags 由 record_exit（SA_NOCLDWAIT）、park 快路径（SA_RESTART）与
/// 建帧投递（SA_NODEFER/SA_SIGINFO/SA_ONSTACK 固定语义处理）消费；
/// mask 由建帧投递并入 handler 期间屏蔽集合；默认值即 DFL。
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalDisposition {
    /// 处理函数地址或 SIG_DFL/SIG_IGN。
    pub handler: usize,
    /// sa_flags（sigaction 传入）。
    pub flags: u32,
    /// sa_mask：建帧投递时并入 handler 期间的屏蔽集合。
    pub mask: SignalSet,
}

/// siginfo si_code 子集（来源：Linux include/uapi/asm-generic/siginfo.h）。
/// CLD_EXITED：子进程正常退出。
pub const CLD_EXITED: i32 = 1;
/// siginfo si_code：子进程死于信号。
pub const CLD_KILLED: i32 = 2;
/// siginfo si_code 负码：SI_QUEUE，sigqueue/rt_sigqueueinfo 发送，
/// siginfo 联合体按 _rt{pid, uid, value} 解释。
pub const SI_QUEUE: i32 = -1;
/// siginfo si_code 负码：SI_TKILL，tkill/tgkill 发送（内核保留码，
/// rt_sigqueueinfo 非自身目标发送被拒）。
pub const SI_TKILL: i32 = -6;

/// stack_t ss_flags（来源：Linux include/uapi/linux/signal.h）：
/// SS_ONSTACK，当前在备用栈上执行。
pub(crate) const SS_ONSTACK: i32 = 1;
/// stack_t ss_flags：SS_DISABLE，备用栈未启用。
pub(crate) const SS_DISABLE: i32 = 2;

/// 每信号一个信息槽（信号号由槽位下标隐含）：siginfo 字段子集。
/// 产生侧只填充 code/pid/status 子集，force 投递另填 fault（硬件异常
/// 细节，检查点终止时透传终态报告）；全部字段由建帧投递的 siginfo
/// 组装（sigframe::fill_siginfo）读出。
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
    /// 硬件异常细节：force 投递路径（致命异常）填充，检查点终止时
    /// 透传给终态报告。
    pub fault: Option<UserFault>,
}

/// 信号备用栈登记（sigaltstack(2) 的内核侧记录，对应 Linux task_struct
/// 的 sas_ss_* 三元组）。enabled=false 时 sp/size 不解释。属线程私有侧，
/// 多线程时随 blocked 一并搬入线程记录。
#[derive(Debug, Clone, Copy, Default)]
pub struct AltStack {
    /// 栈基址（低地址端；用户栈向下增长）。
    sp: usize,
    /// 字节数（对应 Linux sas_ss_size；为 0 即未启用）。
    size: usize,
    /// 是否启用（对应 sas_ss_size != 0）。
    enabled: bool,
}

impl AltStack {
    /// 用户栈指针 sp 是否落在备用栈区间内。公式同 Linux on_sig_stack
    ///（include/linux/sched/signal.h，向下增长分支）：sp 严格大于基址
    /// 且偏移不超过 size（含上边界）。
    fn on_stack(&self, sp: usize) -> bool {
        self.enabled && sp > self.sp && sp - self.sp <= self.size
    }

    /// Linux sas_ss_flags：未启用 → SS_DISABLE；在栈上 → SS_ONSTACK；
    /// 启用且不在栈上 → 0。
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

/// 单进程的信号状态。字段按将来多线程迁移的归属分两组：共享侧
/// 多线程时留 ProcessRecord，私有侧搬入线程记录（依据见
/// docs/ostd-contracts.md）。
#[derive(Debug, Clone)]
pub struct SignalState {
    /// —— 共享侧（多线程时留 ProcessRecord）——
    /// 每信号处置表，下标即信号号；[0] 不是合法信号，恒为默认值。
    disposition: [SignalDisposition; 65],
    /// 已到达未投递的信号位图。
    pending: SignalSet,
    /// 与 pending 对应的信息槽，仅在对应 pending 位有效时解释，
    /// 由 [`SignalState::take_deliverable`] 连同 pending 位一并取出。
    info: [SigInfoSlot; 65],
    /// —— 私有侧（多线程时搬入线程记录）——
    /// 屏蔽位图。
    blocked: SignalSet,
    /// 信号备用栈（sigaltstack），默认禁用。
    alt_stack: AltStack,
}

impl SignalState {
    /// 全部处置为 DFL、pending/blocked 为空、备用栈禁用的新状态。
    pub fn new() -> Self {
        Self {
            disposition: [SignalDisposition::default(); 65],
            pending: 0,
            info: [SigInfoSlot::default(); 65],
            blocked: 0,
            alt_stack: AltStack::default(),
        }
    }

    /// execve 后的状态重置：处置全部恢复 DFL，恰为 SIG_IGN 的保持
    /// IGN；flags/mask 清零；pending/info 与 blocked 保持不变
    ///（execve(2) 语义）。
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

impl SignalState {
    /// 将信号 sig 置为 pending 并写入信息槽；sig 不在 1..=64 时
    /// 不修改任何状态。
    pub fn queue(&mut self, sig: u8, slot: SigInfoSlot) {
        if !(1..=64).contains(&sig) {
            return;
        }
        self.pending.add(sig);
        self.info[sig as usize] = slot;
    }

    /// 同锁信号产生入口：record_exit 与 syscall 层在已持 REGISTRY 锁
    /// 时内联调用（锁非重入，禁止再经 send_signal 嵌套取锁）。过滤
    /// 规则对应 Linux __send_signal/sig_ignored（kernel/signal.c）：
    /// 屏蔽中的信号照常入队（sig_ignored 对 blocked 恒 false）；处置
    /// IGN，或 DFL 且默认动作属 IGNORE 集（CHLD/CONT/URG/WINCH，即
    /// 本表 Ign 与 Cont 两类，对应 include/linux/signal.h 的
    /// SIG_KERNEL_IGNORE_MASK）的信号静默丢弃；其余入队，实际入队后
    /// 请求信号唤醒通道（send_signal 亦经此路径覆盖）；过滤丢弃不置位。
    /// pending 消费与投递属投递阶段 commit。调用方保证 sig 在合法域
    /// 1..=64；queue 对域外信号不修改状态。
    pub fn generate(&mut self, sig: u8, slot: SigInfoSlot) {
        if !self.blocked.has(sig) {
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

    /// 把 add 中的信号加入屏蔽集合。
    pub fn block(&mut self, add: SignalSet) {
        self.blocked |= add;
    }

    /// 把 remove 中的信号移出屏蔽集合。
    pub fn unblock(&mut self, remove: SignalSet) {
        self.blocked &= !remove;
    }

    /// 整体替换屏蔽集合（sigprocmask 的 SIG_SETMASK 语义）。
    pub fn setmask(&mut self, mask: SignalSet) {
        self.blocked = mask;
    }

    /// 当前屏蔽集合（rt_sigprocmask 回写 oldset 用）。
    pub fn blocked(&self) -> SignalSet {
        self.blocked
    }

    /// 备用栈登记；启用时返回 (基址, 字节数)，供 SA_ONSTACK 建帧
    /// 投递选栈（sigframe::build_deliver）。
    pub fn alt_stack(&self) -> Option<(usize, usize)> {
        self.alt_stack
            .enabled
            .then_some((self.alt_stack.sp, self.alt_stack.size))
    }

    /// 当前用户栈指针 sp 是否在备用栈区间内（sigaltstack 的 EPERM
    /// 检查与 SS_ONSTACK 回写共用）。
    pub fn on_alt_stack(&self, sp: usize) -> bool {
        self.alt_stack.on_stack(sp)
    }

    /// Linux sas_ss_flags 的当前取值（old stack_t 的 ss_flags 回写）。
    pub fn alt_stack_flags(&self, sp: usize) -> i32 {
        self.alt_stack.flags(sp)
    }

    /// 整体设置备用栈登记（sigaltstack(2)：SS_DISABLE 置禁用，否则
    /// 登记 sp/size 启用）。
    pub fn set_alt_stack(&mut self, sp: usize, size: usize, enabled: bool) {
        self.alt_stack = AltStack { sp, size, enabled };
    }

    /// 当前 pending 位图（rt_sigpending 回写用）。
    pub fn pending(&self) -> SignalSet {
        self.pending
    }

    /// 非消费版 take_deliverable：返回最低的 `pending & !blocked` 信号
    /// 与信息槽拷贝，不清除 pending 位；无可投递信号返回 None。供
    /// park 快路径先按处置分岔、再决定是否消费的场景。
    pub fn peek_deliverable(&self, blocked: SignalSet) -> Option<(u8, SigInfoSlot)> {
        let sig = (self.pending & !blocked).lowest()?;
        Some((sig, self.info[sig as usize]))
    }

    /// 取出最低的 `pending & !blocked` 信号：清除其 pending 位并返回
    /// 信号号与信息槽拷贝；无可投递信号返回 None。SIGKILL/SIGSTOP
    /// 不可能出现在 blocked（产生/登记侧已剥除），本方法只做纯集合
    /// 运算；调用方取出后不放回（任一去向均视为已消费）。
    pub fn take_deliverable(&mut self, blocked: SignalSet) -> Option<(u8, SigInfoSlot)> {
        let sig = (self.pending & !blocked).lowest()?;
        let slot = self.info[sig as usize];
        self.pending.del(sig);
        Some((sig, slot))
    }
}

/// 锁外路径的信号产生入口（kill/tgkill）：取 REGISTRY 锁、找活跃
/// 目标后交 [`SignalState::generate`] 过滤入队。目标不存在或已退出
///（僵尸）返回 ESRCH。已持 REGISTRY 锁的调用方须改用
/// [`SignalState::generate`]（锁非重入，不可嵌套取锁）。
pub fn send_signal(target: Pid, sig: u8, slot: SigInfoSlot) -> Result<(), Errno> {
    let mut reg = REGISTRY.lock();
    let rec = reg
        .records
        .iter_mut()
        .find(|r| r.pid == target && r.exit.is_none())
        .ok_or(Errno::NoProcess)?;
    rec.signal.generate(sig, slot);
    Ok(())
}

/// force 语义的信号产生入口（对应 Linux force_sig_info，kernel/signal.c）：
/// 同步（硬件）信号不可被屏蔽或忽略——否则装 IGN 的程序访存出错会在
/// 同一条指令上无限陷阱循环。取 REGISTRY 锁找活跃记录（force 目标恒为
/// 自身，找不到仅防御返回），对该信号：IGN 处置重置为 DFL（flags/mask
/// 一并清），从 blocked 清除该信号位，再 generate（此时必入队）。
/// 已持 REGISTRY 锁的调用方禁止使用（锁非重入）。
pub fn force_signal(target: Pid, sig: u8, slot: SigInfoSlot) {
    let mut reg = REGISTRY.lock();
    if let Some(rec) = reg
        .records
        .iter_mut()
        .find(|r| r.pid == target && r.exit.is_none())
    {
        if rec.signal.disposition(sig).handler == SIG_IGN {
            rec.signal
                .set_disposition(sig, SignalDisposition::default());
        }
        let mut one: SignalSet = 0;
        one.add(sig);
        rec.signal.unblock(one);
        rec.signal.generate(sig, slot);
    }
}

impl Default for SignalState {
    /// 见 [`SignalState::new`]。
    fn default() -> Self {
        Self::new()
    }
}
