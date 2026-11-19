//! 信号状态模型：每信号 disposition 表、pending/blocked 集合与信息槽。
//! 存放位置与线程化形状依据见 docs/ostd-contracts.md。
//! 模型先于投递逻辑落地：尚未被消费的项以 allow(dead_code) 标注，
//! 由接入方（后续 commit）移除。
#![deny(unsafe_code)]

use crate::trap::UserFaultKind;

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

/// 致命用户异常对应的终止信号号。
pub fn fault_signal(kind: UserFaultKind) -> u8 {
    match kind {
        UserFaultKind::StorePageFault
        | UserFaultKind::LoadPageFault
        | UserFaultKind::InstructionPageFault => SIGSEGV,
        UserFaultKind::IllegalInstruction | UserFaultKind::Unhandled => SIGILL,
        UserFaultKind::AddressNotAligned => SIGBUS,
        UserFaultKind::Breakpoint => SIGTRAP,
    }
}

/// SignalSet 的最小操作集：u64 别名无法定义固有方法（E0390），
/// 以扩展 trait 提供，调用形式不变。
#[allow(dead_code)]
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
/// flags/mask 本步仅存储不消费；默认值即 DFL。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SignalDisposition {
    /// 处理函数地址或 SIG_DFL/SIG_IGN。
    pub handler: usize,
    /// sa_flags（sigaction 传入，本步仅存储）。
    pub flags: u32,
    /// sa_mask（本步仅存储）。
    pub mask: SignalSet,
}

/// 每信号一个信息槽（信号号由槽位下标隐含）：siginfo 字段子集。
/// 本步只定义结构（默认全零），语义填充由投递阶段接入。
#[allow(dead_code)]
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
}

/// 单进程的信号状态。字段按将来多线程迁移的归属分两组：共享侧
/// 多线程时留 ProcessRecord，私有侧搬入线程记录（依据见
/// docs/ostd-contracts.md）。
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SignalState {
    /// —— 共享侧（多线程时留 ProcessRecord）——
    /// 每信号处置表，下标即信号号；[0] 不是合法信号，恒为默认值。
    disposition: [SignalDisposition; 65],
    /// 已到达未投递的信号位图。
    pending: SignalSet,
    /// 与 pending 对应的信息槽，仅在对应 pending 位有效时解释。
    info: [SigInfoSlot; 65],
    /// —— 私有侧（多线程时搬入线程记录）——
    /// 屏蔽位图。
    blocked: SignalSet,
}

impl SignalState {
    /// 全部处置为 DFL、pending/blocked 为空的新状态。
    pub fn new() -> Self {
        Self {
            disposition: [SignalDisposition::default(); 65],
            pending: 0,
            info: [SigInfoSlot::default(); 65],
            blocked: 0,
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

/// 下列接口的消费方（kill/sigaction/sigprocmask 与投递循环）在后续
/// commit 接入，此前压制 dead_code。
#[allow(dead_code)]
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

    /// 取出最低的 `pending & !blocked` 信号：清除其 pending 位并返回
    /// 信号号与信息槽拷贝；无可投递信号返回 None。SIGKILL/SIGSTOP
    /// 不受屏蔽约束属投递阶段语义，本方法只做纯集合运算。
    pub fn take_deliverable(&mut self, blocked: SignalSet) -> Option<(u8, SigInfoSlot)> {
        let sig = (self.pending & !blocked).lowest()?;
        let slot = self.info[sig as usize];
        self.pending.del(sig);
        Some((sig, slot))
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
}

impl Default for SignalState {
    /// 见 [`SignalState::new`]。
    fn default() -> Self {
        Self::new()
    }
}
