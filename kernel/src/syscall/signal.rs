//! 信号类系统调用：rt_sigaction/rt_sigprocmask/rt_sigpending/rt_sigaltstack。
//! 对应 Linux kernel/signal.c 的 sys_rt_sig* 系列与 sys_sigaltstack。
//! 支持范围与偏差见 docs/ostd-contracts.md §4。
#![deny(unsafe_code)]

use super::Errno;
use crate::mm::{address_space::UserAddressSpace, user_access};
use crate::task::signal::{
    default_action, DefaultAction, SignalDisposition, SignalGroup, SignalSet, SignalSetExt,
    ThreadSig, SIGKILL, SIGSTOP, SIG_DFL, SIG_IGN, SS_DISABLE,
};

/// SA_* 与 SIG_BLOCK/UNBLOCK/SETMASK 的 UAPI 值
///（include/uapi/asm-generic/signal-defs.h，rv64/la64 共用）。
#[allow(dead_code)]
const SA_NOCLDSTOP: u32 = 0x0000_0001;
pub(crate) const SA_NOCLDWAIT: u32 = 0x0000_0002;
/// SA_SIGINFO：rv/la ABI 恒传 siginfo/ucontext 三参。
#[allow(dead_code)]
const SA_SIGINFO: u32 = 0x0000_0004;
/// SA_RESTORER：rv/la 无 restorer 语义，存储时剥除。
const SA_RESTORER: u32 = 0x0400_0000;
/// SA_ONSTACK：帧落备用栈顶。
pub(crate) const SA_ONSTACK: u32 = 0x0800_0000;
pub(crate) const SA_RESTART: u32 = 0x1000_0000;
/// SA_NODEFER：进入处理函数期间不自动屏蔽本信号。
pub(crate) const SA_NODEFER: u32 = 0x4000_0000;
/// SA_RESETHAND：进入处理函数后把本信号处置复位为默认动作。
pub(crate) const SA_RESETHAND: u32 = 0x8000_0000;
const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
const SIG_SETMASK: usize = 2;

/// 内核 sigset_t 字节数：内核侧 sigset 为单个 u64（1..=64）。
pub(crate) const SIGSETSIZE: usize = 8;

/// rt_sigaction 的 syscall 层结构（24 字节：handler、flags、mask）。
/// rv64/la64 无 SA_RESTORER，布局同 {handler, flags, mask}。
#[derive(Debug, Clone, Copy)]
struct KernelSigAction {
    handler: usize,
    flags: u32,
    mask: SignalSet,
}

impl KernelSigAction {
    const SIZE: usize = 24;

    fn from_bytes(raw: &[u8; Self::SIZE]) -> Self {
        Self {
            handler: usize::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8])),
            flags: u64::from_ne_bytes(raw[8..16].try_into().unwrap_or([0; 8])) as u32,
            mask: u64::from_ne_bytes(raw[16..24].try_into().unwrap_or([0; 8])),
        }
    }

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut raw = [0u8; Self::SIZE];
        raw[0..8].copy_from_slice(&self.handler.to_ne_bytes());
        raw[8..16].copy_from_slice(&(self.flags as u64).to_ne_bytes());
        raw[16..24].copy_from_slice(&self.mask.to_ne_bytes());
        raw
    }
}

/// rt_sigaction(2)：单信号处置的读改写，成功返回 0。sigsetsize 须为 8，
/// sig 合法域 1..=64，SIGKILL/SIGSTOP 仅不可改写。
/// act/oact 可分别为空。
pub(super) fn rt_sigaction(
    space: &crate::mm::address_space::UserAddressSpace,
    sig: usize,
    act: usize,
    oact: usize,
    sigsetsize: usize,
    state: &mut SignalGroup,
) -> Result<usize, Errno> {
    if sigsetsize != SIGSETSIZE || !(1..=64).contains(&sig) {
        return Err(Errno::Invalid);
    }
    let sig = sig as u8;
    if act != 0 && (sig == SIGKILL || sig == SIGSTOP) {
        return Err(Errno::Invalid);
    }
    if act != 0 {
        let mut raw = [0u8; KernelSigAction::SIZE];
        user_access::copy_from_user(space, act, &mut raw).map_err(|_| Errno::Fault)?;
        let mut action = KernelSigAction::from_bytes(&raw);
        // SA_RESTORER 位忽略；SIGKILL/SIGSTOP 不可屏蔽，入表前剥除。
        action.flags &= !SA_RESTORER;
        action.mask.del(SIGKILL);
        action.mask.del(SIGSTOP);
        // 旧处置先快照：oact 回写调用前的值。
        let old = (oact != 0).then(|| state.disposition(sig));
        state.set_disposition(
            sig,
            SignalDisposition {
                handler: action.handler,
                flags: action.flags,
                mask: action.mask,
            },
        );
        // 处置转为忽略时冲刷该信号已排队的状态。
        let ignored = action.handler == SIG_IGN
            || (action.handler == SIG_DFL
                && matches!(
                    default_action(sig),
                    DefaultAction::Ign | DefaultAction::Cont
                ));
        if ignored {
            state.flush(sig);
        }
        if let Some(old) = old {
            let old = KernelSigAction {
                handler: old.handler,
                flags: old.flags,
                mask: old.mask,
            };
            user_access::copy_to_user(space, oact, &old.to_bytes()).map_err(|_| Errno::Fault)?;
        }
    } else if oact != 0 {
        let old = state.disposition(sig);
        let old = KernelSigAction {
            handler: old.handler,
            flags: old.flags,
            mask: old.mask,
        };
        user_access::copy_to_user(space, oact, &old.to_bytes()).map_err(|_| Errno::Fault)?;
    }
    Ok(0)
}

/// rt_sigprocmask(2)：改读屏蔽集合，成功返回 0。sigsetsize 须为 8，
/// how 为 SIG_BLOCK/SIG_UNBLOCK/SIG_SETMASK，KILL/STOP 位剥除。
pub(super) fn rt_sigprocmask(
    space: &crate::mm::address_space::UserAddressSpace,
    how: usize,
    set: usize,
    oldset: usize,
    sigsetsize: usize,
    state: &mut ThreadSig,
) -> Result<usize, Errno> {
    if sigsetsize != SIGSETSIZE || how > SIG_SETMASK {
        return Err(Errno::Invalid);
    }
    let old = state.blocked();
    if set != 0 {
        let mut raw = [0u8; SIGSETSIZE];
        user_access::copy_from_user(space, set, &mut raw).map_err(|_| Errno::Fault)?;
        let mut new_set = u64::from_ne_bytes(raw);
        new_set.del(SIGKILL);
        new_set.del(SIGSTOP);
        match how {
            SIG_BLOCK => state.block(new_set),
            SIG_UNBLOCK => state.unblock(new_set),
            _ => state.setmask(new_set),
        }
    }
    if oldset != 0 {
        user_access::copy_to_user(space, oldset, &old.to_ne_bytes()).map_err(|_| Errno::Fault)?;
    }
    Ok(0)
}

/// rt_sigpending(2)：回写 pending & blocked，成功返回 0；sigsetsize 须为 8
///（偏差登记 docs/ostd-contracts.md §4.5）。
pub(super) fn rt_sigpending(
    space: &crate::mm::address_space::UserAddressSpace,
    set: usize,
    sigsetsize: usize,
    group: &SignalGroup,
    thread: &ThreadSig,
) -> Result<usize, Errno> {
    if sigsetsize != SIGSETSIZE {
        return Err(Errno::Invalid);
    }
    let pending = (group.pending() | thread.pending()) & thread.blocked();
    user_access::copy_to_user(space, set, &pending.to_ne_bytes()).map_err(|_| Errno::Fault)?;
    Ok(0)
}

/// stack_t 字节数（ss_sp@0、ss_flags@8、ss_size@16）。
const STACK_T_SIZE: usize = 24;

/// sigaltstack(2)：备用栈登记的换读，成功返回 0。`sp` 为陷入前的用户 sp。
/// uss 非空时先做在栈检查；uoldss 非空回写当前登记。
/// 偏差登记 docs/ostd-contracts.md §4.5。
pub(super) fn rt_sigaltstack(
    space: &UserAddressSpace,
    sp: usize,
    uss: usize,
    uoldss: usize,
    state: &mut ThreadSig,
) -> Result<usize, Errno> {
    if uoldss != 0 {
        let (ss_sp, ss_size, ss_flags) = match state.alt_stack() {
            Some((ss_sp, ss_size)) => (ss_sp, ss_size, state.alt_stack_flags(sp)),
            None => (0, 0, SS_DISABLE),
        };
        let mut out = [0u8; STACK_T_SIZE];
        out[0..8].copy_from_slice(&ss_sp.to_ne_bytes());
        out[8..12].copy_from_slice(&ss_flags.to_ne_bytes());
        out[16..24].copy_from_slice(&ss_size.to_ne_bytes());
        user_access::copy_to_user(space, uoldss, &out).map_err(|_| Errno::Fault)?;
    }
    if uss != 0 {
        let mut raw = [0u8; STACK_T_SIZE];
        user_access::copy_from_user(space, uss, &mut raw).map_err(|_| Errno::Fault)?;
        if state.on_alt_stack(sp) {
            return Err(Errno::Perm);
        }
        let flags = u32::from_ne_bytes(raw[8..12].try_into().unwrap_or([0; 4]));
        if flags as i32 == SS_DISABLE {
            state.set_alt_stack(0, 0, false);
        } else if flags == 0 {
            let ss_sp = usize::from_ne_bytes(raw[0..8].try_into().unwrap_or([0; 8]));
            let ss_size = usize::from_ne_bytes(raw[16..24].try_into().unwrap_or([0; 8]));
            // 区间上界不可表达：按 access_ok 失败返回 EFAULT，拒绝登记。
            if ss_sp.checked_add(ss_size).is_none() {
                return Err(Errno::Fault);
            }
            // size != 0 即启用；size=0 等价于禁用。
            state.set_alt_stack(ss_sp, ss_size, ss_size != 0);
        } else {
            return Err(Errno::Invalid);
        }
    }
    Ok(0)
}
