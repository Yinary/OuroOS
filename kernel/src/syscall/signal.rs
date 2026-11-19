//! 信号类系统调用：rt_sigaction/rt_sigprocmask/rt_sigpending，对应
//! Linux kernel/signal.c 的 sys_rt_sig* 系列；支持范围与语义偏差统一
//! 登记 docs/ostd-contracts.md §4（登记由 docs commit 补做）。kill/
//! tgkill 走 Flow::Process 路由，实现在 task 层，本模块不含。
#![deny(unsafe_code)]

use super::Errno;
use crate::mm::user_access;
use crate::task::signal::{
    SignalDisposition, SignalSet, SignalSetExt, SignalState, SIGKILL, SIGSTOP,
};

/// SA_* 位与 SIG_BLOCK/UNBLOCK/SETMASK 的 UAPI 值（include/uapi/
/// asm-generic/signal-defs.h；rv64/la64 共用，本机交叉工具链头一致）。
/// SA_NOCLDWAIT 由 record_exit 消费；SA_RESTART 由 park 快路径
///（task::user_task）消费；SA_NODEFER/SA_SIGINFO/SA_ONSTACK 由建帧
/// 投递按固定语义处理（sigframe：恒加本信号屏蔽位 / 恒传三参 / 忽略），
/// SA_NOCLDSTOP/SA_RESETHAND 暂无消费方。
#[allow(dead_code)]
const SA_NOCLDSTOP: u32 = 0x0000_0001;
pub(crate) const SA_NOCLDWAIT: u32 = 0x0000_0002;
/// SA_SIGINFO：rv/la ABI 恒传 siginfo/ucontext 三参，仅语义存档。
#[allow(dead_code)]
const SA_SIGINFO: u32 = 0x0000_0004;
/// rv/la 无 restorer 语义；存储时剥除（Linux UAPI_SA_FLAGS 对未定义
/// 该位的架构同样屏蔽）。
const SA_RESTORER: u32 = 0x0400_0000;
/// SA_ONSTACK：无 altstack 支持，建帧投递恒忽略（sigframe）。
#[allow(dead_code)]
const SA_ONSTACK: u32 = 0x0800_0000;
pub(crate) const SA_RESTART: u32 = 0x1000_0000;
/// SA_NODEFER：未支持，建帧投递恒加本信号屏蔽位（sigframe）。
#[allow(dead_code)]
const SA_NODEFER: u32 = 0x4000_0000;
#[allow(dead_code)]
const SA_RESETHAND: u32 = 0x8000_0000;
const SIG_BLOCK: usize = 0;
const SIG_UNBLOCK: usize = 1;
const SIG_SETMASK: usize = 2;

/// 内核 sigset_t 字节数：内核侧 sigset 为单个 u64（1..=64）。
const SIGSETSIZE: usize = 8;

/// rt_sigaction 的 syscall 层结构（rv64/la64 ABI）。查证结论：两架构
/// 的 UAPI 均无 SA_RESTORER（asm/riscv 无 uapi signal.h，loongarch 仅
/// 补栈尺寸后含 asm-generic/signal.h；signal-defs.h 注明新架构不应
/// 定义 SA_RESTORER），故 act/oact 均为 24 字节 {handler, flags, mask}，
/// mask 靠后存放以便扩展；带 restorer 的 32 字节布局属 x86-64 等
/// 定义了 SA_RESTORER 的架构（内核按 sizeof(struct sigaction) 原样
/// copy_from/to_user，musl 侧 k_sigaction 同构）。
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

/// rt_sigaction(2)（sys_rt_sigaction）：单信号处置的读改写。sigsetsize
/// 必须为 8；sig 合法域 1..=64，SIGKILL/SIGSTOP 仅不可改写（act≠0 时
/// EINVAL，查询允许，同 Linux do_sigaction）。act≠0 时读 24 字节结构写
/// 处置：flags 按 u32 存储（SA_* 最大 0x8000_0000 不丢失）并剥除
/// SA_RESTORER 位，sa_mask 中 SIGKILL/SIGSTOP 位剥除（do_sigaction 的
/// sigdelsetmask）。handler ∈ {SIG_DFL=0, SIG_IGN=1, 函数地址}。oact≠0
/// 时回写旧值同构 24 字节（{handler, flags, mask}）。设置 IGN/DFL-Ign
/// 时丢弃已排队信号的语义未实现，登记 docs/ostd-contracts.md。
pub(super) fn rt_sigaction(
    space: &crate::mm::address_space::UserAddressSpace,
    sig: usize,
    act: usize,
    oact: usize,
    sigsetsize: usize,
    state: &mut SignalState,
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
        state.set_disposition(
            sig,
            SignalDisposition {
                handler: action.handler,
                flags: action.flags,
                mask: action.mask,
            },
        );
    }
    if oact != 0 {
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

/// rt_sigprocmask(2)（sys_rt_sigprocmask）：改读屏蔽集合。sigsetsize
/// 必须为 8；how ∈ {SIG_BLOCK=0, SIG_UNBLOCK=1, SIG_SETMASK=2}；set≠0
/// 时读 8 字节 sigset，SIGKILL/SIGSTOP 位剥除后按 how 生效（三种 how
/// 同样过滤，POSIX 不可屏蔽）；oldset≠0 时回写调用前的旧值（Linux 先
/// 快照后生效，同序）。
pub(super) fn rt_sigprocmask(
    space: &crate::mm::address_space::UserAddressSpace,
    how: usize,
    set: usize,
    oldset: usize,
    sigsetsize: usize,
    state: &mut SignalState,
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

/// rt_sigpending(2)（sys_rt_sigpending）：sigsetsize 必须为 8（Linux
/// 允许不大于 8，此处收紧，登记 docs）；回写 pending 位图。中间态：
/// Linux 回写 pending & blocked（"阻塞中不可取"），投递语义接入前
/// 直接回写 pending。
pub(super) fn rt_sigpending(
    space: &crate::mm::address_space::UserAddressSpace,
    set: usize,
    sigsetsize: usize,
    state: &mut SignalState,
) -> Result<usize, Errno> {
    if sigsetsize != SIGSETSIZE {
        return Err(Errno::Invalid);
    }
    user_access::copy_to_user(space, set, &state.pending().to_ne_bytes())
        .map_err(|_| Errno::Fault)?;
    Ok(0)
}
