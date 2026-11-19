//! riscv64 信号帧：建帧投递（build_deliver）与 rt_sigreturn 恢复（restore）。
//! 布局依据：Linux arch/riscv/kernel/signal.c 与 include/uapi/asm-generic/ucontext.h。
//! 契约见 docs/ostd-contracts.md §4.5。
#![deny(unsafe_code)]

use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::mm::{address_space::UserAddressSpace, user_access};
use crate::syscall::signal::SA_ONSTACK;
use crate::task::signal::{
    SigInfoSlot, SignalDisposition, SignalSet, SignalSetExt, SIGKILL, SIGSTOP, SS_DISABLE,
};

use super::{fill_siginfo, on_alt_stack, FrameError};

/// ucontext 起点（siginfo 之后）：uc_flags/uc_link 在此连续 16 字节。
const OFF_UCONTEXT: usize = 128;
/// uc_stack（stack_t：ss_sp/ss_flags/ss_size）偏移：uc_flags/uc_link 之后。
const OFF_UC_STACK: usize = 144;
/// uc_sigmask 偏移：ucontext 在帧内 +128，sigset_t 字段在其内 +40。
const OFF_UC_SIGMASK: usize = 168;
/// uc_mcontext（sigcontext）偏移。
const OFF_UC_MCONTEXT: usize = 304;
/// sc_fpregs / sc_extdesc 联合体偏移。
const OFF_SC_UNION: usize = 560;
/// sc_extdesc.reserved 偏移（联合体内 __padding[129] 之后，恒零字段）。
const OFF_SC_RSVD: usize = 1076;
/// sc_extdesc.hdr（ctx_hdr {magic, size}）偏移：扩展链终点校验位。
const OFF_SC_HDR: usize = 1080;
/// 帧内嵌 sigreturn stub 偏移。
const OFF_STUB: usize = 1088;
/// 帧占用量：uc_mcontext 结束于 +1088，stub 再占 8 字节，总计 1096。
const FRAME_SIZE: usize = 1096;

/// 帧内嵌 sigreturn stub：`li a7,139; ecall`。
const SIGRETURN_STUB: [u32; 2] = [0x08b0_0893, 0x0000_0073];

/// 写用户内存，失败折叠为 [`FrameError::Access`]。
fn write(space: &UserAddressSpace, vaddr: usize, src: &[u8]) -> Result<(), FrameError> {
    user_access::copy_to_user(space, vaddr, src).map_err(|_| FrameError::Access)
}

/// 读用户内存，失败折叠为 [`FrameError::Access`]。
fn read(space: &UserAddressSpace, vaddr: usize, dst: &mut [u8]) -> Result<(), FrameError> {
    user_access::copy_from_user(space, vaddr, dst).map_err(|_| FrameError::Access)
}

/// 在用户栈（或备用栈）上构造 rt_sigframe 并改写 `frame` 进入 handler；
/// 写入失败返回 [`FrameError::Access`]。`blocked_now` 为当前屏蔽集合，
/// `save_mask` 写入 uc_sigmask 供 sigreturn 恢复。
#[allow(clippy::too_many_arguments)] // 建帧需要完整现场、处置与两份掩码。
pub fn build_deliver(
    frame: &mut TrapFrame,
    space: &UserAddressSpace,
    sig: u8,
    slot: &SigInfoSlot,
    d: &SignalDisposition,
    blocked_now: SignalSet,
    save_mask: SignalSet,
    alt: Option<(usize, usize)>,
) -> Result<SignalSet, FrameError> {
    // SA_ONSTACK 且登记了备用栈时从栈顶落帧，否则从当前用户栈落帧；
    // 再 sp = (sp - framesize) & ~0xF。
    let cur_sp = frame[TrapFrameArgs::SP];
    let stack_top = match alt {
        Some((alt_sp, alt_size))
            if d.flags & SA_ONSTACK != 0 && !on_alt_stack(cur_sp, alt_sp, alt_size) =>
        {
            alt_sp + alt_size
        }
        _ => cur_sp,
    };
    let base = stack_top.wrapping_sub(FRAME_SIZE) & !0xF;

    // 写帧头：siginfo 与 ucontext（uc_flags/uc_link 为零），
    // uc_stack 回写当前备用栈登记。
    let (ss_sp, ss_size, ss_flags) = match alt {
        Some((ss_sp, ss_size)) => (ss_sp, ss_size, 0i32),
        None => (0, 0, SS_DISABLE),
    };
    let mut siginfo = [0u8; 128];
    fill_siginfo(&mut siginfo, sig, slot);
    write(space, base, &siginfo)?;
    write(space, base + OFF_UCONTEXT, &[0u8; 16])?;
    let mut uc_stack = [0u8; 24];
    uc_stack[0..8].copy_from_slice(&ss_sp.to_ne_bytes());
    uc_stack[8..12].copy_from_slice(&ss_flags.to_ne_bytes());
    uc_stack[16..24].copy_from_slice(&ss_size.to_ne_bytes());
    write(space, base + OFF_UC_STACK, &uc_stack)?;

    // uc_sigmask：存 save_mask，sigreturn 时恢复。
    let mut sigmask = [0u8; 128];
    sigmask[..8].copy_from_slice(&save_mask.to_ne_bytes());
    write(space, base + OFF_UC_SIGMASK, &sigmask)?;

    // sc_regs：pc 与 x1..x31，共 256 字节。
    let mut regs = [0u8; 256];
    regs[..8].copy_from_slice(&frame[TrapFrameArgs::SEPC].to_ne_bytes());
    for (i, r) in frame.x[1..].iter().enumerate() {
        regs[(i + 1) * 8..(i + 2) * 8].copy_from_slice(&r.to_ne_bytes());
    }
    write(space, base + OFF_UC_MCONTEXT, &regs)?;

    // sc_fpregs：d 态（f[0..32] 位模式 + fcsr 低 32 位）。
    let mut fp = [0u8; 260];
    for (i, r) in frame.fp.iter().enumerate() {
        fp[i * 8..i * 8 + 8].copy_from_slice(&r.to_ne_bytes());
    }
    fp[256..260].copy_from_slice(&(frame.fcsr as u32).to_ne_bytes());
    write(space, base + OFF_SC_UNION, &fp)?;

    // sc_extdesc：reserved 与 END 头共 12 字节全零。
    write(space, base + OFF_SC_RSVD, &[0u8; 12])?;

    // 帧内嵌 sigreturn stub，ra 指向它（本内核无 vDSO）。
    let mut stub = [0u8; 8];
    stub[..4].copy_from_slice(&SIGRETURN_STUB[0].to_ne_bytes());
    stub[4..].copy_from_slice(&SIGRETURN_STUB[1].to_ne_bytes());
    write(space, base + OFF_STUB, &stub)?;

    // handler 现场寄存器。
    frame[TrapFrameArgs::RA] = base + OFF_STUB;
    frame[TrapFrameArgs::SP] = base;
    frame[TrapFrameArgs::ARG0] = sig as usize;
    frame[TrapFrameArgs::ARG1] = base;
    frame[TrapFrameArgs::ARG2] = base + OFF_UCONTEXT;
    frame[TrapFrameArgs::SEPC] = d.handler;

    // handler 期间屏蔽：blocked_now | sa_mask | 本信号。
    let mut new_blocked = blocked_now | d.mask;
    new_blocked.add(sig);
    Ok(new_blocked)
}

/// rt_sigreturn 本体：从 sp 指向的帧恢复被打断的现场，
/// 返回帧中保存的 handler 前 blocked；校验失败返回 [`FrameError::BadFrame`]。
pub fn restore(frame: &mut TrapFrame, space: &UserAddressSpace) -> Result<SignalSet, FrameError> {
    let base = frame[TrapFrameArgs::SP];

    // 校验前移：整段读出并核验，全部通过才写回现场。
    let mut sigmask = [0u8; 8];
    read(space, base + OFF_UC_SIGMASK, &mut sigmask)?;
    let mut old_blocked = SignalSet::from_ne_bytes(sigmask);
    old_blocked.del(SIGKILL);
    old_blocked.del(SIGSTOP);

    let mut rsvd = [0u8; 4];
    read(space, base + OFF_SC_RSVD, &mut rsvd)?;
    if rsvd != [0; 4] {
        return Err(FrameError::BadFrame);
    }

    let mut hdr = [0u8; 8];
    read(space, base + OFF_SC_HDR, &mut hdr)?;
    if hdr != [0; 8] {
        return Err(FrameError::BadFrame);
    }

    let mut regs = [0u8; 256];
    read(space, base + OFF_UC_MCONTEXT, &mut regs)?;
    let mut fp = [0u8; 260];
    read(space, base + OFF_SC_UNION, &mut fp)?;

    // 全部校验通过后恢复 pc、x1..x31 与浮点。
    frame[TrapFrameArgs::SEPC] = usize::from_ne_bytes(regs[..8].try_into().expect("8 bytes"));
    for (i, r) in frame.x[1..].iter_mut().enumerate() {
        *r = usize::from_ne_bytes(regs[(i + 1) * 8..(i + 2) * 8].try_into().expect("8 bytes"));
    }
    for (i, f) in frame.fp.iter_mut().enumerate() {
        *f = u64::from_ne_bytes(fp[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
    }
    frame.fcsr = u32::from_ne_bytes(fp[256..260].try_into().expect("4 bytes")) as usize;
    Ok(old_blocked)
}
