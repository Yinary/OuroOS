//! loongarch64 信号帧：建帧投递（build_deliver）与 rt_sigreturn 恢复（restore）。
//! 布局依据：Linux arch/loongarch/kernel/signal.c 与 uapi asm/{sigcontext,ucontext}.h。
//! 契约见 docs/ostd-contracts.md §4.5。
#![deny(unsafe_code)]

use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::mm::{address_space::UserAddressSpace, user_access};
use crate::syscall::signal::{SA_NODEFER, SA_ONSTACK};
use crate::task::signal::{
    SigInfoSlot, SignalDisposition, SignalSet, SignalSetExt, SIGKILL, SIGSTOP, SS_DISABLE,
};

use super::{fill_siginfo, frame_addr, on_alt_stack, FrameError};

/// ucontext 起点（siginfo 之后）：uc_flags/uc_link 在此连续 16 字节。
const OFF_UCONTEXT: usize = 128;
/// uc_stack（stack_t：ss_sp/ss_flags/ss_size）偏移：uc_flags/uc_link 之后。
const OFF_UC_STACK: usize = 144;
/// uc_sigmask 偏移：ucontext 在帧内 +128，sigset_t 字段在其内 +40。
const OFF_UC_SIGMASK: usize = 168;
/// sc_pc（uc_mcontext 起点）偏移。
const OFF_SC_PC: usize = 304;
/// sc_regs[32] 偏移。
const OFF_SC_REGS: usize = 312;
/// sc_flags 偏移。
const OFF_SC_FLAGS: usize = 568;
/// sc_extcontext 链头偏移（sigcontext 内 16 字节对齐的柔性数组起点）。
const OFF_SC_EXT: usize = 576;
/// FPU 块（sctx_info + fpu_context）长度：16 + 268 后按 16 字节对齐。
const FPU_BLOCK_SIZE: usize = 288;
/// extcontext 链 END 结点偏移。
const OFF_SC_END: usize = 864;
/// 帧内嵌 sigreturn stub 偏移。
const OFF_STUB: usize = 880;
/// 帧占用量：END 结点结束于 +880，stub 再占 8 字节，总计 888。
const FRAME_SIZE: usize = 888;

/// sctx_info 结头 16 字节（magic u32 + size u32 + padding u64）。
const SCTX_INFO_SIZE: usize = 16;
/// fpu_context 有效字段长度（268 字节）。
const FPU_CTX_DATA: usize = 268;
/// FPU 块最小 size（16 + 272）。
const FPU_BLOCK_MIN: usize = SCTX_INFO_SIZE + FPU_CTX_DATA + 4;
/// FPU 块 magic（la-sigcontext.h：FPU_CTX_MAGIC "FPU\x01"）。
const FPU_CTX_MAGIC: u32 = 0x4650_5501;
/// sc_flags 的 SC_USED_FP 位。
const SC_USED_FP: u32 = 1;

/// 帧内嵌 sigreturn stub：`li.w a7,139; syscall 0`。
const SIGRETURN_STUB: [u32; 2] = [0x0382_2c0b, 0x002b_0000];

/// 写用户内存，失败折叠为 [`FrameError::Access`]。
fn write(space: &UserAddressSpace, vaddr: usize, src: &[u8]) -> Result<(), FrameError> {
    user_access::copy_to_user(space, vaddr, src).map_err(|_| FrameError::Access)
}

/// 读用户内存，失败折叠为 [`FrameError::Access`]。
fn read(space: &UserAddressSpace, vaddr: usize, dst: &mut [u8]) -> Result<(), FrameError> {
    user_access::copy_from_user(space, vaddr, dst).map_err(|_| FrameError::Access)
}

/// 在用户栈（或备用栈）上构造 rt_sigframe（含 extcontext 链）并改写
/// `frame` 进入 handler；写入失败返回 [`FrameError::Access`]。
/// `blocked_now` 为当前屏蔽集合，`save_mask` 写入 uc_sigmask 供恢复。
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
    // SA_ONSTACK 且登记了备用栈时从栈顶落帧，否则从当前用户栈落帧。
    let cur_sp = frame[TrapFrameArgs::SP];
    let stack_top = match alt {
        Some((alt_sp, alt_size))
            if d.flags & SA_ONSTACK != 0 && !on_alt_stack(cur_sp, alt_sp, alt_size) =>
        {
            // 登记区间上界不可表达时该备用栈不可用，回退主栈。
            alt_sp.checked_add(alt_size).unwrap_or(cur_sp)
        }
        _ => cur_sp,
    };
    // 帧基址下溢视为用户地址访问失败。
    let base = stack_top
        .checked_sub(FRAME_SIZE)
        .ok_or(FrameError::Access)?
        & !0xF;

    // 写帧头：siginfo 与 ucontext（uc_flags/uc_link 为零），
    // uc_stack 回写当前备用栈登记。
    let (ss_sp, ss_size, ss_flags) = match alt {
        Some((ss_sp, ss_size)) => (ss_sp, ss_size, 0i32),
        None => (0, 0, SS_DISABLE),
    };
    let mut siginfo = [0u8; 128];
    fill_siginfo(&mut siginfo, sig, slot);
    write(space, base, &siginfo)?;
    write(space, frame_addr(base, OFF_UCONTEXT)?, &[0u8; 16])?;
    let mut uc_stack = [0u8; 24];
    uc_stack[0..8].copy_from_slice(&ss_sp.to_ne_bytes());
    uc_stack[8..12].copy_from_slice(&ss_flags.to_ne_bytes());
    uc_stack[16..24].copy_from_slice(&ss_size.to_ne_bytes());
    write(space, frame_addr(base, OFF_UC_STACK)?, &uc_stack)?;

    // uc_sigmask：存 save_mask，sigreturn 时恢复。
    let mut sigmask = [0u8; 128];
    sigmask[..8].copy_from_slice(&save_mask.to_ne_bytes());
    write(space, frame_addr(base, OFF_UC_SIGMASK)?, &sigmask)?;

    // sigcontext：sc_pc、sc_regs、sc_flags=SC_USED_FP。
    let mut sc = [0u8; 272];
    sc[..8].copy_from_slice(&frame[TrapFrameArgs::SEPC].to_ne_bytes());
    for (i, r) in frame.regs[1..].iter().enumerate() {
        sc[8 + (i + 1) * 8..8 + (i + 2) * 8].copy_from_slice(&r.to_ne_bytes());
    }
    // 缓冲区内偏移：pc 8 + regs 256 = 264，sc_flags 紧随其后。
    sc[264..268].copy_from_slice(&SC_USED_FP.to_ne_bytes());
    write(space, frame_addr(base, OFF_SC_PC)?, &sc)?;

    // FPU 块：sctx_info + regs[32] + fcc + fcsr（小端）。
    // fcsr_pending 未实现，偏差登记 docs/ostd-contracts.md §4.5。
    let mut fpu = [0u8; FPU_BLOCK_SIZE];
    fpu[..4].copy_from_slice(&FPU_CTX_MAGIC.to_ne_bytes());
    fpu[4..8].copy_from_slice(&(FPU_BLOCK_SIZE as u32).to_ne_bytes());
    for (i, r) in frame.fp.iter().enumerate() {
        fpu[SCTX_INFO_SIZE + i * 8..SCTX_INFO_SIZE + i * 8 + 8].copy_from_slice(&r.to_ne_bytes());
    }
    let mut fcc = 0u64;
    for (i, b) in frame.fcc.iter().enumerate() {
        fcc |= (*b as u64) << (i * 8);
    }
    fpu[SCTX_INFO_SIZE + 256..SCTX_INFO_SIZE + 264].copy_from_slice(&fcc.to_ne_bytes());
    fpu[SCTX_INFO_SIZE + 264..SCTX_INFO_SIZE + 268].copy_from_slice(&frame.fcsr.to_ne_bytes());
    write(space, frame_addr(base, OFF_SC_EXT)?, &fpu)?;

    // END 结点：magic=size=0（16 字节全零一次写入）。
    write(space, frame_addr(base, OFF_SC_END)?, &[0u8; SCTX_INFO_SIZE])?;

    // 帧内嵌 sigreturn stub，r1 指向它（本内核无 vDSO）。
    let mut stub = [0u8; 8];
    stub[..4].copy_from_slice(&SIGRETURN_STUB[0].to_ne_bytes());
    stub[4..].copy_from_slice(&SIGRETURN_STUB[1].to_ne_bytes());
    write(space, frame_addr(base, OFF_STUB)?, &stub)?;

    // handler 现场寄存器。
    frame[TrapFrameArgs::RA] = frame_addr(base, OFF_STUB)?;
    frame[TrapFrameArgs::SP] = base;
    frame[TrapFrameArgs::ARG0] = sig as usize;
    frame[TrapFrameArgs::ARG1] = base;
    frame[TrapFrameArgs::ARG2] = frame_addr(base, OFF_UCONTEXT)?;
    frame[TrapFrameArgs::SEPC] = d.handler;

    // handler 期间屏蔽：blocked_now | sa_mask，未置 SA_NODEFER 时另加本信号。
    let mut new_blocked = blocked_now | d.mask;
    if d.flags & SA_NODEFER == 0 {
        new_blocked.add(sig);
    }
    Ok(new_blocked)
}

/// rt_sigreturn 本体：从 r3 指向的帧校验并恢复现场，
/// 返回帧中保存的 handler 前 blocked；校验失败返回 [`FrameError::BadFrame`]。
pub fn restore(frame: &mut TrapFrame, space: &UserAddressSpace) -> Result<SignalSet, FrameError> {
    let base = frame[TrapFrameArgs::SP];

    // 校验前移：整段读出并核验，全部通过才写回现场。
    let mut sigmask = [0u8; 8];
    read(space, frame_addr(base, OFF_UC_SIGMASK)?, &mut sigmask)?;
    let mut old_blocked = SignalSet::from_ne_bytes(sigmask);
    old_blocked.del(SIGKILL);
    old_blocked.del(SIGSTOP);

    // sc_flags 仅核验可读性，浮点恒恢复。
    let mut flags = [0u8; 4];
    read(space, frame_addr(base, OFF_SC_FLAGS)?, &mut flags)?;

    // parse_extcontext：必须走到 END；只认 FPU 块，其余 magic 为 badframe。
    // 步数上限 8。
    let mut fpu_base = None;
    let mut cursor = frame_addr(base, OFF_SC_EXT)?;
    let mut saw_end = false;
    for _ in 0..8 {
        let mut hdr = [0u8; SCTX_INFO_SIZE];
        read(space, cursor, &mut hdr)?;
        let magic = u32::from_ne_bytes(hdr[..4].try_into().expect("4 bytes"));
        let size = u32::from_ne_bytes(hdr[4..8].try_into().expect("4 bytes")) as usize;
        match magic {
            0 => {
                // END：不校验 size。
                saw_end = true;
                break;
            }
            m if m == FPU_CTX_MAGIC => {
                if size < FPU_BLOCK_MIN {
                    return Err(FrameError::BadFrame);
                }
                fpu_base = Some(frame_addr(cursor, SCTX_INFO_SIZE)?);
            }
            _ => return Err(FrameError::BadFrame),
        }
        cursor = frame_addr(cursor, size)?;
    }
    // 未遇 END 即链未终止，按坏帧处理。
    if !saw_end {
        return Err(FrameError::BadFrame);
    }

    let mut sc_pc = [0u8; 8];
    read(space, frame_addr(base, OFF_SC_PC)?, &mut sc_pc)?;
    let mut regs = [0u8; 256];
    read(space, frame_addr(base, OFF_SC_REGS)?, &mut regs)?;
    let mut fpu = None;
    if let Some(addr) = fpu_base {
        let mut data = [0u8; FPU_CTX_DATA];
        read(space, addr, &mut data)?;
        fpu = Some(data);
    }

    // 全部校验通过后恢复 sc_pc、sc_regs 与 FPU 现场。
    frame[TrapFrameArgs::SEPC] = usize::from_ne_bytes(sc_pc);
    for (i, r) in frame.regs[1..].iter_mut().enumerate() {
        *r = usize::from_ne_bytes(regs[(i + 1) * 8..(i + 2) * 8].try_into().expect("8 bytes"));
    }
    if let Some(fpu) = fpu {
        for (i, f) in frame.fp.iter_mut().enumerate() {
            *f = u64::from_ne_bytes(fpu[i * 8..i * 8 + 8].try_into().expect("8 bytes"));
        }
        let fcc = u64::from_ne_bytes(fpu[256..264].try_into().expect("8 bytes"));
        for (i, b) in frame.fcc.iter_mut().enumerate() {
            *b = (fcc >> (i * 8)) as u8;
        }
        frame.fcsr = u32::from_ne_bytes(fpu[264..268].try_into().expect("4 bytes"));
    }
    Ok(old_blocked)
}
