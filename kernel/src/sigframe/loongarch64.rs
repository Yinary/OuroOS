//! loongarch64 信号帧：建帧投递（build_deliver）与 rt_sigreturn 恢复
//! （restore）。布局来源：Linux arch/loongarch/kernel/signal.c
//!（setup_rt_frame / setup_sigcontext / restore_sigcontext / parse_extcontext /
//! sys_rt_sigreturn）、arch/loongarch/include/uapi/asm/{sigcontext,ucontext}.h
//! 与 asm/sigframe.h（rt_sigframe）；musl arch/loongarch64/bits/signal.h
//! 交叉验证偏移一致。帧布局（base 为 16 字节对齐的帧基址）：
//!   +0     siginfo 128 字节
//!   +128   ucontext：uc_flags/+128 uc_link/+136 uc_stack/+144
//!          （stack_t：ss_sp@144、ss_flags@152、ss_size@160）
//!          uc_sigmask/+168（128 字节 sigset，仅低 8 字节有效）
//!   +304   uc_mcontext（sigcontext）：sc_pc/+304 sc_regs[32]/+312
//!          （[0]=$r0 恒写零）sc_flags/+568（SC_USED_FP）sc_extcontext/+576
//!   +576   extcontext 链：sctx_info{magic=FPU_CTX_MAGIC, size=288} 后接
//!          fpu_context（regs[32]×u64 + fcc u64 + fcsr u32）
//!   +864   END sctx_info（magic=size=0）
//!   +880   帧内嵌 sigreturn stub（Linux 用 vDSO，本内核无 vDSO）
//! 帧总量 888 字节。SA_ONSTACK 按登记的备用栈落帧（sigsp 语义，
//! uc_stack 回写当前登记），rt_sigreturn 不回改备用栈登记。
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
/// uc_mcontext（sigcontext）偏移：uc_sigmask 128 字节后补 8 字节填充
///（musl ucontext_t 显式 long __uc_pad 同位）。
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
/// fpu_context 有效字段长度：regs[32]×8 + fcc×8 + fcsr×4 = 268
///（sizeof 为 272，fcsr 后另有 4 字节对齐尾填充，不入帧不恢复）。
const FPU_CTX_DATA: usize = 268;
/// parse_extcontext 认可的 FPU 块最小 size：sizeof(sctx_info) +
/// sizeof(fpu_context) = 16 + 272（Linux 同款下界，含尾填充）。
const FPU_BLOCK_MIN: usize = SCTX_INFO_SIZE + FPU_CTX_DATA + 4;
/// FPU 块 magic（la-sigcontext.h：FPU_CTX_MAGIC "FPU\x01"）。
const FPU_CTX_MAGIC: u32 = 0x4650_5501;
/// sc_flags 的 FP 位（la-sigcontext.h：SC_USED_FP）。本内核恒持有 FP
/// 现场，建帧时恒置位。
const SC_USED_FP: u32 = 1;

/// 帧内嵌 sigreturn stub：`li.w a7,139; syscall 0`。编码 0x03822c0b
///（ori a7,zero,139，即 li.w 对 12 位立即数的展开）与 0x002b0000
/// 经本仓库同款工具链（rustc/LLVM，loongarch64-unknown-none 目标）汇编
/// 实证；指令序列与 Linux arch/loongarch/vdso/sigreturn.S 的
/// __vdso_rt_sigreturn（li.w a7,__NR_rt_sigreturn; syscall 0）一致。
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
/// `frame` 进入 handler。
///
/// 对应 Linux setup_rt_frame：落帧栈位按 Linux sigsp 选择——处置带
/// SA_ONSTACK、`alt` 登记了备用栈且当前 sp 不在备用栈上时，帧落备用栈
/// 顶（向下增长）；否则当前用户栈。原 sp 下移帧总量后再对齐 16 字节
/// 落帧（帧含 extcontext 链，rt_sigreturn 以 sp 取帧，形状与 Linux
/// 等价），写 siginfo / ucontext（uc_flags=0、uc_link=0、uc_stack=当前
/// 备用栈登记（Linux __save_altstack 存登记原值，flags 启用为 0、未
/// 启用为 SS_DISABLE）、uc_sigmask=save_mask）/ sigcontext（sc_pc、
/// sc_regs[1..32]、sc_flags=SC_USED_FP）/ FPU 块 / END 结点 / 帧内嵌
/// sigreturn stub；返回地址 r1 指向 stub。handler 参数恒传 a0=sig、
/// a1=&siginfo、a2=&ucontext（SA_SIGINFO 仅语义差异，Linux 恒传）。
/// 返回 handler 期间屏蔽集合：blocked_now | sa_mask | 本信号位
///（SA_NODEFER 未支持，恒加本信号位，偏差登记 docs/ostd-contracts.md）。
/// `blocked_now` 是投递时的当前屏蔽集合，`save_mask` 写入帧内
/// uc_sigmask 供 sigreturn 恢复；sigsuspend 存续期间后者是换入临时集合
/// 之前的旧集合，其余场景两者相同。
/// 任一用户写入失败即返回 [`FrameError::Access`]，`frame` 不被改动。
/// 备用栈溢出防护（Linux get_sigframe 的 sp - framesize 出栈判定）未做，
/// 偏差登记 docs。
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
    // Linux get_sigframe + sigsp：SA_ONSTACK 且登记了备用栈且当前不在
    // 其上 → 从备用栈顶向下落帧；否则从当前用户栈向下落帧。再
    // sp = round_down(sp, 16) 减帧与扩展块总量。
    let cur_sp = frame[TrapFrameArgs::SP];
    let stack_top = match alt {
        Some((alt_sp, alt_size))
            if d.flags & SA_ONSTACK != 0 && !on_alt_stack(cur_sp, alt_sp, alt_size) =>
        {
            alt_sp + alt_size
        }
        _ => cur_sp,
    };
    // 先减帧再对齐 16 字节：FRAME_SIZE=888 不是 16 的倍数，先对齐
    // 会使基址恒偏斜 8（违反 LA64 psABI 与 sc_extcontext aligned(16)）。
    let base = stack_top.saturating_sub(FRAME_SIZE) & !0xF;

    // 分区写帧头：siginfo 独占 base+0..128；ucontext 从 +128 开始，
    // uc_flags/uc_link 恒零，uc_stack（stack_t，帧内偏移 +144）回写当前
    // 备用栈登记：ss_sp@+144、ss_flags@+152、ss_size@+160（flags 按
    // 登记态，不回写 SS_ONSTACK）。
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

    // uc_sigmask：存 save_mask（sigsuspend 存续期间为换入前的旧集合，
    // 否则同 blocked_now），sigreturn 时恢复。
    let mut sigmask = [0u8; 128];
    sigmask[..8].copy_from_slice(&save_mask.to_ne_bytes());
    write(space, base + OFF_UC_SIGMASK, &sigmask)?;

    // sigcontext：sc_pc + sc_regs（[0]=$r0 恒零，Linux 显式写 0）+
    // sc_flags=SC_USED_FP + 16 字节对齐填充。
    let mut sc = [0u8; 272];
    sc[..8].copy_from_slice(&frame[TrapFrameArgs::SEPC].to_ne_bytes());
    for (i, r) in frame.regs[1..].iter().enumerate() {
        sc[8 + (i + 1) * 8..8 + (i + 2) * 8].copy_from_slice(&r.to_ne_bytes());
    }
    // 缓冲区内偏移：pc 8 + regs 256 = 264，sc_flags 紧随其后。
    sc[264..268].copy_from_slice(&SC_USED_FP.to_ne_bytes());
    write(space, base + OFF_SC_PC, &sc)?;

    // FPU 块：sctx_info{magic, size, padding} + regs[32] + fcc + fcsr。
    // fcc 八个条件码按字节拼为 u64（小端）。fcsr_pending（handler 留下
    // 未清 FPU 异常时回 SIGFPE）未实现，偏差登记 docs。
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
    write(space, base + OFF_SC_EXT, &fpu)?;

    // END 结点：magic=size=0（16 字节全零一次写入）。
    write(space, base + OFF_SC_END, &[0u8; SCTX_INFO_SIZE])?;

    // 帧内嵌 sigreturn stub。Linux 用 vDSO 的 __vdso_rt_sigreturn，本内核
    // 无 vDSO，把同样两条指令写进帧尾并令 r1 指向它；QEMU 下 icache 与
    // 存储一致（偏差登记 docs）。
    let mut stub = [0u8; 8];
    stub[..4].copy_from_slice(&SIGRETURN_STUB[0].to_ne_bytes());
    stub[4..].copy_from_slice(&SIGRETURN_STUB[1].to_ne_bytes());
    write(space, base + OFF_STUB, &stub)?;

    // handler 现场（Linux setup_rt_frame 尾部寄存器改写）。
    frame[TrapFrameArgs::RA] = base + OFF_STUB;
    frame[TrapFrameArgs::SP] = base;
    frame[TrapFrameArgs::ARG0] = sig as usize;
    frame[TrapFrameArgs::ARG1] = base;
    frame[TrapFrameArgs::ARG2] = base + OFF_UCONTEXT;
    frame[TrapFrameArgs::SEPC] = d.handler;

    // handler 期间屏蔽：blocked_now | sa_mask | 本信号（Linux 恒加本信号位）。
    let mut new_blocked = blocked_now | d.mask;
    new_blocked.add(sig);
    Ok(new_blocked)
}

/// rt_sigreturn 本体：`frame` 的用户 sp（r3）指向帧基址，校验并恢复
/// 被打断的现场，返回帧中保存的 handler 前 blocked。
///
/// 对应 Linux sys_rt_sigreturn + restore_sigcontext：读 uc_sigmask 低 8 字节
///（set_current_blocked 同样剥除 SIGKILL/SIGSTOP 位）→ 按 parse_extcontext
/// 走 extcontext 链（只认 FPU 块与 END，其余 magic 为 badframe）→ 恢复
/// sc_pc、sc_regs[1..32]（$r0 恒零不恢复）与 FPU 现场。失败返回
/// [`FrameError::BadFrame`]，`frame` 不被改动，由调用方按 badframe 处置
///（Linux force_sig(SIGSEGV)）。备用栈登记不随 sigreturn 恢复（Linux
/// restore_altstack 从 uc_stack 回读改登记；本内核登记不受 sigreturn
/// 影响，偏差登记 docs）。
/// 成功后 a0 保持 handler 的返回值（Linux 以 return regs->regs[4] 透传），
/// PC 已是真实返回点，无需 syscall_ok。
pub fn restore(frame: &mut TrapFrame, space: &UserAddressSpace) -> Result<SignalSet, FrameError> {
    let base = frame[TrapFrameArgs::SP];

    // 校验前移：整段读出并核验，全部通过才写回现场。
    let mut sigmask = [0u8; 8];
    read(space, base + OFF_UC_SIGMASK, &mut sigmask)?;
    let mut old_blocked = SignalSet::from_ne_bytes(sigmask);
    old_blocked.del(SIGKILL);
    old_blocked.del(SIGSTOP);

    // sc_flags 读取仅核验可读性；本内核恒持有 FP 现场，不按位决定
    // 浮点是否恢复（Linux conditional_used_math 分支，偏差登记 docs）。
    let mut flags = [0u8; 4];
    read(space, base + OFF_SC_FLAGS, &mut flags)?;

    // parse_extcontext：走链直到 END。只认 FPU 块（size 有 Linux 同款
    // 下界）；未知 magic 或 FPU 块过小都是 badframe。步数上限防御
    // 构造的链（本内核建的链恰好 FPU+END 两节）。
    let mut fpu_base = None;
    let mut cursor = base + OFF_SC_EXT;
    for _ in 0..8 {
        let mut hdr = [0u8; SCTX_INFO_SIZE];
        read(space, cursor, &mut hdr)?;
        let magic = u32::from_ne_bytes(hdr[..4].try_into().expect("4 bytes"));
        let size = u32::from_ne_bytes(hdr[4..8].try_into().expect("4 bytes")) as usize;
        match magic {
            0 => break, // END：Linux 对 END 不校验 size
            m if m == FPU_CTX_MAGIC => {
                if size < FPU_BLOCK_MIN {
                    return Err(FrameError::BadFrame);
                }
                fpu_base = Some(cursor + SCTX_INFO_SIZE);
            }
            _ => return Err(FrameError::BadFrame),
        }
        cursor += size;
    }

    let mut sc_pc = [0u8; 8];
    read(space, base + OFF_SC_PC, &mut sc_pc)?;
    let mut regs = [0u8; 256];
    read(space, base + OFF_SC_REGS, &mut regs)?;

    // 全部校验通过，落现场：sc_pc 入 ERA，sc_regs[1..32] 入通用寄存器
    //（$r0 恒零不恢复），FPU 块存在则恢复浮点。
    frame[TrapFrameArgs::SEPC] = usize::from_ne_bytes(sc_pc);
    for (i, r) in frame.regs[1..].iter_mut().enumerate() {
        *r = usize::from_ne_bytes(regs[(i + 1) * 8..(i + 2) * 8].try_into().expect("8 bytes"));
    }
    if let Some(addr) = fpu_base {
        let mut fpu = [0u8; FPU_CTX_DATA];
        read(space, addr, &mut fpu)?;
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
