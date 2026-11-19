//! riscv64 信号帧：建帧投递（build_deliver）与 rt_sigreturn 恢复（restore）。
//! 布局来源：Linux arch/riscv/kernel/signal.c（setup_rt_frame / setup_sigcontext /
//! restore_sigcontext / sys_rt_sigreturn，trampoline 取 nommu 分支形状）与
//! arch/riscv/include/uapi/asm/{sigcontext,ptrace}.h、include/uapi/asm-generic/
//! ucontext.h；musl arch/riscv64/bits/signal.h 交叉验证偏移一致。
//! 帧布局（base 为 16 字节对齐的帧基址）：
//!   +0     siginfo 128 字节
//!   +128   ucontext：uc_flags/+128 uc_link/+136 uc_stack/+144（24 字节全零）
//!          uc_sigmask/+168（128 字节 sigset，仅低 8 字节有效）
//!   +304   uc_mcontext（sigcontext，16 字节对齐）：sc_regs 31×8
//!          （user_regs_struct：[0]=pc、[i]=x[i]；x0 恒零不入帧）
//!   +560   union {sc_fpregs, sc_extdesc}：d 态 f[32]×u64 + fcsr u32；
//!          +1076 sc_extdesc.reserved 恒零；+1080 ctx_hdr {magic,size}
//!          = END（两字段均 0）。本内核无向量扩展，扩展链只有 END 一节。
//!   +1088  帧内嵌 sigreturn stub（Linux nommu rt_sigframe 的
//!          sigreturn_code 槽位形状；本内核无 vDSO）
//! 帧总量 1096 字节。SA_ONSTACK 按登记的备用栈落帧（sigsp 语义，
//! uc_stack 回写当前登记），rt_sigreturn 不回改备用栈登记。
#![deny(unsafe_code)]

use polyhal_trap::trapframe::{TrapFrame, TrapFrameArgs};

use crate::mm::{address_space::UserAddressSpace, user_access};
use crate::syscall::signal::SA_ONSTACK;
use crate::task::signal::{
    SigInfoSlot, SignalDisposition, SignalSet, SignalSetExt, SIGKILL, SIGSTOP, SS_DISABLE,
};

use super::{fill_siginfo, on_alt_stack, FrameError};

/// uc_sigmask 偏移：ucontext 在帧内 +128，sigset_t 字段在其内 +40。
const OFF_UC_SIGMASK: usize = 168;
/// uc_mcontext（sigcontext）偏移：uc_sigmask 128 字节后按 sigcontext 的
/// 16 字节对齐补 8 字节填充（musl ucontext_t 显式 char __pad[8] 同位）。
const OFF_UC_MCONTEXT: usize = 304;
/// sc_fpregs / sc_extdesc 联合体偏移：sc_regs 256 字节（32 项）后恰为
/// 16 对齐，无填充。
const OFF_SC_UNION: usize = 560;
/// sc_extdesc.reserved 偏移（联合体内 __padding[129] 之后，恒零字段）。
const OFF_SC_RSVD: usize = 1076;
/// sc_extdesc.hdr（ctx_hdr {magic, size}）偏移：扩展链终点校验位。
const OFF_SC_HDR: usize = 1080;
/// 帧内嵌 sigreturn stub 偏移。
const OFF_STUB: usize = 1088;
/// 帧占用量：uc_mcontext 结束于 +1088，stub 再占 8 字节，总计 1096。
const FRAME_SIZE: usize = 1096;

/// 帧内嵌 sigreturn stub：`li a7,139; ecall`。编码 0x08b00893
///（addi a7,zero,139）与 0x00000073 经本仓库工具链（riscv64-linux-gnu-as）
/// 汇编实证，与 Linux vDSO 的 __user_rt_sigreturn（li a7,__NR_rt_sigreturn;
/// ecall）一致。
const SIGRETURN_STUB: [u32; 2] = [0x08b0_0893, 0x0000_0073];

/// 写用户内存，失败折叠为 [`FrameError::Access`]。
fn write(space: &UserAddressSpace, vaddr: usize, src: &[u8]) -> Result<(), FrameError> {
    user_access::copy_to_user(space, vaddr, src).map_err(|_| FrameError::Access)
}

/// 读用户内存，失败折叠为 [`FrameError::Access`]。
fn read(space: &UserAddressSpace, vaddr: usize, dst: &mut [u8]) -> Result<(), FrameError> {
    user_access::copy_from_user(space, vaddr, dst).map_err(|_| FrameError::Access)
}

/// 在用户栈（或备用栈）上构造 rt_sigframe 并改写 `frame` 进入 handler。
///
/// 对应 Linux setup_rt_frame：落帧栈位按 Linux sigsp 选择——处置带
/// SA_ONSTACK、`alt` 登记了备用栈且当前 sp 不在备用栈上时，帧落备用栈
/// 顶（向下增长）；否则当前用户栈。sp 下移对齐 16 后落帧，写 siginfo /
/// ucontext（uc_flags=0、uc_link=0、uc_stack=当前备用栈登记（Linux
/// __save_altstack 存登记原值，flags 启用为 0、未启用为 SS_DISABLE）、
/// uc_sigmask=old_blocked）/ sigcontext（全通用寄存器 + d 态浮点 + END
/// 扩展链）/ 帧内嵌 sigreturn stub；返回地址 ra 指向 stub。handler 参数
/// 恒传 a0=sig、a1=&siginfo、a2=&ucontext（SA_SIGINFO 仅语义差异，Linux
/// 恒传）。返回 handler 期间屏蔽集合：old_blocked | sa_mask | 本信号位
///（SA_NODEFER 未支持，恒加本信号位，偏差登记 docs/ostd-contracts.md）。
/// 任一用户写入失败即返回 [`FrameError::Access`]，`frame` 不被改动
///（Linux 同：寄存器改写只在全部拷贝成功后进行）。备用栈溢出防护
///（Linux get_sigframe 的 sp - framesize 出栈判定）未做，偏差登记 docs。
pub fn build_deliver(
    frame: &mut TrapFrame,
    space: &UserAddressSpace,
    sig: u8,
    slot: &SigInfoSlot,
    d: &SignalDisposition,
    old_blocked: SignalSet,
    alt: Option<(usize, usize)>,
) -> Result<SignalSet, FrameError> {
    // Linux get_sigframe + sigsp：SA_ONSTACK 且登记了备用栈且当前不在
    // 其上 → 从备用栈顶向下落帧；否则从当前用户栈向下落帧。再
    // sp = (sp - framesize) & ~0xF。
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

    // siginfo + uc_flags/uc_link/uc_stack。uc_stack 回写当前备用栈登记
    //（帧内偏移 +144，head 内 +16；flags 按登记态，不回写 SS_ONSTACK）。
    let (ss_sp, ss_size, ss_flags) = match alt {
        Some((ss_sp, ss_size)) => (ss_sp, ss_size, 0i32),
        None => (0, 0, SS_DISABLE),
    };
    let mut head = [0u8; 176];
    fill_siginfo(&mut head[..128], sig, slot);
    head[16..24].copy_from_slice(&ss_sp.to_ne_bytes());
    head[24..28].copy_from_slice(&ss_flags.to_ne_bytes());
    head[32..40].copy_from_slice(&ss_size.to_ne_bytes());
    write(space, base, &head)?;

    // uc_sigmask：存 handler 前的 blocked，sigreturn 时恢复。
    let mut sigmask = [0u8; 128];
    sigmask[..8].copy_from_slice(&old_blocked.to_ne_bytes());
    write(space, base + OFF_UC_SIGMASK, &sigmask)?;

    // sc_regs：user_regs_struct = [pc, x1..x31]，32 项共 256 字节，
    // 即 pt_regs 的前缀原样拷出。
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

    // sc_extdesc：reserved=0 与 END 头（magic=size=END_MAGIC=0），12 字节
    // 连续全零一次写入。恢复侧读到其余 magic（如 RISCV_V_MAGIC）即 badframe。
    write(space, base + OFF_SC_RSVD, &[0u8; 12])?;

    // 帧内嵌 sigreturn stub。Linux MMU 系统用 vDSO，本内核无 vDSO，按
    // nommu 分支把两条指令写进帧尾并令 ra 指向它；QEMU 下 icache 与
    // 存储一致，无需 Linux nommu 的 flush_icache_range（偏差登记 docs）。
    let mut stub = [0u8; 8];
    stub[..4].copy_from_slice(&SIGRETURN_STUB[0].to_ne_bytes());
    stub[4..].copy_from_slice(&SIGRETURN_STUB[1].to_ne_bytes());
    write(space, base + OFF_STUB, &stub)?;

    // handler 现场（Linux setup_rt_frame 尾部寄存器改写）。
    frame[TrapFrameArgs::RA] = base + OFF_STUB;
    frame[TrapFrameArgs::SP] = base;
    frame[TrapFrameArgs::ARG0] = sig as usize;
    frame[TrapFrameArgs::ARG1] = base;
    frame[TrapFrameArgs::ARG2] = base + 128;
    frame[TrapFrameArgs::SEPC] = d.handler;

    // handler 期间屏蔽：old | sa_mask | 本信号（Linux 恒加本信号位）。
    let mut new_blocked = old_blocked | d.mask;
    new_blocked.add(sig);
    Ok(new_blocked)
}

/// rt_sigreturn 本体：`frame` 的用户 sp 指向帧基址，校验并恢复被打断的
/// 现场，返回帧中保存的 handler 前 blocked。
///
/// 对应 Linux sys_rt_sigreturn + restore_sigcontext：读 uc_sigmask 低 8 字节
///（set_current_blocked 同样剥除 SIGKILL/SIGSTOP 位）→ 校验
/// sc_extdesc.reserved == 0 → 校验扩展链头为 END（magic=size=0；无向量
/// 扩展，其余 magic 一律 badframe）→ 恢复 sc_regs 与 d 态浮点。失败返回
/// [`FrameError::BadFrame`]，`frame` 不被改动，由调用方按 badframe 处置
///（Linux force_sig(SIGSEGV)）。备用栈登记不随 sigreturn 恢复（Linux
/// restore_altstack 从 uc_stack 回读改登记；本内核登记不受 sigreturn
/// 影响，偏差登记 docs）。成功后 a0 保持 handler 的返回值（Linux 以
/// return regs->a0 透传），PC 已是真实返回点，无需 syscall_ok。
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

    // 全部校验通过，落现场：pc 入 SEPC，x1..x31 入通用寄存器（x0 恒零
    // 不恢复），浮点按 d 态位模式恢复。
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
