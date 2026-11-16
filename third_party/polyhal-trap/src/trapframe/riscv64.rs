//! riscv64 陷阱现场：整数与完整浮点状态、用户返回特权状态。
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal-trap/src/trapframe/riscv64.rs
//! 原协议：MIT
//! 修改说明：OuroOS 补全浮点现场并显式构造用户返回状态。

use core::{
    fmt::Debug,
    ops::{Index, IndexMut},
};

use riscv::register::sstatus::{self, Sstatus, FS, SPP};

use super::TrapFrameArgs;

#[repr(C, align(16))]
#[derive(Clone)]
// 上下文
pub struct TrapFrame {
    pub x: [usize; 32], // 32 个通用寄存器
    pub sstatus: Sstatus,
    pub sepc: usize,
    /// 用户浮点寄存器 f0..f31 的原始位模式。
    pub fp: [u64; 32],
    /// 用户 fcsr。
    pub fcsr: usize,
}

const _: () = {
    assert!(core::mem::offset_of!(TrapFrame, fp) == 272);
    assert!(core::mem::offset_of!(TrapFrame, fcsr) == 528);
    assert!(core::mem::size_of::<TrapFrame>() == 544);
};

impl Debug for TrapFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("ra", &self.x[1])
            .field("sp", &self.x[2])
            .field("gp", &self.x[3])
            .field("tp", &self.x[4])
            .field("t0", &self.x[5])
            .field("t1", &self.x[6])
            .field("t2", &self.x[7])
            .field("s0", &self.x[8])
            .field("s1", &self.x[9])
            .field("a0", &self.x[10])
            .field("a1", &self.x[11])
            .field("a2", &self.x[12])
            .field("a3", &self.x[13])
            .field("a4", &self.x[14])
            .field("a5", &self.x[15])
            .field("a6", &self.x[16])
            .field("a7", &self.x[17])
            .field("s2", &self.x[18])
            .field("s3", &self.x[19])
            .field("s4", &self.x[20])
            .field("s5", &self.x[21])
            .field("s6", &self.x[22])
            .field("s7", &self.x[23])
            .field("s8", &self.x[24])
            .field("s9", &self.x[25])
            .field("s10", &self.x[26])
            .field("s11", &self.x[27])
            .field("t3", &self.x[28])
            .field("t4", &self.x[29])
            .field("t5", &self.x[30])
            .field("t6", &self.x[31])
            .field("sstatus", &self.sstatus)
            .field("sepc", &self.sepc)
            .field("fcsr", &self.fcsr)
            .finish()
    }
}

impl TrapFrame {
    // 创建上下文信息
    #[inline]
    pub fn new() -> Self {
        // 只保留硬件报告的 UXL；返回特权级、中断与 FP 状态显式构造。
        let mut status = Sstatus::from_bits(sstatus::read().bits() & (0b11 << 32));
        status.set_spp(SPP::User);
        status.set_spie(true);
        status.set_fs(FS::Initial);
        TrapFrame {
            x: [0usize; 32],
            sstatus: status,
            sepc: 0,
            fp: [0; 32],
            fcsr: 0,
        }
    }

    #[inline]
    pub fn args(&self) -> [usize; 6] {
        self.x[10..16].try_into().expect("args slice force convert")
    }

    /// Check if the trapframe was from user.
    #[inline]
    pub fn from_user(&self) -> bool {
        self.sstatus.spp() == SPP::User
    }

    /// 每次进入用户态前只保留硬件 UXL，明确设置 U 态、中断与 FP。
    pub(crate) fn prepare_user_return(&mut self) {
        let uxl = sstatus::read().bits() & (0b11 << 32);
        self.sstatus = Sstatus::from_bits(uxl | (1 << 5) | (3 << 13));
    }

    #[inline]
    pub fn syscall_ok(&mut self) {
        self.sepc += 4;
    }
}

impl Index<TrapFrameArgs> for TrapFrame {
    type Output = usize;

    fn index(&self, index: TrapFrameArgs) -> &Self::Output {
        match index {
            TrapFrameArgs::SEPC => &self.sepc,
            TrapFrameArgs::RA => &self.x[1],
            TrapFrameArgs::SP => &self.x[2],
            TrapFrameArgs::RET => &self.x[10],
            TrapFrameArgs::ARG0 => &self.x[10],
            TrapFrameArgs::ARG1 => &self.x[11],
            TrapFrameArgs::ARG2 => &self.x[12],
            TrapFrameArgs::TLS => &self.x[4],
            TrapFrameArgs::SYSCALL => &self.x[17],
        }
    }
}

impl IndexMut<TrapFrameArgs> for TrapFrame {
    fn index_mut(&mut self, index: TrapFrameArgs) -> &mut Self::Output {
        match index {
            TrapFrameArgs::SEPC => &mut self.sepc,
            TrapFrameArgs::RA => &mut self.x[1],
            TrapFrameArgs::SP => &mut self.x[2],
            TrapFrameArgs::RET => &mut self.x[10],
            TrapFrameArgs::ARG0 => &mut self.x[10],
            TrapFrameArgs::ARG1 => &mut self.x[11],
            TrapFrameArgs::ARG2 => &mut self.x[12],
            TrapFrameArgs::TLS => &mut self.x[4],
            TrapFrameArgs::SYSCALL => &mut self.x[17],
        }
    }
}
