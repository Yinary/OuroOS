//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal-trap 0.4.0（MIT）。
//! 修改说明：OuroOS vendor 补丁，见本目录 README.md。
#[macro_use]
mod macros;

use super::TrapType;
use crate::trapframe::TrapFrame;
use core::arch::naked_asm;
use riscv::{
    interrupt::{Exception, Interrupt},
    register::{
        scause::{self, Trap},
        sstatus::{self, FS},
        stval,
        stvec::{self, Stvec},
    },
};

// Initialize the trap handler.
pub(crate) fn init() {
    // SAFETY: 初始化阶段独占当前核 CSR，stvec 指向常驻内核陷阱入口。
    unsafe {
        // OuroOS 补丁：允许内核与用户执行 FP 指令，现场由陷阱边界保存。
        sstatus::set_fs(FS::Dirty);
        let mut stvec = Stvec::from_bits(0);
        stvec.set_address(kernelvec as usize);
        stvec.set_trap_mode(stvec::TrapMode::Direct);
        stvec::write(stvec);
    }

    // Initialize the timer component
    polyhal::timer::init();
}

// 内核中断回调
#[no_mangle]
fn kernel_callback(context: &mut TrapFrame) -> TrapType {
    let scause = scause::read();
    let stval = stval::read();

    let trap_type = match scause.cause().try_into() {
        // 中断异常
        Ok(Trap::Exception(Exception::Breakpoint)) => {
            // OuroOS 补丁：只推进内核断点，用户断点地址由信号帧保存。
            if !context.from_user() {
                // SAFETY: sepc 来自触发断点的内核代码，地址至少按半字对齐。
                let first = unsafe { (context.sepc as *const u16).read() };
                context.sepc += if first & 3 == 3 { 4 } else { 2 };
            }
            TrapType::Breakpoint
        }
        Ok(Trap::Exception(Exception::LoadFault)) => TrapType::LoadPageFault(stval),
        Ok(Trap::Exception(Exception::UserEnvCall)) => TrapType::SysCall,
        // 时钟中断
        Ok(Trap::Interrupt(Interrupt::SupervisorTimer)) => TrapType::Timer,
        Ok(Trap::Exception(Exception::StorePageFault)) => TrapType::StorePageFault(stval),
        Ok(Trap::Exception(Exception::StoreFault)) => TrapType::StorePageFault(stval),
        Ok(Trap::Exception(Exception::InstructionPageFault)) => {
            TrapType::InstructionPageFault(stval)
        }
        Ok(Trap::Exception(Exception::IllegalInstruction)) => TrapType::IllegalInstruction(stval),
        Ok(Trap::Exception(Exception::LoadPageFault)) => TrapType::LoadPageFault(stval),
        Ok(Trap::Interrupt(Interrupt::SupervisorExternal)) => TrapType::SupervisorExternal,
        _ => {
            // OuroOS 补丁：未分类陷阱不 panic，交由 OS 回调决策。
            log::error!(
                "unclassified trap: {:#x} {:?}  stval {:#x}  sepc: {:#x}",
                scause.bits(),
                scause.cause(),
                stval,
                context.sepc
            );
            TrapType::Unhandled(scause.bits())
        }
    };
    // SAFETY: context 是当前陷阱保存的有效 TrapFrame，回调同步使用。
    unsafe { super::_interrupt_for_arch(context, trap_type, 0) };
    trap_type
}

#[naked]
pub unsafe extern "C" fn kernelvec() {
    naked_asm!(
        includes_trap_macros!(),
        // 宏定义
        r"
            .align 4
            .altmacro
            .option push
            .option arch, +d
        
            csrrw   sp, sscratch, sp
            bnez    sp, uservec
            csrr    sp, sscratch

            addi    sp, sp, -{cx_size}
            
            SAVE_GENERAL_REGS
            SAVE_USER_FP
            csrw    sscratch, x0

            mv      a0, sp

            call kernel_callback

            LOAD_USER_FP
            LOAD_GENERAL_REGS
            sret
            .option pop
        ",
        cx_size = const crate::trapframe::TRAPFRAME_SIZE,
    )
}

#[naked]
#[no_mangle]
extern "C" fn user_restore(context: *mut TrapFrame) {
    // SAFETY: 仅由关中断的 run_user_task 调用，context 指向存活的用户现场，
    // 当前内核栈可容纳固定续体与 FP 现场。
    unsafe {
        naked_asm!(
            includes_trap_macros!(),
            // 在内核态栈中开一个空间来存储内核态信息
            // 下次发生中断必然会进入中断入口然后恢复这个上下文.
            // 仅保存 Callee-saved regs、gp、tp、ra.
            ".align 4
                .altmacro
                .option push
                .option arch, +d
                addi    sp, sp, -52*8

                STR      sp,  1
                STR      gp,  2
                STR      tp,  3
                STR      s0,  4
                STR      s1,  5
                STR      s2,  6
                STR      s3,  7
                STR      s4,  8
                STR      s5,  9
                STR      s6,  10
                STR      s7,  11
                STR      s8,  12
                STR      s9,  13
                STR      s10, 14
                STR      s11, 15
                STR      a0,  16
                STR      ra,  17
                csrr     t0, sstatus
                STR      t0, 18
                li       t0, 3
                slli     t0, t0, 13
                csrs     sstatus, t0
                SAVE_KERNEL_FP
            ",
            // 将栈信息保存到用户栈.
            // a0 是传入的Context, 然后下面会再次恢复 sp 地址.
            "   sd       sp, 8*0(a0)
                csrw     sscratch, a0
                mv       sp, a0

                LOAD_USER_FP

                LOAD_GENERAL_REGS
                sret
                .option pop
            ",
        )
    }
}

#[naked]
#[no_mangle]
#[allow(named_asm_labels)]
pub unsafe extern "C" fn uservec() {
    naked_asm!(
        includes_trap_macros!(),
        // 保存 general registers, 除了 sp
        "
        .option push
        .option arch, +d
        SAVE_GENERAL_REGS
        SAVE_USER_FP
        csrw    sscratch, x0

        mv      a0, sp
        ld      sp, 0*8(a0)
        sd      x0, 0*8(a0)
    ",
        // 恢复内核上下文信息, 仅恢复 callee-saved 寄存器和 ra、gp、tp
        "  
        LDR      t0, 18
        csrw     sstatus, t0
        li       t0, 3
        slli     t0, t0, 13
        csrs     sstatus, t0
        LOAD_KERNEL_FP
        LDR      t0, 18
        csrw     sstatus, t0
        LDR      gp,  2
        LDR      tp,  3
        LDR      s0,  4
        LDR      s1,  5
        LDR      s2,  6
        LDR      s3,  7
        LDR      s4,  8
        LDR      s5,  9
        LDR      s6,  10
        LDR      s7,  11
        LDR      s8,  12
        LDR      s9,  13
        LDR      s10, 14
        LDR      s11, 15
        LDR      ra,  17
        
        LDR      sp,  1
    ",
        // 回收栈
        "addi sp, sp, 52*8
        ret
        .option pop
    ",
    );
}

/// 进用户态至下一陷阱，返回完整 TrapType（OuroOS 补丁 #5）。
pub fn run_user_task(context: &mut TrapFrame) -> TrapType {
    assert!(
        !polyhal::irq::IRQ::int_enabled(),
        "run_user_task requires IRQ off"
    );
    context.prepare_user_return();
    user_restore(context);
    kernel_callback(context)
}

/// Run user task until interrupt is received.
pub fn run_user_task_forever(context: &mut TrapFrame) -> ! {
    loop {
        assert!(
            !polyhal::irq::IRQ::int_enabled(),
            "run_user_task requires IRQ off"
        );
        context.prepare_user_return();
        user_restore(context);
        kernel_callback(context);
    }
}
