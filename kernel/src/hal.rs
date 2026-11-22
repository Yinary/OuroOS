//! 架构相关的任务切换与等待原语；切换包装器保存完整内核浮点现场。
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal/src/components/kcontext/riscv64.rs、loongarch64.rs
//! 原协议：MIT
//! 修改说明：参照寄存器与调用约定，独立实现浮点保存包装器；原上下文切换仍调用 PolyHAL。

use core::arch::naked_asm;
use polyhal::kcontext::KContext;

/// 关中断状态下切换内核续体，同时保护全部浮点寄存器与控制状态。
///
/// # Safety
/// `from` 与 `to` 必须指向调度器管理的稳定 KContext。
pub unsafe fn context_switch(from: *mut KContext, to: *const KContext) {
    assert!(
        !polyhal::irq::IRQ::int_enabled(),
        "context_switch requires IRQ off"
    );
    // SAFETY: 调用方保证两个 KContext 有效；当前栈可容纳固定现场，
    // PolyHAL 切换器保存并恢复此栈指针。
    unsafe { context_switch_fp(from, to) }
}

#[cfg(target_arch = "riscv64")]
#[naked]
unsafe extern "C" fn context_switch_fp(_from: *mut KContext, _to: *const KContext) {
    naked_asm!(
        r#"
        .option push
                .option arch, +d
                .option norvc
                addi sp, sp, -272
                sd ra, 264(sp)
                fsd f0, 0(sp)
                fsd f1, 8(sp)
                fsd f2, 16(sp)
                fsd f3, 24(sp)
                fsd f4, 32(sp)
                fsd f5, 40(sp)
                fsd f6, 48(sp)
                fsd f7, 56(sp)
                fsd f8, 64(sp)
                fsd f9, 72(sp)
                fsd f10, 80(sp)
                fsd f11, 88(sp)
                fsd f12, 96(sp)
                fsd f13, 104(sp)
                fsd f14, 112(sp)
                fsd f15, 120(sp)
                fsd f16, 128(sp)
                fsd f17, 136(sp)
                fsd f18, 144(sp)
                fsd f19, 152(sp)
                fsd f20, 160(sp)
                fsd f21, 168(sp)
                fsd f22, 176(sp)
                fsd f23, 184(sp)
                fsd f24, 192(sp)
                fsd f25, 200(sp)
                fsd f26, 208(sp)
                fsd f27, 216(sp)
                fsd f28, 224(sp)
                fsd f29, 232(sp)
                fsd f30, 240(sp)
                fsd f31, 248(sp)
                csrr t0, fcsr
                sd t0, 256(sp)
                call {switch}
                ld t0, 256(sp)
                csrw fcsr, t0
                fld f0, 0(sp)
                fld f1, 8(sp)
                fld f2, 16(sp)
                fld f3, 24(sp)
                fld f4, 32(sp)
                fld f5, 40(sp)
                fld f6, 48(sp)
                fld f7, 56(sp)
                fld f8, 64(sp)
                fld f9, 72(sp)
                fld f10, 80(sp)
                fld f11, 88(sp)
                fld f12, 96(sp)
                fld f13, 104(sp)
                fld f14, 112(sp)
                fld f15, 120(sp)
                fld f16, 128(sp)
                fld f17, 136(sp)
                fld f18, 144(sp)
                fld f19, 152(sp)
                fld f20, 160(sp)
                fld f21, 168(sp)
                fld f22, 176(sp)
                fld f23, 184(sp)
                fld f24, 192(sp)
                fld f25, 200(sp)
                fld f26, 208(sp)
                fld f27, 216(sp)
                fld f28, 224(sp)
                fld f29, 232(sp)
                fld f30, 240(sp)
                fld f31, 248(sp)
                ld ra, 264(sp)
                addi sp, sp, 272
                ret
                .option pop
        "#,
        switch = sym polyhal::kcontext::context_switch,
    );
}

#[cfg(target_arch = "loongarch64")]
#[naked]
unsafe extern "C" fn context_switch_fp(_from: *mut KContext, _to: *const KContext) {
    naked_asm!(
        r#"
        addi.d $sp, $sp, -288
                st.d $ra, $sp, 272
                fst.d $f0, $sp, 0
                fst.d $f1, $sp, 8
                fst.d $f2, $sp, 16
                fst.d $f3, $sp, 24
                fst.d $f4, $sp, 32
                fst.d $f5, $sp, 40
                fst.d $f6, $sp, 48
                fst.d $f7, $sp, 56
                fst.d $f8, $sp, 64
                fst.d $f9, $sp, 72
                fst.d $f10, $sp, 80
                fst.d $f11, $sp, 88
                fst.d $f12, $sp, 96
                fst.d $f13, $sp, 104
                fst.d $f14, $sp, 112
                fst.d $f15, $sp, 120
                fst.d $f16, $sp, 128
                fst.d $f17, $sp, 136
                fst.d $f18, $sp, 144
                fst.d $f19, $sp, 152
                fst.d $f20, $sp, 160
                fst.d $f21, $sp, 168
                fst.d $f22, $sp, 176
                fst.d $f23, $sp, 184
                fst.d $f24, $sp, 192
                fst.d $f25, $sp, 200
                fst.d $f26, $sp, 208
                fst.d $f27, $sp, 216
                fst.d $f28, $sp, 224
                fst.d $f29, $sp, 232
                fst.d $f30, $sp, 240
                fst.d $f31, $sp, 248
                movcf2gr $t0, $fcc0
                st.b $t0, $sp, 256
                movcf2gr $t0, $fcc1
                st.b $t0, $sp, 257
                movcf2gr $t0, $fcc2
                st.b $t0, $sp, 258
                movcf2gr $t0, $fcc3
                st.b $t0, $sp, 259
                movcf2gr $t0, $fcc4
                st.b $t0, $sp, 260
                movcf2gr $t0, $fcc5
                st.b $t0, $sp, 261
                movcf2gr $t0, $fcc6
                st.b $t0, $sp, 262
                movcf2gr $t0, $fcc7
                st.b $t0, $sp, 263
                movfcsr2gr $t0, $fcsr0
                st.w $t0, $sp, 264
                bl {switch}
                ld.w $t0, $sp, 264
                movgr2fcsr $fcsr0, $t0
                ld.bu $t0, $sp, 256
                movgr2cf $fcc0, $t0
                ld.bu $t0, $sp, 257
                movgr2cf $fcc1, $t0
                ld.bu $t0, $sp, 258
                movgr2cf $fcc2, $t0
                ld.bu $t0, $sp, 259
                movgr2cf $fcc3, $t0
                ld.bu $t0, $sp, 260
                movgr2cf $fcc4, $t0
                ld.bu $t0, $sp, 261
                movgr2cf $fcc5, $t0
                ld.bu $t0, $sp, 262
                movgr2cf $fcc6, $t0
                ld.bu $t0, $sp, 263
                movgr2cf $fcc7, $t0
                fld.d $f0, $sp, 0
                fld.d $f1, $sp, 8
                fld.d $f2, $sp, 16
                fld.d $f3, $sp, 24
                fld.d $f4, $sp, 32
                fld.d $f5, $sp, 40
                fld.d $f6, $sp, 48
                fld.d $f7, $sp, 56
                fld.d $f8, $sp, 64
                fld.d $f9, $sp, 72
                fld.d $f10, $sp, 80
                fld.d $f11, $sp, 88
                fld.d $f12, $sp, 96
                fld.d $f13, $sp, 104
                fld.d $f14, $sp, 112
                fld.d $f15, $sp, 120
                fld.d $f16, $sp, 128
                fld.d $f17, $sp, 136
                fld.d $f18, $sp, 144
                fld.d $f19, $sp, 152
                fld.d $f20, $sp, 160
                fld.d $f21, $sp, 168
                fld.d $f22, $sp, 176
                fld.d $f23, $sp, 184
                fld.d $f24, $sp, 192
                fld.d $f25, $sp, 200
                fld.d $f26, $sp, 208
                fld.d $f27, $sp, 216
                fld.d $f28, $sp, 224
                fld.d $f29, $sp, 232
                fld.d $f30, $sp, 240
                fld.d $f31, $sp, 248
                ld.d $ra, $sp, 272
                addi.d $sp, $sp, 288
                jr $ra
        "#,
        switch = sym polyhal::kcontext::context_switch,
    );
}

/// 读取当前任务上下文切换器保存的线程指针。
pub fn read_current_tp() -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        let tp: usize;
        // SAFETY: 只读取本核整数寄存器，不访问内存。
        unsafe { core::arch::asm!("mv {0}, tp", out(reg) tp, options(nomem, nostack)) };
        tp
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let tp: usize;
        // SAFETY: 只读取本核整数寄存器，不访问内存。
        unsafe { core::arch::asm!("move {0}, $tp", out(reg) tp, options(nomem, nostack)) };
        tp
    }
}

/// 在空闲循环等待可处理中断。
pub fn wait_for_interrupt() {
    assert!(!polyhal::irq::IRQ::int_enabled(), "idle requires IRQ off");
    polyhal::irq::IRQ::int_enable();
    #[cfg(target_arch = "riscv64")]
    polyhal::instruction::hlt();
    #[cfg(target_arch = "loongarch64")]
    core::hint::spin_loop();
    polyhal::irq::IRQ::int_disable();
}

/// 请求虚拟机关机。GED 请求异步处理，CPU 可在设备完成关机前被唤醒。
#[cfg(target_arch = "loongarch64")]
pub(crate) fn shutdown() -> ! {
    // GED 寄存器和关机值来自本项目固定版本 PolyHAL 0.4.0（MIT）的
    // components/instruction/loongarch64.rs。DMW0 为非缓存设备窗口。
    let ged_sleep_control = (0x8000_0000_0000_0000usize | 0x100e_001c) as *mut u8;
    // SAFETY: 仅在内核关机阶段访问 QEMU virt 的 ACPI GED 寄存器。
    unsafe {
        ged_sleep_control.write_volatile(0x34);
        core::arch::asm!("dbar 0");
        loop {
            core::arch::asm!("idle 0");
        }
    }
}

#[cfg(target_arch = "riscv64")]
pub(crate) use polyhal::instruction::shutdown;
