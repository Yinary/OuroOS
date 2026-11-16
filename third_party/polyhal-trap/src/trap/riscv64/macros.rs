//! riscv64 陷阱汇编宏：整数与浮点现场保存、恢复。
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal-trap/src/trap/riscv64/macros.rs
//! 原协议：MIT
//! 修改说明：OuroOS 补充用户及内核浮点现场宏。

macro_rules! includes_trap_macros {
    () => {
        r#"
        .ifndef REGS_TRAP_MACROS_FLAG
        .equ REGS_TRAP_MACROS_FLAG, 1

        .macro LDR  reg, offset
            ld  \reg, \offset*8(sp)
        .endm

        .macro STR  reg, offset
            sd  \reg, \offset*8(sp)
        .endm

        .macro LOAD reg, offset
            ld  \reg, \offset*8(sp)
        .endm

        .macro SAVE reg, offset
            sd  \reg, \offset*8(sp)
        .endm

        .macro LOAD_N n
            ld  x\n, \n*8(sp)
        .endm

        .macro SAVE_N n
            sd  x\n, \n*8(sp)
        .endm

        .macro SAVE_GENERAL_REGS
            SAVE    x1, 1
            csrr    x1, sscratch
            SAVE    x1, 2
            .set    n, 3
            .rept   29 
                SAVE_N  %n
            .set    n, n + 1
            .endr

            csrr    t0, sstatus
            csrr    t1, sepc
            SAVE    t0, 32
            SAVE    t1, 33
        .endm

        .macro SAVE_USER_FP
            fsd f0, 272(sp)
            fsd f1, 280(sp)
            fsd f2, 288(sp)
            fsd f3, 296(sp)
            fsd f4, 304(sp)
            fsd f5, 312(sp)
            fsd f6, 320(sp)
            fsd f7, 328(sp)
            fsd f8, 336(sp)
            fsd f9, 344(sp)
            fsd f10, 352(sp)
            fsd f11, 360(sp)
            fsd f12, 368(sp)
            fsd f13, 376(sp)
            fsd f14, 384(sp)
            fsd f15, 392(sp)
            fsd f16, 400(sp)
            fsd f17, 408(sp)
            fsd f18, 416(sp)
            fsd f19, 424(sp)
            fsd f20, 432(sp)
            fsd f21, 440(sp)
            fsd f22, 448(sp)
            fsd f23, 456(sp)
            fsd f24, 464(sp)
            fsd f25, 472(sp)
            fsd f26, 480(sp)
            fsd f27, 488(sp)
            fsd f28, 496(sp)
            fsd f29, 504(sp)
            fsd f30, 512(sp)
            fsd f31, 520(sp)
            csrr t0, fcsr
            sd t0, 66*8(sp)
        .endm

        .macro LOAD_USER_FP
            ld t0, 66*8(sp)
            csrw fcsr, t0
            fld f0, 272(sp)
            fld f1, 280(sp)
            fld f2, 288(sp)
            fld f3, 296(sp)
            fld f4, 304(sp)
            fld f5, 312(sp)
            fld f6, 320(sp)
            fld f7, 328(sp)
            fld f8, 336(sp)
            fld f9, 344(sp)
            fld f10, 352(sp)
            fld f11, 360(sp)
            fld f12, 368(sp)
            fld f13, 376(sp)
            fld f14, 384(sp)
            fld f15, 392(sp)
            fld f16, 400(sp)
            fld f17, 408(sp)
            fld f18, 416(sp)
            fld f19, 424(sp)
            fld f20, 432(sp)
            fld f21, 440(sp)
            fld f22, 448(sp)
            fld f23, 456(sp)
            fld f24, 464(sp)
            fld f25, 472(sp)
            fld f26, 480(sp)
            fld f27, 488(sp)
            fld f28, 496(sp)
            fld f29, 504(sp)
            fld f30, 512(sp)
            fld f31, 520(sp)
        .endm

        .macro SAVE_KERNEL_FP
            fsd f0, 152(sp)
            fsd f1, 160(sp)
            fsd f2, 168(sp)
            fsd f3, 176(sp)
            fsd f4, 184(sp)
            fsd f5, 192(sp)
            fsd f6, 200(sp)
            fsd f7, 208(sp)
            fsd f8, 216(sp)
            fsd f9, 224(sp)
            fsd f10, 232(sp)
            fsd f11, 240(sp)
            fsd f12, 248(sp)
            fsd f13, 256(sp)
            fsd f14, 264(sp)
            fsd f15, 272(sp)
            fsd f16, 280(sp)
            fsd f17, 288(sp)
            fsd f18, 296(sp)
            fsd f19, 304(sp)
            fsd f20, 312(sp)
            fsd f21, 320(sp)
            fsd f22, 328(sp)
            fsd f23, 336(sp)
            fsd f24, 344(sp)
            fsd f25, 352(sp)
            fsd f26, 360(sp)
            fsd f27, 368(sp)
            fsd f28, 376(sp)
            fsd f29, 384(sp)
            fsd f30, 392(sp)
            fsd f31, 400(sp)
            csrr t0, fcsr
            sd t0, 51*8(sp)
        .endm

        .macro LOAD_KERNEL_FP
            ld t0, 51*8(sp)
            csrw fcsr, t0
            fld f0, 152(sp)
            fld f1, 160(sp)
            fld f2, 168(sp)
            fld f3, 176(sp)
            fld f4, 184(sp)
            fld f5, 192(sp)
            fld f6, 200(sp)
            fld f7, 208(sp)
            fld f8, 216(sp)
            fld f9, 224(sp)
            fld f10, 232(sp)
            fld f11, 240(sp)
            fld f12, 248(sp)
            fld f13, 256(sp)
            fld f14, 264(sp)
            fld f15, 272(sp)
            fld f16, 280(sp)
            fld f17, 288(sp)
            fld f18, 296(sp)
            fld f19, 304(sp)
            fld f20, 312(sp)
            fld f21, 320(sp)
            fld f22, 328(sp)
            fld f23, 336(sp)
            fld f24, 344(sp)
            fld f25, 352(sp)
            fld f26, 360(sp)
            fld f27, 368(sp)
            fld f28, 376(sp)
            fld f29, 384(sp)
            fld f30, 392(sp)
            fld f31, 400(sp)
        .endm

        .macro LOAD_GENERAL_REGS
            LOAD    t0, 32
            LOAD    t1, 33
            csrw    sstatus, t0
            csrw    sepc, t1

            LOAD    x1, 1
            .set    n, 3
            .rept   29
                LOAD_N  %n
            .set    n, n + 1
            .endr
            LOAD    x2, 2
        .endm

        .macro LOAD_PERCPU dst, sym
            lui  \dst, %hi(__PERCPU_\sym)
            add  \dst, \dst, gp
            ld   \dst, %lo(__PERCPU_\sym)(\dst)
        .endm

        .macro SAVE_PERCPU sym, temp, src
            lui  \temp, %hi(__PERCPU_\sym)
            add  \temp, \temp, gp
            sd   \src,  %lo(__PERCPU_\sym)(\temp)
        .endm

        .endif
        "#
    };
}
