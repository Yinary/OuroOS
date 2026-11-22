//! loongarch64 陷阱汇编宏：整数与浮点现场保存、恢复。
//! 参考来源：PolyHAL https://github.com/Byte-OS/polyhal polyhal-trap/src/trap/loongarch64/macros.rs
//! 原协议：MIT
//! 修改说明：OuroOS 补充用户及内核浮点现场宏。

macro_rules! includes_trap_macros {
    () => {
        r#"
        .ifndef REGS_TRAP_MACROS_FLAG
        .equ REGS_TRAP_MACROS_FLAG, 1

        // 2, 4, 1
        .macro FIXUP_EX from, to, fix
        .if \fix
            .section .fixup, "ax"
        \to: 
            li.w	$a0, -1
            jr	$ra
            .previous
        .endif
            .section __ex_table, "a"
            .word	\from\()b, \to\()b
            .previous
        .endm

        .equ KSAVE_KSP,  0x30
        .equ KSAVE_CTX,  0x31
        .equ KSAVE_USP,  0x32
        .equ LA_CSR_PGDL,          0x19    /* Page table base address when VA[47] = 0 */
        .equ LA_CSR_PGDH,          0x1a    /* Page table base address when VA[47] = 1 */
        .equ LA_CSR_PGD,           0x1b    /* Page table base */
        .equ LA_CSR_TLBRENTRY,     0x88    /* TLB refill exception entry */
        .equ LA_CSR_TLBRBADV,      0x89    /* TLB refill badvaddr */
        .equ LA_CSR_TLBRERA,       0x8a    /* TLB refill ERA */
        .equ LA_CSR_TLBRSAVE,      0x8b    /* KScratch for TLB refill exception */
        .equ LA_CSR_TLBRELO0,      0x8c    /* TLB refill entrylo0 */
        .equ LA_CSR_TLBRELO1,      0x8d    /* TLB refill entrylo1 */
        .equ LA_CSR_TLBREHI,       0x8e    /* TLB refill entryhi */
        .macro SAVE_USER_FP
            fst.d $f0, $sp, 34*8
            fst.d $f1, $sp, 35*8
            fst.d $f2, $sp, 36*8
            fst.d $f3, $sp, 37*8
            fst.d $f4, $sp, 38*8
            fst.d $f5, $sp, 39*8
            fst.d $f6, $sp, 40*8
            fst.d $f7, $sp, 41*8
            fst.d $f8, $sp, 42*8
            fst.d $f9, $sp, 43*8
            fst.d $f10, $sp, 44*8
            fst.d $f11, $sp, 45*8
            fst.d $f12, $sp, 46*8
            fst.d $f13, $sp, 47*8
            fst.d $f14, $sp, 48*8
            fst.d $f15, $sp, 49*8
            fst.d $f16, $sp, 50*8
            fst.d $f17, $sp, 51*8
            fst.d $f18, $sp, 52*8
            fst.d $f19, $sp, 53*8
            fst.d $f20, $sp, 54*8
            fst.d $f21, $sp, 55*8
            fst.d $f22, $sp, 56*8
            fst.d $f23, $sp, 57*8
            fst.d $f24, $sp, 58*8
            fst.d $f25, $sp, 59*8
            fst.d $f26, $sp, 60*8
            fst.d $f27, $sp, 61*8
            fst.d $f28, $sp, 62*8
            fst.d $f29, $sp, 63*8
            fst.d $f30, $sp, 64*8
            fst.d $f31, $sp, 65*8
            movcf2gr $t0, $fcc0
            st.b $t0, $sp, 528
            movcf2gr $t0, $fcc1
            st.b $t0, $sp, 529
            movcf2gr $t0, $fcc2
            st.b $t0, $sp, 530
            movcf2gr $t0, $fcc3
            st.b $t0, $sp, 531
            movcf2gr $t0, $fcc4
            st.b $t0, $sp, 532
            movcf2gr $t0, $fcc5
            st.b $t0, $sp, 533
            movcf2gr $t0, $fcc6
            st.b $t0, $sp, 534
            movcf2gr $t0, $fcc7
            st.b $t0, $sp, 535
            movfcsr2gr $t0, $fcsr0
            st.w $t0, $sp, 67*8
        .endm

        .macro LOAD_USER_FP
            fld.d $f0, $sp, 34*8
            fld.d $f1, $sp, 35*8
            fld.d $f2, $sp, 36*8
            fld.d $f3, $sp, 37*8
            fld.d $f4, $sp, 38*8
            fld.d $f5, $sp, 39*8
            fld.d $f6, $sp, 40*8
            fld.d $f7, $sp, 41*8
            fld.d $f8, $sp, 42*8
            fld.d $f9, $sp, 43*8
            fld.d $f10, $sp, 44*8
            fld.d $f11, $sp, 45*8
            fld.d $f12, $sp, 46*8
            fld.d $f13, $sp, 47*8
            fld.d $f14, $sp, 48*8
            fld.d $f15, $sp, 49*8
            fld.d $f16, $sp, 50*8
            fld.d $f17, $sp, 51*8
            fld.d $f18, $sp, 52*8
            fld.d $f19, $sp, 53*8
            fld.d $f20, $sp, 54*8
            fld.d $f21, $sp, 55*8
            fld.d $f22, $sp, 56*8
            fld.d $f23, $sp, 57*8
            fld.d $f24, $sp, 58*8
            fld.d $f25, $sp, 59*8
            fld.d $f26, $sp, 60*8
            fld.d $f27, $sp, 61*8
            fld.d $f28, $sp, 62*8
            fld.d $f29, $sp, 63*8
            fld.d $f30, $sp, 64*8
            fld.d $f31, $sp, 65*8
            ld.bu $t0, $sp, 528
            movgr2cf $fcc0, $t0
            ld.bu $t0, $sp, 529
            movgr2cf $fcc1, $t0
            ld.bu $t0, $sp, 530
            movgr2cf $fcc2, $t0
            ld.bu $t0, $sp, 531
            movgr2cf $fcc3, $t0
            ld.bu $t0, $sp, 532
            movgr2cf $fcc4, $t0
            ld.bu $t0, $sp, 533
            movgr2cf $fcc5, $t0
            ld.bu $t0, $sp, 534
            movgr2cf $fcc6, $t0
            ld.bu $t0, $sp, 535
            movgr2cf $fcc7, $t0
            ld.w $t0, $sp, 67*8
            movgr2fcsr $fcsr0, $t0
        .endm

        .macro SAVE_KERNEL_FP
            fst.d $f0, $sp, 13*8
            fst.d $f1, $sp, 14*8
            fst.d $f2, $sp, 15*8
            fst.d $f3, $sp, 16*8
            fst.d $f4, $sp, 17*8
            fst.d $f5, $sp, 18*8
            fst.d $f6, $sp, 19*8
            fst.d $f7, $sp, 20*8
            fst.d $f8, $sp, 21*8
            fst.d $f9, $sp, 22*8
            fst.d $f10, $sp, 23*8
            fst.d $f11, $sp, 24*8
            fst.d $f12, $sp, 25*8
            fst.d $f13, $sp, 26*8
            fst.d $f14, $sp, 27*8
            fst.d $f15, $sp, 28*8
            fst.d $f16, $sp, 29*8
            fst.d $f17, $sp, 30*8
            fst.d $f18, $sp, 31*8
            fst.d $f19, $sp, 32*8
            fst.d $f20, $sp, 33*8
            fst.d $f21, $sp, 34*8
            fst.d $f22, $sp, 35*8
            fst.d $f23, $sp, 36*8
            fst.d $f24, $sp, 37*8
            fst.d $f25, $sp, 38*8
            fst.d $f26, $sp, 39*8
            fst.d $f27, $sp, 40*8
            fst.d $f28, $sp, 41*8
            fst.d $f29, $sp, 42*8
            fst.d $f30, $sp, 43*8
            fst.d $f31, $sp, 44*8
            movcf2gr $t0, $fcc0
            st.b $t0, $sp, 360
            movcf2gr $t0, $fcc1
            st.b $t0, $sp, 361
            movcf2gr $t0, $fcc2
            st.b $t0, $sp, 362
            movcf2gr $t0, $fcc3
            st.b $t0, $sp, 363
            movcf2gr $t0, $fcc4
            st.b $t0, $sp, 364
            movcf2gr $t0, $fcc5
            st.b $t0, $sp, 365
            movcf2gr $t0, $fcc6
            st.b $t0, $sp, 366
            movcf2gr $t0, $fcc7
            st.b $t0, $sp, 367
            movfcsr2gr $t0, $fcsr0
            st.w $t0, $sp, 46*8
        .endm

        .macro LOAD_KERNEL_FP
            fld.d $f0, $sp, 13*8
            fld.d $f1, $sp, 14*8
            fld.d $f2, $sp, 15*8
            fld.d $f3, $sp, 16*8
            fld.d $f4, $sp, 17*8
            fld.d $f5, $sp, 18*8
            fld.d $f6, $sp, 19*8
            fld.d $f7, $sp, 20*8
            fld.d $f8, $sp, 21*8
            fld.d $f9, $sp, 22*8
            fld.d $f10, $sp, 23*8
            fld.d $f11, $sp, 24*8
            fld.d $f12, $sp, 25*8
            fld.d $f13, $sp, 26*8
            fld.d $f14, $sp, 27*8
            fld.d $f15, $sp, 28*8
            fld.d $f16, $sp, 29*8
            fld.d $f17, $sp, 30*8
            fld.d $f18, $sp, 31*8
            fld.d $f19, $sp, 32*8
            fld.d $f20, $sp, 33*8
            fld.d $f21, $sp, 34*8
            fld.d $f22, $sp, 35*8
            fld.d $f23, $sp, 36*8
            fld.d $f24, $sp, 37*8
            fld.d $f25, $sp, 38*8
            fld.d $f26, $sp, 39*8
            fld.d $f27, $sp, 40*8
            fld.d $f28, $sp, 41*8
            fld.d $f29, $sp, 42*8
            fld.d $f30, $sp, 43*8
            fld.d $f31, $sp, 44*8
            ld.bu $t0, $sp, 360
            movgr2cf $fcc0, $t0
            ld.bu $t0, $sp, 361
            movgr2cf $fcc1, $t0
            ld.bu $t0, $sp, 362
            movgr2cf $fcc2, $t0
            ld.bu $t0, $sp, 363
            movgr2cf $fcc3, $t0
            ld.bu $t0, $sp, 364
            movgr2cf $fcc4, $t0
            ld.bu $t0, $sp, 365
            movgr2cf $fcc5, $t0
            ld.bu $t0, $sp, 366
            movgr2cf $fcc6, $t0
            ld.bu $t0, $sp, 367
            movgr2cf $fcc7, $t0
            ld.w $t0, $sp, 46*8
            movgr2fcsr $fcsr0, $t0
        .endm

        .macro SAVE_REGS
            st.d    $ra, $sp,  1*8
            st.d    $tp, $sp,  2*8
            st.d    $a0, $sp,  4*8
            st.d    $a1, $sp,  5*8
            st.d    $a2, $sp,  6*8
            st.d    $a3, $sp,  7*8
            st.d    $a4, $sp,  8*8
            st.d    $a5, $sp,  9*8
            st.d    $a6, $sp, 10*8
            st.d    $a7, $sp, 11*8
            st.d    $t0, $sp, 12*8
            st.d    $t1, $sp, 13*8
            st.d    $t2, $sp, 14*8
            st.d    $t3, $sp, 15*8
            st.d    $t4, $sp, 16*8
            st.d    $t5, $sp, 17*8
            st.d    $t6, $sp, 18*8
            st.d    $t7, $sp, 19*8
            st.d    $t8, $sp, 20*8
            st.d    $r21,$sp, 21*8
            st.d    $fp, $sp, 22*8
            st.d    $s0, $sp, 23*8
            st.d    $s1, $sp, 24*8
            st.d    $s2, $sp, 25*8
            st.d    $s3, $sp, 26*8
            st.d    $s4, $sp, 27*8
            st.d    $s5, $sp, 28*8
            st.d    $s6, $sp, 29*8
            st.d    $s7, $sp, 30*8
            st.d    $s8, $sp, 31*8
            csrrd   $t0, KSAVE_USP
            st.d    $t0, $sp,  3*8

            csrrd	$t0, 0x1
            st.d	$t0, $sp, 8*32  // prmd

            csrrd   $t0, 0x6        
            st.d    $t0, $sp, 8*33  // era
        .endm

        .macro LOAD_REGS
            ld.d    $t0, $sp, 32*8
            csrwr   $t0, 0x1        // Write PRMD(PLV PIE PWE) to prmd

            ld.d    $t0, $sp, 33*8
            csrwr   $t0, 0x6        // Write Exception Address to ERA

            ld.d    $ra, $sp, 1*8
            ld.d    $tp, $sp, 2*8
            ld.d    $a0, $sp, 4*8
            ld.d    $a1, $sp, 5*8
            ld.d    $a2, $sp, 6*8
            ld.d    $a3, $sp, 7*8
            ld.d    $a4, $sp, 8*8
            ld.d    $a5, $sp, 9*8
            ld.d    $a6, $sp, 10*8
            ld.d    $a7, $sp, 11*8
            ld.d    $t0, $sp, 12*8
            ld.d    $t1, $sp, 13*8
            ld.d    $t2, $sp, 14*8
            ld.d    $t3, $sp, 15*8
            ld.d    $t4, $sp, 16*8
            ld.d    $t5, $sp, 17*8
            ld.d    $t6, $sp, 18*8
            ld.d    $t7, $sp, 19*8
            ld.d    $t8, $sp, 20*8
            ld.d    $r21,$sp, 21*8
            ld.d    $fp, $sp, 22*8
            ld.d    $s0, $sp, 23*8
            ld.d    $s1, $sp, 24*8
            ld.d    $s2, $sp, 25*8
            ld.d    $s3, $sp, 26*8
            ld.d    $s4, $sp, 27*8
            ld.d    $s5, $sp, 28*8
            ld.d    $s6, $sp, 29*8
            ld.d    $s7, $sp, 30*8
            ld.d    $s8, $sp, 31*8
            
            // restore sp
            ld.d    $sp, $sp, 3*8
        .endm

        .endif
        "#
    }
}
