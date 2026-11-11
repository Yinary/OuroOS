//! 页表硬件适配：Sv39 与 LoongArch 三层 4 KiB 页表的 PTE 编码、切换
//! 与 TLB refill 集中于此。LoongArch NR/NX 位值（61/62）经 Linux
//! pgtable-bits.h 核对。NX 决策与 refill 实现依据见 docs/ostd-contracts.md §1/§2。
use polyhal::{
    pagetable::{MappingFlags as F, PageTable, TLB},
    PhysAddr,
};

pub(super) fn current() -> usize {
    PageTable::current().root().raw()
}

/// 调用方保证根页有效、内核映射保留，并在本核独占切换上下文。
pub(super) fn switch(root: usize) {
    #[cfg(target_arch = "loongarch64")]
    install_refill();
    // SAFETY: 页表层持有 root 的页所有权；RV 复制了内核半区，LA 保留 DMW。
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("csrw satp, {}", in(reg) ((8usize << 60) | (root >> 12)));
        #[cfg(target_arch = "loongarch64")]
        core::arch::asm!("csrwr {}, 0x19", inout(reg) root => _);
    }
    TLB::flush_all();
}
#[cfg(target_arch = "riscv64")]
pub(super) fn table(pa: PhysAddr) -> usize {
    (pa.raw() >> 2) | 1
}
#[cfg(target_arch = "loongarch64")]
pub(super) fn table(pa: PhysAddr) -> usize {
    pa.raw()
}
#[cfg(target_arch = "riscv64")]
pub(super) fn address(pte: usize) -> PhysAddr {
    PhysAddr::new((pte >> 10) << 12)
}
#[cfg(target_arch = "loongarch64")]
pub(super) fn address(pte: usize) -> PhysAddr {
    PhysAddr::new(pte & 0x0000_ffff_ffff_f000)
}
#[cfg(target_arch = "riscv64")]
pub(super) fn leaf(pa: PhysAddr, f: F) -> usize {
    if !f.intersects(F::RWX) {
        return 1 << 9;
    }
    (pa.raw() >> 2)
        | 1
        | 16
        | 64
        | if f.contains(F::R) { 2 } else { 0 }
        | if f.contains(F::W) { 4 | 128 } else { 0 }
        | 8
}
#[cfg(target_arch = "loongarch64")]
pub(super) fn leaf(pa: PhysAddr, f: F) -> usize {
    if !f.intersects(F::RWX) {
        return 1 << 9;
    }
    pa.raw()
        | 1
        | (3 << 2)
        | (1 << 4)
        | if f.contains(F::W) { 2 | (1 << 8) } else { 0 }
        | if f.contains(F::R) { 0 } else { 1 << 61 }
}
#[cfg(target_arch = "riscv64")]
pub(super) fn flags(pte: usize) -> F {
    if pte & 1 == 0 || pte & 14 == 0 {
        return F::empty();
    }
    let mut f = F::U;
    if pte & 2 != 0 {
        f |= F::R;
    }
    if pte & 4 != 0 {
        f |= F::W;
    }
    if pte & 8 != 0 {
        f |= F::X;
    }
    f
}
#[cfg(target_arch = "loongarch64")]
pub(super) fn flags(pte: usize) -> F {
    if pte & 1 == 0 {
        return F::empty();
    }
    let mut f = F::U;
    if pte & (1 << 61) == 0 {
        f |= F::R;
    }
    if pte & 2 != 0 {
        f |= F::W;
    }
    if pte & (1 << 62) == 0 {
        f |= F::X;
    }
    f
}

// 依据 LoongArch Reference Manual Vol.1 §5.4、§7.5 独立实现 4 KiB 软件填充。
// https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html
// QEMU 10.0.2 的 LDPTE 会丢弃 NR/NX，高位权限通过普通 LD.D 完整送入 CSR。
// 这是通用页表填充路径，不根据程序/测例选择行为；不支持大页。
// SAVE3(0x33) 专用于保存 t1，PolyHAL 0.4.0 仅占用 SAVE0..2；升级 HAL 须复核。
// SAFETY: refill 在直接寻址、关闭中断下运行，表页由活动空间持有；只读取
// 页对齐的三层表，空表产生无效 TLB 项；t0/t1 都保存恢复，不使用用户栈。
#[cfg(target_arch = "loongarch64")]
core::arch::global_asm!(
    r#"
    .section .text
    .balign 4096
    .global __ouro_tlb_refill
__ouro_tlb_refill:
    csrwr $t0, 0x8b
    csrwr $t1, 0x33
    csrrd $t0, 0x1b
    beqz $t0, 2f
    lddir $t0, $t0, 3
    beqz $t0, 2f
    lddir $t0, $t0, 1
    beqz $t0, 2f
    csrrd $t1, 0x89
    bstrpick.d $t1, $t1, 20, 13
    slli.d $t1, $t1, 4
    add.d $t0, $t0, $t1
    ld.d $t1, $t0, 0
    bstrins.d $t1, $zero, 11, 7
    csrwr $t1, 0x8c
    ld.d $t1, $t0, 8
    bstrins.d $t1, $zero, 11, 7
    csrwr $t1, 0x8d
    b 3f
2:
    csrwr $zero, 0x8c
    csrwr $zero, 0x8d
3:
    tlbfill
    csrrd $t0, 0x8b
    csrrd $t1, 0x33
    ertn
"#
);
#[cfg(target_arch = "loongarch64")]
fn install_refill() {
    extern "C" {
        fn __ouro_tlb_refill();
    }
    let entry = __ouro_tlb_refill as usize & 0x0000_ffff_ffff_ffff;
    // SAFETY: 入口是镜像内 4 KiB 对齐的持久汇编代码；仅更换本核 refill 向量。
    unsafe {
        core::arch::asm!("csrwr {}, 0x88", inout(reg) entry => _);
    }
}
