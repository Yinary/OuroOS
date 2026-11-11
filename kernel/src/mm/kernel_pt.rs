//! rv 内核页表：启动期一次性细化镜像权限（text RX / rodata R / data RW），
//! 其余 RAM 以大页直映；la 内核映射由 DMW 承担，本模块为空实现。
// SAFETY（本模块全部 unsafe 函数共享）：仅启动单线程阶段、旧页表
// 活跃时调用；表页由帧分配器返回且已清零，经 pa|VIRT 别名窗口访问。

#[cfg(target_arch = "riscv64")]
use polyhal::{consts::VIRT_ADDR_START, mem::get_mem_areas, PhysAddr};

#[cfg(target_arch = "riscv64")]
use super::{arch, frame};

// Sv39 PTE 标志位（仅 rv 填表使用）
#[cfg(target_arch = "riscv64")]
mod pte {
    pub const V: u64 = 1;
    pub const R: u64 = 1 << 1;
    pub const W: u64 = 1 << 2;
    pub const X: u64 = 1 << 3;
    pub const G: u64 = 1 << 5;
    pub const A: u64 = 1 << 6;
    pub const D: u64 = 1 << 7;
}
#[cfg(target_arch = "riscv64")]
use pte::*;

#[cfg(target_arch = "riscv64")]
const ENTRIES: usize = 512;
#[cfg(target_arch = "riscv64")]
const PAGE_SIZE: usize = 0x1000;
#[cfg(target_arch = "riscv64")]
const LARGE_PAGE: usize = 0x20_0000;
#[cfg(target_arch = "riscv64")]
const GIB: usize = 1 << 30;

/// 替换启动页表。须在帧分配器初始化之后、第一个用户地址空间创建之前调用。
pub fn init() {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        init_rv();
    }
    #[cfg(target_arch = "loongarch64")]
    {
        // 内核映射由 DMW 承担，无页表可建
    }
}

/// 启动粗页表（BOOT_PT）物理地址，切换后保留用于诊断与回切。
#[cfg(target_arch = "riscv64")]
static BOOT_PT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

// SAFETY: 启动单线程阶段调用；此刻运行于旧页表，别名窗口与链接符号可达。
#[cfg(target_arch = "riscv64")]
unsafe fn init_rv() {
    extern "C" {
        fn stext();
        fn etext();
        fn _sdata();
        fn _end();
    }
    // 链接符号转物理地址，data 起点向下页对齐
    let va2pa = |v: usize| v & !VIRT_ADDR_START;
    let text = va2pa(stext as usize);
    let ro_end = va2pa(etext as usize);
    let data = va2pa(_sdata as usize) & !(PAGE_SIZE - 1);
    let image_end = va2pa(_end as usize);
    assert!(text <= ro_end && ro_end <= data && data <= image_end);
    let ram_top = get_mem_areas().map(|&(a, s)| a + s).max().unwrap();

    let root = frame::frame_alloc(1).expect("kernel page table: OOM");
    let img_l1 = frame::frame_alloc(1).expect("kernel page table: OOM");
    let img_base = text & !(LARGE_PAGE - 1);
    let img_end = image_end.div_ceil(LARGE_PAGE) * LARGE_PAGE;
    // 断言镜像不跨 GiB 边界
    assert!(img_base >> 30 == (img_end - 1) >> 30);

    // 镜像区每 2 MiB 一张 L0
    let l0_count = (img_end - img_base) / LARGE_PAGE;
    let mut l0s = alloc::vec::Vec::with_capacity(l0_count);
    for _ in 0..l0_count {
        l0s.push(frame::frame_alloc(1).expect("kernel page table: OOM"));
    }

    // 填镜像所在 GiB 的 L1
    for (slot, l0) in l0s.iter().enumerate() {
        let base = img_base + slot * LARGE_PAGE;
        fill_l0(l0, base, text, ro_end, data, image_end);
        write_table(&img_l1, (base >> 21) & 0x1ff, l0.raw());
    }
    // 镜像前：OpenSBI/DTB 区，只读
    let gi_base = img_base & !(GIB - 1);
    for pa in (gi_base..img_base).step_by(LARGE_PAGE) {
        write_leaf(&img_l1, (pa >> 21) & 0x1ff, pa, V | R | A | D | G);
    }
    // 镜像后至 RAM 顶：RWX 大页
    fill_large_leaves(&img_l1, img_end, ram_top.min(gi_base + GIB));

    // 填根表
    write_table(&root, 256 + (gi_base >> 30), img_l1.raw());
    fill_root_tail(&root, gi_base + GIB, ram_top);

    // QEMU virt 的 UART 与 VirtIO MMIO，只有内核可读写。
    let io_l1 = frame::frame_alloc(1).expect("kernel MMIO table: OOM");
    write_leaf(
        &io_l1,
        0x1000_0000 >> 21,
        0x1000_0000,
        V | R | W | A | D | G,
    );
    write_table(&root, 256, io_l1.raw());

    // 切换前软件走表自检
    let va = |pa: usize| pa | VIRT_ADDR_START;
    let check = |pa: usize, want_flags: u64| {
        let pte = leaf_at(root, va(pa)).unwrap_or_else(|| panic!("kpt: unmapped {:#x}", pa));
        assert_eq!(pte & 0x3FF, want_flags, "kpt: flags @ {:#x}", pa);
        pte
    };
    // 镜像段：4K 叶子，物理地址应精确回读
    for (pa, want) in [
        (text, V | R | X | A | D | G),
        (ro_end, V | R | A | D | G),
        (data, V | R | W | A | D | G),
        (image_end, V | R | W | X | A | D | G),
    ] {
        let pte = check(pa, want);
        assert_eq!(((pte >> 10) << 12) as usize, pa, "kpt: pa @ {:#x}", pa);
    }
    // 大页区与无效区
    check(ram_top - PAGE_SIZE, V | R | W | X | A | D | G);
    check(0x1000_0000, V | R | W | A | D | G); // MMIO
    assert_eq!(leaf_at(root, text), None); // 无恒等窗口

    BOOT_PT.store(arch::current(), core::sync::atomic::Ordering::Relaxed);
    // SAFETY: root 为有效 Sv39 根表，高半区映射与当前执行地址一致；
    // arch::switch 内部写 satp 并全量刷 TLB，切换后取指立即走新表。
    arch::switch(root.raw());
}

/// 填一张 L0：页粒度按段权限划分，超出镜像的部分保持直接映射语义。
// SAFETY: l0 指向本函数独占的已清零表页。
#[cfg(target_arch = "riscv64")]
unsafe fn fill_l0(
    l0: &PhysAddr,
    base: usize,
    text: usize,
    ro_end: usize,
    data: usize,
    image_end: usize,
) {
    for i in 0..ENTRIES {
        let pa = base + i * PAGE_SIZE;
        let flags = if pa < text || pa >= ro_end && pa < data {
            V | R | A | D | G
        } else if pa < ro_end {
            V | R | X | A | D | G
        } else if pa < image_end {
            V | R | W | A | D | G
        } else {
            V | R | W | X | A | D | G
        };
        write_leaf(l0, i, pa, flags);
    }
}

/// 用 2 MiB 叶子填满 [start, end)。
// SAFETY: l1 指向本函数独占的已清零表页。
#[cfg(target_arch = "riscv64")]
unsafe fn fill_large_leaves(l1: &PhysAddr, start: usize, end: usize) {
    for pa in (start..end).step_by(LARGE_PAGE) {
        write_leaf(l1, (pa >> 21) & 0x1ff, pa, V | R | W | X | A | D | G);
    }
}

/// RAM 超出镜像 GiB 的部分：整 GiB 用 1 GiB 叶子，尾部 GiB 用 2 MiB 叶子。
// SAFETY: root 独占；尾部 L1 为新分配的已清零页。
#[cfg(target_arch = "riscv64")]
unsafe fn fill_root_tail(root: &PhysAddr, start: usize, ram_top: usize) {
    let mut pa = start;
    while pa < ram_top {
        let idx = 256 + (pa >> 30);
        if pa + GIB <= ram_top {
            write_leaf(root, idx, pa, V | R | W | X | A | D | G);
            pa += GIB;
        } else {
            let l1 = frame::frame_alloc(1).expect("kernel page table: OOM");
            fill_large_leaves(&l1, pa, ram_top);
            write_table(root, idx, l1.raw());
            pa = ram_top;
        }
    }
}

/// 软件走表：返回命中的叶子 PTE（大页或 4K 页）。
// SAFETY: root 及下级表页均为已填好的有效表，索引由 9 位页号截断。
#[cfg(target_arch = "riscv64")]
unsafe fn leaf_at(root: PhysAddr, va: usize) -> Option<u64> {
    let mut pte = read_pte(&root, (va >> 30) & 0x1ff);
    for shift in [21, 12] {
        if pte & V == 0 {
            return None;
        }
        if pte & (R | W | X) != 0 {
            return Some(pte);
        }
        pte = read_pte(
            &PhysAddr::new(((pte >> 10) << 12) as usize),
            (va >> shift) & 0x1ff,
        );
    }
    (pte & V != 0).then_some(pte)
}

/// 写叶子表项：pa 右移 2 位即 ppn << 10。
// SAFETY: table 指向独占表页，idx < 512。
#[cfg(target_arch = "riscv64")]
unsafe fn write_leaf(table: &PhysAddr, idx: usize, pa: usize, flags: u64) {
    pte_slot(table, idx).write_volatile(((pa as u64) >> 2) | flags);
}

/// 写下一级表指针项。
// SAFETY: table 指向独占表页，idx < 512。
#[cfg(target_arch = "riscv64")]
unsafe fn write_table(table: &PhysAddr, idx: usize, next: usize) {
    pte_slot(table, idx).write_volatile(((next as u64) >> 2) | V);
}

/// 读取表项。
// SAFETY: table 为有效表页，idx < 512。
#[cfg(target_arch = "riscv64")]
unsafe fn read_pte(table: &PhysAddr, idx: usize) -> u64 {
    pte_slot(table, idx).read_volatile()
}

/// 表项槽地址：经高位别名窗口访问物理页。
#[cfg(target_arch = "riscv64")]
unsafe fn pte_slot(table: &PhysAddr, idx: usize) -> *mut u64 {
    // SAFETY: 页由帧分配器返回且已清零；启动阶段单线程，无并发访问。
    unsafe { ((table.raw() | VIRT_ADDR_START) as *mut u64).add(idx) }
}
