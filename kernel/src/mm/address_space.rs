//! 用户地址空间：映射、页面所有权与清理。
//!
//! 初版用户布局（两架构共用，4 KiB 页，不承诺为永久布局）：
//!
//! ```text
//! [0x0000_0000, 0x0000_1000)  零页，不映射
//! [0x0000_1000, 0x0001_0000)  未映射空洞（ELF 自 0x0001_0000 起链接）
//! [0x0001_0000, ...)          自编 ELF 的 PT_LOAD 段，按段权限逐页映射
//! [0x7fff_b000, 0x7fff_c000)  栈保护页，不映射
//! [0x7fff_c000, 0x8000_0000)  用户栈，4 页，向低地址增长
//! ```
//!
//! 所有权约定：
//! - `frames` 记录本地址空间**拥有**的用户数据页，Drop 时逐页归还帧分配器；
//! - 页表资源由 [`PageTableWrapper`] 持有，其 Drop 只释放用户半区的
//!   页表页（rv 高半区为与内核共享的根条目，loongarch 内核走 DMW），
//!   不会释放数据页，因此与本处不冲突、无双重释放；
//! - 必须先 [`UserAddressSpace::deactivate`] 切回内核页表再 drop：
//!   rv 侧 satp 若仍指向用户根页，释放后取指/访存会走向已回收的页帧。

use polyhal::{
    consts::VIRT_ADDR_START,
    pagetable::{MappingFlags, MappingSize, PageTable, PageTableWrapper, PAGE_SIZE},
    PhysAddr, VirtAddr,
};

use alloc::{collections::BTreeSet, vec::Vec};

use super::frame;

/// 用户可用地址下界（零页 [0, 0x1000) 不映射）
pub const USER_BASE: usize = 0x1000;
/// 用户可用地址上界（不含）
pub const USER_TOP: usize = 0x8000_0000;
/// 用户栈顶（初始 sp，16 字节对齐，满足两个目标 ABI 的栈对齐要求）
pub const USER_STACK_TOP: usize = USER_TOP;
/// 用户栈底（4 页）
pub const USER_STACK_BOTTOM: usize = 0x7fff_c000;
/// 栈保护页下界（[GUARD_BOTTOM, USER_STACK_BOTTOM) 不映射）
pub const GUARD_BOTTOM: usize = 0x7fff_b000;

/// 映射失败原因
#[derive(Debug)]
pub enum MapError {
    /// 目标页不在用户地址范围内
    OutOfUserRange,
    /// 目标页已存在映射（加载器不支持页级重叠，拒绝而不是覆盖）
    Overlap,
    /// ELF 段侵入栈或栈保护页
    HitsStack,
}

/// 用户地址空间：一个用户任务独占一份。
pub struct UserAddressSpace {
    /// 用户页表。rv 含独立用户低位映射 + 复制自内核的高位条目；
    /// loongarch64 只有用户低位映射，内核高位依赖 DMW 窗口。
    pt: PageTableWrapper,
    /// 创建时（当前 CPU 处于内核页表）保存的页表，deactivate 时恢复。
    /// rv 为引导页表；loongarch64 为 PGDL 原值（引导阶段未建立映射页表）。
    kernel_pt: PageTable,
    /// 本空间拥有的用户数据页（分配后已清零），drop 时归还。
    frames: Vec<PhysAddr>,
    /// 已映射的用户虚拟页号集合。
    ///
    /// 用于页级重叠检测：polyhal 的 `PageTable::translate` 在最后一级
    /// 不检查叶子 PTE 有效性（只要中间表存在就返回 Some），不能用来
    /// 判断某页是否真的映射过；这里自己记录，也同时是页面归属的清单。
    mapped: BTreeSet<usize>,
}

impl UserAddressSpace {
    /// 创建空的用户地址空间。
    ///
    /// 必须在内核页表处于活动状态时调用：rv 的 `PageTableWrapper::alloc`
    /// 会从**当前** satp 复制内核高位条目。
    pub fn new() -> Self {
        Self {
            pt: PageTableWrapper::alloc(),
            kernel_pt: PageTable::current(),
            frames: Vec::new(),
            mapped: BTreeSet::new(),
        }
    }

    /// 分配一页物理帧，清零后映射到 `vaddr`（须页对齐），返回该物理帧。
    ///
    /// 清零是安全要求：避免把内核残留数据经用户映射泄漏给用户程序。
    pub fn map_alloc(&mut self, vaddr: usize, flags: MappingFlags) -> Result<PhysAddr, MapError> {
        if vaddr % PAGE_SIZE != 0 || vaddr < USER_BASE || vaddr + PAGE_SIZE > USER_TOP {
            return Err(MapError::OutOfUserRange);
        }
        if !self.mapped.insert(vaddr / PAGE_SIZE) {
            // 页级重叠：拒绝而不是覆盖已有映射
            return Err(MapError::Overlap);
        }
        let paddr = frame::frame_alloc(1);
        paddr.clear_len(PAGE_SIZE);
        self.pt
            .map_page(VirtAddr::new(vaddr), paddr, flags, MappingSize::Page4KB);
        self.frames.push(paddr);
        Ok(paddr)
    }

    /// 从 `vaddr` 起连续分配 `count` 页（用于用户栈）。
    pub fn map_alloc_range(
        &mut self,
        vaddr: usize,
        count: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        for i in 0..count {
            // 页对齐已由调用方（常量布局）保证；逐页检查仍会做范围校验
            self.map_alloc(vaddr + i * PAGE_SIZE, flags)?;
        }
        Ok(())
    }

    /// 映射用户栈区间 [USER_STACK_BOTTOM, USER_STACK_TOP)。
    pub fn map_stack(&mut self) -> Result<(), MapError> {
        // 栈权限：用户可读写、不可执行（loongarch64 侧 NX 无法表达，见模块注释）
        self.map_alloc_range(
            USER_STACK_BOTTOM,
            (USER_STACK_TOP - USER_STACK_BOTTOM) / PAGE_SIZE,
            MappingFlags::URW,
        )
    }

    /// 翻译用户虚拟地址，返回（物理地址, 映射权限）。
    ///
    /// 注意：polyhal 的 translate 在叶子级不检查 PTE 有效性，只要中间
    /// 表存在就返回 Some（物理地址无意义、flags 为空），调用方必须检查
    /// flags 是否含 U 位；未映射页和内核高位地址都因此被拒。只会命中
    /// 本空间映射过的页：rv 侧内核高位条目是大页 PTE（非表项），三级
    /// 走表在根级即返回 None；loongarch64 侧 PGDL 树中没有内核条目。
    pub fn translate(&self, vaddr: usize) -> Option<(PhysAddr, MappingFlags)> {
        self.pt.translate(VirtAddr::new(vaddr))
    }

    /// 检查 `[start, start+len)` 是否落在用户地址范围内且不触及栈保护页。
    pub fn check_user_span(start: usize, len: usize) -> Result<(), MapError> {
        let Some(end) = start.checked_add(len) else {
            return Err(MapError::OutOfUserRange);
        };
        if start < USER_BASE || end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        Ok(())
    }

    /// 切换到本用户页表（change 内部包含全量 TLB flush）。
    pub fn activate(&self) {
        self.pt.change();
    }

    /// 切回创建时保存的内核页表（同样包含全量 TLB flush，
    /// 用户 PTE 无全局位，切换后 TLB 不再引用用户页表内容）。
    pub fn deactivate(&self) {
        self.kernel_pt.change();
    }
}

impl Drop for UserAddressSpace {
    fn drop(&mut self) {
        // 前提（由调用方 user.rs 保证）：此时 CPU 已切回内核页表，
        // 没有任何 CPU 的 satp/PGDL 还指向本空间的页表。
        for paddr in self.frames.drain(..) {
            frame::frame_dealloc(paddr);
        }
        // pt（PageTableWrapper）随后按字段顺序 drop，释放用户半区页表页。
    }
}

/// 经内核直接映射窗口访问物理地址的辅助函数：返回物理页对应的内核
/// 虚拟地址。rv = pa | 0xffffffc0_00000000（引导页表高半区 1G 大页），
/// loongarch64 = pa | 0x9000_0000_00000000（DMW1，仅 PLV0）。
pub fn phys_to_kernel_vaddr(paddr: PhysAddr) -> usize {
    paddr.raw() | VIRT_ADDR_START
}
