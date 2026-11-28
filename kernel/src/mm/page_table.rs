//! 可失败的用户页表：根与中间表页有唯一所有权；仅管理用户低半区
//! （rv 复制内核高半根项，两架构均共享内核栈窗口根项；la 直映走 DMW）。
use super::{
    arch,
    frame::{FrameError, OwnedFrame},
    kstack::WINDOW_ROOT_INDEX,
};
use alloc::vec::Vec;
use polyhal::{
    consts::VIRT_ADDR_START,
    pagetable::{MappingFlags, TLB},
    PhysAddr, VirtAddr,
};

pub(super) struct UserPageTable {
    root: OwnedFrame,
    tables: Vec<OwnedFrame>,
    kernel: usize,
}

/// 仅限本模块构造的页表物理页凭证，保证指向已拥有的表页或启动内核根页。
#[derive(Clone, Copy)]
struct TablePa(PhysAddr);

impl TablePa {
    fn from_frame(frame: &OwnedFrame) -> Self {
        Self(frame.addr())
    }

    fn from_kernel_root(pa: usize) -> Self {
        assert_ne!(pa, 0, "kernel root must precede user spaces");
        Self(PhysAddr::new(pa))
    }

    fn from_child_pte(pte: usize) -> Self {
        Self(arch::address(pte))
    }

    fn read(self, i: usize) -> usize {
        assert!(i < 512, "page table index out of bounds");
        // SAFETY: `TablePa` 仅由 `OwnedFrame`、已初始化内核根或有效下级表项构造，
        // `i < 512` 保证位于单页 512 项范围内，且不构造页表切片引用。
        unsafe {
            ((self.0.raw() | VIRT_ADDR_START) as *const usize)
                .add(i)
                .read_volatile()
        }
    }
}

impl UserPageTable {
    fn write_entry(&mut self, table: TablePa, i: usize, value: usize) {
        assert!(i < 512, "page table index out of bounds");
        // SAFETY: `&mut self` 保证独占修改本页表拥有的表页，借用的内核高半区从不经此写入，
        // `i < 512` 保证位于单页 512 项范围内，且不构造页表切片引用。
        unsafe {
            ((table.0.raw() | VIRT_ADDR_START) as *mut usize)
                .add(i)
                .write_volatile(value);
        }
    }

    pub(super) fn new() -> Result<Self, FrameError> {
        let root = OwnedFrame::new()?;
        let kernel = super::KERNEL_ROOT.load(core::sync::atomic::Ordering::Relaxed);
        let kernel_table = TablePa::from_kernel_root(kernel);
        let mut table = Self {
            root,
            tables: Vec::new(),
            kernel,
        };
        let root_pa = TablePa::from_frame(&table.root);
        #[cfg(target_arch = "riscv64")]
        for i in 256..512 {
            table.write_entry(root_pa, i, kernel_table.read(i));
        }
        // 共享窗口 L1 表：后续栈映射只改该表，全部地址空间同时可见。
        let window = kernel_table.read(WINDOW_ROOT_INDEX);
        assert_ne!(window, 0, "kernel stack window root entry missing");
        table.write_entry(root_pa, WINDOW_ROOT_INDEX, window);
        Ok(table)
    }
    fn path(&self, va: usize) -> Option<(TablePa, usize)> {
        let mut pa = TablePa::from_frame(&self.root);
        for level in (1..=2).rev() {
            let pte = pa.read((va >> (12 + 9 * level)) & 511);
            if pte == 0 {
                return None;
            }
            pa = TablePa::from_child_pte(pte);
        }
        Some((pa, (va >> 12) & 511))
    }
    /// 先预备所有缺失页表页，再发布表项；任何分配失败都不会改变原表。
    pub(super) fn map(
        &mut self,
        va: usize,
        data: PhysAddr,
        flags: MappingFlags,
    ) -> Result<(), FrameError> {
        let mut pa = TablePa::from_frame(&self.root);
        let mut missing = 0;
        for level in (1..=2).rev() {
            let pte = pa.read((va >> (12 + 9 * level)) & 511);
            if pte == 0 {
                missing = level;
                break;
            }
            pa = TablePa::from_child_pte(pte);
        }
        if missing != 0 {
            self.tables
                .try_reserve(missing)
                .map_err(|_| FrameError::OutOfMemory)?;
            let mut prepared: [Option<OwnedFrame>; 2] = [None, None];
            for frame in prepared.iter_mut().take(missing) {
                *frame = Some(OwnedFrame::new()?);
            }
            // pa 已指向首个缺项所在的表；下级新表均已清零。
            for (level, frame) in (1..=missing).rev().zip(prepared.into_iter().flatten()) {
                let next = TablePa::from_frame(&frame);
                self.tables.push(frame);
                self.write_entry(pa, (va >> (12 + 9 * level)) & 511, arch::table(next.0));
                pa = next;
            }
        }
        self.write_entry(pa, (va >> 12) & 511, arch::leaf(data, flags));
        if self.is_active() {
            TLB::flush_vaddr(VirtAddr::new(va));
        }
        Ok(())
    }
    pub(super) fn translate(&self, va: usize) -> Option<(PhysAddr, MappingFlags)> {
        let (pa, i) = self.path(va)?;
        let pte = pa.read(i);
        let flags = arch::flags(pte);
        if flags.is_empty() {
            None
        } else {
            Some((PhysAddr::new(arch::address(pte).raw() + (va & 4095)), flags))
        }
    }
    /// 只更新已有表槽；PROT_NONE 保留数据页所有权，但硬件叶项清零。
    pub(super) fn protect(&mut self, va: usize, data: PhysAddr, flags: MappingFlags) {
        if let Some((pa, i)) = self.path(va) {
            self.write_entry(pa, i, arch::leaf(data, flags));
            if self.is_active() {
                TLB::flush_vaddr(VirtAddr::new(va));
            }
        }
    }
    /// 在返回用户态前撤销整批共享页的写权限。地址有序时可复用同一张末级表。
    pub(super) fn write_protect_pages(&mut self, pages: impl Iterator<Item = usize>) {
        let mut last = None;
        let mut changed = false;
        for va in pages {
            let key = va >> 21;
            let table = match last {
                Some((prev, table)) if prev == key => table,
                _ => {
                    let Some((table, _)) = self.path(va) else {
                        continue;
                    };
                    last = Some((key, table));
                    table
                }
            };
            let slot = (va >> 12) & 511;
            let pte = table.read(slot);
            let flags = arch::flags(pte);
            if flags.contains(MappingFlags::W) {
                self.write_entry(
                    table,
                    slot,
                    arch::leaf(arch::address(pte), flags - MappingFlags::W),
                );
                changed = true;
            }
        }
        if changed && self.is_active() {
            TLB::flush_all();
        }
    }
    pub(super) fn unmap(&mut self, va: usize) {
        let active = self.is_active();
        if let Some((pa, i)) = self.path(va) {
            self.write_entry(pa, i, 0);
        }
        let mut released = false;
        let root = TablePa::from_frame(&self.root);
        let ri = (va >> 30) & 511;
        let r = root.read(ri);
        if r != 0 {
            let middle = TablePa::from_child_pte(r);
            let mi = (va >> 21) & 511;
            let m = middle.read(mi);
            if m != 0 {
                let leaf = TablePa::from_child_pte(m);
                if (0..512).all(|i| leaf.read(i) == 0) {
                    self.write_entry(middle, mi, 0);
                    released = true;
                    self.release_table(leaf.0);
                }
            }
            if (0..512).all(|i| middle.read(i) == 0) {
                self.write_entry(root, ri, 0);
                released = true;
                self.release_table(middle.0);
            }
        }
        if active {
            TLB::flush_vaddr(VirtAddr::new(va));
            if released {
                TLB::flush_all();
            }
        }
    }
    fn release_table(&mut self, pa: PhysAddr) {
        if let Some(i) = self.tables.iter().position(|f| f.addr().raw() == pa.raw()) {
            self.tables.swap_remove(i);
        }
    }
    pub(super) fn activate(&self) {
        if !self.is_active() {
            arch::switch(self.root.addr().raw());
        }
    }
    pub(super) fn deactivate(&self) {
        arch::switch(self.kernel);
    }
    pub(super) fn is_active(&self) -> bool {
        arch::current() == self.root.addr().raw()
    }
}
impl Drop for UserPageTable {
    fn drop(&mut self) {
        // 在支持跨核共享之前，地址空间 !Send/!Sync 且只在创建核使用。
        if self.is_active() {
            self.deactivate();
        }
    }
}
