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

// 不返回 &'static mut 页表切片，避免对同一物理页制造多个可变引用。
pub(super) fn read(pa: PhysAddr, i: usize) -> usize {
    debug_assert!(i < 512);
    // SAFETY: 仅传入 root/tables 持有的页或引导根页，i 是 9 位页索引。
    unsafe {
        ((pa.raw() | VIRT_ADDR_START) as *const usize)
            .add(i)
            .read_volatile()
    }
}
pub(super) fn write(pa: PhysAddr, i: usize, value: usize) {
    debug_assert!(i < 512);
    // SAFETY: 页由本对象独占持有，修改需 &mut self；借用的内核半区从不修改。
    unsafe {
        ((pa.raw() | VIRT_ADDR_START) as *mut usize)
            .add(i)
            .write_volatile(value);
    }
}
impl UserPageTable {
    pub(super) fn new() -> Result<Self, FrameError> {
        let root = OwnedFrame::new()?;
        let kernel = super::KERNEL_ROOT.load(core::sync::atomic::Ordering::Relaxed);
        debug_assert_ne!(kernel, 0, "kernel root must precede user spaces");
        #[cfg(target_arch = "riscv64")]
        for i in 256..512 {
            write(root.addr(), i, read(PhysAddr::new(kernel), i));
        }
        // 共享窗口 L1 表：后续栈映射只改该表，全部地址空间同时可见。
        let window = read(PhysAddr::new(kernel), WINDOW_ROOT_INDEX);
        debug_assert_ne!(window, 0, "kernel stack window root entry missing");
        write(root.addr(), WINDOW_ROOT_INDEX, window);
        Ok(Self {
            root,
            tables: Vec::new(),
            kernel,
        })
    }
    fn path(&self, va: usize) -> Option<(PhysAddr, usize)> {
        let mut pa = self.root.addr();
        for level in (1..=2).rev() {
            let pte = read(pa, (va >> (12 + 9 * level)) & 511);
            if pte == 0 {
                return None;
            }
            pa = arch::address(pte);
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
        let mut pa = self.root.addr();
        let mut missing = 0;
        for level in (1..=2).rev() {
            let pte = read(pa, (va >> (12 + 9 * level)) & 511);
            if pte == 0 {
                missing = level;
                break;
            }
            pa = arch::address(pte);
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
                let next = frame.addr();
                self.tables.push(frame);
                write(pa, (va >> (12 + 9 * level)) & 511, arch::table(next));
                pa = next;
            }
        }
        write(pa, (va >> 12) & 511, arch::leaf(data, flags));
        if self.is_active() {
            TLB::flush_vaddr(VirtAddr::new(va));
        }
        Ok(())
    }
    pub(super) fn translate(&self, va: usize) -> Option<(PhysAddr, MappingFlags)> {
        let (pa, i) = self.path(va)?;
        let pte = read(pa, i);
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
            write(pa, i, arch::leaf(data, flags));
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
            let pte = read(table, slot);
            let flags = arch::flags(pte);
            if flags.contains(MappingFlags::W) {
                write(
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
            write(pa, i, 0);
        }
        let mut released = false;
        let root = self.root.addr();
        let ri = (va >> 30) & 511;
        let r = read(root, ri);
        if r != 0 {
            let middle = arch::address(r);
            let mi = (va >> 21) & 511;
            let m = read(middle, mi);
            if m != 0 {
                let leaf = arch::address(m);
                if (0..512).all(|i| read(leaf, i) == 0) {
                    write(middle, mi, 0);
                    released = true;
                    self.release_table(leaf);
                }
            }
            if (0..512).all(|i| read(middle, i) == 0) {
                write(root, ri, 0);
                released = true;
                self.release_table(middle);
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
