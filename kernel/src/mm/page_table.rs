//! 可失败的用户页表：根与中间表页有唯一所有权；仅管理用户低半区
//! （rv 共享内核高半根项，la 内核走 DMW）。
use super::{
    arch,
    frame::{FrameError, OwnedFrame},
};
use alloc::vec::Vec;
use polyhal::{
    consts::VIRT_ADDR_START,
    pagetable::{MappingFlags, TLB},
    PhysAddr,
};

pub(super) struct UserPageTable {
    root: OwnedFrame,
    tables: Vec<OwnedFrame>,
    kernel: usize,
}

// 不返回 &'static mut 页表切片，避免对同一物理页制造多个可变引用。
fn read(pa: PhysAddr, i: usize) -> usize {
    debug_assert!(i < 512);
    // SAFETY: 仅传入 root/tables 持有的页或引导根页，i 是 9 位页索引。
    unsafe {
        ((pa.raw() | VIRT_ADDR_START) as *const usize)
            .add(i)
            .read_volatile()
    }
}
fn write(pa: PhysAddr, i: usize, value: usize) {
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
        #[cfg(target_arch = "riscv64")]
        for i in 256..512 {
            write(root.addr(), i, read(PhysAddr::new(kernel), i));
        }
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
        self.tables
            .try_reserve(missing)
            .map_err(|_| FrameError::OutOfMemory)?;
        let mut prepared: [Option<OwnedFrame>; 2] = [None, None];
        for frame in prepared.iter_mut().take(missing) {
            *frame = Some(OwnedFrame::new()?);
        }
        pa = self.root.addr();
        let mut frames = prepared.into_iter().flatten();
        for level in (1..=2).rev() {
            let i = (va >> (12 + 9 * level)) & 511;
            let mut pte = read(pa, i);
            if pte == 0 {
                // missing 由同一条路径预计算，期间 &mut self 排除并发修改。
                if let Some(frame) = frames.next() {
                    pte = arch::table(frame.addr());
                    self.tables.push(frame);
                    write(pa, i, pte);
                }
            }
            pa = arch::address(pte);
        }
        write(pa, (va >> 12) & 511, arch::leaf(data, flags));
        TLB::flush_all();
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
        }
        TLB::flush_all();
    }
    pub(super) fn unmap(&mut self, va: usize) {
        if let Some((pa, i)) = self.path(va) {
            write(pa, i, 0);
        }
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
                    TLB::flush_all();
                    self.release_table(leaf);
                }
            }
            if (0..512).all(|i| read(middle, i) == 0) {
                write(root, ri, 0);
                TLB::flush_all();
                self.release_table(middle);
            }
        }
        TLB::flush_all();
    }
    fn release_table(&mut self, pa: PhysAddr) {
        if let Some(i) = self.tables.iter().position(|f| f.addr().raw() == pa.raw()) {
            self.tables.swap_remove(i);
        }
    }
    pub(super) fn activate(&self) {
        arch::switch(self.root.addr().raw());
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
