//! 内核栈：窗口虚拟槽（低地址端 guard 不映射）+ 连续物理页。窗口下级
//! 页表由全部地址空间共享，guard 溢出即页错误。契约见 docs/ostd-contracts.md §1。

use core::sync::atomic::{AtomicUsize, Ordering};

use polyhal::{
    consts::VIRT_ADDR_START,
    pagetable::{PAGE_SIZE, TLB},
    PhysAddr,
};
use spin::Mutex;

use super::{
    arch,
    frame::{self, FrameError},
};

/// 窗口虚拟区间：16 GiB 起 16 MiB，避开用户低半区与两架构内核直映/DMW。
pub const WINDOW_BASE: usize = 0x4_0000_0000;
const WINDOW_SIZE: usize = 0x0100_0000;
/// 窗口在根表中的索引；用户页表创建时复制该项以共享下级表。
pub(super) const WINDOW_ROOT_INDEX: usize = (WINDOW_BASE >> 30) & 511;

const WINDOW_PAGES: usize = WINDOW_SIZE / PAGE_SIZE;
const L0_COUNT: usize = WINDOW_PAGES / 512;
const L0_ENTRIES: usize = 512;

/// 窗口 L1 表的物理地址，初始化后不变。
static L1_TABLE: AtomicUsize = AtomicUsize::new(0);

struct Window {
    used: [u64; WINDOW_PAGES / 64],
    ready: bool,
}

static WINDOW: Mutex<Window> = Mutex::new(Window {
    used: [0; WINDOW_PAGES / 64],
    ready: false,
});

fn pte_slot(table: PhysAddr, index: usize) -> *mut usize {
    debug_assert!(index < L0_ENTRIES);
    // SAFETY: table 为帧分配器返回的整页，经直映别名可写，index 在页内。
    unsafe { ((table.raw() | VIRT_ADDR_START) as *mut usize).add(index) }
}
fn read_pte(table: PhysAddr, index: usize) -> usize {
    // SAFETY: 同上，只读已分配表页内的表项。
    unsafe { pte_slot(table, index).read_volatile() }
}
fn write_pte(table: PhysAddr, index: usize, value: usize) {
    // SAFETY: 同上；单核独占修改，表页已初始化。
    unsafe { pte_slot(table, index).write_volatile(value) }
}

fn l0_for(page: usize) -> PhysAddr {
    debug_assert!(page < WINDOW_PAGES);
    let l1 = PhysAddr::new(L1_TABLE.load(Ordering::Relaxed));
    debug_assert_ne!(l1.raw(), 0, "kernel stack window not initialized");
    arch::address(read_pte(l1, page / L0_ENTRIES))
}
fn set_leaf(page: usize, leaf: usize) {
    write_pte(l0_for(page), page % L0_ENTRIES, leaf);
}
fn read_leaf(page: usize) -> usize {
    read_pte(l0_for(page), page % L0_ENTRIES)
}

/// 建立共享窗口页表与内核根表项；须在第一个地址空间/内核栈之前调用。
pub(super) fn init_window() -> Result<(), FrameError> {
    assert!(
        !WINDOW.lock().ready,
        "kernel stack window initialized twice"
    );
    assert_eq!(WINDOW_BASE % WINDOW_SIZE, 0);
    assert_eq!((WINDOW_BASE >> 21) & 511, 0);
    let root = arch::kernel_root_for_window();
    let l1 = frame::frame_alloc(1)?;
    l1.clear_len(PAGE_SIZE);
    for i in 0..L0_COUNT {
        let l0 = frame::frame_alloc(1)?;
        l0.clear_len(PAGE_SIZE);
        write_pte(l1, i, arch::table(l0));
    }
    write_pte(root, WINDOW_ROOT_INDEX, arch::table(l1));
    TLB::flush_all();
    L1_TABLE.store(l1.raw(), Ordering::Relaxed);
    WINDOW.lock().ready = true;
    Ok(())
}

fn alloc_slot(count: usize) -> Result<usize, FrameError> {
    let mut window = WINDOW.lock();
    if count == 0 || count > WINDOW_PAGES {
        return Err(FrameError::InvalidCount);
    }
    if !window.ready {
        return Err(FrameError::OutOfMemory);
    }
    let mut run = 0;
    for i in 0..WINDOW_PAGES {
        if window.used[i / 64] & (1 << (i % 64)) == 0 {
            run += 1;
            if run == count {
                let first = i + 1 - count;
                for n in first..=i {
                    window.used[n / 64] |= 1 << (n % 64);
                }
                return Ok(first);
            }
        } else {
            run = 0;
        }
    }
    Err(FrameError::OutOfMemory)
}

fn free_slot(first: usize, count: usize) {
    let mut window = WINDOW.lock();
    for n in first..first + count {
        debug_assert_ne!(window.used[n / 64] & (1 << (n % 64)), 0);
        window.used[n / 64] &= !(1 << (n % 64));
    }
}

/// 窗口虚拟槽内的内核栈：槽首为不映射的 guard，其上为栈页。
pub struct KernelStack {
    base: PhysAddr,
    pages: usize,
    slot: usize,
}

impl KernelStack {
    /// 分配 `pages` 个连续物理页并逐页映射到窗口槽；guard 保持不映射。
    pub fn new(pages: usize) -> Result<Self, FrameError> {
        if pages == 0 || pages >= WINDOW_PAGES {
            return Err(FrameError::InvalidCount);
        }
        let count = pages + 1;
        let slot = alloc_slot(count)?;
        let base = match frame::frame_alloc(pages) {
            Ok(base) => base,
            Err(error) => {
                free_slot(slot, count);
                return Err(error);
            }
        };
        base.clear_len(pages * PAGE_SIZE);
        // 槽内先全部清空（guard 必须无映射），再逐页映射栈页。
        for page in slot..slot + count {
            set_leaf(page, 0);
        }
        for i in 0..pages {
            let pa = PhysAddr::new(base.raw() + i * PAGE_SIZE);
            set_leaf(slot + 1 + i, arch::kernel_leaf(pa));
        }
        TLB::flush_all();
        debug_assert_eq!(read_leaf(slot), 0, "kernel stack guard must stay unmapped");
        Ok(Self { base, pages, slot })
    }

    /// 栈顶虚拟地址（窗口地址，16 字节对齐，供 KContext.ksp）。
    pub fn top(&self) -> usize {
        let top = WINDOW_BASE + (self.slot + self.pages + 1) * PAGE_SIZE;
        debug_assert_eq!(top % 16, 0, "kernel stack top must be 16-byte aligned");
        top
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        for page in self.slot..self.slot + self.pages + 1 {
            set_leaf(page, 0);
        }
        TLB::flush_all();
        for i in 0..self.pages {
            // SAFETY: 构造时独占分配、类型不可复制，拥有者负责先让
            // 任何执行流离开该栈；窗口映射已撤销并刷 TLB。
            unsafe {
                frame::frame_dealloc(PhysAddr::new(self.base.raw() + i * PAGE_SIZE));
            }
        }
        free_slot(self.slot, self.pages + 1);
    }
}
