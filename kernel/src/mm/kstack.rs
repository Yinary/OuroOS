//! 任务栈位于内核共享页表窗口，每个槽的第零页始终不映射。
//! 当前只由启动核运行任务；启用多核调度前需要跨核 TLB 失效。

use super::frame;
use super::{
    arch,
    frame::{FrameError, OwnedFrame},
    page_table::{read, write},
};
use polyhal::consts::VIRT_ADDR_START;
use polyhal::{
    pagetable::{PAGE_SIZE, TLB},
    PhysAddr,
};
use spin::Mutex;

const BASE: usize = 0xffff_ffe4_0000_0000;
const ENTRIES: usize = PAGE_SIZE / core::mem::size_of::<usize>();
const SLOT_SIZE: usize = ENTRIES * PAGE_SIZE;
static DIRECTORY: Mutex<Option<OwnedFrame>> = Mutex::new(None);

/// 在创建任何用户页表前发布永久目录。RV 用户根复制该高半区根项；
/// LA 的高半区根独立于每个进程的 PGDL。
pub(super) fn init() {
    let directory = OwnedFrame::new().expect("kernel stack directory");
    #[cfg(target_arch = "riscv64")]
    let root = PhysAddr::new(arch::current());
    #[cfg(target_arch = "loongarch64")]
    let root = {
        let high: usize;
        // SAFETY: 仅在启动核初始化阶段读取特权寄存器。
        unsafe {
            core::arch::asm!("csrrd {}, 0x1a", out(reg) high);
        }
        arch::install_refill();
        if high == 0 {
            let frame = OwnedFrame::new().expect("kernel high page table");
            let pa = frame.addr();
            // SAFETY: 新根已清零，所有内核直映仍走 DMW，根页永久保留。
            unsafe {
                core::arch::asm!("csrwr {}, 0x1a", inout(reg) pa.raw() => _);
            }
            core::mem::forget(frame);
            pa
        } else {
            PhysAddr::new(high)
        }
    };
    let index = (BASE >> 30) & (ENTRIES - 1);
    assert_eq!(
        read(root, index),
        0,
        "kernel stack window overlaps existing mapping"
    );
    write(root, index, arch::table(directory.addr()));
    *DIRECTORY.lock() = Some(directory);
    TLB::flush_all();
}

fn stack_leaf(pa: PhysAddr) -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        (pa.raw() >> 2) | 0xc7
    } // V/R/W/A/D, supervisor only
    #[cfg(target_arch = "loongarch64")]
    {
        pa.raw() | 0x113
    } // V/D/MAT_CC/W, PLV0
}

pub struct KernelStack {
    slot: usize,
    _leaf: OwnedFrame,
    base: PhysAddr,
    pages: usize,
}

impl KernelStack {
    /// 先构造所有帧，再发布叶表。任何分配失败均由局部对象归还已分配帧。
    pub fn new(pages: usize) -> Result<Self, FrameError> {
        if pages == 0 || pages >= ENTRIES {
            return Err(FrameError::InvalidCount);
        }
        let leaf = OwnedFrame::new()?;
        let window = DIRECTORY.lock();
        let directory = window.as_ref().ok_or(FrameError::InvalidRange)?.addr();
        let slot = (0..ENTRIES)
            .find(|&i| read(directory, i) == 0)
            .ok_or(FrameError::OutOfMemory)?;
        // VirtIO 的同步请求可能直接借用跨页内核栈缓冲区，保持物理连续。
        let base = frame::frame_alloc(pages)?;
        base.clear_len(pages * PAGE_SIZE);
        for i in 0..pages {
            write(
                leaf.addr(),
                i + 1,
                stack_leaf(PhysAddr::new(base.raw() + i * PAGE_SIZE)),
            );
        }
        write(directory, slot, arch::table(leaf.addr()));
        TLB::flush_all();
        Ok(Self {
            slot,
            _leaf: leaf,
            base,
            pages,
        })
    }

    pub fn top(&self) -> usize {
        BASE + self.slot * SLOT_SIZE + (1 + self.pages) * PAGE_SIZE
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        // 调度器已离开此栈；撤销表项、刷新 TLB 后，才让字段析构归还物理页。
        let window = DIRECTORY.lock();
        let directory = window.as_ref().expect("published stack directory").addr();
        write(directory, self.slot, 0);
        TLB::flush_all();
        for i in 0..self.pages {
            // SAFETY: 栈独占连续物理块，调用方已切走，页表撤销后逐页归还。
            unsafe {
                frame::frame_dealloc(PhysAddr::new(self.base.raw() + i * PAGE_SIZE));
            }
        }
    }
}

/// 将内核栈窗口或普通直映缓冲区转换为 DMA 物理地址。
/// 调用方持有有效缓冲区，保证其在同步请求期间存活且物理连续。
pub(crate) fn dma_address(va: usize) -> usize {
    if !(BASE..BASE + ENTRIES * SLOT_SIZE).contains(&va) {
        return va & !VIRT_ADDR_START;
    }
    let window = DIRECTORY.lock();
    let directory = window.as_ref().expect("live kernel stack directory").addr();
    let slot = (va - BASE) / SLOT_SIZE;
    let leaf = read(directory, slot);
    assert_ne!(leaf, 0, "DMA outside a live stack");
    let pte = read(arch::address(leaf), (va / PAGE_SIZE) % ENTRIES);
    assert_ne!(pte, 0, "DMA outside stack data");
    arch::address(pte).raw() + va % PAGE_SIZE
}

#[cfg(debug_assertions)]
pub(super) fn check() {
    let baseline = frame::stats();
    for budget in 0..2 {
        frame::set_test_budget(Some(budget));
        let attempt = KernelStack::new(2);
        frame::set_test_budget(None);
        assert!(matches!(attempt, Err(FrameError::OutOfMemory)));
        assert_eq!(frame::stats(), baseline);
    }
    let stack = KernelStack::new(2).expect("guarded stack");
    assert_eq!(read(stack._leaf.addr(), 0), 0);
    for i in 0..stack.pages {
        let pa = PhysAddr::new(stack.base.raw() + i * PAGE_SIZE);
        assert_eq!(read(stack._leaf.addr(), i + 1), stack_leaf(pa));
        let va = stack.top() - (stack.pages - i) * PAGE_SIZE + 7;
        assert_eq!(dma_address(va), pa.raw() + 7);
        // SAFETY: 栈未交付任务；虚拟地址与物理直映指向同一个独占字节。
        unsafe {
            (va as *mut u8).write_volatile(17);
            assert_eq!(
                ((pa.raw() | VIRT_ADDR_START) as *const u8)
                    .add(7)
                    .read_volatile(),
                17
            );
        }
    }
    let slot = stack.slot;
    drop(stack);
    assert_eq!(read(DIRECTORY.lock().as_ref().unwrap().addr(), slot), 0);
    assert_eq!(frame::stats(), baseline);
}
