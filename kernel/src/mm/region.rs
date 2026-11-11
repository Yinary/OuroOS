//! 启动物理内存账本：FDT RAM 与 HAL 剩余区求交、扣除保留区后登记给帧分配器。
use super::frame::{self, FrameError};
use alloc::vec::Vec;
use polyhal::{
    consts::VIRT_ADDR_START,
    mem::{get_fdt, get_mem_areas},
    pagetable::PAGE_SIZE,
};
use spin::Mutex;

/// 保留区原因；可分配区的 reason 为 None。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reserved {
    /// 保留物理零页，避免中间页表项的零值与空项冲突。
    NullPage,
    Kernel,
    Firmware,
    HalBoot,
    Alignment,
}
/// 不重叠的半开物理区间；来源为 FDT RAM，经 HAL 过滤。
#[derive(Clone, Copy, Debug)]
pub struct Region {
    /// 原始区间来自 FDT RAM，可用性同时受 HAL 启动分配结果约束。
    pub source: &'static str,
    pub start: usize,
    pub end: usize,
    pub reserved: Option<Reserved>,
    pub registered: bool,
}
static REGIONS: Mutex<Vec<Region>> = Mutex::new(Vec::new());

fn push<T>(v: &mut Vec<T>, item: T) -> Result<(), FrameError> {
    v.try_reserve(1).map_err(|_| FrameError::OutOfMemory)?;
    v.push(item);
    Ok(())
}
fn span(start: usize, size: usize) -> Result<(usize, usize), FrameError> {
    Ok((
        start,
        start.checked_add(size).ok_or(FrameError::InvalidRange)?,
    ))
}

/// 只在主核、HAL 启动分配结束后初始化。账本持久保存，登记标志只在成功后置位。
pub(super) fn init() -> Result<(), FrameError> {
    let fdt = get_fdt().map_err(|_| FrameError::InvalidRange)?;
    let mut ram = Vec::new();
    let mut available = Vec::new();
    let mut reserved = Vec::new();
    for r in fdt.memory().flat_map(|m| m.regions()) {
        push(&mut ram, span(r.address as usize, r.size)?)?;
    }
    for &(start, size) in get_mem_areas() {
        push(&mut available, span(start, size)?)?;
    }
    for r in fdt.memory_reservation_block() {
        push(&mut reserved, span(r.address as usize, r.size)?)?;
    }
    // parser 的 reserved_memory 返回父节点，显式遍历其子节点的 reg。
    let mut reserved_level = None;
    for node in fdt.all_nodes() {
        if node.name == "reserved-memory" {
            reserved_level = Some(node.level);
            continue;
        }
        if let Some(level) = reserved_level {
            if node.level <= level {
                reserved_level = None;
                continue;
            }
            if let Some(regs) = node.reg() {
                for r in regs {
                    push(
                        &mut reserved,
                        span(r.address as usize, r.size.ok_or(FrameError::InvalidRange)?)?,
                    )?;
                }
            }
        }
    }
    extern "C" {
        fn _skernel();
        fn _end();
    }
    let kernel = (
        _skernel as usize - VIRT_ADDR_START,
        _end as usize - VIRT_ADDR_START,
    );
    let mut cuts = Vec::new();
    push(&mut cuts, 0)?;
    push(&mut cuts, PAGE_SIZE)?;
    for &(start, end) in ram
        .iter()
        .chain(available.iter())
        .chain(reserved.iter())
        .chain(core::iter::once(&kernel))
    {
        for x in [start, end] {
            push(&mut cuts, x)?;
            push(&mut cuts, x / PAGE_SIZE * PAGE_SIZE)?;
            push(
                &mut cuts,
                x.checked_add(PAGE_SIZE - 1)
                    .ok_or(FrameError::InvalidRange)?
                    / PAGE_SIZE
                    * PAGE_SIZE,
            )?;
        }
    }
    cuts.sort_unstable();
    cuts.dedup();
    let contains = |ranges: &[(usize, usize)], s, e| ranges.iter().any(|&(a, b)| a <= s && e <= b);
    let mut regions = REGIONS.lock();
    if !regions.is_empty() {
        return Err(FrameError::InvalidRange);
    }
    for pair in cuts.windows(2) {
        let (s, e) = (pair[0], pair[1]);
        if !contains(&ram, s, e) {
            continue;
        }
        let reason = if s < PAGE_SIZE {
            Some(Reserved::NullPage)
        } else if kernel.0 <= s && e <= kernel.1 {
            Some(Reserved::Kernel)
        } else if contains(&reserved, s, e) {
            Some(Reserved::Firmware)
        } else if !contains(&available, s, e) {
            Some(Reserved::HalBoot)
        } else if s % PAGE_SIZE != 0 || e % PAGE_SIZE != 0 {
            Some(Reserved::Alignment)
        } else {
            None
        };
        push(
            &mut regions,
            Region {
                source: "FDT RAM / HAL remaining",
                start: s,
                end: e,
                reserved: reason,
                registered: false,
            },
        )?;
    }
    let mut i = 1;
    while i < regions.len() {
        if regions[i - 1].end == regions[i].start && regions[i - 1].reserved == regions[i].reserved
        {
            regions[i - 1].end = regions[i].end;
            regions.remove(i);
        } else {
            i += 1;
        }
    }
    for r in regions.iter_mut() {
        if r.reserved.is_none() {
            frame::add_frame_range(r.start, r.end)?;
            r.registered = true;
        }
        log::info!(
            "RAM {:#x}..{:#x}: source={} reserved={:?} registered={}",
            r.start,
            r.end,
            r.source,
            r.reserved,
            r.registered
        );
    }
    log::info!(
        "memory ledger: {} regions registered",
        regions.iter().filter(|r| r.registered).count()
    );
    Ok(())
}
