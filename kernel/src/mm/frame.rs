//! 物理页所有权与帧分配。启动时建立位图，运行时分配/释放不再申请堆内存。
//!
//! 旧 buddy 的空闲链表使用 BTreeSet，分裂/归还也可能因堆不足终止内核。
//! 本实现采用区域内首次适配；优先保证失败可恢复，暂不做 NUMA/迁移/大页。
use alloc::vec::Vec;
use polyhal::{pagetable::PAGE_SIZE, PhysAddr};
use spin::Mutex;

/// 物理页或管理元数据不足，以及非法申请。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    OutOfMemory,
    InvalidCount,
    InvalidRange,
}

struct Pool {
    start: usize,
    pages: usize,
    used: Vec<u64>,
    hint: usize,
}
struct Allocator {
    pools: Vec<Pool>,
    total: usize,
    free: usize,
    #[cfg(debug_assertions)]
    budget: Option<usize>,
}
static ALLOCATOR: Mutex<Allocator> = Mutex::new(Allocator {
    pools: Vec::new(),
    total: 0,
    free: 0,
    #[cfg(debug_assertions)]
    budget: None,
});

/// 已登记总页数与当前空闲页数；统计与分配在同一把锁内更新。
pub fn stats() -> (usize, usize) {
    let a = ALLOCATOR.lock();
    (a.total, a.free)
}

/// 登记经过 region 层排除保留区的页对齐区间；只允许启动主核调用。
pub(super) fn add_frame_range(start: usize, end: usize) -> Result<(), FrameError> {
    if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
        return Err(FrameError::InvalidRange);
    }
    let mut a = ALLOCATOR.lock();
    if a.pools
        .iter()
        .any(|p| start < p.start + p.pages * PAGE_SIZE && end > p.start)
    {
        return Err(FrameError::InvalidRange);
    }
    let pages = (end - start) / PAGE_SIZE;
    let mut used = Vec::new();
    used.try_reserve_exact(pages.div_ceil(64))
        .map_err(|_| FrameError::OutOfMemory)?;
    used.resize(pages.div_ceil(64), 0);
    a.pools
        .try_reserve(1)
        .map_err(|_| FrameError::OutOfMemory)?;
    a.pools.push(Pool {
        start,
        pages,
        used,
        hint: 0,
    });
    a.total += pages;
    a.free += pages;
    Ok(())
}

/// 分配恰好 count 个连续页。零长度/溢出拒绝；碎片不足与容量不足均返回 OOM。
/// 裸物理页只用于底层适配，普通调用方应使用 OwnedFrame 保证释放。
pub fn frame_alloc(count: usize) -> Result<PhysAddr, FrameError> {
    if count == 0 || count.checked_mul(PAGE_SIZE).is_none() {
        return Err(FrameError::InvalidCount);
    }
    let mut a = ALLOCATOR.lock();
    #[cfg(debug_assertions)]
    if a.budget == Some(0) {
        return Err(FrameError::OutOfMemory);
    }
    if count > a.free {
        return Err(FrameError::OutOfMemory);
    }
    for pool in &mut a.pools {
        let mut run = 0;
        let begin = if count == 1 { pool.hint } else { 0 };
        for i in (begin..pool.pages).chain(0..begin) {
            if i == 0 {
                run = 0;
            }
            run = if pool.used[i / 64] & (1 << (i % 64)) == 0 {
                run + 1
            } else {
                0
            };
            if run == count {
                let first = i + 1 - count;
                for n in first..=i {
                    pool.used[n / 64] |= 1 << (n % 64);
                }
                let pa = pool.start + first * PAGE_SIZE;
                pool.hint = (i + 1) % pool.pages;
                a.free -= count;
                #[cfg(debug_assertions)]
                if let Some(n) = &mut a.budget {
                    *n -= 1;
                }
                return Ok(PhysAddr::new(pa));
            }
        }
    }
    Err(FrameError::OutOfMemory)
}

/// 归还单页。
/// # Safety
/// 调用方必须独占该页、确保不再有映射/TLB/设备引用，且不能重复归还。
pub unsafe fn frame_dealloc(pa: PhysAddr) {
    let mut a = ALLOCATOR.lock();
    for pool in &mut a.pools {
        if pa.raw() >= pool.start && pa.raw() < pool.start + pool.pages * PAGE_SIZE {
            let n = (pa.raw() - pool.start) / PAGE_SIZE;
            assert_eq!(pa.raw() % PAGE_SIZE, 0, "unaligned frame release");
            assert_ne!(
                pool.used[n / 64] & (1 << (n % 64)),
                0,
                "double frame release"
            );
            pool.used[n / 64] &= !(1 << (n % 64));
            pool.hint = pool.hint.min(n);
            a.free += 1;
            return;
        }
    }
    panic!("frame outside allocator");
}

/// 单页唯一所有者，不可 Clone；页表必须先撤销映射并刷新 TLB 再释放它。
pub struct OwnedFrame {
    pa: PhysAddr,
}
impl OwnedFrame {
    /// 分配并清零，避免旧数据泄漏给用户；失败不改变页数。
    pub fn new() -> Result<Self, FrameError> {
        let pa = frame_alloc(1)?;
        pa.clear_len(PAGE_SIZE);
        Ok(Self { pa })
    }
    /// 借用物理地址，不转移释放责任。
    pub fn addr(&self) -> PhysAddr {
        self.pa
    }
}
impl Drop for OwnedFrame {
    fn drop(&mut self) {
        // SAFETY: 构造函数独占分配，类型不可复制；拥有者负责先撤销硬件引用。
        unsafe {
            frame_dealloc(self.pa);
        }
    }
}

/// 仅 debug 启动自检可用；没有用户可控的故障注入入口。
#[cfg(debug_assertions)]
pub(crate) fn set_test_budget(budget: Option<usize>) {
    ALLOCATOR.lock().budget = budget;
}
