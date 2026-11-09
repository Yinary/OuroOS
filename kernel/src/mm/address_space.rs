//! 用户虚拟地址空间：区域描述、页所有权、事务映射与生命周期。
//!
//! 区域描述用户期望权限，页表负责硬件实现；两者不能相互代替。
//! 当前采用立即分配、不共享物理数据页；未来 fork 用深拷贝，exec 先构造
//! 新空间再切换。地址空间 !Send/!Sync，禁止跨核共享直到实现 TLB shootdown。
//! 所有可失败的元数据预留均在修改原空间前进行，解除映射先刷新 TLB 再释放。
use super::{
    frame::{FrameError, OwnedFrame},
    page_table::UserPageTable,
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use polyhal::{
    consts::VIRT_ADDR_START,
    pagetable::{MappingFlags, PAGE_SIZE},
    PhysAddr,
};

/// 零页保留，不允许用户映射。
pub const USER_BASE: usize = 0x1000;
/// 当前静态程序布局上界，未来扩大布局须同步 ELF/栈/系统调用检查。
pub const USER_TOP: usize = 0x8000_0000;
/// 用户栈顶，16 字节对齐。
pub const USER_STACK_TOP: usize = USER_TOP;
/// 4 页初始栈；未来通过区域策略配置，不在缺页路径隐式扩展。
pub const USER_STACK_BOTTOM: usize = USER_TOP - 4 * PAGE_SIZE;
/// 栈底保护页，始终不映射。
pub const GUARD_BOTTOM: usize = USER_STACK_BOTTOM - PAGE_SIZE;

/// 内存层错误，系统调用接入时分别转换为 ENOMEM/EINVAL/EFAULT。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// 当前不支持执行禁止，要求撤销 X 的保护操作被拒绝。
    UnsupportedPermissions,
    OutOfUserRange,
    Overlap,
    HitsStack,
    OutOfMemory,
    InvalidPermissions,
    NotMapped,
}
impl From<FrameError> for MapError {
    fn from(_: FrameError) -> Self {
        Self::OutOfMemory
    }
}
/// 区域用途，用于后续 brk、mmap 与 exec 的策略区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaKind {
    Elf,
    Stack,
    Anonymous,
    Heap,
}
/// 页对齐、不重叠的虚拟区域，不持有物理页。
#[derive(Debug, Clone, Copy)]
pub struct VmArea {
    pub start: usize,
    pub end: usize,
    /// 请求权限；不支持 NX 时实际权限还含 X，实际权限由 translate 返回。
    pub flags: MappingFlags,
    pub kind: AreaKind,
}
struct Page {
    va: usize,
    frame: OwnedFrame,
}

/// 一个用户地址空间，创建/运行/销毁均在同一核；数据页不允许外部释放。
pub struct UserAddressSpace {
    pt: UserPageTable,
    pages: Vec<Page>,
    areas: Vec<VmArea>,
    local_only: PhantomData<*mut ()>,
}
fn reserve<T>(v: &mut Vec<T>, n: usize) -> Result<(), MapError> {
    v.try_reserve(n).map_err(|_| MapError::OutOfMemory)
}
fn check_flags(flags: MappingFlags) -> Result<(), MapError> {
    if !flags.contains(MappingFlags::U)
        || !(flags - (MappingFlags::U | MappingFlags::RWX)).is_empty()
        || (flags.contains(MappingFlags::W) && !flags.contains(MappingFlags::R))
    {
        return Err(MapError::InvalidPermissions);
    }
    Ok(())
}
fn end_of(start: usize, count: usize) -> Result<usize, MapError> {
    let end = count
        .checked_mul(PAGE_SIZE)
        .and_then(|n| start.checked_add(n))
        .ok_or(MapError::OutOfUserRange)?;
    if count == 0 || start % PAGE_SIZE != 0 || start < USER_BASE || end > USER_TOP {
        return Err(MapError::OutOfUserRange);
    }
    Ok(end)
}
impl UserAddressSpace {
    /// 在内核页表活动时创建；根页分配也会返回 OOM。
    pub fn new() -> Result<Self, MapError> {
        Ok(Self {
            pt: UserPageTable::new()?,
            pages: Vec::new(),
            areas: Vec::new(),
            local_only: PhantomData,
        })
    }
    /// 返回区域视图，不暴露可修改的映射或页所有权。
    pub fn areas(&self) -> &[VmArea] {
        &self.areas
    }
    /// 立即分配一段区域。失败时原有映射/页数不变，新页清零。
    /// 不承诺 NX：非 PROT_NONE 页实际可执行，flags 保留用途所请求的权限。
    pub fn map_region(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
        kind: AreaKind,
    ) -> Result<(), MapError> {
        let end = end_of(start, count)?;
        check_flags(flags)?;
        if start < USER_STACK_BOTTOM && end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        if self.areas.iter().any(|a| start < a.end && end > a.start) {
            return Err(MapError::Overlap);
        }
        reserve(&mut self.areas, 1)?;
        reserve(&mut self.pages, count)?;
        let before = self.pages.len();
        for va in (start..end).step_by(PAGE_SIZE) {
            let result = OwnedFrame::new().map_err(MapError::from).and_then(|frame| {
                self.pt.map(va, frame.addr(), flags)?;
                self.pages.push(Page { va, frame });
                Ok(())
            });
            if let Err(e) = result {
                for p in &self.pages[before..] {
                    self.pt.unmap(p.va);
                }
                self.pages.truncate(before);
                return Err(e);
            }
        }
        self.areas.push(VmArea {
            start,
            end,
            flags,
            kind,
        });
        self.coalesce();
        Ok(())
    }
    /// ELF 加载器单页入口；重复映射拒绝，不覆盖旧数据。
    pub fn map_alloc(&mut self, va: usize, flags: MappingFlags) -> Result<PhysAddr, MapError> {
        self.map_region(va, 1, flags, AreaKind::Elf)?;
        Ok(self.pages[self.pages.len() - 1].frame.addr())
    }
    /// 初始栈请求 RW；当前不支持 NX，实际为 RWX，保护页不分配。
    pub fn map_stack(&mut self) -> Result<(), MapError> {
        self.map_region(USER_STACK_BOTTOM, 4, MappingFlags::URW, AreaKind::Stack)
    }
    /// 预生成区间拆分结果。None 表示删除；Some 表示覆盖权限。
    fn split(
        &self,
        start: usize,
        end: usize,
        flags: Option<MappingFlags>,
    ) -> Result<Vec<VmArea>, MapError> {
        let mut result = Vec::new();
        reserve(
            &mut result,
            self.areas
                .len()
                .checked_mul(3)
                .ok_or(MapError::OutOfMemory)?,
        )?;
        for a in &self.areas {
            if a.end <= start || a.start >= end {
                result.push(*a);
                continue;
            }
            if a.start < start {
                result.push(VmArea { end: start, ..*a });
            }
            if let Some(f) = flags {
                result.push(VmArea {
                    start: a.start.max(start),
                    end: a.end.min(end),
                    flags: f,
                    ..*a
                });
            }
            if a.end > end {
                result.push(VmArea { start: end, ..*a });
            }
        }
        Ok(result)
    }
    /// 解除页区间，空洞允许；参数单位为页，syscall 层负责字节长度向上取整。
    pub fn unmap(&mut self, start: usize, count: usize) -> Result<(), MapError> {
        let end = end_of(start, count)?;
        let next = self.split(start, end, None)?;
        for p in &self.pages {
            if start <= p.va && p.va < end {
                self.pt.unmap(p.va);
            }
        }
        self.pages.retain(|p| p.va < start || p.va >= end);
        self.areas = next;
        self.coalesce();
        Ok(())
    }
    /// 修改整个已映射区间权限，遇到空洞拒绝且不部分修改。U 表示 PROT_NONE。
    pub fn protect(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        let end = end_of(start, count)?;
        check_flags(flags)?;
        if flags.intersects(MappingFlags::RWX) && !flags.contains(MappingFlags::X) {
            return Err(MapError::UnsupportedPermissions);
        }
        let mut cursor = start;
        for a in &self.areas {
            if a.end <= cursor {
                continue;
            }
            if a.start > cursor || cursor >= end {
                break;
            }
            cursor = a.end.min(end);
        }
        if cursor != end {
            return Err(MapError::NotMapped);
        }
        let next = self.split(start, end, Some(flags))?;
        for p in &self.pages {
            if start <= p.va && p.va < end {
                self.pt.protect(p.va, p.frame.addr(), flags);
            }
        }
        self.areas = next;
        self.coalesce();
        Ok(())
    }
    fn coalesce(&mut self) {
        self.areas.sort_unstable_by_key(|a| a.start);
        let mut i = 1;
        while i < self.areas.len() {
            let (a, b) = (self.areas[i - 1], self.areas[i]);
            if a.end == b.start && a.flags == b.flags && a.kind == b.kind {
                self.areas[i - 1].end = b.end;
                self.areas.remove(i);
            } else {
                i += 1;
            }
        }
    }
    /// 只翻译合法用户地址；PROT_NONE/未映射返回 None。
    pub fn translate(&self, va: usize) -> Option<(PhysAddr, MappingFlags)> {
        if !(USER_BASE..USER_TOP).contains(&va) {
            return None;
        }
        self.pt.translate(va)
    }
    /// ELF 段不能侵入固定栈和保护区。
    pub fn check_user_span(start: usize, len: usize) -> Result<(), MapError> {
        let end = start.checked_add(len).ok_or(MapError::OutOfUserRange)?;
        if start < USER_BASE || end > GUARD_BOTTOM {
            Err(MapError::HitsStack)
        } else {
            Ok(())
        }
    }
    /// 切换页表并刷新本核 TLB。调用方当前使用内核栈，用户空间只在本核运行。
    pub fn activate(&self) {
        self.pt.activate();
    }
    /// 恢复创建时的页表；销毁前必须停用。
    pub fn deactivate(&self) {
        self.pt.deactivate();
    }
}
impl Drop for UserAddressSpace {
    fn drop(&mut self) {
        // 先停用，再释放数据页/页表；不依赖调用方记住每个错误返回点。
        if self.pt.is_active() {
            self.pt.deactivate();
        }
    }
}
/// 物理 RAM 的内核直映别名，仅用于拥有/验证过的物理页。
pub fn phys_to_kernel_vaddr(pa: PhysAddr) -> usize {
    pa.raw() | VIRT_ADDR_START
}

/// 地址空间的单核使用凭证：让 !Send 的 [`UserAddressSpace`] 能进入
/// 静态容器（进程注册表）。
///
/// SAFETY（unsafe impl Send 的全部依据）：内核当前单核（-smp 1，构建
/// 与运行均不含多核机制），地址空间只在创建核被创建/激活/销毁，
/// 不存在跨核移动。SMP 化时本类型必须先于 TLB shootdown 实现移除
/// 或重构（见 doc/ostd-contracts.md mm 欠账）。不变量的归属在 mm，
/// 因此 unsafe 断言写在这里而不在使用方。
pub struct LocalSpace(pub(crate) UserAddressSpace);
// SAFETY: 见类型文档；单核内不存在跨线程移动。
unsafe impl Send for LocalSpace {}

impl LocalSpace {
    /// 借用内部地址空间。
    pub fn as_space(&self) -> &UserAddressSpace {
        &self.0
    }
}
