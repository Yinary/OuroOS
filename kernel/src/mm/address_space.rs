//! 用户虚拟地址空间：区域（期望权限/用途）+ 页清单（页所有权）+ 页表，
//! 事务性映射与生命周期管理。契约见 docs/ostd-contracts.md §1。
use super::{
    frame::{FrameError, OwnedFrame},
    page_table::UserPageTable,
};
use alloc::{sync::Arc, vec::Vec};
use core::marker::PhantomData;
use polyhal::{
    consts::VIRT_ADDR_START,
    pagetable::{MappingFlags, PAGE_SIZE},
    PhysAddr,
};

/// 静态 ELF 可以包含零地址的只读头部段；未映射的空指针仍会失败。
pub const USER_BASE: usize = 0;
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
    PermissionDenied,
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
    File,
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
/// 私有页独占，共享文件页使用缓存引用计数。
pub enum Backing {
    Private(OwnedFrame),
    Shared(Arc<crate::fs::cache::SharedPage>, bool),
}
impl Backing {
    fn addr(&self) -> PhysAddr {
        match self {
            Self::Private(p) => p.addr(),
            Self::Shared(p, _) => p.addr(),
        }
    }
}
struct Page {
    va: usize,
    frame: Backing,
}

/// 一个用户地址空间，创建/运行/销毁均在同一核；数据页不允许外部释放。
pub struct UserAddressSpace {
    pt: UserPageTable,
    pages: Vec<Page>,
    areas: Vec<VmArea>,
    heap_start: usize,
    program_break: usize,
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
    if count == 0 || start % PAGE_SIZE != 0 || end > USER_TOP {
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
            heap_start: 0,
            program_break: 0,
            local_only: PhantomData,
        })
    }
    /// ELF 加载结束后确定堆起点；只初始化一次，堆与 mmap 共用区域账本。
    pub fn init_heap(&mut self) {
        if self.heap_start == 0 {
            self.heap_start = self
                .areas
                .iter()
                .filter(|a| a.kind == AreaKind::Elf)
                .map(|a| a.end)
                .max()
                .unwrap_or(USER_BASE);
            self.program_break = self.heap_start;
        }
    }
    /// 原始 Linux brk ABI：失败返回原 break；同页调整不改变映射。
    pub fn brk(&mut self, requested: usize) -> usize {
        let old = self.program_break;
        if requested < self.heap_start || requested >= GUARD_BOTTOM || self.heap_start == 0 {
            return old;
        }
        let old_end = old.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let new_end = requested.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let result = match new_end.cmp(&old_end) {
            core::cmp::Ordering::Greater => self.map_region(
                old_end,
                (new_end - old_end) / PAGE_SIZE,
                MappingFlags::URW,
                AreaKind::Heap,
            ),
            core::cmp::Ordering::Less => self.unmap(new_end, (old_end - new_end) / PAGE_SIZE),
            core::cmp::Ordering::Equal => Ok(()),
        };
        if result.is_ok() {
            self.program_break = requested;
        }
        self.program_break
    }
    /// 在用户栈保护区以下寻找页对齐空洞；非固定 hint 冲突时回退搜索。
    pub fn find_free(&self, hint: usize, count: usize) -> Result<usize, MapError> {
        let fits = |start| {
            end_of(start, count)
                .ok()
                .filter(|&end| end <= GUARD_BOTTOM)
                .filter(|&end| !self.areas.iter().any(|a| start < a.end && end > a.start))
        };
        let hint = hint / PAGE_SIZE * PAGE_SIZE;
        if hint != 0 && fits(hint).is_some() {
            return Ok(hint);
        }
        let mut start = 0x1000_0000;
        for a in &self.areas {
            if a.end <= start {
                continue;
            }
            if fits(start).is_some() {
                return Ok(start);
            }
            start = a.end;
        }
        if fits(start).is_some() {
            Ok(start)
        } else {
            Err(MapError::OutOfMemory)
        }
    }
    /// MAP_FIXED 的事务替换：新页、区域元数据、替代页表全部准备成功后才提交。
    /// 不复制保留页的数据；旧空间保持其所有权，直到新页表已激活并刷新 TLB。
    pub fn replace_region(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        let end = end_of(start, count)?;
        check_flags(flags)?;
        if start < USER_STACK_BOTTOM && end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        let mut next_areas = self.split(start, end, None)?;
        reserve(&mut next_areas, 1)?;
        next_areas.push(VmArea {
            start,
            end,
            flags,
            kind: AreaKind::Anonymous,
        });
        reserve(&mut self.pages, count)?;
        let mut fresh = Vec::new();
        reserve(&mut fresh, count)?;
        for va in (start..end).step_by(PAGE_SIZE) {
            fresh.push(Page {
                va,
                frame: Backing::Private(OwnedFrame::new()?),
            });
        }
        let mut next_pt = UserPageTable::new()?;
        for page in &self.pages {
            if start <= page.va && page.va < end {
                continue;
            }
            let area = self
                .areas
                .iter()
                .find(|a| a.start <= page.va && page.va < a.end)
                .ok_or(MapError::NotMapped)?;
            next_pt.map(page.va, page.frame.addr(), area.flags)?;
        }
        for page in &fresh {
            next_pt.map(page.va, page.frame.addr(), flags)?;
        }
        let active = self.pt.is_active();
        core::mem::swap(&mut self.pt, &mut next_pt);
        if active {
            self.pt.activate();
        }
        drop(next_pt);
        self.pages.retain(|p| p.va < start || p.va >= end);
        self.pages.append(&mut fresh);
        self.areas = next_areas;
        self.coalesce();
        Ok(())
    }
    /// 深拷贝私有区域与页面；失败时新空间自动回收，原空间不变。
    pub fn deep_copy(&self) -> Result<Self, MapError> {
        let mut child = Self::new()?;
        for area in &self.areas {
            child.map_region(
                area.start,
                (area.end - area.start) / PAGE_SIZE,
                area.flags,
                area.kind,
            )?;
        }
        for source in &self.pages {
            let dest = child
                .pages
                .iter_mut()
                .find(|q| q.va == source.va)
                .ok_or(MapError::NotMapped)?;
            if let Backing::Shared(page, writable) = &source.frame {
                let flags = self
                    .areas
                    .iter()
                    .find(|a| a.start <= source.va && source.va < a.end)
                    .ok_or(MapError::NotMapped)?
                    .flags;
                child.pt.protect(source.va, page.addr(), flags);
                dest.frame = Backing::Shared(page.clone(), *writable);
            } else {
                // SAFETY: 私有源与目标分别拥有独立页，复制整页不重叠。
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        phys_to_kernel_vaddr(source.frame.addr()) as *const u8,
                        phys_to_kernel_vaddr(dest.frame.addr()) as *mut u8,
                        PAGE_SIZE,
                    );
                }
            }
        }
        child.heap_start = self.heap_start;
        child.program_break = self.program_break;
        super::fence_icache();
        Ok(child)
    }
    /// 事务安装文件页；FIXED 只有在全部页表与元数据准备成功后替换。
    pub fn map_backed(
        &mut self,
        start: usize,
        frames: Vec<Backing>,
        flags: MappingFlags,
        fixed: bool,
    ) -> Result<(), MapError> {
        let end = end_of(start, frames.len())?;
        check_flags(flags)?;
        if end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        if !fixed && self.areas.iter().any(|a| start < a.end && a.start < end) {
            return Err(MapError::Overlap);
        }
        let mut areas = self.split(start, end, None)?;
        reserve(&mut areas, 1)?;
        areas.push(VmArea {
            start,
            end,
            flags,
            kind: AreaKind::File,
        });
        reserve(&mut self.pages, frames.len())?;
        let mut fresh = Vec::new();
        reserve(&mut fresh, frames.len())?;
        let mut pt = UserPageTable::new()?;
        for p in &self.pages {
            if p.va >= start && p.va < end {
                continue;
            }
            let area = self
                .areas
                .iter()
                .find(|a| a.start <= p.va && p.va < a.end)
                .ok_or(MapError::NotMapped)?;
            pt.map(p.va, p.frame.addr(), area.flags)?;
        }
        for (i, frame) in frames.into_iter().enumerate() {
            let va = start + i * PAGE_SIZE;
            pt.map(va, frame.addr(), flags)?;
            fresh.push(Page { va, frame });
        }
        let active = self.pt.is_active();
        core::mem::swap(&mut self.pt, &mut pt);
        if active {
            self.pt.activate();
        }
        drop(pt);
        self.pages.retain(|p| p.va < start || p.va >= end);
        self.pages.append(&mut fresh);
        self.areas = areas;
        self.coalesce();
        Ok(())
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
                self.pages.push(Page {
                    va,
                    frame: Backing::Private(frame),
                });
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
        if flags.contains(MappingFlags::W)
            && self.pages.iter().any(|p| {
                p.va >= start && p.va < end && matches!(p.frame, Backing::Shared(_, false))
            })
        {
            return Err(MapError::PermissionDenied);
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
        if end > GUARD_BOTTOM {
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
/// 或重构（见 docs/ostd-contracts.md mm 欠账）。不变量的归属在 mm，
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
