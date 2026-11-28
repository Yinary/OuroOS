//! 用户虚拟地址空间：区域（期望权限/用途）+ 页清单（页所有权）+ 页表，
//! 事务性映射与生命周期管理。契约见 docs/ostd-contracts.md §1。
use super::shared::SharedPage;
use super::{
    file::{self, FilePage, Mode},
    frame::{FrameError, FrameRef},
    page_table::UserPageTable,
};
use alloc::vec::Vec;
use core::{
    cell::{Cell, RefCell},
    marker::PhantomData,
};
use polyhal::{
    consts::VIRT_ADDR_START,
    pagetable::{MappingFlags, PAGE_SIZE},
    PhysAddr,
};

/// 静态 ELF 可以包含零地址的只读头部段。
pub const USER_BASE: usize = 0;
/// 三层 4 KiB 页表的低半区上界，覆盖 LoongArch 默认的静态 ELF 链接地址。
/// 低半区最后一个根页表项留给跨进程共享的只读信号返回入口。
pub const USER_TOP: usize = (1 << 38) - (1 << 30);
/// 用户栈顶，16 字节对齐。
pub const USER_STACK_TOP: usize = USER_TOP;
/// 用户栈保留 8 MiB 虚拟区间，物理页按需分配。
pub const USER_STACK_BOTTOM: usize = USER_TOP - 8 * 1024 * 1024;
/// 栈底保护页，始终不映射。
pub const GUARD_BOTTOM: usize = USER_STACK_BOTTOM - PAGE_SIZE;

/// 内存层错误，系统调用接入时分别转换为 ENOMEM/EINVAL/EFAULT。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// 映射后备或区域权限不允许本次访问。
    PermissionDenied,
    UnsupportedPermissions,
    OutOfUserRange,
    Overlap,
    HitsStack,
    OutOfMemory,
    InvalidPermissions,
    NotMapped,
    /// 文件后备页在 EOF 之外或无法读入。
    FileFault,
    /// 文件仍覆盖该页，但后端无法提供数据。
    FileIo,
}
impl From<FrameError> for MapError {
    fn from(_: FrameError) -> Self {
        Self::OutOfMemory
    }
}
/// 等待字的身份由地址空间或共享映射的后备对象决定，换物理页不改变身份。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexKey {
    Private { tgid: usize, address: usize },
    Anonymous { object: usize, offset: usize },
    File { inode: u32, offset: usize },
}

/// 区域用途，用于后续 brk、mmap 与 exec 的策略区分。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AreaKind {
    Elf,
    Stack,
    Anonymous,
    SharedAnonymous,
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
    pub locked: bool,
    onfault: bool,
    shared_file: bool,
    no_fork: bool,
    wipe_on_fork: bool,
}
/// 区域页的后备；未调入的文件页没有物理地址。
pub(crate) enum Backing {
    Private(FrameRef),
    AnonymousShared(SharedPage),
    File(FilePage),
}
impl Backing {
    fn addr(&self) -> Option<PhysAddr> {
        match self {
            Self::Private(p) => Some(p.addr()),
            Self::AnonymousShared(p) => p.addr(),
            Self::File(p) => p.addr(),
        }
    }
    fn install(
        &self,
        pt: &mut UserPageTable,
        va: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        if let Some(pa) = self.addr() {
            pt.map(va, pa, flags)?;
        }
        Ok(())
    }
}
struct Page {
    va: usize,
    frame: RefCell<Backing>,
}
impl Page {
    fn new(va: usize, frame: Backing) -> Self {
        Self {
            va,
            frame: RefCell::new(frame),
        }
    }
    fn backing(&self) -> core::cell::Ref<'_, Backing> {
        self.frame.borrow()
    }
    /// 请求权限到实际叶权限的唯一入口；共享私有帧与私有文件页在 COW 阶段扣除 W。
    fn leaf_flags(&self, requested: MappingFlags) -> MappingFlags {
        let cow_shared = match &*self.backing() {
            Backing::Private(frame) => frame.strong_count() > 1,
            Backing::File(file) => file.is_cow_shared(),
            Backing::AnonymousShared(_) => false,
        };
        if cow_shared {
            requested - MappingFlags::W
        } else {
            requested
        }
    }
    fn install(
        &self,
        pt: &mut UserPageTable,
        va: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        self.frame.borrow().install(pt, va, self.leaf_flags(flags))
    }
    fn addr(&self) -> Option<polyhal::PhysAddr> {
        self.frame.borrow().addr()
    }
}

/// 地址空间内已挂接的 System V 共享内存段记录（用于 shmdt、fork 继承与退出回收）。
#[derive(Clone, Copy)]
struct ShmAttachment {
    start: usize,
    shmid: usize,
    pages: usize,
}

/// 一个用户地址空间，创建/运行/销毁均在同一核；数据页不允许外部释放。
pub struct UserAddressSpace {
    pt: RefCell<UserPageTable>,
    pending: RefCell<Vec<Page>>,
    truncations: Cell<usize>,
    pages: Vec<Page>,
    areas: Vec<VmArea>,
    shm_attachments: Vec<ShmAttachment>,
    heap_start: usize,
    program_break: usize,
    limits: [[usize; 2]; 4],
    defer_map_population: bool,
    lock_future: bool,
    lock_onfault: bool,
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
    let end = end_of_unmap(start, count)?;
    if start < super::kstack::WINDOW_ROOT_END && end > super::kstack::WINDOW_ROOT_START {
        return Err(MapError::OutOfUserRange);
    }
    Ok(end)
}
fn end_of_unmap(start: usize, count: usize) -> Result<usize, MapError> {
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
    /// 进程内存资源限额；索引依次为 DATA、STACK、MEMLOCK、AS。
    pub fn memory_limit(&self, resource: usize) -> Option<[usize; 2]> {
        let i = match resource {
            2 => 0,
            3 => 1,
            8 => 2,
            9 => 3,
            _ => return None,
        };
        Some(self.limits[i])
    }
    /// 修改内存限额；降低限额不撤销已存在的映射。
    pub fn set_memory_limit(&mut self, resource: usize, limit: [usize; 2]) -> Result<(), MapError> {
        let i = match resource {
            2 => 0,
            3 => 1,
            8 => 2,
            9 => 3,
            _ => return Err(MapError::InvalidPermissions),
        };
        if limit[0] > limit[1] {
            return Err(MapError::InvalidPermissions);
        }
        self.limits[i] = limit;
        Ok(())
    }
    /// exec 替换地址空间时保留进程限额，锁页策略不继承。
    pub fn inherit_memory_limits(&mut self, old: &Self) {
        self.limits = old.limits;
    }

    /// exec 发布新镜像前校验继承的地址空间与固定栈限额。
    pub fn check_exec_limits(&self) -> Result<(), MapError> {
        let total: usize = self.areas.iter().map(|a| a.end - a.start).sum();
        let stack: usize = self
            .areas
            .iter()
            .filter(|a| a.kind == AreaKind::Stack)
            .map(|a| a.end - a.start)
            .sum();
        if Self::data_bytes(&self.areas) > self.limits[0][0]
            || total > self.limits[3][0]
            || stack > self.limits[1][0]
        {
            return Err(MapError::OutOfMemory);
        }
        Ok(())
    }

    fn chargeable(kind: AreaKind, shared_file: bool, flags: MappingFlags) -> bool {
        !matches!(kind, AreaKind::SharedAnonymous | AreaKind::Stack)
            && !shared_file
            && flags.contains(MappingFlags::W)
            && !flags.contains(MappingFlags::X)
    }
    fn data_bytes(areas: &[VmArea]) -> usize {
        areas
            .iter()
            .filter(|a| Self::chargeable(a.kind, a.shared_file, a.flags))
            .map(|a| a.end - a.start)
            .sum()
    }
    fn check_data_layout(&self, areas: &[VmArea]) -> Result<(), MapError> {
        let next = Self::data_bytes(areas);
        if next > self.limits[0][0] && next > Self::data_bytes(&self.areas) {
            Err(MapError::OutOfMemory)
        } else {
            Ok(())
        }
    }
    fn check_mapping_limit(
        &self,
        start: usize,
        end: usize,
        replace: bool,
        charge: bool,
    ) -> Result<(), MapError> {
        let mut removed_data = 0;
        let mut total = end - start;
        let mut locked = if self.lock_future { end - start } else { 0 };
        for a in &self.areas {
            let overlap = if replace {
                a.end.min(end).saturating_sub(a.start.max(start))
            } else {
                0
            };
            if Self::chargeable(a.kind, a.shared_file, a.flags) {
                removed_data += overlap;
            }
            let size = a.end - a.start - overlap;
            total = total.checked_add(size).ok_or(MapError::OutOfMemory)?;
            if a.locked {
                locked = locked.checked_add(size).ok_or(MapError::OutOfMemory)?;
            }
        }
        if charge
            && end - start > removed_data
            && Self::data_bytes(&self.areas) - removed_data + (end - start) > self.limits[0][0]
        {
            return Err(MapError::OutOfMemory);
        }
        let exceeds_as =
            total > self.limits[3][0] && total > self.areas.iter().map(|a| a.end - a.start).sum();
        let exceeds_lock = locked > self.limits[2][0]
            && locked
                > self
                    .areas
                    .iter()
                    .filter(|a| a.locked)
                    .map(|a| a.end - a.start)
                    .sum();
        if exceeds_as || exceeds_lock {
            return Err(MapError::OutOfMemory);
        }
        Ok(())
    }

    // 单核上截断期间所有用户任务均已离开用户态。重返用户态前先撤销旧 PTE。
    fn refresh_files(&self) {
        let version = file::truncations();
        if self.truncations.replace(version) != version {
            for page in &self.pages {
                if let Backing::File(f) = &*page.backing() {
                    if f.stale() {
                        self.pt.borrow_mut().unmap(page.va);
                        f.discard();
                    }
                }
            }
        }
    }

    fn collect_pending(&mut self) -> Result<(), MapError> {
        self.refresh_files();
        let pending = self.pending.get_mut();
        if pending.is_empty() {
            return Ok(());
        }
        let old_len = self.pages.len();
        let tail_only = self
            .pages
            .last()
            .is_some_and(|last| pending.iter().all(|p| p.va > last.va));
        // 两批页交错时总要整体排序，优先复用能容纳旧页的新缓冲区。
        if !tail_only && pending.capacity() - pending.len() >= old_len {
            pending.append(&mut self.pages);
            self.pages = core::mem::take(pending);
        } else {
            reserve(&mut self.pages, pending.len())?;
            self.pages.append(&mut core::mem::take(pending));
        }
        let first = if tail_only { old_len } else { 0 };
        self.pages[first..].sort_unstable_by_key(|p| p.va);
        Ok(())
    }

    /// 将与下一次映射有关的锁属性交给同一套建图/限额逻辑；
    /// 只在当前独占借用期间覆盖默认值，失败也恢复 mlockall 策略。
    pub(crate) fn with_map_lock<T, E>(
        &mut self,
        build: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let previous = (
            self.lock_future,
            self.lock_onfault,
            self.defer_map_population,
        );
        self.lock_future = true;
        self.lock_onfault = false;
        self.defer_map_population = true;
        let result = build(self);
        (
            self.lock_future,
            self.lock_onfault,
            self.defer_map_population,
        ) = previous;
        result
    }

    /// 仅保留匿名虚拟区间，首次合法访问时才分配物理页。
    pub fn reserve_region(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
        kind: AreaKind,
    ) -> Result<(), MapError> {
        if self.lock_future && !self.lock_onfault && !self.defer_map_population {
            return self.map_region(start, count, flags, kind);
        }
        let end = end_of(start, count)?;
        check_flags(flags)?;
        self.check_mapping_limit(start, end, false, Self::chargeable(kind, false, flags))?;
        if !matches!(kind, AreaKind::Anonymous | AreaKind::Heap | AreaKind::Stack) {
            return Err(MapError::InvalidPermissions);
        }
        let in_stack = self.stack_covers(start, end);
        if end > GUARD_BOTTOM
            && !in_stack
            && !(kind == AreaKind::Stack && start >= USER_STACK_BOTTOM)
        {
            return Err(MapError::HitsStack);
        }
        if self.overlaps(start, count)? {
            return Err(MapError::Overlap);
        }
        reserve(&mut self.areas, 1)?;
        self.areas.push(VmArea {
            start,
            end,
            flags,
            kind,
            locked: self.lock_future,
            onfault: self.lock_future && self.lock_onfault,
            shared_file: false,
            no_fork: false,
            wipe_on_fork: false,
        });
        self.coalesce();
        Ok(())
    }

    /// 事务替换为未驻留的私有匿名区间；先准备元数据，再撤销旧页。
    pub fn reserve_fixed(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        if self.lock_future && !self.lock_onfault && !self.defer_map_population {
            return self.replace_region(start, count, flags);
        }
        let end = end_of(start, count)?;
        check_flags(flags)?;
        self.check_mapping_limit(
            start,
            end,
            true,
            Self::chargeable(AreaKind::Anonymous, false, flags),
        )?;
        let in_stack = self.stack_covers(start, end);
        if end > GUARD_BOTTOM && !in_stack {
            return Err(MapError::HitsStack);
        }
        self.collect_pending()?;
        let mut areas = self.split(start, end, None)?;
        reserve(&mut areas, 1)?;
        areas.push(VmArea {
            start,
            end,
            flags,
            kind: AreaKind::Anonymous,
            locked: self.lock_future,
            onfault: self.lock_future && self.lock_onfault,
            shared_file: false,
            no_fork: false,
            wipe_on_fork: false,
        });
        for p in &self.pages {
            if start <= p.va && p.va < end {
                self.pt.borrow_mut().unmap(p.va);
                if let Backing::File(file) = &*p.backing() {
                    file.discard();
                }
            }
        }
        self.pages.retain(|p| p.va < start || p.va >= end);
        self.areas = areas;
        self.coalesce();
        Ok(())
    }

    /// 查找包含 va 的已排序区域。
    fn area_at(&self, va: usize) -> Option<&VmArea> {
        self.areas
            .binary_search_by(|a| {
                if va < a.start {
                    core::cmp::Ordering::Greater
                } else if va >= a.end {
                    core::cmp::Ordering::Less
                } else {
                    core::cmp::Ordering::Equal
                }
            })
            .ok()
            .map(|i| &self.areas[i])
    }

    /// 定位可读映射中的等待字。查询别名时无需调入页面，也不触发写时复制。
    pub(crate) fn futex_key(&self, tgid: usize, address: usize, private: bool) -> Option<FutexKey> {
        let area = self.area_at(address)?;
        if !area.flags.contains(MappingFlags::R) {
            return None;
        }
        if private || (area.kind != AreaKind::SharedAnonymous && !area.shared_file) {
            return Some(FutexKey::Private { tgid, address });
        }
        let within = address % PAGE_SIZE;
        let page = self.page_at(address - within)?;
        match &*page.backing() {
            Backing::AnonymousShared(page) => {
                let (object, index) = page.identity();
                Some(FutexKey::Anonymous {
                    object,
                    offset: index * PAGE_SIZE + within,
                })
            }
            Backing::File(file) => {
                let (inode, offset) = file.identity();
                Some(FutexKey::File {
                    inode,
                    offset: offset + within,
                })
            }
            Backing::Private(_) => None,
        }
    }

    /// 校验访问权限并在已驻留快路径直接返回物理地址，避免用户拷贝二次遍历页表。
    pub fn ensure_and_translate(
        &self,
        va: usize,
        required: MappingFlags,
    ) -> Result<PhysAddr, MapError> {
        let area = self.area_at(va).ok_or(MapError::NotMapped)?;
        let actual = if area.flags.intersects(MappingFlags::RWX) {
            area.flags | MappingFlags::X
        } else {
            area.flags
        };
        if !actual.contains(required) {
            return Err(MapError::PermissionDenied);
        }
        self.refresh_files();
        let page_va = va / PAGE_SIZE * PAGE_SIZE;
        if let Some((pa, flags)) = self.pt.borrow().translate(page_va) {
            if flags.contains(required) {
                return Ok(PhysAddr::new(pa.raw() + va % PAGE_SIZE));
            }
        }
        self.ensure_access(va, required)?;
        self.translate(va)
            .map(|(pa, _)| pa)
            .ok_or(MapError::NotMapped)
    }

    /// 为访问准备物理页；按区域权限处理匿名和文件后备缺页。
    pub fn ensure_access(&self, va: usize, required: MappingFlags) -> Result<(), MapError> {
        let area = self.area_at(va).ok_or(MapError::NotMapped)?;
        let actual = if area.flags.intersects(MappingFlags::RWX) {
            area.flags | MappingFlags::X
        } else {
            area.flags
        };
        if !actual.contains(required) {
            return Err(MapError::PermissionDenied);
        }
        self.refresh_files();
        let page_va = va / PAGE_SIZE * PAGE_SIZE;
        // 叶项已满足请求时无需再查 pages/pending；避免顺序访问重复线性扫描。
        let leaf = self.pt.borrow().translate(page_va);
        if leaf.is_some_and(|(_, flags)| flags.contains(required)) {
            return Ok(());
        }
        if area.kind == AreaKind::SharedAnonymous {
            if self.pt.borrow().translate(va).is_some() {
                return Ok(());
            }
            let page = self.page_at(page_va).ok_or(MapError::NotMapped)?;
            let Backing::AnonymousShared(shared) = &*page.backing() else {
                return Err(MapError::NotMapped);
            };
            return shared.fault(|pa| {
                self.pt
                    .borrow_mut()
                    .map(page_va, pa, area.flags)
                    .map_err(Into::into)
            });
        }
        if area.kind == AreaKind::File {
            let page = self.page_at(page_va).ok_or(MapError::NotMapped)?;
            let Backing::File(file) = &*page.backing() else {
                return Err(MapError::NotMapped);
            };
            if file.addr().is_none() {
                let pa = file.fault()?;
                if let Err(e) = self.pt.borrow_mut().map(page_va, pa, area.flags) {
                    file.discard();
                    return Err(e.into());
                }
                super::fence_icache();
            } else {
                let shared = file.is_cow_shared();
                let split = shared && required.contains(MappingFlags::W);
                let pa = if split {
                    file.split_private()?
                } else {
                    file.addr().ok_or(MapError::NotMapped)?
                };
                let flags = if shared && !split {
                    area.flags - MappingFlags::W
                } else {
                    area.flags
                };
                if leaf.is_some() {
                    self.pt.borrow_mut().protect(page_va, pa, flags);
                } else {
                    self.pt.borrow_mut().map(page_va, pa, flags)?;
                }
                if split || leaf.is_none() {
                    super::fence_icache();
                }
            }
            return Ok(());
        }
        if matches!(
            area.kind,
            AreaKind::Elf | AreaKind::Anonymous | AreaKind::Heap | AreaKind::Stack
        ) {
            let installed = self.page_at(page_va);
            if leaf.is_none() && installed.is_none() && area.kind != AreaKind::Elf {
                // pending 只收录已安装的匿名页；撤销叶项前先由 collect_pending 接管。
                let mut pending = self.pending.borrow_mut();
                reserve(&mut pending, 1)?;
                let frame = FrameRef::new()?;
                self.pt
                    .borrow_mut()
                    .map(page_va, frame.addr(), area.flags)?;
                pending.push(Page::new(page_va, Backing::Private(frame)));
                return Ok(());
            }
            let pending = self.pending.borrow();
            if let Some(page) = installed.or_else(|| pending.iter().find(|p| p.va == page_va)) {
                if let Backing::Private(frame) = &mut *page.frame.borrow_mut() {
                    let shared = frame.strong_count() > 1;
                    let split = shared && required.contains(MappingFlags::W);
                    let copy = if split {
                        Some(frame.duplicate()?)
                    } else {
                        None
                    };
                    let pa = copy.as_ref().unwrap_or(frame).addr();
                    let flags = if shared && !split {
                        area.flags - MappingFlags::W
                    } else {
                        area.flags
                    };
                    if leaf.is_some() {
                        self.pt.borrow_mut().protect(page_va, pa, flags);
                    } else {
                        self.pt.borrow_mut().map(page_va, pa, flags)?;
                    }
                    if let Some(new) = copy {
                        *frame = new;
                    }
                    if split || leaf.is_none() {
                        super::fence_icache();
                    }
                    return Ok(());
                }
            }
        }
        if self.resident(va)? {
            Ok(())
        } else {
            Err(MapError::NotMapped)
        }
    }

    /// 在内核页表活动时创建；根页分配也会返回 OOM。
    pub fn new() -> Result<Self, MapError> {
        Ok(Self {
            pt: RefCell::new(UserPageTable::new()?),
            pending: RefCell::new(Vec::new()),
            truncations: Cell::new(file::truncations()),
            pages: Vec::new(),
            areas: Vec::new(),
            shm_attachments: Vec::new(),
            heap_start: 0,
            program_break: 0,
            limits: [[usize::MAX; 2]; 4],
            defer_map_population: false,
            lock_future: false,
            lock_onfault: false,
            local_only: PhantomData,
        })
    }
    /// 将准备好的镜像并入地址空间；页表和元数据均准备成功后才提交。
    pub(crate) fn install_image(&mut self, mut image: Self) -> Result<(), MapError> {
        self.collect_pending()?;
        if image.areas.iter().any(|a| {
            self.areas
                .iter()
                .any(|b| a.start < b.end && b.start < a.end)
        }) {
            return Err(MapError::Overlap);
        }
        image.collect_pending()?;
        reserve(&mut self.pages, image.pages.len())?;
        reserve(&mut self.areas, image.areas.len())?;
        let mut pt = UserPageTable::new()?;
        for space in [&*self, &image] {
            for page in &space.pages {
                let area = space
                    .areas
                    .iter()
                    .find(|a| a.start <= page.va && page.va < a.end)
                    .ok_or(MapError::NotMapped)?;
                page.install(&mut pt, page.va, area.flags)?;
            }
        }
        let active = self.pt.borrow_mut().is_active();
        core::mem::swap(self.pt.get_mut(), &mut pt);
        if active {
            self.pt.borrow_mut().activate();
        }
        drop(pt);
        if !image.pages.is_empty() {
            image.pages.sort_unstable_by_key(|p| p.va);
            let ordered = self.pages.last().is_none_or(|p| p.va < image.pages[0].va);
            self.append_pages(core::mem::take(&mut image.pages), ordered);
        }
        self.areas.append(&mut image.areas);
        self.coalesce();
        Ok(())
    }
    /// ELF 加载结束后确定堆起点；只初始化一次。
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
        if requested > old && requested.saturating_sub(self.heap_start) > self.limits[0][0] {
            return old;
        }
        let old_end = old.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let new_end = requested.div_ceil(PAGE_SIZE) * PAGE_SIZE;
        let result = match new_end.cmp(&old_end) {
            core::cmp::Ordering::Greater => self.reserve_region(
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
        let fits = |start: usize| {
            end_of(start, count)
                .ok()
                .filter(|&end| end <= GUARD_BOTTOM)
                .is_some_and(|_| !self.overlaps(start, count).unwrap_or(true))
        };
        let hint = hint / PAGE_SIZE * PAGE_SIZE;
        if hint != 0 && fits(hint) {
            return Ok(hint);
        }
        let mut start = 0x1000_0000;
        for a in &self.areas {
            if a.end <= start {
                continue;
            }
            if start < a.start && fits(start) {
                return Ok(start);
            }
            start = a.end;
        }
        if fits(start) {
            Ok(start)
        } else if fits(super::kstack::WINDOW_ROOT_END) {
            Ok(super::kstack::WINDOW_ROOT_END)
        } else {
            Err(MapError::OutOfMemory)
        }
    }
    /// MAP_FIXED 的事务替换：新页、区域元数据、替代页表全部准备成功后才提交。
    pub fn replace_region(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        self.collect_pending()?;
        let end = end_of(start, count)?;
        check_flags(flags)?;
        self.check_mapping_limit(
            start,
            end,
            true,
            Self::chargeable(AreaKind::Anonymous, false, flags),
        )?;
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
            locked: self.lock_future,
            onfault: self.lock_future && self.lock_onfault,
            shared_file: false,
            no_fork: false,
            wipe_on_fork: false,
        });
        reserve(&mut self.pages, count)?;
        let mut fresh: Vec<Page> = Vec::new();
        reserve(&mut fresh, count)?;
        for va in (start..end).step_by(PAGE_SIZE) {
            fresh.push(Page::new(va, Backing::Private(FrameRef::new()?)));
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
            page.install(&mut next_pt, page.va, area.flags)?;
        }
        for page in &fresh {
            page.install(&mut next_pt, page.va, flags)?;
        }
        let active = self.pt.borrow_mut().is_active();
        core::mem::swap(self.pt.get_mut(), &mut next_pt);
        if active {
            self.pt.borrow_mut().activate();
        }
        drop(next_pt);
        self.pages.retain(|p| p.va < start || p.va >= end);
        let ordered = self.pages.last().is_none_or(|p| p.va < start);
        self.append_pages(fresh, ordered);
        self.areas = next_areas;
        self.coalesce();
        Ok(())
    }
    /// 验证完整页区间；discard 清除私有匿名内容，保留区域和权限。
    pub fn advise(&mut self, start: usize, count: usize, discard: bool) -> Result<(), MapError> {
        self.collect_pending()?;
        let end = end_of(start, count)?;
        let mut cursor = start;
        for area in &self.areas {
            if area.end <= cursor {
                continue;
            }
            if area.start > cursor || cursor == end {
                break;
            }
            if discard && area.locked {
                return Err(MapError::InvalidPermissions);
            }
            if discard
                && !matches!(
                    area.kind,
                    AreaKind::Anonymous
                        | AreaKind::Heap
                        | AreaKind::Stack
                        | AreaKind::File
                        | AreaKind::SharedAnonymous
                )
            {
                return Err(MapError::UnsupportedPermissions);
            }
            cursor = area.end.min(end);
        }
        if cursor != end {
            return Err(MapError::NotMapped);
        }
        if !discard {
            return Ok(());
        }
        for page in &self.pages {
            if page.va >= start && page.va < end {
                self.pt.borrow_mut().unmap(page.va);
                if let Backing::File(file) = &*page.backing() {
                    file.discard();
                }
            }
        }
        self.pages.retain(|p| {
            p.va < start || p.va >= end || !matches!(&*p.backing(), Backing::Private(_))
        });
        super::fence_icache();
        Ok(())
    }

    /// 设置 fork 的区间策略。先检查整段并准备分割后的区域，再一次提交。
    pub(crate) fn fork_advice(
        &mut self,
        start: usize,
        count: usize,
        advice: usize,
    ) -> Result<(), MapError> {
        self.advise(start, count, false)?;
        let end = end_of(start, count)?;
        let mut next = Vec::new();
        reserve(
            &mut next,
            self.areas
                .len()
                .checked_add(2)
                .ok_or(MapError::OutOfMemory)?,
        )?;
        for a in &self.areas {
            if a.end <= start || a.start >= end {
                next.push(*a);
                continue;
            }
            let mut mid = VmArea {
                start: a.start.max(start),
                end: a.end.min(end),
                ..*a
            };
            match advice {
                10 | 11 => mid.no_fork = advice == 10,
                18 if matches!(
                    a.kind,
                    AreaKind::Anonymous | AreaKind::Heap | AreaKind::Stack
                ) =>
                {
                    mid.wipe_on_fork = true
                }
                19 => mid.wipe_on_fork = false,
                _ => return Err(MapError::InvalidPermissions),
            }
            if a.start < start {
                next.push(VmArea { end: start, ..*a });
            }
            next.push(mid);
            if a.end > end {
                next.push(VmArea { start: end, ..*a });
            }
        }
        self.areas = next;
        self.coalesce();
        Ok(())
    }

    /// 立即锁页时，按可写私有映射的写权限预取，提前完成 fork 留下的 COW。
    fn populate_locked(&self, area: &VmArea, start: usize, end: usize) -> Result<(), MapError> {
        let cow = matches!(
            area.kind,
            AreaKind::Elf | AreaKind::Anonymous | AreaKind::Heap | AreaKind::Stack
        ) || (area.kind == AreaKind::File && !area.shared_file);
        let access = if cow && area.flags.contains(MappingFlags::W) {
            MappingFlags::U | MappingFlags::W
        } else {
            MappingFlags::U
        };
        for va in (start..end).step_by(PAGE_SIZE) {
            self.ensure_access(va, access)?;
        }
        Ok(())
    }

    /// 修改锁页属性；普通锁页先填充页面，on-fault 只记录属性。
    pub fn lock_range(
        &mut self,
        start: usize,
        count: usize,
        locked: bool,
        on_fault: bool,
    ) -> Result<(), MapError> {
        let end = end_of(start, count)?;
        self.advise(start, count, false)?;
        if locked {
            let mut bytes = end - start;
            for a in &self.areas {
                if a.locked {
                    bytes += a.end - a.start - a.end.min(end).saturating_sub(a.start.max(start));
                }
            }
            if bytes > self.limits[2][0] {
                return Err(MapError::OutOfMemory);
            }
        }
        let mut areas = Vec::new();
        reserve(
            &mut areas,
            self.areas
                .len()
                .checked_mul(3)
                .ok_or(MapError::OutOfMemory)?,
        )?;
        for a in &self.areas {
            if a.end <= start || a.start >= end {
                areas.push(*a);
                continue;
            }
            if a.start < start {
                areas.push(VmArea { end: start, ..*a });
            }
            areas.push(VmArea {
                start: a.start.max(start),
                end: a.end.min(end),
                locked,
                onfault: locked && on_fault,
                ..*a
            });
            if a.end > end {
                areas.push(VmArea { start: end, ..*a });
            }
        }
        if locked && !on_fault {
            for area in self.areas.iter().filter(|a| a.start < end && start < a.end) {
                self.populate_locked(area, start.max(area.start), end.min(area.end))?;
            }
        }
        self.areas = areas;
        self.coalesce();
        Ok(())
    }

    /// 同步完整映射区间内的共享文件页，复用文件系统已有写回入口。
    pub fn sync_range(
        &mut self,
        start: usize,
        count: usize,
        invalidate: bool,
    ) -> Result<(), crate::syscall::Errno> {
        use crate::syscall::Errno;
        let end = end_of(start, count).map_err(|_| Errno::NoMem)?;
        self.advise(start, count, false).map_err(|_| Errno::NoMem)?;
        if invalidate
            && self
                .areas
                .iter()
                .any(|a| a.start < end && start < a.end && a.locked)
        {
            return Err(Errno::Busy);
        }
        // 所有共享别名已使用同一缓存页；同步时保留其身份和私有映射的内容。
        // 每个文件 VMA 内页偏移连续；只同步用户指定区间对应的文件页。
        for area in self
            .areas
            .iter()
            .filter(|a| a.kind == AreaKind::File && a.shared_file && a.start < end && start < a.end)
        {
            let first = area.start.max(start);
            let length = area.end.min(end) - first;
            let page = self.page_at(first).ok_or(Errno::Fault)?;
            if let Backing::File(file) = &*page.backing() {
                if let Some((ino, offset)) = file.writeback_start() {
                    crate::fs::sync_mapping(ino, offset, length)?;
                }
            }
        }
        Ok(())
    }

    /// mlockall/munlockall 策略；先准备驻留页，成功后统一发布锁属性。
    pub fn lock_all(&mut self, flags: usize) -> Result<(), MapError> {
        if flags == 0 {
            for a in &mut self.areas {
                a.locked = false;
                a.onfault = false;
            }
            self.lock_future = false;
            self.lock_onfault = false;
            self.coalesce();
            return Ok(());
        }
        let on_fault = flags & 4 != 0;
        if flags & 1 != 0 {
            if self.areas.iter().map(|a| a.end - a.start).sum::<usize>() > self.limits[2][0] {
                return Err(MapError::OutOfMemory);
            }
            if !on_fault {
                for a in &self.areas {
                    self.populate_locked(a, a.start, a.end)?;
                }
            }
            for a in &mut self.areas {
                a.locked = true;
                a.onfault = on_fault;
            }
        }
        self.lock_future = flags & 2 != 0;
        self.lock_onfault = on_fault;
        self.coalesce();
        Ok(())
    }

    /// 请求区间是否完全由现有用户栈 VMA 覆盖。
    fn stack_covers(&self, start: usize, end: usize) -> bool {
        if start < USER_STACK_BOTTOM {
            return false;
        }
        let mut cursor = start;
        for area in self
            .areas
            .iter()
            .filter(|a| a.kind == AreaKind::Stack && a.start < end && start < a.end)
        {
            if area.start > cursor {
                break;
            }
            cursor = cursor.max(area.end);
        }
        cursor >= end
    }

    /// 精确地址映射的冲突检测，全程由同一个可变地址空间借用保护。
    pub fn overlaps(&self, start: usize, count: usize) -> Result<bool, MapError> {
        let end = end_of(start, count)?;
        let first = self.areas.partition_point(|a| a.end <= start);
        Ok(self.areas.get(first).is_some_and(|a| a.start < end))
    }

    /// 查询已映射页的驻留状态；PROT_NONE 仍是有效映射。
    pub fn resident(&self, va: usize) -> Result<bool, MapError> {
        self.refresh_files();
        if self.area_at(va).is_none() {
            return Err(MapError::NotMapped);
        }
        let page_va = va / PAGE_SIZE * PAGE_SIZE;
        if self.pt.borrow().translate(page_va).is_some() {
            return Ok(true);
        }
        if let Some(page) = self.page_at(page_va) {
            return Ok(match &*page.backing() {
                Backing::File(file) => file.resident(),
                frame => frame.addr().is_some(),
            });
        }
        Ok(self
            .pending
            .borrow()
            .iter()
            .find(|p| p.va == page_va)
            .is_some_and(|p| match &*p.backing() {
                Backing::File(file) => file.resident(),
                frame => frame.addr().is_some(),
            }))
    }

    /// 调整单个区域中的页区间；提交前保留原页所有权及页表。
    /// 扩展目前仅支持匿名私有页，文件扩展须提供文件后备对象。
    pub fn remap(
        &mut self,
        start: usize,
        old_count: usize,
        new_count: usize,
        may_move: bool,
        fixed: Option<usize>,
    ) -> Result<usize, MapError> {
        self.remap_mode(start, old_count, new_count, may_move, fixed, false)
    }
    pub(crate) fn remap_mode(
        &mut self,
        start: usize,
        old_count: usize,
        new_count: usize,
        may_move: bool,
        fixed: Option<usize>,
        keep_source: bool,
    ) -> Result<usize, MapError> {
        self.collect_pending()?;
        let alias = old_count == 0;
        if (alias || keep_source) && !may_move || keep_source && new_count != old_count {
            return Err(MapError::InvalidPermissions);
        }
        let old_end = if alias {
            start
        } else {
            end_of_unmap(start, old_count)?
        };
        let area = *self
            .area_at(start)
            .filter(|a| old_end <= a.end)
            .ok_or(MapError::NotMapped)?;
        if new_count > old_count
            && !matches!(
                area.kind,
                AreaKind::Anonymous | AreaKind::File | AreaKind::SharedAnonymous
            )
        {
            return Err(MapError::UnsupportedPermissions);
        }
        if alias {
            let shareable = self.page_at(start).is_some_and(|p| match &*p.backing() {
                Backing::AnonymousShared(_) => true,
                Backing::File(f) => matches!(f.mode, Mode::Shared { .. }),
                _ => false,
            });
            if !shareable {
                return Err(MapError::InvalidPermissions);
            }
        }
        if keep_source
            && !matches!(
                area.kind,
                AreaKind::Anonymous | AreaKind::SharedAnonymous | AreaKind::File
            )
        {
            return Err(MapError::UnsupportedPermissions);
        }
        let inplace = end_of(start, new_count).ok().filter(|&end| {
            end <= GUARD_BOTTOM && !self.areas.iter().any(|a| a.start < end && a.end > old_end)
        });
        let dest = if let Some(dest) = fixed {
            if !may_move {
                return Err(MapError::InvalidPermissions);
            }
            let end = end_of(dest, new_count)?;
            if (if alias { dest <= start } else { dest < old_end }) && start < end {
                return Err(MapError::InvalidPermissions);
            }
            dest
        } else if !alias && !keep_source && (new_count <= old_count || inplace.is_some()) {
            start
        } else if may_move {
            self.find_free(0, new_count)?
        } else {
            return Err(MapError::OutOfMemory);
        };
        let end = end_of(dest, new_count)?;
        if end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        let mut total = end - dest;
        let mut locked = if area.locked { end - dest } else { 0 };
        for a in &self.areas {
            let source_overlap = a.end.min(old_end).saturating_sub(a.start.max(start));
            let dest_overlap = if dest == start {
                0
            } else {
                a.end.min(end).saturating_sub(a.start.max(dest))
            };
            let retained = a.end - a.start - source_overlap - dest_overlap;
            total += retained + if keep_source { source_overlap } else { 0 };
            if a.locked {
                locked += retained;
            }
        }
        if (total > self.limits[3][0] && total > self.areas.iter().map(|a| a.end - a.start).sum())
            || (locked > self.limits[2][0]
                && locked
                    > self
                        .areas
                        .iter()
                        .filter(|a| a.locked)
                        .map(|a| a.end - a.start)
                        .sum())
        {
            return Err(MapError::OutOfMemory);
        }
        let remaining = self.split(start, old_end, None)?;
        let mut areas = Vec::new();
        reserve(
            &mut areas,
            remaining
                .len()
                .checked_mul(2)
                .and_then(|n| n.checked_add(2))
                .ok_or(MapError::OutOfMemory)?,
        )?;
        for a in remaining {
            if a.end <= dest || a.start >= end {
                areas.push(a);
            } else {
                if a.start < dest {
                    areas.push(VmArea { end: dest, ..a });
                }
                if a.end > end {
                    areas.push(VmArea { start: end, ..a });
                }
            }
        }
        areas.push(VmArea {
            start: dest,
            end,
            ..area
        });
        if keep_source {
            areas.push(VmArea {
                start,
                end: old_end,
                locked: false,
                onfault: false,
                ..area
            });
        }
        self.check_data_layout(&areas)?;
        let keep = old_count.min(new_count);
        let keep_end = start + keep * PAGE_SIZE;
        // 未锁定的匿名扩展只增加 VMA，不预留逐页元数据或物理帧。
        let extra = if area.kind == AreaKind::Anonymous && (!area.locked || area.onfault) {
            0
        } else {
            new_count.saturating_sub(old_count)
        };
        let mut fresh = Vec::new();
        reserve(&mut fresh, extra)?;
        reserve(&mut self.pages, extra)?;
        for i in keep..keep + extra {
            let frame = if matches!(area.kind, AreaKind::File | AreaKind::SharedAnonymous) {
                let last = self
                    .page_at(if alias { start } else { old_end - PAGE_SIZE })
                    .ok_or(MapError::NotMapped)?;
                match &*last.backing() {
                    Backing::AnonymousShared(s) => {
                        Backing::AnonymousShared(s.following(if alias {
                            i
                        } else {
                            i - old_count + 1
                        })?)
                    }
                    Backing::File(f) => Backing::File(
                        f.following((if alias { i } else { i - old_count + 1 }) * PAGE_SIZE)?,
                    ),
                    _ => return Err(MapError::UnsupportedPermissions),
                }
            } else {
                Backing::Private(FrameRef::new()?)
            };
            fresh.push(Page::new(dest + i * PAGE_SIZE, frame));
        }
        // 原区域保留后备身份，不保留私有副本。全部描述符在发布前准备。
        let mut original = Vec::new();
        if keep_source && area.kind != AreaKind::Anonymous {
            reserve(&mut original, old_count)?;
            reserve(
                &mut self.pages,
                extra.checked_add(old_count).ok_or(MapError::OutOfMemory)?,
            )?;
            for page in self
                .pages
                .iter()
                .filter(|p| start <= p.va && p.va < old_end)
            {
                let frame = match &*page.backing() {
                    Backing::AnonymousShared(p) => Backing::AnonymousShared(p.clone()),
                    Backing::File(f) => Backing::File(f.following(0)?),
                    _ => return Err(MapError::NotMapped),
                };
                original.push(Page::new(page.va, frame));
            }
        }
        let mut pt = UserPageTable::new()?;
        for p in &self.pages {
            if start <= p.va && p.va < old_end {
                if p.va < keep_end {
                    p.install(&mut pt, dest + (p.va - start), area.flags)?;
                }
            } else if p.va < dest || p.va >= end {
                let flags = self
                    .areas
                    .iter()
                    .find(|a| a.start <= p.va && p.va < a.end)
                    .ok_or(MapError::NotMapped)?
                    .flags;
                p.install(&mut pt, p.va, flags)?;
            }
        }
        for p in &fresh {
            if area.locked && !area.onfault {
                match &*p.backing() {
                    Backing::File(f) => {
                        f.fault()?;
                    }
                    Backing::AnonymousShared(s) => s.fault(|_| Ok(()))?,
                    _ => {}
                }
            }
            p.install(&mut pt, p.va, area.flags)?;
        }
        let active = self.pt.borrow_mut().is_active();
        core::mem::swap(self.pt.get_mut(), &mut pt);
        if active {
            self.pt.borrow_mut().activate();
        }
        drop(pt);
        self.pages.retain(|p| {
            if start <= p.va && p.va < old_end {
                p.va < keep_end
            } else {
                p.va < dest || p.va >= end
            }
        });
        for p in &mut self.pages {
            if start <= p.va && p.va < keep_end {
                p.va = dest + (p.va - start);
            }
        }
        self.pages.append(&mut fresh);
        self.pages.append(&mut original);
        self.pages.sort_unstable_by_key(|p| p.va);
        self.areas = areas;
        self.coalesce();
        Ok(dest)
    }

    /// 页与区域均按地址升序排列。遍历整个地址空间时，区域游标只向前移动。
    fn pages_with_areas(&self) -> impl Iterator<Item = Result<(&Page, &VmArea), MapError>> {
        let mut areas = self.areas.iter().peekable();
        self.pages.iter().map(move |page| {
            while areas.next_if(|area| area.end <= page.va).is_some() {}
            let area = areas
                .peek()
                .copied()
                .filter(|area| area.start <= page.va)
                .ok_or(MapError::NotMapped)?;
            Ok((page, area))
        })
    }

    /// 为 fork 复制用户空间。先归并驻留页，待子页表建好后才对父页启用写时复制。
    pub fn deep_copy(&mut self) -> Result<Self, MapError> {
        self.collect_pending()?;
        let mut child = Self::new()?;
        reserve(&mut child.areas, self.areas.len())?;
        reserve(&mut child.pages, self.pages.len())?;
        reserve(&mut child.shm_attachments, self.shm_attachments.len())?;
        child
            .areas
            .extend(self.areas.iter().filter(|a| !a.no_fork).copied());
        for area in &mut child.areas {
            area.locked = false;
            area.onfault = false;
        }
        for entry in self.pages_with_areas() {
            let (source, area) = entry?;
            if area.no_fork || area.wipe_on_fork {
                continue;
            }
            let mut child_flags = area.flags;
            let frame = match &*source.backing() {
                Backing::Private(shared) => {
                    // 全部私有帧（含 ELF、匿名、堆、栈）跨 fork 共享；父页在全部子页安装成功后再降权。
                    child_flags = area.flags - MappingFlags::W;
                    Backing::Private(shared.clone())
                }
                Backing::File(f) => {
                    let forked = f.fork()?;
                    if forked.is_cow_shared() {
                        child_flags = area.flags - MappingFlags::W;
                    }
                    Backing::File(forked)
                }
                Backing::AnonymousShared(page) => Backing::AnonymousShared(page.clone()),
            };
            frame.install(child.pt.get_mut(), source.va, child_flags)?;
            child.pages.push(Page::new(source.va, frame));
        }
        // 只有写时复制的私有帧与私有文件驻留页会由父子共同持有；子空间安装完成后再统一降权。
        let shared = child
            .pages
            .iter()
            .filter_map(|page| match &*page.backing() {
                Backing::Private(frame) if frame.strong_count() > 1 => Some(page.va),
                Backing::File(file) if file.is_cow_shared() => Some(page.va),
                _ => None,
            });
        self.pt.get_mut().write_protect_pages(shared);
        child.limits = self.limits;
        child.heap_start = self.heap_start;
        child.program_break = self.program_break;
        // 全部可失败步骤均已提交后，再继承 SHM 挂接记录并递增段表引用计数。
        child
            .shm_attachments
            .extend_from_slice(&self.shm_attachments);
        for att in &child.shm_attachments {
            super::shm::on_fork_attach(att.shmid);
        }
        super::fence_icache();
        Ok(child)
    }
    /// 将已有共享匿名对象首页 `first` 起的 `count` 页映射到用户空间。
    pub(crate) fn map_shared_pages(
        &mut self,
        start: usize,
        first: &SharedPage,
        count: usize,
        flags: MappingFlags,
        fixed: bool,
    ) -> Result<(), MapError> {
        let end = end_of(start, count)?;
        check_flags(flags)?;
        if end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        if !fixed && self.areas.iter().any(|a| start < a.end && a.start < end) {
            return Err(MapError::Overlap);
        }
        let mut frames = Vec::new();
        reserve(&mut frames, count)?;
        for i in 0..count {
            frames.push(Backing::AnonymousShared(first.following(i)?));
        }
        self.map_backed_kind(start, frames, flags, fixed, AreaKind::SharedAnonymous)
    }
    /// 建立可跨 fork 共享的匿名页；引用元数据与数据页均可失败分配。
    pub fn map_shared_anonymous(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
        fixed: bool,
    ) -> Result<(), MapError> {
        let first = SharedPage::first()?;
        self.map_shared_pages(start, &first, count, flags, fixed)
    }
    /// 挂接 System V 共享内存段：预留挂接表槽位后映射共享页，失败时保持原状。
    pub(crate) fn attach_shm(
        &mut self,
        shmid: usize,
        start: usize,
        first: &SharedPage,
        count: usize,
        flags: MappingFlags,
        fixed: bool,
    ) -> Result<(), MapError> {
        reserve(&mut self.shm_attachments, 1)?;
        self.map_shared_pages(start, first, count, flags, fixed)?;
        self.shm_attachments.push(ShmAttachment {
            start,
            shmid,
            pages: count,
        });
        Ok(())
    }
    /// 按挂接起始地址解除 System V 共享内存段映射，返回被解除的 shmid。
    pub(crate) fn detach_shm(&mut self, start: usize) -> Option<usize> {
        let idx = self.shm_attachments.iter().position(|a| a.start == start)?;
        let att = self.shm_attachments.swap_remove(idx);
        let _ = self.unmap(att.start, att.pages);
        Some(att.shmid)
    }

    /// 事务安装文件页；FIXED 只有在全部页表与元数据准备成功后替换。
    pub(crate) fn map_backed(
        &mut self,
        start: usize,
        frames: Vec<Backing>,
        flags: MappingFlags,
        fixed: bool,
    ) -> Result<(), MapError> {
        self.map_backed_kind(start, frames, flags, fixed, AreaKind::File)
    }
    fn map_backed_kind(
        &mut self,
        start: usize,
        frames: Vec<Backing>,
        flags: MappingFlags,
        fixed: bool,
        kind: AreaKind,
    ) -> Result<(), MapError> {
        self.collect_pending()?;
        let end = end_of(start, frames.len())?;
        check_flags(flags)?;
        let shared_file =
            matches!(frames.first(),Some(Backing::File(f)) if matches!(f.mode,Mode::Shared{..}));
        self.check_mapping_limit(
            start,
            end,
            fixed,
            Self::chargeable(kind, shared_file, flags),
        )?;
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
            kind,
            locked: self.lock_future,
            onfault: self.lock_future && self.lock_onfault,
            shared_file,
            no_fork: false,
            wipe_on_fork: false,
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
            p.install(&mut pt, p.va, area.flags)?;
        }
        for (i, frame) in frames.into_iter().enumerate() {
            let va = start + i * PAGE_SIZE;
            if self.lock_future && !self.lock_onfault && !self.defer_map_population {
                match &frame {
                    Backing::File(f) => {
                        if f.addr().is_none() {
                            f.fault()?;
                        }
                    }
                    Backing::AnonymousShared(s) => s.fault(|_| Ok(()))?,
                    _ => {}
                }
            }
            frame.install(&mut pt, va, flags)?;
            fresh.push(Page::new(va, frame));
        }
        let active = self.pt.borrow_mut().is_active();
        core::mem::swap(self.pt.get_mut(), &mut pt);
        if active {
            self.pt.borrow_mut().activate();
        }
        drop(pt);
        self.pages.retain(|p| p.va < start || p.va >= end);
        let ordered = self.pages.last().is_none_or(|p| p.va < start);
        self.append_pages(fresh, ordered);
        self.areas = areas;
        self.coalesce();
        Ok(())
    }
    /// 返回区域视图，不暴露可修改的映射或页所有权。
    pub fn areas(&self) -> &[VmArea] {
        &self.areas
    }
    /// 页清单按 va 升序维护，查找走二分。
    fn page_at(&self, va: usize) -> Option<&Page> {
        self.pages
            .binary_search_by_key(&va, |p| p.va)
            .ok()
            .map(|i| &self.pages[i])
    }
    /// 追加升序页块；块起点不在末尾之后时排序恢复升序。
    fn append_pages(&mut self, mut fresh: Vec<Page>, ordered: bool) {
        if fresh.is_empty() {
            return;
        }
        debug_assert!(fresh.windows(2).all(|w| w[0].va < w[1].va));
        let ordered = ordered && self.pages.last().is_none_or(|p| p.va < fresh[0].va);
        self.pages.append(&mut fresh);
        if !ordered {
            self.pages.sort_unstable_by_key(|p| p.va);
        }
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
        self.collect_pending()?;
        let end = end_of(start, count)?;
        check_flags(flags)?;
        self.check_mapping_limit(start, end, false, Self::chargeable(kind, false, flags))?;
        if start < USER_STACK_BOTTOM && end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        if self.overlaps(start, count)? {
            return Err(MapError::Overlap);
        }
        reserve(&mut self.areas, 1)?;
        reserve(&mut self.pages, count)?;
        let mut fresh: Vec<Page> = Vec::new();
        reserve(&mut fresh, count)?;
        for va in (start..end).step_by(PAGE_SIZE) {
            let frame = match FrameRef::new() {
                Ok(frame) => frame,
                Err(e) => {
                    for page in &fresh {
                        self.pt.borrow_mut().unmap(page.va);
                    }
                    return Err(MapError::from(e));
                }
            };
            let mapped = self.pt.borrow_mut().map(va, frame.addr(), flags);
            if let Err(e) = mapped {
                for page in &fresh {
                    self.pt.borrow_mut().unmap(page.va);
                }
                return Err(e.into());
            }
            fresh.push(Page::new(va, Backing::Private(frame)));
        }
        let ordered = self.pages.last().is_none_or(|p| p.va < start);
        self.append_pages(fresh, ordered);
        self.areas.push(VmArea {
            start,
            end,
            flags,
            kind,
            locked: self.lock_future,
            onfault: self.lock_future && self.lock_onfault,
            shared_file: false,
            no_fork: false,
            wipe_on_fork: false,
        });
        self.coalesce();
        Ok(())
    }
    /// ELF 加载器单页入口；重复映射拒绝，不覆盖旧数据。
    pub fn map_alloc(&mut self, va: usize, flags: MappingFlags) -> Result<PhysAddr, MapError> {
        self.map_region(va, 1, flags, AreaKind::Elf)?;
        self.page_at(va)
            .and_then(|p| p.addr())
            .ok_or(MapError::NotMapped)
    }
    /// 向已分配的 ELF 私有页写入初始内容；只接受页内区间，不检查用户写权限。
    pub fn init_elf_page(&mut self, va: usize, data: &[u8]) -> Result<(), MapError> {
        let page_va = va / PAGE_SIZE * PAGE_SIZE;
        if !self
            .area_at(page_va)
            .is_some_and(|a| a.kind == AreaKind::Elf)
        {
            return Err(MapError::NotMapped);
        }
        let page = self.page_at(page_va).ok_or(MapError::NotMapped)?;
        match &*page.backing() {
            Backing::Private(frame) => frame
                .write(va - page_va, data)
                .map_err(|_| MapError::OutOfUserRange),
            Backing::File(_) | Backing::AnonymousShared(_) => Err(MapError::PermissionDenied),
        }
    }
    /// 初始栈请求 RW；当前不支持 NX，实际为 RWX，保护页不分配。
    pub fn map_stack(&mut self) -> Result<(), MapError> {
        let bytes = self.limits[1][0].min(USER_TOP - USER_STACK_BOTTOM) / PAGE_SIZE * PAGE_SIZE;
        if bytes == 0 {
            return Err(MapError::OutOfMemory);
        }
        self.reserve_region(
            USER_TOP - bytes,
            bytes / PAGE_SIZE,
            MappingFlags::URW,
            AreaKind::Stack,
        )
    }
    /// 预生成区间拆分结果。None 表示删除；Some 表示覆盖权限。
    fn split(
        &self,
        start: usize,
        end: usize,
        flags: Option<MappingFlags>,
    ) -> Result<Vec<VmArea>, MapError> {
        let mut result = Vec::new();
        let capacity = if flags.is_some() {
            self.areas.len().checked_mul(3)
        } else {
            self.areas.len().checked_add(1)
        };
        reserve(&mut result, capacity.ok_or(MapError::OutOfMemory)?)?;
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
        self.collect_pending()?;
        let end = end_of_unmap(start, count)?;
        let next = self.split(start, end, None)?;
        for p in &self.pages {
            if start <= p.va && p.va < end {
                self.pt.borrow_mut().unmap(p.va);
            }
        }
        self.pages.retain(|p| p.va < start || p.va >= end);
        self.areas = next;
        self.coalesce();
        Ok(())
    }
    /// 先验证整段映射及后备写权限，再更新 VMA 和驻留页。U 表示 PROT_NONE。
    /// VMA 保留请求权限供缺页与限额检查使用；页表为可访问页保留实际执行权限。
    pub fn protect(
        &mut self,
        start: usize,
        count: usize,
        flags: MappingFlags,
    ) -> Result<(), MapError> {
        self.collect_pending()?;
        let end = end_of(start, count)?;
        check_flags(flags)?;
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
                p.va >= start && p.va < end && matches!(&*p.backing(), Backing::File(f) if f.mode == (Mode::Shared { writable: false }))
            })
        {
            return Err(MapError::PermissionDenied);
        }
        let next = self.split(start, end, Some(flags))?;
        self.check_data_layout(&next)?;
        for p in &self.pages {
            if start <= p.va && p.va < end {
                if let Some(pa) = p.addr() {
                    self.pt.borrow_mut().protect(p.va, pa, p.leaf_flags(flags));
                }
            }
        }
        self.areas = next;
        self.coalesce();
        Ok(())
    }
    fn same_backing_at(&self, boundary: usize) -> bool {
        let (Some(left), Some(right)) =
            (self.page_at(boundary - PAGE_SIZE), self.page_at(boundary))
        else {
            return false;
        };
        let left = left.backing();
        let right = right.backing();
        match (&*left, &*right) {
            (Backing::File(a), Backing::File(b)) => a.immediately_before(b),
            (Backing::AnonymousShared(a), Backing::AnonymousShared(b)) => a.immediately_before(b),
            _ => false,
        }
    }
    fn coalesce(&mut self) {
        self.areas.sort_unstable_by_key(|a| a.start);
        let mut i = 1;
        while i < self.areas.len() {
            let (a, b) = (self.areas[i - 1], self.areas[i]);
            if a.end == b.start
                && a.flags == b.flags
                && a.kind == b.kind
                && a.no_fork == b.no_fork
                && a.wipe_on_fork == b.wipe_on_fork
                && a.locked == b.locked
                && a.onfault == b.onfault
                && (!matches!(a.kind, AreaKind::File | AreaKind::SharedAnonymous)
                    || self.same_backing_at(b.start))
            {
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
        if (va >> 30) & 511 == super::kstack::WINDOW_ROOT_INDEX {
            return None;
        }
        self.pt.borrow_mut().translate(va)
    }
    /// ELF 段不能侵入固定栈和保护区。
    pub fn check_user_span(start: usize, len: usize) -> Result<(), MapError> {
        let end = start.checked_add(len).ok_or(MapError::OutOfUserRange)?;
        if end > GUARD_BOTTOM {
            return Err(MapError::HitsStack);
        }
        if len != 0
            && start < super::kstack::WINDOW_ROOT_END
            && end > super::kstack::WINDOW_ROOT_START
        {
            return Err(MapError::OutOfUserRange);
        }
        Ok(())
    }
    /// 切换页表并刷新本核 TLB。调用方当前使用内核栈，用户空间只在本核运行。
    pub fn activate(&self) {
        self.refresh_files();
        self.pt.borrow_mut().activate();
    }
    /// 恢复创建时的页表；销毁前必须停用。
    pub fn deactivate(&self) {
        self.pt.borrow_mut().deactivate();
    }
}
impl Drop for UserAddressSpace {
    fn drop(&mut self) {
        for att in self.shm_attachments.drain(..) {
            super::shm::detach(att.shmid, 0);
        }
        // 先停用，再释放数据页/页表；不依赖调用方记住每个错误返回点。
        if self.pt.borrow_mut().is_active() {
            self.pt.borrow_mut().deactivate();
        }
        // 按去重后的 inode 批量压缩 RESIDENT 弱引用表。
        let mut dirty_inos = [0u32; 32];
        let mut dirty_len = 0usize;
        let mut record_ino = |ino: u32| {
            if dirty_inos[..dirty_len].contains(&ino) {
                return;
            }
            if dirty_len == dirty_inos.len() {
                file::compact_inos(&dirty_inos[..dirty_len]);
                dirty_len = 0;
            }
            dirty_inos[dirty_len] = ino;
            dirty_len += 1;
        };
        for page in &self.pages {
            if let Backing::File(f) = &*page.frame.borrow() {
                if let Some(ino) = f.release_deferred() {
                    record_ino(ino);
                }
            }
        }
        for page in self.pending.get_mut().iter() {
            if let Backing::File(f) = &*page.frame.borrow() {
                if let Some(ino) = f.release_deferred() {
                    record_ino(ino);
                }
            }
        }
        file::compact_inos(&dirty_inos[..dirty_len]);
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
