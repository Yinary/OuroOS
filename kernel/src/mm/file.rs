//! 文件映射持有 inode 和文件偏移。驻留页按需读入，截断使同一 inode 的所有旧页失效。
#![forbid(unsafe_code)]

use super::{address_space::MapError, frame::OwnedFrame};
use crate::{fs, syscall::Errno};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use polyhal::{pagetable::PAGE_SIZE, PhysAddr};
use spin::Mutex;

/// 按 inode 分组的驻留页弱引用，截断只扫描目标 inode。
struct InodeResidents {
    ino: u32,
    pages: Vec<Weak<Resident>>,
    next_clean: usize,
}
static RESIDENT: Mutex<Vec<InodeResidents>> = Mutex::new(Vec::new());
static TRUNCATIONS: AtomicUsize = AtomicUsize::new(0);

/// 截断序号用于跳过没有失效通知的地址空间扫描。
pub(super) fn truncations() -> usize {
    TRUNCATIONS.load(Ordering::Relaxed)
}

/// 后端改变长度后撤销截掉的驻留页；私有尾页保留有效前缀，新暴露的字节清零。
pub(crate) fn resized(ino: u32, old: usize, length: usize) {
    let mut groups = RESIDENT.lock();
    if let Ok(index) = groups.binary_search_by_key(&ino, |group| group.ino) {
        let group = &mut groups[index];
        group.pages.retain(|p| p.strong_count() != 0);
        for page in group.pages.iter().filter_map(Weak::upgrade) {
            if length < old && page.offset >= length {
                page.invalid.store(true, Ordering::Relaxed);
            } else if let Data::Shared(shared) = &page.data {
                if !shared.is_valid() {
                    page.invalid.store(true, Ordering::Relaxed);
                }
            } else if let Data::Private(frame) = &page.data {
                if length < old {
                    frame.clear_range(length - page.offset, PAGE_SIZE);
                } else {
                    frame.clear_range(
                        old.saturating_sub(page.offset),
                        length.saturating_sub(page.offset).min(PAGE_SIZE),
                    );
                }
            }
        }
    }
    if length < old {
        TRUNCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

/// 截断前校验；当前失效路径不分配，因此只需确认目标 inode 可处理。
pub(crate) fn prepare_resize(_ino: u32, _old: usize, _new: usize) -> Result<(), Errno> {
    Ok(())
}

struct MappingHooks;

impl fs::mapping::Hooks for MappingHooks {
    fn prepare_resize(&self, ino: u32, old: u64, new: u64) -> Result<(), Errno> {
        prepare_resize(ino, old as usize, new as usize)
    }

    fn commit_resize(&self, ino: u32, old: u64, new: u64) {
        resized(ino, old as usize, new as usize);
    }
}

static MAPPING_HOOKS: MappingHooks = MappingHooks;

/// 在 mm 初始化时注册；FS 未注册时仍按保守的 ENOTSUP 处理。
pub(super) fn install_hooks() {
    fs::mapping::register(&MAPPING_HOOKS);
}

/// 清理目标 inode 的空登记组，避免每次解除映射都扫描全部 inode。
pub(crate) fn compact_ino(ino: u32) {
    compact_inos(&[ino]);
}

/// 批量清理一组 inode 在 `RESIDENT` 中的失效弱引用。
pub(crate) fn compact_inos(inos: &[u32]) {
    if inos.is_empty() {
        return;
    }
    let mut groups = RESIDENT.lock();
    for &ino in inos {
        if let Ok(index) = groups.binary_search_by_key(&ino, |group| group.ino) {
            let group = &mut groups[index];
            group.pages.retain(|p| p.strong_count() != 0);
            if group.pages.is_empty() {
                groups.remove(index);
            }
        }
    }
}

/// 与打开描述符无关的 inode 引用。
pub(crate) struct MappingFile {
    ino: u32,
    writable_shared: bool,
}
impl MappingFile {
    /// 为文件映射建立 inode 引用句柄，并记录共享可写状态。
    pub(crate) fn new_for_map(ino: u32, writable_shared: bool) -> Result<Arc<Self>, Errno> {
        fs::retain(ino)?;
        if writable_shared && fs::memfd::is_memfd_ino(ino) {
            fs::memfd::inc_writable_map(ino);
        }
        match fs::try_arc(Self {
            ino,
            writable_shared,
        }) {
            Ok(arc) => Ok(arc),
            Err(e) => {
                if writable_shared && fs::memfd::is_memfd_ino(ino) {
                    fs::memfd::dec_writable_map(ino);
                }
                fs::release(ino);
                Err(e)
            }
        }
    }
}
impl Drop for MappingFile {
    fn drop(&mut self) {
        if self.writable_shared && fs::memfd::is_memfd_ino(self.ino) {
            fs::memfd::dec_writable_map(self.ino);
        }
        fs::release(self.ino);
    }
}

enum Data {
    Private(OwnedFrame),
    Shared(Arc<fs::cache::SharedPage>),
}
impl Data {
    fn addr(&self) -> PhysAddr {
        match self {
            Self::Private(p) => p.addr(),
            Self::Shared(p) => p.addr(),
        }
    }
}

struct Resident {
    offset: usize,
    data: Data,
    invalid: AtomicBool,
}

impl Resident {
    fn register(ino: u32, offset: usize, data: Data) -> Result<Arc<Self>, MapError> {
        let mut groups = RESIDENT.lock();
        let index = match groups.binary_search_by_key(&ino, |group| group.ino) {
            Ok(index) => index,
            Err(index) => {
                groups.try_reserve(1).map_err(|_| MapError::OutOfMemory)?;
                groups.insert(
                    index,
                    InodeResidents {
                        ino,
                        pages: Vec::new(),
                        next_clean: 64,
                    },
                );
                index
            }
        };
        let group = &mut groups[index];
        if group.pages.len() >= group.next_clean {
            group.pages.retain(|p| p.strong_count() != 0);
            group.next_clean = group.pages.len().saturating_mul(2).max(64);
        }
        group
            .pages
            .try_reserve(1)
            .map_err(|_| MapError::OutOfMemory)?;
        let page = Arc::try_new(Self {
            offset,
            data,
            invalid: AtomicBool::new(false),
        })
        .map_err(|_| MapError::OutOfMemory)?;
        group.pages.push(Arc::downgrade(&page));
        Ok(page)
    }
}

/// 私有、只读共享与可写共享映射保留打开时的权限。
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Private,
    Shared { writable: bool },
}

/// 虚拟文件页保留后备身份，包括当前位于 EOF 之后的页。
pub(crate) struct FilePage {
    file: Arc<MappingFile>,
    offset: usize,
    pub(super) mode: Mode,
    data: RefCell<Option<Arc<Resident>>>,
}
impl FilePage {
    /// 构造指向指定文件偏移与映射模式的页描述。
    pub(crate) fn new(file: Arc<MappingFile>, offset: usize, mode: Mode) -> Self {
        Self {
            file,
            offset,
            mode,
            data: RefCell::new(None),
        }
    }
    pub(super) fn identity(&self) -> (u32, usize) {
        (self.file.ino, self.offset)
    }

    pub(super) fn immediately_before(&self, next: &Self) -> bool {
        Arc::ptr_eq(&self.file, &next.file)
            && self.mode == next.mode
            && self.offset.checked_add(PAGE_SIZE) == Some(next.offset)
    }
    pub(super) fn following(&self, distance: usize) -> Result<Self, MapError> {
        let offset = self
            .offset
            .checked_add(distance)
            .filter(|n| *n <= i64::MAX as usize)
            .ok_or(MapError::OutOfUserRange)?;
        Ok(Self::new(self.file.clone(), offset, self.mode))
    }
    pub(super) fn stale(&self) -> bool {
        self.data.borrow().as_ref().is_some_and(|p| {
            p.invalid.load(Ordering::Relaxed)
                || matches!(&p.data, Data::Shared(page) if !page.is_valid())
        })
    }
    /// 释放驻留页引用并回收空闲共享页，返回待压缩的 inode 号。
    pub(super) fn release_deferred(&self) -> Option<u32> {
        self.data.borrow_mut().take()?;
        let ino = self.file.ino;
        if matches!(self.mode, Mode::Shared { .. }) {
            crate::fs::cache::release_idle(ino, self.offset);
        }
        Some(ino)
    }
    pub(super) fn discard(&self) {
        if let Some(ino) = self.release_deferred() {
            compact_ino(ino);
        }
    }
    pub(super) fn addr(&self) -> Option<PhysAddr> {
        self.data.borrow().as_ref().map(|p| p.data.addr())
    }
    /// mincore 同时观察此映射和同一文件偏移的共享缓存，不安装页表项。
    pub(super) fn resident(&self) -> bool {
        self.addr().is_some() || fs::cache::resident(self.file.ino, self.offset)
    }
    pub(super) fn fault(&self) -> Result<PhysAddr, MapError> {
        let length = fs::stat(self.file.ino).map_err(map_io)?.1;
        if self.offset as u64 >= length {
            return Err(MapError::FileFault);
        }
        let data = match self.mode {
            Mode::Private => {
                let mut frame = OwnedFrame::new()?;
                let count = (length - self.offset as u64).min(PAGE_SIZE as u64) as usize;
                let mut i = 0;
                while i < count {
                    let n = frame.fill_range_with(i, count - i, |dst| {
                        fs::read(self.file.ino, self.offset + i, dst).map_err(map_io)
                    })?;
                    if n == 0 {
                        return Err(MapError::FileIo);
                    }
                    i += n;
                }
                Data::Private(frame)
            }
            Mode::Shared { .. } => {
                Data::Shared(fs::cache::page(self.file.ino, self.offset).map_err(map_io)?)
            }
        };
        let pa = data.addr();
        *self.data.borrow_mut() = Some(Resident::register(self.file.ino, self.offset, data)?);
        Ok(pa)
    }
    /// 私有文件驻留页正由多个地址空间共享，写入前须执行写时复制。
    pub(super) fn is_cow_shared(&self) -> bool {
        self.mode == Mode::Private
            && self
                .data
                .borrow()
                .as_ref()
                .is_some_and(|r| Arc::strong_count(r) > 1)
    }
    /// 为写时复制分配独占私有页副本并替换当前驻留项，返回新物理页地址。
    pub(super) fn split_private(&self) -> Result<PhysAddr, MapError> {
        let copy = {
            let cur = self.data.borrow();
            let Some(resident) = cur.as_ref() else {
                return Err(MapError::NotMapped);
            };
            let Data::Private(src) = &resident.data else {
                return Err(MapError::PermissionDenied);
            };
            let frame = OwnedFrame::new()?;
            frame.copy_from(src);
            Resident::register(self.file.ino, self.offset, Data::Private(frame))?
        };
        let pa = copy.data.addr();
        *self.data.borrow_mut() = Some(copy);
        Ok(pa)
    }
    pub(super) fn fork(&self) -> Result<Self, MapError> {
        let child = Self::new(self.file.clone(), self.offset, self.mode);
        if let Some(parent) = self.data.borrow().as_ref() {
            // 私有与共享驻留页均直接共享 Arc；私有页在首次写入时由 split_private 拆分。
            *child.data.borrow_mut() = Some(parent.clone());
        }
        Ok(child)
    }
    /// 同步入口不区分共享映射是否可写；只读映射也要让后端决定错误。
    pub(super) fn writeback_start(&self) -> Option<(u32, usize)> {
        match self.mode {
            // 可写后端的同一缓存页也可能由另一个映射修改。
            Mode::Shared { writable } if writable || !cfg!(feature = "rsext4-readonly") => {
                Some((self.file.ino, self.offset))
            }
            _ => None,
        }
    }
}
impl Drop for FilePage {
    fn drop(&mut self) {
        // 释放残留共享页并清理 RESIDENT 登记。
        self.discard();
    }
}
fn map_io(error: Errno) -> MapError {
    if error == Errno::NoMem {
        MapError::OutOfMemory
    } else {
        MapError::FileIo
    }
}
