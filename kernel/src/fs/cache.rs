//! 文件共享页缓存；映射持有强引用，索引只持弱引用。
#![deny(unsafe_code)]
use crate::{mm::frame::OwnedFrame, syscall::Errno};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};
use polyhal::PhysAddr;
use spin::Mutex;

static PAGES: Mutex<Vec<(u32, usize, Weak<SharedPage>)>> = Mutex::new(Vec::new());

/// 是否有存活共享页；调用方保证单核非抢占的检查与截断顺序。
pub(super) fn has_live(ino: u32) -> bool {
    PAGES
        .lock()
        .iter()
        .any(|(id, _, page)| *id == ino && page.strong_count() != 0)
}

/// 查询同一 inode/offset 是否已有驻留共享页；不触发读取/分配。
#[allow(dead_code)] // MM 的 mincore 在后续 PR 接入
pub fn resident(ino: u32, offset: usize) -> bool {
    PAGES.lock().iter().any(|(id, off, page)| {
        *id == ino
            && *off == offset
            && page
                .upgrade()
                .is_some_and(|page| page.valid.load(Ordering::Acquire))
    })
}

/// 当前驻留共享页的 KiB 数（按 4 KiB 页计）。
pub(super) fn cached_kib() -> usize {
    PAGES
        .lock()
        .iter()
        .filter(|(_, _, page)| {
            page.upgrade()
                .is_some_and(|page| page.valid.load(Ordering::Acquire))
        })
        .count()
        * 4
}

/// 一页共享文件内容，最后一个映射释放时写回。
pub struct SharedPage {
    frame: OwnedFrame,
    ino: u32,
    offset: usize,
    retained: bool,
    valid: AtomicBool,
}
impl SharedPage {
    /// 页表映射使用的物理地址；所有权仍由 Arc 管理。
    pub fn addr(&self) -> PhysAddr {
        self.frame.addr()
    }
    fn load(&self, offset: usize, out: &mut [u8]) -> Result<(), Errno> {
        self.frame.read(offset, out).map_err(|_| Errno::Invalid)
    }
    fn store(&self, offset: usize, data: &[u8]) -> Result<(), Errno> {
        self.frame.write(offset, data).map_err(|_| Errno::Invalid)
    }

    fn write_back(&self) -> Result<(), Errno> {
        if !self.valid.load(Ordering::Acquire) {
            return Ok(());
        }
        let len = super::stat(self.ino)?.1 as usize;
        let count = len.saturating_sub(self.offset).min(4096);
        if count != 0 {
            let mut data = [0; 4096];
            self.load(0, &mut data[..count])?;
            if super::write_raw(self.ino, self.offset, &data[..count])? != count {
                return Err(Errno::Io);
            }
        }
        Ok(())
    }

    /// 该页是否仍可写回；截断越过 EOF 后为 false。
    #[allow(dead_code)] // MM 的 stale 检查在后续 PR 接入
    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }

    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
    }

    fn zero(&self, offset: usize, count: usize) {
        let zeros = [0u8; 4096];
        if let Err(e) = self.store(offset, &zeros[..count]) {
            log::error!("shared page zero failed: {:?}", e);
        }
    }
}
impl Drop for SharedPage {
    fn drop(&mut self) {
        if !self.retained {
            return;
        }
        if self.valid.load(Ordering::Acquire) {
            if let Err(e) = self.write_back() {
                log::error!("shared page writeback failed: {:?}", e);
            }
        }
        super::release(self.ino);
    }
}

/// 文件长度变化后调整共享页：整页越过新 EOF 的失效，保留页清零新暴露/截掉区间。
pub(crate) fn resize_inode(ino: u32, old: usize, new: usize) {
    let mut pages = PAGES.lock();
    for (id, off, page) in pages.iter() {
        if *id != ino {
            continue;
        }
        let Some(page) = page.upgrade() else {
            continue;
        };
        if new <= *off {
            page.invalidate();
            continue;
        }
        if new > old {
            let begin = old.max(*off);
            let stop = new.min(*off + 4096);
            if begin < stop {
                page.zero(begin - *off, stop - begin);
            }
        }
        if new < old {
            let begin = new.max(*off);
            let stop = old.min(*off + 4096);
            if begin < stop {
                page.zero(begin - *off, stop - begin);
            }
        }
    }
    pages.retain(|(id, off, page)| *id != ino || (*off < new && page.strong_count() != 0));
}

/// 写回指定文件偏移范围内的驻留共享页。
#[cfg(not(feature = "rsext4-readonly"))]
#[allow(dead_code)] // MM msync 在后续 PR 接入
pub(crate) fn sync_span(ino: u32, offset: usize, length: usize) -> Result<(), Errno> {
    let end = offset.checked_add(length).ok_or(Errno::Invalid)?;
    for (id, off, page) in PAGES.lock().iter() {
        if *id != ino || *off < offset || *off >= end {
            continue;
        }
        if let Some(page) = page.upgrade() {
            if page.is_valid() {
                page.write_back()?;
            }
        }
    }
    Ok(())
}

/// 仅使文件偏移范围内相交的共享页失效；范围外的页保持原状。
#[allow(dead_code)] // MM msync 在后续 PR 接入
pub(crate) fn invalidate_range(ino: u32, offset: usize, length: usize) -> Result<(), Errno> {
    let end = offset.checked_add(length).ok_or(Errno::Invalid)?;
    let mut pages = PAGES.lock();
    for (id, off, page) in pages.iter() {
        if *id == ino && *off < end && offset < *off + 4096 {
            if let Some(page) = page.upgrade() {
                page.invalidate();
            }
        }
    }
    pages.retain(|(id, off, _)| *id != ino || *off >= end || *off + 4096 <= offset);
    Ok(())
}

/// 截断前使某 inode 的旧共享页失效，后续不再写回；索引立即移除。
#[allow(dead_code)] // msync/后续范围失效入口
pub(crate) fn invalidate_inode(ino: u32) {
    let mut pages = PAGES.lock();
    for (id, _, page) in pages.iter() {
        if *id == ino {
            if let Some(page) = page.upgrade() {
                page.invalidate();
            }
        }
    }
    pages.retain(|(id, _, _)| *id != ino);
}

/// 将指定 inode 的驻留共享页写回文件后端。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn sync_inode(ino: u32) -> Result<(), Errno> {
    for (_, _, page) in PAGES.lock().iter().filter(|(id, _, _)| *id == ino) {
        if let Some(page) = page.upgrade() {
            if page.valid.load(Ordering::Acquire) {
                page.write_back()?;
            }
        }
    }
    Ok(())
}

/// 取得同一 inode/offset 的唯一共享页。
pub fn page(ino: u32, offset: usize) -> Result<Arc<SharedPage>, Errno> {
    let mut pages = PAGES.lock();
    pages.retain(|(_, _, p)| p.strong_count() != 0);
    if let Some(p) = pages
        .iter()
        .find(|(i, o, _)| *i == ino && *o == offset)
        .and_then(|(_, _, p)| p.upgrade())
        .filter(|page| page.valid.load(Ordering::Acquire))
    {
        return Ok(p);
    }
    pages.try_reserve(1).map_err(|_| Errno::NoMem)?;
    let frame = OwnedFrame::new().map_err(|_| Errno::NoMem)?;
    let mut data = [0; 4096];
    super::read_raw(ino, offset, &mut data)?;
    let mut p = crate::fs::try_arc(SharedPage {
        frame,
        ino,
        offset,
        retained: false,
        valid: AtomicBool::new(true),
    })?;
    p.store(0, &data)?;
    let page = Arc::get_mut(&mut p).ok_or(Errno::Io)?;
    super::retain(ino)?;
    page.retained = true;
    pages.push((ino, offset, Arc::downgrade(&p)));
    Ok(p)
}

/// 文件 read 覆盖共享页中的最新内容，write 同步更新已有映射。
pub fn coherent(ino: u32, offset: usize, data: &mut [u8], write: bool) {
    let Some(request_end) = offset.checked_add(data.len()) else {
        return;
    };
    let pages = PAGES.lock();
    for (id, start, page) in pages.iter() {
        if *id != ino {
            continue;
        }
        let begin = offset.max(*start);
        let end = request_end.min(*start + 4096);
        if begin >= end {
            continue;
        }
        if let Some(page) = page.upgrade() {
            if !page.valid.load(Ordering::Acquire) {
                continue;
            }
            let result = if write {
                page.store(begin - *start, &data[begin - offset..end - offset])
            } else {
                page.load(begin - *start, &mut data[begin - offset..end - offset])
            };
            if let Err(e) = result {
                log::error!("shared page coherence failed: {:?}", e);
            }
        }
    }
}
