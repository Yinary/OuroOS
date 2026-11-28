//! 文件共享页缓存；缓存持有强引用，最后一个映射释放后仍可重试写回。
#![deny(unsafe_code)]
use crate::{mm::frame::OwnedFrame, syscall::Errno};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use polyhal::PhysAddr;
use spin::Mutex;

static PAGES: Mutex<Vec<(u32, usize, Arc<SharedPage>)>> = Mutex::new(Vec::new());
/// `PAGES` 向量当前条目数，用于无 mmap 共享页时零锁跳过读写一致性检查。
static PAGE_ENTRIES: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn sync_entries_count(pages: &[(u32, usize, Arc<SharedPage>)]) {
    PAGE_ENTRIES.store(pages.len(), Ordering::Release);
}

/// 是否有存活共享页；调用方保证单核非抢占的检查与截断顺序。
pub(super) fn has_live(ino: u32) -> bool {
    PAGES
        .lock()
        .iter()
        .any(|(id, _, page)| *id == ino && page.is_valid())
}

/// 查询同一 inode/offset 是否已有驻留共享页；不触发读取/分配。
pub fn resident(ino: u32, offset: usize) -> bool {
    PAGES
        .lock()
        .iter()
        .any(|(id, off, page)| *id == ino && *off == offset && page.is_valid())
}

/// 当前驻留共享页的 KiB 数（按 4 KiB 页计）。
pub(super) fn cached_kib() -> usize {
    PAGES.lock().iter().filter(|(_, _, p)| p.is_valid()).count() * 4
}

/// 一页共享文件内容，缓存持有强引用，最后一个映射释放后仍可重试。
pub struct SharedPage {
    frame: OwnedFrame,
    ino: u32,
    offset: usize,
    retained: bool,
    valid: AtomicBool,
    clean: AtomicBool,
}
impl SharedPage {
    /// 页表映射使用的物理地址；所有权仍由缓存和映射共同持有。
    pub fn addr(&self) -> PhysAddr {
        self.frame.addr()
    }
    fn load(&self, offset: usize, out: &mut [u8]) -> Result<(), Errno> {
        self.frame.read(offset, out).map_err(|_| Errno::Invalid)
    }
    fn store(&self, offset: usize, data: &[u8]) -> Result<(), Errno> {
        self.frame.write(offset, data).map_err(|_| Errno::Invalid)
    }

    /// 只在内容与后端不同时写回，避免只读稀疏页把空洞变成实块。
    fn write_back(&self) -> Result<(), Errno> {
        if !self.is_valid() {
            return Ok(());
        }
        let len = super::stat(self.ino)?.1 as usize;
        let count = len.saturating_sub(self.offset).min(4096);
        if count == 0 {
            self.mark_clean();
            return Ok(());
        }
        let mut page = [0u8; 256];
        let mut disk = [0u8; 256];
        let mut differs = false;
        let mut done = 0;
        while done < count {
            let k = (count - done).min(page.len());
            self.load(done, &mut page[..k])?;
            disk[..k].fill(0);
            let n = super::read_raw(self.ino, self.offset + done, &mut disk[..k])?;
            if n > k {
                return Err(Errno::Io);
            }
            if page[..k] != disk[..k] {
                differs = true;
                break;
            }
            done += k;
        }
        if !differs {
            self.mark_clean();
            return Ok(());
        }
        let mut done = 0;
        while done < count {
            let k = (count - done).min(page.len());
            self.load(done, &mut page[..k])?;
            if super::write_raw(self.ino, self.offset + done, &page[..k])? != k {
                return Err(Errno::Io);
            }
            done += k;
        }
        self.mark_clean();
        Ok(())
    }

    /// 返回缓存页是否仍有效（未被截断作废）。
    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }

    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
    }

    fn mark_clean(&self) {
        self.clean.store(true, Ordering::Release);
    }

    fn zero(&self, offset: usize, count: usize) {
        let zeros = [0u8; 256];
        let mut done = 0;
        while done < count {
            let k = (count - done).min(zeros.len());
            if let Err(e) = self.store(offset + done, &zeros[..k]) {
                log::error!("shared page zero failed: {:?}", e);
                return;
            }
            done += k;
        }
    }
}
impl Drop for SharedPage {
    fn drop(&mut self) {
        if !self.retained {
            return;
        }
        if self.is_valid() && !self.clean.load(Ordering::Acquire) {
            if let Err(e) = self.write_back() {
                log::error!("shared page writeback failed: {:?}", e);
            }
        }
        super::release(self.ino);
    }
}

/// 文件长度变化后调整共享页：整页越过新 EOF 的失效，保留页清零新暴露/截掉区间。
pub(crate) fn resize_inode(ino: u32, old: usize, new: usize) {
    if PAGE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let mut pages = PAGES.lock();
    for (id, off, page) in pages.iter() {
        if *id != ino {
            continue;
        }
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
    pages.retain(|(id, off, page)| *id != ino || (*off < new && page.is_valid()));
    sync_entries_count(&pages);
}

/// 截断前使某 inode 的旧共享页失效，后续不再写回；索引立即移除。
#[allow(dead_code)] // 保留全量失效入口
pub(crate) fn invalidate_inode(ino: u32) {
    let mut pages = PAGES.lock();
    for (id, _, page) in pages.iter() {
        if *id == ino {
            page.invalidate();
        }
    }
    pages.retain(|(id, _, _)| *id != ino);
    sync_entries_count(&pages);
}

/// 写回指定文件偏移范围内的驻留共享页；无外部映射时成功后可回收。
#[cfg(not(feature = "rsext4-readonly"))]
pub(crate) fn sync_span(ino: u32, offset: usize, length: usize) -> Result<(), Errno> {
    let end = offset.checked_add(length).ok_or(Errno::Invalid)?;
    let mut pages = PAGES.lock();
    for (id, off, page) in pages.iter() {
        if *id == ino && *off >= offset && *off < end && page.is_valid() {
            page.write_back()?;
            if Arc::strong_count(page) == 1 {
                page.mark_clean();
            }
        }
    }
    pages.retain(|(id, off, page)| {
        *id != ino || *off < offset || *off >= end || Arc::strong_count(page) != 1
    });
    sync_entries_count(&pages);
    Ok(())
}

/// 将指定 inode 的驻留共享页写回文件后端。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn sync_inode(ino: u32) -> Result<(), Errno> {
    let mut pages = PAGES.lock();
    for (id, _, page) in pages.iter() {
        if *id == ino && page.is_valid() {
            page.write_back()?;
            if Arc::strong_count(page) == 1 {
                page.mark_clean();
            }
        }
    }
    pages.retain(|(id, _, page)| *id != ino || Arc::strong_count(page) != 1);
    sync_entries_count(&pages);
    Ok(())
}

/// 将所有仍被缓存持有的页写回；失败时保留页，供后续重试。
pub(crate) fn flush(ino: Option<u32>) -> Result<(), Errno> {
    let mut pages = PAGES.lock();
    let mut first_error = None;
    for (id, _, page) in pages.iter() {
        if ino.is_some_and(|want| *id != want) || !page.is_valid() {
            continue;
        }
        page.clean.store(false, Ordering::Release);
        match page.write_back() {
            Ok(()) if Arc::strong_count(page) == 1 => page.mark_clean(),
            Ok(()) => {}
            Err(e) => {
                first_error.get_or_insert(e);
            }
        }
    }
    pages.retain(|(id, _, page)| {
        ino.is_some_and(|want| *id != want)
            || Arc::strong_count(page) != 1
            || !page.clean.load(Ordering::Acquire)
    });
    sync_entries_count(&pages);
    first_error.map_or(Ok(()), Err)
}

/// 没有外部映射时尝试写回并回收；失败则保留页供 flush 重试。
pub(crate) fn release_idle(ino: u32, offset: usize) {
    let mut pages = PAGES.lock();
    let Some(index) = pages
        .iter()
        .position(|(id, off, page)| *id == ino && *off == offset && page.is_valid())
    else {
        return;
    };
    if Arc::strong_count(&pages[index].2) != 1 {
        return;
    }
    if pages[index].2.write_back().is_ok() {
        pages[index].2.mark_clean();
        pages.swap_remove(index);
        sync_entries_count(&pages);
    }
}

/// 仍被缓存持有的页帧数（任务退出帧守恒自检用）。
pub(crate) fn retained_frames() -> usize {
    PAGES.lock().iter().filter(|(_, _, p)| p.is_valid()).count()
}

/// 取得同一 inode/offset 的唯一共享页。
pub fn page(ino: u32, offset: usize) -> Result<Arc<SharedPage>, Errno> {
    let mut pages = PAGES.lock();
    if let Some(page) = pages
        .iter()
        .find(|(i, o, p)| *i == ino && *o == offset && p.is_valid())
        .map(|(_, _, p)| p.clone())
    {
        return Ok(page);
    }
    pages.retain(|(_, _, p)| p.is_valid());
    pages.try_reserve(1).map_err(|_| Errno::NoMem)?;
    let frame = OwnedFrame::new().map_err(|_| Errno::NoMem)?;
    let mut data = [0u8; 256];
    let mut page = crate::fs::try_arc(SharedPage {
        frame,
        ino,
        offset,
        retained: false,
        valid: AtomicBool::new(true),
        clean: AtomicBool::new(false),
    })?;
    let mut done = 0;
    while done < 4096 {
        let k = (4096 - done).min(data.len());
        data[..k].fill(0);
        let n = super::read_raw(ino, offset + done, &mut data[..k])?;
        if n > k {
            return Err(Errno::Io);
        }
        page.store(done, &data[..k])?;
        done += k;
        if n < k {
            break;
        }
    }
    super::retain(ino)?;
    let page_ref = Arc::get_mut(&mut page).ok_or(Errno::Io)?;
    page_ref.retained = true;
    let cached = page.clone();
    pages.push((ino, offset, page));
    sync_entries_count(&pages);
    Ok(cached)
}

/// 文件 read 覆盖共享页中的最新内容，write 同步更新已有映射。
pub fn coherent(ino: u32, offset: usize, data: &mut [u8], write: bool) {
    if PAGE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(request_end) = offset.checked_add(data.len()) else {
        return;
    };
    let pages = PAGES.lock();
    for (id, start, page) in pages.iter() {
        if *id != ino || !page.is_valid() {
            continue;
        }
        let begin = offset.max(*start);
        let end = request_end.min(*start + 4096);
        if begin >= end {
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
        if write {
            page.clean.store(false, Ordering::Release);
        }
    }
}

/// 文件 write 同步更新已有共享页；接收只读切片，避免额外暂存复制。
pub(crate) fn coherent_write(ino: u32, offset: usize, data: &[u8]) {
    if PAGE_ENTRIES.load(Ordering::Acquire) == 0 {
        return;
    }
    let Some(request_end) = offset.checked_add(data.len()) else {
        return;
    };
    let pages = PAGES.lock();
    for (id, start, page) in pages.iter() {
        if *id != ino || !page.is_valid() {
            continue;
        }
        let begin = offset.max(*start);
        let end = request_end.min(*start + 4096);
        if begin >= end {
            continue;
        }
        if let Err(e) = page.store(begin - *start, &data[begin - offset..end - offset]) {
            log::error!("shared page coherence failed: {:?}", e);
        }
        page.clean.store(false, Ordering::Release);
    }
}
