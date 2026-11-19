//! 共享文件页及其写回。索引持有缓存页，最后一个映射释放时尝试回收。
#![deny(unsafe_code)]
use super::try_arc;
use crate::{mm::frame::OwnedFrame, syscall::Errno};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use polyhal::{pagetable::PAGE_SIZE, PhysAddr};
use spin::Mutex;

static PAGES: Mutex<Vec<Arc<Entry>>> = Mutex::new(Vec::new());

struct Entry {
    ino: u32,
    offset: usize,
    frame: OwnedFrame,
    // 保存已被文件后端接受的内容，可识别经任意用户别名产生的修改。
    clean: OwnedFrame,
    valid: Mutex<usize>,
    retry: AtomicBool,
}

fn buffer(n: usize) -> Result<Vec<u8>, Errno> {
    let mut buf = Vec::new();
    buf.try_reserve_exact(n).map_err(|_| Errno::NoMem)?;
    buf.resize(n, 0);
    Ok(buf)
}

impl Entry {
    fn write_back(&self) -> Result<(), Errno> {
        let len = *self.valid.lock();
        let mut current = [0; 128];
        let mut baseline = [0; 128];
        for start in (0..len).step_by(current.len()) {
            let n = current.len().min(len - start);
            self.frame
                .read(start, &mut current[..n])
                .map_err(|_| Errno::Io)?;
            self.clean
                .read(start, &mut baseline[..n])
                .map_err(|_| Errno::Io)?;
            if self.retry.load(Ordering::Relaxed) || current[..n] != baseline[..n] {
                let mut bytes = buffer(len)?;
                self.frame.read(0, &mut bytes).map_err(|_| Errno::Io)?;
                self.retry.store(true, Ordering::Relaxed);
                if super::write_raw(self.ino, self.offset, &bytes)? != len {
                    return Err(Errno::Io);
                }
                self.retry.store(false, Ordering::Relaxed);
                self.clean.copy_from(&self.frame);
                break;
            }
        }
        Ok(())
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        super::release(self.ino);
    }
}

/// 一个用户映射对共享页的引用；内核缓存独立持有写回责任。
#[derive(Clone)]
pub struct SharedPage(Arc<Entry>);
impl SharedPage {
    /// 页表映射使用的物理地址。
    pub fn addr(&self) -> PhysAddr {
        self.0.frame.addr()
    }
}
impl Drop for SharedPage {
    fn drop(&mut self) {
        let mut pages = PAGES.lock();
        if Arc::strong_count(&self.0) == 2 {
            if let Some(i) = pages.iter().position(|p| Arc::ptr_eq(p, &self.0)) {
                match self.0.write_back() {
                    Ok(()) => {
                        pages.swap_remove(i);
                    }
                    Err(e) => log::error!(
                        "inode {} offset {}: writeback pending: {:?}",
                        self.0.ino,
                        self.0.offset,
                        e
                    ),
                }
            }
        }
    }
}

/// 同步指定 inode，成功后回收已无用户映射的缓存页。
pub(super) fn sync_inode(ino: u32) -> Result<(), Errno> {
    flush(Some(ino))
}

pub(crate) fn flush(ino: Option<u32>) -> Result<(), Errno> {
    flush_where(|p| ino.is_none() || ino == Some(p.ino))
}

pub(super) fn sync_span(ino: u32, offset: usize, length: usize) -> Result<(), Errno> {
    let end = offset.checked_add(length).ok_or(Errno::Invalid)?;
    flush_where(|p| p.ino == ino && offset <= p.offset && p.offset < end)
}

fn flush_where(select: impl Fn(&Entry) -> bool) -> Result<(), Errno> {
    let mut pages = PAGES.lock();
    let mut first_error = None;
    let mut i = 0;
    while i < pages.len() {
        let p = &pages[i];
        if select(p) {
            match p.write_back() {
                Ok(()) if Arc::strong_count(p) == 1 => {
                    pages.swap_remove(i);
                    continue;
                }
                Err(error) => {
                    first_error.get_or_insert(error);
                }
                _ => {}
            }
        }
        i += 1;
    }
    first_error.map_or(Ok(()), Err)
}

/// 返回文件缓存数据页大小，不包含用于脏数据比较的副本。
pub(super) fn cached_kib() -> usize {
    PAGES.lock().len() * (PAGE_SIZE / 1024)
}

/// 返回退出后缓存独占的物理帧数，供帧守恒检查使用。
pub(crate) fn retained_frames() -> usize {
    PAGES
        .lock()
        .iter()
        .filter(|p| Arc::strong_count(p) == 1)
        .count()
        * 2
}

/// 查询文件偏移对应的数据页是否已驻留。只读索引，不触发读盘或分配。
pub(crate) fn resident(ino: u32, offset: usize) -> bool {
    PAGES
        .lock()
        .iter()
        .any(|p| p.ino == ino && p.offset == offset)
}

/// 后端成功调整文件长度后更新有效字节。整页截掉后脱离索引，旧引用不能写回。
pub(super) fn resized(ino: u32, length: usize) {
    PAGES.lock().retain(|p| {
        if p.ino != ino {
            return true;
        }
        if p.offset >= length {
            return false;
        }
        let count = (length - p.offset).min(PAGE_SIZE);
        let mut valid = p.valid.lock();
        if count != *valid {
            // 缩短时清除尾部；扩长时不能把用户原先写在 EOF 外的字节变成文件内容。
            let (start, end) = if count < *valid {
                (count, PAGE_SIZE)
            } else {
                (*valid, count)
            };
            p.frame.clear_range(start, end);
            p.clean.clear_range(start, end);
            *valid = count;
        }
        true
    });
}

/// 为文件页建立唯一缓存项，初始化完成才发布。调用者先检查 EOF。
pub fn page(ino: u32, offset: usize) -> Result<SharedPage, Errno> {
    let mut pages = PAGES.lock();
    if let Some(p) = pages.iter().find(|p| p.ino == ino && p.offset == offset) {
        return Ok(SharedPage(p.clone()));
    }
    pages.try_reserve(1).map_err(|_| Errno::NoMem)?;
    let frame = OwnedFrame::new().map_err(|_| Errno::NoMem)?;
    let clean = OwnedFrame::new().map_err(|_| Errno::NoMem)?;
    let mut buf = buffer(PAGE_SIZE)?;
    let mut len = 0;
    let count = super::stat(ino)?
        .1
        .saturating_sub(offset as u64)
        .min(PAGE_SIZE as u64) as usize;
    while len < count {
        let n = super::read_raw(ino, offset + len, &mut buf[len..count])?;
        if n == 0 {
            return Err(Errno::Io);
        }
        len += n;
    }
    frame.write(0, &buf).map_err(|_| Errno::Io)?;
    clean.copy_from(&frame);
    super::retain(ino)?;
    let p = try_arc(Entry {
        ino,
        offset,
        frame,
        clean,
        valid: Mutex::new(len),
        retry: AtomicBool::new(false),
    })?;
    pages.push(p.clone());
    Ok(SharedPage(p))
}

/// 用驻留页的最新内容覆盖普通 read 已读取的字节。
pub(super) fn overlay(ino: u32, offset: usize, data: &mut [u8]) -> Result<(), Errno> {
    let end = offset.checked_add(data.len()).ok_or(Errno::Invalid)?;
    for p in PAGES.lock().iter().filter(|p| p.ino == ino) {
        let lo = offset.max(p.offset);
        let hi = end.min(p.offset.saturating_add(PAGE_SIZE));
        if lo < hi {
            p.frame
                .read(lo - p.offset, &mut data[lo - offset..hi - offset])
                .map_err(|_| Errno::Io)?;
        }
    }
    Ok(())
}

/// 后端接受普通写入后更新共享别名与基线；扩展文件时新暴露的空洞为零。
pub(super) fn written(ino: u32, offset: usize, data: &[u8]) -> Result<(), Errno> {
    let end = offset.checked_add(data.len()).ok_or(Errno::Invalid)?;
    if data.is_empty() {
        return Ok(());
    }
    for p in PAGES.lock().iter().filter(|p| p.ino == ino) {
        let mut valid = p.valid.lock();
        let new_valid = end.saturating_sub(p.offset).min(PAGE_SIZE);
        let gap_end = offset.saturating_sub(p.offset).min(new_valid);
        p.frame.clear_range(*valid, gap_end);
        p.clean.clear_range(*valid, gap_end);
        let lo = offset.max(p.offset);
        let hi = end.min(p.offset.saturating_add(PAGE_SIZE));
        if lo < hi {
            let bytes = &data[lo - offset..hi - offset];
            p.frame.write(lo - p.offset, bytes).map_err(|_| Errno::Io)?;
            p.clean.write(lo - p.offset, bytes).map_err(|_| Errno::Io)?;
        }
        *valid = (*valid).max(new_valid);
    }
    Ok(())
}
