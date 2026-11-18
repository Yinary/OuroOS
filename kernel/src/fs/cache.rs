//! 文件共享页缓存；映射持有强引用，索引只持弱引用。
#![deny(unsafe_code)]
use crate::{mm::frame::OwnedFrame, syscall::Errno};
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use polyhal::PhysAddr;
use spin::Mutex;
static PAGES: Mutex<Vec<(u32, usize, Weak<SharedPage>)>> = Mutex::new(Vec::new());

/// 一页共享文件内容，最后一个映射释放时写回。
pub struct SharedPage {
    frame: OwnedFrame,
    ino: u32,
    offset: usize,
    retained: bool,
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
}
impl Drop for SharedPage {
    fn drop(&mut self) {
        if !self.retained {
            return;
        }
        if let Err(e) = self.write_back() {
            log::error!("shared page writeback failed: {:?}", e);
        }
        super::release(self.ino);
    }
}

/// 将指定 inode 的驻留共享页写回文件后端。
#[cfg(not(feature = "rsext4-readonly"))]
pub(super) fn sync_inode(ino: u32) -> Result<(), Errno> {
    for (_, _, page) in PAGES.lock().iter().filter(|(id, _, _)| *id == ino) {
        if let Some(page) = page.upgrade() {
            page.write_back()?;
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
