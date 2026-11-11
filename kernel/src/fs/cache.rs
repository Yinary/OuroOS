//! 文件共享页缓存；映射持有强引用，索引只持弱引用。
use crate::{
    mm::{address_space::phys_to_kernel_vaddr, frame::OwnedFrame},
    syscall::Errno,
};
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
}
impl SharedPage {
    /// 页表映射使用的物理地址；所有权仍由 Arc 管理。
    pub fn addr(&self) -> PhysAddr {
        self.frame.addr()
    }
    fn load(&self, offset: usize, out: &mut [u8]) {
        // SAFETY: offset+len 在调用方限制于一页；单核且用户态已停止。
        // 只短暂借用内核缓冲区，物理共享页不构造 Rust 引用。
        unsafe {
            core::ptr::copy_nonoverlapping(
                (phys_to_kernel_vaddr(self.addr()) + offset) as *const u8,
                out.as_mut_ptr(),
                out.len(),
            );
        }
    }
    fn store(&self, offset: usize, data: &[u8]) {
        // SAFETY: 页内范围由调用方检查；单核内核操作不与用户执行并发。
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (phys_to_kernel_vaddr(self.addr()) + offset) as *mut u8,
                data.len(),
            );
        }
    }
}
impl Drop for SharedPage {
    fn drop(&mut self) {
        let result = (|| {
            let len = super::stat(self.ino)?.1 as usize;
            let count = len.saturating_sub(self.offset).min(4096);
            if count != 0 {
                let mut data = [0; 4096];
                self.load(0, &mut data[..count]);
                super::write_raw(self.ino, self.offset, &data[..count])?;
            }
            Ok::<(), Errno>(())
        })();
        if let Err(e) = result {
            log::error!("shared page writeback failed: {:?}", e);
        }
        super::release(self.ino);
    }
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
    super::retain(ino)?;
    let p = crate::fs::try_arc(SharedPage { frame, ino, offset })?;
    p.store(0, &data);
    pages.push((ino, offset, Arc::downgrade(&p)));
    Ok(p)
}
/// 文件 read 覆盖共享页中的最新内容，write 同步更新已有映射。
pub fn coherent(ino: u32, offset: usize, data: &mut [u8], write: bool) {
    let pages = PAGES.lock();
    for (id, start, page) in pages.iter() {
        if *id != ino {
            continue;
        }
        let begin = offset.max(*start);
        let end = (offset + data.len()).min(*start + 4096);
        if begin >= end {
            continue;
        }
        if let Some(page) = page.upgrade() {
            if write {
                page.store(begin - *start, &data[begin - offset..end - offset]);
            } else {
                page.load(begin - *start, &mut data[begin - offset..end - offset]);
            }
        }
    }
}
