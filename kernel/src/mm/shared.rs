//! 共享匿名对象由映射持有；相同对象的相同页号在各地址空间引用同一帧。
use super::{address_space::MapError, frame::OwnedFrame};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use polyhal::PhysAddr;
use spin::Mutex;

// 序号只在新建共享对象时分配，地址复用不会唤醒上一对象的等待者。
static NEXT_OBJECT: AtomicUsize = AtomicUsize::new(1);

struct SharedObject {
    id: usize,
    writable: bool,
    pages: Mutex<Vec<(usize, OwnedFrame)>>,
}

#[derive(Clone)]
pub(crate) struct SharedPage {
    object: Arc<SharedObject>,
    index: usize,
}
impl SharedPage {
    pub(super) fn first(writable: bool) -> Result<Self, MapError> {
        Ok(Self {
            object: Arc::try_new(SharedObject {
                id: NEXT_OBJECT.fetch_add(1, Ordering::Relaxed),
                writable,
                pages: Mutex::new(Vec::new()),
            })
            .map_err(|_| MapError::OutOfMemory)?,
            index: 0,
        })
    }
    pub(super) fn immediately_before(&self, next: &Self) -> bool {
        Arc::ptr_eq(&self.object, &next.object) && self.index.checked_add(1) == Some(next.index)
    }
    pub(super) fn following(&self, n: usize) -> Result<Self, MapError> {
        Ok(Self {
            object: self.object.clone(),
            index: self.index.checked_add(n).ok_or(MapError::OutOfUserRange)?,
        })
    }
    pub(super) fn writable(&self) -> bool {
        self.object.writable
    }

    pub(super) fn identity(&self) -> (usize, usize) {
        (self.object.id, self.index)
    }

    pub(super) fn addr(&self) -> Option<PhysAddr> {
        let pages = self.object.pages.lock();
        pages
            .binary_search_by_key(&self.index, |p| p.0)
            .ok()
            .map(|i| pages[i].1.addr())
    }
    /// 只有所需页表与物理帧均准备成功后，才公布原本不存在的页。
    pub(super) fn fault(
        &self,
        install: impl FnOnce(PhysAddr) -> Result<(), MapError>,
    ) -> Result<(), MapError> {
        let mut pages = self.object.pages.lock();
        match pages.binary_search_by_key(&self.index, |p| p.0) {
            Ok(i) => install(pages[i].1.addr()),
            Err(i) => {
                pages.try_reserve(1).map_err(|_| MapError::OutOfMemory)?;
                let frame = OwnedFrame::new()?;
                install(frame.addr())?;
                pages.insert(i, (self.index, frame));
                Ok(())
            }
        }
    }
}
