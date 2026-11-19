//! 主机回归：用可故障注入的内存磁盘运行内核的文件后备与共享页缓存代码。
//! 在仓库工具链下运行 rustc --edition=2021 --test tests/file_mapping.rs -o /tmp/file_mapping。
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as log;
extern crate self as polyhal;
extern crate self as spin;

use std::sync::Mutex as StdMutex;
#[macro_export]
macro_rules! error { ($($args:tt)*) => { eprintln!($($args)*) } }
pub struct Mutex<T>(StdMutex<T>);
impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self(StdMutex::new(value))
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}
pub mod pagetable {
    pub const PAGE_SIZE: usize = 4096;
}
type PhysAddr = usize;
mod syscall {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Errno {
        Invalid,
        Io,
        NoMem,
    }
}
mod mm {
    pub mod frame {
        use crate::{pagetable::PAGE_SIZE, Mutex};
        pub struct OwnedFrame(Mutex<Box<[u8; PAGE_SIZE]>>);
        impl OwnedFrame {
            pub fn new() -> Result<Self, ()> {
                Ok(Self(Mutex::new(Box::new([0; PAGE_SIZE]))))
            }
            pub fn addr(&self) -> usize {
                self.0.lock().as_ptr() as usize
            }
            pub fn read(&self, off: usize, dst: &mut [u8]) -> Result<(), ()> {
                dst.copy_from_slice(&self.0.lock()[off..off + dst.len()]);
                Ok(())
            }
            pub fn write(&self, off: usize, src: &[u8]) -> Result<(), ()> {
                self.0.lock()[off..off + src.len()].copy_from_slice(src);
                Ok(())
            }
            pub fn copy_from(&self, other: &Self) {
                self.0.lock().copy_from_slice(other.0.lock().as_slice());
            }
            pub fn clear_range(&self, start: usize, end: usize) {
                if start < end {
                    self.0.lock()[start..end].fill(0);
                }
            }
        }
    }
    pub mod address_space {
        #[derive(Debug)]
        pub enum MapError {
            FileFault,
            FileIo,
            OutOfMemory,
            OutOfUserRange,
        }
        impl From<()> for MapError {
            fn from(_: ()) -> Self {
                Self::OutOfMemory
            }
        }
    }
    pub(crate) use crate::file;
    pub fn check_fault_reason(ino: u32) {
        use crate::file::{FilePage, MappingFile, Mode};
        use address_space::MapError;
        let file = MappingFile::new(ino).unwrap();
        for mode in [Mode::Private, Mode::Shared { writable: false }] {
            let beyond = FilePage::new(file.clone(), 8192, mode);
            assert!(matches!(beyond.fault(), Err(MapError::FileFault)));
            let data = FilePage::new(file.clone(), 0, mode);
            crate::DISK.lock().fail = true;
            assert!(matches!(data.fault(), Err(MapError::FileIo)));
            crate::DISK.lock().fail = false;
            assert!(data.fault().is_ok());
        }
    }

    pub fn nonzero_shrink(ino: u32) {
        use file::*;
        let object = MappingFile::new(ino).unwrap();
        let first = FilePage::new(object.clone(), 0, Mode::Private);
        let second = first.following(4096).unwrap();
        let ptr = first.fault().unwrap() as *mut u8;
        // SAFETY: 两次写入均在 first 持有的测试帧内，当前线程独占测试数据。
        unsafe {
            ptr.write(43);
            ptr.add(100).write(71);
        }
        second.fault().unwrap();
        let child = first.fork().unwrap();
        resized(ino, 4100, 64);
        assert!(!first.stale() && !child.stale() && second.stale());
        for page in [&first, &child] {
            let ptr = page.addr().unwrap() as *const u8;
            // SAFETY: 测试页及私有副本均存活，读取位置在页内。
            unsafe {
                assert_eq!((ptr.read(), ptr.add(100).read()), (43, 0));
            }
        }
    }
}
pub(crate) use mm::{address_space, frame};
#[path = "../kernel/src/fs/cache.rs"]
mod cache;
#[path = "../kernel/src/mm/file.rs"]
mod file;
mod fs {
    pub(crate) use super::read_raw as read;
    pub(crate) use super::{cache, release, retain, stat, try_arc};
}
use std::sync::Arc;
use syscall::Errno;
struct Disk {
    data: Vec<u8>,
    refs: usize,
    writes: usize,
    max_write: usize,
    fail: bool,
}
static DISK: Mutex<Disk> = Mutex::new(Disk {
    data: Vec::new(),
    refs: 0,
    writes: 0,
    max_write: usize::MAX,
    fail: false,
});
pub(crate) fn try_arc<T>(value: T) -> Result<Arc<T>, Errno> {
    Arc::try_new(value).map_err(|_| Errno::NoMem)
}
pub(crate) fn retain(_: u32) -> Result<(), Errno> {
    DISK.lock().refs += 1;
    Ok(())
}
pub(crate) fn release(_: u32) {
    DISK.lock().refs -= 1;
}
pub(crate) fn stat(_: u32) -> Result<(u16, u64), Errno> {
    Ok((0, DISK.lock().data.len() as u64))
}
pub(crate) fn read_raw(_: u32, at: usize, data: &mut [u8]) -> Result<usize, Errno> {
    if DISK.lock().fail {
        return Err(Errno::Io);
    }
    let d = DISK.lock();
    let n = data.len().min(d.data.len().saturating_sub(at)).min(137);
    if n != 0 {
        data[..n].copy_from_slice(&d.data[at..at + n]);
    }
    Ok(n)
}
fn write_raw(_: u32, at: usize, data: &[u8]) -> Result<usize, Errno> {
    let mut d = DISK.lock();
    d.writes += 1;
    if d.fail {
        return Err(Errno::Io);
    }
    let n = data.len().min(d.max_write);
    d.data[at..at + n].copy_from_slice(&data[..n]);
    Ok(n)
}

#[test]
fn mapped_file_lifetime_and_retry() {
    DISK.lock().data = vec![11; 4100];
    {
        let p0 = cache::page(1, 0).unwrap();
        let p1 = cache::page(1, 4096).unwrap();
        // SAFETY: 两个引用均持有存活的独立页，单线程模拟两个用户映射。
        unsafe {
            (p0.addr() as *mut u8).write(97);
            (p1.addr() as *mut u8).write(98);
        }
        cache::sync_span(1, 4096, 4096).unwrap();
        {
            let d = DISK.lock();
            assert_eq!((d.data[0], d.data[4096]), (11, 98));
        }
        drop((p0, p1));
        let mut d = DISK.lock();
        assert_eq!(d.data[0], 97);
        d.data.fill(11);
        d.writes = 0;
    }
    mm::check_fault_reason(1);
    mm::nonzero_shrink(1);
    assert_eq!(DISK.lock().refs, 0);
    let page = cache::page(1, 0).unwrap();
    drop(page);
    assert_eq!(DISK.lock().writes, 0);
    let page = cache::page(1, 0).unwrap();
    // SAFETY: page 和再次打开的别名保证页存活；单线程模拟用户 CPU 写入。
    unsafe {
        (page.addr() as *mut u8).write(22);
    }
    DISK.lock().max_write = 1;
    drop(page);
    assert_eq!(cache::retained_frames(), 2);
    assert_eq!(DISK.lock().refs, 1);
    let alias = cache::page(1, 0).unwrap();
    // SAFETY: alias 持有页。恢复为旧基线，验证短写后仍必须重试。
    unsafe {
        (alias.addr() as *mut u8).write(11);
    }
    DISK.lock().fail = true;
    assert_eq!(cache::sync_inode(1), Err(Errno::Io));
    drop(alias);
    assert_eq!(cache::retained_frames(), 2);
    DISK.lock().fail = false;
    DISK.lock().max_write = usize::MAX;
    cache::sync_inode(1).unwrap();
    assert_eq!(DISK.lock().data[0], 11);
    assert_eq!((cache::retained_frames(), DISK.lock().refs), (0, 0));

    let page = cache::page(1, 0).unwrap();
    // SAFETY: 两个位置都在 page 所有的页内。
    unsafe {
        (page.addr() as *mut u8).write(33);
        (page.addr() as *mut u8).add(8).write(99);
    }
    DISK.lock().data.truncate(4);
    cache::resized(1, 4);
    drop(page);
    assert_eq!(DISK.lock().data, [33, 11, 11, 11]);

    let page = cache::page(1, 0).unwrap();
    assert!(cache::resident(1, 0));
    assert!(!cache::resident(2, 0) && !cache::resident(1, 4096));
    // SAFETY: page 持有整页。模拟在 EOF 外写入，再由后端将文件扩长。
    unsafe {
        (page.addr() as *mut u8).add(6).write(88);
    }
    DISK.lock().data.resize(8, 0);
    cache::resized(1, 8);
    // SAFETY: 页引用仍在，偏移 6 和 7 位于新有效范围内。
    unsafe {
        assert_eq!((page.addr() as *const u8).add(6).read(), 0);
        (page.addr() as *mut u8).add(7).write(77);
    }
    drop(page);
    assert_eq!(DISK.lock().data, [33, 11, 11, 11, 0, 0, 0, 77]);
    assert!(!cache::resident(1, 0));

    let page = cache::page(1, 0).unwrap();
    // SAFETY: page 仍拥有本次写入的首字节。
    unsafe {
        (page.addr() as *mut u8).write(66);
    }
    DISK.lock().fail = true;
    drop(page);
    cache::resized(1, 0);
    DISK.lock().data.clear();
    cache::flush(None).unwrap();
    assert_eq!((cache::retained_frames(), DISK.lock().refs), (0, 0));
}
