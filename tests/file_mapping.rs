//! 主机回归：在可注入 I/O 的内存磁盘上验证共享文件页缓存。
//! 运行：rustc --edition=2021 --test tests/file_mapping.rs -o /tmp/file_mapping
#![feature(allocator_api)]
#![allow(dead_code)]
extern crate alloc;
extern crate self as log;
extern crate self as polyhal;
extern crate self as spin;

use std::sync::Mutex as StdMutex;
#[macro_export]
macro_rules! error {
    ($($args:tt)*) => {
        eprintln!($($args)*)
    };
}
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
        }
    }
}
#[path = "../kernel/src/fs/cache.rs"]
mod cache;

mod fs {
    pub(crate) use super::try_arc;
}
use std::sync::Arc;
use syscall::Errno;

struct Disk {
    data: Vec<u8>,
    refs: usize,
    writes: usize,
    fail: bool,
    write_fail: bool,
    write_fail_at: Option<usize>,
}
static TEST_LOCK: StdMutex<()> = StdMutex::new(());

static DISK: Mutex<Disk> = Mutex::new(Disk {
    data: Vec::new(),
    refs: 0,
    writes: 0,
    fail: false,
    write_fail: false,
    write_fail_at: None,
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
    let n = data.len().min(d.data.len().saturating_sub(at));
    if n != 0 {
        data[..n].copy_from_slice(&d.data[at..at + n]);
    }
    Ok(n)
}
fn write_raw(_: u32, at: usize, data: &[u8]) -> Result<usize, Errno> {
    let mut d = DISK.lock();
    d.writes += 1;
    if d.fail || d.write_fail || d.write_fail_at == Some(at) {
        return Err(Errno::Io);
    }
    d.data[at..at + data.len()].copy_from_slice(data);
    Ok(data.len())
}

#[test]
fn page_cache_roundtrip() {
    let _guard = TEST_LOCK.lock().unwrap();
    DISK.lock().data = vec![11; 4100];
    let page = cache::page(1, 0).unwrap();
    unsafe {
        (page.addr() as *mut u8).write(97);
    }
    assert!(cache::resident(1, 0));
    cache::sync_inode(1).unwrap();
    assert_eq!(DISK.lock().data[0], 97);
    drop(page);
    assert!(cache::resident(1, 0));
    cache::flush(None).unwrap();
    assert!(!cache::resident(1, 0));
    assert_eq!(DISK.lock().refs, 0);
}

#[test]
fn resize_zeroes_tail_and_expands() {
    let _guard = TEST_LOCK.lock().unwrap();
    DISK.lock().data = vec![11; 8];
    let page = cache::page(1, 0).unwrap();
    unsafe {
        (page.addr() as *mut u8).write(33);
    }
    DISK.lock().data.truncate(4);
    cache::resize_inode(1, 4096, 4);
    drop(page);
    cache::flush(None).unwrap();
    assert_eq!(DISK.lock().data, [33, 11, 11, 11]);

    let page = cache::page(1, 0).unwrap();
    DISK.lock().data.resize(8, 0);
    cache::resize_inode(1, 4, 8);
    unsafe {
        assert_eq!((page.addr() as *const u8).add(6).read(), 0);
    }
    drop(page);
    cache::flush(None).unwrap();
    assert_eq!(DISK.lock().data, [33, 11, 11, 11, 0, 0, 0, 0]);
    assert_eq!(cache::retained_frames(), 0);
}

#[test]
fn flush_retries_after_writeback_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    DISK.lock().data = vec![0; 4096];
    let page = cache::page(1, 0).unwrap();
    unsafe {
        (page.addr() as *mut u8).write(42);
    }
    drop(page);
    DISK.lock().write_fail = true;
    assert!(cache::flush(None).is_err());
    assert!(cache::resident(1, 0));
    DISK.lock().write_fail = false;
    cache::flush(None).unwrap();
    assert_eq!(DISK.lock().data[0], 42);
    assert!(!cache::resident(1, 0));
}

#[test]
fn read_only_sparse_page_does_not_write() {
    let _guard = TEST_LOCK.lock().unwrap();
    DISK.lock().data = vec![0; 4096];
    DISK.lock().writes = 0;
    let page = cache::page(1, 0).unwrap();
    drop(page);
    cache::flush(None).unwrap();
    assert_eq!(DISK.lock().writes, 0);
    assert!(!cache::resident(1, 0));
}

#[test]
fn flush_continues_after_one_page_failure() {
    let _guard = TEST_LOCK.lock().unwrap();
    DISK.lock().data = vec![0; 8192];
    let first = cache::page(1, 0).unwrap();
    let second = cache::page(1, 4096).unwrap();
    cache::coherent(1, 0, &mut [1], true);
    cache::coherent(1, 4096, &mut [2], true);
    drop((first, second));
    DISK.lock().write_fail_at = Some(0);
    assert!(cache::flush(None).is_err());
    assert_eq!(DISK.lock().data[4096], 2);
    assert_eq!(DISK.lock().data[0], 0);
    assert!(!cache::resident(1, 4096));
    assert!(cache::resident(1, 0));
    let mut retained = [0u8; 1];
    cache::coherent(1, 0, &mut retained, false);
    assert_eq!(retained[0], 1);
    DISK.lock().write_fail_at = None;
    cache::flush(None).unwrap();
    assert_eq!(DISK.lock().data[0], 1);
    assert!(!cache::resident(1, 0) && !cache::resident(1, 4096));
}

#[test]
fn dirty_page_survives_failed_second_writeback() {
    let _guard = TEST_LOCK.lock().unwrap();
    DISK.lock().data = vec![0; 4096];
    let page = cache::page(1, 0).unwrap();
    cache::coherent(1, 0, &mut [7], true);
    drop(page);
    cache::flush(None).unwrap();
    assert_eq!(DISK.lock().data[0], 7);

    let page = cache::page(1, 0).unwrap();
    cache::coherent(1, 0, &mut [8], true);
    drop(page);
    DISK.lock().write_fail_at = Some(0);
    assert!(cache::flush(None).is_err());
    assert!(cache::resident(1, 0));
    assert_eq!(DISK.lock().data[0], 7);
    DISK.lock().write_fail_at = None;
    cache::flush(None).unwrap();
    assert_eq!(DISK.lock().data[0], 8);
    assert!(!cache::resident(1, 0));
}
