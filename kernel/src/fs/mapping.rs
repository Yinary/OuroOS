//! 文件长度变化的 MM 通知钩子。
//!
//! FS 不直接依赖 MM：MM 在初始化时注册 hooks；没有注册时，FS 保持
//! “有存活共享页就拒绝截断”的保守行为。截断顺序：
//! 1. `prepare_resize`：MM 校验并预分配失效所需资源，失败不改变文件；
//! 2. FS 后端调整长度；
//! 3. `cache::invalidate_inode`：禁止旧共享页写回；
//! 4. `commit_resize`：MM 撤销/缩短旧映射。

use crate::syscall::Errno;
use spin::Mutex;

/// MM 侧实现；`prepare` 可失败，`commit` 必须不可失败。
pub trait Hooks: Sync {
    fn prepare_resize(&self, ino: u32, old: u64, new: u64) -> Result<(), Errno>;
    fn commit_resize(&self, ino: u32, old: u64, new: u64);
}

static HOOKS: Mutex<Option<&'static dyn Hooks>> = Mutex::new(None);

/// 注册 MM hooks；只允许一次。
#[allow(dead_code)] // MM 在后续 PR 注册
pub fn register(hooks: &'static dyn Hooks) {
    *HOOKS.lock() = Some(hooks);
}

pub fn registered() -> bool {
    HOOKS.lock().is_some()
}

pub fn prepare_resize(ino: u32, old: u64, new: u64) -> Result<(), Errno> {
    match *HOOKS.lock() {
        Some(hooks) => hooks.prepare_resize(ino, old, new),
        None => Ok(()),
    }
}

pub fn commit_resize(ino: u32, old: u64, new: u64) {
    if let Some(hooks) = *HOOKS.lock() {
        hooks.commit_resize(ino, old, new);
    }
}
