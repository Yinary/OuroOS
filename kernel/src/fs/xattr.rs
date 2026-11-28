//! 文件扩展属性（xattr(7)）内存索引表：按 Ext4 inode 维护属性键值。
//! 无任何扩展属性时，通过单次 Relaxed 原子读取走零锁快速路径，不影响常规文件读写热路径。
#![deny(unsafe_code)]

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::syscall::Errno;

/// Linux XATTR_NAME_MAX（含命名空间前缀，不含末尾 NUL）。
pub const XATTR_NAME_MAX: usize = 255;
/// Linux XATTR_SIZE_MAX（单个属性值最大字节数）。
pub const XATTR_SIZE_MAX: usize = 65536;
/// Linux XATTR_LIST_MAX（listxattr 列表最大字节数）。
pub const XATTR_LIST_MAX: usize = 65536;

/// XATTR_CREATE：仅当属性不存在时创建，已存在返回 EEXIST。
pub const XATTR_CREATE: u32 = 0x1;
/// XATTR_REPLACE：仅当属性已存在时替换，不存在返回 ENODATA。
pub const XATTR_REPLACE: u32 = 0x2;

/// Ext4 不可变/仅追加文件标志（linux/fs.h：FS_IMMUTABLE_FL / FS_APPEND_FL）。
pub const FS_IMMUTABLE_FL: u32 = 0x10;
pub const FS_APPEND_FL: u32 = 0x20;

/// 栈上快速路径阈值（常见短属性值/列表免堆分配）。
const STACK_FAST_CAP: usize = 256;

/// 全局快速路径标志：尚未设置过任何扩展属性时，所有查询/清理直接跳过锁竞争。
static HAS_XATTR: AtomicBool = AtomicBool::new(false);
/// 全局快速路径标志：尚未设置过任何 FS_IOC_SETFLAGS 时，跳过锁竞争。
static HAS_INODE_FLAGS: AtomicBool = AtomicBool::new(false);

/// 全局扩展属性表：inode -> (属性名 -> 属性值)。
static XATTRS: Mutex<BTreeMap<u32, BTreeMap<String, Vec<u8>>>> = Mutex::new(BTreeMap::new());
/// 全局 inode 文件标志表（FS_IOC_GETFLAGS / FS_IOC_SETFLAGS）。
static INODE_FLAGS: Mutex<BTreeMap<u32, u32>> = Mutex::new(BTreeMap::new());

/// 读取指定 inode 的 FS_IOC_GETFLAGS 标志位；未设置时零锁返回 0。
#[inline]
pub fn get_inode_flags(ino: u32) -> u32 {
    if !HAS_INODE_FLAGS.load(Ordering::Acquire) {
        return 0;
    }
    INODE_FLAGS.lock().get(&ino).copied().unwrap_or(0)
}

/// 更新指定 inode 的 FS_IOC_SETFLAGS 标志位（仅保留常见有效位）。
pub fn set_inode_flags(ino: u32, flags: u32) {
    let mut table = INODE_FLAGS.lock();
    if flags == 0 {
        table.remove(&ino);
        if table.is_empty() {
            HAS_INODE_FLAGS.store(false, Ordering::Release);
        }
    } else {
        table.insert(ino, flags);
        HAS_INODE_FLAGS.store(true, Ordering::Release);
    }
}

/// 扩展属性命名空间分类。
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    User,
    Trusted,
    Security,
    System,
}

/// 校验并解析属性名所属命名空间；未识别前缀返回 EOPNOTSUPP，空后缀返回 EINVAL。
pub fn parse_namespace(name: &str) -> Result<Namespace, Errno> {
    if let Some(rest) = name.strip_prefix("user.") {
        return if rest.is_empty() {
            Err(Errno::Invalid)
        } else {
            Ok(Namespace::User)
        };
    }
    if let Some(rest) = name.strip_prefix("trusted.") {
        return if rest.is_empty() {
            Err(Errno::Invalid)
        } else {
            Ok(Namespace::Trusted)
        };
    }
    if let Some(rest) = name.strip_prefix("security.") {
        return if rest.is_empty() {
            Err(Errno::Invalid)
        } else {
            Ok(Namespace::Security)
        };
    }
    if let Some(rest) = name.strip_prefix("system.") {
        return if rest.is_empty() {
            Err(Errno::Invalid)
        } else {
            Ok(Namespace::System)
        };
    }
    Err(Errno::NotSupported)
}

/// 清理指定 inode 的全部扩展属性与文件标志（新创建或删尽 inode 时调用；无属性时仅两次原子读）。
#[inline]
pub fn purge_inode(ino: u32) {
    if HAS_XATTR.load(Ordering::Relaxed) {
        let mut table = XATTRS.lock();
        table.remove(&ino);
        if table.is_empty() {
            HAS_XATTR.store(false, Ordering::Release);
        }
    }
    if HAS_INODE_FLAGS.load(Ordering::Relaxed) {
        let mut table = INODE_FLAGS.lock();
        table.remove(&ino);
        if table.is_empty() {
            HAS_INODE_FLAGS.store(false, Ordering::Release);
        }
    }
}

/// 设置或替换指定 inode 的扩展属性。
pub fn set(ino: u32, name: &str, value: &[u8], flags: u32) -> Result<(), Errno> {
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return Err(Errno::Invalid);
    }
    let mut table = XATTRS.lock();
    let exists = table
        .get(&ino)
        .is_some_and(|attrs| attrs.contains_key(name));
    if flags & XATTR_CREATE != 0 && exists {
        return Err(Errno::Exists);
    }
    if flags & XATTR_REPLACE != 0 && !exists {
        return Err(Errno::NoData);
    }
    let mut owned_val = Vec::new();
    owned_val
        .try_reserve_exact(value.len())
        .map_err(|_| Errno::NoMem)?;
    owned_val.extend_from_slice(value);

    let attrs = table.entry(ino).or_default();
    if let Some(slot) = attrs.get_mut(name) {
        *slot = owned_val;
    } else {
        let mut owned_name = String::new();
        owned_name
            .try_reserve_exact(name.len())
            .map_err(|_| Errno::NoMem)?;
        owned_name.push_str(name);
        attrs.insert(owned_name, owned_val);
    }
    HAS_XATTR.store(true, Ordering::Release);
    Ok(())
}

/// 读取指定 inode 的扩展属性并通过回调交付（`size == 0` 仅返回长度；短值走栈缓冲免堆分配）。
pub fn get(
    ino: u32,
    name: &str,
    size: usize,
    deliver: impl FnOnce(&[u8]) -> Result<(), Errno>,
) -> Result<usize, Errno> {
    if !HAS_XATTR.load(Ordering::Acquire) {
        return Err(Errno::NoData);
    }
    let mut stack_buf = [0u8; STACK_FAST_CAP];
    let mut heap_buf: Option<Vec<u8>> = None;
    let len = {
        let table = XATTRS.lock();
        let val = table
            .get(&ino)
            .and_then(|attrs| attrs.get(name))
            .ok_or(Errno::NoData)?;
        let len = val.len();
        if size == 0 {
            return Ok(len);
        }
        if size < len {
            return Err(Errno::Range);
        }
        if len <= STACK_FAST_CAP {
            stack_buf[..len].copy_from_slice(val);
        } else {
            let mut v = Vec::new();
            v.try_reserve_exact(len).map_err(|_| Errno::NoMem)?;
            v.extend_from_slice(val);
            heap_buf = Some(v);
        }
        len
    };
    let slice = match heap_buf.as_deref() {
        Some(v) => v,
        None => &stack_buf[..len],
    };
    deliver(slice)?;
    Ok(len)
}

/// 列出指定 inode 可见的全部扩展属性名（以 NUL 分隔；`trusted.*` 仅对具备权限者可见）。
pub fn list(
    ino: u32,
    size: usize,
    show_trusted: bool,
    deliver: impl FnOnce(&[u8]) -> Result<(), Errno>,
) -> Result<usize, Errno> {
    if !HAS_XATTR.load(Ordering::Acquire) {
        return Ok(0);
    }
    let cap = size.min(XATTR_LIST_MAX);
    let mut stack_buf = [0u8; STACK_FAST_CAP];
    let mut heap_buf: Option<Vec<u8>> = None;
    let total = {
        let table = XATTRS.lock();
        let Some(attrs) = table.get(&ino) else {
            return Ok(0);
        };
        let mut total = 0usize;
        for name in attrs.keys() {
            if !show_trusted && name.starts_with("trusted.") {
                continue;
            }
            total = total.saturating_add(name.len() + 1);
        }
        if size == 0 || total == 0 {
            return Ok(total);
        }
        if cap < total {
            return Err(Errno::Range);
        }
        if total <= STACK_FAST_CAP {
            let mut pos = 0usize;
            for name in attrs.keys() {
                if !show_trusted && name.starts_with("trusted.") {
                    continue;
                }
                let b = name.as_bytes();
                stack_buf[pos..pos + b.len()].copy_from_slice(b);
                stack_buf[pos + b.len()] = 0;
                pos += b.len() + 1;
            }
        } else {
            let mut out = Vec::new();
            out.try_reserve_exact(total).map_err(|_| Errno::NoMem)?;
            for name in attrs.keys() {
                if !show_trusted && name.starts_with("trusted.") {
                    continue;
                }
                out.extend_from_slice(name.as_bytes());
                out.push(0);
            }
            heap_buf = Some(out);
        }
        total
    };
    let slice = match heap_buf.as_deref() {
        Some(v) => v,
        None => &stack_buf[..total],
    };
    deliver(slice)?;
    Ok(total)
}

/// 删除指定 inode 的扩展属性；不存在返回 ENODATA。
pub fn remove(ino: u32, name: &str) -> Result<(), Errno> {
    if !HAS_XATTR.load(Ordering::Acquire) {
        return Err(Errno::NoData);
    }
    let mut table = XATTRS.lock();
    let Some(attrs) = table.get_mut(&ino) else {
        return Err(Errno::NoData);
    };
    if attrs.remove(name).is_none() {
        return Err(Errno::NoData);
    }
    if attrs.is_empty() {
        table.remove(&ino);
        if table.is_empty() {
            HAS_XATTR.store(false, Ordering::Release);
        }
    }
    Ok(())
}
