//! 与后端无关的文件属性，以及保留符号链接语义的状态查询路径解析。
#![deny(unsafe_code)]
use super::{ext4, fat, lookup, FAT_INODE};
use crate::syscall::Errno;
use alloc::string::String;

/// 自 Unix 纪元起的秒数及纳秒部分。
#[derive(Clone, Copy, Default)]
pub(crate) struct Timestamp {
    pub sec: i64,
    pub nsec: u32,
}

/// 文件属性快照；后端没有提供的时间使用 None。
#[derive(Default)]
pub(crate) struct Metadata {
    pub ino: u64,
    pub dev: u64,
    pub rdev: u64,
    pub mode: u16,
    pub links: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub blocks: u64,
    pub block_size: u32,
    pub atime: Option<Timestamp>,
    pub mtime: Option<Timestamp>,
    pub ctime: Option<Timestamp>,
    pub btime: Option<Timestamp>,
}

/// 按 inode 取得后端元数据，失败返回后端错误。
pub(super) fn metadata(ino: u32) -> Result<Metadata, Errno> {
    // procfs 虚拟节点（/proc、/proc/<pid>、/dev/*）无后端 inode，按统一
    // stat 结果合成，避免 resolve 逐分量解析时把虚拟节点当 ext4 处理
    if ino >= super::procfs::MISC_DIR || super::procfs::pid_ino_parts(ino).is_some() {
        let (mode, size, links, _) = super::stat(ino)?;
        return Ok(Metadata {
            ino: ino as u64,
            mode,
            links: u32::from(links),
            size,
            block_size: 4096,
            ..Default::default()
        });
    }
    if ino & FAT_INODE != 0 {
        fat::metadata(ino)
    } else {
        ext4::metadata(ino)
    }
}

fn string(s: &str) -> Result<String, Errno> {
    let mut out = String::new();
    out.try_reserve(s.len()).map_err(|_| Errno::NoMem)?;
    out.push_str(s);
    Ok(out)
}

/// 查询绝对路径；follow 只控制末项链接，最多跟随 40 个链接。
pub(crate) fn query(path: &str, follow: bool) -> Result<Metadata, Errno> {
    resolve(path, follow).map(|(_, info)| info)
}

/// 解析绝对路径并返回规范路径及属性；保留与 query 相同的链接规则。
pub(super) fn resolve(path: &str, follow: bool) -> Result<(String, Metadata), Errno> {
    let mut pending = string(path)?;
    let mut current = string("/")?;
    let mut info = metadata(lookup("/")?)?;
    let mut cursor = 0;
    let mut links = 0;
    while cursor < pending.len() {
        if info.mode & 0xf000 != 0x4000 {
            return Err(Errno::NotDir);
        }
        let rest = pending[cursor..].trim_start_matches('/');
        if rest.is_empty() {
            break;
        }
        let end = rest.find('/').unwrap_or(rest.len());
        let name = &rest[..end];
        let suffix = &rest[end..];
        let next = pending.len() - suffix.len();
        match name {
            "." => {}
            ".." => {
                current.truncate(current.rfind('/').unwrap_or(0).max(1));
                info = metadata(lookup(&current)?)?;
            }
            _ => {
                if name.len() > 255 {
                    return Err(Errno::NameTooLong);
                }
                let mut candidate = string(&current)?;
                candidate
                    .try_reserve(name.len() + 1)
                    .map_err(|_| Errno::NoMem)?;
                if candidate != "/" {
                    candidate.push('/');
                }
                candidate.push_str(name);
                if candidate.len() >= 4096 {
                    return Err(Errno::NameTooLong);
                }
                let ino = lookup(&candidate)?;
                let child = metadata(ino)?;
                if child.mode & 0xf000 == 0xa000 && (follow || !suffix.is_empty()) {
                    links += 1;
                    if links > 40 {
                        return Err(Errno::Loop);
                    }
                    let mut target = ext4::link_target(ino)?;
                    if target.is_empty() {
                        return Err(Errno::NoEntry);
                    }
                    if target
                        .len()
                        .checked_add(suffix.len())
                        .ok_or(Errno::NameTooLong)?
                        >= 4096
                    {
                        return Err(Errno::NameTooLong);
                    }
                    target.try_reserve(suffix.len()).map_err(|_| Errno::NoMem)?;
                    target.push_str(suffix);
                    if target.starts_with('/') {
                        current.truncate(1);
                        info = metadata(lookup("/")?)?;
                    }
                    pending = target;
                    cursor = 0;
                    continue;
                }
                current = candidate;
                info = child;
            }
        }
        cursor = next;
    }
    Ok((current, info))
}
