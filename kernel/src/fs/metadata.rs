//! 与后端无关的文件属性与路径解析。
#![deny(unsafe_code)]
use super::{ext2_mount, ext4, fat, lookup, FAT_INODE};
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
    pub(super) handle: Option<u32>,
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

/// 一次权限查询使用的身份，补充组借用调用进程的凭证。
#[derive(Clone, Copy)]
pub(super) struct AccessIdentity<'a> {
    pub uid: u32,
    pub gid: u32,
    pub groups: &'a [u32],
}

impl<'a> AccessIdentity<'a> {
    /// 取得实际文件操作使用的文件系统身份。
    pub fn filesystem(credentials: &'a crate::task::Credentials) -> Self {
        Self {
            uid: credentials.fsuid,
            gid: credentials.fsgid,
            groups: &credentials.groups,
        }
    }

    /// 取得 access 查询身份；默认使用真实号，effective 沿用文件系统身份。
    pub fn for_access(credentials: &'a crate::task::Credentials, effective: bool) -> Self {
        if effective {
            Self::filesystem(credentials)
        } else {
            Self {
                uid: credentials.ruid,
                gid: credentials.rgid,
                groups: &credentials.groups,
            }
        }
    }
}

impl Metadata {
    /// 返回文件系统内部使用的 inode 句柄。
    pub(crate) fn inode_handle(&self) -> u32 {
        self.handle.unwrap_or(self.ino as u32)
    }

    /// 按文件系统凭证检查目录权限位，权限不足返回 EACCES。
    pub(super) fn check_directory_access(
        &self,
        credentials: &crate::task::Credentials,
        required: u16,
    ) -> Result<(), Errno> {
        if self.mode & 0xf000 != 0x4000 {
            return Err(Errno::NotDir);
        }
        self.check_access(AccessIdentity::filesystem(credentials), required)
    }

    /// 检查读、写、执行权限位；任一请求位未获授权时返回 EACCES。
    pub(super) fn check_access(
        &self,
        identity: AccessIdentity<'_>,
        required: u16,
    ) -> Result<(), Errno> {
        if identity.uid == 0 {
            if required & 1 != 0 && self.mode & 0xf000 == 0x8000 && self.mode & 0o111 == 0 {
                return Err(Errno::Access);
            }
            return Ok(());
        }
        let shift = if identity.uid == self.uid {
            6
        } else if identity.gid == self.gid || identity.groups.contains(&self.gid) {
            3
        } else {
            0
        };
        if (self.mode >> shift) & required != required {
            return Err(Errno::Access);
        }
        Ok(())
    }
}

/// 按 inode 取得后端元数据，失败返回后端错误。
pub(super) fn metadata(ino: u32) -> Result<Metadata, Errno> {
    if ino == super::procfs::DEVNULL {
        return Ok(super::procfs::null_metadata());
    }
    if ino == super::procfs::DEVZERO {
        return Ok(super::procfs::zero_metadata());
    }
    if ino == super::procfs::DEVURANDOM {
        return Ok(super::procfs::random_metadata(true));
    }
    if ino == super::procfs::DEVRANDOM {
        return Ok(super::procfs::random_metadata(false));
    }
    if ino == super::procfs::MEMINFO {
        return super::procfs::metadata();
    }
    if ino == super::procfs::DEVBLK {
        return Ok(Metadata {
            ino: ino.into(),
            mode: 0o060600,
            links: 1,
            block_size: 4096,
            ..Default::default()
        });
    }
    // procfs 虚拟节点（/proc、/proc/<pid>、/dev/*）无后端 inode，按统一
    // stat 结果合成，避免 resolve 逐分量解析时把虚拟节点当 ext4 处理
    if super::procfs::is_virtual_ino(ino) {
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
    if ext2_mount::is_handle(ino) {
        ext2_mount::metadata(ino)
    } else if ino & FAT_INODE != 0 {
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

fn is_clean_ext4_path(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    if !path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path == "/proc"
        || path.starts_with("/proc/")
        || path == "/dev"
        || path.starts_with("/dev/")
    {
        return false;
    }
    !path.split('/').any(|s| s == "." || s == "..")
}

/// 查询绝对路径；follow 只控制末项链接，最多跟随 40 个链接。
pub(crate) fn query(path: &str, follow: bool) -> Result<Metadata, Errno> {
    if is_clean_ext4_path(path) && !fat::has_mounts() && !ext2_mount::has_mounts() {
        if let Ok(Some(info)) = ext4::fast_metadata(path) {
            return Ok(info);
        }
    }
    resolve(path, follow).map(|(_, info)| info)
}

/// 解析绝对路径并返回规范路径及属性；保留与 query 相同的链接规则。
pub(crate) fn resolve(path: &str, follow: bool) -> Result<(String, Metadata), Errno> {
    let (path, target) = resolve_entry(path, follow, false)?;
    match target {
        ResolvedEntry::Existing(info) => Ok((path, info)),
        ResolvedEntry::Missing { .. } => Err(Errno::NoEntry),
    }
}

/// 路径末项存在，或可在已确认的父目录下新建。
pub(crate) enum ResolvedEntry {
    Existing(Metadata),
    Missing { parent: u32 },
}

/// 解析路径并保留规范名称；allow_create 只允许末项不存在。
pub(super) fn resolve_entry(
    path: &str,
    follow: bool,
    allow_create: bool,
) -> Result<(String, ResolvedEntry), Errno> {
    resolve_entry_from("/", path, follow, allow_create, None)
}

/// 从给定目录解析路径，并按调用者凭证检查沿途目录的搜索权限。
pub(super) fn resolve_with_credentials(
    base: &str,
    path: &str,
    follow: bool,
    credentials: &crate::task::Credentials,
) -> Result<(String, Metadata), Errno> {
    resolve_with_identity(base, path, follow, AccessIdentity::filesystem(credentials))
}

/// 按指定身份解析路径；沿途目录必须授予搜索权限。
pub(super) fn resolve_with_identity(
    base: &str,
    path: &str,
    follow: bool,
    identity: AccessIdentity<'_>,
) -> Result<(String, Metadata), Errno> {
    match resolve_entry_from(base, path, follow, false, Some(identity))? {
        (path, ResolvedEntry::Existing(info)) => Ok((path, info)),
        (_, ResolvedEntry::Missing { .. }) => Err(Errno::NoEntry),
    }
}

fn resolve_entry_from(
    base: &str,
    path: &str,
    follow: bool,
    allow_create: bool,
    identity: Option<AccessIdentity<'_>>,
) -> Result<(String, ResolvedEntry), Errno> {
    let mut pending = string(path)?;
    let mut current = string(if path.starts_with('/') { "/" } else { base })?;
    let mut info = metadata(lookup(&current)?)?;
    let mut cursor = 0;
    let mut links = 0;
    let mut saw_symlink = false;
    while cursor < pending.len() {
        if info.mode & 0xf000 != 0x4000 {
            return Err(Errno::NotDir);
        }
        let rest = pending[cursor..].trim_start_matches('/');
        if rest.is_empty() {
            break;
        }
        if let Some(identity) = identity {
            info.check_access(identity, 1)?;
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
                let ino = match lookup(&candidate) {
                    Ok(ino) => ino,
                    Err(Errno::NoEntry) if allow_create && suffix.is_empty() => {
                        return Ok((
                            candidate,
                            ResolvedEntry::Missing {
                                parent: info.inode_handle(),
                            },
                        ));
                    }
                    Err(e) => return Err(e),
                };
                let child = metadata(ino)?;
                if child.mode & 0xf000 == 0xa000 && (follow || !suffix.is_empty()) {
                    saw_symlink = true;
                    links += 1;
                    if links > 40 {
                        return Err(Errno::Loop);
                    }
                    let mut target = super::read_link(ino)?;
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
    if identity.is_none()
        && !saw_symlink
        && info.mode & 0xf000 != 0xa000
        && is_clean_ext4_path(&current)
        && !fat::has_mounts()
        && !ext2_mount::has_mounts()
    {
        ext4::mark_direct_stat(&current, info.inode_handle());
    }
    Ok((current, ResolvedEntry::Existing(info)))
}
