//! 进程工作目录、FD 表和打开文件对象；提供内核缓冲区读写与管道操作。
#![deny(unsafe_code)]
use crate::{
    fs,
    mm::{address_space::UserAddressSpace, user_access},
    syscall::Errno,
};
use alloc::{
    collections::VecDeque,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

/// pipe 缓冲容量（对齐 Linux 默认 64KiB）；写满/读空时阻塞等待。
const PIPE_CAPACITY: usize = 65536;
const FD_DEFAULT_SOFT: usize = 1024;
const FD_DEFAULT_HARD: usize = 4096;
const FD_HARD_MAX: usize = 65536;
const OPEN_CREATION_FLAGS: usize = 0x40 | 0x80 | 0x100 | 0x200 | 0x80000;

static DIRECTORIES: Mutex<Vec<Weak<DirectoryPath>>> = Mutex::new(Vec::new());

struct DirectoryPath {
    path: String,
    ino: Option<u32>,
    detached: AtomicBool,
}

impl DirectoryPath {
    fn path(&self) -> Result<&str, Errno> {
        if self.detached.load(Ordering::Acquire) {
            return Err(Errno::NoEntry);
        }
        Ok(&self.path)
    }
}

impl Drop for DirectoryPath {
    fn drop(&mut self) {
        if let Some(ino) = self.ino {
            fs::release(ino);
        }
    }
}

fn directory_path(path: String, ino: Option<u32>) -> Result<Arc<DirectoryPath>, Errno> {
    if let Some(ino) = ino {
        fs::retain(ino)?;
    }
    let path = fs::try_arc(DirectoryPath {
        path,
        ino,
        detached: AtomicBool::new(false),
    })?;
    let mut paths = DIRECTORIES.lock();
    paths.retain(|p| p.strong_count() != 0);
    paths.try_reserve(1).map_err(|_| Errno::NoMem)?;
    paths.push(Arc::downgrade(&path));
    Ok(path)
}

fn contains(parent: &str, path: &str) -> bool {
    parent == "/"
        || path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|s| s.starts_with('/'))
}

pub(crate) fn directory_busy(path: &str) -> bool {
    DIRECTORIES
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .any(|p| p.path().is_ok_and(|candidate| contains(path, candidate)))
}

/// 标记已从名字空间移除的目录；现有引用继续持有 inode。
pub(super) fn detach_directory(ino: u32) {
    for path in DIRECTORIES.lock().iter().filter_map(Weak::upgrade) {
        if path.ino == Some(ino) {
            path.detached.store(true, Ordering::Release);
        }
    }
}

/// 下一个新建管道的唯一实例号；单调递增，0 保留表示槽位空闲。
static NEXT_PIPE_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

struct Pipe {
    data: VecDeque<u8>,
    readers: usize,
    writers: usize,
}
enum Kind {
    Input,
    Output,
    Pipe {
        id: u64,
        pipe: Arc<Mutex<Pipe>>,
        reading: bool,
    },
    Inode {
        ino: u32,
        path: String,
        directory: Option<Arc<DirectoryPath>>,
    },
    MemInfo(String),
    /// /dev/null：读 EOF、写全收（见 fs::procfs::DEVNULL）
    DevNull,
    /// /dev/zero：读返回零填充，写入丢弃。
    DevZero,
    /// /dev/urandom 与 /dev/random：读返回内核熵流字节，写入丢弃。
    DevRandom {
        urandom: bool,
    },
    /// /dev/misc/rtc：仅支持 ioctl 的 RTC 查询设备
    Rtc,
    /// /dev 下的块设备节点：按节点登记的 (盘, 分区) 通用块访问
    DevBlk {
        disk: usize,
        start: usize,
        len: u64,
    },
    /// 本地回环套接字句柄
    Socket(crate::net::SocketId),
}
/// 共享偏移、打开标志和文件资源的持有者。
pub(crate) struct OpenFile {
    kind: Kind,
    offset: usize,
    flags: usize,
}
impl Drop for OpenFile {
    fn drop(&mut self) {
        match &self.kind {
            Kind::Inode {
                ino,
                directory: None,
                ..
            } => fs::release(*ino),
            Kind::Pipe { id, pipe, reading } => {
                let mut p = pipe.lock();
                if *reading {
                    p.readers -= 1;
                } else {
                    p.writers -= 1;
                }
                // 对端计数变化可能使等待者可读（EOF）或写失败（EPIPE），
                // 按管道实例定向唤醒；无锁原子槽位，可在任意持锁环境下调用。
                crate::task::sched::request_pipe_id_wake(*id);
            }
            Kind::Socket(id) => {
                crate::net::close(*id);
            }
            _ => {}
        }
    }
}
/// FD 表与调用期间共同持有的打开文件引用。
pub(crate) type Handle = Arc<Mutex<OpenFile>>;
#[derive(Clone)]
struct Descriptor {
    handle: Handle,
    cloexec: bool,
}

/// 进程拥有 fd 表副本，共享打开文件描述，工作目录独立。
pub struct Context {
    cwd: Arc<DirectoryPath>,
    fds: Vec<Option<Descriptor>>,
    nofile_limit: [usize; 2],
    umask: u16,
    /// 本进程最近一次 execve 的绝对路径（/proc/self/exe 的目标，proc(5)）。
    /// 内核内嵌启动的程序没有盘上路径，保持为空串。
    exe_path: String,
}
fn string(s: &str) -> Result<String, Errno> {
    let mut result = String::new();
    result.try_reserve(s.len()).map_err(|_| Errno::NoMem)?;
    result.push_str(s);
    Ok(result)
}
impl Context {
    /// 初始根目录和标准输入输出。
    pub fn new() -> Result<Self, Errno> {
        let mut fds = Vec::new();
        fds.try_reserve(3).map_err(|_| Errno::NoMem)?;
        for kind in [Kind::Input, Kind::Output, Kind::Output] {
            fds.push(Some(Descriptor {
                handle: crate::fs::try_arc(Mutex::new(OpenFile {
                    flags: if matches!(kind, Kind::Input) { 0 } else { 1 },
                    kind,
                    offset: 0,
                }))?,
                cloexec: false,
            }));
        }
        Ok(Self {
            cwd: directory_path(string("/")?, None)?,
            fds,
            nofile_limit: [FD_DEFAULT_SOFT, FD_DEFAULT_HARD],
            umask: 0o022,
            exe_path: String::new(),
        })
    }
    /// fork 复制描述符表，保留共享偏移。
    pub fn fork(&self) -> Result<Self, Errno> {
        let mut fds = Vec::new();
        fds.try_reserve(self.fds.len()).map_err(|_| Errno::NoMem)?;
        fds.extend(self.fds.iter().cloned());
        Ok(Self {
            cwd: self.cwd.clone(),
            fds,
            nofile_limit: self.nofile_limit,
            umask: self.umask,
            exe_path: self.exe_path.clone(),
        })
    }
    /// 查询本进程 RLIMIT_NOFILE 的软硬限额。
    pub(crate) fn nofile_limit(&self) -> [usize; 2] {
        self.nofile_limit
    }
    /// 修改本进程 RLIMIT_NOFILE；降低不关闭已打开描述符，非特权进程不得抬高硬限额。
    pub(crate) fn set_nofile_limit(
        &mut self,
        limit: [usize; 2],
        privileged: bool,
    ) -> Result<(), Errno> {
        if limit[0] > limit[1] {
            return Err(Errno::Invalid);
        }
        if !privileged && limit[1] > self.nofile_limit[1] {
            return Err(Errno::Perm);
        }
        if limit[1] > FD_HARD_MAX {
            return Err(Errno::Perm);
        }
        self.nofile_limit = limit;
        Ok(())
    }
    fn fd_limit(&self) -> usize {
        self.nofile_limit[0].min(FD_HARD_MAX)
    }
    /// 记录最近一次 execve 的绝对路径（供 /proc/self/exe 解析）。
    /// 接收调用方已分配好的 String：本方法处于 exec 提交段，无失败路径。
    pub(crate) fn set_exe_path_owned(&mut self, value: String) {
        self.exe_path = value;
    }
    /// 设置创建权限掩码，仅保存权限位并返回旧值。
    pub(crate) fn set_umask(&mut self, mask: usize) -> usize {
        let previous = self.umask;
        self.umask = mask as u16 & 0o777;
        previous as usize
    }

    /// 对新建文件和目录的请求权限应用当前进程掩码。
    pub(crate) fn creation_mode(&self, mode: usize) -> u16 {
        mode as u16 & 0o777 & !self.umask
    }

    /// 取得打开文件引用，无效 FD 返回 EBADF。
    pub(crate) fn get(&self, fd: usize) -> Result<Handle, Errno> {
        self.fds
            .get(fd)
            .and_then(|f| f.as_ref().map(|d| d.handle.clone()))
            .ok_or(Errno::BadF)
    }
    /// 安装打开文件，返回最低可用 FD；超出 RLIMIT_NOFILE 返回 EMFILE。
    pub(crate) fn install(&mut self, file: Handle, cloexec: bool) -> Result<usize, Errno> {
        self.install_at(file, 0, cloexec, false)
    }

    /// 从指定下界安装到最低空闲 FD；下界超出 RLIMIT_NOFILE 返回 EINVAL，表满返回 EMFILE。
    pub(crate) fn install_from(
        &mut self,
        file: Handle,
        minimum: usize,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        self.install_at(file, minimum, cloexec, true)
    }

    fn install_at(
        &mut self,
        file: Handle,
        minimum: usize,
        cloexec: bool,
        reject_min_over_limit: bool,
    ) -> Result<usize, Errno> {
        let limit = self.fd_limit();
        if minimum >= limit {
            return Err(if reject_min_over_limit {
                Errno::Invalid
            } else {
                Errno::TooManyFiles
            });
        }
        let search_end = self.fds.len().min(limit);
        if let Some(i) = (minimum..search_end).find(|&i| self.fds[i].is_none()) {
            self.fds[i] = Some(Descriptor {
                handle: file,
                cloexec,
            });
            return Ok(i);
        }
        let i = minimum.max(self.fds.len());
        if i >= limit {
            return Err(Errno::TooManyFiles);
        }
        self.fds
            .try_reserve(i + 1 - self.fds.len())
            .map_err(|_| Errno::NoMem)?;
        self.fds.resize_with(i, || None);
        self.fds.push(Some(Descriptor {
            handle: file,
            cloexec,
        }));
        Ok(i)
    }

    /// 查询 FD_CLOEXEC；无效描述符返回 EBADF。
    pub(crate) fn descriptor_flags(&self, fd: usize) -> Result<usize, Errno> {
        self.fds
            .get(fd)
            .and_then(Option::as_ref)
            .map(|d| usize::from(d.cloexec))
            .ok_or(Errno::BadF)
    }

    /// 设置本描述符的 FD_CLOEXEC，忽略其他位；无效描述符返回 EBADF。
    pub(crate) fn set_descriptor_flags(&mut self, fd: usize, flags: usize) -> Result<usize, Errno> {
        let descriptor = self
            .fds
            .get_mut(fd)
            .and_then(Option::as_mut)
            .ok_or(Errno::BadF)?;
        descriptor.cloexec = flags & 1 != 0;
        Ok(0)
    }
    /// 相对工作目录或目录 FD 解析路径，失败返回路径错误。
    pub(crate) fn path(&self, dir: usize, input: &str) -> Result<String, Errno> {
        if input.is_empty() {
            return Err(Errno::NoEntry);
        }
        let mut out = if input.starts_with('/') {
            string("/")?
        } else if dir as isize == -100 {
            string(self.cwd()?)?
        } else {
            string(self.get(dir)?.lock().directory_path()?)?
        };
        out.try_reserve(input.len() + 1).map_err(|_| Errno::NoMem)?;
        let mut parent_end = None;
        for component in input.split('/') {
            match component {
                "" => {}
                "." | ".." => {
                    directory(&out)?;
                    parent_end = None;
                    if component == ".." {
                        if let Some(i) = out.rfind('/') {
                            out.truncate(i.max(1));
                        }
                    }
                }
                name => {
                    if name.len() > 255 {
                        directory(&out)?;
                        return Err(Errno::NameTooLong);
                    }
                    parent_end = Some(out.len());
                    if out != "/" {
                        out.push('/');
                    }
                    out.push_str(name);
                }
            }
        }
        // 后端会检查中间目录；只验证末项的父目录，末项允许尚不存在。
        if let Some(end) = parent_end {
            directory(&out[..end])?;
        }
        if out.len() > 4096 {
            return Err(Errno::NameTooLong);
        }
        Ok(out)
    }
    /// 状态查询保留原始路径分量，由 FS 处理链接、点分量与尾斜杠。
    pub(crate) fn query(
        &self,
        dir: usize,
        input: &str,
        empty: bool,
        follow: bool,
    ) -> Result<fs::Metadata, Errno> {
        if input == "/proc" {
            return Ok(fs::Metadata {
                ino: super::procfs::DIR as u64,
                mode: 0o040555,
                links: 2,
                block_size: 4096,
                ..Default::default()
            });
        }
        if input == "/proc/meminfo" {
            return super::procfs::metadata();
        }
        if input.is_empty() && empty {
            if dir as isize == -100 {
                if let Some(ino) = self.cwd.ino {
                    return fs::metadata::metadata(ino);
                }
                return fs::query(self.cwd()?, true);
            }
            return self.get(dir)?.lock().metadata();
        }
        if input.is_empty() {
            return Err(Errno::NoEntry);
        }
        if input.starts_with('/') {
            return fs::query(input, follow);
        }
        fs::query(&self.absolute_path(dir, input)?, follow)
    }

    fn absolute_path(&self, dir: usize, input: &str) -> Result<String, Errno> {
        let mut path = if dir as isize == -100 {
            string(self.cwd()?)?
        } else {
            string(self.get(dir)?.lock().directory_path()?)?
        };
        path.try_reserve(input.len() + 1)
            .map_err(|_| Errno::NoMem)?;
        if path != "/" {
            path.push('/');
        }
        path.push_str(input);
        Ok(path)
    }

    /// 解析供 openat 使用的路径，允许在已解析的父目录中创建末项。
    pub(crate) fn open_path(
        &self,
        dir: usize,
        input: &str,
        follow: bool,
        allow_create: bool,
    ) -> Result<(String, fs::ResolvedEntry), Errno> {
        if input.is_empty() {
            return Err(Errno::NoEntry);
        }
        if input.starts_with('/') {
            fs::metadata::resolve_entry(input, follow, allow_create)
        } else {
            fs::metadata::resolve_entry(&self.absolute_path(dir, input)?, follow, allow_create)
        }
    }

    /// 返回当前工作目录路径。已删名的目录返回 ENOENT。
    pub(crate) fn cwd(&self) -> Result<&str, Errno> {
        self.cwd.path()
    }

    /// 持有调用方已验证的工作目录。根目录无需额外保留。
    pub(crate) fn set_cwd(&mut self, path: String, ino: u32) -> Result<(), Errno> {
        let retained = (path != "/" && ino & fs::FAT_INODE == 0).then_some(ino);
        self.cwd = directory_path(path, retained)?;
        Ok(())
    }

    fn entry_path(&self, dir: usize, input: &str) -> Result<(String, u32, String), Errno> {
        if input.is_empty() {
            return Err(Errno::NoEntry);
        }
        let trimmed = input.trim_end_matches('/');
        let (parent, name) = match trimmed.rsplit_once('/') {
            Some(("", name)) => ("/", name),
            Some(parts) => parts,
            None => (".", trimmed),
        };
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(Errno::Busy);
        }
        if name.len() > 255 {
            return Err(Errno::NameTooLong);
        }
        let mut base = if input.starts_with('/') {
            string("")?
        } else if dir as isize == -100 {
            string(self.cwd()?)?
        } else {
            string(self.get(dir)?.lock().directory_path()?)?
        };
        base.try_reserve(parent.len() + 1)
            .map_err(|_| Errno::NoMem)?;
        if !base.is_empty() {
            base.push('/');
        }
        base.push_str(parent);
        let (mut canonical, info) = fs::metadata::resolve(&base, true)?;
        if info.mode & 0xf000 != 0x4000 {
            return Err(Errno::NotDir);
        }
        canonical
            .try_reserve(name.len() + 1)
            .map_err(|_| Errno::NoMem)?;
        if canonical != "/" {
            canonical.push('/');
        }
        canonical.push_str(name);
        if canonical.len() >= 4096 {
            return Err(Errno::NameTooLong);
        }
        Ok((canonical, info.ino as u32, string(name)?))
    }

    fn new_entry_path(&self, dir: usize, path: &str) -> Result<(u32, String), Errno> {
        if path.ends_with('/') || matches!(path.rsplit('/').next(), Some("." | "..")) {
            let trimmed = path.trim_end_matches('/');
            let target = if trimmed.is_empty() { "/" } else { trimmed };
            self.query(dir, target, false, false)?;
            return Err(Errno::Exists);
        }
        let (_, parent, name) = self.entry_path(dir, path)?;
        Ok((parent, name))
    }

    /// 在指定目录下创建符号链接，目标文本由读取或跟随链接时使用。
    pub(crate) fn symlink(
        &self,
        dir: usize,
        path: &str,
        target: &str,
        credentials: &crate::task::Credentials,
    ) -> Result<(), Errno> {
        if target.is_empty() {
            return Err(Errno::NoEntry);
        }
        let (parent, name) = self.new_entry_path(dir, path)?;
        fs::symlink(parent, &name, target, credentials.fsuid, credentials.fsgid)
    }

    /// 将源 inode 添加到目标父目录，按 follow 决定是否跟随源路径末项。
    pub(crate) fn link(
        &self,
        old_dir: usize,
        old: &str,
        new_dir: usize,
        new: &str,
        follow: bool,
    ) -> Result<(), Errno> {
        let source = self.query(old_dir, old, false, follow)?;
        let (parent, name) = self.new_entry_path(new_dir, new)?;
        fs::link(&source, parent, &name)
    }

    /// 删除末项名称，符号链接按其自身的 inode 处理。
    pub(crate) fn unlink(&self, dir: usize, input: &str) -> Result<(), Errno> {
        let path = input.trim_end_matches('/');
        let path = if path.is_empty() && !input.is_empty() {
            "/"
        } else {
            path
        };
        let source = self.query(dir, path, false, false)?;
        if source.mode & 0xf000 == 0x4000 {
            return Err(Errno::IsDir);
        }
        if input.ends_with('/') {
            return Err(Errno::NotDir);
        }
        let (_, parent, name) = self.entry_path(dir, input)?;
        fs::unlink(parent, source.ino as u32, &name)
    }

    /// 重命名文件或目录；拒绝移动仍由 cwd、目录 FD 或挂载引用的目录树。
    pub(crate) fn rename(
        &self,
        old_dir: usize,
        old: &str,
        new_dir: usize,
        new: &str,
        no_replace: bool,
    ) -> Result<(), Errno> {
        let (old_path, old_parent, old_name) = self.entry_path(old_dir, old)?;
        let (new_path, new_parent, new_name) = self.entry_path(new_dir, new)?;
        let source = fs::query(&old_path, false)?;
        let target = match fs::query(&new_path, false) {
            Ok(info) => Some(info),
            Err(Errno::NoEntry) => None,
            Err(error) => return Err(error),
        };
        if (old.ends_with('/') || new.ends_with('/')) && source.mode & 0xf000 != 0x4000 {
            return Err(Errno::NotDir);
        }
        if new.ends_with('/') && target.as_ref().is_some_and(|t| t.mode & 0xf000 != 0x4000) {
            return Err(Errno::NotDir);
        }
        if no_replace && target.is_some() {
            return Err(Errno::Exists);
        }
        if source.mode & 0xf000 == 0x4000 && contains(&old_path, &new_path) && old_path != new_path
        {
            return Err(Errno::Invalid);
        }
        if fs::fat::contains_mount(&old_path) || fs::fat::contains_mount(&new_path) {
            return Err(Errno::Busy);
        }
        if !no_replace
            && target
                .as_ref()
                .is_some_and(|t| t.dev == source.dev && t.ino == source.ino)
        {
            return fs::rename(old_parent, &old_name, new_parent, &new_name, false);
        }
        if source.mode & 0xf000 == 0x4000 && directory_busy(&old_path)
            || target.as_ref().is_some_and(|t| t.mode & 0xf000 == 0x4000)
                && directory_busy(&new_path)
        {
            return Err(Errno::Busy);
        }
        fs::rename(old_parent, &old_name, new_parent, &new_name, no_replace)
    }

    /// 将打开文件复制到指定 FD，替换原描述符。
    pub(crate) fn dup_to(&mut self, from: usize, to: usize, cloexec: bool) -> Result<usize, Errno> {
        let file = self.get(from)?;
        if to >= self.fd_limit() {
            return Err(Errno::BadF);
        }
        if to >= self.fds.len() {
            self.fds
                .try_reserve(to + 1 - self.fds.len())
                .map_err(|_| Errno::NoMem)?;
            self.fds.resize_with(to + 1, || None);
        }
        self.fds[to] = Some(Descriptor {
            handle: file,
            cloexec,
        });
        Ok(to)
    }

    /// 关闭 FD 并释放引用，无效 FD 返回 EBADF。
    pub(crate) fn close(&mut self, fd: usize) -> Result<(), Errno> {
        self.fds
            .get_mut(fd)
            .ok_or(Errno::BadF)?
            .take()
            .ok_or(Errno::BadF)?;
        Ok(())
    }

    /// 安装 inode 的打开文件对象，失败自动释放已持有的引用。
    pub(crate) fn open_inode(
        &mut self,
        ino: u32,
        path: String,
        flags: usize,
        cloexec: bool,
        is_directory: bool,
    ) -> Result<usize, Errno> {
        let directory = if is_directory {
            Some(directory_path(string(&path)?, Some(ino))?)
        } else {
            fs::retain(ino)?;
            None
        };
        self.install(
            fs::try_arc(Mutex::new(OpenFile {
                kind: Kind::Inode {
                    ino,
                    path,
                    directory,
                },
                offset: 0,
                flags: flags & !OPEN_CREATION_FLAGS,
            }))?,
            cloexec,
        )
    }

    /// 打开只读 /proc/meminfo 快照。
    pub(crate) fn open_meminfo(&mut self, flags: usize, cloexec: bool) -> Result<usize, Errno> {
        self.open_proc_text(super::procfs::meminfo()?, flags, cloexec)
    }

    /// 打开任意 procfs 只读文本快照（meminfo/mounts/pid 文件共用）。
    pub(crate) fn open_proc_text(
        &mut self,
        text: String,
        flags: usize,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        if flags & (3 | 0x200) != 0 {
            return Err(Errno::ReadOnly);
        }
        if flags & 0x10000 != 0 {
            return Err(Errno::NotDir);
        }
        let file = OpenFile {
            kind: Kind::MemInfo(text),
            offset: 0,
            flags: flags & !OPEN_CREATION_FLAGS,
        };
        self.install(fs::try_arc(Mutex::new(file))?, cloexec)
    }

    /// 打开 /dev/null：读恒 EOF、写全部接收并丢弃。
    pub(crate) fn open_devnull(&mut self, flags: usize, cloexec: bool) -> Result<usize, Errno> {
        self.open_special(Kind::DevNull, flags, cloexec)
    }

    /// 打开 /dev/zero；独占创建已存在的节点返回 EEXIST。
    pub(crate) fn open_devzero(&mut self, flags: usize, cloexec: bool) -> Result<usize, Errno> {
        if flags & 0xc0 == 0xc0 {
            return Err(Errno::Exists);
        }
        self.open_special(Kind::DevZero, flags, cloexec)
    }

    /// 打开 /dev/urandom 或 /dev/random；独占创建已存在的节点返回 EEXIST。
    pub(crate) fn open_devrandom(
        &mut self,
        urandom: bool,
        flags: usize,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        if flags & 0xc0 == 0xc0 {
            return Err(Errno::Exists);
        }
        self.open_special(Kind::DevRandom { urandom }, flags, cloexec)
    }

    /// fchmod(2)（fd, mode）：按已打开对象的 inode 身份改权限位，
    /// rename/unlink 后仍有效；非 inode FD 返回 ENOENT（fd 无权限位语义）。
    pub(crate) fn fchmod_fd(
        &self,
        fd: usize,
        mode: usize,
        space: &crate::mm::address_space::UserAddressSpace,
    ) -> Result<usize, Errno> {
        let handle = self.get(fd)?;
        let (ino, path) = {
            let f = handle.lock();
            let Kind::Inode { ino, path, .. } = &f.kind else {
                return Err(Errno::NoEntry);
            };
            if f.detached_directory() {
                return Err(Errno::NoEntry);
            }
            (*ino, path.clone())
        };
        super::chmod_apply(path.as_str(), ino, mode, space)
    }

    /// ioctl(2) 的设备分派：当前仅 RTC 设备支持 RTC_RD_TIME（读硬件
    /// 墙上时钟，按 linux/rtc.h 的 struct rtc_time 九个 int 拷贝到用户
    /// 缓冲）；其余命令与设备一律 ENOTTY，不假装成功。
    pub(crate) fn ioctl(
        &self,
        fd: usize,
        cmd: usize,
        arg: usize,
        space: &crate::mm::address_space::UserAddressSpace,
    ) -> Result<usize, Errno> {
        // _IOR('p', 0x09, struct rtc_time)：32 位方向/大小/类型/序号编码
        const RTC_RD_TIME: usize = 0x8024_7009;
        let file = self.get(fd)?;
        let f = file.lock();
        // ioctl(2) 的 cmd 是 unsigned int：部分 libc（如 musl）把负的 int
        // 常量符号扩展到 64 位寄存器，比较前统一截断为 32 位
        if !matches!(f.kind, Kind::Rtc) || (cmd as u32) as usize != RTC_RD_TIME {
            return Err(Errno::InappropriateIoctl);
        }
        let Some(secs) = crate::drivers::rtc::read_utc_seconds() else {
            return Err(Errno::Io);
        };
        let tm = crate::drivers::rtc::epoch_to_tm(secs);
        let mut bytes = [0u8; 36];
        for (i, word) in tm.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
        }
        crate::mm::user_access::copy_to_user(space, arg, &bytes).map_err(|_| Errno::Fault)?;
        Ok(0)
    }

    /// 打开 /dev/misc/rtc：RTC 查询设备，ioctl(RTC_RD_TIME) 读时间。
    pub(crate) fn open_rtc(&mut self, flags: usize, cloexec: bool) -> Result<usize, Errno> {
        self.open_special(Kind::Rtc, flags, cloexec)
    }

    /// 打开 /dev 下注册的块设备节点：通用块访问（读/写按分区边界）。
    pub(crate) fn open_devblk(
        &mut self,
        disk: usize,
        start: usize,
        len: u64,
        flags: usize,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        if flags & 0x10000 != 0 {
            return Err(Errno::NotDir);
        }
        if flags & 0xc00 != 0 {
            // O_APPEND|O_DIRECT 未支持（块访问按 offset 语义）
            return Err(Errno::Invalid);
        }
        let file = OpenFile {
            kind: Kind::DevBlk { disk, start, len },
            offset: 0,
            flags: flags & !OPEN_CREATION_FLAGS,
        };
        self.install(fs::try_arc(Mutex::new(file))?, cloexec)
    }

    /// 打开无数据的字符设备（flags 只保留打开方式，无创建位）。
    fn open_special(&mut self, kind: Kind, flags: usize, cloexec: bool) -> Result<usize, Errno> {
        if flags & 0x10000 != 0 {
            return Err(Errno::NotDir);
        }
        let file = OpenFile {
            kind,
            offset: 0,
            flags: flags & !OPEN_CREATION_FLAGS,
        };
        self.install(fs::try_arc(Mutex::new(file))?, cloexec)
    }

    /// 若 `fd` 指向管道端，返回其唯一实例号，供调度器定向等待。
    pub(crate) fn pipe_id(&self, fd: usize) -> Option<u64> {
        let handle = self.get(fd).ok()?;
        let file = handle.lock();
        match file.kind {
            Kind::Pipe { id, .. } => Some(id),
            _ => None,
        }
    }

    /// 创建管道两端，安装失败时回收已安装的 FD。
    pub(crate) fn pipe(&mut self, flags: usize) -> Result<(usize, usize), Errno> {
        let mut data = VecDeque::new();
        data.try_reserve(4096).map_err(|_| Errno::NoMem)?;
        let id = NEXT_PIPE_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let pipe = fs::try_arc(Mutex::new(Pipe {
            data,
            readers: 1,
            writers: 1,
        }))?;
        let r = fs::try_arc(Mutex::new(OpenFile {
            kind: Kind::Pipe {
                id,
                pipe: pipe.clone(),
                reading: true,
            },
            offset: 0,
            flags: flags & 0x800,
        }))?;
        let w = fs::try_arc(Mutex::new(OpenFile {
            kind: Kind::Pipe {
                id,
                pipe,
                reading: false,
            },
            offset: 0,
            flags: (flags & 0x800) | 1,
        }))?;
        let rfd = self.install(r, flags & 0x80000 != 0)?;
        let wfd = match self.install(w, flags & 0x80000 != 0) {
            Ok(fd) => fd,
            Err(e) => {
                self.fds[rfd] = None;
                return Err(e);
            }
        };
        Ok((rfd, wfd))
    }

    /// 将新创建的套接字句柄安装到 FD 表（默认 O_RDWR，按需置 O_NONBLOCK/FD_CLOEXEC）。
    /// 安装失败时自动关闭套接字句柄，避免泄漏。
    pub(crate) fn open_socket(
        &mut self,
        id: crate::net::SocketId,
        nonblock: bool,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        let flags = 2 | if nonblock { 0x800 } else { 0 };
        let file = match fs::try_arc(Mutex::new(OpenFile {
            kind: Kind::Socket(id),
            offset: 0,
            flags,
        })) {
            Ok(f) => f,
            Err(e) => {
                crate::net::close(id);
                return Err(e);
            }
        };
        // 若 install 失败，file 被 drop，OpenFile::drop 自动调用 net::close(id)。
        self.install(file, cloexec)
    }

    /// 查询 FD 对应的套接字句柄与当前 O_NONBLOCK 状态；非套接字返回 ENOTSOCK。
    pub(crate) fn socket_id(&self, fd: usize) -> Result<(crate::net::SocketId, bool), Errno> {
        let handle = self.get(fd)?;
        let f = handle.lock();
        match f.kind {
            Kind::Socket(id) => Ok((id, f.flags & 0x800 != 0)),
            _ => Err(Errno::NotSock),
        }
    }
}

/// 确认路径存在且为目录。
fn directory(path: &str) -> Result<(), Errno> {
    if fs::stat(fs::lookup(path)?)?.0 & 0xf000 != 0x4000 {
        return Err(Errno::NotDir);
    }
    Ok(())
}

impl OpenFile {
    /// 按可写 FD 调整普通文件长度，不改变共享文件偏移；其他对象返回 EINVAL。
    pub(crate) fn truncate(&self, length: u64) -> Result<(), Errno> {
        if self.flags & 0x200000 != 0 {
            return Err(Errno::BadF);
        }
        if self.flags & 3 == 0 {
            return Err(Errno::Invalid);
        }
        match self.kind {
            Kind::Inode { ino, .. } if fs::stat(ino)?.0 & 0xf000 == 0x8000 => {
                fs::truncate(ino, length)
            }
            _ => Err(Errno::Invalid),
        }
    }

    /// 查询共享的访问模式和文件状态标志。
    pub(crate) fn status_flags(&self) -> usize {
        self.flags
    }

    /// 更新共享的追加、非阻塞标志；未实现的可变标志返回 EOPNOTSUPP。
    pub(crate) fn set_status_flags(&mut self, flags: usize) -> Result<usize, Errno> {
        if flags & (0x2000 | 0x4000 | 0x40000) != 0 {
            return Err(Errno::NotSupported);
        }
        let mutable = 0x400 | 0x800;
        self.flags = (self.flags & !mutable) | (flags & mutable);
        Ok(0)
    }

    /// 获取 inode；没有后端 inode 的对象返回 EINVAL。
    pub(crate) fn inode(&self) -> Result<u32, Errno> {
        match self.kind {
            Kind::Inode { ino, .. } => Ok(ino),
            _ => Err(Errno::Invalid),
        }
    }

    fn directory_path(&self) -> Result<&str, Errno> {
        match &self.kind {
            Kind::Inode {
                directory: Some(dir),
                ..
            } => dir.path(),
            _ => Err(Errno::NotDir),
        }
    }

    /// 目录仍可查询 inode，但已经不再属于名字空间。
    pub(crate) fn detached_directory(&self) -> bool {
        matches!(&self.kind, Kind::Inode { directory: Some(dir), .. }
            if dir.detached.load(Ordering::Acquire))
    }

    /// 获取目录 inode，其他对象返回 ENOTDIR。
    pub(crate) fn directory(&self) -> Result<u32, Errno> {
        match self.kind {
            Kind::Inode { ino, .. } if fs::stat(ino)?.0 & 0xf000 == 0x4000 => Ok(ino),
            _ => Err(Errno::NotDir),
        }
    }

    /// 更新打开 inode 的访问和修改时间；管道与控制台返回 EOPNOTSUPP。
    pub(crate) fn update_times(&self, times: [fs::TimeUpdate; 2]) -> Result<(), Errno> {
        match self.kind {
            Kind::Inode { ino, .. } => fs::update_times(ino, times),
            _ => Err(Errno::NotSupported),
        }
    }

    /// 查询 inode 所属卷的容量；管道与控制台尚不提供卷统计。
    pub(crate) fn filesystem_stats(&self) -> Result<fs::FileSystemStats, Errno> {
        match self.kind {
            Kind::Inode { ino, .. } => fs::filesystem_stats(ino),
            _ => Err(Errno::NotSupported),
        }
    }

    /// 返回打开对象的属性快照；管道与控制台提供合成属性。
    pub(crate) fn metadata(&self) -> Result<fs::Metadata, Errno> {
        match &self.kind {
            Kind::DevNull => Ok(super::procfs::null_metadata()),
            Kind::DevZero => Ok(super::procfs::zero_metadata()),
            Kind::DevRandom { urandom } => Ok(super::procfs::random_metadata(*urandom)),
            Kind::Inode { ino, .. } => {
                // procfs 虚拟节点（/proc、/dev/*、pid 派生）无后端 inode
                // 元数据，直接按统一 stat 结果合成
                if *ino >= super::procfs::MISC_DIR || super::procfs::pid_ino_parts(*ino).is_some() {
                    let (mode, size, links, _) = fs::stat(*ino)?;
                    return Ok(fs::Metadata {
                        ino: *ino as u64,
                        mode,
                        links: u32::from(links),
                        size,
                        block_size: 4096,
                        ..Default::default()
                    });
                }
                fs::metadata::metadata(*ino)
            }
            Kind::MemInfo(text) => Ok(fs::Metadata {
                ino: super::procfs::MEMINFO as u64,
                mode: 0o100444,
                links: 1,
                size: text.len() as u64,
                block_size: 4096,
                ..Default::default()
            }),
            Kind::Socket(_) => Ok(fs::Metadata {
                mode: 0o140777,
                links: 1,
                block_size: 4096,
                ..Default::default()
            }),
            _ => Ok(fs::Metadata {
                mode: (if matches!(&self.kind, Kind::Pipe { .. }) {
                    0x1000
                } else {
                    0x2000
                }) | 0o666,
                links: 1,
                block_size: 4096,
                ..Default::default()
            }),
        }
    }

    /// 返回共享的文件或目录偏移。
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    /// 提交调用方已经完成的目录续读位置。
    pub(crate) fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    /// 依据打开模式检查读写权限，失败返回 EBADF。
    pub(crate) fn check_access(&self, reading: bool) -> Result<(), Errno> {
        if self.flags & 0x200000 != 0
            || (reading && self.flags & 3 == 1)
            || (!reading && self.flags & 3 == 0)
        {
            return Err(Errno::BadF);
        }
        Ok(())
    }

    fn check_type(&self, first: bool) -> Result<(), Errno> {
        if first {
            if let Kind::Inode { ino, .. } = self.kind {
                if fs::stat(ino)?.0 & 0xf000 == 0x4000 {
                    return Err(Errno::IsDir);
                }
            }
        }
        Ok(())
    }

    /// 从起点、当前位置或文件末尾调整偏移；管道返回 ESPIPE。
    pub(crate) fn seek(&mut self, delta: isize, whence: usize) -> Result<usize, Errno> {
        if self.flags & 0x200000 != 0 {
            return Err(Errno::BadF);
        }
        let base = match &self.kind {
            Kind::DevZero | Kind::DevRandom { .. } if whence <= 4 => return Ok(0),
            Kind::DevZero | Kind::DevRandom { .. } => return Err(Errno::Invalid),
            Kind::Inode { ino, .. } => match whence {
                0 => 0,
                1 => self.offset,
                2 => fs::stat(*ino)?.1 as usize,
                _ => return Err(Errno::Invalid),
            },
            Kind::MemInfo(text) => match whence {
                0 => 0,
                1 => self.offset,
                2 => text.len(),
                _ => return Err(Errno::Invalid),
            },
            Kind::DevNull | Kind::Rtc => match whence {
                0 => 0,
                1 => self.offset,
                2 => 0,
                _ => return Err(Errno::Invalid),
            },
            Kind::DevBlk { len, .. } => match whence {
                0 => 0usize,
                1 => self.offset,
                2 => *len as usize,
                _ => return Err(Errno::Invalid),
            },
            _ => return Err(Errno::SeekPipe),
        };
        let offset = base as i128 + delta as i128;
        if offset < 0 || offset > isize::MAX as i128 {
            return Err(Errno::Invalid);
        }
        self.offset = offset as usize;
        Ok(self.offset)
    }

    /// 读取一块内核缓冲区；交付成功后才消费管道数据或推进偏移。
    /// first 指示本次读取的首块；交付函数返回实际写入用户缓冲区的长度。
    pub(crate) fn read_chunk(
        &mut self,
        data: &mut [u8],
        first: bool,
        deliver: impl FnOnce(&[u8]) -> Result<usize, Errno>,
    ) -> Result<usize, Errno> {
        self.check_type(first)?;
        match &self.kind {
            Kind::Input => Ok(0),
            Kind::Pipe { id, pipe, .. } => {
                let mut p = pipe.lock();
                if p.data.is_empty() {
                    return if p.writers == 0 {
                        Ok(0)
                    } else {
                        Err(nonblock_or_wait(self.flags))
                    };
                }
                let count = data.len().min(p.data.len());
                for (i, b) in p.data.iter().take(count).enumerate() {
                    data[i] = *b;
                }
                let delivered = deliver(&data[..count])?;
                if delivered > count {
                    return Err(Errno::Invalid);
                }
                p.data.drain(..delivered);
                crate::task::sched::request_pipe_id_wake(*id);
                Ok(delivered)
            }
            Kind::DevNull | Kind::Rtc => Ok(0),
            Kind::DevZero | Kind::DevRandom { .. } => self.read_at(0, data, false, deliver),
            Kind::DevBlk { .. } => Ok(0), // 设备块读走专用路径（见 read_devblk）
            Kind::MemInfo(text) => {
                let bytes = text.as_bytes().get(self.offset..).unwrap_or(&[]);
                let count = data.len().min(bytes.len());
                let delivered = deliver(&bytes[..count])?;
                if delivered > count {
                    return Err(Errno::Invalid);
                }
                self.offset = self.offset.checked_add(delivered).ok_or(Errno::Invalid)?;
                Ok(delivered)
            }
            Kind::Inode { .. } => {
                let count = self.read_at(self.offset, data, false, deliver)?;
                self.offset = self.offset.checked_add(count).ok_or(Errno::Invalid)?;
                Ok(count)
            }
            Kind::Socket(id) => {
                let nonblock = self.flags & 0x800 != 0;
                crate::net::recvfrom(*id, data, 0, nonblock, |bytes, _| deliver(bytes))
            }
            _ => Err(Errno::BadF),
        }
    }

    /// 写入一块内核缓冲区；首块检查类型，追加模式逐块取得文件末尾。
    /// 空间不足返回等待或 EAGAIN，无读者的管道返回 EPIPE。
    pub(crate) fn write_chunk(&mut self, data: &[u8], first: bool) -> Result<usize, Errno> {
        self.check_type(first)?;
        match &self.kind {
            Kind::DevNull | Kind::DevZero | Kind::DevRandom { .. } => Ok(data.len()),
            Kind::Output => {
                use polyhal::debug_console::DebugConsole;
                for &b in data {
                    DebugConsole::putchar(b);
                }
                Ok(data.len())
            }
            Kind::Pipe { id, pipe, .. } => {
                let mut p = pipe.lock();
                if p.readers == 0 {
                    return Err(Errno::Pipe);
                }
                if PIPE_CAPACITY - p.data.len() < data.len() {
                    return Err(nonblock_or_wait(self.flags));
                }
                p.data.extend(data);
                crate::task::sched::request_pipe_id_wake(*id);
                Ok(data.len())
            }
            Kind::Socket(id) => {
                let nonblock = self.flags & 0x800 != 0;
                crate::net::sendto(*id, data, 0, None, nonblock)
            }
            Kind::Inode { ino, .. } => {
                let offset = if self.flags & 0x400 != 0 {
                    fs::stat(*ino)?.1 as usize
                } else {
                    self.offset
                };
                let count = fs::write(*ino, offset, data)?;
                self.offset = offset.checked_add(count).ok_or(Errno::Invalid)?;
                Ok(count)
            }
            _ => Err(Errno::BadF),
        }
    }

    /// 定位 I/O 只接受支持偏移的对象；流式对象返回 ESPIPE。
    pub(crate) fn check_positioned(&self) -> Result<(), Errno> {
        match self.kind {
            Kind::Inode { .. }
            | Kind::MemInfo(_)
            | Kind::DevNull
            | Kind::DevZero
            | Kind::DevRandom { .. } => Ok(()),
            _ => Err(Errno::SeekPipe),
        }
    }

    /// 从给定位置读取并交付，返回已交付长度；不改变共享偏移。
    pub(crate) fn read_at(
        &self,
        offset: usize,
        data: &mut [u8],
        first: bool,
        deliver: impl FnOnce(&[u8]) -> Result<usize, Errno>,
    ) -> Result<usize, Errno> {
        self.check_type(first)?;
        if matches!(self.kind, Kind::DevNull) {
            return Ok(0);
        }
        if matches!(self.kind, Kind::DevRandom { .. }) {
            if !crate::entropy::ready() || !crate::entropy::fill_random(data) {
                return Err(Errno::Again);
            }
            let delivered = deliver(data)?;
            return if delivered <= data.len() {
                Ok(delivered)
            } else {
                Err(Errno::Invalid)
            };
        }
        if matches!(self.kind, Kind::DevZero) {
            data.fill(0);
            let delivered = deliver(data)?;
            return if delivered <= data.len() {
                Ok(delivered)
            } else {
                Err(Errno::Invalid)
            };
        }
        if let Kind::DevBlk { disk, start, len } = &self.kind {
            // 块设备节点：分区起点+fd 偏移经驱动通用读
            let off = start + offset;
            if offset.saturating_add(data.len()) > *len as usize {
                return Err(Errno::Range);
            }
            crate::drivers::read_bytes(*disk, off, data).map_err(|_| Errno::Io)?;
            let delivered = deliver(&data[..data.len()])?;
            return Ok(delivered);
        }
        if let Kind::MemInfo(text) = &self.kind {
            let bytes = text.as_bytes().get(offset..).unwrap_or(&[]);
            let count = data.len().min(bytes.len());
            let delivered = deliver(&bytes[..count])?;
            if delivered > count {
                return Err(Errno::Invalid);
            }
            return Ok(delivered);
        }
        let ino = match self.kind {
            Kind::Inode { ino, .. } => ino,
            _ => return Err(Errno::SeekPipe),
        };
        let count = fs::read(ino, offset, data)?;
        let delivered = deliver(&data[..count])?;
        if delivered > count {
            return Err(Errno::Invalid);
        }
        Ok(delivered)
    }

    /// 写给定位置且不改变共享偏移；O_APPEND 沿用 Linux 的追加行为。
    pub(crate) fn write_at(&self, offset: usize, data: &[u8], first: bool) -> Result<usize, Errno> {
        self.check_type(first)?;
        if let Kind::DevBlk { disk, start, len } = &self.kind {
            let off = start + offset;
            if offset.saturating_add(data.len()) > *len as usize {
                return Err(Errno::Range);
            }
            crate::drivers::write_bytes(*disk, off, data).map_err(|_| Errno::Io)?;
            return Ok(data.len());
        }
        if matches!(
            self.kind,
            Kind::DevNull | Kind::DevZero | Kind::DevRandom { .. } | Kind::Rtc
        ) {
            return Ok(data.len());
        }
        let ino = match self.kind {
            Kind::Inode { ino, .. } => ino,
            _ => return Err(Errno::SeekPipe),
        };
        let offset = if self.flags & 0x400 != 0 {
            fs::stat(ino)?.1 as usize
        } else {
            offset
        };
        fs::write(ino, offset, data)
    }
}

/// 查找路径的父目录并返回末项名称。
pub(crate) fn parent(path: &str) -> Result<(u32, &str), Errno> {
    let i = path.rfind('/').ok_or(Errno::Invalid)?;
    let dir = fs::lookup(if i == 0 { "/" } else { &path[..i] })?;
    if fs::stat(dir)?.0 & 0xf000 != 0x4000 {
        return Err(Errno::NotDir);
    }
    Ok((dir, &path[i + 1..]))
}

fn nonblock_or_wait(flags: usize) -> Errno {
    if flags & 0x800 != 0 {
        Errno::Again
    } else {
        Errno::WouldBlock
    }
}
/// 按进程工作目录读取可执行文件，返回独立内核镜像。
pub fn executable(ctx: &Context, path: &str) -> Result<Vec<u8>, Errno> {
    // /proc/self/exe 指向当前进程的可执行文件（proc(5)）；execve 与
    // open 共用该重写。没有盘上可执行路径（内核内嵌程序）时按 ENOENT。
    let redirected;
    let path = if path == "/proc/self/exe" {
        if ctx.exe_path.is_empty() {
            return Err(Errno::NoEntry);
        }
        redirected = ctx.exe_path.clone();
        &redirected
    } else {
        path
    };
    let ino = fs::lookup(&ctx.path((-100isize) as usize, path)?)?;
    let (mode, len, _, _) = fs::stat(ino)?;
    if mode & 0xf000 != 0x8000 {
        return Err(Errno::Invalid);
    }
    // execve(2)：任一执行位为 1 才可执行（无凭证模型等同 root，root 同样
    // 要求 x 位）；ELF、#! 脚本与其解释器统一走本入口
    if mode & 0o111 == 0 {
        return Err(Errno::Access);
    }
    let len = usize::try_from(len).map_err(|_| Errno::NoMem)?;
    let mut data = Vec::new();
    data.try_reserve_exact(len).map_err(|_| Errno::NoMem)?;
    data.resize(len, 0);
    let mut done = 0;
    while done < len {
        let n = fs::read(ino, done, &mut data[done..])?;
        if n == 0 {
            return Err(Errno::Io);
        }
        done += n;
    }
    Ok(data)
}
/// 获取 mmap 用的普通文件，权限来自打开方式。
/// 单文件描述符在 poll/select 下的就绪事件计算。
fn fd_poll_events(file: &OpenFile, requested: u16) -> u16 {
    match &file.kind {
        Kind::Input => 0x41 & requested,
        Kind::Output => 0x104 & requested,
        Kind::Inode { .. } | Kind::MemInfo(_) => 0x145 & requested,
        // /dev/null、/dev/zero、/dev/urandom 与 rtc 永远可读可写；块节点同
        Kind::DevNull
        | Kind::DevZero
        | Kind::DevRandom { .. }
        | Kind::Rtc
        | Kind::DevBlk { .. } => 0x145 & requested,
        Kind::Socket(id) => crate::net::poll_events(*id, requested),
        Kind::Pipe { pipe, reading, .. } => {
            let p = pipe.lock();
            if *reading {
                (if p.data.is_empty() {
                    0
                } else {
                    0x41 & requested
                }) | (if p.writers == 0 { 16 } else { 0 })
            } else {
                (if p.data.len() < PIPE_CAPACITY {
                    0x104 & requested
                } else {
                    0
                }) | (if p.readers == 0 { 8 } else { 0 })
            }
        }
    }
}

/// poll(2) 子集：按 fd 表状态返回就绪数；pipe 与套接字的等待由任务层处理。
pub(crate) fn poll(
    ctx: &Context,
    space: &UserAddressSpace,
    addr: usize,
    count: usize,
) -> Result<usize, Errno> {
    if count > 1024 {
        return Err(Errno::Invalid);
    }
    let mut ready = 0;
    for i in 0..count {
        let at = addr.checked_add(i * 8).ok_or(Errno::Fault)?;
        let mut bytes = [0; 8];
        user_access::copy_from_user(space, at, &mut bytes).map_err(|_| Errno::Fault)?;
        let fd = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let requested = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let events: u16 = if fd < 0 {
            0
        } else if let Ok(file) = ctx.get(fd as usize) {
            fd_poll_events(&file.lock(), requested)
        } else {
            32
        };
        user_access::copy_to_user(space, at + 6, &events.to_ne_bytes())
            .map_err(|_| Errno::Fault)?;
        if events != 0 {
            ready += 1;
        }
    }
    Ok(ready)
}

/// pselect6(2) 的位图快照：仅在调用真正结束时才写回用户空间，
/// 避免阻塞重试时覆盖用户原始输入位图。
pub(crate) struct SelectSets {
    bytes: usize,
    read: [u8; 128],
    write: [u8; 128],
    except: [u8; 128],
    pub(crate) ready: usize,
}

/// 检查 pselect6(2) 位图集合的就绪情况；遇无效 FD 立即返回 EBADF。
pub(crate) fn select_check(
    ctx: &Context,
    space: &UserAddressSpace,
    nfds: usize,
    rfds_ptr: usize,
    wfds_ptr: usize,
    efds_ptr: usize,
) -> Result<SelectSets, Errno> {
    let nfds = nfds as u32 as i32;
    if !(0..=1024).contains(&nfds) {
        return Err(Errno::Invalid);
    }
    let nfds = nfds as usize;
    let bytes = nfds.div_ceil(8);
    let mut in_r = [0u8; 128];
    let mut in_w = [0u8; 128];
    let mut in_e = [0u8; 128];
    if bytes > 0 {
        if rfds_ptr != 0 {
            user_access::copy_from_user(space, rfds_ptr, &mut in_r[..bytes])
                .map_err(|_| Errno::Fault)?;
        }
        if wfds_ptr != 0 {
            user_access::copy_from_user(space, wfds_ptr, &mut in_w[..bytes])
                .map_err(|_| Errno::Fault)?;
        }
        if efds_ptr != 0 {
            user_access::copy_from_user(space, efds_ptr, &mut in_e[..bytes])
                .map_err(|_| Errno::Fault)?;
        }
    }
    let mut out = SelectSets {
        bytes,
        read: [0u8; 128],
        write: [0u8; 128],
        except: [0u8; 128],
        ready: 0,
    };
    const ALL_SELECT_MASK: u16 = 0x2147;
    for fd in 0..nfds {
        let idx = fd / 8;
        let bit = 1u8 << (fd % 8);
        let want_r = rfds_ptr != 0 && (in_r[idx] & bit != 0);
        let want_w = wfds_ptr != 0 && (in_w[idx] & bit != 0);
        let want_e = efds_ptr != 0 && (in_e[idx] & bit != 0);
        if !want_r && !want_w && !want_e {
            continue;
        }
        let handle = ctx.get(fd)?;
        let ev = fd_poll_events(&handle.lock(), ALL_SELECT_MASK);
        if want_r && (ev & (0x1 | 0x40 | 0x10 | 0x8 | 0x2000) != 0) {
            out.read[idx] |= bit;
            out.ready += 1;
        }
        if want_w && (ev & (0x4 | 0x100 | 0x8 | 0x10) != 0) {
            out.write[idx] |= bit;
            out.ready += 1;
        }
        if want_e && (ev & 0x2 != 0) {
            out.except[idx] |= bit;
            out.ready += 1;
        }
    }
    Ok(out)
}

/// 将 pselect6(2) 结果位图写回用户缓冲区。
pub(crate) fn select_write_back(
    space: &UserAddressSpace,
    rfds_ptr: usize,
    wfds_ptr: usize,
    efds_ptr: usize,
    sets: &SelectSets,
) -> Result<(), Errno> {
    if sets.bytes == 0 {
        return Ok(());
    }
    if rfds_ptr != 0 {
        user_access::copy_to_user(space, rfds_ptr, &sets.read[..sets.bytes])
            .map_err(|_| Errno::Fault)?;
    }
    if wfds_ptr != 0 {
        user_access::copy_to_user(space, wfds_ptr, &sets.write[..sets.bytes])
            .map_err(|_| Errno::Fault)?;
    }
    if efds_ptr != 0 {
        user_access::copy_to_user(space, efds_ptr, &sets.except[..sets.bytes])
            .map_err(|_| Errno::Fault)?;
    }
    Ok(())
}

/// 文件描述符对应的映射来源及共享写权限。
pub(crate) enum MappingSource {
    File { ino: u32, writable: bool },
    Zero { writable: bool },
}

/// 检查描述符的映射权限，返回文件或零设备。
pub(crate) fn mapping(ctx: &Context, fd: usize, write: bool) -> Result<MappingSource, Errno> {
    let handle = ctx.get(fd)?;
    let f = handle.lock();
    if f.flags & 0x200000 != 0 {
        return Err(Errno::BadF);
    }
    let writable = f.flags & 3 == 2;
    if f.flags & 3 == 1 || (write && !writable) {
        return Err(Errno::Access);
    }
    match f.kind {
        Kind::DevZero => Ok(MappingSource::Zero { writable }),
        Kind::Inode { ino, .. } if fs::stat(ino)?.0 & 0xf000 == 0x8000 => {
            Ok(MappingSource::File { ino, writable })
        }
        _ => Err(Errno::NoDevice),
    }
}

/// exec 成功提交后关闭 CLOEXEC 描述符，标志不与 dup 的源 fd 共享。
pub fn close_exec(ctx: &mut Context) {
    for fd in &mut ctx.fds {
        if fd.as_ref().is_some_and(|d| d.cloexec) {
            *fd = None;
        }
    }
}
