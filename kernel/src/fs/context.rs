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
/// 下一个打开文件描述（OFD）的唯一标识号，供 flock 与 OFD 记录锁区分归属。
static NEXT_OFD_ID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

fn next_ofd_id() -> u64 {
    NEXT_OFD_ID.fetch_add(1, Ordering::Relaxed)
}

struct Pipe {
    data: VecDeque<u8>,
    capacity: usize,
    readers: usize,
    writers: usize,
    event_gen: u64,
    fifo_ino: Option<u32>,
    opening_readers: Vec<u32>,
    opening_writers: Vec<u32>,
}

struct FifoEntry {
    ino: u32,
    id: u64,
    pipe: Arc<Mutex<Pipe>>,
}

/// 命名管道（FIFO）运行期注册表，按 Ext4 inode 编号关联共享管道缓冲。
/// 锁序约定：始终先锁 FIFOS 再锁单条 Pipe，严禁反向加锁。
static FIFOS: Mutex<Vec<FifoEntry>> = Mutex::new(Vec::new());

const PIPE_MAX_SIZE: usize = 1024 * 1024;
enum Kind {
    Input,
    Output,
    Pipe {
        id: u64,
        pipe: Arc<Mutex<Pipe>>,
        reading: bool,
        writing: bool,
        ino: Option<u32>,
    },
    Inode {
        ino: u32,
        path: String,
        directory: Option<Arc<DirectoryPath>>,
    },
    MemInfo(String),
    /// /proc/self/fd 目录快照，记录打开时刻存活的 FD 编号列表。
    ProcFdDir(Vec<usize>),
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
    /// eventfd2(2) 事件计数器句柄
    EventFd {
        id: u64,
        efd: Arc<Mutex<super::event::EventFd>>,
    },
    /// timerfd_create(2) 定时器句柄
    TimerFd {
        id: u64,
        tfd: Arc<Mutex<super::event::TimerFd>>,
    },
    /// epoll_create1(2) 事件多路复用实例
    Epoll(Arc<Mutex<super::event::EpollInstance>>),
    /// signalfd4(2) 信号事件描述符（存储监听信号集掩码）
    SignalFd {
        mask: u64,
        event_gen: u64,
    },
}
/// 共享偏移、打开标志和文件资源的持有者。
pub(crate) struct OpenFile {
    ofd_id: u64,
    kind: Kind,
    offset: usize,
    flags: usize,
}
impl Drop for OpenFile {
    fn drop(&mut self) {
        fs::locks::release_ofd(self.ofd_id);
        match &self.kind {
            Kind::Inode {
                ino,
                directory: None,
                ..
            } => fs::release(*ino),
            Kind::Pipe {
                id,
                pipe,
                reading,
                writing,
                ino,
            } => {
                let maybe_cleanup = {
                    let mut p = pipe.lock();
                    if *reading {
                        p.readers = p.readers.saturating_sub(1);
                    }
                    if *writing {
                        p.writers = p.writers.saturating_sub(1);
                    }
                    p.event_gen = p.event_gen.wrapping_add(1);
                    if p.readers == 0 && p.writers == 0 {
                        p.fifo_ino
                    } else {
                        None
                    }
                };
                if let Some(fifo_ino) = maybe_cleanup {
                    let mut fifos = FIFOS.lock();
                    fifos.retain(|e| {
                        if e.ino != fifo_ino {
                            return true;
                        }
                        let p = e.pipe.lock();
                        p.readers > 0
                            || p.writers > 0
                            || !p.opening_readers.is_empty()
                            || !p.opening_writers.is_empty()
                    });
                }
                if let Some(fifo_ino) = *ino {
                    fs::release(fifo_ino);
                    crate::task::sched::request_pipe_wake();
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
                    ofd_id: next_ofd_id(),
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

    /// 对新建文件和目录的请求权限应用当前进程掩码（保留特殊权限位 0o7000）。
    pub(crate) fn creation_mode(&self, mode: usize) -> u16 {
        mode as u16 & 0o7777 & !self.umask
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
        let base = if dir as isize == -100 {
            string(self.cwd()?)?
        } else {
            string(self.get(dir)?.lock().directory_path()?)?
        };
        let mut path = base;
        path.try_reserve(input.len() + 1)
            .map_err(|_| Errno::NoMem)?;
        path.push('/');
        path.push_str(input);
        fs::query(&path, follow)
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

    /// fchdir(2)：将工作目录切换到已打开的目录 FD（允许 O_PATH 目录 FD）；非特权进程校验搜索权限。
    pub(crate) fn fchdir(
        &mut self,
        fd: usize,
        credentials: &crate::task::Credentials,
    ) -> Result<(), Errno> {
        let handle = self.get(fd)?;
        let (path, ino) = {
            let f = handle.lock();
            match &f.kind {
                Kind::Inode {
                    ino,
                    directory: Some(dir),
                    ..
                } => (string(dir.path()?)?, *ino),
                _ => return Err(Errno::NotDir),
            }
        };
        if credentials.euid != 0 {
            let meta = fs::metadata::metadata(ino)?;
            let bit = if credentials.euid == meta.uid {
                0o100
            } else if credentials.egid == meta.gid {
                0o010
            } else {
                0o001
            };
            if meta.mode & bit == 0 {
                return Err(Errno::Access);
            }
        }
        self.set_cwd(path, ino)
    }

    fn rename_path(&self, dir: usize, input: &str) -> Result<(String, u32, String), Errno> {
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

    /// 构造带基准目录的未词法折叠路径，供保留符号链接顺序的逐分量解析使用。
    pub(crate) fn join_raw(&self, dir: usize, input: &str) -> Result<String, Errno> {
        if input.is_empty() {
            return Err(Errno::NoEntry);
        }
        if input.starts_with('/') {
            return string(input);
        }
        let mut base = if dir as isize == -100 {
            string(self.cwd()?)?
        } else {
            string(self.get(dir)?.lock().directory_path()?)?
        };
        base.try_reserve(input.len() + 1)
            .map_err(|_| Errno::NoMem)?;
        if base != "/" {
            base.push('/');
        }
        base.push_str(input);
        Ok(base)
    }

    /// 解析末项父目录（跟随中间符号链接）并返回规范全路径、父 inode 与末项名称。
    pub(crate) fn resolve_parent_entry(
        &self,
        dir: usize,
        input: &str,
        dot_err: Errno,
    ) -> Result<(String, u32, String), Errno> {
        if input.is_empty() {
            return Err(Errno::NoEntry);
        }
        let trimmed = input.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(dot_err);
        }
        let (parent, name) = match trimmed.rsplit_once('/') {
            Some(("", name)) => ("/", name),
            Some(parts) => parts,
            None => (".", trimmed),
        };
        if name.is_empty() || matches!(name, "." | "..") {
            return Err(dot_err);
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

    /// 创建符号链接（symlinkat 语义）；目标允许相对或悬空，不得为空。
    pub(crate) fn symlink(&self, dir: usize, linkpath: &str, target: &str) -> Result<(), Errno> {
        if target.is_empty() || linkpath.is_empty() {
            return Err(Errno::NoEntry);
        }
        if target.len() >= 4096 {
            return Err(Errno::NameTooLong);
        }
        if linkpath.ends_with('/') {
            let (canonical, _, _) = self.resolve_parent_entry(dir, linkpath, Errno::Exists)?;
            return match fs::query(&canonical, false) {
                Ok(_) => Err(Errno::Exists),
                Err(Errno::NoEntry) => Err(Errno::NoEntry),
                Err(e) => Err(e),
            };
        }
        let (_canonical, parent, name) = self.resolve_parent_entry(dir, linkpath, Errno::Exists)?;
        fs::symlink(parent, &name, target)?;
        Ok(())
    }

    /// 创建硬链接（linkat 语义）；拒绝目录，默认不跟随旧路径末项符号链接。
    pub(crate) fn link(
        &self,
        old_dir: usize,
        old_path: &str,
        new_dir: usize,
        new_path: &str,
        follow: bool,
        empty_path: bool,
    ) -> Result<(), Errno> {
        let (ino, mode) = if old_path.is_empty() {
            if !empty_path {
                return Err(Errno::NoEntry);
            }
            if old_dir as isize == -100 {
                let ino = fs::lookup(self.cwd()?)?;
                (ino, fs::stat(ino)?.0)
            } else {
                let handle = self.get(old_dir)?;
                let f = handle.lock();
                let ino = f.inode()?;
                (ino, fs::stat(ino)?.0)
            }
        } else {
            let info = self.query(old_dir, old_path, false, follow)?;
            if old_path.ends_with('/') && info.mode & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            (info.ino as u32, info.mode)
        };
        if mode & 0xf000 == 0x4000 {
            return Err(Errno::Perm);
        }
        if new_path.is_empty() {
            return Err(Errno::NoEntry);
        }
        if new_path.ends_with('/') {
            let (canonical, _, _) = self.resolve_parent_entry(new_dir, new_path, Errno::Exists)?;
            return match fs::query(&canonical, false) {
                Ok(_) => Err(Errno::Exists),
                Err(Errno::NoEntry) => Err(Errno::NoEntry),
                Err(e) => Err(e),
            };
        }
        let (_canonical, new_parent, new_name) =
            self.resolve_parent_entry(new_dir, new_path, Errno::Exists)?;
        fs::link(ino, new_parent, &new_name)
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
        let (old_path, old_parent, old_name) = self.rename_path(old_dir, old)?;
        let (new_path, new_parent, new_name) = self.rename_path(new_dir, new)?;
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

    /// 将打开文件复制到指定 FD，替换原描述符；若目标槽原有 FD 则按 POSIX 释放该进程对应锁。
    pub(crate) fn dup_to(
        &mut self,
        from: usize,
        to: usize,
        cloexec: bool,
        tgid: u32,
    ) -> Result<usize, Errno> {
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
        let replaced = self.fds[to].replace(Descriptor {
            handle: file,
            cloexec,
        });
        if let Some(old) = replaced {
            let key = old.handle.lock().lock_key();
            if tgid != 0 {
                fs::locks::release_posix_for_key(tgid, key);
            }
        }
        Ok(to)
    }

    /// 关闭 FD 并释放引用，按 POSIX fcntl(2) 释放该进程在该文件上的全部 POSIX 记录锁。
    pub(crate) fn close(&mut self, fd: usize, tgid: u32) -> Result<(), Errno> {
        let desc = self
            .fds
            .get_mut(fd)
            .ok_or(Errno::BadF)?
            .take()
            .ok_or(Errno::BadF)?;
        if tgid != 0 {
            let key = desc.handle.lock().lock_key();
            fs::locks::release_posix_for_key(tgid, key);
        }
        drop(desc);
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
                ofd_id: next_ofd_id(),
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
            ofd_id: next_ofd_id(),
            kind: Kind::MemInfo(text),
            offset: 0,
            flags: flags & !OPEN_CREATION_FLAGS,
        };
        self.install(fs::try_arc(Mutex::new(file))?, cloexec)
    }

    /// 打开 /proc/self/fd 目录快照，供 opendir/getdents64 枚举当前打开的 FD 编号。
    pub(crate) fn open_proc_fd_dir(&mut self, flags: usize, cloexec: bool) -> Result<usize, Errno> {
        if flags & (3 | 0x200) != 0 {
            return Err(Errno::IsDir);
        }
        let mut entries = Vec::new();
        for (idx, slot) in self.fds.iter().enumerate() {
            if slot.is_some() {
                entries.try_reserve(1).map_err(|_| Errno::NoMem)?;
                entries.push(idx);
            }
        }
        let file = OpenFile {
            ofd_id: next_ofd_id(),
            kind: Kind::ProcFdDir(entries),
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
            match &f.kind {
                Kind::Inode { ino, path, .. } => {
                    if f.detached_directory() {
                        return Err(Errno::NoEntry);
                    }
                    (*ino, path.clone())
                }
                Kind::Pipe { ino: Some(ino), .. } => (*ino, String::new()),
                _ => return Err(Errno::NoEntry),
            }
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
        // FIONREAD：返回管道或普通文件当前可读字节数（i32）
        const FIONREAD: usize = 0x541B;
        let file = self.get(fd)?;
        let f = file.lock();
        // ioctl(2) 的 cmd 是 unsigned int：部分 libc（如 musl）把负的 int
        // 常量符号扩展到 64 位寄存器，比较前统一截断为 32 位
        let cmd32 = (cmd as u32) as usize;
        if cmd32 == FIONREAD {
            let avail: i32 = match &f.kind {
                Kind::Pipe { pipe, .. } => pipe.lock().data.len().min(i32::MAX as usize) as i32,
                Kind::Inode {
                    ino,
                    directory: None,
                    ..
                } => {
                    let size = fs::stat(*ino)?.1 as usize;
                    size.saturating_sub(f.offset).min(i32::MAX as usize) as i32
                }
                _ => return Err(Errno::InappropriateIoctl),
            };
            crate::mm::user_access::copy_to_user(space, arg, &avail.to_ne_bytes())
                .map_err(|_| Errno::Fault)?;
            return Ok(0);
        }
        if !matches!(f.kind, Kind::Rtc) || cmd32 != RTC_RD_TIME {
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
            ofd_id: next_ofd_id(),
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
            ofd_id: next_ofd_id(),
            kind,
            offset: 0,
            flags: flags & !OPEN_CREATION_FLAGS,
        };
        self.install(fs::try_arc(Mutex::new(file))?, cloexec)
    }

    /// 为阻塞读写的 fd 选择精确等待原因（管道/eventfd/套接字定向唤醒，timerfd 挂接硬件到期）。
    pub(crate) fn wait_reason_for_fd(&self, fd: usize) -> crate::task::WaitReason {
        let Ok(handle) = self.get(fd) else {
            return crate::task::WaitReason::Pipe;
        };
        let file = handle.lock();
        match &file.kind {
            Kind::Pipe { id, .. } | Kind::EventFd { id, .. } => {
                crate::task::WaitReason::PipeId(*id)
            }
            Kind::Socket(id) => crate::task::WaitReason::PipeId(id.wake_id()),
            Kind::TimerFd { id, tfd } => match tfd.lock().next_deadline() {
                Some(d) => crate::task::WaitReason::PollUntil(d),
                None => crate::task::WaitReason::PipeId(*id),
            },
            _ => crate::task::WaitReason::Pipe,
        }
    }

    /// 创建管道两端，安装失败时回收已安装的 FD。
    pub(crate) fn pipe(&mut self, flags: usize) -> Result<(usize, usize), Errno> {
        let mut data = VecDeque::new();
        data.try_reserve(4096).map_err(|_| Errno::NoMem)?;
        let id = NEXT_PIPE_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let pipe = fs::try_arc(Mutex::new(Pipe {
            data,
            capacity: PIPE_CAPACITY,
            readers: 1,
            writers: 1,
            event_gen: 1,
            fifo_ino: None,
            opening_readers: Vec::new(),
            opening_writers: Vec::new(),
        }))?;
        let r = fs::try_arc(Mutex::new(OpenFile {
            ofd_id: next_ofd_id(),
            kind: Kind::Pipe {
                id,
                pipe: pipe.clone(),
                reading: true,
                writing: false,
                ino: None,
            },
            offset: 0,
            flags: flags & 0x800,
        }))?;
        let w = fs::try_arc(Mutex::new(OpenFile {
            ofd_id: next_ofd_id(),
            kind: Kind::Pipe {
                id,
                pipe,
                reading: false,
                writing: true,
                ino: None,
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

    /// 打开命名管道（FIFO，fifo(7) 语义）：支持 O_RDONLY、O_WRONLY、O_RDWR 与 O_NONBLOCK。
    pub(crate) fn open_fifo(
        &mut self,
        ino: u32,
        flags: usize,
        cloexec: bool,
        tgid: u32,
    ) -> Result<usize, Errno> {
        let acc = flags & 3;
        let nonblock = flags & 0x800 != 0;
        let (id, pipe) = {
            let mut fifos = FIFOS.lock();
            if let Some(entry) = fifos.iter().find(|e| e.ino == ino) {
                (entry.id, entry.pipe.clone())
            } else {
                let mut data = VecDeque::new();
                data.try_reserve(4096).map_err(|_| Errno::NoMem)?;
                let id = NEXT_PIPE_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                let pipe = fs::try_arc(Mutex::new(Pipe {
                    data,
                    capacity: PIPE_CAPACITY,
                    readers: 0,
                    writers: 0,
                    event_gen: 1,
                    fifo_ino: Some(ino),
                    opening_readers: Vec::new(),
                    opening_writers: Vec::new(),
                }))?;
                fifos.try_reserve(1).map_err(|_| Errno::NoMem)?;
                fifos.push(FifoEntry {
                    ino,
                    id,
                    pipe: pipe.clone(),
                });
                (id, pipe)
            }
        };

        let (reading, writing) = {
            let mut p = pipe.lock();
            match acc {
                2 => {
                    p.opening_readers.retain(|&x| x != tgid);
                    p.opening_writers.retain(|&x| x != tgid);
                    p.readers += 1;
                    p.writers += 1;
                    (true, true)
                }
                0 => {
                    if nonblock || p.writers > 0 || !p.opening_writers.is_empty() {
                        p.opening_readers.retain(|&x| x != tgid);
                        p.readers += 1;
                        (true, false)
                    } else {
                        if !p.opening_readers.contains(&tgid) {
                            p.opening_readers.try_reserve(1).map_err(|_| Errno::NoMem)?;
                            p.opening_readers.push(tgid);
                        }
                        return Err(Errno::WouldBlock);
                    }
                }
                1 => {
                    if p.readers == 0 && p.opening_readers.is_empty() {
                        if nonblock {
                            let empty = p.writers == 0 && p.opening_writers.is_empty();
                            drop(p);
                            if empty {
                                let mut fifos = FIFOS.lock();
                                fifos.retain(|e| {
                                    if e.ino != ino {
                                        return true;
                                    }
                                    let q = e.pipe.lock();
                                    q.readers > 0
                                        || q.writers > 0
                                        || !q.opening_readers.is_empty()
                                        || !q.opening_writers.is_empty()
                                });
                            }
                            return Err(Errno::NxIo);
                        }
                        if !p.opening_writers.contains(&tgid) {
                            p.opening_writers.try_reserve(1).map_err(|_| Errno::NoMem)?;
                            p.opening_writers.push(tgid);
                        }
                        return Err(Errno::WouldBlock);
                    }
                    p.opening_writers.retain(|&x| x != tgid);
                    p.writers += 1;
                    p.event_gen = p.event_gen.wrapping_add(1);
                    (false, true)
                }
                _ => return Err(Errno::Invalid),
            }
        };

        crate::task::sched::request_pipe_wake();
        crate::task::sched::request_pipe_id_wake(id);
        if let Err(e) = fs::retain(ino) {
            let mut p = pipe.lock();
            if reading {
                p.readers = p.readers.saturating_sub(1);
            }
            if writing {
                p.writers = p.writers.saturating_sub(1);
            }
            return Err(e);
        }
        let file = fs::try_arc(Mutex::new(OpenFile {
            ofd_id: next_ofd_id(),
            kind: Kind::Pipe {
                id,
                pipe,
                reading,
                writing,
                ino: Some(ino),
            },
            offset: 0,
            flags: flags & !OPEN_CREATION_FLAGS,
        }))?;
        self.install(file, cloexec)
    }

    /// 若 `fd` 指向管道或套接字，返回当前是否有可读数据（供 splice/tee 选择精确等待目标）。
    pub(crate) fn has_readable_data(&self, fd: usize) -> bool {
        let Ok(handle) = self.get(fd) else {
            return false;
        };
        let f = handle.lock();
        match &f.kind {
            Kind::Pipe { pipe, .. } => {
                let p = pipe.lock();
                !p.data.is_empty() || p.writers == 0
            }
            Kind::Socket(id) => crate::net::poll_events(*id, 0x01) != 0,
            _ => true,
        }
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
            ofd_id: next_ofd_id(),
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

    /// eventfd2(2)：创建事件计数器描述符。
    pub(crate) fn open_eventfd(&mut self, initval: u32, flags: usize) -> Result<usize, Errno> {
        use super::event::{EventFd, EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};
        if flags & !(EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC) != 0 {
            return Err(Errno::Invalid);
        }
        let id = NEXT_PIPE_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let efd = fs::try_arc(Mutex::new(EventFd::new(
            id,
            initval,
            flags & EFD_SEMAPHORE != 0,
        )))?;
        let file_flags = 2 | if flags & EFD_NONBLOCK != 0 { 0x800 } else { 0 };
        let file = fs::try_arc(Mutex::new(OpenFile {
            ofd_id: next_ofd_id(),
            kind: Kind::EventFd { id, efd },
            offset: 0,
            flags: file_flags,
        }))?;
        self.install(file, flags & EFD_CLOEXEC != 0)
    }

    /// timerfd_create(2)：创建定时器描述符。
    pub(crate) fn open_timerfd(&mut self, clockid: i32, flags: usize) -> Result<usize, Errno> {
        use super::event::{TimerFd, TFD_CLOEXEC, TFD_NONBLOCK};
        if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
            return Err(Errno::Invalid);
        }
        let id = NEXT_PIPE_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let tfd = fs::try_arc(Mutex::new(TimerFd::new(id, clockid)?))?;
        let file_flags = 2 | if flags & TFD_NONBLOCK != 0 { 0x800 } else { 0 };
        let file = fs::try_arc(Mutex::new(OpenFile {
            ofd_id: next_ofd_id(),
            kind: Kind::TimerFd { id, tfd },
            offset: 0,
            flags: file_flags,
        }))?;
        self.install(file, flags & TFD_CLOEXEC != 0)
    }

    /// timerfd_settime(2)：设置或撤防定时器并返回旧值。
    pub(crate) fn timerfd_settime(
        &self,
        fd: usize,
        flags: usize,
        interval: core::time::Duration,
        value: core::time::Duration,
    ) -> Result<(core::time::Duration, core::time::Duration), Errno> {
        let handle = self.get(fd)?;
        let f = handle.lock();
        let Kind::TimerFd { tfd, .. } = &f.kind else {
            return Err(Errno::Invalid);
        };
        let res = tfd.lock().settime(flags, interval, value);
        res
    }

    /// timerfd_gettime(2)：查询当前周期与剩余时间。
    pub(crate) fn timerfd_gettime(
        &self,
        fd: usize,
    ) -> Result<(core::time::Duration, core::time::Duration), Errno> {
        let handle = self.get(fd)?;
        let f = handle.lock();
        let Kind::TimerFd { tfd, .. } = &f.kind else {
            return Err(Errno::Invalid);
        };
        let res = tfd.lock().gettime();
        Ok(res)
    }

    /// epoll_create1(2)：创建 epoll 实例描述符。
    pub(crate) fn open_epoll(&mut self, flags: usize) -> Result<usize, Errno> {
        use super::event::{EpollInstance, EPOLL_CLOEXEC};
        if flags & !EPOLL_CLOEXEC != 0 {
            return Err(Errno::Invalid);
        }
        let ep = fs::try_arc(Mutex::new(EpollInstance::new()))?;
        let file = fs::try_arc(Mutex::new(OpenFile {
            ofd_id: next_ofd_id(),
            kind: Kind::Epoll(ep),
            offset: 0,
            flags: 2,
        }))?;
        self.install(file, flags & EPOLL_CLOEXEC != 0)
    }

    /// epoll_ctl(2)：向 epoll 实例增、改、删目标描述符。
    pub(crate) fn epoll_ctl(
        &self,
        epfd: usize,
        op: i32,
        fd: usize,
        event: Option<(u32, u64)>,
    ) -> Result<(), Errno> {
        use super::event::{EpollInstance, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD};
        let ep_handle = self.get(epfd)?;
        let target_handle = self.get(fd)?;
        if epfd == fd || Arc::ptr_eq(&ep_handle, &target_handle) {
            return Err(Errno::Invalid);
        }
        let ep = {
            let f = ep_handle.lock();
            f.epoll_instance().ok_or(Errno::Invalid)?
        };
        let (supported, target_ep) = {
            let tf = target_handle.lock();
            (tf.epoll_supported(), tf.epoll_instance())
        };
        if !supported {
            return Err(Errno::Perm);
        }
        match op {
            EPOLL_CTL_ADD => {
                let (events, data) = event.ok_or(Errno::Fault)?;
                if let Some(ref child_ep) = target_ep {
                    EpollInstance::check_nesting(&ep, child_ep)?;
                }
                ep.lock()
                    .add(&ep, fd, &target_handle, events, data, target_ep.as_ref())
            }
            EPOLL_CTL_MOD => {
                let (events, data) = event.ok_or(Errno::Fault)?;
                ep.lock().modify(fd, &target_handle, events, data)
            }
            EPOLL_CTL_DEL => ep.lock().delete(
                Arc::as_ptr(&ep) as usize,
                fd,
                &target_handle,
                target_ep.as_ref(),
            ),
            _ => Err(Errno::Invalid),
        }
    }

    /// signalfd4(2)：创建新 signalfd（fd == -1）或更新已有 signalfd 的掩码与标志。
    pub(crate) fn open_or_update_signalfd(
        &mut self,
        fd: i32,
        mask: u64,
        nonblock: bool,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        if fd == -1 {
            let file_flags = 2 | if nonblock { 0x800 } else { 0 };
            let file = fs::try_arc(Mutex::new(OpenFile {
                ofd_id: next_ofd_id(),
                kind: Kind::SignalFd { mask, event_gen: 1 },
                offset: 0,
                flags: file_flags,
            }))?;
            return self.install(file, cloexec);
        }
        if fd < 0 {
            return Err(Errno::BadF);
        }
        let idx = fd as usize;
        let handle = self.get(idx)?;
        {
            let mut f = handle.lock();
            let Kind::SignalFd {
                mask: cur_mask,
                event_gen,
            } = &mut f.kind
            else {
                return Err(Errno::Invalid);
            };
            *cur_mask = mask;
            *event_gen = event_gen.wrapping_add(1);
            if nonblock {
                f.flags |= 0x800;
            } else {
                f.flags &= !0x800;
            }
        }
        if cloexec {
            let _ = self.set_descriptor_flags(idx, 1);
        }
        Ok(idx)
    }

    /// 若 `fd` 为 signalfd，返回 `(监听掩码, 是否非阻塞)` 并可选递增版本号。
    pub(crate) fn signalfd_info(&self, fd: usize) -> Option<(u64, bool)> {
        let handle = self.get(fd).ok()?;
        let f = handle.lock();
        match f.kind {
            Kind::SignalFd { mask, .. } => Some((mask, f.flags & 0x800 != 0)),
            _ => None,
        }
    }

    /// 消费 signalfd 信号后递增其边沿版本号。
    pub(crate) fn bump_signalfd_gen(&self, fd: usize) {
        if let Ok(handle) = self.get(fd) {
            let mut f = handle.lock();
            if let Kind::SignalFd { event_gen, .. } = &mut f.kind {
                *event_gen = event_gen.wrapping_add(1);
            }
        }
    }

    /// 采集 epoll 实例当前就绪事件及最早武装 timerfd 到期时刻。
    pub(crate) fn epoll_collect(
        &self,
        epfd: usize,
        maxevents: usize,
        pending_signals: u64,
    ) -> Result<(Vec<u8>, usize, Option<core::time::Duration>), Errno> {
        let ep_handle = self.get(epfd)?;
        let ep = {
            let f = ep_handle.lock();
            f.epoll_instance().ok_or(Errno::Invalid)?
        };
        let mut guard = ep.lock();
        guard.collect_ready(maxevents, 0, pending_signals)
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

    /// 返回本打开文件描述（OFD）的全局唯一标识号。
    pub(crate) fn ofd_id(&self) -> u64 {
        self.ofd_id
    }

    /// 返回本打开文件对应的文件锁对象键。
    pub(crate) fn lock_key(&self) -> u64 {
        match &self.kind {
            Kind::Inode { ino, .. } => u64::from(*ino),
            Kind::Pipe { id, .. } => (1u64 << 62) | *id,
            Kind::Socket(id) => (2u64 << 62) | id.wake_id(),
            Kind::DevNull => (3u64 << 62) | 1,
            Kind::DevZero => (3u64 << 62) | 2,
            Kind::DevRandom { urandom } => (3u64 << 62) | if *urandom { 3 } else { 4 },
            Kind::Rtc => (3u64 << 62) | 5,
            Kind::DevBlk { disk, start, .. } => {
                (4u64 << 62) | ((*disk as u64) << 40) | ((*start as u64) & 0xffff_ffff)
            }
            _ => (3u64 << 62) | self.ofd_id,
        }
    }

    /// 返回用于 fcntl 锁 SEEK_END 计算的文件长度。
    pub(crate) fn lock_file_size(&self) -> Result<u64, Errno> {
        match &self.kind {
            Kind::Inode { ino, .. } => Ok(fs::stat(*ino)?.1),
            Kind::MemInfo(text) => Ok(text.len() as u64),
            Kind::DevBlk { len, .. } => Ok(*len),
            _ => Ok(0),
        }
    }

    /// 查询管道当前容量（fcntl F_GETPIPE_SZ）；非管道返回 EINVAL。
    pub(crate) fn pipe_size(&self) -> Result<usize, Errno> {
        match &self.kind {
            Kind::Pipe { pipe, .. } => Ok(pipe.lock().capacity),
            _ => Err(Errno::Invalid),
        }
    }

    /// 调整管道容量（fcntl F_SETPIPE_SZ）；按页向上取整，小于当前积压字节数返回 EBUSY。
    pub(crate) fn set_pipe_size(&self, requested: usize) -> Result<usize, Errno> {
        let Kind::Pipe { id, pipe, .. } = &self.kind else {
            return Err(Errno::Invalid);
        };
        let req_i32 = requested as u32 as i32;
        if req_i32 < 0 {
            return Err(Errno::Invalid);
        }
        let req = (req_i32 as usize).max(4096);
        let rounded = req.next_power_of_two().max(4096);
        if rounded > PIPE_MAX_SIZE {
            return Err(Errno::Perm);
        }
        let mut p = pipe.lock();
        if rounded < p.data.len() {
            return Err(Errno::Busy);
        }
        p.capacity = rounded;
        crate::task::sched::request_pipe_id_wake(*id);
        Ok(rounded)
    }

    /// 若本打开对象是 `/proc/self/fd` 目录快照，返回其 FD 列表。
    pub(crate) fn proc_fd_entries(&self) -> Option<&[usize]> {
        match &self.kind {
            Kind::ProcFdDir(entries) => Some(entries),
            _ => None,
        }
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
            Kind::Inode { ino, .. } | Kind::Pipe { ino: Some(ino), .. } => Ok(ino),
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

    /// 更新打开 inode 的访问和修改时间；匿名管道与控制台返回 EOPNOTSUPP。
    pub(crate) fn update_times(&self, times: [fs::TimeUpdate; 2]) -> Result<(), Errno> {
        match self.kind {
            Kind::Inode { ino, .. } | Kind::Pipe { ino: Some(ino), .. } => {
                fs::update_times(ino, times)
            }
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
                if super::procfs::is_virtual_ino(*ino) {
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
            Kind::Pipe { ino: Some(ino), .. } => fs::metadata::metadata(*ino),
            Kind::ProcFdDir(_) => Ok(fs::Metadata {
                ino: super::procfs::SELF_FD_DIR as u64,
                mode: 0o040555,
                links: 2,
                block_size: 4096,
                ..Default::default()
            }),
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
            Kind::EventFd { .. }
            | Kind::TimerFd { .. }
            | Kind::Epoll(_)
            | Kind::SignalFd { .. } => Ok(fs::Metadata {
                mode: 0o000600,
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

    /// 依据打开模式检查读写权限，失败返回 EBADF（含 O_PATH）。
    pub(crate) fn check_access(&self, reading: bool) -> Result<(), Errno> {
        if self.flags & 0x200000 != 0
            || (reading && self.flags & 3 == 1)
            || (!reading && self.flags & 3 == 0)
        {
            return Err(Errno::BadF);
        }
        Ok(())
    }

    /// 是否指向目录打开对象。
    pub(crate) fn is_directory(&self) -> bool {
        matches!(
            self.kind,
            Kind::Inode {
                directory: Some(_),
                ..
            } | Kind::ProcFdDir(_)
        )
    }

    fn check_type(&self, first: bool) -> Result<(), Errno> {
        if first
            && matches!(
                self.kind,
                Kind::Inode {
                    directory: Some(_),
                    ..
                } | Kind::ProcFdDir(_)
            )
        {
            return Err(Errno::IsDir);
        }
        Ok(())
    }

    /// 从起点、当前位置或文件末尾调整偏移；管道返回 ESPIPE。
    pub(crate) fn seek(&mut self, delta: isize, whence: usize) -> Result<usize, Errno> {
        let base = match &self.kind {
            Kind::DevZero | Kind::DevRandom { .. } if self.flags & 0x200000 != 0 => {
                return Err(Errno::BadF);
            }
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

    /// 零字节读写前置检查：eventfd/timerfd/epoll 拒绝小于 8 字节的读写并报 EINVAL。
    pub(crate) fn check_zero_rw(&self, _reading: bool) -> Result<usize, Errno> {
        match self.kind {
            Kind::EventFd { .. }
            | Kind::TimerFd { .. }
            | Kind::Epoll(_)
            | Kind::SignalFd { .. } => Err(Errno::Invalid),
            _ => Ok(0),
        }
    }

    pub(super) fn epoll_instance(&self) -> Option<Arc<Mutex<super::event::EpollInstance>>> {
        match &self.kind {
            Kind::Epoll(ep) => Some(ep.clone()),
            _ => None,
        }
    }

    fn epoll_supported(&self) -> bool {
        matches!(
            self.kind,
            Kind::Pipe { .. }
                | Kind::Socket(_)
                | Kind::EventFd { .. }
                | Kind::TimerFd { .. }
                | Kind::Epoll(_)
                | Kind::SignalFd { .. }
                | Kind::Input
                | Kind::Output
        )
    }

    pub(super) fn event_gen(&mut self) -> u64 {
        match &self.kind {
            Kind::Pipe { pipe, .. } => pipe.lock().event_gen,
            Kind::EventFd { efd, .. } => efd.lock().event_gen(),
            Kind::TimerFd { tfd, .. } => tfd.lock().event_gen(),
            Kind::SignalFd { event_gen, .. } => *event_gen,
            _ => 0,
        }
    }

    pub(super) fn timer_deadline(&mut self, depth: usize) -> Option<core::time::Duration> {
        match &self.kind {
            Kind::TimerFd { tfd, .. } => tfd.lock().next_deadline(),
            Kind::Epoll(ep) => ep.lock().earliest_timer_deadline(depth),
            _ => None,
        }
    }

    /// 若为管道或命名管道，返回其管道实例号。
    pub(crate) fn pipe_id(&self) -> Option<u64> {
        match &self.kind {
            Kind::Pipe { id, .. } => Some(*id),
            _ => None,
        }
    }

    /// 若为管道或命名管道且非 O_PATH，返回 `(可读, 可写)`（供 vmsplice 判定传输方向）。
    pub(crate) fn pipe_rw_mode(&self) -> Option<(bool, bool)> {
        if self.flags & 0x200000 != 0 {
            return None;
        }
        match self.kind {
            Kind::Pipe {
                reading, writing, ..
            } => Some((reading, writing)),
            _ => None,
        }
    }

    /// 是否为套接字打开对象。
    pub(crate) fn is_socket(&self) -> bool {
        matches!(self.kind, Kind::Socket(_))
    }

    /// 是否为已连接的套接字打开对象（供 splice 校验）。
    pub(crate) fn is_connected_socket(&self) -> bool {
        match &self.kind {
            Kind::Socket(id) => crate::net::is_connected(*id),
            _ => false,
        }
    }

    /// 是否为普通文件 inode（非目录、非管道、非套接字、非设备）。
    pub(crate) fn is_regular_file(&self) -> Result<bool, Errno> {
        match &self.kind {
            Kind::Inode {
                ino,
                directory: None,
                ..
            } => Ok(fs::stat(*ino)?.0 & 0xf000 == 0x8000),
            _ => Ok(false),
        }
    }

    /// 返回管道剩余可写空间；无读端返回 EPIPE，无空间返回 EAGAIN/WouldBlock。
    pub(crate) fn pipe_writable_space(&self, nonblock: bool) -> Result<usize, Errno> {
        let Kind::Pipe { pipe, .. } = &self.kind else {
            return Err(Errno::Invalid);
        };
        let p = pipe.lock();
        if p.readers == 0 {
            return Err(Errno::Pipe);
        }
        let avail = p.capacity.saturating_sub(p.data.len());
        if avail == 0 {
            return if nonblock || self.flags & 0x800 != 0 {
                Err(Errno::Again)
            } else {
                Err(Errno::WouldBlock)
            };
        }
        Ok(avail)
    }

    /// 按显式 nonblock 标志从套接字读入内核缓冲区（供 splice 使用）。
    pub(crate) fn read_socket_into(&self, dst: &mut [u8], nonblock: bool) -> Result<usize, Errno> {
        let Kind::Socket(id) = &self.kind else {
            return Err(Errno::Invalid);
        };
        let nb = nonblock || self.flags & 0x800 != 0;
        crate::net::recvfrom(*id, dst, 0, nb, |bytes, _| Ok(bytes.len()))
    }

    /// 按显式 nonblock 标志向套接字写入内核缓冲区（供 splice 使用）。
    pub(crate) fn write_socket_from(&self, data: &[u8], nonblock: bool) -> Result<usize, Errno> {
        let Kind::Socket(id) = &self.kind else {
            return Err(Errno::Invalid);
        };
        let nb = nonblock || self.flags & 0x800 != 0;
        crate::net::sendto(*id, data, 0, None, nb)
    }

    /// 按显式 nonblock 标志从指定偏移只看不消费地读取管道内容（供 splice/tee 使用）。
    pub(crate) fn peek_pipe_into(
        &self,
        skip: usize,
        dst: &mut [u8],
        nonblock: bool,
    ) -> Result<usize, Errno> {
        let Kind::Pipe { pipe, .. } = &self.kind else {
            return Err(Errno::Invalid);
        };
        let p = pipe.lock();
        if p.data.len() <= skip {
            return if skip > 0 || p.writers == 0 {
                Ok(0)
            } else if nonblock || self.flags & 0x800 != 0 {
                Err(Errno::Again)
            } else {
                Err(Errno::WouldBlock)
            };
        }
        let avail = p.data.len() - skip;
        let count = dst.len().min(avail);
        let (first, second) = p.data.as_slices();
        if skip < first.len() {
            let take_first = count.min(first.len() - skip);
            dst[..take_first].copy_from_slice(&first[skip..skip + take_first]);
            if take_first < count {
                dst[take_first..count].copy_from_slice(&second[..count - take_first]);
            }
        } else {
            let s = skip - first.len();
            dst[..count].copy_from_slice(&second[s..s + count]);
        }
        Ok(count)
    }

    /// 消费管道前端已成功搬运的字节并唤醒写端（供 pipe->pipe splice 使用）。
    pub(crate) fn consume_pipe(&self, count: usize) {
        if count == 0 {
            return;
        }
        if let Kind::Pipe { id, pipe, .. } = &self.kind {
            let mut p = pipe.lock();
            let take = count.min(p.data.len());
            p.data.drain(..take);
            if take > 0 {
                p.event_gen = p.event_gen.wrapping_add(1);
            }
            crate::task::sched::request_pipe_id_wake(*id);
        }
    }

    /// 按显式 nonblock 标志向管道写入字节（供 splice/tee 使用）。
    pub(crate) fn write_pipe_from(&self, data: &[u8], nonblock: bool) -> Result<usize, Errno> {
        let Kind::Pipe { id, pipe, .. } = &self.kind else {
            return Err(Errno::Invalid);
        };
        let mut p = pipe.lock();
        if p.readers == 0 {
            return Err(Errno::Pipe);
        }
        let avail = p.capacity.saturating_sub(p.data.len());
        let need = if data.len() <= 4096 { data.len() } else { 1 };
        if avail < need {
            return if nonblock || self.flags & 0x800 != 0 {
                Err(Errno::Again)
            } else {
                Err(Errno::WouldBlock)
            };
        }
        let n = data.len().min(avail);
        p.data.extend(&data[..n]);
        if n > 0 {
            p.event_gen = p.event_gen.wrapping_add(1);
        }
        crate::task::sched::request_pipe_id_wake(*id);
        Ok(n)
    }
    /// 将一段内容直接读入调用方提供的内核缓冲区（供 sendfile 等内核态搬运使用）。
    pub(crate) fn read_into_buf(
        &mut self,
        offset: Option<usize>,
        dst: &mut [u8],
        first: bool,
    ) -> Result<usize, Errno> {
        if let Kind::MemInfo(text) = &self.kind {
            let start = offset.unwrap_or(self.offset);
            let bytes = text.as_bytes().get(start..).unwrap_or(&[]);
            let count = dst.len().min(bytes.len());
            dst[..count].copy_from_slice(&bytes[..count]);
            if offset.is_none() {
                self.offset = self.offset.checked_add(count).ok_or(Errno::Invalid)?;
            }
            return Ok(count);
        }
        if let Some(off) = offset {
            self.read_at(off, dst, first, |b| Ok(b.len()))
        } else {
            self.read_chunk(dst, first, |b| Ok(b.len()))
        }
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
                let (first, second) = p.data.as_slices();
                let take_first = count.min(first.len());
                data[..take_first].copy_from_slice(&first[..take_first]);
                if take_first < count {
                    data[take_first..count].copy_from_slice(&second[..count - take_first]);
                }
                let delivered = deliver(&data[..count])?;
                if delivered > count {
                    return Err(Errno::Invalid);
                }
                p.data.drain(..delivered);
                if delivered > 0 {
                    p.event_gen = p.event_gen.wrapping_add(1);
                }
                crate::task::sched::request_pipe_id_wake(*id);
                Ok(delivered)
            }
            Kind::EventFd { efd, .. } => {
                if data.len() < 8 {
                    return Err(Errno::Invalid);
                }
                efd.lock().read(self.flags & 0x800 != 0, deliver)
            }
            Kind::TimerFd { tfd, .. } => {
                if data.len() < 8 {
                    return Err(Errno::Invalid);
                }
                tfd.lock().read(self.flags & 0x800 != 0, deliver)
            }
            Kind::Epoll(_) | Kind::SignalFd { .. } => Err(Errno::Invalid),
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
                let avail = p.capacity.saturating_sub(p.data.len());
                // 遵循 POSIX PIPE_BUF(4096) 原子写语义；更大请求允许部分写入以提升大块管道吞吐。
                let need = if data.len() <= 4096.min(p.capacity) {
                    data.len()
                } else {
                    1
                };
                if avail < need {
                    return Err(nonblock_or_wait(self.flags));
                }
                let count = data.len().min(avail);
                p.data.extend(&data[..count]);
                if count > 0 {
                    p.event_gen = p.event_gen.wrapping_add(1);
                }
                crate::task::sched::request_pipe_id_wake(*id);
                Ok(count)
            }
            Kind::EventFd { efd, .. } => efd.lock().write(data, self.flags & 0x800 != 0),
            Kind::TimerFd { .. } | Kind::Epoll(_) | Kind::SignalFd { .. } => Err(Errno::Invalid),
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
/// 单文件描述符在 poll/select/epoll 下的就绪事件计算。
pub(super) fn fd_poll_events(
    file: &mut OpenFile,
    requested: u16,
    depth: usize,
    pending_signals: u64,
) -> u16 {
    match &file.kind {
        Kind::Input => 0x41 & requested,
        Kind::Output => 0x104 & requested,
        Kind::Inode { .. } | Kind::MemInfo(_) | Kind::ProcFdDir(_) => 0x145 & requested,
        // /dev/null、/dev/zero、/dev/urandom 与 rtc 永远可读可写；块节点同
        Kind::DevNull
        | Kind::DevZero
        | Kind::DevRandom { .. }
        | Kind::Rtc
        | Kind::DevBlk { .. } => 0x145 & requested,
        Kind::Socket(id) => crate::net::poll_events(*id, requested),
        Kind::EventFd { efd, .. } => efd.lock().poll_events(requested),
        Kind::TimerFd { tfd, .. } => tfd.lock().poll_events(requested),
        Kind::SignalFd { mask, .. } => {
            if pending_signals & *mask != 0 {
                0x41 & requested
            } else {
                0
            }
        }
        Kind::Epoll(ep) => {
            if ep.lock().has_ready(depth, pending_signals) {
                0x41 & requested
            } else {
                0
            }
        }
        Kind::Pipe {
            pipe,
            reading,
            writing,
            ..
        } => {
            let p = pipe.lock();
            let mut ev = 0u16;
            if *reading {
                if !p.data.is_empty() {
                    ev |= 0x41 & requested;
                }
                if p.writers == 0 {
                    ev |= 16;
                }
            }
            if *writing {
                if p.data.len() < p.capacity {
                    ev |= 0x104 & requested;
                }
                if p.readers == 0 {
                    ev |= 8;
                }
            }
            ev
        }
    }
}

/// poll(2) 子集：按 fd 表状态返回 `(就绪数, 最早 timerfd 截止时刻)`。
pub(crate) fn poll(
    ctx: &Context,
    space: &UserAddressSpace,
    addr: usize,
    count: usize,
    pending_signals: u64,
) -> Result<(usize, Option<core::time::Duration>), Errno> {
    if count > 1024 {
        return Err(Errno::Invalid);
    }
    let mut ready = 0;
    let mut earliest_timer: Option<core::time::Duration> = None;
    for i in 0..count {
        let at = addr.checked_add(i * 8).ok_or(Errno::Fault)?;
        let mut bytes = [0; 8];
        user_access::copy_from_user(space, at, &mut bytes).map_err(|_| Errno::Fault)?;
        let fd = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let requested = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let events: u16 = if fd < 0 {
            0
        } else if let Ok(file) = ctx.get(fd as usize) {
            let mut guard = file.lock();
            if let Some(d) = guard.timer_deadline(0) {
                earliest_timer = Some(match earliest_timer {
                    Some(cur) => cur.min(d),
                    None => d,
                });
            }
            fd_poll_events(&mut guard, requested, 0, pending_signals)
        } else {
            32
        };
        user_access::copy_to_user(space, at + 6, &events.to_ne_bytes())
            .map_err(|_| Errno::Fault)?;
        if events != 0 {
            ready += 1;
        }
    }
    Ok((ready, earliest_timer))
}

/// pselect6(2) 的位图快照：仅在调用真正结束时才写回用户空间，
/// 避免阻塞重试时覆盖用户原始输入位图。
pub(crate) struct SelectSets {
    bytes: usize,
    read: [u8; 128],
    write: [u8; 128],
    except: [u8; 128],
    pub(crate) ready: usize,
    pub(crate) earliest_timer: Option<core::time::Duration>,
}

/// 检查 pselect6(2) 位图集合的就绪情况；遇无效 FD 立即返回 EBADF。
pub(crate) fn select_check(
    ctx: &Context,
    space: &UserAddressSpace,
    nfds: usize,
    rfds_ptr: usize,
    wfds_ptr: usize,
    efds_ptr: usize,
    pending_signals: u64,
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
        earliest_timer: None,
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
        let mut guard = handle.lock();
        if let Some(d) = guard.timer_deadline(0) {
            out.earliest_timer = Some(match out.earliest_timer {
                Some(cur) => cur.min(d),
                None => d,
            });
        }
        let ev = fd_poll_events(&mut guard, ALL_SELECT_MASK, 0, pending_signals);
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

pub fn mapping(ctx: &Context, fd: usize, write: bool) -> Result<(u32, bool), Errno> {
    let handle = ctx.get(fd)?;
    let f = handle.lock();
    if f.flags & 0x200000 != 0 {
        return Err(Errno::BadF);
    }
    if f.flags & 3 == 1 || (write && f.flags & 3 != 2) {
        return Err(Errno::Access);
    }
    if let Kind::Inode { ino, .. } = f.kind {
        if fs::stat(ino)?.0 & 0xf000 == 0x8000 {
            return Ok((ino, f.flags & 3 == 2));
        }
    }
    Err(Errno::NoDevice)
}

/// exec 成功提交后关闭 CLOEXEC 描述符，标志不与 dup 的源 fd 共享。
pub fn close_exec(ctx: &mut Context) {
    for fd in &mut ctx.fds {
        if fd.as_ref().is_some_and(|d| d.cloexec) {
            *fd = None;
        }
    }
}
