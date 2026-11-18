//! 进程工作目录、FD 表和打开文件对象；提供内核缓冲区读写与管道操作。
#![deny(unsafe_code)]
use crate::{fs, syscall::Errno};
use alloc::{collections::VecDeque, string::String, sync::Arc, vec::Vec};
use spin::Mutex;

/// pipe 缓冲容量（对齐 Linux 默认 64KiB）；写满/读空时阻塞等待。
const PIPE_CAPACITY: usize = 65536;
const FD_LIMIT: usize = 1024;
const OPEN_CREATION_FLAGS: usize = 0x40 | 0x80 | 0x100 | 0x200 | 0x80000;

struct Pipe {
    data: VecDeque<u8>,
    readers: usize,
    writers: usize,
}
enum Kind {
    Input,
    Output,
    Pipe {
        pipe: Arc<Mutex<Pipe>>,
        reading: bool,
    },
    Inode {
        ino: u32,
        path: String,
    },
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
            Kind::Inode { ino, .. } => fs::release(*ino),
            Kind::Pipe { pipe, reading } => {
                let mut p = pipe.lock();
                if *reading {
                    p.readers -= 1;
                } else {
                    p.writers -= 1;
                }
                // 对端计数变化可能使等待者可读（EOF）或写失败（EPIPE），
                // 请求唤醒；无锁原子标志，可在任意持锁环境下调用。
                crate::task::sched::request_pipe_wake();
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
    cwd: String,
    fds: Vec<Option<Descriptor>>,
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
            cwd: string("/")?,
            fds,
        })
    }
    /// fork 复制描述符表，保留共享偏移。
    pub fn fork(&self) -> Result<Self, Errno> {
        let mut fds = Vec::new();
        fds.try_reserve(self.fds.len()).map_err(|_| Errno::NoMem)?;
        fds.extend(self.fds.iter().cloned());
        Ok(Self {
            cwd: string(&self.cwd)?,
            fds,
        })
    }
    /// 取得打开文件引用，无效 FD 返回 EBADF。
    pub(crate) fn get(&self, fd: usize) -> Result<Handle, Errno> {
        self.fds
            .get(fd)
            .and_then(|f| f.as_ref().map(|d| d.handle.clone()))
            .ok_or(Errno::BadF)
    }
    /// 安装打开文件，返回最低可用 FD；容量不足返回错误。
    pub(crate) fn install(&mut self, file: Handle, cloexec: bool) -> Result<usize, Errno> {
        self.install_from(file, 0, cloexec)
    }

    /// 从指定下界安装到最低空闲 FD；超出上限返回 EINVAL，表满返回 EMFILE。
    pub(crate) fn install_from(
        &mut self,
        file: Handle,
        minimum: usize,
        cloexec: bool,
    ) -> Result<usize, Errno> {
        if minimum >= FD_LIMIT {
            return Err(Errno::Invalid);
        }
        if let Some(i) = (minimum..self.fds.len()).find(|&i| self.fds[i].is_none()) {
            self.fds[i] = Some(Descriptor {
                handle: file,
                cloexec,
            });
            return Ok(i);
        }
        let i = minimum.max(self.fds.len());
        if i >= FD_LIMIT {
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
            string(&self.cwd)?
        } else {
            let f = self.get(dir)?;
            let f = f.lock();
            match &f.kind {
                Kind::Inode { ino, path } if fs::stat(*ino)?.0 & 0xf000 == 0x4000 => string(path)?,
                _ => return Err(Errno::NotDir),
            }
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
        if input.is_empty() && empty {
            if dir as isize == -100 {
                return fs::query(&self.cwd, true);
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
            string(&self.cwd)?
        } else {
            let file = self.get(dir)?;
            let file = file.lock();
            file.directory()?;
            match &file.kind {
                Kind::Inode { path, .. } => string(path)?,
                _ => return Err(Errno::NotDir),
            }
        };
        let mut path = base;
        path.try_reserve(input.len() + 1)
            .map_err(|_| Errno::NoMem)?;
        path.push('/');
        path.push_str(input);
        fs::query(&path, follow)
    }

    /// 返回当前工作目录。
    pub(crate) fn cwd(&self) -> &str {
        &self.cwd
    }

    /// 保存调用方已验证的绝对工作目录。
    pub(crate) fn set_cwd(&mut self, path: String) {
        self.cwd = path;
    }

    /// 将打开文件复制到指定 FD，替换原描述符。
    pub(crate) fn dup_to(&mut self, from: usize, to: usize, cloexec: bool) -> Result<usize, Errno> {
        let file = self.get(from)?;
        if to >= FD_LIMIT {
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
    ) -> Result<usize, Errno> {
        fs::retain(ino)?;
        self.install(
            fs::try_arc(Mutex::new(OpenFile {
                kind: Kind::Inode { ino, path },
                offset: 0,
                flags: flags & !OPEN_CREATION_FLAGS,
            }))?,
            cloexec,
        )
    }

    /// 创建管道两端，安装失败时回收已安装的 FD。
    pub(crate) fn pipe(&mut self, flags: usize) -> Result<(usize, usize), Errno> {
        let mut data = VecDeque::new();
        data.try_reserve(4096).map_err(|_| Errno::NoMem)?;
        let pipe = fs::try_arc(Mutex::new(Pipe {
            data,
            readers: 1,
            writers: 1,
        }))?;
        let r = fs::try_arc(Mutex::new(OpenFile {
            kind: Kind::Pipe {
                pipe: pipe.clone(),
                reading: true,
            },
            offset: 0,
            flags: flags & 0x800,
        }))?;
        let w = fs::try_arc(Mutex::new(OpenFile {
            kind: Kind::Pipe {
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
}

/// 确认路径存在且为目录。
fn directory(path: &str) -> Result<(), Errno> {
    if fs::stat(fs::lookup(path)?)?.0 & 0xf000 != 0x4000 {
        return Err(Errno::NotDir);
    }
    Ok(())
}

impl OpenFile {
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

    /// 获取 inode，设备和管道返回 EINVAL。
    #[cfg(not(feature = "rsext4-readonly"))]
    pub(crate) fn inode(&self) -> Result<u32, Errno> {
        match self.kind {
            Kind::Inode { ino, .. } => Ok(ino),
            _ => Err(Errno::Invalid),
        }
    }

    /// 获取目录 inode，其他对象返回 ENOTDIR。
    pub(crate) fn directory(&self) -> Result<u32, Errno> {
        match self.kind {
            Kind::Inode { ino, .. } if fs::stat(ino)?.0 & 0xf000 == 0x4000 => Ok(ino),
            _ => Err(Errno::NotDir),
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
        match self.kind {
            Kind::Inode { ino, .. } => fs::metadata::metadata(ino),
            _ => Ok(fs::Metadata {
                mode: (if matches!(self.kind, Kind::Pipe { .. }) {
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
        if (reading && self.flags & 3 == 1) || (!reading && self.flags & 3 == 0) {
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
        let ino = match self.kind {
            Kind::Inode { ino, .. } => ino,
            _ => return Err(Errno::SeekPipe),
        };
        let base = match whence {
            0 => 0,
            1 => self.offset,
            2 => fs::stat(ino)?.1 as usize,
            _ => return Err(Errno::Invalid),
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
            Kind::Pipe { pipe, .. } => {
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
                crate::task::sched::request_pipe_wake();
                Ok(delivered)
            }
            Kind::Inode { .. } => {
                let count = self.read_at(self.offset, data, false, deliver)?;
                self.offset = self.offset.checked_add(count).ok_or(Errno::Invalid)?;
                Ok(count)
            }
            _ => Err(Errno::BadF),
        }
    }

    /// 写入一块内核缓冲区；首块检查类型，追加模式逐块取得文件末尾。
    /// 空间不足返回等待或 EAGAIN，无读者的管道返回 EPIPE。
    pub(crate) fn write_chunk(&mut self, data: &[u8], first: bool) -> Result<usize, Errno> {
        self.check_type(first)?;
        match &self.kind {
            Kind::Output => {
                use polyhal::debug_console::DebugConsole;
                for &b in data {
                    DebugConsole::putchar(b);
                }
                Ok(data.len())
            }
            Kind::Pipe { pipe, .. } => {
                let mut p = pipe.lock();
                if p.readers == 0 {
                    return Err(Errno::Pipe);
                }
                if PIPE_CAPACITY - p.data.len() < data.len() {
                    return Err(nonblock_or_wait(self.flags));
                }
                p.data.extend(data);
                crate::task::sched::request_pipe_wake();
                Ok(data.len())
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

    /// 定位 I/O 只接受 inode 对象；流式对象返回 ESPIPE。
    pub(crate) fn check_positioned(&self) -> Result<(), Errno> {
        match self.kind {
            Kind::Inode { .. } => Ok(()),
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
    let ino = fs::lookup(&ctx.path((-100isize) as usize, path)?)?;
    let (mode, len, _, _) = fs::stat(ino)?;
    if mode & 0xf000 != 0x8000 {
        return Err(Errno::Invalid);
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
pub fn mapping(ctx: &Context, fd: usize, write: bool) -> Result<(u32, bool), Errno> {
    let handle = ctx.get(fd)?;
    let f = handle.lock();
    if f.flags & 3 == 1 || (write && f.flags & 3 != 2) {
        return Err(Errno::BadF);
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
