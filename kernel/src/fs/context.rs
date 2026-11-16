//! 每进程工作目录、fd 表与文件类系统调用分发；dup/fork 共享打开文件
//! 的偏移；read/write 循环分块，pipe 阻塞语义见 ostd-contracts §4。
use crate::{
    fs,
    mm::{address_space::UserAddressSpace, user_access},
    syscall::{sysnr, Errno},
};
use alloc::{collections::VecDeque, string::String, sync::Arc, vec::Vec};
use spin::Mutex;

/// pipe 缓冲容量（对齐 Linux 默认 64KiB）；写满/读空时阻塞等待。
const PIPE_CAPACITY: usize = 65536;

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
struct OpenFile {
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
type Handle = Arc<Mutex<OpenFile>>;
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
                    kind,
                    offset: 0,
                    flags: 2,
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
    fn get(&self, fd: usize) -> Result<Handle, Errno> {
        self.fds
            .get(fd)
            .and_then(|f| f.as_ref().map(|d| d.handle.clone()))
            .ok_or(Errno::BadF)
    }
    fn install(&mut self, file: Handle, cloexec: bool) -> Result<usize, Errno> {
        if let Some(i) = self.fds.iter().position(Option::is_none) {
            self.fds[i] = Some(Descriptor {
                handle: file,
                cloexec,
            });
            return Ok(i);
        }
        if self.fds.len() >= 1024 {
            return Err(Errno::TooManyFiles);
        }
        self.fds.try_reserve(1).map_err(|_| Errno::NoMem)?;
        self.fds.push(Some(Descriptor {
            handle: file,
            cloexec,
        }));
        Ok(self.fds.len() - 1)
    }
    fn path(&self, dir: usize, input: &str) -> Result<String, Errno> {
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
        for component in input.split('/') {
            if !component.is_empty() && fs::stat(fs::lookup(&out)?)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            match component {
                "" | "." => {}
                ".." => {
                    if let Some(i) = out.rfind('/') {
                        out.truncate(i.max(1));
                    }
                }
                name => {
                    if name.len() > 255 {
                        return Err(Errno::NameTooLong);
                    }
                    if out != "/" {
                        out.push('/');
                    }
                    out.push_str(name);
                }
            }
        }
        if out.len() > 4096 {
            return Err(Errno::NameTooLong);
        }
        Ok(out)
    }
}

/// 从用户内存读取 NUL 结尾路径，最长 4096 字节。
pub fn user_path(space: &UserAddressSpace, ptr: usize) -> Result<String, Errno> {
    let mut bytes = Vec::new();
    bytes.try_reserve(4096).map_err(|_| Errno::NoMem)?;
    for n in 0..4096 {
        let mut b = [0];
        user_access::copy_from_user(space, ptr.checked_add(n).ok_or(Errno::Fault)?, &mut b)
            .map_err(|_| Errno::Fault)?;
        if b[0] == 0 {
            return String::from_utf8(bytes).map_err(|_| Errno::Invalid);
        }
        bytes.push(b[0]);
    }
    Err(Errno::NameTooLong)
}
fn parent(path: &str) -> Result<(u32, &str), Errno> {
    let i = path.rfind('/').ok_or(Errno::Invalid)?;
    let dir = fs::lookup(if i == 0 { "/" } else { &path[..i] })?;
    if fs::stat(dir)?.0 & 0xf000 != 0x4000 {
        return Err(Errno::NotDir);
    }
    Ok((dir, &path[i + 1..]))
}

/// Linux 文件调用，所有用户缓冲区经 user_access 复制。
pub fn dispatch(
    nr: usize,
    a: [usize; 6],
    space: &UserAddressSpace,
    ctx: &mut Context,
) -> Result<usize, Errno> {
    match nr {
        sysnr::GETCWD => {
            if a[1] < ctx.cwd.len() + 1 {
                return Err(Errno::Range);
            }
            user_access::copy_to_user(space, a[0], ctx.cwd.as_bytes()).map_err(|_| Errno::Fault)?;
            user_access::copy_to_user(
                space,
                a[0].checked_add(ctx.cwd.len()).ok_or(Errno::Fault)?,
                &[0],
            )
            .map_err(|_| Errno::Fault)?;
            Ok(ctx.cwd.len() + 1)
        }
        sysnr::DUP => ctx.install(ctx.get(a[0])?, false),
        sysnr::DUP3 => {
            if a[2] & !0x80000 != 0 || a[0] == a[1] {
                return Err(Errno::Invalid);
            }
            let file = ctx.get(a[0])?;
            if a[1] >= 1024 {
                return Err(Errno::BadF);
            }
            if a[1] >= ctx.fds.len() {
                ctx.fds
                    .try_reserve(a[1] + 1 - ctx.fds.len())
                    .map_err(|_| Errno::NoMem)?;
                ctx.fds.resize_with(a[1] + 1, || None);
            }
            ctx.fds[a[1]] = Some(Descriptor {
                handle: file,
                cloexec: a[2] & 0x80000 != 0,
            });
            Ok(a[1])
        }
        sysnr::MKDIRAT => {
            let path = ctx.path(a[0], &user_path(space, a[1])?)?;
            match fs::lookup(&path) {
                Ok(_) => Err(Errno::Exists),
                Err(Errno::NoEntry) => {
                    let (p, name) = parent(&path)?;
                    fs::create(p, name, 0x4000 | (a[2] as u16 & 0o777))?;
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        }
        sysnr::MOUNT => {
            if a[3] != 0 {
                return Err(Errno::NotSupported);
            }
            let source = user_path(space, a[0])?;
            let target = ctx.path((-100isize) as usize, &user_path(space, a[1])?)?;
            let kind = user_path(space, a[2])?;
            if kind != "vfat" && kind != "fat" {
                return Err(Errno::NoDevice);
            }
            if fs::stat(fs::lookup(&target)?)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            fs::fat::mount(&source, &target)?;
            Ok(0)
        }
        sysnr::UMOUNT2 => {
            if a[1] != 0 {
                return Err(Errno::NotSupported);
            }
            let target = ctx.path((-100isize) as usize, &user_path(space, a[0])?)?;
            fs::fat::unmount(&target)?;
            Ok(0)
        }
        sysnr::UNLINKAT => {
            if a[2] != 0 {
                return Err(Errno::NotSupported);
            }
            let path = ctx.path(a[0], &user_path(space, a[1])?)?;
            let ino = fs::lookup(&path)?;
            let (p, name) = parent(&path)?;
            fs::unlink(p, ino, name)?;
            Ok(0)
        }
        sysnr::PIPE2 => {
            if a[1] & !(0x80000 | 0x800) != 0 {
                return Err(Errno::Invalid);
            }
            let mut data = VecDeque::new();
            data.try_reserve(4096).map_err(|_| Errno::NoMem)?;
            let pipe = crate::fs::try_arc(Mutex::new(Pipe {
                data,
                readers: 1,
                writers: 1,
            }))?;
            let r = crate::fs::try_arc(Mutex::new(OpenFile {
                kind: Kind::Pipe {
                    pipe: pipe.clone(),
                    reading: true,
                },
                offset: 0,
                flags: a[1],
            }))?;
            let w = crate::fs::try_arc(Mutex::new(OpenFile {
                kind: Kind::Pipe {
                    pipe,
                    reading: false,
                },
                offset: 0,
                flags: a[1] | 1,
            }))?;
            let rfd = ctx.install(r, a[1] & 0x80000 != 0)?;
            let wfd = match ctx.install(w, a[1] & 0x80000 != 0) {
                Ok(fd) => fd,
                Err(e) => {
                    ctx.fds[rfd] = None;
                    return Err(e);
                }
            };
            let mut pair = [0; 8];
            pair[..4].copy_from_slice(&(rfd as u32).to_ne_bytes());
            pair[4..].copy_from_slice(&(wfd as u32).to_ne_bytes());
            if user_access::copy_to_user(space, a[0], &pair).is_err() {
                ctx.fds[rfd] = None;
                ctx.fds[wfd] = None;
                return Err(Errno::Fault);
            }
            Ok(0)
        }
        sysnr::GETDENTS64 => {
            let handle = ctx.get(a[0])?;
            let mut f = handle.lock();
            let ino = match f.kind {
                Kind::Inode { ino, .. } => ino,
                _ => return Err(Errno::NotDir),
            };
            if fs::stat(ino)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            let mut out = [0u8; 4096];
            let cap = a[2].min(out.len());
            let mut used = 0;
            let mut offset = f.offset;
            loop {
                let mut entry = [0u8; 264];
                let n = fs::read_dir_at(ino, offset, &mut entry)?;
                if n == 0 {
                    break;
                }
                if n < 8 {
                    return Err(Errno::Io);
                }
                let inode = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                let disk_len = u16::from_le_bytes([entry[4], entry[5]]) as usize;
                let name_len = entry[6] as usize;
                if disk_len < 8
                    || disk_len % 4 != 0
                    || disk_len > fs::EXT4_BLOCK_SIZE - offset % fs::EXT4_BLOCK_SIZE
                    || name_len + 8 > n
                    || name_len + 8 > disk_len
                {
                    return Err(Errno::Io);
                }
                let next = offset.checked_add(disk_len).ok_or(Errno::Io)?;
                if inode != 0 {
                    let len = (19 + name_len + 1 + 7) & !7;
                    if used + len > cap {
                        if used == 0 {
                            return Err(Errno::Invalid);
                        }
                        break;
                    }
                    let d = &mut out[used..used + len];
                    d[..8].copy_from_slice(&(inode as u64).to_ne_bytes());
                    d[8..16].copy_from_slice(&(next as u64).to_ne_bytes());
                    d[16..18].copy_from_slice(&(len as u16).to_ne_bytes());
                    d[18] = match entry[7] {
                        1 => 8,
                        2 => 4,
                        3 => 2,
                        4 => 6,
                        5 => 1,
                        6 => 12,
                        7 => 10,
                        _ => 0,
                    };
                    d[19..19 + name_len].copy_from_slice(&entry[8..8 + name_len]);
                    used += len;
                }
                offset = next;
            }
            user_access::copy_to_user(space, a[1], &out[..used]).map_err(|_| Errno::Fault)?;
            f.offset = offset;
            Ok(used)
        }
        sysnr::CHDIR => {
            let path = ctx.path((-100isize) as usize, &user_path(space, a[0])?)?;
            if fs::stat(fs::lookup(&path)?)?.0 & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            ctx.cwd = path;
            Ok(0)
        }
        sysnr::OPENAT => {
            if a[2] & 3 == 3 {
                return Err(Errno::Invalid);
            }
            if a[2] & 0x10000 != 0 && a[2] & 64 != 0 {
                return Err(Errno::Invalid);
            }
            let path = ctx.path(a[0], &user_path(space, a[1])?)?;
            let ino = match fs::lookup(&path) {
                Ok(ino) => {
                    if a[2] & 0xc0 == 0xc0 {
                        return Err(Errno::Exists);
                    }
                    ino
                }
                Err(Errno::NoEntry) if a[2] & 64 != 0 => {
                    let (p, name) = parent(&path)?;
                    fs::create(p, name, 0x8000 | (a[3] as u16 & 0o777))?
                }
                Err(e) => return Err(e),
            };
            let mode = fs::stat(ino)?.0;
            if a[2] & 0x10000 != 0 && mode & 0xf000 != 0x4000 {
                return Err(Errno::NotDir);
            }
            if mode & 0xf000 == 0x4000 && a[2] & 3 != 0 {
                return Err(Errno::IsDir);
            }
            if a[2] & 0x200 != 0 && a[2] & 3 != 0 {
                fs::truncate(ino)?;
            }
            fs::retain(ino)?;
            ctx.install(
                crate::fs::try_arc(Mutex::new(OpenFile {
                    kind: Kind::Inode { ino, path },
                    offset: 0,
                    flags: a[2],
                }))?,
                a[2] & 0x80000 != 0,
            )
        }
        #[cfg(not(feature = "rsext4-readonly"))]
        sysnr::FSYNC => {
            let handle = ctx.get(a[0])?;
            let ino = match handle.lock().kind {
                Kind::Inode { ino, .. } => ino,
                _ => return Err(Errno::Invalid),
            };
            fs::sync_inode(ino)?;
            Ok(0)
        }
        sysnr::CLOSE => {
            let slot = ctx.fds.get_mut(a[0]).ok_or(Errno::BadF)?;
            slot.take().ok_or(Errno::BadF)?;
            Ok(0)
        }
        sysnr::LSEEK => {
            let handle = ctx.get(a[0])?;
            let mut f = handle.lock();
            let ino = match f.kind {
                Kind::Inode { ino, .. } => ino,
                _ => return Err(Errno::SeekPipe),
            };
            let base = match a[2] {
                0 => 0,
                1 => f.offset,
                2 => fs::stat(ino)?.1 as usize,
                _ => return Err(Errno::Invalid),
            };
            let offset = base as i128 + (a[1] as isize) as i128;
            if offset < 0 || offset > isize::MAX as i128 {
                return Err(Errno::Invalid);
            }
            f.offset = offset as usize;
            Ok(f.offset)
        }
        sysnr::READ | sysnr::WRITE => rw(nr, a, space, ctx),
        sysnr::STATX => {
            let path = user_path(space, a[1])?;
            if a[2] & !(0x1000 | 0x100 | 0x800 | 0x6000) != 0 {
                return Err(Errno::Invalid);
            }
            let (ino, mode, size, links, blocks) = if path.is_empty() && a[2] & 0x1000 != 0 {
                let handle = ctx.get(a[0])?;
                let f = handle.lock();
                match &f.kind {
                    Kind::Inode { ino, .. } => {
                        let (m, s, l, b) = fs::stat(*ino)?;
                        (*ino as u64, m, s, l, b)
                    }
                    _ => (0, 0x2000 | 0o666, 0, 1, 0),
                }
            } else {
                let ino = fs::lookup(&ctx.path(a[0], &path)?)?;
                let (m, s, l, b) = fs::stat(ino)?;
                (ino as u64, m, s, l, b)
            };
            let mut data = [0u8; 256];
            data[0..4].copy_from_slice(&0x307u32.to_ne_bytes());
            data[4..8].copy_from_slice(&4096u32.to_ne_bytes());
            data[16..20].copy_from_slice(&(links as u32).to_ne_bytes());
            data[28..30].copy_from_slice(&mode.to_ne_bytes());
            data[32..40].copy_from_slice(&ino.to_ne_bytes());
            data[40..48].copy_from_slice(&size.to_ne_bytes());
            data[48..56].copy_from_slice(&blocks.to_ne_bytes());
            user_access::copy_to_user(space, a[4], &data).map_err(|_| Errno::Fault)?;
            Ok(0)
        }
        sysnr::FSTAT => {
            let handle = ctx.get(a[0])?;
            let f = handle.lock();
            let (ino, mode, size, links, blocks) = match &f.kind {
                Kind::Inode { ino, .. } => {
                    let (m, s, l, b) = fs::stat(*ino)?;
                    (*ino as u64, m, s, l, b)
                }
                _ => (0, 0x2000 | 0o666, 0, 1, 0),
            };
            let mut data = [0u8; 128];
            data[8..16].copy_from_slice(&ino.to_ne_bytes());
            data[16..20].copy_from_slice(&(mode as u32).to_ne_bytes());
            data[20..24].copy_from_slice(&(links as u32).to_ne_bytes());
            data[48..56].copy_from_slice(&size.to_ne_bytes());
            data[56..60].copy_from_slice(&4096u32.to_ne_bytes());
            data[64..72].copy_from_slice(&blocks.to_ne_bytes());
            user_access::copy_to_user(space, a[1], &data).map_err(|_| Errno::Fault)?;
            Ok(0)
        }
        _ => Err(Errno::NoSys),
    }
}

/// read(2)/write(2)：分块循环直至缓冲区填满/写尽或 EOF；单次分块上限
/// 4KiB（内核栈缓冲）。pipe 读空/写满：O_NONBLOCK 返回 EAGAIN，否则
/// 返回 EWOULDBLOCK 由分发层转为阻塞等待，醒来后重执行重查。
/// 状态变化（pipe 读/写、对端关闭）请求唤醒对应等待者。
fn rw(nr: usize, a: [usize; 6], space: &UserAddressSpace, ctx: &Context) -> Result<usize, Errno> {
    let reading = nr == sysnr::READ;
    let handle = ctx.get(a[0])?;
    let mut f = handle.lock();
    if (reading && f.flags & 3 == 1) || (!reading && f.flags & 3 == 0) {
        return Err(Errno::BadF);
    }
    let total = a[2];
    if total == 0 {
        return Ok(0);
    }
    let mut chunk = [0u8; 4096];
    let mut done = 0;
    while done < total {
        let want = (total - done).min(chunk.len());
        let part: Result<usize, Errno> = (|| {
            if !reading {
                user_access::copy_from_user(space, a[1] + done, &mut chunk[..want])
                    .map_err(|_| Errno::Fault)?;
            }
            match &f.kind {
                Kind::Output if !reading => {
                    use polyhal::debug_console::DebugConsole;
                    for &b in &chunk[..want] {
                        DebugConsole::putchar(b);
                    }
                    Ok(want)
                }
                Kind::Input if reading => Ok(0),
                Kind::Pipe { pipe, .. } => {
                    let mut p = pipe.lock();
                    if reading {
                        if p.data.is_empty() {
                            if p.writers == 0 {
                                return Ok(0);
                            }
                            return Err(nonblock_or_wait(f.flags));
                        }
                        let count = want.min(p.data.len());
                        for (i, b) in p.data.iter().take(count).enumerate() {
                            chunk[i] = *b;
                        }
                        user_access::copy_to_user(space, a[1] + done, &chunk[..count])
                            .map_err(|_| Errno::Fault)?;
                        p.data.drain(..count);
                        // 腾出空间，唤醒写者
                        crate::task::sched::request_pipe_wake();
                        Ok(count)
                    } else {
                        if p.readers == 0 {
                            return Err(Errno::Pipe);
                        }
                        if PIPE_CAPACITY - p.data.len() < want {
                            return Err(nonblock_or_wait(f.flags));
                        }
                        p.data.extend(&chunk[..want]);
                        // 有数据可读，唤醒读者
                        crate::task::sched::request_pipe_wake();
                        Ok(want)
                    }
                }
                Kind::Inode { ino, .. } => {
                    let ino = *ino;
                    if fs::stat(ino)?.0 & 0xf000 == 0x4000 {
                        return Err(Errno::IsDir);
                    }
                    let offset = if !reading && f.flags & 0x400 != 0 {
                        fs::stat(ino)?.1 as usize
                    } else {
                        f.offset
                    };
                    let count = if reading {
                        fs::read(ino, offset, &mut chunk[..want])?
                    } else {
                        fs::write(ino, offset, &chunk[..want])?
                    };
                    if reading {
                        user_access::copy_to_user(space, a[1] + done, &chunk[..count])
                            .map_err(|_| Errno::Fault)?;
                    }
                    f.offset = offset.checked_add(count).ok_or(Errno::Invalid)?;
                    Ok(count)
                }
                _ => Err(Errno::BadF),
            }
        })();
        match part {
            Ok(0) => break, // EOF（或零长请求）
            Ok(n) => done += n,
            Err(e) => {
                // 部分完成后出错：返回已完成量（Linux 短读/短写语义）
                if done != 0 {
                    return Ok(done);
                }
                return Err(e);
            }
        }
    }
    Ok(done)
}

/// pipe 阻塞判定：O_NONBLOCK 返回 EAGAIN，否则 EWOULDBLOCK（分发层
/// 转为 Flow::Wait 挂起）。
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
