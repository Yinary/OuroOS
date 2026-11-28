//! 套接字类系统调用实现（socket/socketpair/bind/listen/accept/connect/getsockname/
//! getpeername/sendto/recvfrom/setsockopt/getsockopt/shutdown）。
//! 当前覆盖 AF_INET 本地回环 UDP/TCP 与 AF_UNIX 匿名套接字对，语义范围见 docs/ostd-contracts.md。
#![deny(unsafe_code)]

use alloc::vec::Vec;
use core::time::Duration;

use crate::{
    fs::context::Context,
    mm::{address_space::UserAddressSpace, user_access},
    net::{
        self, SockType, SocketAddr, SocketAddrV4, AF_INET, AF_NETLINK, AF_UNIX, AF_UNSPEC,
        IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, MSG_CMSG_CLOEXEC, MSG_CTRUNC, MSG_DONTWAIT,
        MSG_NOSIGNAL, MSG_TRUNC, MSG_WAITFORONE, SCM_RIGHTS, SOCKADDR_IN_LEN, SOCK_CLOEXEC,
        SOCK_DGRAM, SOCK_NONBLOCK, SOCK_RAW, SOCK_STREAM, SOL_SOCKET,
    },
    syscall::{sysnr, Errno},
    task::{
        signal::{SigInfoSlot, SignalGroup, SignalSet, SIGPIPE},
        WaitReason,
    },
};

const MAX_OPTVAL_LEN: usize = 512;
const MAX_SENDRECV_CHUNK: usize = 65536;

/// 阻塞型套接字调用的结果：立即完成或挂起等待。
pub(crate) enum NetFlow {
    Done(Result<usize, Errno>),
    Wait(WaitReason),
}

fn read_sockaddr(
    space: &UserAddressSpace,
    fs: &Context,
    addr: usize,
    addrlen: usize,
    allow_unspec: bool,
) -> Result<Option<SocketAddr>, Errno> {
    if addr == 0 {
        return Err(Errno::Fault);
    }
    if !(2..=128).contains(&addrlen) {
        return Err(Errno::Invalid);
    }
    let mut raw = [0u8; 128];
    user_access::copy_from_user(space, addr, &mut raw[..addrlen]).map_err(|_| Errno::Fault)?;
    let family = u16::from_ne_bytes([raw[0], raw[1]]);
    if allow_unspec && family == AF_UNSPEC {
        return Ok(None);
    }
    if family == AF_UNIX {
        let path_raw = &raw[2..addrlen];
        if path_raw.is_empty() {
            return Ok(Some(SocketAddr::Unix));
        }
        if path_raw[0] == 0 {
            let mut key = Vec::new();
            key.try_reserve_exact(path_raw.len())
                .map_err(|_| Errno::NoMem)?;
            key.extend_from_slice(path_raw);
            return Ok(Some(SocketAddr::UnixPath(key)));
        }
        let end = path_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_raw.len());
        if end == 0 {
            return Ok(Some(SocketAddr::Unix));
        }
        let s = core::str::from_utf8(&path_raw[..end]).map_err(|_| Errno::Invalid)?;
        let canonical = fs.path((-100isize) as usize, s)?;
        return Ok(Some(SocketAddr::UnixPath(canonical.into_bytes())));
    }
    SocketAddrV4::from_bytes(&raw[..addrlen]).map(|v4| Some(SocketAddr::V4(v4)))
}

fn encode_sockaddr(sockaddr: &SocketAddr) -> ([u8; 110], usize) {
    let mut buf = [0u8; 110];
    let total_len = match sockaddr {
        SocketAddr::V4(v4) => {
            buf[..SOCKADDR_IN_LEN].copy_from_slice(&v4.to_bytes());
            SOCKADDR_IN_LEN
        }
        SocketAddr::Unix => {
            buf[0..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
            2
        }
        SocketAddr::UnixPath(path) => {
            buf[0..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
            let is_abstract = path.first() == Some(&0);
            let max_body = if is_abstract { 108 } else { 107 };
            let n = path.len().min(max_body);
            buf[2..2 + n].copy_from_slice(&path[..n]);
            if is_abstract {
                2 + n
            } else {
                buf[2 + n] = 0;
                2 + n + 1
            }
        }
    };
    (buf, total_len)
}

fn write_sockaddr(
    space: &UserAddressSpace,
    addr: usize,
    addrlen_ptr: usize,
    sockaddr: SocketAddr,
) -> Result<(), Errno> {
    if addr == 0 || addrlen_ptr == 0 {
        return Err(Errno::Fault);
    }
    let mut len_bytes = [0u8; 4];
    user_access::copy_from_user(space, addrlen_ptr, &mut len_bytes).map_err(|_| Errno::Fault)?;
    let user_len = i32::from_ne_bytes(len_bytes);
    if user_len < 0 {
        return Err(Errno::Invalid);
    }
    let (buf, total_len) = encode_sockaddr(&sockaddr);
    let copy_len = (user_len as usize).min(total_len);
    if copy_len > 0 {
        user_access::copy_to_user(space, addr, &buf[..copy_len]).map_err(|_| Errno::Fault)?;
    }
    let actual_len = (total_len as u32).to_ne_bytes();
    user_access::copy_to_user(space, addrlen_ptr, &actual_len).map_err(|_| Errno::Fault)?;
    Ok(())
}

/// 同步套接字系统调用分发（不阻塞、不修改其他进程记录）。
pub(crate) fn dispatch_sync(
    nr: usize,
    args: [usize; 6],
    space: &UserAddressSpace,
    fs: &mut Context,
) -> Result<usize, Errno> {
    match nr {
        sysnr::SOCKET => {
            // socket(2)：创建 AF_INET 或 AF_UNIX 的 SOCK_STREAM/SOCK_DGRAM 套接字。
            let domain = args[0] as u32 as i32;
            let raw_type = args[1] as u32 as usize;
            let protocol = args[2] as u32 as i32;
            if domain != AF_INET as i32 && domain != AF_UNIX as i32 && domain != AF_NETLINK as i32 {
                return Err(Errno::AfNoSupport);
            }
            let flags = raw_type & !0xf;
            if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
                return Err(Errno::Invalid);
            }
            let base_type = (raw_type & 0xf) as i32;
            if !(1..=10).contains(&base_type) {
                return Err(Errno::Invalid);
            }
            if domain == AF_NETLINK as i32 {
                if base_type != SOCK_RAW && base_type != SOCK_DGRAM {
                    return Err(Errno::ProtoNoSupport);
                }
                if protocol != 0 {
                    return Err(Errno::ProtoNoSupport);
                }
                let id = net::create_netlink()?;
                return fs.open_socket(id, flags & SOCK_NONBLOCK != 0, flags & SOCK_CLOEXEC != 0);
            }
            let sock_type = if domain == AF_UNIX as i32 {
                if protocol != 0 {
                    return Err(Errno::ProtoNoSupport);
                }
                match base_type {
                    SOCK_STREAM => SockType::Stream,
                    SOCK_DGRAM => SockType::Dgram,
                    _ => return Err(Errno::ProtoNoSupport),
                }
            } else {
                match base_type {
                    SOCK_STREAM => {
                        if protocol != IPPROTO_IP && protocol != IPPROTO_TCP {
                            return Err(Errno::ProtoNoSupport);
                        }
                        SockType::Stream
                    }
                    SOCK_DGRAM => {
                        if protocol != IPPROTO_IP && protocol != IPPROTO_UDP {
                            return Err(Errno::ProtoNoSupport);
                        }
                        SockType::Dgram
                    }
                    _ => return Err(Errno::ProtoNoSupport),
                }
            };
            let id = if domain == AF_UNIX as i32 {
                net::create_unix(sock_type)?
            } else {
                net::create(sock_type)?
            };
            fs.open_socket(id, flags & SOCK_NONBLOCK != 0, flags & SOCK_CLOEXEC != 0)
        }
        sysnr::SOCKETPAIR => {
            // socketpair(2)：创建一对已互连的 AF_UNIX SOCK_STREAM/SOCK_DGRAM 套接字。
            let domain = args[0] as u32 as i32;
            let raw_type = args[1] as u32 as usize;
            let protocol = args[2] as u32 as i32;
            let sv_ptr = args[3];
            if domain != AF_UNIX as i32 && domain != AF_INET as i32 {
                return Err(Errno::AfNoSupport);
            }
            let flags = raw_type & !0xf;
            if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
                return Err(Errno::Invalid);
            }
            let base_type = (raw_type & 0xf) as i32;
            if !(1..=10).contains(&base_type) {
                return Err(Errno::Invalid);
            }
            let sock_type = match base_type {
                SOCK_STREAM => SockType::Stream,
                SOCK_DGRAM => SockType::Dgram,
                _ => return Err(Errno::ProtoNoSupport),
            };
            if domain == AF_INET as i32 {
                let proto_ok = match sock_type {
                    SockType::Stream => protocol == IPPROTO_IP || protocol == IPPROTO_TCP,
                    SockType::Dgram => protocol == IPPROTO_IP || protocol == IPPROTO_UDP,
                };
                if !proto_ok {
                    return Err(Errno::ProtoNoSupport);
                }
                return Err(Errno::NotSupported);
            }
            if protocol != 0 {
                return Err(Errno::ProtoNoSupport);
            }
            if sv_ptr == 0 {
                return Err(Errno::Fault);
            }
            let nonblock = flags & SOCK_NONBLOCK != 0;
            let cloexec = flags & SOCK_CLOEXEC != 0;
            let (id0, id1) = net::create_unix_pair(sock_type)?;
            let fd0 = match fs.open_socket(id0, nonblock, cloexec) {
                Ok(fd) => fd,
                Err(e) => {
                    net::close(id1);
                    return Err(e);
                }
            };
            let fd1 = match fs.open_socket(id1, nonblock, cloexec) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = fs.close(fd0, 0);
                    return Err(e);
                }
            };
            let mut out = [0u8; 8];
            out[0..4].copy_from_slice(&(fd0 as i32).to_ne_bytes());
            out[4..8].copy_from_slice(&(fd1 as i32).to_ne_bytes());
            if user_access::copy_to_user(space, sv_ptr, &out).is_err() {
                let _ = fs.close(fd0, 0);
                let _ = fs.close(fd1, 0);
                return Err(Errno::Fault);
            }
            Ok(0)
        }
        sysnr::BIND => {
            // bind(2)：绑定本地 IPv4 地址（0.0.0.0 或 127.x.x.x）或 AF_UNIX 路径/抽象名。
            let (id, _) = fs.socket_id(args[0])?;
            let addr = read_sockaddr(space, fs, args[1], args[2] as u32 as usize, false)?
                .ok_or(Errno::AfNoSupport)?;
            match addr {
                SocketAddr::V4(v4) => net::bind(id, v4)?,
                SocketAddr::UnixPath(path) => {
                    if !net::is_unix(id)? {
                        return Err(Errno::AfNoSupport);
                    }
                    if path.first() != Some(&0) {
                        let s = core::str::from_utf8(&path).map_err(|_| Errno::Invalid)?;
                        let (canonical, parent, name) =
                            fs.resolve_parent_entry((-100isize) as usize, s, Errno::AddrInUse)?;
                        match crate::fs::query(&canonical, false) {
                            Ok(_) => return Err(Errno::AddrInUse),
                            Err(Errno::NoEntry) => {
                                crate::fs::create_node(
                                    parent,
                                    &name,
                                    0xc000 | fs.creation_mode(0o777),
                                    0,
                                    (0, 0),
                                )?;
                            }
                            Err(e) => return Err(e),
                        }
                        net::bind_unix(id, canonical.into_bytes())?;
                    } else {
                        net::bind_unix(id, path)?;
                    }
                }
                SocketAddr::Unix => return Err(Errno::Invalid),
            }
            Ok(0)
        }
        sysnr::LISTEN => {
            // listen(2)：将 TCP 套接字置为监听状态。
            let (id, _) = fs.socket_id(args[0])?;
            net::listen(id, args[1] as u32 as i32)?;
            Ok(0)
        }
        sysnr::GETSOCKNAME => {
            // getsockname(2)：读取本地绑定地址。
            let (id, _) = fs.socket_id(args[0])?;
            let addr = net::getsockname(id)?;
            write_sockaddr(space, args[1], args[2], addr)?;
            Ok(0)
        }
        sysnr::GETPEERNAME => {
            // getpeername(2)：读取已连接套接字的对端地址。
            let (id, _) = fs.socket_id(args[0])?;
            let addr = net::getpeername(id)?;
            write_sockaddr(space, args[1], args[2], addr)?;
            Ok(0)
        }
        sysnr::SETSOCKOPT => {
            // setsockopt(2)：设置 SOL_SOCKET / IPPROTO_TCP 常用选项。
            let (id, _) = fs.socket_id(args[0])?;
            let level = args[1] as u32 as i32;
            let optname = args[2] as u32 as i32;
            let optlen = args[4] as u32 as usize;
            if optlen > MAX_OPTVAL_LEN {
                return Err(Errno::Invalid);
            }
            let mut raw = [0u8; MAX_OPTVAL_LEN];
            if optlen > 0 {
                if args[3] == 0 {
                    return Err(Errno::Fault);
                }
                user_access::copy_from_user(space, args[3], &mut raw[..optlen])
                    .map_err(|_| Errno::Fault)?;
            }
            net::setsockopt(id, level, optname, &raw[..optlen])?;
            Ok(0)
        }
        sysnr::GETSOCKOPT => {
            // getsockopt(2)：查询 SOL_SOCKET / IPPROTO_TCP 常用选项。
            let (id, _) = fs.socket_id(args[0])?;
            let level = args[1] as u32 as i32;
            let optname = args[2] as u32 as i32;
            if args[3] == 0 || args[4] == 0 {
                return Err(Errno::Fault);
            }
            let mut len_bytes = [0u8; 4];
            user_access::copy_from_user(space, args[4], &mut len_bytes)
                .map_err(|_| Errno::Fault)?;
            let user_len = i32::from_ne_bytes(len_bytes);
            if user_len < 0 {
                return Err(Errno::Invalid);
            }
            let cap = (user_len as usize).min(MAX_OPTVAL_LEN);
            let mut raw = [0u8; MAX_OPTVAL_LEN];
            let written = net::getsockopt(id, level, optname, &mut raw[..cap])?;
            if written > 0 {
                user_access::copy_to_user(space, args[3], &raw[..written])
                    .map_err(|_| Errno::Fault)?;
            }
            user_access::copy_to_user(space, args[4], &(written as u32).to_ne_bytes())
                .map_err(|_| Errno::Fault)?;
            Ok(0)
        }
        sysnr::SHUTDOWN => {
            // shutdown(2)：关闭套接字读/写方向。
            let (id, _) = fs.socket_id(args[0])?;
            net::shutdown(id, args[1] as u32 as i32)?;
            Ok(0)
        }
        _ => Err(Errno::NoSys),
    }
}

fn wait_with_timeout(
    wake_id: Option<u64>,
    timeout: Option<Duration>,
    sleep_deadline: &mut Option<Duration>,
) -> NetFlow {
    let Some(dur) = timeout else {
        return NetFlow::Wait(match wake_id {
            Some(id) => WaitReason::PipeId(id),
            None => WaitReason::Pipe,
        });
    };
    let now = crate::time::monotonic();
    let deadline = match *sleep_deadline {
        Some(d) => d,
        None => {
            let d = now.saturating_add(dur);
            *sleep_deadline = Some(d);
            d
        }
    };
    if now >= deadline {
        *sleep_deadline = None;
        NetFlow::Done(Err(Errno::Again))
    } else {
        NetFlow::Wait(WaitReason::PollUntil(deadline))
    }
}

/// 可阻塞套接字系统调用分发（accept/accept4/connect/sendto/recvfrom）。
#[allow(clippy::too_many_arguments)]
pub(crate) fn dispatch_blocking(
    nr: usize,
    args: [usize; 6],
    space: &UserAddressSpace,
    fs: &mut Context,
    signal: &mut SignalGroup,
    thread_blocked: SignalSet,
    thread_tgid: usize,
    sleep_deadline: &mut Option<Duration>,
) -> NetFlow {
    let result: Result<usize, Errno> = match nr {
        sysnr::ACCEPT | sysnr::ACCEPT4 => (|| {
            // accept(2)/accept4(2)：从监听队列取出已连接套接字并分配新 FD。
            let flags = if nr == sysnr::ACCEPT4 {
                args[3] as u32 as usize
            } else {
                0
            };
            if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
                return Err(Errno::Invalid);
            }
            let (id, nonblock) = fs.socket_id(args[0])?;
            let (server_id, peer) = net::accept(id, nonblock)?;
            let new_fd = fs.open_socket(
                server_id,
                flags & SOCK_NONBLOCK != 0,
                flags & SOCK_CLOEXEC != 0,
            )?;
            if args[1] != 0 {
                if let Err(e) = write_sockaddr(space, args[1], args[2], peer) {
                    let _ = fs.close(new_fd, 0);
                    return Err(e);
                }
            }
            Ok(new_fd)
        })(),
        sysnr::CONNECT => (|| {
            // connect(2)：发起 UDP 关联、TCP 回环连接或 AF_UNIX 连接。
            let (id, nonblock) = fs.socket_id(args[0])?;
            let dst = read_sockaddr(space, fs, args[1], args[2] as u32 as usize, true)?;
            net::connect(id, dst, nonblock)?;
            Ok(0)
        })(),
        sysnr::SENDTO => (|| {
            // sendto(2)：向套接字发送数据；对端关闭且未置 MSG_NOSIGNAL 时投递 SIGPIPE。
            let (id, nonblock) = fs.socket_id(args[0])?;
            let buf_ptr = args[1];
            let len = args[2];
            let flags = args[3] as u32;
            let dst = if args[4] != 0 {
                Some(
                    read_sockaddr(space, fs, args[4], args[5] as u32 as usize, false)?
                        .ok_or(Errno::AfNoSupport)?,
                )
            } else {
                None
            };
            let take = len.min(MAX_SENDRECV_CHUNK);
            let mut kbuf = Vec::new();
            if take > 0 {
                if buf_ptr == 0 {
                    return Err(Errno::Fault);
                }
                kbuf.try_reserve_exact(take).map_err(|_| Errno::NoMem)?;
                kbuf.resize(take, 0);
                user_access::copy_from_user(space, buf_ptr, &mut kbuf).map_err(|_| Errno::Fault)?;
            }
            let res = net::sendto(id, &kbuf, flags, dst, nonblock);
            if res == Err(Errno::Pipe) && (flags & MSG_NOSIGNAL == 0) {
                signal.generate(
                    SIGPIPE,
                    SigInfoSlot {
                        pid: thread_tgid as u32,
                        ..Default::default()
                    },
                    thread_blocked,
                );
            }
            res
        })(),
        sysnr::RECVFROM => (|| {
            // recvfrom(2)：从套接字接收数据并可选回写发送方地址。
            let (id, nonblock) = fs.socket_id(args[0])?;
            let buf_ptr = args[1];
            let len = args[2];
            let flags = args[3] as u32;
            let src_addr_ptr = args[4];
            let src_len_ptr = args[5];
            let take = len.min(MAX_SENDRECV_CHUNK);
            let mut kbuf = Vec::new();
            if take > 0 {
                if buf_ptr == 0 {
                    return Err(Errno::Fault);
                }
                kbuf.try_reserve_exact(take).map_err(|_| Errno::NoMem)?;
                kbuf.resize(take, 0);
            }
            net::recvfrom(id, &mut kbuf, flags, nonblock, |data, src| {
                if !data.is_empty() {
                    user_access::copy_to_user(space, buf_ptr, data).map_err(|_| Errno::Fault)?;
                }
                if src_addr_ptr != 0 {
                    if let Some(peer) = src {
                        write_sockaddr(space, src_addr_ptr, src_len_ptr, peer)?;
                    }
                }
                Ok(data.len())
            })
        })(),
        sysnr::SENDMSG => do_sendmsg(
            space,
            fs,
            signal,
            thread_blocked,
            thread_tgid,
            args[0],
            args[1],
            args[2] as u32,
        ),
        sysnr::RECVMSG => do_recvmsg(space, fs, args[0], args[1], args[2] as u32),
        sysnr::SENDMMSG => do_sendmmsg(
            space,
            fs,
            signal,
            thread_blocked,
            thread_tgid,
            args[0],
            args[1],
            args[2],
            args[3] as u32,
        ),
        sysnr::RECVMMSG => {
            return do_recvmmsg(
                space,
                fs,
                args[0],
                args[1],
                args[2],
                args[3] as u32,
                args[4],
                sleep_deadline,
            );
        }
        _ => Err(Errno::NoSys),
    };

    if result == Err(Errno::WouldBlock) {
        let (wake_id, timeout) = match fs.socket_id(args[0]).ok() {
            Some((id, _)) => (
                Some(id.wake_id()),
                match nr {
                    sysnr::SENDTO | sysnr::SENDMSG | sysnr::SENDMMSG | sysnr::CONNECT => {
                        net::snd_timeout(id)
                    }
                    _ => net::rcv_timeout(id),
                },
            ),
            None => (None, None),
        };
        return wait_with_timeout(wake_id, timeout, sleep_deadline);
    }
    *sleep_deadline = None;
    NetFlow::Done(result)
}

const MAX_IOV: usize = 1024;
const MAX_CMSG_LEN: usize = 2048;
const SCM_MAX_FD: usize = 253;
const MSGHDR_SIZE: usize = 56;
const MMSGHDR_SIZE: usize = 64;
const CMSGHDR_SIZE: usize = 16;

struct MsgHdr {
    name: usize,
    namelen: u32,
    iov: usize,
    iovlen: usize,
    control: usize,
    controllen: usize,
}

fn read_msghdr(space: &UserAddressSpace, ptr: usize) -> Result<MsgHdr, Errno> {
    if ptr == 0 {
        return Err(Errno::Fault);
    }
    let mut raw = [0u8; MSGHDR_SIZE];
    user_access::copy_from_user(space, ptr, &mut raw).map_err(|_| Errno::Fault)?;
    let u64_at = |off: usize| -> usize {
        usize::from_ne_bytes([
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ])
    };
    let namelen = u32::from_ne_bytes([raw[8], raw[9], raw[10], raw[11]]);
    Ok(MsgHdr {
        name: u64_at(0),
        namelen,
        iov: u64_at(16),
        iovlen: u64_at(24),
        control: u64_at(32),
        controllen: u64_at(40),
    })
}

fn import_msg_iov(
    space: &UserAddressSpace,
    iov_ptr: usize,
    iovlen: usize,
) -> Result<(Vec<(usize, usize)>, usize), Errno> {
    if iovlen > MAX_IOV {
        return Err(Errno::MsgSize);
    }
    if iovlen == 0 {
        return Ok((Vec::new(), 0));
    }
    if iov_ptr == 0 {
        return Err(Errno::Fault);
    }
    let mut iovs = Vec::new();
    iovs.try_reserve_exact(iovlen).map_err(|_| Errno::NoMem)?;
    let mut total = 0usize;
    for i in 0..iovlen {
        let mut pair = [0u8; 16];
        let p = iov_ptr.checked_add(i * 16).ok_or(Errno::Fault)?;
        user_access::copy_from_user(space, p, &mut pair).map_err(|_| Errno::Fault)?;
        let base = usize::from_ne_bytes([
            pair[0], pair[1], pair[2], pair[3], pair[4], pair[5], pair[6], pair[7],
        ]);
        let len = usize::from_ne_bytes([
            pair[8], pair[9], pair[10], pair[11], pair[12], pair[13], pair[14], pair[15],
        ]);
        total = total
            .checked_add(len)
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or(Errno::MsgSize)?;
        if len > 0 {
            if base == 0 {
                return Err(Errno::Fault);
            }
            user_access::check_user_range(base, len).map_err(|_| Errno::Fault)?;
        }
        iovs.push((base, len));
    }
    Ok((iovs, total))
}

fn parse_cmsg_rights(
    space: &UserAddressSpace,
    fs: &Context,
    control_ptr: usize,
    controllen: usize,
) -> Result<Vec<crate::fs::context::Handle>, Errno> {
    if controllen == 0 {
        return Ok(Vec::new());
    }
    if control_ptr == 0 {
        return Err(Errno::Fault);
    }
    if controllen > MAX_CMSG_LEN {
        return Err(Errno::Invalid);
    }
    let mut raw = Vec::new();
    raw.try_reserve_exact(controllen)
        .map_err(|_| Errno::NoMem)?;
    raw.resize(controllen, 0);
    user_access::copy_from_user(space, control_ptr, &mut raw).map_err(|_| Errno::Fault)?;

    let mut rights = Vec::new();
    let mut off = 0usize;
    while off < controllen {
        if controllen - off < CMSGHDR_SIZE {
            return Err(Errno::Invalid);
        }
        let cmsg_len = usize::from_ne_bytes([
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ]);
        let level = i32::from_ne_bytes([raw[off + 8], raw[off + 9], raw[off + 10], raw[off + 11]]);
        let ctype =
            i32::from_ne_bytes([raw[off + 12], raw[off + 13], raw[off + 14], raw[off + 15]]);
        if cmsg_len < CMSGHDR_SIZE || cmsg_len > controllen - off {
            return Err(Errno::Invalid);
        }
        if level == SOL_SOCKET && ctype == SCM_RIGHTS {
            let payload_len = cmsg_len - CMSGHDR_SIZE;
            let n_fds = payload_len / 4;
            if rights.len() + n_fds > SCM_MAX_FD {
                return Err(Errno::Invalid);
            }
            rights.try_reserve(n_fds).map_err(|_| Errno::NoMem)?;
            for i in 0..n_fds {
                let p = off + CMSGHDR_SIZE + i * 4;
                let fd = i32::from_ne_bytes([raw[p], raw[p + 1], raw[p + 2], raw[p + 3]]);
                if fd < 0 {
                    return Err(Errno::BadF);
                }
                rights.push(fs.get(fd as usize)?);
            }
        } else {
            return Err(Errno::Invalid);
        }
        let step = (cmsg_len + 7) & !7;
        if step == 0 {
            break;
        }
        off = off.saturating_add(step);
    }
    Ok(rights)
}

#[allow(clippy::too_many_arguments)]
/// 对应 Linux `sendmsg(2)`，支持向量缓冲与 `SCM_RIGHTS` 文件描述符传递。
fn do_sendmsg(
    space: &UserAddressSpace,
    fs: &Context,
    signal: &mut SignalGroup,
    thread_blocked: SignalSet,
    thread_tgid: usize,
    fd: usize,
    msg_ptr: usize,
    flags: u32,
) -> Result<usize, Errno> {
    let (id, nonblock) = fs.socket_id(fd)?;
    let hdr = read_msghdr(space, msg_ptr)?;
    let dst = if hdr.name != 0 {
        if (hdr.namelen as i32) < 0 {
            return Err(Errno::Invalid);
        }
        if hdr.namelen == 0 {
            None
        } else {
            Some(
                read_sockaddr(space, fs, hdr.name, hdr.namelen as usize, false)?
                    .ok_or(Errno::AfNoSupport)?,
            )
        }
    } else {
        None
    };

    let (iovs, total) = import_msg_iov(space, hdr.iov, hdr.iovlen)?;
    let rights = parse_cmsg_rights(space, fs, hdr.control, hdr.controllen)?;
    let take = total.min(MAX_SENDRECV_CHUNK);
    let mut kbuf = Vec::new();
    if take > 0 {
        kbuf.try_reserve_exact(take).map_err(|_| Errno::NoMem)?;
        kbuf.resize(take, 0);
        let mut copied = 0usize;
        for (base, len) in iovs {
            if copied >= take {
                break;
            }
            let chunk = len.min(take - copied);
            if chunk > 0 {
                user_access::copy_from_user(space, base, &mut kbuf[copied..copied + chunk])
                    .map_err(|_| Errno::Fault)?;
                copied += chunk;
            }
        }
    }
    let res = net::sendmsg_with_rights(id, &kbuf, flags, dst, nonblock, rights);
    if res == Err(Errno::Pipe) && (flags & MSG_NOSIGNAL == 0) {
        signal.generate(
            SIGPIPE,
            SigInfoSlot {
                pid: thread_tgid as u32,
                ..Default::default()
            },
            thread_blocked,
        );
    }
    res
}

/// 对应 Linux `recvmsg(2)`，支持分散接收、对端地址回写与 `SCM_RIGHTS` 控制消息。
fn do_recvmsg(
    space: &UserAddressSpace,
    fs: &mut Context,
    fd: usize,
    msg_ptr: usize,
    flags: u32,
) -> Result<usize, Errno> {
    let (id, nonblock) = fs.socket_id(fd)?;
    let hdr = read_msghdr(space, msg_ptr)?;
    if hdr.name != 0 && (hdr.namelen as i32) < 0 {
        return Err(Errno::Invalid);
    }
    if hdr.controllen > 0 && hdr.control == 0 {
        return Err(Errno::Fault);
    }
    let (iovs, total) = import_msg_iov(space, hdr.iov, hdr.iovlen)?;
    let cap = total.min(MAX_SENDRECV_CHUNK);
    let mut kbuf = Vec::new();
    if cap > 0 {
        kbuf.try_reserve_exact(cap).map_err(|_| Errno::NoMem)?;
        kbuf.resize(cap, 0);
    }
    let cloexec = flags & MSG_CMSG_CLOEXEC != 0;
    net::recvmsg_ext(
        id,
        &mut kbuf,
        flags,
        nonblock,
        |data, _orig_len, src, truncated, rights| {
            // 1. 散射数据到用户 iovec
            let mut offset = 0usize;
            for &(base, len) in &iovs {
                if offset >= data.len() {
                    break;
                }
                let chunk = len.min(data.len() - offset);
                if chunk > 0 {
                    user_access::copy_to_user(space, base, &data[offset..offset + chunk])
                        .map_err(|_| Errno::Fault)?;
                    offset += chunk;
                }
            }
            // 2. 写回发送方地址
            let out_namelen: u32 = if hdr.name != 0 {
                if let Some(peer) = src {
                    let (bytes, total_len) = encode_sockaddr(&peer);
                    let copy_len = (hdr.namelen as usize).min(total_len);
                    if copy_len > 0 {
                        user_access::copy_to_user(space, hdr.name, &bytes[..copy_len])
                            .map_err(|_| Errno::Fault)?;
                    }
                    total_len as u32
                } else {
                    0
                }
            } else {
                0
            };
            // 3. 安装并写回 SCM_RIGHTS 附属描述符
            let mut out_flags: i32 = if truncated { MSG_TRUNC as i32 } else { 0 };
            let mut installed_fds: Vec<usize> = Vec::new();
            let out_controllen: usize = if rights.is_empty() {
                0
            } else {
                let max_fds = if hdr.controllen >= CMSGHDR_SIZE {
                    (hdr.controllen - CMSGHDR_SIZE) / 4
                } else {
                    0
                };
                let want = rights.len().min(max_fds);
                let mut truncated_cmsg = want < rights.len();
                for handle in rights.iter().take(want) {
                    match fs.install(handle.clone(), cloexec) {
                        Ok(new_fd) => installed_fds.push(new_fd),
                        Err(_) => {
                            truncated_cmsg = true;
                            break;
                        }
                    }
                }
                if truncated_cmsg {
                    out_flags |= MSG_CTRUNC as i32;
                }
                if installed_fds.is_empty() {
                    0
                } else {
                    let cmsg_len = CMSGHDR_SIZE + installed_fds.len() * 4;
                    let aligned_len = ((cmsg_len + 7) & !7).min(hdr.controllen);
                    let mut cbuf = Vec::new();
                    if cbuf.try_reserve_exact(aligned_len).is_err() {
                        for f in installed_fds {
                            let _ = fs.close(f, 0);
                        }
                        return Err(Errno::NoMem);
                    }
                    cbuf.resize(aligned_len, 0);
                    cbuf[0..8].copy_from_slice(&cmsg_len.to_ne_bytes());
                    cbuf[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
                    cbuf[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
                    for (i, &f) in installed_fds.iter().enumerate() {
                        let p = CMSGHDR_SIZE + i * 4;
                        cbuf[p..p + 4].copy_from_slice(&(f as i32).to_ne_bytes());
                    }
                    if user_access::copy_to_user(space, hdr.control, &cbuf).is_err() {
                        for f in installed_fds {
                            let _ = fs.close(f, 0);
                        }
                        return Err(Errno::Fault);
                    }
                    aligned_len
                }
            };
            // 4. 写回 msghdr 的 msg_namelen、msg_controllen、msg_flags
            let write_back = (|| {
                if hdr.name != 0 {
                    user_access::copy_to_user(space, msg_ptr + 8, &out_namelen.to_ne_bytes())
                        .map_err(|_| Errno::Fault)?;
                }
                user_access::copy_to_user(space, msg_ptr + 40, &out_controllen.to_ne_bytes())
                    .map_err(|_| Errno::Fault)?;
                user_access::copy_to_user(space, msg_ptr + 48, &out_flags.to_ne_bytes())
                    .map_err(|_| Errno::Fault)?;
                Ok(())
            })();
            if let Err(e) = write_back {
                for f in installed_fds {
                    let _ = fs.close(f, 0);
                }
                return Err(e);
            }
            Ok(data.len())
        },
    )
}

#[allow(clippy::too_many_arguments)]
/// 对应 Linux `sendmmsg(2)`，批量发送多条套接字消息并回写实际发送字节数。
fn do_sendmmsg(
    space: &UserAddressSpace,
    fs: &Context,
    signal: &mut SignalGroup,
    thread_blocked: SignalSet,
    thread_tgid: usize,
    fd: usize,
    msgvec_ptr: usize,
    vlen_raw: usize,
    flags: u32,
) -> Result<usize, Errno> {
    let _ = fs.socket_id(fd)?;
    let vlen = (vlen_raw as u32 as usize).min(MAX_IOV);
    if vlen == 0 {
        return Ok(0);
    }
    if msgvec_ptr == 0 {
        return Err(Errno::Fault);
    }
    let mut sent_count = 0usize;
    for i in 0..vlen {
        let elem_ptr = msgvec_ptr
            .checked_add(i * MMSGHDR_SIZE)
            .ok_or(Errno::Fault)?;
        match do_sendmsg(
            space,
            fs,
            signal,
            thread_blocked,
            thread_tgid,
            fd,
            elem_ptr,
            flags,
        ) {
            Ok(n) => {
                user_access::copy_to_user(space, elem_ptr + 56, &(n as u32).to_ne_bytes())
                    .map_err(|_| Errno::Fault)?;
                sent_count += 1;
            }
            Err(e) => {
                if sent_count > 0 {
                    return Ok(sent_count);
                }
                return Err(e);
            }
        }
    }
    Ok(sent_count)
}

#[allow(clippy::too_many_arguments)]
/// 对应 Linux `recvmmsg(2)`，批量接收消息并支持 `MSG_WAITFORONE` 与超时控制。
fn do_recvmmsg(
    space: &UserAddressSpace,
    fs: &mut Context,
    fd: usize,
    msgvec_ptr: usize,
    vlen_raw: usize,
    flags: u32,
    timeout_ptr: usize,
    sleep_deadline: &mut Option<Duration>,
) -> NetFlow {
    let (id, _) = match fs.socket_id(fd) {
        Ok(v) => v,
        Err(e) => {
            *sleep_deadline = None;
            return NetFlow::Done(Err(e));
        }
    };
    if timeout_ptr != 0 && sleep_deadline.is_none() {
        let mut ts = [0u8; 16];
        if user_access::copy_from_user(space, timeout_ptr, &mut ts).is_err() {
            return NetFlow::Done(Err(Errno::Fault));
        }
        let sec = i64::from_ne_bytes([ts[0], ts[1], ts[2], ts[3], ts[4], ts[5], ts[6], ts[7]]);
        let nsec =
            i64::from_ne_bytes([ts[8], ts[9], ts[10], ts[11], ts[12], ts[13], ts[14], ts[15]]);
        if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
            return NetFlow::Done(Err(Errno::Invalid));
        }
        let dur = Duration::new(sec as u64, nsec as u32);
        *sleep_deadline = Some(crate::time::monotonic().saturating_add(dur));
    }
    let vlen = (vlen_raw as u32 as usize).min(MAX_IOV);
    if vlen == 0 {
        *sleep_deadline = None;
        return NetFlow::Done(Ok(0));
    }
    if msgvec_ptr == 0 {
        *sleep_deadline = None;
        return NetFlow::Done(Err(Errno::Fault));
    }
    let base_flags = flags & !MSG_WAITFORONE;
    let waitforone = flags & MSG_WAITFORONE != 0;
    let mut received = 0usize;
    for i in 0..vlen {
        let Some(elem_ptr) = msgvec_ptr.checked_add(i * MMSGHDR_SIZE) else {
            *sleep_deadline = None;
            return NetFlow::Done(if received > 0 {
                Ok(received)
            } else {
                Err(Errno::Fault)
            });
        };
        let cur_flags = if i > 0 && waitforone {
            base_flags | MSG_DONTWAIT
        } else {
            base_flags
        };
        match do_recvmsg(space, fs, fd, elem_ptr, cur_flags) {
            Ok(n) => {
                if user_access::copy_to_user(space, elem_ptr + 56, &(n as u32).to_ne_bytes())
                    .is_err()
                {
                    *sleep_deadline = None;
                    return NetFlow::Done(if received > 0 {
                        Ok(received)
                    } else {
                        Err(Errno::Fault)
                    });
                }
                received += 1;
                if let Some(dl) = *sleep_deadline {
                    if crate::time::monotonic() >= dl {
                        break;
                    }
                }
            }
            Err(Errno::WouldBlock) => {
                if received > 0 {
                    break;
                }
                if timeout_ptr != 0 {
                    let dl = sleep_deadline.unwrap_or_else(crate::time::monotonic);
                    if crate::time::monotonic() >= dl {
                        let _ = user_access::copy_to_user(space, timeout_ptr, &[0u8; 16]);
                        *sleep_deadline = None;
                        return NetFlow::Done(Ok(0));
                    }
                    return NetFlow::Wait(WaitReason::PollUntil(dl));
                }
                return wait_with_timeout(Some(id.wake_id()), net::rcv_timeout(id), sleep_deadline);
            }
            Err(e) => {
                if received > 0 {
                    break;
                }
                *sleep_deadline = None;
                return NetFlow::Done(Err(e));
            }
        }
    }
    if timeout_ptr != 0 {
        if let Some(dl) = *sleep_deadline {
            let rem = dl.saturating_sub(crate::time::monotonic());
            let mut ts = [0u8; 16];
            ts[0..8].copy_from_slice(&(rem.as_secs() as i64).to_ne_bytes());
            ts[8..16].copy_from_slice(&(rem.subsec_nanos() as i64).to_ne_bytes());
            let _ = user_access::copy_to_user(space, timeout_ptr, &ts);
        }
    }
    *sleep_deadline = None;
    NetFlow::Done(Ok(received))
}
