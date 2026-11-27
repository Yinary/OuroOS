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
        self, SockType, SocketAddr, SocketAddrV4, AF_INET, AF_UNIX, AF_UNSPEC, IPPROTO_IP,
        IPPROTO_TCP, IPPROTO_UDP, MSG_NOSIGNAL, SOCKADDR_IN_LEN, SOCK_CLOEXEC, SOCK_DGRAM,
        SOCK_NONBLOCK, SOCK_STREAM,
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
    addr: usize,
    addrlen: usize,
    allow_unspec: bool,
) -> Result<Option<SocketAddrV4>, Errno> {
    if addr == 0 {
        return Err(Errno::Fault);
    }
    if addrlen < 2 || addrlen > 128 {
        return Err(Errno::Invalid);
    }
    let mut raw = [0u8; 128];
    user_access::copy_from_user(space, addr, &mut raw[..addrlen]).map_err(|_| Errno::Fault)?;
    if allow_unspec && u16::from_ne_bytes([raw[0], raw[1]]) == AF_UNSPEC {
        return Ok(None);
    }
    SocketAddrV4::from_bytes(&raw[..addrlen]).map(Some)
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
    let mut buf = [0u8; SOCKADDR_IN_LEN];
    let total_len = match sockaddr {
        SocketAddr::V4(v4) => {
            buf.copy_from_slice(&v4.to_bytes());
            SOCKADDR_IN_LEN
        }
        SocketAddr::Unix => {
            buf[0..2].copy_from_slice(&AF_UNIX.to_ne_bytes());
            2
        }
    };
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
            // socket(2)：创建 AF_INET SOCK_STREAM/SOCK_DGRAM 套接字。
            let domain = args[0] as u32 as i32;
            let raw_type = args[1] as u32 as usize;
            let protocol = args[2] as u32 as i32;
            if domain != AF_INET as i32 {
                return Err(Errno::AfNoSupport);
            }
            let flags = raw_type & !0xf;
            if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
                return Err(Errno::Invalid);
            }
            let sock_type = match (raw_type & 0xf) as i32 {
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
                _ => return Err(Errno::ProtoType),
            };
            let id = net::create(sock_type)?;
            fs.open_socket(id, flags & SOCK_NONBLOCK != 0, flags & SOCK_CLOEXEC != 0)
        }
        sysnr::SOCKETPAIR => {
            // socketpair(2)：创建一对已互连的 AF_UNIX SOCK_STREAM/SOCK_DGRAM 套接字。
            let domain = args[0] as u32 as i32;
            let raw_type = args[1] as u32 as usize;
            let protocol = args[2] as u32 as i32;
            let sv_ptr = args[3];
            if domain == AF_INET as i32 {
                return Err(Errno::NotSupported);
            }
            if domain != AF_UNIX as i32 {
                return Err(Errno::AfNoSupport);
            }
            if protocol != 0 {
                return Err(Errno::ProtoNoSupport);
            }
            let flags = raw_type & !0xf;
            if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
                return Err(Errno::Invalid);
            }
            let sock_type = match (raw_type & 0xf) as i32 {
                SOCK_STREAM => SockType::Stream,
                SOCK_DGRAM => SockType::Dgram,
                _ => return Err(Errno::ProtoType),
            };
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
                    let _ = fs.close(fd0);
                    return Err(e);
                }
            };
            let mut out = [0u8; 8];
            out[0..4].copy_from_slice(&(fd0 as i32).to_ne_bytes());
            out[4..8].copy_from_slice(&(fd1 as i32).to_ne_bytes());
            if user_access::copy_to_user(space, sv_ptr, &out).is_err() {
                let _ = fs.close(fd0);
                let _ = fs.close(fd1);
                return Err(Errno::Fault);
            }
            Ok(0)
        }
        sysnr::BIND => {
            // bind(2)：绑定本地 IPv4 地址（0.0.0.0 或 127.x.x.x）。
            let (id, _) = fs.socket_id(args[0])?;
            let addr = read_sockaddr(space, args[1], args[2] as u32 as usize, false)?
                .ok_or(Errno::AfNoSupport)?;
            net::bind(id, addr)?;
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
                if let Err(e) = write_sockaddr(space, args[1], args[2], SocketAddr::V4(peer)) {
                    let _ = fs.close(new_fd);
                    return Err(e);
                }
            }
            Ok(new_fd)
        })(),
        sysnr::CONNECT => (|| {
            // connect(2)：发起 UDP 关联或 TCP 回环连接。
            let (id, nonblock) = fs.socket_id(args[0])?;
            let dst = read_sockaddr(space, args[1], args[2] as u32 as usize, true)?;
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
                    read_sockaddr(space, args[4], args[5] as u32 as usize, false)?
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
                        write_sockaddr(space, src_addr_ptr, src_len_ptr, SocketAddr::V4(peer))?;
                    }
                }
                Ok(data.len())
            })
        })(),
        _ => Err(Errno::NoSys),
    };

    if result == Err(Errno::WouldBlock) {
        let (wake_id, timeout) = match fs.socket_id(args[0]).ok() {
            Some((id, _)) => (
                Some(id.wake_id()),
                match nr {
                    sysnr::SENDTO | sysnr::CONNECT => net::snd_timeout(id),
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
