//! 本地回环 IPv4（AF_INET）套接字子系统：支持 UDP 数据报与 TCP 字节流。
//! 契约与支持范围见 docs/ostd-contracts.md。
#![deny(unsafe_code)]

use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use core::time::Duration;
use spin::Mutex;

use crate::syscall::Errno;

pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;

pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_NONBLOCK: usize = 0x800;
pub const SOCK_CLOEXEC: usize = 0x80000;

pub const IPPROTO_IP: i32 = 0;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;
pub const SO_TYPE: i32 = 3;
pub const SO_ERROR: i32 = 4;
pub const SO_SNDBUF: i32 = 7;
pub const SO_RCVBUF: i32 = 8;
pub const SO_KEEPALIVE: i32 = 9;
pub const SO_REUSEPORT: i32 = 15;
pub const SO_RCVTIMEO_OLD: i32 = 20;
pub const SO_SNDTIMEO_OLD: i32 = 21;
pub const SO_RCVTIMEO_NEW: i32 = 66;
pub const SO_SNDTIMEO_NEW: i32 = 67;
pub const TCP_NODELAY: i32 = 1;

pub const MSG_PEEK: u32 = 0x2;
pub const MSG_DONTWAIT: u32 = 0x40;
pub const MSG_NOSIGNAL: u32 = 0x4000;

pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// IPv4 sockaddr_in 长度（字节）。
pub const SOCKADDR_IN_LEN: usize = 16;

const EPHEMERAL_START: u16 = 49152;
const EPHEMERAL_END: u16 = 65535;
const STREAM_BUF_DEFAULT: usize = 65536;
const MAX_UDP_PAYLOAD: usize = 65507;
const MAX_UDP_QUEUE_BYTES: usize = 262_144;
const MAX_UDP_QUEUE_PACKETS: usize = 64;

/// 套接字句柄标识，由全局表分配，关闭时回收。
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SocketId(u64);

/// 支持的传输层套接字类型。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SockType {
    Stream,
    Dgram,
}

/// IPv4 套接字地址（端口按主机字节序保存）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SocketAddrV4 {
    pub ip: [u8; 4],
    pub port: u16,
}

impl SocketAddrV4 {
    pub const UNSPECIFIED: Self = Self {
        ip: [0, 0, 0, 0],
        port: 0,
    };

    /// 将 IPv4 地址编码为 16 字节 Linux struct sockaddr_in。
    pub fn to_bytes(self) -> [u8; SOCKADDR_IN_LEN] {
        let mut out = [0u8; SOCKADDR_IN_LEN];
        out[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        out[2..4].copy_from_slice(&self.port.to_be_bytes());
        out[4..8].copy_from_slice(&self.ip);
        out
    }

    /// 从 Linux struct sockaddr_in 字节切片解码。
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Errno> {
        if raw.len() < SOCKADDR_IN_LEN {
            return Err(Errno::Invalid);
        }
        let family = u16::from_ne_bytes([raw[0], raw[1]]);
        if family != AF_INET {
            return Err(Errno::AfNoSupport);
        }
        let port = u16::from_be_bytes([raw[2], raw[3]]);
        let ip = [raw[4], raw[5], raw[6], raw[7]];
        Ok(Self { ip, port })
    }

    fn is_loopback_or_any(self) -> bool {
        self.ip == [0, 0, 0, 0] || self.ip[0] == 127
    }

    /// 本地回环通信中未指定地址（0.0.0.0）解析为 127.0.0.1。
    fn resolve_loopback(self) -> Self {
        let ip = if self.ip == [0, 0, 0, 0] {
            [127, 0, 0, 1]
        } else {
            self.ip
        };
        Self {
            ip,
            port: self.port,
        }
    }
}

struct UdpDatagram {
    src: SocketAddrV4,
    data: Vec<u8>,
}

struct UdpSocket {
    local: Option<SocketAddrV4>,
    peer: Option<SocketAddrV4>,
    rx: VecDeque<UdpDatagram>,
    rx_bytes: usize,
}

enum TcpState {
    Unbound,
    Bound {
        local: SocketAddrV4,
    },
    Listening {
        local: SocketAddrV4,
        backlog: usize,
        accept_queue: VecDeque<SocketId>,
    },
    Connected {
        local: SocketAddrV4,
        peer: SocketAddrV4,
        peer_id: Option<SocketId>,
        rx: VecDeque<u8>,
        peer_closed: bool,
    },
}

enum SockKind {
    Udp(UdpSocket),
    Tcp(TcpState),
}

struct SocketOptions {
    reuse_addr: bool,
    reuse_port: bool,
    keep_alive: bool,
    tcp_nodelay: bool,
    snd_buf: usize,
    rcv_buf: usize,
    rcv_timeout: Option<Duration>,
    snd_timeout: Option<Duration>,
    pending_error: i32,
}

impl Default for SocketOptions {
    fn default() -> Self {
        Self {
            reuse_addr: false,
            reuse_port: false,
            keep_alive: false,
            tcp_nodelay: false,
            snd_buf: STREAM_BUF_DEFAULT,
            rcv_buf: STREAM_BUF_DEFAULT,
            rcv_timeout: None,
            snd_timeout: None,
            pending_error: 0,
        }
    }
}

struct SocketEntry {
    kind: SockKind,
    opts: SocketOptions,
    shut_rd: bool,
    shut_wr: bool,
}

impl SocketEntry {
    fn sock_type(&self) -> SockType {
        match self.kind {
            SockKind::Udp(_) => SockType::Dgram,
            SockKind::Tcp(_) => SockType::Stream,
        }
    }

    fn local_addr(&self) -> Option<SocketAddrV4> {
        match &self.kind {
            SockKind::Udp(u) => u.local,
            SockKind::Tcp(TcpState::Unbound) => None,
            SockKind::Tcp(TcpState::Bound { local })
            | SockKind::Tcp(TcpState::Listening { local, .. })
            | SockKind::Tcp(TcpState::Connected { local, .. }) => Some(*local),
        }
    }
}

struct NetState {
    next_id: u64,
    next_port: u16,
    sockets: BTreeMap<SocketId, SocketEntry>,
}

impl NetState {
    const fn new() -> Self {
        Self {
            next_id: 1,
            next_port: EPHEMERAL_START,
            sockets: BTreeMap::new(),
        }
    }

    fn alloc_id(&mut self) -> SocketId {
        let id = SocketId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    fn port_in_use(
        &self,
        sock_type: SockType,
        addr: SocketAddrV4,
        ignore: SocketId,
        allow_reuse: bool,
    ) -> bool {
        self.sockets.iter().any(|(&id, entry)| {
            if id == ignore || entry.sock_type() != sock_type {
                return false;
            }
            let Some(bound) = entry.local_addr() else {
                return false;
            };
            if bound.port != addr.port {
                return false;
            }
            let ip_overlap =
                bound.ip == [0, 0, 0, 0] || addr.ip == [0, 0, 0, 0] || bound.ip == addr.ip;
            if !ip_overlap {
                return false;
            }
            if allow_reuse && entry.opts.reuse_port {
                return false;
            }
            // 已连接 TCP 套接字允许与同端口监听套接字共存（accept 派生端共享本地端口）
            if matches!(entry.kind, SockKind::Tcp(TcpState::Connected { .. })) {
                return false;
            }
            true
        })
    }

    fn alloc_ephemeral_port(
        &mut self,
        sock_type: SockType,
        ignore: SocketId,
    ) -> Result<u16, Errno> {
        let span = (EPHEMERAL_END - EPHEMERAL_START) as usize + 1;
        for _ in 0..span {
            let port = self.next_port;
            self.next_port = if port == EPHEMERAL_END {
                EPHEMERAL_START
            } else {
                port + 1
            };
            let candidate = SocketAddrV4 {
                ip: [0, 0, 0, 0],
                port,
            };
            if !self.port_in_use(sock_type, candidate, ignore, false) {
                return Ok(port);
            }
        }
        Err(Errno::AddrNotAvail)
    }

    fn find_udp_receiver(&self, dst: SocketAddrV4) -> Option<SocketId> {
        // 精确 IP 匹配优先于 0.0.0.0 通配绑定
        let mut wildcard = None;
        for (&id, entry) in &self.sockets {
            let SockKind::Udp(u) = &entry.kind else {
                continue;
            };
            let Some(local) = u.local else {
                continue;
            };
            if local.port != dst.port {
                continue;
            }
            if local.ip == dst.ip && dst.ip != [0, 0, 0, 0] {
                return Some(id);
            }
            if local.ip == [0, 0, 0, 0] || dst.ip == [0, 0, 0, 0] {
                wildcard = Some(id);
            }
        }
        wildcard
    }

    fn find_tcp_listener(&self, dst: SocketAddrV4) -> Option<SocketId> {
        let mut wildcard = None;
        for (&id, entry) in &self.sockets {
            let SockKind::Tcp(TcpState::Listening { local, .. }) = &entry.kind else {
                continue;
            };
            if local.port != dst.port {
                continue;
            }
            if local.ip == dst.ip && dst.ip != [0, 0, 0, 0] {
                return Some(id);
            }
            if local.ip == [0, 0, 0, 0] || dst.ip == [0, 0, 0, 0] {
                wildcard = Some(id);
            }
        }
        wildcard
    }

    fn detach_peer(&mut self, peer_id: Option<SocketId>) {
        if let Some(pid) = peer_id {
            if let Some(peer) = self.sockets.get_mut(&pid) {
                if let SockKind::Tcp(TcpState::Connected {
                    peer_id,
                    peer_closed,
                    ..
                }) = &mut peer.kind
                {
                    *peer_id = None;
                    *peer_closed = true;
                }
            }
        }
    }
}

static NET: Mutex<NetState> = Mutex::new(NetState::new());

/// 创建新的 AF_INET 套接字。
pub fn create(sock_type: SockType) -> Result<SocketId, Errno> {
    let mut net = NET.lock();
    let id = net.alloc_id();
    let kind = match sock_type {
        SockType::Dgram => SockKind::Udp(UdpSocket {
            local: None,
            peer: None,
            rx: VecDeque::new(),
            rx_bytes: 0,
        }),
        SockType::Stream => SockKind::Tcp(TcpState::Unbound),
    };
    net.sockets.insert(
        id,
        SocketEntry {
            kind,
            opts: SocketOptions::default(),
            shut_rd: false,
            shut_wr: false,
        },
    );
    Ok(id)
}

/// 关闭套接字并通知对端或清理待接收队列。
pub fn close(id: SocketId) {
    let mut net = NET.lock();
    let Some(entry) = net.sockets.remove(&id) else {
        return;
    };
    match entry.kind {
        SockKind::Udp(_) => {}
        SockKind::Tcp(TcpState::Connected { peer_id, .. }) => {
            net.detach_peer(peer_id);
            crate::task::sched::request_pipe_wake();
        }
        SockKind::Tcp(TcpState::Listening { accept_queue, .. }) => {
            for queued in accept_queue {
                if let Some(server) = net.sockets.remove(&queued) {
                    if let SockKind::Tcp(TcpState::Connected { peer_id, .. }) = server.kind {
                        net.detach_peer(peer_id);
                    }
                }
            }
            crate::task::sched::request_pipe_wake();
        }
        SockKind::Tcp(TcpState::Unbound | TcpState::Bound { .. }) => {}
    }
}

/// 绑定本地 IPv4 地址；端口为 0 时自动分配临时端口。
pub fn bind(id: SocketId, addr: SocketAddrV4) -> Result<(), Errno> {
    if !addr.is_loopback_or_any() {
        return Err(Errno::AddrNotAvail);
    }
    let mut net = NET.lock();
    let (sock_type, reuse_port) = {
        let entry = net.sockets.get(&id).ok_or(Errno::BadF)?;
        if entry.local_addr().is_some() {
            return Err(Errno::Invalid);
        }
        (entry.sock_type(), entry.opts.reuse_port)
    };
    let port = if addr.port == 0 {
        net.alloc_ephemeral_port(sock_type, id)?
    } else {
        if net.port_in_use(sock_type, addr, id, reuse_port) {
            return Err(Errno::AddrInUse);
        }
        addr.port
    };
    let bound = SocketAddrV4 { ip: addr.ip, port };
    let entry = net.sockets.get_mut(&id).ok_or(Errno::BadF)?;
    match &mut entry.kind {
        SockKind::Udp(u) => u.local = Some(bound),
        SockKind::Tcp(state @ TcpState::Unbound) => *state = TcpState::Bound { local: bound },
        SockKind::Tcp(_) => return Err(Errno::Invalid),
    }
    Ok(())
}

/// 将 TCP 套接字置为监听状态；未绑定时按 Linux 语义自动绑定临时端口。
pub fn listen(id: SocketId, backlog: i32) -> Result<(), Errno> {
    let mut net = NET.lock();
    let backlog = backlog.clamp(1, 128) as usize;
    let needs_bind = match net.sockets.get(&id).ok_or(Errno::BadF)?.kind {
        SockKind::Udp(_) => return Err(Errno::NotSupported),
        SockKind::Tcp(TcpState::Unbound) => true,
        SockKind::Tcp(TcpState::Bound { .. } | TcpState::Listening { .. }) => false,
        SockKind::Tcp(TcpState::Connected { .. }) => return Err(Errno::Invalid),
    };
    let auto_port = if needs_bind {
        Some(net.alloc_ephemeral_port(SockType::Stream, id)?)
    } else {
        None
    };
    let entry = net.sockets.get_mut(&id).ok_or(Errno::BadF)?;
    match &mut entry.kind {
        SockKind::Tcp(state) => match state {
            TcpState::Unbound => {
                let port = auto_port.ok_or(Errno::AddrNotAvail)?;
                *state = TcpState::Listening {
                    local: SocketAddrV4 {
                        ip: [0, 0, 0, 0],
                        port,
                    },
                    backlog,
                    accept_queue: VecDeque::new(),
                };
            }
            TcpState::Bound { local } => {
                let local = *local;
                *state = TcpState::Listening {
                    local,
                    backlog,
                    accept_queue: VecDeque::new(),
                };
            }
            TcpState::Listening {
                backlog: current, ..
            } => {
                *current = backlog;
            }
            TcpState::Connected { .. } => return Err(Errno::Invalid),
        },
        SockKind::Udp(_) => return Err(Errno::NotSupported),
    }
    Ok(())
}

/// 发起连接；UDP 记录默认对端，TCP 立即建立回环对端并入监听者 accept 队列。
/// 非阻塞 TCP 发起连接按 Linux 语义返回 EINPROGRESS，对端随即立即可被 accept。
pub fn connect(id: SocketId, dst: Option<SocketAddrV4>, nonblock: bool) -> Result<(), Errno> {
    let mut net = NET.lock();
    let sock_type = net.sockets.get(&id).ok_or(Errno::BadF)?.sock_type();
    if sock_type == SockType::Dgram {
        let Some(dst) = dst else {
            // AF_UNSPEC 解除 UDP 默认对端绑定
            if let Some(SocketEntry {
                kind: SockKind::Udp(u),
                ..
            }) = net.sockets.get_mut(&id)
            {
                u.peer = None;
            }
            return Ok(());
        };
        if !dst.is_loopback_or_any() {
            return Err(Errno::NetUnreach);
        }
        let needs_bind = matches!(
            net.sockets.get(&id),
            Some(SocketEntry {
                kind: SockKind::Udp(u),
                ..
            }) if u.local.is_none()
        );
        let port = if needs_bind {
            Some(net.alloc_ephemeral_port(SockType::Dgram, id)?)
        } else {
            None
        };
        if let Some(SocketEntry {
            kind: SockKind::Udp(u),
            ..
        }) = net.sockets.get_mut(&id)
        {
            if let Some(p) = port {
                u.local = Some(SocketAddrV4 {
                    ip: [0, 0, 0, 0],
                    port: p,
                });
            }
            u.peer = Some(dst.resolve_loopback());
        }
        return Ok(());
    }

    // TCP 连接
    let dst = dst.ok_or(Errno::AfNoSupport)?;
    if !dst.is_loopback_or_any() {
        return Err(Errno::NetUnreach);
    }
    if dst.port == 0 {
        return Err(Errno::ConnRefused);
    }
    let client_local = match &net.sockets.get(&id).ok_or(Errno::BadF)?.kind {
        SockKind::Tcp(TcpState::Unbound) => None,
        SockKind::Tcp(TcpState::Bound { local }) => Some(*local),
        SockKind::Tcp(TcpState::Connected { .. }) => return Err(Errno::IsConn),
        SockKind::Tcp(TcpState::Listening { .. }) => return Err(Errno::Invalid),
        SockKind::Udp(_) => return Err(Errno::Invalid),
    };
    let listener_id = net.find_tcp_listener(dst).ok_or(Errno::ConnRefused)?;
    let listener_local = match &net
        .sockets
        .get(&listener_id)
        .ok_or(Errno::ConnRefused)?
        .kind
    {
        SockKind::Tcp(TcpState::Listening {
            local,
            backlog,
            accept_queue,
        }) => {
            if accept_queue.len() >= *backlog {
                return Err(if nonblock {
                    Errno::Again
                } else {
                    Errno::WouldBlock
                });
            }
            local.resolve_loopback()
        }
        _ => return Err(Errno::ConnRefused),
    };
    let client_local = match client_local {
        Some(local) => local.resolve_loopback(),
        None => SocketAddrV4 {
            ip: [127, 0, 0, 1],
            port: net.alloc_ephemeral_port(SockType::Stream, id)?,
        },
    };
    let server_id = net.alloc_id();
    let server_entry = SocketEntry {
        kind: SockKind::Tcp(TcpState::Connected {
            local: listener_local,
            peer: client_local,
            peer_id: Some(id),
            rx: VecDeque::new(),
            peer_closed: false,
        }),
        opts: SocketOptions::default(),
        shut_rd: false,
        shut_wr: false,
    };
    net.sockets.insert(server_id, server_entry);
    if let Some(client) = net.sockets.get_mut(&id) {
        client.kind = SockKind::Tcp(TcpState::Connected {
            local: client_local,
            peer: listener_local,
            peer_id: Some(server_id),
            rx: VecDeque::new(),
            peer_closed: false,
        });
    }
    if let Some(SocketEntry {
        kind: SockKind::Tcp(TcpState::Listening { accept_queue, .. }),
        ..
    }) = net.sockets.get_mut(&listener_id)
    {
        accept_queue.push_back(server_id);
    }
    crate::task::sched::request_pipe_wake();
    if nonblock {
        Err(Errno::InProgress)
    } else {
        Ok(())
    }
}

/// 从监听队列取出一条已建立的 TCP 连接并返回新建服务端套接字与对端地址。
pub fn accept(id: SocketId, nonblock: bool) -> Result<(SocketId, SocketAddrV4), Errno> {
    let mut net = NET.lock();
    let server_id = match &mut net.sockets.get_mut(&id).ok_or(Errno::BadF)?.kind {
        SockKind::Udp(_) => return Err(Errno::NotSupported),
        SockKind::Tcp(TcpState::Listening { accept_queue, .. }) => match accept_queue.pop_front() {
            Some(sid) => sid,
            None => {
                return Err(if nonblock {
                    Errno::Again
                } else {
                    Errno::WouldBlock
                });
            }
        },
        SockKind::Tcp(_) => return Err(Errno::Invalid),
    };
    let peer = match &net.sockets.get(&server_id).ok_or(Errno::ConnReset)?.kind {
        SockKind::Tcp(TcpState::Connected { peer, .. }) => *peer,
        _ => SocketAddrV4::UNSPECIFIED,
    };
    crate::task::sched::request_pipe_wake();
    Ok((server_id, peer))
}

/// 查询本地绑定地址；未绑定时返回 0.0.0.0:0。
pub fn getsockname(id: SocketId) -> Result<SocketAddrV4, Errno> {
    let net = NET.lock();
    let entry = net.sockets.get(&id).ok_or(Errno::BadF)?;
    Ok(entry.local_addr().unwrap_or(SocketAddrV4::UNSPECIFIED))
}

/// 查询已连接套接字的对端地址；未连接返回 ENOTCONN。
pub fn getpeername(id: SocketId) -> Result<SocketAddrV4, Errno> {
    let net = NET.lock();
    let entry = net.sockets.get(&id).ok_or(Errno::BadF)?;
    match &entry.kind {
        SockKind::Udp(u) => u.peer.ok_or(Errno::NotConn),
        SockKind::Tcp(TcpState::Connected { peer, .. }) => Ok(*peer),
        SockKind::Tcp(_) => Err(Errno::NotConn),
    }
}

/// 向套接字发送数据；支持 UDP 指定目的地址和 TCP 已连接流写入。
pub fn sendto(
    id: SocketId,
    data: &[u8],
    flags: u32,
    dst: Option<SocketAddrV4>,
    nonblock: bool,
) -> Result<usize, Errno> {
    let dontwait = nonblock || (flags & MSG_DONTWAIT != 0);
    let mut net = NET.lock();
    let entry = net.sockets.get(&id).ok_or(Errno::BadF)?;
    if entry.shut_wr {
        return Err(Errno::Pipe);
    }
    match &entry.kind {
        SockKind::Udp(u) => {
            if data.len() > MAX_UDP_PAYLOAD {
                return Err(Errno::MsgSize);
            }
            let target = match dst {
                Some(d) => d,
                None => u.peer.ok_or(Errno::DestAddrReq)?,
            };
            if !target.is_loopback_or_any() {
                return Err(Errno::NetUnreach);
            }
            let sender_local = match u.local {
                Some(local) => local,
                None => {
                    let port = net.alloc_ephemeral_port(SockType::Dgram, id)?;
                    let local = SocketAddrV4 {
                        ip: [0, 0, 0, 0],
                        port,
                    };
                    if let Some(SocketEntry {
                        kind: SockKind::Udp(u_mut),
                        ..
                    }) = net.sockets.get_mut(&id)
                    {
                        u_mut.local = Some(local);
                    }
                    local
                }
            };
            let src = sender_local.resolve_loopback();
            if let Some(recv_id) = net.find_udp_receiver(target) {
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(data.len())
                    .map_err(|_| Errno::NoMem)?;
                payload.extend_from_slice(data);
                if let Some(recv_entry) = net.sockets.get_mut(&recv_id) {
                    if !recv_entry.shut_rd {
                        if let SockKind::Udp(recv_u) = &mut recv_entry.kind {
                            if recv_u.rx.len() < MAX_UDP_QUEUE_PACKETS
                                && recv_u.rx_bytes.saturating_add(payload.len())
                                    <= MAX_UDP_QUEUE_BYTES
                            {
                                recv_u.rx_bytes += payload.len();
                                recv_u.rx.push_back(UdpDatagram { src, data: payload });
                                crate::task::sched::request_pipe_wake();
                            }
                        }
                    }
                }
            }
            Ok(data.len())
        }
        SockKind::Tcp(TcpState::Connected {
            peer_id,
            peer_closed,
            ..
        }) => {
            if *peer_closed {
                return Err(Errno::Pipe);
            }
            let Some(pid) = *peer_id else {
                return Err(Errno::Pipe);
            };
            if data.is_empty() {
                return Ok(0);
            }
            let peer = net.sockets.get_mut(&pid).ok_or(Errno::Pipe)?;
            let cap = peer.opts.rcv_buf.max(4096);
            if peer.shut_rd {
                return Err(Errno::Pipe);
            }
            let SockKind::Tcp(TcpState::Connected { rx, .. }) = &mut peer.kind else {
                return Err(Errno::Pipe);
            };
            let avail = cap.saturating_sub(rx.len());
            if avail == 0 {
                return Err(if dontwait {
                    Errno::Again
                } else {
                    Errno::WouldBlock
                });
            }
            let count = data.len().min(avail);
            rx.try_reserve(count).map_err(|_| Errno::NoMem)?;
            rx.extend(&data[..count]);
            crate::task::sched::request_pipe_wake();
            Ok(count)
        }
        SockKind::Tcp(_) => Err(Errno::NotConn),
    }
}

/// 从套接字接收数据并在交付回调成功后消费缓冲；UDP 返回来源地址。
pub fn recvfrom(
    id: SocketId,
    buf: &mut [u8],
    flags: u32,
    nonblock: bool,
    deliver: impl FnOnce(&[u8], Option<SocketAddrV4>) -> Result<usize, Errno>,
) -> Result<usize, Errno> {
    let dontwait = nonblock || (flags & MSG_DONTWAIT != 0);
    let peek = flags & MSG_PEEK != 0;
    let mut net = NET.lock();
    let entry = net.sockets.get_mut(&id).ok_or(Errno::BadF)?;
    let shut_rd = entry.shut_rd;
    match &mut entry.kind {
        SockKind::Udp(u) => {
            let Some(front) = u.rx.front() else {
                if shut_rd {
                    return deliver(&[], None);
                }
                return Err(if dontwait {
                    Errno::Again
                } else {
                    Errno::WouldBlock
                });
            };
            let src = front.src;
            let count = buf.len().min(front.data.len());
            buf[..count].copy_from_slice(&front.data[..count]);
            let delivered = deliver(&buf[..count], Some(src))?;
            if !peek {
                if let Some(dgram) = u.rx.pop_front() {
                    u.rx_bytes = u.rx_bytes.saturating_sub(dgram.data.len());
                }
                crate::task::sched::request_pipe_wake();
            }
            Ok(delivered)
        }
        SockKind::Tcp(TcpState::Connected {
            rx, peer_closed, ..
        }) => {
            if rx.is_empty() {
                if *peer_closed || shut_rd {
                    return Ok(0);
                }
                return Err(if dontwait {
                    Errno::Again
                } else {
                    Errno::WouldBlock
                });
            }
            let count = buf.len().min(rx.len());
            for (slot, byte) in buf[..count].iter_mut().zip(rx.iter().take(count)) {
                *slot = *byte;
            }
            let delivered = deliver(&buf[..count], None)?;
            if delivered > count {
                return Err(Errno::Invalid);
            }
            if !peek {
                rx.drain(..delivered);
                crate::task::sched::request_pipe_wake();
            }
            Ok(delivered)
        }
        SockKind::Tcp(_) => Err(Errno::NotConn),
    }
}

/// 关闭套接字的读/写半双工方向。
pub fn shutdown(id: SocketId, how: i32) -> Result<(), Errno> {
    if !matches!(how, SHUT_RD | SHUT_WR | SHUT_RDWR) {
        return Err(Errno::Invalid);
    }
    let mut net = NET.lock();
    let peer_to_close = {
        let entry = net.sockets.get_mut(&id).ok_or(Errno::BadF)?;
        if matches!(
            entry.kind,
            SockKind::Tcp(TcpState::Unbound | TcpState::Bound { .. })
        ) {
            return Err(Errno::NotConn);
        }
        if how == SHUT_RD || how == SHUT_RDWR {
            entry.shut_rd = true;
        }
        if how == SHUT_WR || how == SHUT_RDWR {
            entry.shut_wr = true;
            if let SockKind::Tcp(TcpState::Connected { peer_id, .. }) = entry.kind {
                peer_id
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(pid) = peer_to_close {
        if let Some(peer) = net.sockets.get_mut(&pid) {
            if let SockKind::Tcp(TcpState::Connected { peer_closed, .. }) = &mut peer.kind {
                *peer_closed = true;
            }
        }
    }
    crate::task::sched::request_pipe_wake();
    Ok(())
}

/// 解析 16 字节 struct timeval，零值表示无限等待。
fn parse_timeval(raw: &[u8]) -> Result<Option<Duration>, Errno> {
    if raw.len() < 16 {
        return Err(Errno::Invalid);
    }
    let sec = i64::from_ne_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]);
    let usec = i64::from_ne_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(Errno::Invalid);
    }
    if sec == 0 && usec == 0 {
        Ok(None)
    } else {
        Ok(Some(Duration::new(sec as u64, (usec as u32) * 1000)))
    }
}

fn encode_timeval(dur: Option<Duration>) -> [u8; 16] {
    let mut out = [0u8; 16];
    if let Some(d) = dur {
        out[0..8].copy_from_slice(&(d.as_secs() as i64).to_ne_bytes());
        out[8..16].copy_from_slice(&(d.subsec_micros() as i64).to_ne_bytes());
    }
    out
}

fn parse_i32(raw: &[u8]) -> Result<i32, Errno> {
    if raw.len() < 4 {
        return Err(Errno::Invalid);
    }
    Ok(i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// 设置套接字选项（SOL_SOCKET / IPPROTO_TCP 常用子集）。
pub fn setsockopt(id: SocketId, level: i32, optname: i32, optval: &[u8]) -> Result<(), Errno> {
    let mut net = NET.lock();
    let entry = net.sockets.get_mut(&id).ok_or(Errno::BadF)?;
    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) => entry.opts.reuse_addr = parse_i32(optval)? != 0,
        (SOL_SOCKET, SO_REUSEPORT) => entry.opts.reuse_port = parse_i32(optval)? != 0,
        (SOL_SOCKET, SO_KEEPALIVE) => entry.opts.keep_alive = parse_i32(optval)? != 0,
        (SOL_SOCKET, SO_SNDBUF) => {
            let v = parse_i32(optval)?;
            entry.opts.snd_buf = (v.max(4096) as usize).min(1024 * 1024);
        }
        (SOL_SOCKET, SO_RCVBUF) => {
            let v = parse_i32(optval)?;
            entry.opts.rcv_buf = (v.max(4096) as usize).min(1024 * 1024);
        }
        (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) => {
            entry.opts.rcv_timeout = parse_timeval(optval)?;
        }
        (SOL_SOCKET, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW) => {
            entry.opts.snd_timeout = parse_timeval(optval)?;
        }
        (IPPROTO_TCP, TCP_NODELAY) => {
            if entry.sock_type() != SockType::Stream {
                return Err(Errno::NoProtoOpt);
            }
            entry.opts.tcp_nodelay = parse_i32(optval)? != 0;
        }
        _ => return Err(Errno::NoProtoOpt),
    }
    Ok(())
}

/// 读取套接字选项，返回写入 buf 的字节数。
pub fn getsockopt(id: SocketId, level: i32, optname: i32, buf: &mut [u8]) -> Result<usize, Errno> {
    let mut net = NET.lock();
    let entry = net.sockets.get_mut(&id).ok_or(Errno::BadF)?;
    let write_i32 = |buf: &mut [u8], val: i32| -> Result<usize, Errno> {
        let bytes = val.to_ne_bytes();
        let n = buf.len().min(4);
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    };
    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) => write_i32(buf, i32::from(entry.opts.reuse_addr)),
        (SOL_SOCKET, SO_REUSEPORT) => write_i32(buf, i32::from(entry.opts.reuse_port)),
        (SOL_SOCKET, SO_KEEPALIVE) => write_i32(buf, i32::from(entry.opts.keep_alive)),
        (SOL_SOCKET, SO_TYPE) => write_i32(
            buf,
            match entry.sock_type() {
                SockType::Stream => SOCK_STREAM,
                SockType::Dgram => SOCK_DGRAM,
            },
        ),
        (SOL_SOCKET, SO_ERROR) => {
            let err = entry.opts.pending_error;
            entry.opts.pending_error = 0;
            write_i32(buf, err)
        }
        (SOL_SOCKET, SO_SNDBUF) => write_i32(buf, entry.opts.snd_buf as i32),
        (SOL_SOCKET, SO_RCVBUF) => write_i32(buf, entry.opts.rcv_buf as i32),
        (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) => {
            let bytes = encode_timeval(entry.opts.rcv_timeout);
            let n = buf.len().min(bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            Ok(n)
        }
        (SOL_SOCKET, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW) => {
            let bytes = encode_timeval(entry.opts.snd_timeout);
            let n = buf.len().min(bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            Ok(n)
        }
        (IPPROTO_TCP, TCP_NODELAY) => {
            if entry.sock_type() != SockType::Stream {
                return Err(Errno::NoProtoOpt);
            }
            write_i32(buf, i32::from(entry.opts.tcp_nodelay))
        }
        _ => Err(Errno::NoProtoOpt),
    }
}

/// 读取套接字接收超时配置。
pub fn rcv_timeout(id: SocketId) -> Option<Duration> {
    NET.lock().sockets.get(&id).and_then(|e| e.opts.rcv_timeout)
}

/// 读取套接字发送超时配置。
pub fn snd_timeout(id: SocketId) -> Option<Duration> {
    NET.lock().sockets.get(&id).and_then(|e| e.opts.snd_timeout)
}

/// 计算套接字在 poll(2) 中当前就绪的事件掩码。
pub fn poll_events(id: SocketId, requested: u16) -> u16 {
    let net = NET.lock();
    let Some(entry) = net.sockets.get(&id) else {
        return 32; // POLLNVAL
    };
    let mut revents: u16 = 0;
    match &entry.kind {
        SockKind::Udp(u) => {
            if !u.rx.is_empty() || entry.shut_rd {
                revents |= 0x41 & requested;
            }
            if !entry.shut_wr {
                revents |= 0x104 & requested;
            }
        }
        SockKind::Tcp(TcpState::Listening { accept_queue, .. }) => {
            if !accept_queue.is_empty() {
                revents |= 0x41 & requested;
            }
        }
        SockKind::Tcp(TcpState::Connected {
            peer_id,
            rx,
            peer_closed,
            ..
        }) => {
            if !rx.is_empty() || *peer_closed || entry.shut_rd {
                revents |= 0x41 & requested;
            }
            if !entry.shut_wr && !*peer_closed {
                let peer_space = peer_id
                    .and_then(|pid| net.sockets.get(&pid))
                    .is_some_and(|p| match &p.kind {
                        SockKind::Tcp(TcpState::Connected { rx, .. }) => {
                            !p.shut_rd && rx.len() < p.opts.rcv_buf.max(4096)
                        }
                        _ => false,
                    });
                if peer_space {
                    revents |= 0x104 & requested;
                }
            }
            if *peer_closed {
                revents |= 0x2000 & requested; // POLLRDHUP
                if entry.shut_wr {
                    revents |= 0x10; // POLLHUP
                }
            }
        }
        SockKind::Tcp(TcpState::Unbound | TcpState::Bound { .. }) => {
            revents |= 0x10; // POLLHUP
        }
    }
    revents
}
