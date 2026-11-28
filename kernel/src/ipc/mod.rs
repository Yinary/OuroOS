//! System V IPC 子系统：消息队列（msgget/msgctl/msgsnd/msgrcv）与
//! 信号量集（semget/semctl/semop/semtimedop）。
//! 契约与锁序见 docs/ostd-contracts.md §4 与 §5。
#![deny(unsafe_code)]

pub mod mqueue;
pub mod msg;
pub mod sem;

use core::time::Duration;

use crate::{syscall::Errno, task::Credentials};

/// IPC_PRIVATE：每次调用都新建独立私有对象。
pub const IPC_PRIVATE: i32 = 0;
/// IPC_CREAT：键不存在时创建。
pub const IPC_CREAT: i32 = 0o1000;
/// IPC_EXCL：与 IPC_CREAT 同用，键已存在时返回 EEXIST。
pub const IPC_EXCL: i32 = 0o2000;
/// IPC_NOWAIT：资源未就绪时不阻塞，立即返回错误。
pub const IPC_NOWAIT: i32 = 0o4000;

/// 通用 IPC 控制命令（asm-generic 64 位 Linux UAPI）。
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;
/// 64 位 IPC 命令可选携带的 IPC_64 标志位。
pub const IPC_64: i32 = 0x100;

/// 索引与序号编码跨度；保持生成出的 id 始终为非负 i32。
pub(crate) const IPCMNI: usize = 32768;
/// 序号掩码（0..32767），确保 `seq * IPCMNI + idx <= 0x3fff_ffff < i32::MAX`。
pub(crate) const IPC_SEQ_MASK: u16 = 0x7fff;

/// 读权限请求位（S_IRUGO）。
pub(crate) const IPC_R: i32 = 0o444;
/// 写权限请求位（S_IWUGO）。
pub(crate) const IPC_W: i32 = 0o222;

/// 标准化控制命令号（剥离 64 位可选的 IPC_64 标志位）。
#[inline]
pub const fn normalize_cmd(cmd: i32) -> i32 {
    cmd & !IPC_64
}

/// 进程阻塞在 System V IPC 系统调用期间的循环局部状态。
#[derive(Clone, Copy, Debug)]
pub struct IpcWaitState {
    /// 首次进入等待时已验证存在的对象标识，用于唤醒后区分 EIDRM 与 EINVAL。
    pub id: i32,
    /// 可选单调时钟截止时刻（用于 semtimedop）。
    pub deadline: Option<Duration>,
    /// 本次等待是否登记在信号量等待表中（供打断/退出清理 GETNCNT/GETZCNT）。
    pub is_sem: bool,
}

/// System V IPC 阻塞型调用的执行结果。
pub enum IpcFlow {
    /// 已完成，返回 Linux ABI 对应 Result。
    Done(Result<usize, Errno>),
    /// 需挂起等待指定 IPC 唤醒键与可选截止时刻。
    Wait {
        key: u64,
        deadline: Option<Duration>,
        state: IpcWaitState,
    },
}

/// 通用 IPC 权限头（对应 asm-generic 64 位 `struct ipc64_perm`，48 字节）。
#[derive(Clone, Copy, Debug)]
pub(crate) struct IpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
    pub seq: u16,
}

impl IpcPerm {
    pub fn new(key: i32, mode: i32, seq: u16, creds: &Credentials) -> Self {
        Self {
            key,
            uid: creds.euid,
            gid: creds.egid,
            cuid: creds.euid,
            cgid: creds.egid,
            mode: (mode & 0o777) as u32,
            seq,
        }
    }

    /// 按 Linux `ipcperms()` 语义检查访问权限（euid==0 视为特权放行）。
    pub fn check_access(&self, flag: i32, creds: &Credentials) -> Result<(), Errno> {
        if creds.euid == 0 {
            return Ok(());
        }
        let requested = (((flag >> 6) | (flag >> 3) | flag) & 0o7) as u32;
        if requested == 0 {
            return Ok(());
        }
        let granted = if creds.euid == self.uid || creds.euid == self.cuid {
            (self.mode >> 6) & 0o7
        } else if creds.egid == self.gid
            || creds.egid == self.cgid
            || creds.groups.contains(&self.gid)
            || creds.groups.contains(&self.cgid)
        {
            (self.mode >> 3) & 0o7
        } else {
            self.mode & 0o7
        };
        if requested & !granted != 0 {
            Err(Errno::Access)
        } else {
            Ok(())
        }
    }

    /// 检查是否拥有属主/创建者/特权身份（用于 IPC_SET 与 IPC_RMID）。
    pub fn check_owner(&self, creds: &Credentials) -> Result<(), Errno> {
        if creds.euid == 0 || creds.euid == self.uid || creds.euid == self.cuid {
            Ok(())
        } else {
            Err(Errno::Perm)
        }
    }

    /// 编码为 48 字节 `struct ipc64_perm`。
    pub fn encode(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.key.to_ne_bytes());
        out[4..8].copy_from_slice(&self.uid.to_ne_bytes());
        out[8..12].copy_from_slice(&self.gid.to_ne_bytes());
        out[12..16].copy_from_slice(&self.cuid.to_ne_bytes());
        out[16..20].copy_from_slice(&self.cgid.to_ne_bytes());
        out[20..24].copy_from_slice(&self.mode.to_ne_bytes());
        out[24..26].copy_from_slice(&self.seq.to_ne_bytes());
        // 其余字节为 __pad2 与 __unused1/__unused2，由调用方清零。
    }

    /// 从 48 字节 `struct ipc64_perm` 解码 IPC_SET 可修改字段（uid/gid/mode 低 9 位）。
    pub fn decode_set(raw: &[u8]) -> (u32, u32, u32) {
        let uid = u32::from_ne_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let gid = u32::from_ne_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let mode = u32::from_ne_bytes([raw[20], raw[21], raw[22], raw[23]]) & 0o777;
        (uid, gid, mode)
    }
}

/// 生成消息队列定向唤醒键（高位标签 0x4000_0000_0000_0000，恒非零）。
#[inline]
pub(crate) const fn msg_wake_key(id: usize) -> u64 {
    (1u64 << 62) | (id as u64)
}

/// 生成信号量集定向唤醒键（高位标签 0x8000_0000_0000_0000，恒非零）。
#[inline]
pub(crate) const fn sem_wake_key(id: usize) -> u64 {
    (1u64 << 63) | (id as u64)
}

#[inline]
pub(crate) fn now_secs() -> i64 {
    crate::time::realtime().as_secs() as i64
}
