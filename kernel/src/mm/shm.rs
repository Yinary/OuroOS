//! System V 共享内存段表：管理 shmget/shmctl/shmat/shmdt 的全局段元数据与生命周期。
//! 物理页后备直接复用 [`super::shared::SharedPage`]，契约见 docs/ostd-contracts.md §4.3。
#![deny(unsafe_code)]

use alloc::vec::Vec;
use polyhal::pagetable::PAGE_SIZE;

use crate::{sync::DebugMutex, syscall::Errno, task::Credentials};

use super::shared::SharedPage;

/// IPC_PRIVATE：每次调用都新建独立私有共享段。
pub const IPC_PRIVATE: i32 = 0;
/// IPC_CREAT：键不存在时创建。
pub const IPC_CREAT: usize = 0o1000;
/// IPC_EXCL：与 IPC_CREAT 同用，键已存在时返回 EEXIST。
pub const IPC_EXCL: usize = 0o2000;

/// shmctl 控制命令常量（asm-generic 64 位 Linux UAPI）。
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
/// 64 位 IPC 命令可选携带的 IPC_64 标志位。
const IPC_64: i32 = 0x100;

/// 单个共享段页数上限（256 MiB / 4 KiB），防止恶意请求耗尽内核地址空间或堆。
const SHM_MAX_PAGES: usize = 65536;
/// 系统同时存在的共享段数量上限。
const SHM_MAX_SEGMENTS: usize = 1024;

/// 共享段静态元数据与页后备。
struct ShmSegment {
    id: usize,
    key: i32,
    size: usize,
    pages: usize,
    first: SharedPage,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    seq: u16,
    atime: i64,
    dtime: i64,
    ctime: i64,
    cpid: i32,
    lpid: i32,
    nattch: usize,
    removed: bool,
}

struct ShmTable {
    next_id: usize,
    next_seq: u16,
    segments: Vec<ShmSegment>,
}

impl ShmTable {
    const fn new() -> Self {
        Self {
            next_id: 1,
            next_seq: 1,
            segments: Vec::new(),
        }
    }

    fn find_by_key(&self, key: i32) -> Option<usize> {
        self.segments
            .iter()
            .position(|s| !s.removed && s.key == key)
    }

    fn find_by_id(&self, id: usize) -> Option<usize> {
        self.segments.iter().position(|s| s.id == id)
    }
}

/// 全局共享内存段表；叶子锁，锁序 REGISTRY → SHM_TABLE。
static SHM_TABLE: DebugMutex<ShmTable> = DebugMutex::new("SHM_TABLE", ShmTable::new());

fn now_secs() -> i64 {
    crate::time::realtime().as_secs() as i64
}

/// shmget(2)：按 key 查找或创建共享内存段，返回段标识 shmid。
pub fn get(
    key: i32,
    size: usize,
    shmflg: usize,
    pid: usize,
    creds: &Credentials,
) -> Result<usize, Errno> {
    let mut table = SHM_TABLE.lock();
    if key != IPC_PRIVATE {
        if let Some(idx) = table.find_by_key(key) {
            if shmflg & (IPC_CREAT | IPC_EXCL) == (IPC_CREAT | IPC_EXCL) {
                return Err(Errno::Exists);
            }
            let seg = &table.segments[idx];
            if size > seg.size {
                return Err(Errno::Invalid);
            }
            return Ok(seg.id);
        }
        if shmflg & IPC_CREAT == 0 {
            return Err(Errno::NoEntry);
        }
    }

    if size == 0 {
        return Err(Errno::Invalid);
    }
    let pages = size
        .checked_add(PAGE_SIZE - 1)
        .map(|n| n / PAGE_SIZE)
        .ok_or(Errno::Invalid)?;
    if pages == 0 || pages > SHM_MAX_PAGES {
        return Err(Errno::Invalid);
    }
    if table.segments.len() >= SHM_MAX_SEGMENTS {
        return Err(Errno::NoSpace);
    }
    table.segments.try_reserve(1).map_err(|_| Errno::NoMem)?;
    let first = SharedPage::first(true).map_err(|_| Errno::NoMem)?;

    let id = table.next_id;
    table.next_id = table.next_id.checked_add(1).ok_or(Errno::NoSpace)?;
    let seq = table.next_seq;
    table.next_seq = table.next_seq.wrapping_add(1);

    let now = now_secs();
    table.segments.push(ShmSegment {
        id,
        key,
        size,
        pages,
        first,
        uid: creds.euid,
        gid: creds.egid,
        cuid: creds.euid,
        cgid: creds.egid,
        mode: (shmflg & 0o777) as u32,
        seq,
        atime: 0,
        dtime: 0,
        ctime: now,
        cpid: pid as i32,
        lpid: 0,
        nattch: 0,
        removed: false,
    });
    Ok(id)
}

/// 准备挂接：查出共享段的首页对象与页数；段不存在返回 EINVAL。
pub(crate) fn lookup_for_attach(shmid: usize) -> Result<(SharedPage, usize), Errno> {
    let table = SHM_TABLE.lock();
    let idx = table.find_by_id(shmid).ok_or(Errno::Invalid)?;
    let seg = &table.segments[idx];
    Ok((seg.first.clone(), seg.pages))
}

/// 挂接成功后递增挂接计数并刷新 atime/lpid。
pub(crate) fn commit_attach(shmid: usize, pid: usize) {
    let mut table = SHM_TABLE.lock();
    if let Some(idx) = table.find_by_id(shmid) {
        let seg = &mut table.segments[idx];
        seg.nattch = seg.nattch.saturating_add(1);
        seg.atime = now_secs();
        seg.lpid = pid as i32;
    }
}

/// fork 继承共享段映射时递增挂接计数。
pub(crate) fn on_fork_attach(shmid: usize) {
    let mut table = SHM_TABLE.lock();
    if let Some(idx) = table.find_by_id(shmid) {
        let seg = &mut table.segments[idx];
        seg.nattch = seg.nattch.saturating_add(1);
    }
}

/// 解除一次挂接并刷新 dtime/lpid；若已标记 IPC_RMID 且挂接归零则从段表回收。
pub(crate) fn detach(shmid: usize, pid: usize) {
    let mut table = SHM_TABLE.lock();
    let Some(idx) = table.find_by_id(shmid) else {
        return;
    };
    let seg = &mut table.segments[idx];
    seg.nattch = seg.nattch.saturating_sub(1);
    if pid != 0 {
        seg.dtime = now_secs();
        seg.lpid = pid as i32;
    }
    if seg.removed && seg.nattch == 0 {
        table.segments.swap_remove(idx);
    }
}

/// shmctl(2) 的 IPC_RMID：标记延迟删除并解绑 key；当前无挂接者时立即回收段表项。
pub fn remove(shmid: usize) -> Result<(), Errno> {
    let mut table = SHM_TABLE.lock();
    let idx = table.find_by_id(shmid).ok_or(Errno::Invalid)?;
    let seg = &mut table.segments[idx];
    seg.removed = true;
    seg.key = IPC_PRIVATE;
    if seg.nattch == 0 {
        table.segments.swap_remove(idx);
    }
    Ok(())
}

/// shmctl(2) 的 IPC_STAT：按 asm-generic 64 位 struct shmid64_ds 编码为 112 字节。
pub fn stat(shmid: usize) -> Result<[u8; 112], Errno> {
    let table = SHM_TABLE.lock();
    let idx = table.find_by_id(shmid).ok_or(Errno::Invalid)?;
    let s = &table.segments[idx];
    let mut out = [0u8; 112];
    // struct ipc64_perm（48 字节）
    out[0..4].copy_from_slice(&s.key.to_ne_bytes());
    out[4..8].copy_from_slice(&s.uid.to_ne_bytes());
    out[8..12].copy_from_slice(&s.gid.to_ne_bytes());
    out[12..16].copy_from_slice(&s.cuid.to_ne_bytes());
    out[16..20].copy_from_slice(&s.cgid.to_ne_bytes());
    let mode = s.mode | if s.removed { 0o1000 } else { 0 };
    out[20..24].copy_from_slice(&mode.to_ne_bytes());
    out[24..26].copy_from_slice(&s.seq.to_ne_bytes());
    // struct shmid64_ds 主体（64 字节）
    out[48..56].copy_from_slice(&(s.size as u64).to_ne_bytes());
    out[56..64].copy_from_slice(&s.atime.to_ne_bytes());
    out[64..72].copy_from_slice(&s.dtime.to_ne_bytes());
    out[72..80].copy_from_slice(&s.ctime.to_ne_bytes());
    out[80..84].copy_from_slice(&s.cpid.to_ne_bytes());
    out[84..88].copy_from_slice(&s.lpid.to_ne_bytes());
    out[88..96].copy_from_slice(&(s.nattch as u64).to_ne_bytes());
    Ok(out)
}

/// shmctl(2) 的 IPC_SET：更新属主、属组与低 9 位权限，并刷新 ctime。
pub fn set(shmid: usize, raw: &[u8; 112]) -> Result<(), Errno> {
    let uid = u32::from_ne_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let gid = u32::from_ne_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let mode = u32::from_ne_bytes([raw[20], raw[21], raw[22], raw[23]]) & 0o777;
    let mut table = SHM_TABLE.lock();
    let idx = table.find_by_id(shmid).ok_or(Errno::Invalid)?;
    let s = &mut table.segments[idx];
    s.uid = uid;
    s.gid = gid;
    s.mode = mode;
    s.ctime = now_secs();
    Ok(())
}

/// 标准化 shmctl 命令号（剥离 64 位可选的 IPC_64 标志位）。
#[inline]
pub const fn normalize_cmd(cmd: i32) -> i32 {
    cmd & !IPC_64
}
