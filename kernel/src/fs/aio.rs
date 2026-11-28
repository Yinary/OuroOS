//! Linux AIO 异步 I/O 上下文：io_setup / io_destroy / io_submit / io_cancel / io_getevents / io_pgetevents。
//!
//! 性能设计：每进程 `AioTable` 默认空 Vec（零堆分配），仅在 `io_setup` 时按需映射单页匿名占坑区
//! （兼容 libaio 读取 `ring->magic` 而不触发页错误，按需缺页、未读零物理页）；I/O 执行复用
//! `syscall::fs` 的 256B 栈缓冲与 64 KiB 共享暂存池，无额外大缓冲分配。
#![deny(unsafe_code)]

use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    mm::{
        address_space::{AreaKind, UserAddressSpace},
        user_access,
    },
    syscall::Errno,
};
use polyhal::pagetable::MappingFlags;

/// `/proc/sys/fs/aio-max-nr` 默认全局请求槽上限（对齐 Linux 默认 65536）。
pub const DEFAULT_AIO_MAX_NR: usize = 65536;

static AIO_NR: AtomicUsize = AtomicUsize::new(0);
static AIO_MAX_NR: AtomicUsize = AtomicUsize::new(DEFAULT_AIO_MAX_NR);

pub fn aio_nr() -> usize {
    AIO_NR.load(Ordering::Relaxed)
}

pub fn aio_max_nr() -> usize {
    AIO_MAX_NR.load(Ordering::Relaxed)
}

/// Linux `iocb.aio_lio_opcode` 操作码（include/uapi/linux/aio_abi.h）。
pub const IOCB_CMD_PREAD: u16 = 0;
pub const IOCB_CMD_PWRITE: u16 = 1;
pub const IOCB_CMD_FSYNC: u16 = 2;
pub const IOCB_CMD_FDSYNC: u16 = 3;
pub const IOCB_CMD_PREADV: u16 = 7;
pub const IOCB_CMD_PWRITEV: u16 = 8;

/// Linux `iocb.aio_flags`。
pub const IOCB_FLAG_RESFD: u32 = 1 << 0;
pub const IOCB_FLAG_IOPRIO: u32 = 1 << 1;

/// Linux `RWF_*` 标志位掩码（HIPRI | DSYNC | SYNC | NOWAIT | APPEND）。
const RWF_SUPPORTED: u32 = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;
pub const RWF_APPEND: u32 = 0x10;

/// 完成事件（对应 32 字节 `struct io_event`）。
#[derive(Clone, Copy)]
pub struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

impl IoEvent {
    pub fn encode(self) -> [u8; 32] {
        let mut raw = [0u8; 32];
        raw[0..8].copy_from_slice(&self.data.to_ne_bytes());
        raw[8..16].copy_from_slice(&self.obj.to_ne_bytes());
        raw[16..24].copy_from_slice(&self.res.to_ne_bytes());
        raw[24..32].copy_from_slice(&self.res2.to_ne_bytes());
        raw
    }
}

/// 解析后的 64 字节 `struct iocb`。
pub struct Iocb {
    pub aio_data: u64,
    pub aio_rw_flags: u32,
    pub aio_lio_opcode: u16,
    pub aio_reqprio: i16,
    pub aio_fildes: u32,
    pub aio_buf: u64,
    pub aio_nbytes: u64,
    pub aio_offset: i64,
    pub aio_reserved2: u64,
    pub aio_flags: u32,
    pub aio_resfd: u32,
}

impl Iocb {
    pub fn decode(raw: &[u8; 64]) -> Self {
        Self {
            aio_data: u64::from_ne_bytes([
                raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
            ]),
            aio_rw_flags: u32::from_ne_bytes([raw[12], raw[13], raw[14], raw[15]]),
            aio_lio_opcode: u16::from_ne_bytes([raw[16], raw[17]]),
            aio_reqprio: i16::from_ne_bytes([raw[18], raw[19]]),
            aio_fildes: u32::from_ne_bytes([raw[20], raw[21], raw[22], raw[23]]),
            aio_buf: u64::from_ne_bytes([
                raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
            ]),
            aio_nbytes: u64::from_ne_bytes([
                raw[32], raw[33], raw[34], raw[35], raw[36], raw[37], raw[38], raw[39],
            ]),
            aio_offset: i64::from_ne_bytes([
                raw[40], raw[41], raw[42], raw[43], raw[44], raw[45], raw[46], raw[47],
            ]),
            aio_reserved2: u64::from_ne_bytes([
                raw[48], raw[49], raw[50], raw[51], raw[52], raw[53], raw[54], raw[55],
            ]),
            aio_flags: u32::from_ne_bytes([raw[56], raw[57], raw[58], raw[59]]),
            aio_resfd: u32::from_ne_bytes([raw[60], raw[61], raw[62], raw[63]]),
        }
    }
}

struct AioContext {
    id: u64,
    max_events: usize,
    events: VecDeque<IoEvent>,
}

/// 进程级 AIO 上下文表（不跨 fork 继承，exec/退出自动归还全局槽位）。
pub struct AioTable {
    contexts: Vec<AioContext>,
}

impl Drop for AioTable {
    fn drop(&mut self) {
        self.clear();
    }
}

impl AioTable {
    pub const fn new() -> Self {
        Self {
            contexts: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        let mut released = 0usize;
        for ctx in self.contexts.drain(..) {
            released = released.saturating_add(ctx.max_events);
        }
        if released != 0 {
            AIO_NR.fetch_sub(released, Ordering::Release);
        }
    }

    /// `io_setup(nr_events, ctx_idp)`：校验参数并分配单页只读占位映射作为 `aio_context_t`。
    pub fn setup(
        &mut self,
        space: &mut UserAddressSpace,
        nr_events_raw: u32,
        ctx_idp: usize,
    ) -> Result<usize, Errno> {
        // 先检查用户指针并确认初始值为 0（Linux 要求 *ctx_idp == 0，否则 EINVAL）。
        let mut init_bytes = [0u8; 8];
        user_access::copy_from_user(space, ctx_idp, &mut init_bytes).map_err(|_| Errno::Fault)?;
        if u64::from_ne_bytes(init_bytes) != 0 {
            return Err(Errno::Invalid);
        }
        let nr_i32 = nr_events_raw as i32;
        if nr_i32 <= 0 {
            return Err(Errno::Invalid);
        }
        let nr_events = nr_i32 as usize;

        // 原子预留全局 AIO 请求配额（超限返回 EAGAIN）。
        let max_nr = aio_max_nr();
        loop {
            let cur = AIO_NR.load(Ordering::Acquire);
            let Some(next) = cur.checked_add(nr_events) else {
                return Err(Errno::Again);
            };
            if next > max_nr {
                return Err(Errno::Again);
            }
            if AIO_NR
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }

        // 在用户空间保留 1 页只读匿名区（magic 恒为 0，确保 libaio 跳过用户环并安全走系统调用）。
        let ctx_addr = match space.find_free(0, 1).and_then(|addr| {
            space.reserve_region(
                addr,
                1,
                MappingFlags::U | MappingFlags::R,
                AreaKind::Anonymous,
            )?;
            Ok(addr)
        }) {
            Ok(addr) => addr,
            Err(_) => {
                AIO_NR.fetch_sub(nr_events, Ordering::Release);
                return Err(Errno::NoMem);
            }
        };

        let ctx_id = ctx_addr as u64;
        if self.contexts.try_reserve(1).is_err() {
            let _ = space.unmap(ctx_addr, 1);
            AIO_NR.fetch_sub(nr_events, Ordering::Release);
            return Err(Errno::NoMem);
        }
        if user_access::copy_to_user(space, ctx_idp, &ctx_id.to_ne_bytes()).is_err() {
            let _ = space.unmap(ctx_addr, 1);
            AIO_NR.fetch_sub(nr_events, Ordering::Release);
            return Err(Errno::Fault);
        }

        self.contexts.push(AioContext {
            id: ctx_id,
            max_events: nr_events,
            events: VecDeque::new(),
        });
        Ok(0)
    }

    /// `io_destroy(ctx_id)`：销毁上下文、解除占坑页并归还配额。
    pub fn destroy(&mut self, space: &mut UserAddressSpace, ctx_id: u64) -> Result<usize, Errno> {
        if ctx_id == 0 {
            return Err(Errno::Invalid);
        }
        let Some(pos) = self.contexts.iter().position(|c| c.id == ctx_id) else {
            return Err(Errno::Invalid);
        };
        let removed = self.contexts.swap_remove(pos);
        AIO_NR.fetch_sub(removed.max_events, Ordering::Release);
        let _ = space.unmap(ctx_id as usize, 1);
        Ok(0)
    }

    pub fn contains(&self, ctx_id: u64) -> bool {
        ctx_id != 0 && self.contexts.iter().any(|c| c.id == ctx_id)
    }

    pub fn has_space(&self, ctx_id: u64) -> Result<bool, Errno> {
        let ctx = self
            .contexts
            .iter()
            .find(|c| c.id == ctx_id)
            .ok_or(Errno::Invalid)?;
        Ok(ctx.events.len() < ctx.max_events)
    }

    pub fn push_event(&mut self, ctx_id: u64, ev: IoEvent) -> Result<(), Errno> {
        let ctx = self
            .contexts
            .iter_mut()
            .find(|c| c.id == ctx_id)
            .ok_or(Errno::Invalid)?;
        if ctx.events.len() >= ctx.max_events {
            return Err(Errno::Again);
        }
        ctx.events.try_reserve(1).map_err(|_| Errno::NoMem)?;
        ctx.events.push_back(ev);
        Ok(())
    }

    pub fn available_events(&self, ctx_id: u64) -> Result<usize, Errno> {
        let ctx = self
            .contexts
            .iter()
            .find(|c| c.id == ctx_id)
            .ok_or(Errno::Invalid)?;
        Ok(ctx.events.len())
    }

    /// 从队列头提取至多 `max_nr` 条事件拷贝到用户缓冲；全部写入成功后再出队。
    pub fn pop_events_to_user(
        &mut self,
        space: &UserAddressSpace,
        ctx_id: u64,
        max_nr: usize,
        events_ptr: usize,
    ) -> Result<usize, Errno> {
        let ctx = self
            .contexts
            .iter_mut()
            .find(|c| c.id == ctx_id)
            .ok_or(Errno::Invalid)?;
        let count = ctx.events.len().min(max_nr);
        for i in 0..count {
            let encoded = ctx.events[i].encode();
            let dst = events_ptr.checked_add(i * 32).ok_or(Errno::Fault)?;
            user_access::copy_to_user(space, dst, &encoded).map_err(|_| Errno::Fault)?;
        }
        for _ in 0..count {
            let _ = ctx.events.pop_front();
        }
        Ok(count)
    }
}

/// 校验 `struct iocb` 字段合法性（不含 fd 权限与 I/O 执行）。
pub fn validate_iocb(cb: &Iocb) -> Result<(), Errno> {
    if cb.aio_reserved2 != 0 {
        return Err(Errno::Invalid);
    }
    if cb.aio_flags & !(IOCB_FLAG_RESFD | IOCB_FLAG_IOPRIO) != 0 {
        return Err(Errno::Invalid);
    }
    if cb.aio_flags & IOCB_FLAG_IOPRIO == 0 && cb.aio_reqprio != 0 {
        return Err(Errno::Invalid);
    }
    if cb.aio_rw_flags & !RWF_SUPPORTED != 0 {
        return Err(Errno::NotSupported);
    }
    match cb.aio_lio_opcode {
        IOCB_CMD_PREAD | IOCB_CMD_PWRITE | IOCB_CMD_PREADV | IOCB_CMD_PWRITEV => {
            if cb.aio_offset < 0 {
                return Err(Errno::Invalid);
            }
            Ok(())
        }
        IOCB_CMD_FSYNC | IOCB_CMD_FDSYNC => {
            if cb.aio_buf != 0 || cb.aio_nbytes != 0 || cb.aio_offset != 0 || cb.aio_rw_flags != 0 {
                return Err(Errno::Invalid);
            }
            Ok(())
        }
        _ => Err(Errno::Invalid),
    }
}
