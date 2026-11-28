//! 块层写回缓存：以物理页帧承载 4 KiB 块，对上透明实现 `rsext4::BlockDevice`。
//! 契约见 docs/ostd-contracts.md §6。
#![forbid(unsafe_code)]

use crate::mm::frame::OwnedFrame;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use polyhal::pagetable::PAGE_SIZE;
use rsext4::{bmalloc::AbsoluteBN, BlockDevice, Ext4Error, Ext4Result, Ext4Timestamp, BLOCK_SIZE};

const _: () = assert!(BLOCK_SIZE == PAGE_SIZE);

/// 单卷块缓存上限：4096 块 = 16 MiB（数据存放于物理页帧，不占内核堆）。
const MAX_BLOCKS: usize = 4096;
/// 开放寻址哈希表桶数（2 倍负载余量，2 的幂便于位掩码取模）。
const HASH_BUCKETS: usize = MAX_BLOCKS * 2;
const HASH_MASK: usize = HASH_BUCKETS - 1;
const EMPTY_SLOT: u16 = u16::MAX;
/// `flush` 合并连续脏块写回时的单次最大批大小（16 块 = 64 KiB）。
const FLUSH_RUN_MAX: usize = 16;

/// 全系统块缓存当前持有的物理页帧总数（用于任务退出帧守恒自检与 `/proc/meminfo`）。
static BLOCK_CACHE_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// 块缓存当前持有的物理页帧数。
pub(crate) fn retained_frames() -> usize {
    BLOCK_CACHE_FRAMES.load(Ordering::Relaxed)
}

/// 块缓存当前占用容量，单位 KiB（供 `/proc/meminfo` 的 `Buffers` 字段）。
pub(crate) fn cached_kib() -> usize {
    retained_frames() * (PAGE_SIZE / 1024)
}

#[inline]
fn hash_block(block_id: u64) -> usize {
    // splitmix64 终混，打散连续块号避免线性探测聚集。
    let mut x = block_id.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 31;
    (x as usize) & HASH_MASK
}

struct Slot {
    block_id: u64,
    frame: OwnedFrame,
    valid: bool,
    dirty: bool,
    referenced: bool,
}

/// 通用 4 KiB 块写回缓存，包裹任意底层 `BlockDevice`。
pub(super) struct BlockCache<B: BlockDevice> {
    inner: B,
    slots: Vec<Slot>,
    /// 开放寻址线性探测索引表，存放 `slots` 下标或 `EMPTY_SLOT`。
    table: Vec<u16>,
    /// Clock（二次机会）淘汰指针。
    clock_hand: usize,
    /// `flush` 合并连续脏块写回用的可复用连续缓冲。
    flush_buf: Vec<u8>,
}

impl<B: BlockDevice> BlockCache<B> {
    /// 创建块缓存包装器；哈希表分配失败时退化为空表（直通读写）。
    pub(super) fn new(inner: B) -> Self {
        let mut table = Vec::new();
        if table.try_reserve_exact(HASH_BUCKETS).is_ok() {
            table.resize(HASH_BUCKETS, EMPTY_SLOT);
        }
        Self {
            inner,
            slots: Vec::new(),
            table,
            clock_hand: 0,
            flush_buf: Vec::new(),
        }
    }

    #[inline]
    fn enabled(&self) -> bool {
        self.table.len() == HASH_BUCKETS
    }

    #[inline]
    fn lookup(&self, block_id: u64) -> Option<usize> {
        if !self.enabled() {
            return None;
        }
        let mut idx = hash_block(block_id);
        loop {
            let entry = self.table[idx];
            if entry == EMPTY_SLOT {
                return None;
            }
            let slot_idx = entry as usize;
            if self.slots[slot_idx].block_id == block_id {
                return Some(slot_idx);
            }
            idx = (idx + 1) & HASH_MASK;
        }
    }

    fn table_insert(&mut self, block_id: u64, slot_idx: usize) {
        debug_assert!(slot_idx < MAX_BLOCKS);
        let mut idx = hash_block(block_id);
        while self.table[idx] != EMPTY_SLOT {
            idx = (idx + 1) & HASH_MASK;
        }
        self.table[idx] = slot_idx as u16;
    }

    /// Knuth Algorithm R 后向移位删除：不留墓碑，保持 O(1) 探测长度。
    fn table_remove(&mut self, block_id: u64) {
        let mut hole = hash_block(block_id);
        loop {
            let entry = self.table[hole];
            if entry == EMPTY_SLOT {
                return;
            }
            if self.slots[entry as usize].block_id == block_id {
                break;
            }
            hole = (hole + 1) & HASH_MASK;
        }
        let mut cur = (hole + 1) & HASH_MASK;
        while self.table[cur] != EMPTY_SLOT {
            let cur_slot = self.table[cur] as usize;
            let natural = hash_block(self.slots[cur_slot].block_id);
            let dist_cur = cur.wrapping_sub(natural) & HASH_MASK;
            let dist_hole = hole.wrapping_sub(natural) & HASH_MASK;
            if dist_hole < dist_cur {
                self.table[hole] = self.table[cur];
                hole = cur;
            }
            cur = (cur + 1) & HASH_MASK;
        }
        self.table[hole] = EMPTY_SLOT;
    }

    /// 按 Clock 算法选出一个可复用槽位；若槽位为脏则先同步写回底层设备。
    fn evict_one(&mut self) -> Ext4Result<usize> {
        let len = self.slots.len();
        debug_assert!(len > 0);
        let victim = loop {
            if self.clock_hand >= len {
                self.clock_hand = 0;
            }
            let idx = self.clock_hand;
            self.clock_hand = (idx + 1) % len;
            if !self.slots[idx].valid {
                break idx;
            }
            if self.slots[idx].referenced {
                self.slots[idx].referenced = false;
            } else {
                break idx;
            }
        };
        if self.slots[victim].valid {
            if self.slots[victim].dirty {
                let old_id = self.slots[victim].block_id;
                self.inner.write(
                    self.slots[victim].frame.as_slice(),
                    AbsoluteBN::new(old_id),
                    1,
                )?;
                self.slots[victim].dirty = false;
            }
            let old_id = self.slots[victim].block_id;
            self.table_remove(old_id);
            self.slots[victim].valid = false;
        }
        Ok(victim)
    }

    /// 为新块获取空槽：未达上限优先按需分配物理页帧，上限或内存紧缺时淘汰复用。
    /// 返回 `Ok(None)` 表示完全无槽可用，调用方应直通底层设备。
    fn acquire_slot(&mut self, block_id: u64) -> Ext4Result<Option<usize>> {
        if !self.enabled() {
            return Ok(None);
        }
        if self.slots.len() < MAX_BLOCKS && self.slots.try_reserve(1).is_ok() {
            if let Ok(frame) = OwnedFrame::new() {
                let slot_idx = self.slots.len();
                self.slots.push(Slot {
                    block_id,
                    frame,
                    valid: true,
                    dirty: false,
                    referenced: true,
                });
                BLOCK_CACHE_FRAMES.fetch_add(1, Ordering::Relaxed);
                self.table_insert(block_id, slot_idx);
                return Ok(Some(slot_idx));
            }
        }
        if self.slots.is_empty() {
            return Ok(None);
        }
        let slot_idx = self.evict_one()?;
        self.slots[slot_idx].block_id = block_id;
        self.slots[slot_idx].valid = true;
        self.slots[slot_idx].dirty = false;
        self.slots[slot_idx].referenced = true;
        self.table_insert(block_id, slot_idx);
        Ok(Some(slot_idx))
    }

    /// 缓存命中读取或未命中从底层加载单块并写入 `dst`（长度必须为 `BLOCK_SIZE`）。
    fn read_one(&mut self, block_id: u64, dst: &mut [u8]) -> Ext4Result<()> {
        if let Some(slot_idx) = self.lookup(block_id) {
            let slot = &mut self.slots[slot_idx];
            slot.referenced = true;
            dst.copy_from_slice(slot.frame.as_slice());
            return Ok(());
        }
        if let Some(slot_idx) = self.acquire_slot(block_id)? {
            let res = self.inner.read(
                self.slots[slot_idx].frame.as_mut_slice(),
                AbsoluteBN::new(block_id),
                1,
            );
            if let Err(err) = res {
                // 读失败时撤销刚登记的未初始化块，避免污染缓存。
                self.table_remove(block_id);
                self.slots[slot_idx].valid = false;
                self.slots[slot_idx].referenced = false;
                return Err(err);
            }
            dst.copy_from_slice(self.slots[slot_idx].frame.as_slice());
            Ok(())
        } else {
            self.inner.read(dst, AbsoluteBN::new(block_id), 1)
        }
    }

    /// 将一整块数据写入缓存并标脏；无槽可用时直写底层设备。
    fn write_one(&mut self, block_id: u64, src: &[u8]) -> Ext4Result<()> {
        if let Some(slot_idx) = self.lookup(block_id) {
            let slot = &mut self.slots[slot_idx];
            slot.frame.as_mut_slice().copy_from_slice(src);
            slot.dirty = true;
            slot.referenced = true;
            return Ok(());
        }
        if let Some(slot_idx) = self.acquire_slot(block_id)? {
            let slot = &mut self.slots[slot_idx];
            slot.frame.as_mut_slice().copy_from_slice(src);
            slot.dirty = true;
            slot.referenced = true;
            Ok(())
        } else {
            self.inner.write(src, AbsoluteBN::new(block_id), 1)
        }
    }

    /// 将所有脏块按块号排序并合并连续段写回底层设备；任一写失败均保留脏标记。
    fn flush_dirty_blocks(&mut self) -> Ext4Result<()> {
        let mut dirty: Vec<(u64, usize)> = Vec::new();
        let dirty_count = self.slots.iter().filter(|s| s.dirty).count();
        if dirty_count == 0 {
            return Ok(());
        }
        if dirty.try_reserve_exact(dirty_count).is_err() {
            // 极端堆紧缺时退化为逐槽直写，保证持久化语义不失败。
            for slot in &mut self.slots {
                if slot.dirty {
                    let id = slot.block_id;
                    self.inner
                        .write(slot.frame.as_slice(), AbsoluteBN::new(id), 1)?;
                    slot.dirty = false;
                }
            }
            return Ok(());
        }
        for (idx, slot) in self.slots.iter().enumerate() {
            if slot.dirty {
                dirty.push((slot.block_id, idx));
            }
        }
        dirty.sort_unstable_by_key(|&(id, _)| id);

        let mut i = 0;
        while i < dirty.len() {
            let start_id = dirty[i].0;
            let mut run = 1;
            while i + run < dirty.len()
                && run < FLUSH_RUN_MAX
                && dirty[i + run].0 == start_id.saturating_add(run as u64)
            {
                run += 1;
            }
            if run == 1 {
                let slot_idx = dirty[i].1;
                self.inner.write(
                    self.slots[slot_idx].frame.as_slice(),
                    AbsoluteBN::new(start_id),
                    1,
                )?;
                self.slots[slot_idx].dirty = false;
            } else {
                let total_bytes = run * BLOCK_SIZE;
                if self.flush_buf.len() < total_bytes {
                    let add = total_bytes - self.flush_buf.len();
                    if self.flush_buf.try_reserve_exact(add).is_ok() {
                        self.flush_buf.resize(total_bytes, 0);
                    }
                }
                if self.flush_buf.len() >= total_bytes {
                    for off in 0..run {
                        let slot_idx = dirty[i + off].1;
                        let dst = &mut self.flush_buf[off * BLOCK_SIZE..(off + 1) * BLOCK_SIZE];
                        dst.copy_from_slice(self.slots[slot_idx].frame.as_slice());
                    }
                    self.inner.write(
                        &self.flush_buf[..total_bytes],
                        AbsoluteBN::new(start_id),
                        run as u32,
                    )?;
                    for &(_, slot_idx) in &dirty[i..i + run] {
                        self.slots[slot_idx].dirty = false;
                    }
                } else {
                    for &(id, slot_idx) in &dirty[i..i + run] {
                        self.inner.write(
                            self.slots[slot_idx].frame.as_slice(),
                            AbsoluteBN::new(id),
                            1,
                        )?;
                        self.slots[slot_idx].dirty = false;
                    }
                }
            }
            i += run;
        }
        Ok(())
    }

    fn validate_range(&self, block: AbsoluteBN, count: u32, buf_len: usize) -> Ext4Result<u64> {
        let start = block.raw();
        let total = self.inner.total_blocks();
        let end = start
            .checked_add(u64::from(count))
            .ok_or_else(Ext4Error::io)?;
        if end > total {
            return Err(Ext4Error::io());
        }
        let needed = (count as usize)
            .checked_mul(BLOCK_SIZE)
            .ok_or_else(Ext4Error::io)?;
        if buf_len < needed {
            return Err(Ext4Error::io());
        }
        Ok(start)
    }
}

impl<B: BlockDevice> Drop for BlockCache<B> {
    fn drop(&mut self) {
        let count = self.slots.len();
        self.slots.clear();
        BLOCK_CACHE_FRAMES.fetch_sub(count, Ordering::Relaxed);
    }
}

impl<B: BlockDevice> BlockDevice for BlockCache<B> {
    fn read(&mut self, dst: &mut [u8], block: AbsoluteBN, count: u32) -> Ext4Result<()> {
        if count == 0 {
            return Ok(());
        }
        let start = self.validate_range(block, count, dst.len())?;
        if count == 1 {
            return self.read_one(start, &mut dst[..BLOCK_SIZE]);
        }
        // 多块读：命中段直接内存拷贝，连续未命中段合并为一次底层多块读再回填缓存。
        let count_usize = count as usize;
        let mut i = 0usize;
        while i < count_usize {
            let block_id = start + i as u64;
            if let Some(slot_idx) = self.lookup(block_id) {
                let slot = &mut self.slots[slot_idx];
                slot.referenced = true;
                dst[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(slot.frame.as_slice());
                i += 1;
                continue;
            }
            let mut miss_run = 1usize;
            while i + miss_run < count_usize && self.lookup(start + (i + miss_run) as u64).is_none()
            {
                miss_run += 1;
            }
            let run_start = i * BLOCK_SIZE;
            let run_end = (i + miss_run) * BLOCK_SIZE;
            self.inner.read(
                &mut dst[run_start..run_end],
                AbsoluteBN::new(block_id),
                miss_run as u32,
            )?;
            for off in 0..miss_run {
                let id = block_id + off as u64;
                if let Some(slot_idx) = self.acquire_slot(id)? {
                    let src_start = (i + off) * BLOCK_SIZE;
                    self.slots[slot_idx]
                        .frame
                        .as_mut_slice()
                        .copy_from_slice(&dst[src_start..src_start + BLOCK_SIZE]);
                }
            }
            i += miss_run;
        }
        Ok(())
    }

    fn write(&mut self, data: &[u8], block: AbsoluteBN, count: u32) -> Ext4Result<()> {
        if self.inner.is_readonly() {
            return Err(Ext4Error::read_only());
        }
        if count == 0 {
            return Ok(());
        }
        let start = self.validate_range(block, count, data.len())?;
        for i in 0..count as usize {
            let off = i * BLOCK_SIZE;
            self.write_one(start + i as u64, &data[off..off + BLOCK_SIZE])?;
        }
        Ok(())
    }

    fn read_slice(&mut self, dst: &mut [u8], block: AbsoluteBN, offset: usize) -> Ext4Result<()> {
        let end = offset
            .checked_add(dst.len())
            .ok_or_else(Ext4Error::invalid_input)?;
        if end > BLOCK_SIZE {
            return Err(Ext4Error::invalid_input());
        }
        let block_id = block.raw();
        if block_id >= self.inner.total_blocks() {
            return Err(Ext4Error::io());
        }
        if dst.is_empty() {
            return Ok(());
        }
        if let Some(slot_idx) = self.lookup(block_id) {
            let slot = &mut self.slots[slot_idx];
            slot.referenced = true;
            dst.copy_from_slice(&slot.frame.as_slice()[offset..end]);
            return Ok(());
        }
        if let Some(slot_idx) = self.acquire_slot(block_id)? {
            let res = self
                .inner
                .read(self.slots[slot_idx].frame.as_mut_slice(), block, 1);
            if let Err(err) = res {
                self.table_remove(block_id);
                self.slots[slot_idx].valid = false;
                self.slots[slot_idx].referenced = false;
                return Err(err);
            }
            dst.copy_from_slice(&self.slots[slot_idx].frame.as_slice()[offset..end]);
            Ok(())
        } else {
            self.inner.read_slice(dst, block, offset)
        }
    }

    fn write_slice(
        &mut self,
        src: &[u8],
        block: AbsoluteBN,
        offset: usize,
        zero_rest: bool,
    ) -> Ext4Result<()> {
        if self.inner.is_readonly() {
            return Err(Ext4Error::read_only());
        }
        let end = offset
            .checked_add(src.len())
            .ok_or_else(Ext4Error::invalid_input)?;
        if end > BLOCK_SIZE {
            return Err(Ext4Error::invalid_input());
        }
        let block_id = block.raw();
        if block_id >= self.inner.total_blocks() {
            return Err(Ext4Error::io());
        }
        if src.is_empty() && !zero_rest {
            return Ok(());
        }
        if let Some(slot_idx) = self.lookup(block_id) {
            let slot = &mut self.slots[slot_idx];
            let frame = slot.frame.as_mut_slice();
            if zero_rest && (offset != 0 || end != BLOCK_SIZE) {
                frame.fill(0);
            }
            frame[offset..end].copy_from_slice(src);
            slot.dirty = true;
            slot.referenced = true;
            return Ok(());
        }
        if let Some(slot_idx) = self.acquire_slot(block_id)? {
            let full = offset == 0 && end == BLOCK_SIZE;
            if zero_rest {
                let frame = self.slots[slot_idx].frame.as_mut_slice();
                if !full {
                    frame.fill(0);
                }
                frame[offset..end].copy_from_slice(src);
            } else {
                let res = self
                    .inner
                    .read(self.slots[slot_idx].frame.as_mut_slice(), block, 1);
                if let Err(err) = res {
                    self.table_remove(block_id);
                    self.slots[slot_idx].valid = false;
                    self.slots[slot_idx].referenced = false;
                    return Err(err);
                }
                self.slots[slot_idx].frame.as_mut_slice()[offset..end].copy_from_slice(src);
            }
            self.slots[slot_idx].dirty = true;
            self.slots[slot_idx].referenced = true;
            Ok(())
        } else {
            self.inner.write_slice(src, block, offset, zero_rest)
        }
    }

    fn flush(&mut self) -> Ext4Result<()> {
        if !self.inner.is_readonly() {
            self.flush_dirty_blocks()?;
        }
        self.inner.flush()
    }

    fn open(&mut self) -> Ext4Result<()> {
        self.inner.open()
    }

    fn close(&mut self) -> Ext4Result<()> {
        self.inner.close()
    }

    fn total_blocks(&self) -> u64 {
        self.inner.total_blocks()
    }

    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }

    fn is_readonly(&self) -> bool {
        self.inner.is_readonly()
    }

    fn current_time(&self) -> Ext4Result<Ext4Timestamp> {
        self.inner.current_time()
    }
}
