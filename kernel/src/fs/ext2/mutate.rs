//! Ext2 普通文件和目录项更新。每次操作暂存完整块，失败时恢复旧内容。

use super::{
    directory, le16, le32, put16, put32, Device, Error, Group, Inode, Result, Volume, BLOCK_SIZE,
    GROUP_DESC_SIZE, INODE_SIZE, REGULAR, TYPE_MASK,
};
use alloc::vec::Vec;

const DIRECT: usize = 12;
const LINK_MAX: u16 = 32_000;

struct Edit {
    block: u32,
    old: Vec<u8>,
    new: Vec<u8>,
}

struct Transaction<'a, D> {
    volume: &'a mut Volume<D>,
    edits: Vec<Edit>,
}

impl<'a, D: Device> Transaction<'a, D> {
    fn begin(volume: &'a mut Volume<D>) -> Result<Self> {
        if volume.failed {
            return Err(Error::Io);
        }
        if volume.readonly {
            return Err(Error::ReadOnly);
        }
        Ok(Self {
            volume,
            edits: Vec::new(),
        })
    }

    fn edit(&mut self, block: u32) -> Result<&mut [u8]> {
        if let Some(position) = self.edits.iter().position(|entry| entry.block == block) {
            return Ok(&mut self.edits[position].new);
        }
        let mut old = Vec::new();
        let mut new = Vec::new();
        old.try_reserve_exact(BLOCK_SIZE)
            .map_err(|_| Error::NoMemory)?;
        new.try_reserve_exact(BLOCK_SIZE)
            .map_err(|_| Error::NoMemory)?;
        self.edits.try_reserve(1).map_err(|_| Error::NoMemory)?;
        old.resize(BLOCK_SIZE, 0);
        self.volume.read_block(
            block,
            old.as_mut_slice().try_into().map_err(|_| Error::Invalid)?,
        )?;
        new.extend_from_slice(&old);
        self.edits.push(Edit { block, old, new });
        let last = self.edits.len() - 1;
        Ok(&mut self.edits[last].new)
    }

    fn inode(&mut self, offset: u64) -> Result<&mut [u8]> {
        let (block, start) = split_offset(offset)?;
        self.edit(block)?
            .get_mut(start..start + INODE_SIZE)
            .ok_or(Error::Invalid)
    }

    fn count(&mut self, group: &Group, inode: bool, allocate: bool) -> Result<()> {
        let group_limit = if inode {
            self.volume.geometry.inodes_per_group
        } else {
            self.volume.geometry.blocks_per_group
        };
        let volume_limit = if inode {
            self.volume.geometry.inodes
        } else {
            self.volume.geometry.blocks - self.volume.geometry.first_data_block
        };
        let (block, pos) = split_offset(group.offset)?;
        let desc = self.edit(block)?;
        let field = pos + group_count_offset(inode) as usize;
        let value = u32::from(le16(desc, field));
        put16(
            desc,
            field,
            adjust_count(value, group_limit, allocate)? as u16,
        );
        let sb = self.edit(1)?;
        let field = if inode { 16 } else { 12 };
        let value = le32(sb, field);
        put32(sb, field, adjust_count(value, volume_limit, allocate)?);
        Ok(())
    }

    fn group_free(&mut self, group: &Group, inode: bool) -> Result<u16> {
        let offset = group.offset + group_count_offset(inode);
        let (block, pos) = split_offset(offset)?;
        if let Some(edit) = self.edits.iter().find(|edit| edit.block == block) {
            return Ok(le16(&edit.new, pos));
        }
        let mut raw = [0; 2];
        self.volume.device.read_at(offset, &mut raw)?;
        Ok(u16::from_le_bytes(raw))
    }

    fn bitmap(&mut self, group: &Group, inode: bool, bit: u32, allocate: bool) -> Result<()> {
        let bitmap = if inode {
            group.inode_bitmap
        } else {
            group.block_bitmap
        };
        let bits = self.edit(bitmap)?;
        let byte = bits.get_mut((bit / 8) as usize).ok_or(Error::Invalid)?;
        let mask = 1 << (bit % 8);
        if (*byte & mask == 0) != allocate {
            return Err(Error::Invalid);
        }
        *byte ^= mask;
        self.count(group, inode, allocate)
    }

    fn allocate(&mut self, preferred_group: u32, inode: bool) -> Result<u32> {
        let g = &self.volume.geometry;
        let (groups, first, total, stride) = if inode {
            (g.groups, 1, g.inodes, g.inodes_per_group)
        } else {
            (
                g.groups,
                g.first_data_block,
                g.blocks - g.first_data_block,
                g.blocks_per_group,
            )
        };
        for step in 0..groups {
            let index = ((u64::from(preferred_group) + u64::from(step)) % u64::from(groups)) as u32;
            let group = self.volume.group(index)?;
            if self.group_free(&group, inode)? == 0 {
                continue;
            }
            let base = index.checked_mul(stride).ok_or(Error::Invalid)?;
            let begin = base.checked_add(first).ok_or(Error::Invalid)?;
            let limit = stride.min(total.checked_sub(base).ok_or(Error::Invalid)?);
            let minimum = if inode {
                self.volume.geometry.first_inode.saturating_sub(begin)
            } else {
                0
            };
            let bitmap = if inode {
                group.inode_bitmap
            } else {
                group.block_bitmap
            };
            let bytes = self.edit(bitmap)?;
            let bit = (minimum..limit)
                .find(|&bit| bytes[(bit / 8) as usize] & (1 << (bit % 8)) == 0)
                .ok_or(Error::Invalid)?;
            let id = begin.checked_add(bit).ok_or(Error::Invalid)?;
            if !inode {
                self.volume.check_data_block(id)?;
            }
            self.bitmap(&group, inode, bit, true)?;
            return Ok(id);
        }
        Err(Error::NoSpace)
    }

    fn free_inode(&mut self, ino: u32) -> Result<()> {
        let g = &self.volume.geometry;
        if ino < g.first_inode || ino > g.inodes {
            return Err(Error::Invalid);
        }
        let index = (ino - 1) / g.inodes_per_group;
        let bit = (ino - 1) % g.inodes_per_group;
        let group = self.volume.group(index)?;
        self.bitmap(&group, true, bit, false)
    }

    fn free_block(&mut self, block: u32) -> Result<()> {
        self.volume.check_data_block(block)?;
        let pos = block - self.volume.geometry.first_data_block;
        let stride = self.volume.geometry.blocks_per_group;
        let group = self.volume.group(pos / stride)?;
        self.bitmap(&group, false, pos % stride, false)
    }

    fn commit(self) -> Result<()> {
        for (index, edit) in self.edits.iter().enumerate() {
            if let Err(err) = self
                .volume
                .device
                .write_at(block_offset(edit.block), &edit.new)
            {
                return self.rollback(index + 1, err);
            }
        }
        if let Err(err) = self.volume.device.flush() {
            let written = self.edits.len();
            return self.rollback(written, err);
        }
        Ok(())
    }

    fn rollback(self, attempted: usize, error: Error) -> Result<()> {
        let mut failed = false;
        for edit in self.edits[..attempted].iter().rev() {
            failed |= self
                .volume
                .device
                .write_at(block_offset(edit.block), &edit.old)
                .is_err();
        }
        failed |= self.volume.device.flush().is_err();
        if failed {
            self.volume.failed = true;
            Err(Error::Io)
        } else {
            Err(error)
        }
    }
}

fn group_count_offset(inode: bool) -> u64 {
    if inode {
        14
    } else {
        12
    }
}

fn adjust_count(value: u32, limit: u32, allocate: bool) -> Result<u32> {
    let next = if allocate {
        value.checked_sub(1)
    } else {
        value.checked_add(1)
    };
    next.filter(|&count| count <= limit).ok_or(Error::Invalid)
}

fn split_offset(offset: u64) -> Result<(u32, usize)> {
    Ok((
        (offset / BLOCK_SIZE as u64)
            .try_into()
            .map_err(|_| Error::Invalid)?,
        (offset % BLOCK_SIZE as u64) as usize,
    ))
}

fn block_offset(block: u32) -> u64 {
    u64::from(block) * BLOCK_SIZE as u64
}

fn name_len(name: &[u8]) -> Result<usize> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, b"." | b"..")
        || name.iter().any(|&b| b == 0 || b == b'/')
    {
        return Err(Error::Invalid);
    }
    Ok(dir_size(name.len()))
}

fn dir_size(name: usize) -> usize {
    (8 + name + 3) & !3
}

struct Slot {
    block: u32,
    offset: usize,
    length: usize,
    split: Option<usize>,
}

struct Hit {
    block: u32,
    offset: usize,
    next: usize,
    previous: Option<usize>,
    ino: u32,
}

fn touch(raw: &mut [u8], now: u32) {
    put32(raw, 12, now);
    put32(raw, 16, now);
}

fn write_entry(data: &mut [u8], offset: usize, length: usize, ino: u32, name: &[u8]) {
    let entry = &mut data[offset..offset + length];
    entry.fill(0);
    put32(entry, 0, ino);
    put16(entry, 4, length as u16);
    entry[6] = name.len() as u8;
    entry[7] = 1;
    entry[8..8 + name.len()].copy_from_slice(name);
}

impl<D: Device> Volume<D> {
    fn data_block_group(&mut self, block: u32) -> Result<(Group, u32)> {
        let g = &self.geometry;
        if block < g.first_data_block || block >= g.blocks {
            return Err(Error::Invalid);
        }
        let index = (block - g.first_data_block) / g.blocks_per_group;
        let bit = block - g.group_bounds(index)?.start;
        let descriptors = g.groups.div_ceil((BLOCK_SIZE / GROUP_DESC_SIZE) as u32);
        let table_blocks = g
            .inodes_per_group
            .div_ceil((BLOCK_SIZE / INODE_SIZE) as u32);
        if g.has_superblock(index) && bit <= descriptors {
            return Err(Error::Invalid);
        }
        let group = self.group(index)?;
        if block == group.block_bitmap
            || block == group.inode_bitmap
            || block
                .checked_sub(group.inode_table)
                .is_some_and(|i| i < table_blocks)
        {
            return Err(Error::Invalid);
        }
        Ok((group, bit))
    }

    fn check_data_block(&mut self, block: u32) -> Result<()> {
        self.data_block_group(block).map(|_| ())
    }

    fn check_allocated_block(&mut self, block: u32) -> Result<()> {
        let (group, bit) = self.data_block_group(block)?;
        let mut byte = [0];
        self.device.read_at(
            block_offset(group.block_bitmap) + u64::from(bit / 8),
            &mut byte,
        )?;
        if byte[0] & (1 << (bit % 8)) == 0 {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    fn inode_offset(&mut self, ino: u32) -> Result<u64> {
        let stride = self.geometry.inodes_per_group;
        let group = self.group((ino - 1) / stride)?;
        Ok(block_offset(group.inode_table) + u64::from((ino - 1) % stride) * INODE_SIZE as u64)
    }

    fn regular(&mut self, ino: u32) -> Result<Inode> {
        let inode = self.read_inode(ino)?;
        if inode.is_dir() {
            return Err(Error::IsDir);
        }
        if inode.mode() & TYPE_MASK != REGULAR || inode.flags() != 0 || inode.links() == 0 {
            return Err(Error::Unsupported);
        }
        Ok(inode)
    }

    fn scan_directory(
        &mut self,
        dir: &Inode,
        name: &[u8],
        want: usize,
    ) -> Result<(Option<Hit>, Option<Slot>)> {
        if !dir.is_dir() {
            return Err(Error::NotDir);
        }
        if dir.flags() != 0 {
            return Err(Error::Unsupported);
        }
        if dir.size() % BLOCK_SIZE as u64 != 0 || dir.size() == 0 {
            return Err(Error::Invalid);
        }
        if dir.size() / BLOCK_SIZE as u64 > u64::from(self.geometry.blocks) {
            return Err(Error::Invalid);
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(BLOCK_SIZE)
            .map_err(|_| Error::NoMemory)?;
        buffer.resize(BLOCK_SIZE, 0);
        let buffer = buffer.first_chunk_mut::<BLOCK_SIZE>().ok_or(Error::Io)?;
        let mut slot = None;
        for logical in 0..dir.size() / BLOCK_SIZE as u64 {
            let block = self.mapped_block(dir, logical)?.ok_or(Error::Invalid)?;
            self.check_allocated_block(block)?;
            self.read_block(block, buffer)?;
            let mut offset = 0;
            let mut previous = None;
            while offset < BLOCK_SIZE {
                let entry = directory::entry_at(buffer, offset)?;
                if entry.ino > self.geometry.inodes {
                    return Err(Error::Invalid);
                }
                let len = entry.next - offset;
                if entry.ino != 0 && entry.name == name {
                    return Ok((
                        Some(Hit {
                            block,
                            offset,
                            next: entry.next,
                            previous,
                            ino: entry.ino,
                        }),
                        slot,
                    ));
                }
                let used = if entry.ino == 0 {
                    0
                } else {
                    dir_size(entry.name.len())
                };
                if slot.is_none() && len - used >= want {
                    slot = Some(Slot {
                        block,
                        offset: offset + used,
                        length: len - used,
                        split: (used != 0).then_some(offset),
                    });
                }
                previous = Some(offset);
                offset = entry.next;
            }
        }
        Ok((None, slot))
    }

    fn insert_slot(&mut self, dir: &Inode, name: &[u8]) -> Result<Slot> {
        let needed = name_len(name)?;
        let (hit, slot) = self.scan_directory(dir, name, needed)?;
        if hit.is_some() {
            return Err(Error::Exists);
        }
        slot.ok_or(Error::Unsupported)
    }

    /// 在现有线性目录块中创建空的普通文件，返回新 inode。
    pub(crate) fn create(
        &mut self,
        parent: u32,
        name: &[u8],
        mode: u16,
        owner: (u32, u32),
        now: u32,
    ) -> Result<u32> {
        let mut tx = Transaction::begin(self)?;
        if !matches!(mode & TYPE_MASK, 0 | REGULAR) {
            return Err(Error::Unsupported);
        }
        let dir = tx.volume.read_inode(parent)?;
        let slot = tx.volume.insert_slot(&dir, name)?;
        let group = (parent - 1) / tx.volume.geometry.inodes_per_group;
        let ino = tx.allocate(group, true)?;
        let offset = tx.volume.inode_offset(ino)?;
        let raw = tx.inode(offset)?;
        raw.fill(0);
        put16(raw, 0, REGULAR | (mode & 0o7777));
        put16(raw, 2, owner.0 as u16);
        put16(raw, 120, (owner.0 >> 16) as u16);
        put16(raw, 24, owner.1 as u16);
        put16(raw, 122, (owner.1 >> 16) as u16);
        put16(raw, 26, 1);
        put32(raw, 8, now);
        touch(raw, now);
        insert(&mut tx, slot, ino, name)?;
        touch(tx.inode(dir.offset)?, now);
        tx.commit()?;
        Ok(ino)
    }

    /// 通过直接块指针写入普通文件，成功返回完整写入量。
    pub(crate) fn write_file(
        &mut self,
        ino: u32,
        offset: u64,
        data: &[u8],
        now: u32,
    ) -> Result<usize> {
        let mut tx = Transaction::begin(self)?;
        let inode = tx.volume.regular(ino)?;
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Range)?;
        if end.max(inode.size()) > (DIRECT * BLOCK_SIZE) as u64
            || (DIRECT..15).any(|index| inode.pointer(index) != 0)
        {
            return Err(Error::Unsupported);
        }
        let preferred = (ino - 1) / tx.volume.geometry.inodes_per_group;
        let mut pointers = [0; DIRECT];
        for index in 0..DIRECT {
            let block = inode.pointer(index);
            if block != 0 {
                if pointers[..index].contains(&block) {
                    return Err(Error::Invalid);
                }
                tx.volume.check_allocated_block(block)?;
            }
            pointers[index] = block;
        }
        let old = inode.size() as usize;
        let offset = offset as usize;
        if offset > old && old % BLOCK_SIZE != 0 {
            let block = pointers[old / BLOCK_SIZE];
            if block != 0 {
                let stop = (offset - (old / BLOCK_SIZE) * BLOCK_SIZE).min(BLOCK_SIZE);
                tx.edit(block)?[old % BLOCK_SIZE..stop].fill(0);
            }
        }
        let mut extra_sectors = 0;
        let mut written = 0;
        while written < data.len() {
            let pos = offset + written;
            let logical = pos / BLOCK_SIZE;
            let start = pos % BLOCK_SIZE;
            let count = (BLOCK_SIZE - start).min(data.len() - written);
            let block = &mut pointers[logical];
            if *block == 0 {
                *block = tx.allocate(preferred, false)?;
                tx.edit(*block)?.fill(0);
                extra_sectors += (BLOCK_SIZE / 512) as u32;
            }
            tx.edit(*block)?[start..start + count].copy_from_slice(&data[written..written + count]);
            written += count;
        }
        let raw = tx.inode(inode.offset)?;
        for (i, &block) in pointers.iter().enumerate() {
            put32(raw, 40 + 4 * i, block);
        }
        let sectors = le32(raw, 28)
            .checked_add(extra_sectors)
            .ok_or(Error::Invalid)?;
        put32(raw, 28, sectors);
        put32(raw, 4, inode.size().max(end) as u32);
        touch(raw, now);
        tx.commit()?;
        Ok(written)
    }

    /// 在现有目录块内为普通文件添加硬链接。
    pub(crate) fn link(&mut self, parent: u32, ino: u32, name: &[u8], now: u32) -> Result<()> {
        let mut tx = Transaction::begin(self)?;
        let dir = tx.volume.read_inode(parent)?;
        let inode = tx.volume.regular(ino)?;
        let slot = tx.volume.insert_slot(&dir, name)?;
        if inode.links() >= LINK_MAX {
            return Err(Error::TooManyLinks);
        }
        let raw = tx.inode(inode.offset)?;
        put16(raw, 26, inode.links() + 1);
        put32(raw, 12, now);
        insert(&mut tx, slot, ino, name)?;
        touch(tx.inode(dir.offset)?, now);
        tx.commit()
    }

    /// 删除普通文件名。调用方须保证最后一个链接删除时没有打开引用。
    pub(crate) fn unlink(&mut self, parent: u32, name: &[u8], now: u32) -> Result<()> {
        let mut tx = Transaction::begin(self)?;
        name_len(name)?;
        let dir = tx.volume.read_inode(parent)?;
        let (hit, _) = tx.volume.scan_directory(&dir, name, 0)?;
        let hit = hit.ok_or(Error::NotFound)?;
        let inode = tx.volume.regular(hit.ino)?;
        if inode.links() == 1 {
            if (DIRECT..15).any(|index| inode.pointer(index) != 0) || le32(&inode.raw, 104) != 0 {
                return Err(Error::Unsupported);
            }
            let mut sectors = 0;
            for index in 0..DIRECT {
                let block = inode.pointer(index);
                if block != 0 {
                    tx.free_block(block)?;
                    sectors += (BLOCK_SIZE / 512) as u32;
                }
            }
            if sectors != le32(&inode.raw, 28) {
                return Err(Error::Invalid);
            }
            tx.free_inode(hit.ino)?;
            let raw = tx.inode(inode.offset)?;
            raw.fill(0);
            put32(raw, 20, now.max(1));
        } else {
            let raw = tx.inode(inode.offset)?;
            put16(raw, 26, inode.links() - 1);
            put32(raw, 12, now);
        }
        let data = tx.edit(hit.block)?;
        if let Some(previous) = hit.previous {
            put16(data, previous + 4, (hit.next - previous) as u16);
        } else {
            data[hit.offset..hit.next].fill(0);
            put16(data, hit.offset + 4, (hit.next - hit.offset) as u16);
        }
        touch(tx.inode(dir.offset)?, now);
        tx.commit()
    }
}

fn insert<D: Device>(tx: &mut Transaction<'_, D>, slot: Slot, ino: u32, name: &[u8]) -> Result<()> {
    let data = tx.edit(slot.block)?;
    if let Some(previous) = slot.split {
        put16(data, previous + 4, (slot.offset - previous) as u16);
    }
    write_entry(data, slot.offset, slot.length, ino, name);
    Ok(())
}
