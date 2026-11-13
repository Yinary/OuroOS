// OuroOS patch: 03-directory-and-descriptor-parsing (see README.md).
//! Block group descriptor table views.

use super::desc::Ext4GroupDesc;
use crate::{bmalloc::BGIndex, endian::DiskFormat};

fn descriptor_range(index: BGIndex, count: u32, stride: usize) -> Option<core::ops::Range<usize>> {
    if index.raw() >= count || stride < 32 {
        return None;
    }
    let start = index.as_usize().ok()?.checked_mul(stride)?;
    let size = if stride >= 64 { 64 } else if stride == 32 { 32 } else { return None };
    Some(start..start.checked_add(size)?)
}

/// Immutable view over an on-disk block group descriptor table.
#[derive(Debug)]
pub struct BlockGroupDescTable<'a> {
    data: &'a [u8],
    desc_size: usize,
    group_count: u32,
}

impl<'a> BlockGroupDescTable<'a> {
    /// Creates a descriptor table view.
    pub fn new(data: &'a [u8], desc_size: usize, group_count: u32) -> Self {
        Self {
            data,
            desc_size,
            group_count,
        }
    }

    /// Returns the descriptor for the specified group.
    pub fn get_desc(&self, group_idx: BGIndex) -> Option<Ext4GroupDesc> {
        let range = descriptor_range(group_idx, self.group_count, self.desc_size)?;
        self.data.get(range).map(Ext4GroupDesc::from_disk_bytes)
    }

    /// Returns the number of descriptors in the table.
    pub fn group_count(&self) -> u32 {
        self.group_count
    }

    /// Returns the descriptor size in bytes.
    pub fn desc_size(&self) -> usize {
        self.desc_size
    }

    /// Iterates over all descriptors.
    pub fn iter(&'a self) -> BlockGroupDescIter<'a> {
        BlockGroupDescIter {
            table: self,
            current: 0,
        }
    }

    /// Returns the total free block count across all groups.
    pub fn total_free_blocks(&self) -> u64 {
        let mut total = 0u64;
        for desc in self.iter() {
            total += desc.free_blocks_count() as u64;
        }
        total
    }

    /// Returns the total free inode count across all groups.
    pub fn total_free_inodes(&self) -> u64 {
        let mut total = 0u64;
        for desc in self.iter() {
            total += desc.free_inodes_count() as u64;
        }
        total
    }

    /// Returns the total used directory count across all groups.
    pub fn total_used_dirs(&self) -> u64 {
        let mut total = 0u64;
        for desc in self.iter() {
            total += desc.used_dirs_count() as u64;
        }
        total
    }

    /// Finds a group with at least `needed` free blocks.
    pub fn find_group_with_free_blocks(&self, needed: u32) -> Option<BGIndex> {
        for raw_idx in 0..self.group_count {
            let idx = BGIndex::new(raw_idx);
            let desc = self.get_desc(idx)?;
            if desc.free_blocks_count() >= needed && !desc.is_block_bitmap_uninit() {
                return Some(idx);
            }
        }
        None
    }

    /// Finds a group that still has free inodes.
    pub fn find_group_with_free_inodes(&self) -> Option<BGIndex> {
        for raw_idx in 0..self.group_count {
            let idx = BGIndex::new(raw_idx);
            let desc = self.get_desc(idx)?;
            if desc.free_inodes_count() > 0 && !desc.is_inode_bitmap_uninit() {
                return Some(idx);
            }
        }
        None
    }
}

/// Iterator over block group descriptors.
pub struct BlockGroupDescIter<'a> {
    table: &'a BlockGroupDescTable<'a>,
    current: u32,
}

impl<'a> Iterator for BlockGroupDescIter<'a> {
    type Item = Ext4GroupDesc;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.table.group_count {
            return None;
        }

        let desc = self.table.get_desc(BGIndex::new(self.current))?;
        self.current += 1;
        Some(desc)
    }
}

/// Mutable view over an on-disk block group descriptor table.
pub struct BlockGroupDescTableMut<'a> {
    data: &'a mut [u8],
    desc_size: usize,
    group_count: u32,
}

impl<'a> BlockGroupDescTableMut<'a> {
    /// Creates a mutable descriptor table view.
    pub fn new(data: &'a mut [u8], desc_size: usize, group_count: u32) -> Self {
        Self {
            data,
            desc_size,
            group_count,
        }
    }

    fn update_desc(&mut self, group_idx: BGIndex, update: impl FnOnce(&mut Ext4GroupDesc)) -> bool {
        let Some(bytes) = descriptor_range(group_idx, self.group_count, self.desc_size)
            .and_then(|range| self.data.get_mut(range))
        else {
            return false;
        };
        let mut desc = Ext4GroupDesc::from_disk_bytes(bytes);
        update(&mut desc);
        desc.to_disk_bytes(bytes);
        true
    }

    /// Updates the free block count for one group.
    pub fn update_free_blocks(&mut self, group_idx: BGIndex, count: u32) -> bool {
        self.update_desc(group_idx, |desc| {
            desc.bg_free_blocks_count_lo = (count & 0xFFFF) as u16;
            desc.bg_free_blocks_count_hi = ((count >> 16) & 0xFFFF) as u16;
        })
    }

    /// Updates the free inode count for one group.
    pub fn update_free_inodes(&mut self, group_idx: BGIndex, count: u32) -> bool {
        self.update_desc(group_idx, |desc| {
            desc.bg_free_inodes_count_lo = (count & 0xFFFF) as u16;
            desc.bg_free_inodes_count_hi = ((count >> 16) & 0xFFFF) as u16;
        })
    }

    /// Updates the used directory count for one group.
    pub fn update_used_dirs(&mut self, group_idx: BGIndex, count: u32) -> bool {
        self.update_desc(group_idx, |desc| {
            desc.bg_used_dirs_count_lo = (count & 0xFFFF) as u16;
            desc.bg_used_dirs_count_hi = ((count >> 16) & 0xFFFF) as u16;
        })
    }

    /// Increments the used directory count for one group.
    pub fn increment_used_dirs(&mut self, group_idx: BGIndex) -> bool {
        self.update_desc(group_idx, |desc| {
            let count = desc.used_dirs_count() + 1;
            desc.bg_used_dirs_count_lo = (count & 0xFFFF) as u16;
            desc.bg_used_dirs_count_hi = ((count >> 16) & 0xFFFF) as u16;
        })
    }

    /// Decrements the used directory count for one group.
    pub fn decrement_used_dirs(&mut self, group_idx: BGIndex) -> bool {
        self.update_desc(group_idx, |desc| {
            let count = desc.used_dirs_count().saturating_sub(1);
            desc.bg_used_dirs_count_lo = (count & 0xFFFF) as u16;
            desc.bg_used_dirs_count_hi = ((count >> 16) & 0xFFFF) as u16;
        })
    }

    /// Sets descriptor flags for one group.
    pub fn set_flags(&mut self, group_idx: BGIndex, flags: u16) -> bool {
        self.update_desc(group_idx, |desc| {
            desc.bg_flags |= flags;
        })
    }

    /// Clears descriptor flags for one group.
    pub fn clear_flags(&mut self, group_idx: BGIndex, flags: u16) -> bool {
        self.update_desc(group_idx, |desc| {
            desc.bg_flags &= !flags;
        })
    }
}
