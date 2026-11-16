// OuroOS patch: 03-directory-and-descriptor-parsing (see README.md).
//! Hash tree node parsing helpers.

use alloc::vec::Vec;

use super::{HashTreeError, HashTreeManager, HashTreeNode};
use crate::{
    endian::{read_u16_le, read_u32_le},
    entries::{
        Ext4DirEntry2, Ext4DirEntryInfo, Ext4DxCountlimit, Ext4DxEntry, Ext4DxNode, Ext4DxRoot,
        Ext4DxRootInfo,
    },
};

impl HashTreeManager {
    pub(super) fn parse_root_node(&self, data: &[u8]) -> Result<HashTreeNode, HashTreeError> {
        if data.len() < core::mem::size_of::<Ext4DxRoot>() {
            return Err(HashTreeError::BufferTooSmall);
        }

        // "." 占 12 字节，".." 的记录头和名字之后是索引元数据。
        let dot = Ext4DirEntryInfo::parse_from_bytes(&data[..12]);
        let dotdot = Ext4DirEntryInfo::parse_from_bytes(&data[12..24]);
        if read_u16_le(&data[4..6]) != 12
            || read_u16_le(&data[16..18]) as usize != data.len() - 12
            || !dot.is_some_and(|entry| entry.is_dot())
            || !dotdot.is_some_and(|entry| entry.is_dotdot())
        {
            return Err(HashTreeError::InvalidDirectoryEntry);
        }
        let info_bytes = &data[24..32];
        if read_u32_le(&info_bytes[..4]) != 0
            || info_bytes[5] as usize != core::mem::size_of::<Ext4DxRootInfo>()
        {
            return Err(HashTreeError::CorruptedHashTree);
        }
        let hash_version = info_bytes[4];
        let indirect_levels = info_bytes[6];

        let index = &data[32..];
        let header = index.get(..8).ok_or(HashTreeError::BufferTooSmall)?;
        let limit = read_u16_le(&header[..2]) as usize;
        let count = read_u16_le(&header[2..4]) as usize;
        if count == 0 || count > limit || limit > index.len() / 8 {
            return Err(HashTreeError::CorruptedHashTree);
        }
        let mut entries = Vec::with_capacity(count);
        for (i, entry) in index[..count * 8].chunks_exact(8).enumerate() {
            let hash = if i == 0 { 0 } else { read_u32_le(&entry[..4]) };
            entries.push(Ext4DxEntry {
                hash,
                block: read_u32_le(&entry[4..8]),
            });
        }

        Ok(HashTreeNode::Root {
            hash_version,
            indirect_levels,
            entries,
        })
    }

    pub(super) fn parse_dx_entries(&self, data: &[u8]) -> Result<Vec<Ext4DxEntry>, HashTreeError> {
        let mut entries = Vec::new();
        let mut offset = 0;

        while offset + core::mem::size_of::<Ext4DxEntry>() <= data.len() {
            let hash = read_u32_le(&data[offset..offset + 4]);
            let block = read_u32_le(&data[offset + 4..offset + 8]);

            if block == 0 {
                break;
            }

            entries.push(Ext4DxEntry { hash, block });
            offset += core::mem::size_of::<Ext4DxEntry>();
        }

        Ok(entries)
    }

    pub(super) fn parse_internal_node(&self, data: &[u8]) -> Result<HashTreeNode, HashTreeError> {
        if data.len() < core::mem::size_of::<Ext4DxNode>() {
            return Err(HashTreeError::BufferTooSmall);
        }

        let fake_entry_size = core::mem::size_of::<Ext4DirEntry2>();
        let countlimit_offset = fake_entry_size;
        if countlimit_offset + core::mem::size_of::<Ext4DxCountlimit>() > data.len() {
            return Err(HashTreeError::CorruptedHashTree);
        }

        let countlimit_bytes =
            &data[countlimit_offset..countlimit_offset + core::mem::size_of::<Ext4DxCountlimit>()];
        let _count = read_u16_le(&countlimit_bytes[2..4]) as usize;

        let entries_offset = countlimit_offset + core::mem::size_of::<Ext4DxCountlimit>();
        let entries = self.parse_dx_entries(&data[entries_offset..])?;

        Ok(HashTreeNode::Internal { entries, level: 0 })
    }
}
