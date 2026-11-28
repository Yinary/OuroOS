//! Ext2 线性目录的按块解析和路径分量查找。
use super::{le16, le32, Device, Error, Inode, Result, Volume, BLOCK_SIZE};
use alloc::vec::Vec;

const HEADER_SIZE: usize = 8;
const DIR_INDEX: u32 = 0x1000;

pub(super) struct Entry<'a> {
    pub(super) ino: u32,
    pub(super) next: usize,
    pub(super) name: &'a [u8],
    pub(super) file_type: u8,
}

/// 目录项及下次读取位置，名称保留卷内的原始字节。
pub(crate) struct DirEntry<'a> {
    pub(crate) ino: u32,
    pub(crate) next: usize,
    pub(crate) name: &'a [u8],
    pub(crate) file_type: u8,
}

pub(super) fn entry_at(block: &[u8; BLOCK_SIZE], offset: usize) -> Result<Entry<'_>> {
    let remaining = block.get(offset..).ok_or(Error::Io)?;
    if remaining.len() < HEADER_SIZE {
        return Err(Error::Io);
    }
    let ino = le32(remaining, 0);
    let length = usize::from(le16(remaining, 4));
    let name_length = usize::from(remaining[6]);
    let file_type = remaining[7];
    if length % 4 != 0 || !(HEADER_SIZE..=remaining.len()).contains(&length) {
        return Err(Error::Io);
    }
    let name = if ino == 0 {
        &[][..]
    } else {
        if name_length == 0 || HEADER_SIZE + name_length > length || file_type > 7 {
            return Err(Error::Io);
        }
        let name = &remaining[HEADER_SIZE..HEADER_SIZE + name_length];
        if name.iter().any(|&byte| byte == b'/' || byte == 0) {
            return Err(Error::Io);
        }
        name
    };
    Ok(Entry {
        ino,
        next: offset + length,
        name,
        file_type,
    })
}

impl<D: Device> Volume<D> {
    /// 查找父目录下的一个名称，返回卷内 inode。
    pub(crate) fn lookup(&mut self, parent: u32, name: &[u8]) -> Result<u32> {
        if name.is_empty() || name.len() > 255 || name.iter().any(|&byte| byte == b'/' || byte == 0)
        {
            return Err(Error::Invalid);
        }
        let mut result = None;
        self.read_dir(parent, 0, |entry| {
            if entry.name == name {
                result = Some(entry.ino);
                false
            } else {
                true
            }
        })?;
        result.ok_or(Error::NotFound)
    }

    fn directory_inode(&mut self, ino: u32) -> Result<Inode> {
        let inode = self.read_inode(ino)?;
        if !inode.is_dir() {
            return Err(Error::NotDir);
        }
        if inode.flags() & DIR_INDEX != 0 {
            return Err(Error::Unsupported);
        }
        if inode.size() == 0 || inode.size() % BLOCK_SIZE as u64 != 0 {
            return Err(Error::Io);
        }
        Ok(inode)
    }

    /// 从字节位置起读取目录；访问者拒绝条目时保留该条目的起始位置。
    pub(crate) fn read_dir(
        &mut self,
        ino: u32,
        mut offset: usize,
        mut visit: impl FnMut(DirEntry<'_>) -> bool,
    ) -> Result<usize> {
        let inode = self.directory_inode(ino)?;
        let size = usize::try_from(inode.size()).map_err(|_| Error::Range)?;
        if offset >= size {
            return Ok(offset);
        }
        if offset % 4 != 0 {
            return Err(Error::Invalid);
        }

        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(BLOCK_SIZE)
            .map_err(|_| Error::NoMemory)?;
        scratch.resize(BLOCK_SIZE, 0);
        let block = scratch.first_chunk_mut::<BLOCK_SIZE>().ok_or(Error::Io)?;
        while offset < size {
            let start = offset / BLOCK_SIZE * BLOCK_SIZE;
            let physical = self
                .mapped_block(&inode, (start / BLOCK_SIZE) as u64)?
                .ok_or(Error::Io)?;
            self.read_block(physical, block)?;
            while offset - start < BLOCK_SIZE {
                let entry = entry_at(block, offset - start)?;
                let next = start + entry.next;
                if entry.ino > self.geometry.inodes {
                    return Err(Error::Io);
                }
                if entry.ino != 0
                    && !visit(DirEntry {
                        ino: entry.ino,
                        next,
                        name: entry.name,
                        file_type: entry.file_type,
                    })
                {
                    return Ok(offset);
                }
                offset = next;
            }
        }
        Ok(offset)
    }
}
