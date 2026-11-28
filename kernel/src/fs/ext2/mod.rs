//! 独立 Ext2 后端，校验卷几何并按 inode 读写文件和目录。
#![deny(unsafe_code)]

mod directory;
mod mutate;

use alloc::{string::String, vec::Vec};

const BLOCK_SIZE: usize = 1024;
const INODE_SIZE: usize = 128;
const SUPERBLOCK: u64 = 1024;
const GROUP_TABLE: u64 = 2048;
const GROUP_DESC_SIZE: usize = 32;
const POINTERS_PER_BLOCK: u64 = (BLOCK_SIZE / 4) as u64;
const TYPE_MASK: u16 = 0xf000;
const REGULAR: u16 = 0x8000;
const DIRECTORY: u16 = 0x4000;
pub(super) const ROOT_INODE: u32 = 2;

pub(super) type Result<T> = core::result::Result<T, Error>;

/// 后端错误，由文件系统入口映射为系统调用错误。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Io,
    Invalid,
    Unsupported,
    ReadOnly,
    NotFound,
    Exists,
    NotDir,
    IsDir,
    NoSpace,
    TooManyLinks,
    Range,
    NoMemory,
}

/// 受分区长度约束的字节设备。
pub(super) trait Device {
    /// 返回可访问的字节数。
    fn len(&self) -> u64;
    /// 读取指定字节范围，设备错误时返回失败。
    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<()>;
    /// 写入指定字节范围，设备错误时返回失败。
    fn write_at(&mut self, offset: u64, src: &[u8]) -> Result<()>;
    /// 将缓存写回设备。
    fn flush(&mut self) -> Result<()>;
}

/// Ext2 inode 中的文件属性，blocks 以 512 字节为单位。
pub(super) struct Metadata {
    pub(super) mode: u16,
    pub(super) size: u64,
    pub(super) links: u16,
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) blocks: u64,
    pub(super) atime: u32,
    pub(super) mtime: u32,
    pub(super) ctime: u32,
}

/// 超级块中的容量和剩余空间统计，块大小为 1024 字节。
pub(super) struct Statistics {
    pub(super) blocks: u64,
    pub(super) blocks_free: u64,
    pub(super) blocks_available: u64,
    pub(super) inodes: u64,
    pub(super) inodes_free: u64,
}

/// 已打开的 Ext2 卷和写入状态。
pub(super) struct Volume<D> {
    device: D,
    geometry: Geometry,
    readonly: bool,
    failed: bool,
}

#[derive(Clone, Copy)]
struct Geometry {
    blocks: u32,
    inodes: u32,
    first_data_block: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    groups: u32,
    first_inode: u32,
    sparse_super: bool,
}

struct Group {
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
    offset: u64,
}

struct Inode {
    raw: [u8; INODE_SIZE],
    offset: u64,
}

fn le16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

impl Geometry {
    fn parse(sb: &[u8; BLOCK_SIZE], device_len: u64) -> Result<Self> {
        if le16(sb, 56) != 0xef53 {
            return Err(Error::Invalid);
        }
        const DIR_INDEX: u32 = 0x20;
        const FILETYPE: u32 = 0x02;
        const SPARSE_SUPER_AND_LARGE_FILE: u32 = 0x03;
        let ro_compat = le32(sb, 100);
        if le32(sb, 24) != 0
            || le32(sb, 28) != 0
            || le32(sb, 72) != 0
            || le32(sb, 76) != 1
            || le16(sb, 88) != INODE_SIZE as u16
            || le32(sb, 92) & !DIR_INDEX != 0
            || le32(sb, 96) != FILETYPE
            || ro_compat & !SPARSE_SUPER_AND_LARGE_FILE != 0
        {
            return Err(Error::Unsupported);
        }
        if le16(sb, 58) != 1 || le32(sb, 232) != 0 {
            return Err(Error::Unsupported);
        }
        let blocks = le32(sb, 4);
        let inodes = le32(sb, 0);
        let first_data_block = le32(sb, 20);
        let blocks_per_group = le32(sb, 32);
        let inodes_per_group = le32(sb, 40);
        let first_inode = le32(sb, 84);
        if blocks < 3
            || u64::from(blocks) > device_len / BLOCK_SIZE as u64
            || first_data_block != 1
            || !(1..=(BLOCK_SIZE * 8) as u32).contains(&blocks_per_group)
            || le32(sb, 36) != blocks_per_group
            || !(1..=(BLOCK_SIZE * 8) as u32).contains(&inodes_per_group)
            || inodes_per_group % (BLOCK_SIZE / INODE_SIZE) as u32 != 0
            || !(11..=inodes_per_group).contains(&first_inode)
            || first_inode > inodes
            || le32(sb, 12) > blocks - first_data_block
            || le32(sb, 16) > inodes
        {
            return Err(Error::Invalid);
        }
        let groups = (blocks - first_data_block).div_ceil(blocks_per_group);
        if inodes.div_ceil(inodes_per_group) != groups
            || GROUP_TABLE + u64::from(groups) * GROUP_DESC_SIZE as u64
                > u64::from(blocks) * BLOCK_SIZE as u64
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            blocks,
            inodes,
            first_data_block,
            blocks_per_group,
            inodes_per_group,
            groups,
            first_inode,
            sparse_super: ro_compat & 1 != 0,
        })
    }

    fn group_bounds(self, index: u32) -> Result<core::ops::Range<u32>> {
        if index >= self.groups {
            return Err(Error::Range);
        }
        let start = self.first_data_block + index * self.blocks_per_group;
        Ok(start..start.saturating_add(self.blocks_per_group).min(self.blocks))
    }

    fn block_offset(self, block: u32) -> Result<u64> {
        if !(self.first_data_block..self.blocks).contains(&block) {
            return Err(Error::Io);
        }
        Ok(u64::from(block) * BLOCK_SIZE as u64)
    }

    fn has_superblock(self, index: u32) -> bool {
        fn power_of(mut value: u32, base: u32) -> bool {
            if value == 0 {
                return false;
            }
            while value % base == 0 {
                value /= base;
            }
            value == 1
        }
        !self.sparse_super || index == 0 || [3, 5, 7].into_iter().any(|base| power_of(index, base))
    }
}

impl Inode {
    fn mode(&self) -> u16 {
        le16(&self.raw, 0)
    }

    fn size(&self) -> u64 {
        let low = u64::from(le32(&self.raw, 4));
        if self.mode() & TYPE_MASK == REGULAR {
            return low | (u64::from(le32(&self.raw, 108)) << 32);
        }
        low
    }

    fn flags(&self) -> u32 {
        le32(&self.raw, 32)
    }

    fn links(&self) -> u16 {
        le16(&self.raw, 26)
    }

    fn pointer(&self, index: usize) -> u32 {
        le32(&self.raw, 40 + index * 4)
    }

    fn is_dir(&self) -> bool {
        self.mode() & TYPE_MASK == DIRECTORY
    }
}

impl<D: Device> Volume<D> {
    /// 打开支持的干净、无日志 Ext2 卷，确认根目录可读。
    pub(super) fn open(mut device: D, readonly: bool) -> Result<Self> {
        let mut sb = [0; BLOCK_SIZE];
        if device.len() < SUPERBLOCK + BLOCK_SIZE as u64 {
            return Err(Error::Invalid);
        }
        device.read_at(SUPERBLOCK, &mut sb)?;
        let geometry = Geometry::parse(&sb, device.len())?;
        let mut volume = Self {
            device,
            geometry,
            readonly,
            failed: false,
        };
        for index in 0..geometry.groups {
            volume.group(index)?;
        }
        if volume.lookup(ROOT_INODE, b".")? != ROOT_INODE {
            return Err(Error::Io);
        }
        Ok(volume)
    }

    /// 返回卷是否拒绝写入。
    pub(super) fn readonly(&self) -> bool {
        self.readonly
    }

    /// 刷回卷中的写入，随后切换到只读状态。
    pub(super) fn set_readonly(&mut self) -> Result<()> {
        self.sync()?;
        self.readonly = true;
        Ok(())
    }

    /// 将卷的修改同步至下层设备。
    pub(super) fn sync(&mut self) -> Result<()> {
        if self.failed {
            return Err(Error::Io);
        }
        self.device.flush()
    }

    /// 返回已分配 inode 的文件属性。
    pub(super) fn metadata(&mut self, ino: u32) -> Result<Metadata> {
        let inode = self.read_inode(ino)?;
        let raw = &inode.raw;
        Ok(Metadata {
            mode: inode.mode(),
            size: inode.size(),
            links: inode.links(),
            uid: u32::from(le16(raw, 2)) | (u32::from(le16(raw, 120)) << 16),
            gid: u32::from(le16(raw, 24)) | (u32::from(le16(raw, 122)) << 16),
            blocks: u64::from(le32(raw, 28)),
            atime: le32(raw, 8),
            ctime: le32(raw, 12),
            mtime: le32(raw, 16),
        })
    }

    /// 读取卷的当前空间计数，普通用户的可用块数扣除保留块。
    pub(super) fn statfs(&mut self) -> Result<Statistics> {
        if self.failed {
            return Err(Error::Io);
        }
        let mut sb = [0; 20];
        self.device.read_at(SUPERBLOCK, &mut sb)?;
        let reserved = le32(&sb, 8);
        let blocks_free = le32(&sb, 12);
        let inodes_free = le32(&sb, 16);
        if blocks_free > self.geometry.blocks || inodes_free > self.geometry.inodes {
            return Err(Error::Io);
        }
        Ok(Statistics {
            blocks: self.geometry.blocks.into(),
            blocks_free: blocks_free.into(),
            blocks_available: blocks_free.saturating_sub(reserved).into(),
            inodes: self.geometry.inodes.into(),
            inodes_free: inodes_free.into(),
        })
    }

    /// 读取普通文件，越过文件末尾的部分不计入返回长度。
    pub(super) fn read(&mut self, ino: u32, offset: u64, dst: &mut [u8]) -> Result<usize> {
        let inode = self.read_inode(ino)?;
        match inode.mode() & TYPE_MASK {
            REGULAR => {}
            DIRECTORY => return Err(Error::IsDir),
            _ => return Err(Error::Unsupported),
        }
        self.read_data(&inode, offset, dst)
    }

    /// 读取小于 4096 字节的 UTF-8 符号链接目标。
    pub(super) fn read_link(&mut self, ino: u32) -> Result<String> {
        let inode = self.read_inode(ino)?;
        if inode.mode() & TYPE_MASK != 0xa000 {
            return Err(Error::Invalid);
        }
        let length = inode.size() as usize;
        if !(1..4096).contains(&length) {
            return Err(Error::Unsupported);
        }
        let mut text = Vec::new();
        text.try_reserve_exact(length)
            .map_err(|_| Error::NoMemory)?;
        if le32(&inode.raw, 28) == 0 {
            let inline = inode.raw[40..100].get(..length).ok_or(Error::Io)?;
            text.extend_from_slice(inline);
        } else {
            text.resize(length, 0);
            self.read_data(&inode, 0, &mut text)?;
        }
        if text.contains(&0) {
            return Err(Error::Io);
        }
        String::from_utf8(text).map_err(|_| Error::Unsupported)
    }

    fn read_data(&mut self, inode: &Inode, offset: u64, dst: &mut [u8]) -> Result<usize> {
        let length = (dst.len() as u64).min(inode.size().saturating_sub(offset)) as usize;
        let mut done = 0;
        while done < length {
            let position = offset + done as u64;
            let within = (position % BLOCK_SIZE as u64) as usize;
            let count = (length - done).min(BLOCK_SIZE - within);
            let output = &mut dst[done..done + count];
            if let Some(block) = self.mapped_block(inode, position / BLOCK_SIZE as u64)? {
                let start = self.geometry.block_offset(block)? + within as u64;
                self.device.read_at(start, output)?;
            } else {
                output.fill(0);
            }
            done += count;
        }
        Ok(done)
    }

    fn group(&mut self, index: u32) -> Result<Group> {
        let bounds = self.geometry.group_bounds(index)?;
        let offset = GROUP_TABLE + u64::from(index) * GROUP_DESC_SIZE as u64;
        let mut raw = [0; GROUP_DESC_SIZE];
        self.device.read_at(offset, &mut raw)?;
        let block_bitmap = le32(&raw, 0);
        let inode_bitmap = le32(&raw, 4);
        let inode_table = le32(&raw, 8);
        let table_blocks = self.geometry.inodes_per_group / (BLOCK_SIZE / INODE_SIZE) as u32;
        let table_end = inode_table.checked_add(table_blocks).ok_or(Error::Io)?;
        let table = inode_table..table_end;
        let metadata_start = if self.geometry.has_superblock(index) {
            let desc_blocks = self
                .geometry
                .groups
                .div_ceil((BLOCK_SIZE / GROUP_DESC_SIZE) as u32);
            bounds.start.checked_add(1 + desc_blocks).ok_or(Error::Io)?
        } else {
            bounds.start
        };
        let valid = metadata_start..bounds.end;
        if !valid.contains(&block_bitmap)
            || !valid.contains(&inode_bitmap)
            || !valid.contains(&inode_table)
            || table_end > bounds.end
            || block_bitmap == inode_bitmap
            || table.contains(&block_bitmap)
            || table.contains(&inode_bitmap)
            || u32::from(le16(&raw, 12)) > bounds.end - bounds.start
            || u32::from(le16(&raw, 14)) > self.geometry.inodes_per_group
        {
            return Err(Error::Io);
        }
        Ok(Group {
            block_bitmap,
            inode_bitmap,
            inode_table,
            offset,
        })
    }

    fn read_inode(&mut self, ino: u32) -> Result<Inode> {
        if self.failed {
            return Err(Error::Io);
        }
        if !(1..=self.geometry.inodes).contains(&ino) {
            return Err(Error::NotFound);
        }
        let index = (ino - 1) / self.geometry.inodes_per_group;
        let slot = (ino - 1) % self.geometry.inodes_per_group;
        let group = self.group(index)?;
        let mut bitmap_byte = [0];
        let bit_offset = self.geometry.block_offset(group.inode_bitmap)? + u64::from(slot / 8);
        self.device.read_at(bit_offset, &mut bitmap_byte)?;
        if bitmap_byte[0] & (1 << (slot % 8)) == 0 {
            return Err(Error::NotFound);
        }
        let offset =
            self.geometry.block_offset(group.inode_table)? + u64::from(slot) * INODE_SIZE as u64;
        let mut raw = [0; INODE_SIZE];
        self.device.read_at(offset, &mut raw)?;
        if le16(&raw, 0) & TYPE_MASK == 0 {
            return Err(Error::Io);
        }
        Ok(Inode { raw, offset })
    }

    fn read_block(&mut self, block: u32, dst: &mut [u8; BLOCK_SIZE]) -> Result<()> {
        self.device.read_at(self.geometry.block_offset(block)?, dst)
    }

    fn mapped_block(&mut self, inode: &Inode, logical: u64) -> Result<Option<u32>> {
        const DIRECT: u64 = 12;
        const COMPRESSED_OR_EXTENTS: u32 = 0x0008_0004;
        if inode.flags() & COMPRESSED_OR_EXTENTS != 0 {
            return Err(Error::Unsupported);
        }
        let block = if logical < DIRECT {
            inode.pointer(logical as usize)
        } else {
            let mut slot = logical - DIRECT;
            let mut span = POINTERS_PER_BLOCK;
            let mut level = 1;
            while slot >= span && level < 3 {
                slot -= span;
                span *= POINTERS_PER_BLOCK;
                level += 1;
            }
            if slot >= span {
                return Err(Error::Range);
            }
            let mut block = inode.pointer(11 + level);
            for _ in 0..level {
                if block == 0 {
                    return Ok(None);
                }
                span /= POINTERS_PER_BLOCK;
                let offset = self.geometry.block_offset(block)? + (slot / span) * 4;
                let mut raw = [0; 4];
                self.device.read_at(offset, &mut raw)?;
                block = le32(&raw, 0);
                slot %= span;
            }
            block
        };
        if block == 0 {
            return Ok(None);
        }
        self.geometry.block_offset(block)?;
        Ok(Some(block))
    }
}
