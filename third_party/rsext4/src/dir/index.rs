//! OuroOS patch: 单个大目录的有界内存索引与插入位置提示。
use alloc::vec::Vec;

use crate::{
    blockdev::{BlockDevice, Jbd2Dev},
    bmalloc::{AbsoluteBN, InodeNumber},
    checksum::verify_ext4_dirblock_checksum,
    config::BLOCK_SIZE,
    disknode::Ext4Inode,
    entries::classic_dir,
    error::{Ext4Error, Ext4Result},
    ext4::Ext4FileSystem,
    file::ParentDirEntry,
    hashtree::Ext4InodeHashTreeExt,
    loopfile::resolve_inode_blocks,
};

const MAX_SLOTS: usize = 131072;

#[derive(Clone, Copy, Default)]
struct Slot {
    hash: u64,
    block: u64,
    occupied: bool,
}

/// 只为一个线性大目录保存名称指纹，命中后仍核对盘上名称。
pub(crate) struct DirectoryIndex {
    pub(crate) parent: InodeNumber,
    generation: u32,
    size: u64,
    slots: Vec<Slot>,
    used: usize,
    pub(crate) insertion: usize,
}

fn hash(name: &[u8]) -> u64 {
    name.iter().fold(0xcbf29ce484222325, |value, byte| {
        (value ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
    })
}

impl DirectoryIndex {
    fn new(parent: InodeNumber, inode: &Ext4Inode) -> Self {
        Self {
            parent,
            generation: inode.i_generation,
            size: inode.size(),
            slots: Vec::new(),
            used: 0,
            insertion: 0,
        }
    }

    fn insert_slot(slots: &mut [Slot], slot: Slot) {
        let mut position = slot.hash as usize & (slots.len() - 1);
        while slots[position].occupied {
            position = (position + 1) & (slots.len() - 1);
        }
        slots[position] = slot;
    }

    /// 加入名称和所在块；分配失败时由调用方丢弃索引。
    pub(crate) fn remember(&mut self, name: &[u8], block: AbsoluteBN) -> Ext4Result<()> {
        if self.used * 2 >= self.slots.len() {
            let capacity = (self.slots.len() * 2).max(256);
            if capacity > MAX_SLOTS {
                return Err(Ext4Error::no_space());
            }
            let mut slots = Vec::new();
            slots
                .try_reserve_exact(capacity)
                .map_err(|_| Ext4Error::no_space())?;
            slots.resize(capacity, Slot::default());
            for slot in self.slots.iter().filter(|slot| slot.occupied) {
                Self::insert_slot(&mut slots, *slot);
            }
            self.slots = slots;
        }
        Self::insert_slot(
            &mut self.slots,
            Slot {
                hash: hash(name),
                block: block.raw(),
                occupied: true,
            },
        );
        self.used += 1;
        Ok(())
    }

    /// 更新插入后的目录大小与候选逻辑块。
    pub(crate) fn inserted(&mut self, inode: &Ext4Inode, logical: usize) {
        self.size = inode.size();
        self.insertion = logical;
    }
}

fn build<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    parent: InodeNumber,
    inode: &Ext4Inode,
) -> Ext4Result<DirectoryIndex> {
    let mut index = DirectoryIndex::new(parent, inode);
    let mut copy = *inode;
    let blocks = resolve_inode_blocks(fs, dev, &mut copy)?;
    if blocks.len() as u64 != inode.size().div_ceil(BLOCK_SIZE as u64)
        || blocks.keys().copied().ne(0..blocks.len() as u32)
    {
        return Err(Ext4Error::corrupted());
    }
    for block in blocks.into_values() {
        let cached = fs.datablock_cache.get_or_load(dev, block)?;
        let data = &cached.data[..BLOCK_SIZE];
        if !verify_ext4_dirblock_checksum(&fs.superblock, parent.raw(), inode.i_generation, data) {
            return Err(Ext4Error::corrupted());
        }
        let mut offset = 0;
        while offset + 8 <= data.len() {
            let record = &data[offset..];
            let length = u16::from_le_bytes([record[4], record[5]]) as usize;
            if length < 8 || length % 4 != 0 || length > data.len() - offset {
                return Err(Ext4Error::corrupted());
            }
            let name_len = record[6] as usize;
            let ino = u32::from_le_bytes([record[0], record[1], record[2], record[3]]);
            if ino != 0 {
                if name_len == 0 || 8 + name_len > length {
                    return Err(Ext4Error::corrupted());
                }
                index.remember(&record[8..8 + name_len], block)?;
            }
            offset += length;
        }
        if offset != data.len() {
            return Err(Ext4Error::corrupted());
        }
    }
    Ok(index)
}

/// 为线性大目录查询名称；无索引时让调用方沿用既有路径。
pub(crate) fn cached_lookup<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    parent: InodeNumber,
    inode: &Ext4Inode,
    name: &[u8],
) -> Option<Ext4Result<ParentDirEntry>> {
    if inode.is_htree_indexed()
        || !inode.have_extend_header_and_use_extend()
        || inode.size() < 8 * BLOCK_SIZE as u64
    {
        return None;
    }
    let valid = fs.directory_index.as_ref().is_some_and(|index| {
        index.parent == parent
            && index.generation == inode.i_generation
            && index.size == inode.size()
    });
    if !valid {
        // 缓存构造失败不改变目录查询的既有错误处理。
        fs.directory_index = build(fs, dev, parent, inode).ok();
    }
    let index = fs.directory_index.as_ref()?;
    if index.slots.is_empty() {
        return None;
    }
    let target = hash(name);
    let mut position = target as usize & (index.slots.len() - 1);
    while index.slots[position].occupied {
        let slot = index.slots[position];
        if slot.hash == target {
            let block = AbsoluteBN::new(slot.block);
            let cached = match fs.datablock_cache.get_or_load(dev, block) {
                Ok(cached) => cached,
                Err(error) => return Some(Err(error)),
            };
            if let Some(entry) = classic_dir::find_entry(&cached.data, name) {
                return Some(InodeNumber::new(entry.inode).map(|ino| ParentDirEntry {
                    ino,
                    phys: block,
                    file_type: entry.file_type,
                }));
            }
        }
        position = (position + 1) & (index.slots.len() - 1);
    }
    Some(Err(Ext4Error::not_found()))
}
