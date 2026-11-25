//! 按父目录 inode 更新目录项，由调用方管理被移除对象的引用。
// OuroOS patch: 按 inode 更新目录项并延迟回收，见 README.md。
use super::{
    delete::{find_named_entry_in_parent, remove_named_entry_at},
    *,
};

fn valid_name(name: &str) -> Ext4Result<()> {
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(Ext4Error::invalid_input());
    }
    if name.len() > 255 {
        return Err(Ext4Error::new(Errno::ENAMETOOLONG));
    }
    Ok(())
}

struct Undo {
    blocks: Vec<(AbsoluteBN, Vec<u8>)>,
    inodes: Vec<(InodeNumber, Ext4Inode)>,
}
impl Undo {
    fn new() -> Ext4Result<Self> {
        let mut blocks = Vec::new();
        let mut inodes = Vec::new();
        blocks
            .try_reserve(3)
            .map_err(|_| Ext4Error::new(Errno::ENOMEM))?;
        inodes
            .try_reserve(4)
            .map_err(|_| Ext4Error::new(Errno::ENOMEM))?;
        Ok(Self { blocks, inodes })
    }
    fn block<B: BlockDevice>(
        &mut self,
        fs: &mut Ext4FileSystem,
        dev: &mut Jbd2Dev<B>,
        block: AbsoluteBN,
    ) -> Ext4Result<()> {
        if !self.blocks.iter().any(|(id, _)| *id == block) {
            self.blocks
                .push((block, fs.datablock_cache.get_or_load(dev, block)?.data));
        }
        Ok(())
    }
    fn inode<B: BlockDevice>(
        &mut self,
        fs: &mut Ext4FileSystem,
        dev: &mut Jbd2Dev<B>,
        ino: InodeNumber,
    ) -> Ext4Result<()> {
        if !self.inodes.iter().any(|(id, _)| *id == ino) {
            self.inodes.push((ino, fs.get_inode_by_num(dev, ino)?));
        }
        Ok(())
    }
    fn restore<B: BlockDevice>(
        &self,
        fs: &mut Ext4FileSystem,
        dev: &mut Jbd2Dev<B>,
    ) -> Ext4Result<()> {
        for (block, data) in &self.blocks {
            fs.datablock_cache
                .modify_via_journal(dev, *block, |out| out.copy_from_slice(data))?;
        }
        for (ino, inode) in &self.inodes {
            fs.modify_inode(dev, *ino, |out| *out = *inode)?;
        }
        Ok(())
    }
}

fn entry_offset(data: &[u8], name: &[u8]) -> Ext4Result<usize> {
    let mut offset = 0;
    while offset + 8 <= data.len() {
        let h = &data[offset..offset + 8];
        let len = u16::from_le_bytes([h[4], h[5]]) as usize;
        let end = offset + len;
        if len < 8 || end > data.len() || 8 + h[6] as usize > len {
            return Err(Ext4Error::corrupted());
        }
        if h[..4] != [0; 4] && &data[offset + 8..offset + 8 + h[6] as usize] == name {
            return Ok(offset);
        }
        offset = end;
    }
    Err(Ext4Error::not_found())
}

fn replace_entry<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    parent: InodeNumber,
    block: AbsoluteBN,
    name: &str,
    ino: InodeNumber,
    kind: u8,
) -> Ext4Result<()> {
    let inode = fs.get_inode_by_num(dev, parent)?;
    let data = fs.datablock_cache.get_or_load(dev, block)?;
    let offset = entry_offset(&data.data, name.as_bytes())?;
    // OuroOS patch: 目录块经日志事务
    fs.datablock_cache.modify_via_journal(dev, block, |data| {
        data[offset..offset + 4].copy_from_slice(&ino.raw().to_le_bytes());
        data[offset + 7] = kind;
        update_ext4_dirblock_csum32(&fs.superblock, parent.raw(), inode.i_generation, data);
    })
}

/// 在两个父目录之间移动一项；返回需由调用方检查回收的旧目标 inode。
/// 调用方须串行化整个操作；不负责被打开目标的生命周期和掉电恢复。
pub fn rename_entry<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    old: InodeNumber,
    name: &str,
    new: InodeNumber,
    target: &str,
    no_replace: bool,
) -> Ext4Result<Option<InodeNumber>> {
    if fs.readonly {
        return Err(Ext4Error::read_only());
    }
    valid_name(name)?;
    valid_name(target)?;
    let old_inode = fs.get_inode_by_num(dev, old)?;
    let mut new_inode = fs.get_inode_by_num(dev, new)?;
    let source = find_named_entry_in_parent(fs, dev, old, &old_inode, name.as_bytes())?;
    let src = fs.get_inode_by_num(dev, source.ino)?;
    if source.ino == fs.root_inode {
        return Err(Ext4Error::busy());
    }
    let destination = match find_named_entry_in_parent(fs, dev, new, &new_inode, target.as_bytes())
    {
        Ok(entry) => Some(entry),
        Err(e) if e.code == Errno::ENOENT => None,
        Err(e) => return Err(e),
    };
    if no_replace && destination.is_some() {
        return Err(Ext4Error::already_exists());
    }
    if destination.as_ref().is_some_and(|d| d.ino == source.ino) {
        return Ok(None);
    }
    let dst = destination
        .as_ref()
        .map(|d| fs.get_inode_by_num(dev, d.ino))
        .transpose()?;
    if let Some(mut inode) = dst {
        if src.is_dir() && !inode.is_dir() {
            return Err(Ext4Error::not_dir());
        }
        if !src.is_dir() && inode.is_dir() {
            return Err(Ext4Error::is_dir());
        }
        if inode.is_dir() && !is_dir_empty(fs, dev, &mut inode)? {
            return Err(Ext4Error::not_empty());
        }
        if inode.file_acl() != 0
            || (inode.blocks_count() != 0 && !inode.have_extend_header_and_use_extend())
        {
            return Err(Ext4Error::unsupported());
        }
        if inode.i_links_count == 0 {
            return Err(Ext4Error::corrupted());
        }
    }
    let dotdot = if src.is_dir() && old != new {
        let mut parent = new;
        let mut visited = 0;
        while parent != fs.root_inode {
            if parent == source.ino {
                return Err(Ext4Error::invalid_input());
            }
            visited += 1;
            if visited > fs.superblock.s_inodes_count {
                return Err(Ext4Error::corrupted());
            }
            let dir = fs.get_inode_by_num(dev, parent)?;
            parent = find_named_entry_in_parent(fs, dev, parent, &dir, b"..")?.ino;
        }
        Some(find_named_entry_in_parent(fs, dev, source.ino, &src, b"..")?.phys)
    } else {
        None
    };
    let old_links = if src.is_dir() && old != new {
        old_inode
            .i_links_count
            .checked_sub(1)
            .ok_or_else(Ext4Error::corrupted)?
    } else {
        old_inode.i_links_count
    };
    let delta = i32::from(src.is_dir() && old != new) - i32::from(dst.is_some_and(|d| d.is_dir()));
    let new_links = i32::from(new_inode.i_links_count) + delta;
    if !(0..=u16::MAX as i32).contains(&new_links) {
        return Err(Ext4Error::new(Errno::EMLINK));
    }
    let mut undo = Undo::new()?;
    // 目标不存在时先插入；失败不会删除源文件或已有目标。
    let inserted = destination.is_none();
    if inserted {
        if let Err(error) = insert_dir_entry(
            fs,
            dev,
            new,
            &mut new_inode,
            source.ino,
            target,
            source.file_type,
        ) {
            // 扩容后的映射先保留为空目录容量，再撤销可能已发布的新名称。
            if new_inode.size() != fs.get_inode_by_num(dev, new)?.size() {
                fs.modify_inode(dev, new, |inode| *inode = new_inode)?;
            }
            let parent = fs.get_inode_by_num(dev, new)?;
            match find_named_entry_in_parent(fs, dev, new, &parent, target.as_bytes()) {
                Ok(entry) if entry.ino == source.ino => {
                    remove_named_entry_at(fs, dev, new, &parent, entry.phys, target.as_bytes())?;
                }
                Ok(_) => return Err(Ext4Error::corrupted()),
                Err(e) if e.code == Errno::ENOENT => {}
                Err(e) => return Err(e),
            }
            return Err(error);
        }
    }
    let result = (|| {
        undo.block(fs, dev, source.phys)?;
        if let Some(entry) = &destination {
            undo.block(fs, dev, entry.phys)?;
        }
        if let Some(block) = dotdot {
            undo.block(fs, dev, block)?;
        }
        for ino in [old, new, source.ino] {
            undo.inode(fs, dev, ino)?;
        }
        if let Some(entry) = &destination {
            undo.inode(fs, dev, entry.ino)?;
        }
        if let Some(entry) = &destination {
            replace_entry(
                fs,
                dev,
                new,
                entry.phys,
                target,
                source.ino,
                source.file_type,
            )?;
        }
        remove_named_entry_at(fs, dev, old, &old_inode, source.phys, name.as_bytes())?;
        if let Some(block) = dotdot {
            replace_entry(fs, dev, source.ino, block, "..", new, 2)?;
        }
        if src.is_dir() && old != new {
            fs.set_inode_links_count(dev, old, old_links)?;
        }
        if delta != 0 {
            fs.set_inode_links_count(dev, new, new_links as u16)?;
        }
        if let (Some(entry), Some(inode)) = (&destination, dst) {
            fs.set_inode_links_count(
                dev,
                entry.ino,
                if inode.is_dir() {
                    0
                } else {
                    inode.i_links_count - 1
                },
            )?;
        }
        fs.touch_inode_ctime_for_link_change(dev, source.ino)?;
        fs.touch_parent_dir_for_entry_change(dev, old)?;
        if old != new {
            fs.touch_parent_dir_for_entry_change(dev, new)?;
        }
        Ok(destination.as_ref().map(|d| d.ino))
    })();
    if result.is_err() {
        undo.restore(fs, dev)?;
        if inserted {
            let parent = fs.get_inode_by_num(dev, new)?;
            let entry = find_named_entry_in_parent(fs, dev, new, &parent, target.as_bytes())?;
            remove_named_entry_at(fs, dev, new, &parent, entry.phys, target.as_bytes())?;
        }
    }
    result
}

/// 移除空目录的名字并清零链接数，调用方负责在无引用时回收 inode。
pub fn unlink_empty_directory<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    parent: InodeNumber,
    ino: InodeNumber,
    name: &str,
) -> Ext4Result<()> {
    if fs.readonly {
        return Err(Ext4Error::read_only());
    }
    valid_name(name)?;
    let dir = fs.get_inode_by_num(dev, parent)?;
    let entry = find_named_entry_in_parent(fs, dev, parent, &dir, name.as_bytes())?;
    if entry.ino != ino {
        return Err(Ext4Error::not_found());
    }
    let mut child = fs.get_inode_by_num(dev, ino)?;
    if !child.is_dir() {
        return Err(Ext4Error::not_dir());
    }
    if !super::delete::is_dir_empty(fs, dev, &mut child)? {
        return Err(Ext4Error::new(Errno::ENOTEMPTY));
    }
    // dir_nlink 溢出后用 1 表示未知的目录链接数。
    let links = match dir.i_links_count {
        0 => return Err(Ext4Error::corrupted()),
        1 => 1,
        n => n - 1,
    };
    let mut undo = Undo::new()?;
    undo.block(fs, dev, entry.phys)?;
    undo.inode(fs, dev, parent)?;
    undo.inode(fs, dev, ino)?;
    let result = (|| {
        remove_named_entry_at(fs, dev, parent, &dir, entry.phys, name.as_bytes())?;
        fs.set_inode_links_count(dev, parent, links)?;
        fs.set_inode_links_count(dev, ino, 0)?;
        fs.touch_parent_dir_for_entry_change(dev, parent)
    })();
    if result.is_err() {
        undo.restore(fs, dev).map_err(|_| Ext4Error::io())?;
    }
    result
}

/// 回收已无链接和外部引用的 inode，目录同时减少分组目录计数。
pub fn reclaim_unlinked_inode<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    ino: InodeNumber,
) -> Ext4Result<()> {
    let mut inode = fs.get_inode_by_num(dev, ino)?;
    if inode.i_links_count != 0 {
        return Ok(());
    }
    let directory = inode.is_dir();
    free_inode(fs, dev, ino, &mut inode)?;
    if directory {
        let (group, _) = fs.inode_allocator.global_to_group(ino)?;
        let desc = fs
            .get_group_desc_mut(group)
            .ok_or_else(Ext4Error::corrupted)?;
        let count = desc
            .used_dirs_count()
            .checked_sub(1)
            .ok_or_else(Ext4Error::corrupted)?;
        desc.bg_used_dirs_count_lo = count as u16;
        desc.bg_used_dirs_count_hi = (count >> 16) as u16;
    }
    Ok(())
}

fn by_path<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    path: &str,
) -> Ext4Result<(InodeNumber, String)> {
    let norm = normalize_path(path);
    let (parent, name) = norm.rsplit_once('/').ok_or_else(Ext4Error::invalid_input)?;
    valid_name(name)?;
    let (ino, _) = get_inode_with_num(fs, dev, if parent.is_empty() { "/" } else { parent })?
        .ok_or_else(Ext4Error::not_found)?;
    Ok((ino, name.to_string()))
}

/// 按路径重命名；调用方保证不存在需要保留的打开目标引用。
pub fn rename<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    old: &str,
    new: &str,
) -> Ext4Result<()> {
    let (old_parent, name) = by_path(fs, device, old)?;
    let (new_parent, target) = by_path(fs, device, new)?;
    if let Some(ino) = rename_entry(fs, device, old_parent, &name, new_parent, &target, false)? {
        reclaim_unlinked_inode(fs, device, ino)?;
    }
    Ok(())
}

/// 移动到尚不存在的目标；目标存在时返回 EEXIST。
pub fn mv<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    device: &mut Jbd2Dev<B>,
    old: &str,
    new: &str,
) -> Ext4Result<()> {
    let (old_parent, name) = by_path(fs, device, old)?;
    let (new_parent, target) = by_path(fs, device, new)?;
    rename_entry(fs, device, old_parent, &name, new_parent, &target, true).map(|_| ())
}
