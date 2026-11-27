//! 硬链接的目录项与 inode 更新。
use super::{
    delete::{find_named_entry_in_parent, remove_inodeentry_from_parentdir, rollback_entry_insert},
    *,
};

// OuroOS patch: 使用调用方已解析的 inode 添加目录项，失败时恢复链接数。
/// 在父目录中为已存在的普通文件或符号链接 增加一个名称。
pub fn link_entry<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    dev: &mut Jbd2Dev<B>,
    parent: InodeNumber,
    source: InodeNumber,
    name: &str,
) -> Ext4Result<()> {
    const LINK_MAX: u16 = 65_000;
    if fs.readonly {
        return Err(Ext4Error::read_only());
    }
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(Ext4Error::invalid_input());
    }
    if name.len() > 255 {
        return Err(Ext4Error::new(Errno::ENAMETOOLONG));
    }
    let inode = fs.get_inode_by_num(dev, source)?;
    let kind = match inode.i_mode & Ext4Inode::S_IFMT {
        Ext4Inode::S_IFREG => Ext4DirEntry2::EXT4_FT_REG_FILE,
        Ext4Inode::S_IFLNK => Ext4DirEntry2::EXT4_FT_SYMLINK,
        _ => return Err(Ext4Error::new(Errno::EPERM)),
    };
    if inode.i_flags & (Ext4Inode::EXT4_IMMUTABLE_FL | Ext4Inode::EXT4_APPEND_FL) != 0 {
        return Err(Ext4Error::new(Errno::EPERM));
    }
    if inode.i_links_count == 0 {
        return Err(Ext4Error::not_found());
    }
    let original_dir = fs.get_inode_by_num(dev, parent)?;
    match find_named_entry_in_parent(fs, dev, parent, &original_dir, name.as_bytes()) {
        Ok(_) => return Err(Ext4Error::already_exists()),
        Err(e) if e.code == Errno::ENOENT => {}
        Err(e) => return Err(e),
    }
    if inode.i_links_count >= LINK_MAX {
        return Err(Ext4Error::new(Errno::EMLINK));
    }

    let mut dir = original_dir;
    let inserted = insert_dir_entry(fs, dev, parent, &mut dir, source, name, kind);
    let result = match inserted {
        Ok(()) => fs
            .set_inode_links_count(dev, source, inode.i_links_count + 1)
            .map(|_| ()),
        Err(error) if no_space_before_insert(error) => return Err(error),
        Err(error) => Err(error),
    };
    if result.is_err() {
        rollback_entry_insert(fs, dev, parent, source, name, &original_dir, &dir)
            .map_err(|_| Ext4Error::io())?;
        if inserted.is_ok() {
            fs.modify_inode(dev, source, |out| *out = inode)
                .map_err(|_| Ext4Error::io())?;
        }
    }
    result
}

/// Create a hard link.
pub fn link<B: BlockDevice>(
    fs: &mut Ext4FileSystem,
    block_dev: &mut Jbd2Dev<B>,
    link_path: &str,
    linked_path: &str,
) -> Ext4Result<()> {
    let link_norm = normalize_path(link_path);
    let linked_norm = normalize_path(linked_path);

    // Resolve the target inode first.
    let (target_ino, target_inode) = match get_file_inode(fs, block_dev, &linked_norm) {
        Ok(Some(v)) => v,
        Ok(None) => return Err(Ext4Error::not_found()),
        Err(e) => return Err(e),
    };

    // Hard-linking directories is rejected.
    if target_inode.is_dir() {
        return Err(Ext4Error::permission_denied());
    }

    // Destination entry must not already exist.
    if get_file_inode(fs, block_dev, &link_norm)
        .ok()
        .flatten()
        .is_some()
    {
        return Err(Ext4Error::already_exists());
    }

    // The destination parent directory must exist and be a directory.
    let (parent_path, child_name) = if let Some(pos) = link_norm.rfind('/') {
        let parent = if pos == 0 {
            "/".to_string()
        } else {
            link_norm[..pos].to_string()
        };
        let child = link_norm[pos + 1..].to_string();
        (parent, child)
    } else {
        ("/".to_string(), link_norm)
    };
    let (parent_ino, mut parent_inode) = match get_inode_with_num(fs, block_dev, &parent_path)
        .ok()
        .flatten()
    {
        Some(v) => v,
        None => return Err(Ext4Error::not_found()),
    };
    if !parent_inode.is_dir() {
        return Err(Ext4Error::not_dir());
    }

    // Reuse the source entry's file type when possible so the new directory
    // entry matches existing metadata.
    let (linked_parent_path, linked_child_name) = if let Some(pos) = linked_norm.rfind('/') {
        let parent = if pos == 0 {
            "/".to_string()
        } else {
            linked_norm[..pos].to_string()
        };
        let child = linked_norm[pos + 1..].to_string();
        (parent, child)
    } else {
        ("/".to_string(), linked_norm.clone())
    };

    let mut copied_ft: Option<u8> = None;
    if let Some((_lpino, mut lp_inode)) = get_inode_with_num(fs, block_dev, &linked_parent_path)
        .ok()
        .flatten()
        && let Ok(blocks) = resolve_inode_blocks(fs, block_dev, &mut lp_inode)
    {
        for &phys in blocks.values() {
            let cached = match fs.datablock_cache.get_or_load(block_dev, phys) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let data = &cached.data[..BLOCK_SIZE];
            let iter = DirEntryIterator::new(data);
            for (entry, _) in iter {
                if entry.inode == 0 {
                    continue;
                }
                if entry.name == linked_child_name.as_bytes() {
                    copied_ft = Some(entry.file_type);
                    break;
                }
            }
            if copied_ft.is_some() {
                break;
            }
        }
    }

    let file_type = copied_ft.unwrap_or_else(|| {
        if target_inode.is_file() {
            Ext4DirEntry2::EXT4_FT_REG_FILE
        } else if target_inode.is_symlink() {
            Ext4DirEntry2::EXT4_FT_SYMLINK
        } else {
            Ext4DirEntry2::EXT4_FT_UNKNOWN
        }
    });

    // `insert_dir_entry` recalculates name length and record length for the new
    // entry automatically.
    if insert_dir_entry(
        fs,
        block_dev,
        parent_ino,
        &mut parent_inode,
        target_ino,
        &child_name,
        file_type,
    )
    .is_err()
    {
        return Err(Ext4Error::corrupted());
    }

    // Update the target link count and roll back the inserted entry on failure.
    let new_links = target_inode.i_links_count.saturating_add(1);
    if fs
        .set_inode_links_count(block_dev, target_ino, new_links)
        .is_err()
    {
        let _ = remove_inodeentry_from_parentdir(fs, block_dev, &parent_path, &child_name);
        return Err(Ext4Error::corrupted());
    }

    Ok(())
}
