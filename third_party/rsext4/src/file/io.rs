//! 文件数据读写与截断，维护 inode 长度、块映射和访问时间。
use super::*;

const MAX_RUN_IO_BYTES: usize = 1024 * 1024;

pub fn truncate<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    path: &str,
    truncate_size: u64,
) -> Ext4Result<()> {
    let norm_path = normalize_path(path);

    // Resolve the target inode once, then delegate to the inode-based helper.
    let (inode_num, _inode) = match get_inode_with_num(fs, device, &norm_path).ok().flatten() {
        Some(v) => v,
        None => return Err(Ext4Error::not_found()),
    };

    truncate_inode(device, fs, inode_num, truncate_size)
}

// OuroOS patch: truncate-ranges (see README.md).
/// 按 inode 调整普通文件长度；extent 文件稀疏扩展，缩短时回收数据及索引块。
pub fn truncate_inode<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    inode_num: InodeNumber,
    length: u64,
) -> Ext4Result<()> {
    if fs.readonly {
        return Err(Ext4Error::read_only());
    }
    let mut inode = fs.get_inode_by_num(device, inode_num)?;
    if !inode.is_file() {
        return Err(if inode.is_dir() {
            Ext4Error::is_dir()
        } else {
            Ext4Error::invalid_input()
        });
    }
    let new_blocks = length.div_ceil(BLOCK_SIZE as u64);
    if new_blocks > u32::MAX as u64 {
        return Err(Ext4Error::new(Errno::EFBIG));
    }
    let old_size = inode.size();
    if inode.file_acl() != 0 || inode.i_flags & Ext4Inode::EXT4_HUGE_FILE_FL != 0 {
        return Err(Ext4Error::unsupported());
    }
    let extents = inode.have_extend_header_and_use_extend();
    if !extents
        && (length != 0
            || inode.i_flags & Ext4Inode::EXT4_EXTENTS_FL != 0
            || inode.i_block[12..].iter().any(|&b| b != 0))
    {
        return Err(Ext4Error::unsupported());
    }
    // 时间与权限更新先在副本上完成，避免时间源失败时已经释放文件数据。
    fs.apply_loaded_inode_metadata(
        device,
        &mut inode,
        Ext4InodeMetadataUpdate::truncate_access(),
    )?;
    if extents {
        let shrinking = length <= old_size;
        let zero_start = length.min(old_size);
        let zero_end = if shrinking {
            new_blocks * BLOCK_SIZE as u64
        } else {
            length
        };
        if zero_start < zero_end {
            let runs = ExtentTree::new(&mut inode).initialized_runs_in_range(
                device,
                (zero_start / BLOCK_SIZE as u64) as u32,
                ((zero_end - 1) / BLOCK_SIZE as u64) as u32,
            )?;
            for run in runs {
                for i in 0..run.len {
                    let base = (u64::from(run.logical_start) + u64::from(i)) * BLOCK_SIZE as u64;
                    let begin = zero_start.saturating_sub(base) as usize;
                    let end = (zero_end - base).min(BLOCK_SIZE as u64) as usize;
                    fs.datablock_cache.modify(
                        device,
                        run.physical_start.checked_add(i)?,
                        |data| data[begin..end].fill(0),
                    )?;
                }
            }
        }
        if shrinking {
            let runs = ExtentTree::new(&mut inode).allocated_runs_in_range(
                device,
                new_blocks as u32,
                u32::MAX,
            )?;
            for run in runs {
                let mut removed = 0;
                while removed < run.len {
                    let count = (run.len - removed).min(Ext4Extent::EXT_INIT_MAX_LEN as u32);
                    ExtentTree::with_checksum(&mut inode, &fs.superblock, inode_num)
                        .remove_extent(
                            fs,
                            Ext4Extent::new(run.logical_start + removed, 0, count as u16),
                            device,
                        )?;
                    for i in removed..removed + count {
                        fs.datablock_cache
                            .invalidate(run.physical_start.checked_add(i)?);
                    }
                    removed += count;
                }
            }
            let mut tree = ExtentTree::with_checksum(&mut inode, &fs.superblock, inode_num);
            let data_blocks: u64 = tree
                .allocated_runs_in_range(device, 0, u32::MAX)?
                .iter()
                .map(|r| u64::from(r.len))
                .sum();
            let index_blocks = tree.external_node_blocks(device)?.len() as u64;
            let sectors = (data_blocks + index_blocks) * (BLOCK_SIZE as u64 / 512);
            inode.i_blocks_lo = sectors as u32;
            inode.l_i_blocks_high = (sectors >> 32) as u16;
        }
    } else {
        // 旧式块映射仅保留原有的直接块清零能力。
        for block in &mut inode.i_block[..12] {
            if *block != 0 {
                let phys = AbsoluteBN::from(*block);
                fs.free_block(device, phys)?;
                fs.datablock_cache.invalidate(phys);
                *block = 0;
            }
        }
        inode.i_blocks_lo = 0;
        inode.l_i_blocks_high = 0;
    }
    inode.i_size_lo = length as u32;
    inode.i_size_high = (length >> 32) as u32;
    fs.modify_inode(device, inode_num, |stored| *stored = inode)
}

fn read_symlink_target<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    inode: &mut Ext4Inode,
) -> Ext4Result<Vec<u8>> {
    let size = inode.size() as usize;
    if size == 0 {
        return Ok(Vec::new());
    }

    // Fast symlinks consume no data blocks. Length alone is insufficient:
    // e2fsprogs stores a 60-byte target in a regular data block.
    if size <= 60 && inode.blocks_count() == 0 {
        let mut raw = [0u8; 60];
        for (i, word) in inode.i_block.iter().take(15).enumerate() {
            raw[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        return Ok(raw[..size].to_vec());
    }

    let block_bytes = BLOCK_SIZE;
    let total_blocks = size.div_ceil(block_bytes);
    let mut buf = Vec::with_capacity(size);

    if inode.have_extend_header_and_use_extend() {
        let blocks = resolve_inode_blocks(fs, device, inode)?;
        for &phys in blocks.values() {
            let cached = fs.datablock_cache.get_or_load(device, phys)?;
            let data = &cached.data[..block_bytes];
            buf.extend_from_slice(data);
            if buf.len() >= size {
                break;
            }
        }
    } else {
        for lbn in 0..total_blocks {
            let phys = match resolve_inode_block(device, inode, lbn as u32)? {
                Some(b) => b,
                None => break,
            };
            let cached = fs.datablock_cache.get_or_load(device, phys)?;
            let data = &cached.data[..block_bytes];
            buf.extend_from_slice(data);
        }
    }

    buf.truncate(size);

    Ok(buf)
}

fn resolve_symlink_path(current_path: &str, target: &str) -> String {
    if target.starts_with('/') {
        return normalize_path(target);
    }
    let parent = match current_path.rfind('/') {
        Some(0) | None => "/",
        Some(pos) => &current_path[..pos],
    };
    let mut combined = String::new();
    if parent == "/" {
        combined.push('/');
        combined.push_str(target);
    } else {
        combined.push_str(parent);
        combined.push('/');
        combined.push_str(target);
    }
    normalize_path(&combined)
}

fn read_file_follow<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    path: &str,
    depth: usize,
) -> Ext4Result<Vec<u8>> {
    if depth > 8 {
        return Err(Ext4Error::invalid_input());
    }

    let (inode_num, mut inode) = match get_file_inode(fs, device, path) {
        Ok(Some((ino_num, ino))) => (ino_num, ino),
        Ok(None) => return Err(Ext4Error::not_found()),
        Err(e) => return Err(e),
    };

    if inode.is_symlink() {
        let target_bytes = read_symlink_target(device, fs, &mut inode)?;
        let target = match core::str::from_utf8(&target_bytes) {
            Ok(s) => s,
            Err(_) => return Err(Ext4Error::corrupted()),
        };
        let resolved = resolve_symlink_path(path, target);
        return read_file_follow(device, fs, &resolved, depth + 1);
    }

    if !inode.is_file() {
        error!("Entry:{path} not a file");
        return Err(if inode.is_dir() {
            Ext4Error::is_dir()
        } else {
            Ext4Error::unsupported()
        });
    }

    let size = inode.size() as usize;
    if size == 0 {
        fs.touch_inode_atime_if_needed(device, inode_num)?;
        return Ok(Vec::new());
    }

    let block_bytes = BLOCK_SIZE;
    let total_blocks = size.div_ceil(block_bytes);

    let mut buf = Vec::with_capacity(size);

    if inode.have_extend_header_and_use_extend() {
        let blocks = resolve_inode_blocks(fs, device, &mut inode)?;
        for &phys in blocks.values() {
            let cached = fs.datablock_cache.get_or_load(device, phys)?;
            let data = &cached.data[..block_bytes];
            buf.extend_from_slice(data);
            if buf.len() >= size {
                break;
            }
        }
    } else {
        for lbn in 0..total_blocks {
            let phys = match resolve_inode_block(device, &mut inode, lbn as u32)? {
                Some(b) => b,
                None => break,
            };

            let cached = fs.datablock_cache.get_or_load(device, phys)?;
            let data = &cached.data[..block_bytes];
            buf.extend_from_slice(data);
        }
    }

    buf.truncate(size);

    fs.touch_inode_atime_if_needed(device, inode_num)?;

    Ok(buf)
}

/// Read the whole file at `path`.
pub fn read_file<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    path: &str,
) -> Ext4Result<Vec<u8>> {
    read_file_follow(device, fs, path, 0)
}

pub fn read_inode_data_into<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    inode_num: InodeNumber,
    offset: u64,
    dst: &mut [u8],
) -> Ext4Result<usize> {
    if dst.is_empty() {
        return Ok(0);
    }

    let mut inode = fs.get_inode_by_num(device, inode_num)?;
    let file_size = inode.size();
    if offset >= file_size {
        return Ok(0);
    }

    if inode.is_symlink() {
        let target = read_symlink_target(device, fs, &mut inode)?;
        let start = offset as usize;
        let available = target.len().saturating_sub(start);
        let to_read = core::cmp::min(dst.len(), available);
        dst[..to_read].copy_from_slice(&target[start..start + to_read]);
        fs.touch_inode_atime_if_needed(device, inode_num)?;
        return Ok(to_read);
    }

    if !inode.is_file() {
        return Err(if inode.is_dir() {
            Ext4Error::is_dir()
        } else {
            Ext4Error::unsupported()
        });
    }

    let to_read = core::cmp::min(dst.len() as u64, file_size - offset) as usize;
    let block_bytes = BLOCK_SIZE as u64;
    let end = offset + to_read as u64;
    let start_lbn = offset / block_bytes;
    let end_lbn = (end - 1) / block_bytes;

    let mut copied = 0usize;
    if inode.have_extend_header_and_use_extend() {
        let mut tree = ExtentTree::new(&mut inode);
        let runs = tree.initialized_runs_in_range(device, start_lbn as u32, end_lbn as u32)?;
        let mut lbn = start_lbn;
        let max_run_blocks = (MAX_RUN_IO_BYTES / BLOCK_SIZE).max(1) as u32;
        for run in runs {
            let run_lbn = u64::from(run.logical_start);
            while lbn < run_lbn {
                let zero_len = copy_len_for_lbn(offset, end, lbn)?;
                dst[copied..copied + zero_len].fill(0);
                copied += zero_len;
                lbn += 1;
            }

            let mut run_block_offset = 0u32;
            while run_block_offset < run.len {
                let part_blocks = (run.len - run_block_offset).min(max_run_blocks);
                let phys = run.physical_start.checked_add(run_block_offset)?;
                let run_bytes = BLOCK_SIZE
                    .checked_mul(part_blocks as usize)
                    .ok_or_else(|| Ext4Error::from(Errno::EOVERFLOW))?;
                let mut run_buf = alloc::vec![0; run_bytes];
                fs.datablock_cache
                    .read_run(device, phys, part_blocks, &mut run_buf)?;

                for off in 0..part_blocks {
                    let current_lbn = run_lbn + u64::from(run_block_offset + off);
                    let src_len = copy_len_for_lbn(offset, end, current_lbn)?;
                    let lbn_start = current_lbn * block_bytes;
                    let src_off = (core::cmp::max(offset, lbn_start) - lbn_start) as usize;
                    let run_off = off as usize * BLOCK_SIZE + src_off;
                    dst[copied..copied + src_len]
                        .copy_from_slice(&run_buf[run_off..run_off + src_len]);
                    copied += src_len;
                    lbn = current_lbn + 1;
                }
                run_block_offset += part_blocks;
            }
        }
        while lbn <= end_lbn {
            let zero_len = copy_len_for_lbn(offset, end, lbn)?;
            dst[copied..copied + zero_len].fill(0);
            copied += zero_len;
            lbn += 1;
        }
    } else {
        let mut lbn = start_lbn;
        while lbn <= end_lbn {
            let copy_len = copy_len_for_lbn(offset, end, lbn)?;
            if let Some(phys) = resolve_inode_block(device, &mut inode, lbn as u32)? {
                let cached = fs.datablock_cache.get_or_load(device, phys)?;
                let lbn_start = lbn * block_bytes;
                let src_off = (core::cmp::max(offset, lbn_start) - lbn_start) as usize;
                dst[copied..copied + copy_len]
                    .copy_from_slice(&cached.data[src_off..src_off + copy_len]);
            } else {
                dst[copied..copied + copy_len].fill(0);
            }
            copied += copy_len;
            lbn += 1;
        }
    }

    fs.touch_inode_atime_if_needed(device, inode_num)?;
    Ok(copied)
}

fn copy_len_for_lbn(offset: u64, end: u64, lbn: u64) -> Ext4Result<usize> {
    let block_bytes = BLOCK_SIZE as u64;
    let lbn_start = lbn.saturating_mul(block_bytes);
    let lbn_end = lbn_start.saturating_add(block_bytes);
    usize::try_from(core::cmp::min(end, lbn_end) - core::cmp::max(offset, lbn_start))
        .map_err(|_| Ext4Error::from(Errno::EOVERFLOW))
}

pub fn write_file<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    path: &str,
    offset: u64,
    data: &[u8],
) -> Ext4Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    // Resolve the inode once before switching to the inode-based writer.
    let info = match get_inode_with_num(fs, device, path).ok().flatten() {
        Some(v) => v,
        None => return Err(Ext4Error::not_found()),
    };
    let (inode_num, _inode) = info;

    write_inode_data(device, fs, inode_num, offset, data)
}

fn add_inode_data_blocks(inode: &mut Ext4Inode, blocks: u64) {
    let sectors = blocks.saturating_mul(BLOCK_SIZE as u64 / 512);
    let current = inode.blocks_count();
    let next = current.saturating_add(sectors);
    inode.i_blocks_lo = (next & 0xffff_ffff) as u32;
    inode.l_i_blocks_high = ((next >> 32) & 0xffff) as u16;
}

struct WriteSlice<'a> {
    offset: u64,
    end: u64,
    data: &'a [u8],
}

fn write_inode_block_data<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    phys: AbsoluteBN,
    lbn: u64,
    write: &WriteSlice<'_>,
    newly_allocated: bool,
) -> Ext4Result<()> {
    let block_bytes = BLOCK_SIZE as u64;
    let block_start = lbn.saturating_mul(block_bytes);
    let block_end = block_start.saturating_add(block_bytes);

    let write_start = core::cmp::max(write.offset, block_start);
    let write_end = core::cmp::min(write.end, block_end);
    if write_start >= write_end {
        return Ok(());
    }

    let src_off = usize::try_from(write_start - write.offset)
        .map_err(|_| Ext4Error::from(Errno::EOVERFLOW))?;
    let dst_off = usize::try_from(write_start - block_start)
        .map_err(|_| Ext4Error::from(Errno::EOVERFLOW))?;
    let len =
        usize::try_from(write_end - write_start).map_err(|_| Ext4Error::from(Errno::EOVERFLOW))?;
    let src_end = src_off
        .checked_add(len)
        .ok_or_else(|| Ext4Error::from(Errno::EOVERFLOW))?;
    let dst_end = dst_off
        .checked_add(len)
        .ok_or_else(|| Ext4Error::from(Errno::EOVERFLOW))?;

    let full_block = dst_off == 0 && len == BLOCK_SIZE;
    if newly_allocated || full_block {
        fs.datablock_cache.modify_new(device, phys, |blk| {
            if !full_block {
                blk.fill(0);
            }
            blk[dst_off..dst_end].copy_from_slice(&write.data[src_off..src_end]);
        })?;
    } else {
        fs.datablock_cache.modify(device, phys, |blk| {
            blk[dst_off..dst_end].copy_from_slice(&write.data[src_off..src_end]);
        })?;
    }

    Ok(())
}

fn write_full_block_run<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    start_phys: AbsoluteBN,
    run_start_lbn: u64,
    offset: u64,
    data: &[u8],
    block_count: u32,
) -> Ext4Result<()> {
    let block_bytes = BLOCK_SIZE as u64;
    let src_off = usize::try_from(run_start_lbn.saturating_mul(block_bytes) - offset)
        .map_err(|_| Ext4Error::from(Errno::EOVERFLOW))?;
    let byte_len = BLOCK_SIZE
        .checked_mul(block_count as usize)
        .ok_or_else(|| Ext4Error::from(Errno::EOVERFLOW))?;
    let src_end = src_off
        .checked_add(byte_len)
        .ok_or_else(|| Ext4Error::from(Errno::EOVERFLOW))?;
    fs.datablock_cache
        .write_run(device, start_phys, block_count, &data[src_off..src_end])
}

fn existing_full_block_run(
    runs: &[ExtentRun],
    start_lbn: u64,
    offset: u64,
    end: u64,
) -> Option<(AbsoluteBN, u32)> {
    let block_bytes = BLOCK_SIZE as u64;
    let block_start = start_lbn.saturating_mul(block_bytes);
    if offset > block_start {
        return None;
    }

    let run = runs.iter().find(|run| {
        let run_start = u64::from(run.logical_start);
        let run_end = run_start + u64::from(run.len);
        start_lbn >= run_start && start_lbn < run_end
    })?;
    let run_offset = start_lbn.saturating_sub(u64::from(run.logical_start));
    let start_phys = run.physical_start.checked_add(run_offset as u32).ok()?;
    let available_blocks = run.len.saturating_sub(run_offset as u32);
    if available_blocks == 0 {
        return None;
    };
    let max_blocks_by_write = (end - block_start) / block_bytes;
    let run_len = available_blocks.min(max_blocks_by_write as u32);
    if run_len <= 1 {
        return None;
    }
    Some((start_phys, run_len))
}

fn alloc_contiguous_run_best_effort<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    requested: u32,
) -> Ext4Result<Vec<AbsoluteBN>> {
    let mut count = requested.max(1);
    loop {
        match fs.alloc_blocks(device, count) {
            Ok(blocks) => return Ok(blocks),
            Err(err) if err.code == Errno::ENOSPC && count > 1 => {
                count = count.div_ceil(2);
            }
            Err(err) => return Err(err),
        }
    }
}

pub fn write_inode_data<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    inode_num: InodeNumber,
    offset: u64,
    data: &[u8],
) -> Ext4Result<()> {
    if data.is_empty() {
        return Ok(());
    }

    let mut inode = fs.get_inode_by_num(device, inode_num)?;

    let old_size = inode.size();
    let block_bytes = BLOCK_SIZE as u64;

    // Some older or partially initialized inodes may carry the extents flag
    // without a valid embedded header. Repair that before extent operations.
    if fs.superblock.has_extents() && !inode.have_extend_header_and_use_extend() {
        inode.i_flags |= Ext4Inode::EXT4_EXTENTS_FL;
        inode.write_extend_header();
    }

    if offset > old_size {
        info!("Expand write!");
    }

    let end = offset.saturating_add(data.len() as u64);

    let start_lbn = offset / block_bytes;
    let end_lbn = (end - 1) / block_bytes;
    if end_lbn > u32::MAX as u64 {
        return Err(Ext4Error::new(Errno::EFBIG));
    }

    // Non-extent files cannot grow through sparse writes in this implementation.
    if end > old_size
        && (!fs.superblock.has_extents() || !inode.have_extend_header_and_use_extend())
    {
        return Err(Ext4Error::unsupported());
    }

    let old_blocks = if old_size == 0 {
        0
    } else {
        old_size.div_ceil(block_bytes)
    };
    let write = WriteSlice { offset, end, data };
    let use_existing_run_map = end <= old_size
        && offset.is_multiple_of(block_bytes)
        && end.is_multiple_of(block_bytes)
        && start_lbn < end_lbn
        && inode.have_extend_header_and_use_extend();
    let existing_runs = if use_existing_run_map {
        let mut tree = ExtentTree::new(&mut inode);
        Some(tree.initialized_runs_in_range(device, start_lbn as u32, end_lbn as u32)?)
    } else {
        None
    };

    let mut lbn = start_lbn;
    while lbn <= end_lbn {
        if let Some(runs) = existing_runs.as_ref()
            && let Some((start_phys, run_len)) = existing_full_block_run(runs, lbn, offset, end)
            && run_len > 1
        {
            write_full_block_run(device, fs, start_phys, lbn, offset, data, run_len)?;
            lbn += u64::from(run_len);
            continue;
        }

        let phys = if inode.have_extend_header_and_use_extend() {
            match resolve_inode_block(device, &mut inode, lbn as u32)? {
                Some(b) => b,
                None => {
                    let missing_len = if lbn >= old_blocks {
                        end_lbn - lbn + 1
                    } else {
                        1
                    };
                    let requested = core::cmp::min(missing_len, Ext4Extent::EXT_INIT_MAX_LEN as u64)
                        .min(u32::MAX as u64) as u32;
                    let blocks = alloc_contiguous_run_best_effort(device, fs, requested)?;
                    let first_phys = *blocks.first().ok_or(Ext4Error::no_space())?;
                    let run_len = u32::try_from(blocks.len())
                        .map_err(|_| Ext4Error::from(Errno::EOVERFLOW))?;

                    {
                        let mut tree =
                            ExtentTree::with_checksum(&mut inode, &fs.superblock, inode_num);
                        let ext = Ext4Extent::new(lbn as u32, first_phys.raw(), run_len as u16);
                        tree.insert_extent(fs, ext, device)?;
                    }
                    add_inode_data_blocks(&mut inode, u64::from(run_len));

                    let run_start = lbn.saturating_mul(block_bytes);
                    let run_end = run_start.saturating_add(u64::from(run_len) * block_bytes);
                    let write_start = core::cmp::max(offset, run_start);
                    let write_end = core::cmp::min(end, run_end);
                    let covers_full_run = write_start == run_start && write_end == run_end;
                    if covers_full_run {
                        write_full_block_run(device, fs, first_phys, lbn, offset, data, run_len)?;
                    } else {
                        for (idx, &block) in blocks.iter().enumerate() {
                            write_inode_block_data(
                                device,
                                fs,
                                block,
                                lbn + idx as u64,
                                &write,
                                true,
                            )?;
                        }
                    }

                    lbn += u64::from(run_len);
                    continue;
                }
            }
        } else {
            match resolve_inode_block(device, &mut inode, lbn as u32)? {
                Some(b) => b,
                None => return Err(Ext4Error::unsupported()),
            }
        };

        write_inode_block_data(device, fs, phys, lbn, &write, false)?;
        lbn += 1;
    }

    if end > old_size {
        inode.i_size_lo = (end & 0xffff_ffff) as u32;
        inode.i_size_high = (end >> 32) as u32;
    }

    fs.finalize_inode_update(
        device,
        inode_num,
        &mut inode,
        Ext4InodeMetadataUpdate::write_access(),
    )?;

    Ok(())
}
