//! OuroOS patch: bounded directory-block reads for directory iteration.

use crate::{
    blockdev::{BlockDevice, Jbd2Dev},
    bmalloc::InodeNumber,
    config::BLOCK_SIZE,
    error::{Ext4Error, Ext4Result},
    ext4::Ext4FileSystem,
    loopfile::resolve_inode_block,
};

/// Copies directory bytes up to the end of the current block or directory.
/// Returns zero at EOF and an error for non-directories or missing blocks.
pub fn read_dir_at<B: BlockDevice>(
    device: &mut Jbd2Dev<B>,
    fs: &mut Ext4FileSystem,
    ino: InodeNumber,
    offset: usize,
    dst: &mut [u8],
) -> Ext4Result<usize> {
    let mut inode = fs.get_inode_by_num(device, ino)?;
    if !inode.is_dir() {
        return Err(Ext4Error::not_dir());
    }
    if dst.is_empty() || offset as u64 >= inode.size() {
        return Ok(0);
    }
    let logical = u32::try_from(offset / BLOCK_SIZE).map_err(|_| Ext4Error::invalid_input())?;
    let block =
        resolve_inode_block(device, &mut inode, logical)?.ok_or_else(Ext4Error::corrupted)?;
    let start = offset % BLOCK_SIZE;
    let len = dst.len().min(BLOCK_SIZE - start);
    let len = (len as u64).min(inode.size() - offset as u64) as usize;
    let cached = fs.datablock_cache.get_or_load(device, block)?;
    dst[..len].copy_from_slice(&cached.data[start..start + len]);
    Ok(len)
}
