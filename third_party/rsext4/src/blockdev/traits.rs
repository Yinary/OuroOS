//! Public block device traits.

use crate::{bmalloc::AbsoluteBN, disknode::Ext4Timestamp, error::Ext4Result};

/// Marker trait for call sites that are expected to trigger block device writes.
pub trait INeedBlockdevToWrite {}

/// Low-level block device interface used by the filesystem.
pub trait BlockDevice {
    /// Writes `count` blocks from `buffer` starting at `block_id`.
    fn write(&mut self, buffer: &[u8], block_id: AbsoluteBN, count: u32) -> Ext4Result<()>;

    /// Reads `count` blocks into `buffer` starting at `block_id`.
    fn read(&mut self, buffer: &mut [u8], block_id: AbsoluteBN, count: u32) -> Ext4Result<()>;

    // OuroOS patch: 允许底层块缓存提供块内切片直读，免除整块拷贝。
    fn read_slice(
        &mut self,
        dst: &mut [u8],
        block_id: AbsoluteBN,
        offset: usize,
    ) -> Ext4Result<()> {
        let bs = self.block_size() as usize;
        let end = offset
            .checked_add(dst.len())
            .ok_or_else(crate::error::Ext4Error::invalid_input)?;
        if end > bs {
            return Err(crate::error::Ext4Error::invalid_input());
        }
        let mut buf = alloc::vec![0u8; bs];
        self.read(&mut buf, block_id, 1)?;
        dst.copy_from_slice(&buf[offset..end]);
        Ok(())
    }

    // OuroOS patch: 允许底层块缓存提供块内切片直写，免除读-改-写二次整块拷贝。
    fn write_slice(
        &mut self,
        src: &[u8],
        block_id: AbsoluteBN,
        offset: usize,
        zero_rest: bool,
    ) -> Ext4Result<()> {
        if self.is_readonly() {
            return Err(crate::error::Ext4Error::read_only());
        }
        let bs = self.block_size() as usize;
        let end = offset
            .checked_add(src.len())
            .ok_or_else(crate::error::Ext4Error::invalid_input)?;
        if end > bs {
            return Err(crate::error::Ext4Error::invalid_input());
        }
        if offset == 0 && src.len() == bs {
            return self.write(src, block_id, 1);
        }
        let mut buf = alloc::vec![0u8; bs];
        if !zero_rest {
            self.read(&mut buf, block_id, 1)?;
        }
        buf[offset..end].copy_from_slice(src);
        self.write(&buf, block_id, 1)
    }

    /// Opens the underlying device.
    fn open(&mut self) -> Ext4Result<()>;

    /// Closes the underlying device.
    fn close(&mut self) -> Ext4Result<()>;

    /// Returns the total number of device blocks.
    fn total_blocks(&self) -> u64;

    /// Returns the device block size in bytes.
    fn block_size(&self) -> u32 {
        512
    }

    /// Flushes device state to stable storage.
    fn flush(&mut self) -> Ext4Result<()> {
        Ok(())
    }

    /// Returns whether the device is currently open.
    fn is_open(&self) -> bool {
        true
    }

    /// Returns whether the device is read-only.
    fn is_readonly(&self) -> bool {
        false
    }

    /// Returns the current timestamp used for inode metadata updates.
    fn current_time(&self) -> Ext4Result<Ext4Timestamp>;
}
