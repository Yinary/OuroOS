//! 同步块设备接口。上层以字节寻址，设备自行处理底层块对齐。

/// 块设备操作错误。
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BlockError {
    OutOfBounds,
    ReadOnly,
    Io,
}

/// 有界设备访问。成功表示整个请求完成，失败时缓冲区或设备可能部分更新。
/// 返回前设备须停止访问调用方的切片。
pub(crate) trait BlockDevice {
    /// 设备容量，单位为字节。
    fn capacity(&self) -> usize;
    /// 从字节偏移读取数据，越界或设备故障时返回错误。
    fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<(), BlockError>;
    /// 从字节偏移写入数据，越界、只读或设备故障时返回错误。
    fn write_at(&mut self, offset: usize, src: &[u8]) -> Result<(), BlockError>;
    /// 同步此前写入，设备无法兑现同步契约时返回错误。
    fn flush(&mut self) -> Result<(), BlockError>;
}

/// 用借用的内存模拟设备，供启动自检使用。
pub(crate) struct RamBlock<'a> {
    bytes: &'a mut [u8],
    read_only: bool,
}

impl<'a> RamBlock<'a> {
    /// 以给定缓冲区作为设备内容，可禁止写入。
    pub(crate) fn new(bytes: &'a mut [u8], read_only: bool) -> Self {
        Self { bytes, read_only }
    }
}

fn span(offset: usize, len: usize) -> Result<core::ops::Range<usize>, BlockError> {
    Ok(offset..offset.checked_add(len).ok_or(BlockError::OutOfBounds)?)
}

impl BlockDevice for RamBlock<'_> {
    fn capacity(&self) -> usize {
        self.bytes.len()
    }

    fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<(), BlockError> {
        let src = self
            .bytes
            .get(span(offset, dst.len())?)
            .ok_or(BlockError::OutOfBounds)?;
        dst.copy_from_slice(src);
        Ok(())
    }

    fn write_at(&mut self, offset: usize, src: &[u8]) -> Result<(), BlockError> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        let dst = self
            .bytes
            .get_mut(span(offset, src.len())?)
            .ok_or(BlockError::OutOfBounds)?;
        dst.copy_from_slice(src);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        // RAM 后端没有待写回的缓冲区。
        Ok(())
    }
}
