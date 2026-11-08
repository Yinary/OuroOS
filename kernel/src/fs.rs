//! 只读文件接入验证。文件位置由自检提供，后续由磁盘格式后端解析。
#![forbid(unsafe_code)]

use crate::framework::block::{BlockDevice, BlockError, RamBlock};

struct ReadOnlyFile<'a> {
    device: &'a dyn BlockDevice,
    start: usize,
    len: usize,
}

impl<'a> ReadOnlyFile<'a> {
    fn new(device: &'a dyn BlockDevice, start: usize, len: usize) -> Result<Self, BlockError> {
        if len
            > device
                .capacity()
                .checked_sub(start)
                .ok_or(BlockError::OutOfBounds)?
        {
            return Err(BlockError::OutOfBounds);
        }
        Ok(Self { device, start, len })
    }

    fn read_at(&self, offset: usize, dst: &mut [u8]) -> Result<usize, BlockError> {
        let len = dst.len().min(self.len.saturating_sub(offset));
        if len != 0 {
            self.device.read_at(self.start + offset, &mut dst[..len])?;
        }
        Ok(len)
    }
}

/// 检查 RAM 设备及只读文件边界，失败时停止启动。
pub(crate) fn self_check() {
    struct BrokenDevice;
    impl BlockDevice for BrokenDevice {
        fn capacity(&self) -> usize {
            1
        }
        fn read_at(&self, _: usize, _: &mut [u8]) -> Result<(), BlockError> {
            Err(BlockError::Io)
        }
        fn write_at(&mut self, _: usize, _: &[u8]) -> Result<(), BlockError> {
            Err(BlockError::Io)
        }
        fn flush(&mut self) -> Result<(), BlockError> {
            Err(BlockError::Io)
        }
    }

    let mut image = *b".hello.";
    let mut device = RamBlock::new(&mut image, false);
    assert_eq!(device.write_at(1, b"H"), Ok(()));
    assert_eq!(device.flush(), Ok(()));
    let mut buf = [0; 8];
    assert_eq!(
        device.read_at(usize::MAX, &mut buf),
        Err(BlockError::OutOfBounds)
    );

    let mut device = RamBlock::new(&mut image, true);
    assert_eq!(device.write_at(1, b"x"), Err(BlockError::ReadOnly));
    assert!(ReadOnlyFile::new(&device, 1, usize::MAX).is_err());
    let file = ReadOnlyFile::new(&device, 1, 5).unwrap();
    assert_eq!(file.read_at(0, &mut buf), Ok(5));
    assert_eq!(&buf[..6], b"Hello\0");
    assert_eq!(file.read_at(usize::MAX, &mut buf), Ok(0));
    let broken = ReadOnlyFile::new(&BrokenDevice, 0, 1).unwrap();
    assert_eq!(broken.read_at(0, &mut buf), Err(BlockError::Io));
    log::info!("[fs] RAM block self-check passed");
}
