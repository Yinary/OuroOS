//! VirtIO 块设备与物理 DMA 适配；两个平台的总线枚举集中在此。
//! 使用 virtio-drivers 0.7.5（MIT），来源见 docs/third-party.md。
use crate::mm::frame;
use alloc::vec::Vec;
use core::ptr::NonNull;
use polyhal::{consts::VIRT_ADDR_START, PhysAddr};
use spin::Mutex;
use virtio_drivers::{device::blk::VirtIOBlk, BufferDirection, Hal};

// 平台总线不同，仅驱动边界选择传输类型。
#[cfg(target_arch = "riscv64")]
type Bus = virtio_drivers::transport::mmio::MmioTransport;
#[cfg(target_arch = "loongarch64")]
type Bus = virtio_drivers::transport::pci::PciTransport;
type Disk = VirtIOBlk<Dma, Bus>;
static DISKS: Mutex<Vec<Disk>> = Mutex::new(Vec::new());

/// 块层错误：设备不存在、范围非法、内存不足或设备 I/O 失败。
#[derive(Debug, Clone, Copy)]
pub enum Error {
    NoDevice,
    Range,
    NoMemory,
    Io,
}

struct Dma;
// SAFETY: DMA 页来自连续物理帧；share 仅接收驱动持有的内核直映缓冲区；
// 同步请求完成前缓冲区保持存活，QEMU virt 平台 DMA 与 CPU 缓存一致。
unsafe impl Hal for Dma {
    fn dma_alloc(pages: usize, _: BufferDirection) -> (usize, NonNull<u8>) {
        match frame::frame_alloc(pages) {
            Ok(pa) => {
                pa.clear_len(pages * 4096);
                // SAFETY: 有效帧的高半区别名永不为零。
                (pa.raw(), unsafe {
                    NonNull::new_unchecked((pa.raw() | VIRT_ADDR_START) as *mut u8)
                })
            }
            Err(_) => (0, NonNull::dangling()),
        }
    }
    unsafe fn dma_dealloc(pa: usize, _: NonNull<u8>, pages: usize) -> i32 {
        for i in 0..pages {
            // SAFETY: Hal 调用者保证设备已放弃该分配，逐页归还且只调用一次。
            unsafe {
                frame::frame_dealloc(PhysAddr::new(pa + i * 4096));
            }
        }
        0
    }
    unsafe fn mmio_phys_to_virt(pa: usize, _: usize) -> NonNull<u8> {
        // SAFETY: 总线层只传入已映射的 MMIO 区域。
        unsafe { NonNull::new_unchecked(mmio_address(pa) as *mut u8) }
    }
    unsafe fn share(buffer: NonNull<[u8]>, _: BufferDirection) -> usize {
        buffer.as_ptr() as *mut u8 as usize & !VIRT_ADDR_START
    }
    unsafe fn unshare(_: usize, _: NonNull<[u8]>, _: BufferDirection) {}
}

fn mmio_address(pa: usize) -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        pa | VIRT_ADDR_START
    }
    // LoongArch DMW0 是非缓存设备窗口，DMW1 用于普通 RAM。
    #[cfg(target_arch = "loongarch64")]
    {
        pa | 0x8000_0000_0000_0000
    }
}

fn attach(bus: Bus) -> Result<(), Error> {
    let disk = VirtIOBlk::<Dma, _>::new(bus).map_err(|_| Error::Io)?;
    log::info!("virtio block: {} sectors", disk.capacity());
    let mut disks = DISKS.lock();
    disks.try_reserve(1).map_err(|_| Error::NoMemory)?;
    disks.push(disk);
    Ok(())
}

/// 在启动主核枚举块设备，无设备时保留内嵌程序运行能力。
pub fn init() -> Result<(), Error> {
    #[cfg(target_arch = "riscv64")]
    {
        use virtio_drivers::transport::{mmio::VirtIOHeader, DeviceType, Transport};
        for pa in (0x1000_1000..=0x1000_8000).step_by(0x1000) {
            let ptr = mmio_address(pa) as *mut VirtIOHeader;
            // SAFETY: QEMU virt 的八个固定 MMIO 插槽已由 kernel_pt 映射。
            let bus = unsafe { Bus::new(NonNull::new_unchecked(ptr)) };
            if let Ok(bus) = bus {
                if bus.device_type() == DeviceType::Block {
                    attach(bus)?;
                }
            }
        }
    }
    #[cfg(target_arch = "loongarch64")]
    {
        use virtio_drivers::transport::{
            pci::{
                bus::{Cam, Command, PciRoot},
                virtio_device_type,
            },
            DeviceType,
        };
        // SAFETY: QEMU virt ECAM 通过 DMW0 可访问；仅枚举 bus 0，地址在 128 MiB 窗口内。
        let mut root = unsafe { PciRoot::new(mmio_address(0x2000_0000) as *mut u8, Cam::Ecam) };
        let mut next = 0x4000_0000u64;
        for (bdf, info) in root.enumerate_bus(0) {
            if virtio_device_type(&info) != Some(DeviceType::Block) {
                continue;
            }
            root.set_command(bdf, Command::empty());
            let mut index = 0;
            while index < 6 {
                let bar = root.bar_info(bdf, index).map_err(|_| Error::Io)?;
                if let Some((_, size)) = bar.memory_address_size() {
                    if size != 0 {
                        let size = u64::from(size);
                        next = next.checked_add(size - 1).ok_or(Error::Range)? & !(size - 1);
                        let end = next.checked_add(size).ok_or(Error::Range)?;
                        if end > 0x8000_0000 {
                            return Err(Error::Range);
                        }
                        if bar.takes_two_entries() {
                            root.set_bar_64(bdf, index, next);
                        } else {
                            root.set_bar_32(bdf, index, next as u32);
                        }
                        next = end;
                    }
                }
                index += if bar.takes_two_entries() { 2 } else { 1 };
            }
            root.set_command(
                bdf,
                Command::MEMORY_SPACE | Command::BUS_MASTER | Command::INTERRUPT_DISABLE,
            );
            attach(Bus::new::<Dma>(&mut root, bdf).map_err(|_| Error::Io)?)?;
        }
    }
    Ok(())
}

/// 返回设备扇区数；扇区固定为 512 字节。
pub fn capacity(id: usize) -> Result<u64, Error> {
    DISKS
        .lock()
        .get(id)
        .map(|d| d.capacity())
        .ok_or(Error::NoDevice)
}

/// 同步读连续扇区到内核缓冲区，用户地址不得直接传入。
pub fn read(id: usize, sector: usize, data: &mut [u8]) -> Result<(), Error> {
    let mut disks = DISKS.lock();
    let disk = disks.get_mut(id).ok_or(Error::NoDevice)?;
    bounds(disk, sector, data.len())?;
    if data.is_empty() {
        return Ok(());
    }
    disk.read_blocks(sector, data).map_err(|_| Error::Io)
}

/// 同步写连续扇区；返回前设备已结束对缓冲区的访问。
pub fn write(id: usize, sector: usize, data: &[u8]) -> Result<(), Error> {
    let mut disks = DISKS.lock();
    let disk = disks.get_mut(id).ok_or(Error::NoDevice)?;
    bounds(disk, sector, data.len())?;
    if data.is_empty() {
        return Ok(());
    }
    disk.write_blocks(sector, data).map_err(|_| Error::Io)
}

/// 将块设备已完成的写请求同步到后端。
pub fn flush(id: usize) -> Result<(), Error> {
    DISKS
        .lock()
        .get_mut(id)
        .ok_or(Error::NoDevice)?
        .flush()
        .map_err(|_| Error::Io)
}

fn bounds(disk: &Disk, sector: usize, len: usize) -> Result<(), Error> {
    if len % 512 != 0 || sector.checked_add(len / 512).ok_or(Error::Range)? as u64 > disk.capacity()
    {
        return Err(Error::Range);
    }
    Ok(())
}
/// 按字节读设备，完整且对齐的扇区范围一次提交。
pub fn read_bytes(id: usize, offset: usize, out: &mut [u8]) -> Result<(), Error> {
    let end = offset.checked_add(out.len()).ok_or(Error::Range)?;
    if end as u64 > capacity(id)?.checked_mul(512).ok_or(Error::Range)? {
        return Err(Error::Range);
    }
    if offset % 512 == 0 && out.len() % 512 == 0 {
        return read(id, offset / 512, out);
    }
    let mut done = 0;
    while done < out.len() {
        let pos = offset + done;
        let mut sector = [0; 512];
        read(id, pos / 512, &mut sector)?;
        let begin = pos % 512;
        let count = (512 - begin).min(out.len() - done);
        out[done..done + count].copy_from_slice(&sector[begin..begin + count]);
        done += count;
    }
    Ok(())
}

/// 按字节写设备，完整且对齐的扇区范围一次提交。
/// 不完整扇区先读后改，调用方须串行化重叠写入。
pub fn write_bytes(id: usize, offset: usize, data: &[u8]) -> Result<(), Error> {
    let end = offset.checked_add(data.len()).ok_or(Error::Range)?;
    if end as u64 > capacity(id)?.checked_mul(512).ok_or(Error::Range)? {
        return Err(Error::Range);
    }
    if offset % 512 == 0 && data.len() % 512 == 0 {
        return write(id, offset / 512, data);
    }
    let mut done = 0;
    while done < data.len() {
        let pos = offset + done;
        let begin = pos % 512;
        let count = (512 - begin).min(data.len() - done);
        let mut sector = [0; 512];
        if count != 512 {
            read(id, pos / 512, &mut sector)?;
        }
        sector[begin..begin + count].copy_from_slice(&data[done..done + count]);
        write(id, pos / 512, &sector)?;
        done += count;
    }
    Ok(())
}
/// MBR 主分区的字节范围；编号为 1..=4，整盘用 0。
pub fn partition(id: usize, number: usize) -> Result<(usize, usize), Error> {
    let total = usize::try_from(capacity(id)?)
        .map_err(|_| Error::Range)?
        .checked_mul(512)
        .ok_or(Error::Range)?;
    if number == 0 {
        return Ok((0, total));
    }
    if !(1..=4).contains(&number) {
        return Err(Error::Range);
    }
    let mut mbr = [0; 512];
    read(id, 0, &mut mbr)?;
    if mbr[510..] != [0x55, 0xaa] {
        return Err(Error::Range);
    }
    let i = 446 + (number - 1) * 16;
    let start =
        u32::from_le_bytes([mbr[i + 8], mbr[i + 9], mbr[i + 10], mbr[i + 11]]) as usize * 512;
    let len =
        u32::from_le_bytes([mbr[i + 12], mbr[i + 13], mbr[i + 14], mbr[i + 15]]) as usize * 512;
    if len == 0 || start.checked_add(len).ok_or(Error::Range)? > total {
        return Err(Error::Range);
    }
    Ok((start, len))
}
