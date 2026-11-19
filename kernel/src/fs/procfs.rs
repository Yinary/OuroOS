//! MM 的只读虚拟文件，每次 open 捕获一次统计；dup/fork 共享快照和读偏移。
use crate::syscall::Errno;
use alloc::string::String;
use core::fmt::Write;
pub(super) const MEMINFO: u32 = u32::MAX - 1;
pub(super) const DIR: u32 = u32::MAX;
pub(super) fn meminfo() -> Result<String, Errno> {
    let s = crate::mm::frame::memory_snapshot();
    let cached = super::cache::cached_kib();
    let mut out = String::new();
    // 9 个短字段及最多四个 20 位十进制数；写入不会另行扩容。
    out.try_reserve(384).map_err(|_| Errno::NoMem)?;
    write!(out,"MemTotal: {} kB\nMemFree: {} kB\nMemAvailable: {} kB\nBuffers: 0 kB\nCached: {} kB\nSReclaimable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",s.total_kib,s.free_kib,s.free_kib,cached).map_err(|_|Errno::Io)?;
    Ok(out)
}
