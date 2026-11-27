//! 只读虚拟文件：每次 open 捕获一次快照；dup/fork 共享快照和读偏移。
//! 覆盖 /proc/{cpuinfo,meminfo,mounts}、进程信息与基本 /dev 设备节点。
use crate::syscall::Errno;
use alloc::string::String;
use core::fmt::Write;

pub(super) const MEMINFO: u32 = u32::MAX - 1;
pub(super) const DIR: u32 = u32::MAX;
/// /dev/null 的虚拟 inode：读返回 EOF，写全部接收并丢弃（null(4)）
pub(super) const DEVNULL: u32 = u32::MAX - 2;
/// /dev/zero 的虚拟 inode。
pub(super) const DEVZERO: u32 = u32::MAX - 8;
/// /dev/urandom 与 /dev/random 的虚拟 inode。
pub(super) const DEVURANDOM: u32 = u32::MAX - 9;
pub(super) const DEVRANDOM: u32 = u32::MAX - 10;
pub(super) const CPUINFO: u32 = u32::MAX - 11;

pub(super) fn null_metadata() -> super::Metadata {
    super::Metadata {
        ino: u64::from(DEVNULL),
        rdev: (1 << 8) | 3,
        mode: 0o020666,
        links: 1,
        block_size: 4096,
        ..Default::default()
    }
}

pub(super) fn zero_metadata() -> super::Metadata {
    super::Metadata {
        ino: u64::from(DEVZERO),
        rdev: (1 << 8) | 5,
        mode: 0o020666,
        links: 1,
        block_size: 4096,
        ..Default::default()
    }
}

pub(super) fn random_metadata(urandom: bool) -> super::Metadata {
    super::Metadata {
        ino: u64::from(if urandom { DEVURANDOM } else { DEVRANDOM }),
        rdev: (1 << 8) | if urandom { 9 } else { 8 },
        mode: 0o020666,
        links: 1,
        block_size: 4096,
        ..Default::default()
    }
}
/// /dev 目录
pub(super) const DEVDIR: u32 = u32::MAX - 3;
/// /dev/misc/rtc（RTC 查询设备，hwclock 使用）
pub(super) const RTC: u32 = u32::MAX - 5;
/// /dev 下的块设备节点（mknodat 注册，如 /dev/vda2）
pub(super) const DEVBLK: u32 = u32::MAX - 7;
/// /dev/misc 目录
pub(super) const MISC_DIR: u32 = u32::MAX - 6;
/// /proc/mounts（df 等读取，格式见 mounts(5)）
pub(super) const MOUNTS: u32 = u32::MAX - 4;

/// /proc/<pid> 目录的 inode：pid 目录与其下文件按 16 偏移分段，
/// 避开 FAT 的最高位与 u32::MAX 附近的固定节点。
pub fn pid_dir_ino(pid: u32) -> u32 {
    0x4000_0000u32.wrapping_add(pid.wrapping_mul(16))
}

/// pid 派生 inode 的反解：Some((pid, file))，file 0=目录 1=stat 2=cmdline
/// 3=status
pub fn pid_ino_parts(ino: u32) -> Option<(u32, u8)> {
    if !(0x4000_0000..0x7FFF_0000).contains(&ino) {
        return None;
    }
    let rel = ino - 0x4000_0000;
    let pid = rel / 16;
    let file = rel % 16;
    if pid == 0 || file > 3 {
        return None;
    }
    Some((pid, file as u8))
}

pub(super) fn meminfo() -> Result<String, Errno> {
    let (total, free) = crate::mm::frame::stats();
    let cached = super::cache::cached_kib();
    let mut out = String::new();
    // 9 个短字段及最多四个 20 位十进制数；写入不会另行扩容。
    out.try_reserve(384).map_err(|_| Errno::NoMem)?;
    write!(
        out,
        "MemTotal: {} kB\nMemFree: {} kB\nMemAvailable: {} kB\nBuffers: 0 kB\nCached: {} kB\nSReclaimable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        total * 4, free * 4, free * 4, cached
    )
    .map_err(|_| Errno::Io)?;
    Ok(out)
}

/// 生成当前内核可用的逻辑处理器记录。
pub(super) fn cpuinfo() -> Result<String, Errno> {
    let mut out = String::new();
    out.try_reserve(64).map_err(|_| Errno::NoMem)?;
    writeln!(
        out,
        "processor\t: 0\narchitecture\t: {}",
        crate::config::ARCH_NAME
    )
    .map_err(|_| Errno::Io)?;
    Ok(out)
}

/// 生成根卷和辅助卷的挂载记录快照。
pub(super) fn mounts() -> Result<String, Errno> {
    let mut out = String::new();
    out.try_reserve(128).map_err(|_| Errno::NoMem)?;
    let root_disk = super::ext4::root_disk_name();
    let mode = if cfg!(feature = "rsext4-readonly") {
        "ro"
    } else {
        "rw"
    };
    let _ = writeln!(out, "/dev/{} / ext4 {} 0 0", root_disk, mode);
    for (source, target) in super::fat::mount_list() {
        let _ = writeln!(out, "{} {} vfat rw 0 0", source, target);
    }
    for (source, target, readonly) in super::ext2_mount::mount_list()? {
        let mode = if readonly { "ro" } else { "rw" };
        out.try_reserve(source.len() + target.len() + 16)
            .map_err(|_| Errno::NoMem)?;
        writeln!(out, "{} {} ext2 {} 0 0", source, target, mode).map_err(|_| Errno::Io)?;
    }
    Ok(out)
}

/// /proc/<pid>/stat 快照（proc(5) 编号 1..=53 全字段；busybox ps 按下标解析
/// utime/ starttime 等字段，缺字段会导致进程行被跳过）。状态、父 pid、进程组与
/// 会话取自 Task 快照表；CPU 记账与内存尺寸字段置 0（未导出，登记契约欠账）。
pub(super) fn pid_stat(pid: u32) -> Result<String, Errno> {
    let Some((name, state, ppid, _)) = crate::task::proc_table_lookup(pid) else {
        return Err(Errno::NoEntry);
    };
    let Some((pgid, sid, _)) = crate::task::proc_table_identity(pid) else {
        return Err(Errno::NoEntry);
    };
    let mut out = String::new();
    out.try_reserve(256).map_err(|_| Errno::NoMem)?;
    let _ = write!(
        out,
        "{} ({}) {} {} {} {}",
        pid, name, state as char, ppid, pgid, sid
    );
    // 字段 7..53 全部补零；comm 含空格的场景按 proc(5) 无需转义（任务名
    // 来自登记的 &'static str，不含括号）
    for _ in 7..=53 {
        out.push_str(" 0");
    }
    out.push('\n');
    Ok(out)
}

/// /proc/<pid>/status 快照（proc(5) 关键行；Uid 与 Gid 取进程凭证）。
pub(super) fn pid_status(pid: u32) -> Result<String, Errno> {
    let Some((name, state, ppid, _)) = crate::task::proc_table_lookup(pid) else {
        return Err(Errno::NoEntry);
    };
    let Some((_, _, ids)) = crate::task::proc_table_identity(pid) else {
        return Err(Errno::NoEntry);
    };
    let mut out = String::new();
    out.try_reserve(192).map_err(|_| Errno::NoMem)?;
    let state_text = match state {
        b'R' => "R (running)",
        b'Z' => "Z (zombie)",
        _ => "S (sleeping)",
    };
    let _ = write!(
        out,
        "Name:\t{}\nState:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\n",
        name, state_text, pid, ppid, ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7]
    );
    Ok(out)
}

/// /proc/<pid>/cmdline 快照：execve 提交后的真实 argv（NUL 分隔、末尾
/// NUL）；未 exec 过的内核/内嵌任务以登记名近似（契约偏差表）。
pub(super) fn pid_cmdline(pid: u32) -> Result<String, Errno> {
    let Some((name, .., cmdline)) = crate::task::proc_table_lookup(pid) else {
        return Err(Errno::NoEntry);
    };
    let mut out = String::new();
    match cmdline {
        Some(argv) => {
            out.try_reserve(argv.len()).map_err(|_| Errno::NoMem)?;
            out.push_str(&String::from_utf8_lossy(&argv));
        }
        None => {
            out.try_reserve(name.len() + 1).map_err(|_| Errno::NoMem)?;
            out.push_str(name);
            out.push('\0');
        }
    }
    Ok(out)
}

pub(super) fn metadata() -> Result<super::Metadata, Errno> {
    let size = meminfo()?.len() as u64;
    Ok(super::Metadata {
        ino: MEMINFO as u64,
        mode: 0o100444,
        links: 1,
        size,
        block_size: 4096,
        ..Default::default()
    })
}
