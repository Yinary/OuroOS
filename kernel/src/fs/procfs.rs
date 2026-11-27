//! 只读虚拟文件：每次 open 捕获一次快照；dup/fork 共享快照和读偏移。
//! 覆盖 /proc/meminfo、/proc/mounts、/proc/<pid>/{stat,cmdline} 与基本 /dev 设备节点。
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
/// /proc/sys 目录
pub(super) const SYS_DIR: u32 = u32::MAX - 11;
/// /proc/sys/kernel 目录
pub(super) const SYS_KERNEL_DIR: u32 = u32::MAX - 12;
/// /proc/sys/kernel/pid_max
pub(super) const PID_MAX: u32 = u32::MAX - 13;
/// /proc/version
pub(super) const VERSION: u32 = u32::MAX - 14;
/// /proc/self 目录
pub(super) const SELF_DIR: u32 = u32::MAX - 15;
/// /proc/self/maps
pub(super) const SELF_MAPS: u32 = u32::MAX - 16;
/// /proc/self/fd 目录
pub(super) const SELF_FD_DIR: u32 = u32::MAX - 17;
/// /proc/sys/kernel/tainted 文件
pub(super) const TAINTED: u32 = u32::MAX - 18;
/// /proc/sys/fs 目录
pub(super) const SYS_FS_DIR: u32 = u32::MAX - 19;
/// /proc/sys/fs/pipe-max-size 文件
pub(super) const PIPE_MAX_SIZE_NODE: u32 = u32::MAX - 20;

/// 判断 inode 是否属于虚拟节点区间（固定虚拟节点或 /proc/<pid> 派生节点）。
pub(super) fn is_virtual_ino(ino: u32) -> bool {
    ino >= PIPE_MAX_SIZE_NODE || pid_ino_parts(ino).is_some()
}

/// /proc/sys/kernel/pid_max 内容。
pub(super) fn pid_max() -> &'static str {
    "32768\n"
}

/// /proc/sys/kernel/tainted 内容（0 表示无内核污染）。
pub(super) fn tainted() -> &'static str {
    "0\n"
}

/// /proc/sys/fs/pipe-max-size 内容（与 context::PIPE_MAX_SIZE = 1 MiB 一致）。
pub(super) fn pipe_max_size() -> &'static str {
    "1048576\n"
}

/// /proc/version 内容。
pub(super) fn version() -> &'static str {
    "Linux version 6.1.0-OuroOS (ouroos@build) (rustc) #1 SMP\n"
}

/// 生成当前进程的 /proc/self/maps 快照（proc(5) 标准行格式，地址按 Linux %08lx 排版）。
pub(crate) fn format_maps(
    space: &crate::mm::address_space::UserAddressSpace,
) -> Result<String, Errno> {
    use polyhal::pagetable::MappingFlags as F;
    let areas = space.areas();
    let mut out = String::new();
    out.try_reserve(areas.len().saturating_mul(64))
        .map_err(|_| Errno::NoMem)?;
    for area in areas {
        let r = if area.flags.contains(F::R) { 'r' } else { '-' };
        let w = if area.flags.contains(F::W) { 'w' } else { '-' };
        let x = if area.flags.contains(F::X) { 'x' } else { '-' };
        let s = if matches!(
            area.kind,
            crate::mm::address_space::AreaKind::SharedAnonymous
        ) {
            's'
        } else {
            'p'
        };
        let _ = writeln!(
            out,
            "{:08x}-{:08x} {}{}{}{} 00000000 00:00 0",
            area.start, area.end, r, w, x, s
        );
    }
    Ok(out)
}

/// /proc/<pid> 目录的 inode：pid 目录与其下文件按 16 偏移分段，
/// 避开 FAT 的最高位与 u32::MAX 附近的固定节点。
pub fn pid_dir_ino(pid: u32) -> u32 {
    0x4000_0000u32.wrapping_add(pid.wrapping_mul(16))
}

/// pid 派生 inode 的反解：Some((pid, file))，file 0=目录 1=stat 2=cmdline
/// 3=status 4=comm 5=timerslack_ns
pub fn pid_ino_parts(ino: u32) -> Option<(u32, u8)> {
    if !(0x4000_0000..0x7FFF_0000).contains(&ino) {
        return None;
    }
    let rel = ino - 0x4000_0000;
    let pid = rel / 16;
    let file = rel % 16;
    if pid == 0 || file > 5 {
        return None;
    }
    Some((pid, file as u8))
}

pub(super) fn meminfo() -> Result<String, Errno> {
    let (total, free) = crate::mm::frame::stats();
    let buffers = super::block_cache::cached_kib();
    let cached = super::cache::cached_kib();
    let available = free * 4 + buffers + cached;
    let mut out = String::new();
    // 9 个短字段及最多五个 20 位十进制数；写入不会另行扩容。
    out.try_reserve(384).map_err(|_| Errno::NoMem)?;
    write!(
        out,
        "MemTotal: {} kB\nMemFree: {} kB\nMemAvailable: {} kB\nBuffers: {} kB\nCached: {} kB\nSReclaimable: 0 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
        total * 4, free * 4, available, buffers, cached
    )
    .map_err(|_| Errno::Io)?;
    Ok(out)
}

/// /proc/mounts 快照：根卷一条 + FAT 追加挂载记录（字段见 mounts(5)）。
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
    let comm_buf = crate::task::proc_table_comm(pid);
    let comm = comm_buf
        .as_ref()
        .and_then(|raw| {
            let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            core::str::from_utf8(&raw[..len]).ok()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let mut out = String::new();
    out.try_reserve(256).map_err(|_| Errno::NoMem)?;
    let _ = write!(
        out,
        "{} ({}) {} {} {} {}",
        pid, comm, state as char, ppid, pgid, sid
    );
    // 字段 7..53 全部补零；comm 含空格的场景按 proc(5) 无需转义
    for _ in 7..=53 {
        out.push_str(" 0");
    }
    out.push('\n');
    Ok(out)
}

/// /proc/<pid>/status 快照（proc(5) 关键行；Uid、Gid、Name 与 NoNewPrivs 取自进程快照）。
pub(super) fn pid_status(pid: u32) -> Result<String, Errno> {
    let Some((name, state, ppid, _)) = crate::task::proc_table_lookup(pid) else {
        return Err(Errno::NoEntry);
    };
    let Some((_, _, ids)) = crate::task::proc_table_identity(pid) else {
        return Err(Errno::NoEntry);
    };
    let comm_buf = crate::task::proc_table_comm(pid);
    let comm = comm_buf
        .as_ref()
        .and_then(|raw| {
            let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            core::str::from_utf8(&raw[..len]).ok()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let nnp = u8::from(crate::task::proc_table_no_new_privs(pid));
    let mut out = String::new();
    out.try_reserve(224).map_err(|_| Errno::NoMem)?;
    let state_text = match state {
        b'R' => "R (running)",
        b'Z' => "Z (zombie)",
        _ => "S (sleeping)",
    };
    let _ = write!(
        out,
        "Name:\t{}\nState:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{}\t{}\t{}\t{}\nGid:\t{}\t{}\t{}\t{}\nNoNewPrivs:\t{}\n",
        comm, state_text, pid, ppid, ids[0], ids[1], ids[2], ids[3], ids[4], ids[5], ids[6], ids[7], nnp
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

/// /proc/<pid>/comm 快照（含末尾换行，见 proc(5)）。
pub(super) fn pid_comm(pid: u32) -> Result<String, Errno> {
    let Some((name, ..)) = crate::task::proc_table_lookup(pid) else {
        return Err(Errno::NoEntry);
    };
    let comm_buf = crate::task::proc_table_comm(pid);
    let comm = comm_buf
        .as_ref()
        .and_then(|raw| {
            let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            core::str::from_utf8(&raw[..len]).ok()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let mut out = String::new();
    out.try_reserve(comm.len() + 1).map_err(|_| Errno::NoMem)?;
    out.push_str(comm);
    out.push('\n');
    Ok(out)
}

/// /proc/<pid>/timerslack_ns 快照（十进制纳秒加换行）。
pub(super) fn pid_timerslack(pid: u32) -> Result<String, Errno> {
    let Some(slack) = crate::task::proc_table_timer_slack(pid) else {
        return Err(Errno::NoEntry);
    };
    let mut out = String::new();
    out.try_reserve(24).map_err(|_| Errno::NoMem)?;
    let _ = writeln!(out, "{}", slack);
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
