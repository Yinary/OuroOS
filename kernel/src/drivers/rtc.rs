//! 平台 RTC 墙上时钟读取（hwclock 的 RTC_RD_TIME）。
//! RV：Goldfish RTC @0x101000（LOW 锁存 HIGH，64 位纳秒，UTC 纪元）。
//! LA：LS7A TOY @0x100d_0100（年@0x30、月日时分秒@0x2c，双读一致防跨秒）。

/// 读硬件 RTC 并换算为 UTC 纪元秒；无设备或读数无效时返回 None。
pub fn read_utc_seconds() -> Option<i64> {
    #[cfg(target_arch = "riscv64")]
    {
        let regs = crate::drivers::mmio_volatile(0x101_000);
        // SAFETY: 0x101000 位于 kernel_pt 映射的 MMIO 大页（见
        // mmio_volatile 前提）；Goldfish RTC 寄存器为 32 位，先读 LOW
        // 后 HIGH 已被硬件锁存，两次读构成一次一致的 64 位采样。
        let low = unsafe { core::ptr::read_volatile(regs) } as u64;
        let high = unsafe { core::ptr::read_volatile(regs.add(1)) } as u64;
        let ns = (high << 32) | low;
        Some((ns / 1_000_000_000) as i64)
    }
    #[cfg(target_arch = "loongarch64")]
    {
        read_loongarch_toy()
    }
}

#[cfg(target_arch = "loongarch64")]
fn read_loongarch_toy() -> Option<i64> {
    let base = crate::drivers::mmio_volatile(0x100d_0100);
    // SAFETY: 0x100d_0100 经 LA DMW0 uncached 窗口直映（见 mmio_volatile
    // 前提）；写 0x20 关闭闹钟、置 0x40 的 0x900 启用 TOY 计数器，寄存器
    // 均为 32 位且无其他访问者（启动期单核）。
    unsafe {
        core::ptr::write_volatile(base.add(8), 0);
        let enable = core::ptr::read_volatile(base.add(0x40 / 4));
        core::ptr::write_volatile(base.add(0x40 / 4), enable | 0x900);
    }
    for _ in 0..8 {
        // SAFETY: 同上；TOY 无读锁存，四个 32 位读在单核上连续执行，
        // 双读一致才接受样本。
        let (high, low, high2, low2) = unsafe {
            (
                core::ptr::read_volatile(base.add(0x30 / 4)),
                core::ptr::read_volatile(base.add(0x2c / 4)),
                core::ptr::read_volatile(base.add(0x30 / 4)),
                core::ptr::read_volatile(base.add(0x2c / 4)),
            )
        };
        if high == high2 && low == low2 {
            return toy_to_epoch(high, low);
        }
    }
    None
}

/// TOY 字段（tm_year 编码的年 + 打包的月/日/时/分/秒）换算 UTC 纪元秒。
#[cfg(target_arch = "loongarch64")]
fn toy_to_epoch(high: u32, low: u32) -> Option<i64> {
    let year = i64::from(high) + 1900;
    if !(1970..=3000).contains(&year) {
        return None;
    }
    let month = low >> 26;
    let day = (low >> 21) & 0x1f;
    let hour = (low >> 16) & 0x1f;
    let minute = (low >> 10) & 0x3f;
    let second = (low >> 4) & 0x3f;
    if !(1..=12).contains(&month) || day == 0 || day > 31 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let lengths = [
        31,
        28 + u32::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day > lengths[(month - 1) as usize] || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut days = 0i64;
    for y in 1970..year {
        days += 365 + i64::from(y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
    }
    days += i64::from(lengths[..(month - 1) as usize].iter().sum::<u32>());
    days += i64::from(day) - 1;
    Some(days * 86400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))
}

/// UTC 纪元秒拆成 struct rtc_time 的九个 int 字段（linux/rtc.h 顺序）：
/// 秒、分、时、日、月（0 起）、年-1900、星期（0=周日）、年内天、isdst=0。
pub fn epoch_to_tm(secs: i64) -> [i32; 9] {
    let days = secs.div_euclid(86400);
    let sod = secs.rem_euclid(86400);
    // civil_from_days（Howard Hinnant 算法）：
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + i64::from(m <= 2);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let lengths = [
        31,
        28 + i64::from(leap),
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut yday = d;
    for len in &lengths[..(m - 1) as usize] {
        yday += len;
    }
    let wday = (days + 4).rem_euclid(7); // 1970-01-01 是周四
    [
        (sod % 60) as i32,
        ((sod / 60) % 60) as i32,
        (sod / 3600) as i32,
        d as i32,
        (m - 1) as i32,
        (year - 1900) as i32,
        wday as i32,
        (yday - 1) as i32,
        0,
    ]
}
