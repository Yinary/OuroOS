//! 内核日志环：收集启动报告、任务终态与 panic 行，供 syslog(2)/klogctl
//! 读取；log 分级宏的串口输出不经过这里。

#![forbid(unsafe_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use spin::Mutex;

/// 环形上限：截掉最旧内容，防无界增长
pub(crate) const CAP: usize = 8 * 1024;

static RING: Mutex<Vec<u8>> = Mutex::new(Vec::new());
/// 消耗式读游标（syslog READ 语义；READ_ALL/CLEAR 之外推进）
static CURSOR: AtomicUsize = AtomicUsize::new(0);
/// syslog SET_CONSOLE_LEVEL 记录的请求级别（1..=8）；串口直通，不改变输出
static CONSOLE_LEVEL: AtomicU8 = AtomicU8::new(7);

/// 追加一行日志（自动补换行）
pub fn append(line: &str) {
    let mut ring = RING.lock();
    // 预留失败直接丢弃本行，绝不未预留成功就 push/extend
    if ring.try_reserve(line.len() + 1).is_err() {
        return;
    }
    ring.extend_from_slice(line.as_bytes());
    if !line.ends_with('\n') {
        ring.push(b'\n');
    }
    let overflow = ring.len().saturating_sub(CAP);
    if overflow > 0 {
        ring.drain(..overflow);
    }
    let cur = CURSOR.load(Ordering::Relaxed);
    CURSOR.store(cur.saturating_sub(overflow.min(cur)), Ordering::Relaxed);
}

/// 消耗式读取第一步：返回未读内容与新游标位置（不推进），交付成功后调
/// read_consume_commit 推进。分配失败返回 None（转 ENOMEM）。
pub fn read_consume_peek(max: usize) -> Option<(String, usize)> {
    let ring = RING.lock();
    let cur = CURSOR.load(Ordering::Relaxed).min(ring.len());
    let end = ring.len().min(cur.saturating_add(max));
    let mut out = String::new();
    out.try_reserve(end - cur).ok()?;
    out.push_str(core::str::from_utf8(&ring[cur..end]).ok()?);
    Some((out, end))
}

/// 确认消耗式读取的交付：交付成功后推进游标。
pub fn read_consume_commit(new_cursor: usize) {
    CURSOR.store(new_cursor.min(RING.lock().len()), Ordering::Relaxed);
}

/// 清空日志环（SYSLOG_ACTION_CLEAR / READ_CLEAR 的清除部分）。
pub fn clear() {
    RING.lock().clear();
    CURSOR.store(0, Ordering::Relaxed);
}

/// 当前未读字节数（SYSLOG_ACTION_SIZE_UNREAD）。
pub fn unread() -> usize {
    RING.lock()
        .len()
        .saturating_sub(CURSOR.load(Ordering::Relaxed))
}

/// 记录 console 级别请求；不改变实际输出（见契约偏差表）。
pub fn set_console_level(level: u8) {
    CONSOLE_LEVEL.store(level, Ordering::Relaxed);
}

/// 环容量（SYSLOG_ACTION_SIZE_BUFFER）。
pub fn capacity() -> usize {
    CAP
}

/// 全部日志文本（SYSLOG_ACTION_READ_ALL），失败返回 None（转 ENOMEM）。
pub fn read_all() -> Option<String> {
    let ring = RING.lock();
    let mut out = String::new();
    out.try_reserve(ring.len()).ok()?;
    out.push_str(core::str::from_utf8(&ring).ok()?);
    Some(out)
}
