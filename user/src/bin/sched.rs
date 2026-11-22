//! sched：调度验证负载——打印 pid 与轮次，每轮 sched_yield()；
//! 双实例并行应见交错轮次，忙循环跨时钟 tick 时应见抢占。

#![no_std]
#![no_main]

use core::hint::black_box;

use user::{define_user_entry, sys_exit, sys_getpid, sys_sched_yield, sys_write};

/// 忙循环轮数
const ROUNDS: usize = 6;
/// 每轮迭代数：足以跨过多个时钟 tick（TICK_MS=100），让抢占可见
const ITERS: usize = 20_000_000;

/// 用户主函数（由 _start 调用，不返回）
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let pid = sys_getpid();
    report(pid, b"start\n");

    let mut sink: usize = 0;
    for round in 0..ROUNDS {
        for i in 0..ITERS {
            // 不可优化的忙工作量
            sink = sink.wrapping_add(i);
        }
        black_box(&mut sink);
        report_num(pid, round);
        sys_sched_yield();
    }

    report(pid, b"done\n");
    sys_exit(0);
}

/// 带 pid 前缀输出一段常量消息
fn report(pid: isize, msg: &[u8]) {
    let head = b"sched[";
    let _ = sys_write(1, head);
    let _ = write_usize(pid as usize);
    let _ = sys_write(1, b"]: ");
    let _ = sys_write(1, msg);
}

/// 带 pid 前缀输出轮次号
fn report_num(pid: isize, round: usize) {
    report(pid, b"round ");
    let _ = write_usize(round);
    let _ = sys_write(1, b"\n");
}

/// 十进制无符号输出（免格式化运行时），返回 write 结果
fn write_usize(mut v: usize) -> isize {
    let mut buf = [0u8; 20];
    let mut len = 0;
    loop {
        buf[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut out = 0isize;
    // 逆序逐字节写：本程序只求可读，不追求系统调用次数
    for i in (0..len).rev() {
        out = sys_write(1, &buf[i..i + 1]);
    }
    out
}

define_user_entry!(ouro_main);
