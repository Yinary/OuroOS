//! 内核 panic 处理：打印信息后走 QEMU 关机，让 QEMU 自行退出。

use core::panic::PanicInfo;

use polyhal::{instruction::shutdown, println};

/// panic 回调：打印位置与消息后关机，不会返回。
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    if let Some(location) = info.location() {
        println!(
            "[panic] {}:{}: {}",
            location.file(),
            location.line(),
            info.message()
        );
    } else {
        println!("[panic] {}", info.message());
    }
    shutdown()
}
