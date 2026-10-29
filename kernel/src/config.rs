//! 内核全局配置常量

/// 内核名（对外标识，改名请同时改 Cargo.toml 与本处）
pub const KERNEL_NAME: &str = "OuroOS";

/// 版本号，取自 Cargo.toml
pub const KERNEL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 当前架构名（编译期确定）
pub const ARCH_NAME: &str = match () {
    #[cfg(target_arch = "riscv64")]
    () => "riscv64",
    #[cfg(target_arch = "loongarch64")]
    () => "loongarch64",
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    () => "unknown",
};

/// 内核堆大小：8 MiB（位于内核 .bss，帧分配器已排除内核镜像区域）
pub const KERNEL_HEAP_SIZE: usize = 0x80_0000;

/// 时钟中断间隔（毫秒）
pub const TICK_MS: u64 = 100;

/// 启动自检需要收到的 tick 数
pub const BOOT_TICKS: usize = 3;
