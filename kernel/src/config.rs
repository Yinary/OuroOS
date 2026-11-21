//! 内核全局配置常量

/// 内核名（对外标识，改名请同时改 Cargo.toml 与本处）
pub const KERNEL_NAME: &str = "OuroOS";

/// 版本号，取自 Cargo.toml
pub const KERNEL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// uname(2) 的 release 字段。按 Linux 惯例给出 "数字版本-标识" 形式：
/// glibc 等用户空间在启动时解析该字段做最低内核版本检查，纯项目版本号
/// （如 0.1.0）会被判为过旧的内核而拒绝启动。
pub const KERNEL_RELEASE: &str = "6.1.0-OuroOS";

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

/// 每个任务的内核栈页数（8 页 = 32 KiB，另有低地址 guard 页；见 docs/ostd-contracts.md §1）。
pub const KSTACK_PAGES: usize = 8;
