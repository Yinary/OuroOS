# OuroOS

OuroOS 是一个用 Rust 编写的宏内核，支持 RISC-V64 和 LoongArch64，兼容 Linux 系统调用接口。

本文只描述已经实现的内容。

## 构建与运行

依赖：

- Rust 工具链：按 `rust-toolchain.toml` 自动安装（nightly-2025-02-18，含 rust-src 等组件）。
- QEMU 10.0.2（`qemu-system-riscv64`、`qemu-system-loongarch64`）。

常用命令：

```bash
make all      # 构建双架构内核，产出仓库根目录下的 kernel-rv 与 kernel-la
make run-rv   # QEMU 启动 riscv64 内核（OpenSBI 交接，物理 0x80200000）
make run-la   # QEMU 启动 loongarch64 内核（直启 ELF）
```

启动自检（堆、帧分配器、trap、时钟、多核）全部通过后，内核会打印下面这一行
并调用 QEMU 关机退出（boot hart 编号以实际启动核为准）：

```text
OuroOS v0.1.0 · riscv64 · boot hart 2 · 4 cpus · boot ok
```

## 测试情况

## 文档

## 第三方代码声明

| 名称 | 来源 | 协议 | 用途 |
|---|---|---|---|
| PolyHAL 0.4.0 | https://github.com/Byte-OS/polyhal | MIT | 硬件抽象层 |
| PolyHAL example | https://github.com/Byte-OS/polyhal example 目录 | MIT | 改编了 `kernel/build.rs`、`kernel/linker.lds`、`kernel/src/mm/frame.rs` |
| polyhal-boot 0.4.0 | https://crates.io/crates/polyhal-boot | MIT | 双架构早期汇编入口与拉起副核 |
| polyhal-trap 0.4.0 | https://crates.io/crates/polyhal-trap | MIT | 双架构中断/异常初始化与分发 |
| log 0.4.34 | https://crates.io/crates/log | MIT OR Apache-2.0 | 分级日志 |
| spin 0.10.1 | https://crates.io/crates/spin | MIT | 自旋锁（帧分配器） |
| buddy_system_allocator 0.11.0 | https://crates.io/crates/buddy_system_allocator | MIT | 内核堆与页帧 buddy 分配器 |

## AI 工具使用说明

| 工具 | 版本 | 用途与阶段 | 使用方式 |
|---|---|---|---|

## 演示视频

## 团队成员

## 许可证

MIT，见 [LICENSE](LICENSE)。
