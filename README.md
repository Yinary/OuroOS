# OuroOS

OuroOS 是一个用 Rust 编写的宏内核，支持 RISC-V64 和 LoongArch64，兼容 Linux 系统调用接口。

本文只描述已经实现的内容。

## 构建与运行

依赖：

- Rust 工具链：按 `rust-toolchain.toml` 自动安装（nightly-2025-02-18，含 rust-src 等组件）。
- QEMU 10.0.2（`qemu-system-riscv64`、`qemu-system-loongarch64`）：需在 PATH 中，
  否则运行时用 `QEMU_RV` / `QEMU_LA` 变量指定路径，如
  `make run-la QEMU_LA=/path/to/qemu-system-loongarch64`。

常用命令：

```bash
make all      # 构建双架构内核与内嵌用户程序，产出 kernel-rv 与 kernel-la
make run-rv   # QEMU 启动 riscv64 内核（OpenSBI 交接，物理 0x80200000）
make run-la   # QEMU 启动 loongarch64 内核（直启 ELF）
make clippy   # 双架构 clippy（含用户程序构建）
make fmt      # 格式化内核与用户程序代码
```

启动自检（堆、帧分配器、trap、时钟、多核）全部通过后，内核会打印下面这一行
（boot hart 编号以实际启动核为准）：

```text
OuroOS v0.1.0 · riscv64 · boot hart 2 · 4 cpus · boot ok
```

随后内核进入最小用户态链路：依次运行内嵌的用户程序 `hello` 与 `check`
（源码在 `user/hello/`，构建时嵌入内核镜像，不经磁盘），用户程序真实
运行在用户权限级，通过 ecall / syscall 执行 write 与 exit：

```text
hello, OuroOS user world (riscv64)
[user] hello: exited with status 0
check: write ok
check: all syscall paths ok, faulting now
[user] check: killed by LoadPageFault @ 0x5000, pc 0x100e8
```

`check` 覆盖：write 成功路径与返回字节数、跨页用户缓冲区、未映射地址与
内核高地址缓冲区（EFAULT）、错误 fd（EBADF）、未实现系统调用（ENOSYS），
以及用户态非法访存被内核报告并终止。两个程序运行结束后内核统一关机。

## 测试情况

- 2026-10 本仓库尚在起步阶段，未接入官方测例；上述用户程序验证为本地
  `make run-rv` / `make run-la`（QEMU 9.2.1 / 10.0.2）实测结果。

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
