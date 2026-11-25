<p align="center">
  <img src="docs/assets/ouro_icon.png" width="180" alt="OuroOS">
</p>

<p align="center">
  <img src="docs/assets/ouroos-wordmark.svg" width="300" alt="OuroOS">
</p>

<p align="center">
  <a href="https://github.com/riscv/riscv-isa-manual"><img src="https://img.shields.io/badge/RISC--V-64--BIT_SV39-2563eb?style=for-the-badge" alt="RISC-V 64-bit SV39"></a>
  <a href="https://loongson.github.io/LoongArch-Documentation/"><img src="https://img.shields.io/badge/LOONGARCH-64--BIT_LA464-d93f3f?style=for-the-badge" alt="LoongArch 64-bit LA464"></a>
  <img src="https://img.shields.io/badge/RUST-nightly_2025--02--01-dea584?style=for-the-badge&logo=rust" alt="Rust nightly">
  <img src="https://img.shields.io/badge/QEMU-10.0.2-6f42c1?style=for-the-badge&logo=qemu" alt="QEMU 10.0.2">
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-MIT-2ea44f?style=for-the-badge" alt="MIT License"></a>
</p>

OuroOS 是一个用 Rust 编写的宏内核，支持 RISC-V64 和 LoongArch64，兼容 Linux 系统调用接口。

本文只描述已经实现的内容。

OuroOS 目前仅面向单核：QEMU 以 `-smp 1` 运行，内核不含多核机制。

## 构建与运行

依赖：

- Rust 工具链：按 `rust-toolchain.toml` 自动安装（nightly-2025-02-01，含
  rust-src 等组件，与官方评测镜像预装版本一致）。
- QEMU 10.0.2（`qemu-system-riscv64`、`qemu-system-loongarch64`）：需在 PATH 中，
  否则运行时用 `QEMU_RV` / `QEMU_LA` 变量指定路径，如
  `make run-la QEMU_LA=/path/to/qemu-system-loongarch64`。

常用命令：

```bash
make all         # 构建双架构内核与辅助盘，产出 kernel-rv / kernel-la / disk.img / disk-la.img
make run-rv      # QEMU 启动 riscv64 内核（OpenSBI 交接，物理 0x80200000）
make run-la      # QEMU 启动 loongarch64 内核（直启 ELF）
make test-setup  # 准备官方评测器与原盘（一次性，幂等）
make test-rv     # 官方原盘验收（riscv64，原版 judge 判分）
make test-la     # 官方原盘验收（loongarch64）
make clippy      # 双架构 clippy（含用户程序构建）
make fmt         # 格式化内核与用户程序代码
```

启动自检（堆、帧分配器、trap、时钟）全部通过后，内核会打印下面这一行：

```text
OuroOS v0.1.0 · riscv64 · boot hart 0 · 1 cpus · boot ok
```

随后内核进入用户态链路。挂载官方测例盘时由内嵌启动器 `official_init`
布置动态解释器与 busybox 入口后运行盘上组脚本；无盘或调试场景则依次
运行内嵌的用户程序 `smoke` 与 `check`（源码在 `user/`，构建时嵌入内核
镜像，不经磁盘），用户程序运行在用户权限级，经 ecall / syscall 执行
write、exit 及内存系统调用：

```text
hello, OuroOS user world (riscv64)
[user] hello: exited with status 0
check: write ok
check: mm syscall paths ok
check: all syscall paths ok, faulting now
[user] check: killed by LoadPageFault @ 0x5000
```

`check` 覆盖：write 成功路径与返回字节数、跨页用户缓冲区、未映射地址与
内核高地址缓冲区（EFAULT）、错误 fd（EBADF）、未实现系统调用（ENOSYS），
以及 brk/mmap/munmap/mprotect 的成功、固定替换、权限与错误路径，
最后验证用户态非法访存被内核报告并终止。所有任务结束后内核统一关机。

## 内存系统调用范围

| 编号 | 名称 | 已支持与限制 |
|---|---|---|
| 213 | readahead | 普通文件按偏移预读，最多 128 KiB，保留文件游标 |
| 214 | brk | 查询、扩展、收缩；失败返回原 break，物理页按首次访问分配 |
| 222 | mmap | 私有与共享匿名、文件映射、MAP_FIXED 事务替换；访问整个位于 EOF 外的页按 SIGBUS 终止 |
| 215 | munmap | 起址必须页对齐，长度向上取整，允许空洞；零长度拒绝 |
| 226 | mprotect | 支持修改读写权限和 PROT_NONE；可访问页实际可执行，写保护由页表执行 |

可访问页实际允许执行，PROT_WRITE 蕴含 PROT_READ。每个任务拥有带未映射保护页的内核栈。支持 mremap、mincore、madvise、msync 和锁页调用，细节见内存契约。fork 深拷贝私有驻留页，TLB 刷新限于当前核。

## 测试情况

官方 pre-20250615 原盘 + 原版 judge（QEMU 10.0.2）：

| 组 | riscv64 | loongarch64 |
|---|---|---|
| basic-musl / basic-glibc | 102/102 | 102/102 |
| busybox-musl / busybox-glibc | 54/55 | 54/55 |
| lua-musl / lua-glibc | 9/9 | 9/9 |
| libcbench-musl / libcbench-glibc | 27/27 | 27/27 |

busybox 各差 1 分来自判分器内嵌的 `kill 10` 命令与盘上命令表不对齐（外部差异，非功能缺陷）。libcbench 按有效计时数计：27 个子项各得 1 到 2 分的性能分，慢于基线得 1 分，快于基线按比例增加。basic 的 `test_pipe` 偶发因父子进程输出交错少 3 分，见契约 §3.8。自建盘 FS 语义回归（`make test-regress`）双架构四配置全通过。

## 文档

- [ostd 契约与已知缺陷](docs/ostd-contracts.md)
- [第三方与借鉴代码登记](docs/third-party.md)

## 第三方代码声明

| 名称 | 来源 | 协议 | 用途 |
|---|---|---|---|
| PolyHAL 0.4.0 | https://github.com/Byte-OS/polyhal | MIT | 硬件抽象层 |
| PolyHAL example | https://github.com/Byte-OS/polyhal example 目录 | MIT | 改编了 `kernel/build.rs`、`kernel/linker.lds`、`kernel/src/mm/frame.rs` |
| polyhal-boot 0.4.0 | https://crates.io/crates/polyhal-boot | MIT | 双架构早期汇编入口与早期初始化（多核拉起路径本项目不使用） |
| polyhal-trap 0.4.0 | https://github.com/Byte-OS/polyhal | MIT | 双架构中断/异常初始化与分发；vendor 至 `third_party/polyhal-trap` 并打本地补丁（清单见其 README） |
| virtio-drivers 0.7.5 | https://github.com/rcore-os/virtio-drivers | MIT | 块设备驱动；自写 DMA 与 MMIO/PCI 适配 |
| rsext4 0.8.1 | https://crates.io/crates/rsext4/0.8.1 | Apache-2.0 | Ext4 后端，vendor 于 `third_party/rsext4` |
| rust-fatfs（锁定 revision） | https://github.com/rafalh/rust-fatfs | MIT | FAT 挂载与文件读写 |
| log 0.4.34 | https://crates.io/crates/log | MIT OR Apache-2.0 | 分级日志 |
| spin 0.10.1 | https://crates.io/crates/spin | MIT | 自旋锁（帧分配器） |
| buddy_system_allocator 0.11.0 | https://crates.io/crates/buddy_system_allocator | MIT | 内核堆分配器（页帧分配器为自建位图） |

官方评测器 [autotest-for-oskernel](https://github.com/oscomp/autotest-for-oskernel) 仅作为本地验收工具经 `make test-setup` 克隆使用，不随本仓库分发。

## AI 工具使用说明

本项目在 AI 编码助手协作下开发：助手参与代码生成、测试与文档整理，
全部改动经人工审查后合入。使用工具与版本由维护者按需登记。

## 许可证

MIT，见 [LICENSE](LICENSE)。
