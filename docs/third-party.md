# 第三方与借鉴代码登记

按 AGENTS.md 第 7 节登记。新增条目须包含：来源、协议、使用/修改方式。

| 来源 | 协议 | 使用方式 | 登记时间 |
|---|---|---|---|
| [PolyHAL](https://github.com/Byte-OS/polyhal) polyhal / polyhal-boot / polyhal-trap 0.4.0 | MIT | crates.io 依赖（polyhal-boot）；polyhal 与 polyhal-trap 整 crate vendor 至 `third_party/polyhal` 与 `third_party/polyhal-trap` 并打本地补丁（rv 时钟频率读设备树，rv/la 用户断点 PC 修复，清单见各自 README.md） | polyhal-patch 分支 |
| [PolyHAL](https://github.com/Byte-OS/polyhal) polyhal-trap 0.4.0 `trap/loongarch64/unaligned.rs` | MIT | 整数非对齐指令解码范围借鉴并重写于 `kernel/src/trap/unaligned.rs`；用户访存改用 OuroOS 权限检查与复制 | 2026-11-14 |
| [virtio-drivers](https://github.com/rcore-os/virtio-drivers) 0.7.5 | MIT | 精确版本 crates.io 依赖；自写 DMA 与 MMIO/PCI 适配，未修改上游 | 2026-11-10 |
| [rsext4 0.8.1](https://crates.io/crates/rsext4/0.8.1) | Apache-2.0 | 源码和许可证位于 `third_party/rsext4`，默认 Ext4 后端，`rsext4-readonly` 选择只读模式。补丁见该目录 README | 2026-11-12 |
| [rust-fatfs](https://github.com/rafalh/rust-fatfs) 38b3a7950bf0e765e34286d1dfe76c519ee347e2 | MIT | 锁定 Git revision，no_std + alloc + lfn，FAT 挂载/读写/unlink（无目录列举） | 2026-11-10 |
| [Linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git) 6.x `arch/{riscv,loongarch}/kernel/signal.c` 与 UAPI 头（signal/sigcontext/ucontext/siginfo） | GPL-2.0（仅对照，未复制代码） | 信号帧布局/魔数/stub 指令编码的 ABI 事实标准：`kernel/src/sigframe/` 逐项对照并经交叉 gcc offsetof 实测核验；投递/EINTR 语义参考 `kernel/signal.c`（仅思路） | 2026-11-19 |

目录删除补丁：rsext4 新增按父目录 inode 移除空目录名的接口，复用目录项回滚和无引用 inode 回收。

属主更新补丁：rsext4 新增 `metadata::chown_inode`，复用现有元数据更新流程。Linux v6.12 `fs/attr.c` 仅用于核对基本授权语义，未复制源码。

历史条目：ext4_rs 1.3.3（MIT）曾作为 Ext4 后端 vendor 于 `third_party/ext4_rs`，含块分配起点与 panic 审计 9 处补丁，随 rsext4 接入而移除（fs/rsext4 集成分支）；审计工作待在 rsext4 上重做（见 ostd-contracts §6 欠账）。

本地 JBD2 栈占用补丁：提交临时块改为预先可失败分配的堆缓冲，复用单个 payload，避免多块数组叠加；版本与协议不变，详见 rsext4 README。

LoongArch 关机使用 PolyHAL 0.4.0（MIT）中 QEMU virt GED 的寄存器地址和关机值，等待循环位于 `kernel/src/hal.rs`。

## 本轮官方盘适配涉及的第三方补丁（2026-11-21）

- `third_party/rsext4`（Apache-2.0，rsext4 0.8.1）新增补丁：
  - JBD2 写入端 checksum_v3 支持：16 字节 v3 tag（64bit 块号 + 逐块
    crc32c(uuid_seed + be32(seq) + 载荷)）、描述符块尾与 commit 块校验、
    首个 tag 后的 journal UUID 与后续 SAME_UUID 协议、commit 块落盘前
    先持久化 journal 超级块（s_start/s_sequence）使已提交事务在任意断电
    时刻可被标准工具重放。补丁标记 `// OuroOS patch:` 见
    `src/jbd2/jbd2.rs` 与 `src/ext4/mount.rs`。参考语义来源：
    Linux v6.12 `fs/jbd2/{commit,recovery,journal,checkpoint}.c`
    （GPL-2.0，仅对照行为，未复制代码）。
  - 已知缺陷（上游设计，未在本轮修改）：目录块经 datablock_cache 以
    非 metadata 标记直写 home 块、绕过 JBD2（data=writeback 式）。断电
    窗口可留下指向未分配 inode 的目录项，标准 e2fsck 会清理并返回一致
    状态（本轮断电实验已验证）。
- BoarOS（GPL-2.0，github/gitlab 同期参赛作品）仅参考其公开文档中的
  思路与测例勘误（辅助盘分区布局、解释器别名路径、LA musl 调度包装
  ENOSYS 等事实），未复制任何代码。

## 本轮块缓存与读写热路径涉及的第三方补丁（2026-11-26）

- `third_party/rsext4`（Apache-2.0，rsext4 0.8.1）新增补丁（均标注 `// OuroOS patch:`，明细见 `third_party/rsext4/README.md`）：
  - `BlockDevice::{read_slice, write_slice}` 默认方法及 `BlockDev`/`Jbd2Dev`/`DataBlockCache` 块内切片直读直写透传、`write_block_static` 整块写回免多余读块；
  - `file/io.rs` 单块读免 `Vec<ExtentRun>` 堆分配与 `write_regular_inode_data` 合并加载；
  - `metadata/apply.rs` 按 Linux `mount(8)` 默认 `relatime` 语义更新 `atime`；
  - `cache/inode_table.rs` 与 `checksum/inode.rs` 命中单次查找及落盘编码前延迟更新 inode CRC32C（思路参考 Linux Ext4 `ext4_do_update_inode`，未复制 GPL 源码）。

## 本轮符号链接与硬链接涉及的第三方补丁（2026-11-27）

- `third_party/rsext4`（Apache-2.0，rsext4 0.8.1）新增补丁（均标注 `// OuroOS patch:`，明细见 `third_party/rsext4/README.md`）：
  - `file/create.rs` 新增 `create_symlink_inode`（支持相对与悬空目标，区分 <60 字节快速内联与块存储长链接）；
  - `file/link.rs` 新增 `link_inode`（按 inode 创建非目录硬链接，支持 `EMLINK` 检查与失败回滚）；
  - `file/delete.rs` 扩展 `unlink_regular_entry` 支持删除符号链接，并在 `free_inode` 中为快速内联符号链接跳过块指针遍历。

## 本轮命名管道与特殊节点涉及的第三方补丁（2026-11-27）

- `third_party/rsext4`（Apache-2.0，rsext4 0.8.1）新增补丁（均标注 `// OuroOS patch:`，明细见 `third_party/rsext4/README.md`）：
  - `file/create.rs` 新增 `create_special_inode` 支持 `S_IFREG`/`S_IFIFO`/`S_IFCHR`/`S_IFBLK`/`S_IFSOCK` 及 Ext4 `i_block[0..2]` 设备号编码；
  - `file/delete.rs` 与 `file/link.rs` 同步扩展无数据块特殊节点的 `free_inode`、`unlink_regular_entry` 与 `link_inode` 类型处理（参考 Ext4 磁盘格式规范，未复制 GPL 源码）。
