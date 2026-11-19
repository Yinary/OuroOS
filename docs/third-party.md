# 第三方与借鉴代码登记

按 AGENTS.md 第 7 节登记。新增条目须包含：来源、协议、使用/修改方式。

| 来源 | 协议 | 使用方式 | 登记时间 |
|---|---|---|---|
| [PolyHAL](https://github.com/Byte-OS/polyhal) polyhal / polyhal-boot / polyhal-trap 0.4.0 | MIT | crates.io 依赖（polyhal、polyhal-boot）；polyhal-trap 整 crate vendor 至 `third_party/polyhal-trap` 并打本地补丁（清单见其 README.md） | polyhal-patch 分支 |
| [PolyHAL](https://github.com/Byte-OS/polyhal) polyhal-trap 0.4.0 `trap/loongarch64/unaligned.rs` | MIT | 整数非对齐指令解码范围借鉴并重写于 `kernel/src/trap/unaligned.rs`；用户访存改用 OuroOS 权限检查与复制 | 2026-11-14 |
| [virtio-drivers](https://github.com/rcore-os/virtio-drivers) 0.7.5 | MIT | 精确版本 crates.io 依赖；自写 DMA 与 MMIO/PCI 适配，未修改上游 | 2026-11-10 |
| [rsext4 0.8.1](https://crates.io/crates/rsext4/0.8.1) | Apache-2.0 | 源码和许可证位于 `third_party/rsext4`，默认 Ext4 后端，`rsext4-readonly` 选择只读模式。补丁见该目录 README | 2026-11-12 |
| [rust-fatfs](https://github.com/rafalh/rust-fatfs) 38b3a7950bf0e765e34286d1dfe76c519ee347e2 | MIT | 锁定 Git revision，no_std + alloc + lfn，FAT 挂载/读写/unlink（无目录列举） | 2026-11-10 |

历史条目：ext4_rs 1.3.3（MIT）曾作为 Ext4 后端 vendor 于 `third_party/ext4_rs`，含块分配起点与 panic 审计 9 处补丁，随 rsext4 接入而移除（fs/rsext4 集成分支）；审计工作待在 rsext4 上重做（见 ostd-contracts §6 欠账）。

rsext4 本地时间接口补丁（2026-11-18）：在 `src/metadata/api.rs` 新增 `utimens_inode`，由 `src/metadata/mod.rs` 导出；路径版接口复用同一实现。沿用 Apache-2.0，未新增依赖或复制其他内核代码。

rsext4 本地重命名补丁（2026-11-19）：重写 `src/file/rename.rs`，从 `src/file/mod.rs` 导出按父 inode 重命名及旧目标回收接口；替换不提前释放目标，失败恢复目录块与 inode，目录移动维护父项及链接数，空目录目标回收维护分组目录计数。沿用 Apache-2.0，补丁由本项目实现，Linux 仅参考公开语义。

rsext4 本地截断补丁（2026-11-19）：修改 `src/file/io.rs` 的 inode 截断流程及 `src/extents_tree/parse.rs` 的区间遍历，支持稀疏扩展、尾块清零、unwritten extent 和索引块回收；保留原 Apache-2.0 协议，无新增依赖，未复制 Linux 实现代码。
