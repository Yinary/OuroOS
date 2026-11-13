# 第三方与借鉴代码登记

按 AGENTS.md 第 7 节登记。新增条目须包含：来源、协议、使用/修改方式。

| 来源 | 协议 | 使用方式 | 登记时间 |
|---|---|---|---|
| [PolyHAL](https://github.com/Byte-OS/polyhal) polyhal / polyhal-boot / polyhal-trap 0.4.0 | MIT | crates.io 依赖（polyhal、polyhal-boot）；polyhal-trap 整 crate vendor 至 `third_party/polyhal-trap` 并打本地补丁（清单见其 README.md） | polyhal-patch 分支 |
| [virtio-drivers](https://github.com/rcore-os/virtio-drivers) 0.7.5 | MIT | 精确版本 crates.io 依赖；自写 DMA 与 MMIO/PCI 适配，未修改上游 | 2026-11-10 |
| [rsext4 0.8.1](https://crates.io/crates/rsext4/0.8.1) | Apache-2.0 | 源码和许可证位于 `third_party/rsext4`，默认 Ext4 后端，`rsext4-readonly` 选择只读模式。补丁见该目录 README | 2026-11-12 |
| [rust-fatfs](https://github.com/rafalh/rust-fatfs) 38b3a7950bf0e765e34286d1dfe76c519ee347e2 | MIT | 锁定 Git revision，no_std + alloc + lfn，FAT 挂载/读写/unlink（无目录列举） | 2026-11-10 |

历史条目：ext4_rs 1.3.3（MIT）曾作为 Ext4 后端 vendor 于 `third_party/ext4_rs`，含块分配起点与 panic 审计 9 处补丁，随 rsext4 接入而移除（fs/rsext4 集成分支）；审计工作待在 rsext4 上重做（见 ostd-contracts §6 欠账）。
