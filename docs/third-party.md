# 第三方与借鉴代码登记

按 AGENTS.md 第 7 节登记。新增条目须包含：来源、协议、使用/修改方式。

| 来源 | 协议 | 使用方式 | 登记时间 |
|---|---|---|---|
| [PolyHAL](https://github.com/Byte-OS/polyhal) polyhal / polyhal-boot / polyhal-trap 0.4.0 | MIT | crates.io 依赖（polyhal、polyhal-boot）；polyhal-trap 整 crate vendor 至 `third_party/polyhal-trap` 并打本地补丁（清单见其 README.md） | polyhal-patch 分支 |

| [virtio-drivers](https://github.com/rcore-os/virtio-drivers) 0.7.5 | MIT | 精确版本 crates.io 依赖；自写 DMA 与 MMIO/PCI 适配，未修改上游 | 2026-11-10 |
| [ext4_rs](https://github.com/yuoo655/ext4_rs) 1.3.3 | MIT | 固定 1.3.3，源码 vendor 至 third_party/ext4_rs；file.rs 分配起点从写死块组 1 改为 inode 所属组，避免小卷访问不存在的块组；保留 MIT 协议 | 2026-11-10 |
| [rust-fatfs](https://github.com/rafalh/rust-fatfs) 38b3a7950bf0e765e34286d1dfe76c519ee347e2 | MIT | 锁定 Git revision，no_std + alloc + lfn，FAT 支持（接入中） | 2026-11-10 |
