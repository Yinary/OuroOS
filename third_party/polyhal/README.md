# polyhal（OuroOS vendor 副本）

- 参考来源：PolyHAL https://github.com/Byte-OS/polyhal （polyhal 0.4.0）
- 原协议：MIT
- 引入方式：整 crate 复制进本仓库（`[patch.crates-io]` 指向本目录，
  见根 Cargo.toml），内容取自 `cargo vendor` 生成的 crates.io 包，不含包内
  的 Cargo.lock；polyhal-boot 仍走 crates.io。
- 修改说明（相对上游 0.4.0，对应 docs/ostd-contracts.md §2.2 缺陷 #13）：
  1. riscv64 的时钟频率不再写死 12.5 MHz，改为读设备树 `/cpus` 的
     `timebase-frequency`。QEMU virt 的默认值是 10 MHz，写死后
     `current_time` 与 `set_next_timer` 的换算都偏慢 25%。设备树没有
     该属性时沿用 12.5 MHz。
- 升级提示：polyhal 版本更新时，须按上述清单逐条回归或重放补丁。
