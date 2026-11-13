# polyhal-trap（OuroOS vendor 副本）

- 参考来源：PolyHAL https://github.com/Byte-OS/polyhal （polyhal-trap 0.4.0）
- 原协议：MIT
- 引入方式：整 crate 复制进本仓库（`[patch.crates-io]` 指向本目录，
  见根 Cargo.toml），仅 polyhal-trap 一个 crate；polyhal 本体未 vendor。
- 修改说明（相对上游 0.4.0，逐条对应 docs/ostd-contracts.md 缺陷表）：
  1. 缺陷 #5（EscapeReason 有损）：四架构 `run_user_task` 改为返回完整
     `TrapType`，不再 `From<TrapType> for EscapeReason` 降维。EscapeReason
     类型与 From 实现保留仅为兼容，不应再使用。
  2. 缺陷 #7（la 未分类异常在 HAL 层 panic）：loongarch64 分类器的
     `_ =>`/`todo!()` 分支改为返回新增的 `TrapType::Unhandled(code)`，
     由 OS 回调决策（用户态→终止任务，内核态→内核 bug）；
     riscv64 的未分类 scause 同样改为 `Unhandled`（原为 panic）；
     la 非对齐访问模拟成功改报新增的 `TrapType::Absorbed`（原为
     `Unknown`，与未分类无法区分）；x86_64 kernel_callback 改为返回
     TrapType 以透传。
  3. la `TrapFrame::from_user()` 补齐（rv 侧上游已有），OS 侧无需再
     手工读 prmd。
- 升级提示：polyhal-trap 版本更新时，须按上述清单逐条回归或重放补丁。
