# OuroOS ostd 契约与已知缺陷

本文档是三个子系统（mm / polyhal 边界 / task）的框架级契约与欠账清单，
配合各模块源码头部的模块契约阅读。定位：框内核（frame kernel）思想的
落地——HAL 提供原语，框架层（mm、task、syscall）提供带不变量的安全
服务，上层模块只经安全接口使用资源。

**本文档是设计决策、语义规范、路线计划、已知缺陷与欠账的唯一权威
文本**：代码注释只做介绍（"这是什么"、不易懂代码在做什么），不承载
上述内容（AGENTS.md §6）。准则：**能编译期管的不写注释，
能断言管的不写文档，其余全部记录在案。**

维护约定：契约条目变更须与代码同 PR；"欠账"条目解决时移入对应
"已兑现"并在 commit message 说明。

---

## 1. mm 契约（权威全文；mm 各模块头只留职责摘要）

mm 把物理内存变成失败可预期、责任可追溯的虚拟内存服务，五层链：
region（物理账本，唯一入口）→ frame（OwnedFrame 唯一释放凭证）→
page_table/arch（硬件机制，PTE 差异收敛于 arch.rs）→ address_space
（区域期望权限 + 页清单真实所有权）→ user_access（两遍式验证后复制）。

十律：物理内存唯一入口；唯一释放凭证；分配即清零；期望权限 ≠ 实际
权限（无 NX，团队决策，撤 X 请求明确拒绝）；PROT_NONE 占坑保留页；
事务性（失败与未调用不可区分）；两遍式用户访问（无部分写、用户指针
永不成引用）；地址空间 !Send（单核绑定）；TLB 全量刷保守策略；
关键路径零堆依赖零 panic。

补充语义（自各模块注释收编）：
- 帧分配器选位图而非 buddy：buddy 空闲链表依赖堆，堆耗尽会 panic
  内核；位图 + try_reserve 元数据使运行期分配路径零堆依赖、失败
  可恢复。连续多页分配无所有权封装，仅限底层适配（kernel_pt 启动
  期与 kstack），普通调用方一律走 OwnedFrame。
- 零页（物理 <0x1000）永久保留：空 PTE 与指向物理 0 的有效 PTE
  无法区分，保留后"表项为零"可安全表示"从未映射"。
- region 保留区语义：FDT 显式保留、内核镜像、固件、对齐碎片各有
  类型化来源；HAL 启动占用且无法经公开 API 追溯的空洞统一记
  HalBoot，不伪造来源。原始 FDT RAM 不得绕过账本直接交给分配器。
- 内核堆固定 8 MiB 不扩容（TODO 已在 allocator.rs 挂锚点）；MM
  元数据全部 try_reserve 返回 OOM，帧分配/归还不依赖运行期堆。
- user_access 并发前提：当前全局单任务、复制期间无并发 munmap；
  并发化时需持空间锁或固定被访问页。
- kstack：连续物理页 + 直映访问，无保护页（直映上无法用"不映射"
  表达，伪造保护被明文禁止）；虚拟窗口欠账见下。
- ELF 加载器仅支持 ET_EXEC 静态小端 ELF64；与 Linux 的差异
  （对齐、note 段、auxv 等）见 §4。

已定的未来语义：brk 字节级记账；mmap 匿名找空洞、MAP_FIXED 先备
齐再原子替换；fork 深拷贝、建成才发布、无 COW；exec 先建新空间
（含 argv/envp/auxv）后切换。

### mm 欠账

- 内核栈虚拟窗口 + 保护页（见下节 task 欠账）；当前 kstack 为直映
  连续页，`kernel/src/mm/kstack.rs`。
- 数据页/区域清单线性扫描，规模大后换有序映射。
- 按需分页、COW、页缓存、swap、共享空间远端 TLB 同步：明文不做，
  按接入顺序（不变量 → brk/匿名 mmap → fork/exec → 文件映射）推进。

## 2. polyhal 边界契约与已知缺陷

PolyHAL（0.4.0，三 crate：polyhal / polyhal-trap / polyhal-boot）承担
启动链、trap 框架、运行期原语（控制台/时钟/中断/percpu/KContext）。
定位是**原语库而非框架**：不表达所有权、不变量与失败路径。因此：

- 页表服务整体弃用（缺陷 1/2），只借硬件事实：PAGE_SIZE、
  MappingFlags、PageTable::current/root、TLB；自建带所有权的
  page_table 层。
- 上下文切换用 KContext + context_switch；页表切换自管
  （mm::arch::switch 控制 flush 时序），不用 context_switch_pt。
- LA TLB refill 向量被本仓自写实现替换（QEMU 10.0.2 LDPTE 丢
  NR/NX 位），SAVE3 暂存 t1（PolyHAL 占用 SAVE0..2）。
- HAL 未封装、由内核自补的接口：fence_icache（fence.i/ibar）、
  read_current_tp、la idle 指令（当前自旋等钟）。

### 已知缺陷清单（详录见 notes/log/2026-10-29-polyhal-0.4.0-已知缺陷.md）

| # | 缺陷 | 当前对策 |
|---|---|---|
| 1 | map_page 分配的页表页不清零 | 弃用其页表 API，自建 |
| 2 | translate 叶子级不查 PTE 有效性 | 弃用，自建 translate |
| 3 | SysCall 不推进 PC | 运行循环恰好一次 syscall_ok |
| 4 | 内核 SBI ecall 也表现为 SysCall | 来源判定（from_user）+ 事件标志 |
| 5 | EscapeReason 有损（用户异常只剩 NoReason） | **已修复**（vendor 补丁：run_user_task 返回完整 TrapType，事件侧信道已移除） |
| 6 | la 无法表达撤 X（无 NX） | 团队决策不实现 NX；translate 报实际权限 |
| 7 | la 未分类异常在 HAL 层直接 panic | **已修复**（vendor 补丁：新增 TrapType::Unhandled 转交 OS；验收：ill 程序 la 侧 ADEF 被终止任务而非 panic 内核） |
| 8 | 启动期（rust_main 之前）一处 ptr::add 越界 | **已定位**：polyhal 本体 percpu `set_local_thread_pointer`（rv，percpu/mod.rs:88）把 VIRT_ADDR_START 作 ptr::add 字节偏移，超出 isize 范围（数学结果正确，技术 UB）。不在 polyhal-trap vendor 范围内，selftest 档继续以 -Zub-checks=no 规避（Makefile UB_CHECKS_OFF）；vendor polyhal 本体时顺手修复 |
| — | la 缺 TrapFrame::from_user 封装 | trap.rs 内联读 prmd（带 cfg 注释） |

### vendor 补丁（已实施，polyhal-patch 分支）

polyhal-trap 0.4.0 整 crate vendor 至 `third_party/polyhal-trap`，
根 Cargo.toml `[patch.crates-io]` 指向本地副本；polyhal 本体与
polyhal-boot 仍走 crates.io。补丁清单与升级回归说明见其 README.md，
登记于 docs/third-party.md。修复项：#5（TrapType 直达）、#7
（Unhandled 转交）、la from_user 补齐；另将 la 非对齐模拟成功改报
新增的 Absorbed（与未分类异常区分）。**不得直接编辑
~/.cargo/registry**（不进版本控制、会被缓存事件静默还原）。
上游 PR（Byte-OS/polyhal，MIT）待提——补丁已写好，成本近零。

## 3. task 契约（本节为权威文本；`kernel/src/task/mod.rs` 头部只留摘要）

执行模型：用户态唯一入口 run_user_task，续体暂存于每核槽（rv
sscratch / la SAVE0）。两不变量：进用户态的内核栈在整个用户态期间
存活；每核同时至多一个用户态会话。栈转移只发生在 trap 返回与
context_switch。PC 推进语义归 HAL（断点 +2 由 polyhal 做、syscall 由
syscall_ok 恰好一次）。

中断与抢占：内核态一律关中断；中断只在用户态与 idle 等待开启。
抢占只发生在用户态逃逸点；内核路径不可抢占，内核任务协作让出。
时钟信号不丢失（挂起到边界送达）。trap 回调不取锁。

数据模型：Task（内核栈+KContext+身体+pid）与 ProcessRecord
（地址空间+退出信息，静态注册表）分离，为线程预留。地址空间只住
注册表不进 Task；实现中发现静态注册表同样要求 Send，故由 mm 提供
LocalSpace 单核凭证（unsafe impl Send 断言集中在不变量归属地 mm，
SMP 化时欠账集中于此）。pid 递增不复用，孵化失败允许空洞。
CURRENT（percpu，以整数存址绕开裸指针 !Send）是身份唯一来源。

生命周期：本轮无 fork ⇒ 无父子 ⇒ 无 wait/僵尸，**退出即全回收**。
exit(n) 码为 n；被致命异常杀死以 128+11 占位（Linux 编码进 wait
status 位域，此为记录在案的偏差，wait 实现时统一）。

时间片：固定 1 tick 轮转（TICK_MS=100），无优先级；切入刷新
slice_tick，逃逸点比较判定。

孵化时机：rv 初始 TrapFrame 依赖开中断稳态（SPP=0/SPIE=1），
spawn 必须发生在 task::run 关中断之前；spawn 内有断言兜底。

syscall 框架协议：内部一律 Result<_, Errno>，边界统一转负值；
Flow（Continue/Yield/Exited）是调用对执行流的全部影响——阻塞类
调用向运行循环声明让出意图而非内核自旋，是"阻塞即让出"协议的
最小实例。现支持 write/exit/sched_yield/getpid，其余 ENOSYS。

锁调试（sync.rs，feature `lock_debug`，selftest 档启用）：单核关中断
内核中 try_lock 失败即 bug（持锁跨调度），立即报告；切换入口断言
持锁深度为零（might_sleep 内核版）；锁序 SCHED → REGISTRY → FRAME。

已知妥协：缺陷 #5/#7 已由 vendor 补丁修复，事件侧信道（percpu 槽）
已移除——运行循环直接按 run_user_task 返回的完整 TrapType 处置：
SysCall 经 cx.from_user() 判来源；Absorbed（la 非对齐模拟成功）继续
执行；Unhandled 与各异常类来自用户则终止任务。残留：#8（polyhal
本体 percpu，见 §2）与 la idle 指令未封装。

### task 欠账

- 内核栈虚拟窗口 + 底部保护页：需 rv 内核共享页表窗口条目 + la PGDL
  映射 + 既有用户页表的同步协议；当前直映无保护（mm/kstack.rs）。
- 阻塞/唤醒原语：sleep/wakeup，pipe 与未来 fs 的地基；引入后
  idle 的"队列空即全部退出"判定需重写。
- fork/exec/wait/僵尸语义、退出码 wait status 编码。
- exec 栈内容构造（argv/envp/auxv）。
- 锁序图（lockdep 式环检测）。
- polyhal 本体 vendor（#8 修复）；la idle 指令封装（当前 idle 自旋等钟）。

### 非目标（团队决定不做，区别于"欠账"）

**SMP/多核不做。** 与之相关的不变量在单核下各有职责、全部保留：
!Send/LocalSpace（所有权边界与静态容器约束）、percpu（访问形态）、
全量 TLB flush（正确性优先）。若将来重开多核，以下设计须重新审视：
TLB shootdown 协议、调度器与注册表的单核假设、锁序与 irq-off 模型、
页表全量刷新策略。不为想象中的 SMP 预留任何参数化或间接层——
可扩展性的证明是重构成本低（不变量清晰），不是预留钩子。

## 4. syscall 与用户 ABI 语义偏差

语义基线是 man 2（调用号与寄存器约定按 riscv64/loongarch64 通用
UAPI：a7=调用号、a0..a5=参数、a0=返回）。框架协议：内核内部一律
`Result<_, Errno>`、ABI 边界统一转负 errno；`Flow`
（Continue/Yield/Exited）是调用对执行流的全部影响——阻塞类调用向
运行循环声明让出意图而非内核自旋，是"阻塞即让出"协议的最小实例。

与 Linux 的已登记偏差：
- write：仅 fd=1/2 直通控制台；不做部分写（Linux 允许先写部分再
  EFAULT）；len=0 只查 fd 返回 0（与 Linux 一致）；无文件偏移。
- exit：本轮无 wait/僵尸，退出即全回收，退出码仅记录于注册表；
  被致命异常杀死以 128+11 占位（Linux 编码进 wait status 位域，
  wait 实现时统一）。
- sched_yield：单核轮转，让出后可能立即被再次调度（语义兼容）。
- getpid：总成功。
- 其余调用号一律 ENOSYS；fd 表、文件框架、信号均不存在。
- ELF 加载：仅 ET_EXEC 静态；段页级重叠/越界/侵入栈保护区拒绝；
  不处理对齐差异、note 段、auxv。

## 5. sync 锁模型（DebugMutex，feature `lock_debug`）

前提：内核态一律关中断（见 §3），单核上不存在"另一执行流持锁"的
合法状态——try_lock 失败即 bug（持锁跨 context_switch），立即报告，
不做超时等待。提供的检查：持锁者与获取点（#[track_caller]）、
percpu 持锁深度、调度切换入口断言深度为零（might_sleep 内核版）。
锁序 SCHED → REGISTRY → FRAME，任何路径不得反向持有。release 构建
零开销。欠账：锁序图（lockdep 式环检测）、SMP 化时全面重审。

## 6. 自检清单与验证入口

### 自检注释规范

所有自检代码的注释以 `自检：` 开头，写明两件事：**验证的不变量**、
**运行时机**（每次启动 / 仅 selftest 档）。自检测的是不变量而不是
功能清单；新增自检时同步登记本表。

### 自检清单

| 位置 | 不变量 | 运行时机 |
|---|---|---|
| main.rs（ebreak/BREAK_TICKS） | trap 回调链路：断点恰好送达一次 | 每次启动 |
| main.rs（BOOT_TICKS 等待） | 时钟中断持续到达 | 每次启动 |
| mm/mod.rs::init | 帧账本：超量申请被拒且不改变空闲数 | 每次启动 |
| mm/self_test.rs | 页所有权/区间分裂/权限/边界/释放守恒 | 每次启动 |
| task/mod.rs::run（帧守恒断言） | 全部任务退出后帧统计回到基线（覆盖 kstack 与用户空间回收） | 每次启动 |
| task/mod.rs::spawn_oom_probe | 孵化 OOM 无副作用：失败不改帧数、不登记 | 仅 selftest 档 |
| mm/frame.rs（cfg(debug_assertions) 预算注入） | 逐点 OOM 失败路径不变量 | 仅 selftest 档 |

### 验证入口

- `make run-rv` / `make run-la`：release，七任务验收（kthread A/B
  交错、hello、sched×2 交错+抢占、check 正常+被杀路径、ill 异常类
  终止——rv IllegalInstruction / la Unhandled(ADEF)），末尾帧守恒
  断言与逐进程汇总。
- `make selftest-rv` / `make selftest-la`：selftest 档（debug 断言 +
  lock_debug + LOG=info），额外启用 OOM 注入自检与调试锁检查。
  注意：polyhal 缺陷 #8 使本档需 `-Zub-checks=no`（Makefile 已内置）。
