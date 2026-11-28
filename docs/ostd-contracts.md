# OuroOS ostd 契约与已知缺陷

本文档是 OuroOS 框内核（frame kernel）设计的权威说明：HAL 只提供
原语，mm/task/syscall 框架层逐步提供带不变量的安全服务。当前安全
边界限于已列出的接口；其余上层模块与第三方代码仍需单独审查。

文档只记录三类内容，不记录开发或审查过程：

1. **契约**：框架层保证什么、不变量是什么（§1–§3）。
2. **对照**：与 Linux 的语义差异（§4、§6）；§5 是跨子系统的锁模型。
3. **记录**：已兑现项、已知缺陷与欠账（各节表格、§8）。

维护约定：

- 契约条目变更与代码同 PR。
- 欠账解决后从欠账表删除，并在对应节的“已兑现”表补一行（没有该
  表时新建）。
- 代码注释只做介绍，不承载设计决策（AGENTS.md §6）。
- 与 Linux 语义不同的条目必须在“性质”一栏标明归属：设计要写明理由和代价；
  行为错误的列入 §4.4 的待修缺陷表；未实现的列入欠账。只描述做法而没有给出
  理由的条目不得称为设计。

## 0. 总览

| 子系统 | 权威内容 | 主要实现 |
|---|---|---|
| mm | §1 不变量与失败模型 | `kernel/src/mm/` |
| polyhal 边界 | §2 可用原语与缺陷 | `third_party/polyhal-trap/` |
| task | §3 执行、调度、生命周期 | `kernel/src/task/` |
| 信号 | §3.4/§3.5/§4.5 投递模型与偏差 | `kernel/src/task/signal.rs`、`kernel/src/sigframe/`、`kernel/src/syscall/signal.rs` |
| syscall | §4 Linux ABI 对照 | `kernel/src/syscall/` |
| sync | §5 锁模型与锁序 | `kernel/src/sync.rs` |
| fs | §6 结构、挂载、偏差 | `kernel/src/fs/`、`kernel/src/drivers/` |

## 1. mm 契约

### 1.1 分层

| 层 | 职责 | 代码 |
|---|---|---|
| region | 物理账本、保留区，唯一登记入口 | `mm/region.rs` |
| frame | 位图分配器、`OwnedFrame` 所有权 | `mm/frame.rs` |
| page_table / arch | Sv39 / LA 三层 PTE、切换、TLB | `mm/page_table.rs`、`mm/arch.rs` |
| address_space | 区域期望权限 + 页清单所有权 | `mm/address_space.rs` |
| user_access | 校验后经直映复制 | `mm/user_access.rs` |

### 1.1.1 区域调整与驻留查询

- ELF 先在临时地址空间构造，再以替代页表一次性安装；合法的页内偏移按文件字节交集复制，未覆盖部分清零。失败时已有映射与数据不变。
- `mremap`（216）支持单个同权限区域中的非零区间扩缩、MAYMOVE、FIXED。搬移保留页所有权及共享引用；新增匿名私有页清零。替代页表、区域和数据页全部准备成功后提交；失败保留源区间和目标区间。
- 文件区域可扩展到 EOF 之后，只保留文件身份和页偏移；访问时以文件当前长度判定。关闭 fd、unlink 不丢失映射。共享映射可以通过零旧长度建立别名；等长 DONTUNMAP 保留源区间，源私有匿名页重新取零，文件与共享匿名页按后备取数。不支持跨不同属性区域搬移。
- `mincore`（232）查询驻留位。文件映射按 inode 和页偏移查询共享缓存，同一文件页的别名可在首次访问前报告驻留。查询本身不会调页。PROT_NONE 仍属于映射。查询空洞返回 ENOMEM，未对齐起点返回 EINVAL，结果缓冲区不可写返回 EFAULT。复制前验证完整结果缓冲区。
- MAP_SHARED | MAP_ANONYMOUS 使用按页号索引的共享对象，首次访问时分配物理页；fork 保留共享，最后一个映射销毁才释放，固定搬移和收缩保持引用。fork 不为共享页额外分配临时私有页。共享匿名区可以扩展，重叠的别名仍指向同一对象页。
- 私有匿名 mmap、brk 与文件映射按需分配。用户缺页和内核复制共用 ensure_access；共享匿名也按需分配，ELF 装载页预分配。fork 后，已驻留的私有匿名页、堆页和用户栈页采用写时复制（copy-on-write，COW）。
- 语义依据：[mremap(2)](https://man7.org/linux/man-pages/man2/mremap.2.html)、[mincore(2)](https://man7.org/linux/man-pages/man2/mincore.2.html)。实现独立编写，未复制 Linux 代码。

### 1.2 十律

| 不变量 | 落地方式 |
|---|---|
| 物理内存唯一入口 | 只有 region → frame 登记；裸 `frame_alloc` 仅 kernel_pt、kstack、DMA 三处受限适配 |
| 唯一释放凭证 | `OwnedFrame` 不可 Clone；释放前必须撤销映射并刷 TLB |
| 分配即清零 | `OwnedFrame::new` 清零；kstack/DMA 显式清零 |
| 拥有页字节访问 | `OwnedFrame::read/write/copy_from` 校验页内范围并封装直映指针；`address_space::init_elf_page` 提供 ELF 初始页写入接口 |
| 期望权限 ≠ 实际权限 | 两架构无 NX；`mprotect` 接受读写权限变更，可访问页实际可执行 |
| PROT_NONE 占坑 | 保留数据页所有权，硬件叶项清零 |
| 事务性 | 失败与未调用不可区分；map/replace/map_backed/deep_copy/exec 先备齐后提交 |
| 两遍式用户访问 | 先整段校验再复制；失败不部分写；用户指针不成引用 |
| 地址空间 !Send | `PhantomData`；`LocalSpace` 是注册表用的单核凭证 |
| TLB 全量刷 | map/protect/unmap/switch 都 `flush_all` |
| 零堆依赖零 panic | mm 元数据全部 try_reserve；整内核用户路径的堆分配见 §1.5 |

### 1.3 补充约定

| 项 | 约定 |
|---|---|
| 位图而非 buddy | buddy 空闲链表依赖堆；位图 + try_reserve 使运行期帧分配零堆依赖 |
| 零页保留 | 物理 <0x1000 永不分配，空 PTE 才可安全表示“从未映射” |
| region 保留区 | FDT 保留、内核镜像、固件、对齐碎片有类型化来源；HAL 启动占用记 HalBoot |
| 内核堆 | 固定 32 MiB，TODO 在 `allocator.rs`；mm 元数据 try_reserve |
| user_access 并发前提 | 单核、内核不可抢占，复制期间无并发 munmap |
| kstack | 每栈独占窗口槽（低地址 guard + 8 栈页）；窗口下级表在全部地址空间共享，guard 不映射；rv 复制窗口根项，la 自建仅含窗口项的内核根；数据帧连续以支持跨页 DMA |
| ELF | 静态小端 ELF64，支持 ET_EXEC 与 ET_DYN；差异见 §4 |

### 1.4 已兑现

| 项 | 说明 |
|---|---|
| brk 字节级记账 | `address_space::brk` |
| mmap 空洞 / MAP_FIXED | `find_free`、`replace_region` 事务替换 |
| fork | `deep_copy` 完成子地址空间后，将父子共享的私有匿名、堆、栈、ELF 段与私有文件映射驻留页统一设为只读。首次写入时分配私有副本；只剩一个引用时恢复写权限。 |
| exec 先建后切 | 新空间含 argv/envp/auxv，成功才替换 |
| 页字节访问收口 | 拥有页复制及 ELF 初始页写入由 mm 封装；`elf.rs`、`fs/cache.rs`、`syscall/memory.rs`、`task/user_task.rs`、`task/exec.rs`、`task/task.rs` 拒绝 `unsafe` |
| MAP_SHARED 文件页缓存 | `fs/cache.rs`；索引独立持有页，比较有效字节和上次写回基线，失败后可重试 |
| 内核栈虚拟窗口 + 底部保护页 | `mm/kstack.rs`；16 GiB 起 32 MiB 共享窗口，槽 = guard + 8 栈页（可容纳 910 个并发任务），逐页映射，溢出即页错误 |
### 1.5 欠账

| 项 | 现状 / 计划 |
|---|---|
| 直映硬化 | 直映区 base canary + 去可执行权限；未实现 |
| 数据页/区域线性扫描 | 区域和页清单均按地址排序，查找走二分；fork/remap 仍逐页遍历 |
| 通用页缓存 / swap / 远端 TLB | 未做；MAP_SHARED 文件页缓存已实现，不是通用读写页缓存 |
| 全局堆失败策略 | 32 MiB 固定；pipe 扩容、rsext4 的 `alloc::vec!` 不可失败，可耗尽→panic；需要统一 OOM 策略 |

## 2. polyhal 边界

### 2.1 使用边界（原语库，不是框架）

| 能力 | 用法 |
|---|---|
| 页表 | 只用 `PAGE_SIZE`、`MappingFlags`、`PageTable::current/root`、`TLB`；页表服务自建（缺陷 1/2） |
| 上下文切换 | `kernel/hal.rs` 在 PolyHAL `KContext` + `context_switch` 外保存内核 FP 现场；页表切换自管，不用 `context_switch_pt` |
| LA TLB refill | 自写向量（QEMU 10.0.2 LDPTE 丢 NR/NX）；SAVE3 暂存 t1 |
| 架构辅助 | `fence_icache` 由框架封装；`read_current_tp` 与单核 idle 等待由 `kernel/hal.rs` 封装（la 自旋等钟） |

### 2.2 已知缺陷

| # | 缺陷 | 对策 / 状态 |
|---|---|---|
| 1 | map_page 分配的页表页不清零 | 弃用其页表 API，自建 |
| 2 | translate 叶子级不查 PTE 有效性 | 弃用，自建 translate |
| 3 | SysCall 不推进 PC | 运行循环恰好一次 syscall_ok |
| 4 | 内核 SBI ecall 也表现为 SysCall | 用 `from_user` 判来源；事件侧信道已移除 |
| 5 | EscapeReason 有损（用户异常只剩 NoReason） | 已修：vendor 让 `run_user_task` 返回完整 TrapType |
| 6 | la 无法表达撤 X（无 NX） | 团队决定不实现；translate 报实际权限 |
| 7 | la 未分类异常在 HAL 层直接 panic | 分类器已修：新增 `TrapType::Unhandled` 交 OS；模拟器/中断见 #9/#10 |
| 8 | 启动期一处 ptr::add 越界 | 已定位：polyhal 本体 percpu（rv，`percpu/mod.rs:88`）把 VIRT_ADDR_START 当字节偏移，数学正确但技术 UB；不在 vendor 范围，selftest 用 `-Zub-checks=no` 规避 |
| 9 | la 非对齐模拟内部 panic / 裸用户访存 | 已修：HAL 只报告 BADV；OS 经用户地址空间权限校验后模拟原整数指令范围，失败终止用户任务 |
| 10 | la 未知中断在 HAL 层 panic | 已修：返回 `TrapType::Irq` 交 OS；实际外设 IRQ 的应答与屏蔽仍待驱动接入 |
| 11 | rv 未知 cause unwrap 与 LoadFault 地址特判 panic | 已修：未知 cause 报 `Unhandled`；LoadFault 统一作为用户或内核页错误交 OS 判来源 |
| 12 | 用户 FP 现场不完整 / 内核 FP 跨切换不保留 | 已修：rv/la 陷阱边界保存完整用户 FP、控制状态与内核 FP；框架切换包装器在原 KContext 外保存内核 FP |
| — | la 缺 `TrapFrame::from_user` | 已修：vendor 补齐，OS 侧统一用 `from_user` |
| 13 | rv 时钟频率写死 12.5 MHz，QEMU virt 的设备树是 10 MHz，来宾时间比真实时间慢 25% | 已修：vendor polyhal 本体，按设备树 `timebase-frequency` 换算 |

### 2.3 vendor 补丁

polyhal 与 polyhal-trap 0.4.0 整 crate vendor 至 `third_party/polyhal`
与 `third_party/polyhal-trap`，根 `[patch.crates-io]` 指向本地；
polyhal-boot 仍走 crates.io。polyhal-trap 的补丁：#5 TrapType 直达、
#7 Unhandled 转交、la `from_user` 补齐、la 非对齐事件交 OS 安全模拟、
完整 FP 现场与显式用户返回状态、用户断点保留故障 PC。polyhal 的补丁：
#13 rv 时钟频率读设备树。清单与升级回归见各目录 README；不得直接编辑
`~/.cargo/registry`。上游 PR（MIT）待提。

## 3. task 契约

### 3.1 执行模型

- 用户态唯一入口 `run_user_task`；续体在每核槽（rv `sscratch`；la
  SAVE0 存内核栈指针、SAVE1 存 TrapFrame 地址）。
- 不变量：用户态期间内核栈存活；每核至多一个用户态会话。栈转移只
  在 trap 返回与 `context_switch`。
- 用户页表不在 `context_switch` 内切换：每轮进入用户态前激活本任务
  空间。内核任务与切换窗口内的代码运行在切换时仍激活的页表上
  （通常是上一任务；退出路径已切回内核根），依赖高半区一致（rv 复
  制根项，la 走 DMW）；这些路径不得访问用户低半区。
- 用户断点的信号地址和信号帧 PC 都指向断点指令。内核断点由 HAL 按指令长度推进，系统调用由 `syscall_ok` 推进一次。
- 首次入口在调度器锁下取出 `TaskBody`；用户 TrapFrame 和 nanosleep
  截止时间由该任务内核栈上的运行循环局部持有，调度器不借用用户现场。

### 3.2 中断、抢占、时间片

| 项 | 约定 |
|---|---|
| 中断 | 任务时代内核态关中断；用户态与 idle 等待开；启动阶段（`IRQ::int_enable` 到 `task::run`）是例外，仅时钟到达 |
| 抢占 | 只发生在用户态逃逸点；内核路径不可抢占，内核任务协作让出 |
| 时钟 | 信号不丢失，挂起至少到调度边界送达；trap 回调不取锁 |
| 时间片 | 固定 10 毫秒（TICK_MS=10）按时间计算；切入刷新 `slice_end`，到期轮转；等待中不占就绪队列。就绪表按调度策略选择：实时策略（SCHED_FIFO、SCHED_RR）高于普通策略（SCHED_OTHER、SCHED_BATCH），SCHED_IDLE 最低；实时策略之间优先级数值大者先运行，同等级按就绪先后轮转。就绪表出现等级更高的任务时，当前任务在回用户态前的调度检查点让出 |
| 定时器 | 拍每 TICK_MS 一次；当前任务的时间片终点与等待表里最早的到期时刻会提前触发时钟中断，到期者在随后的调度边界回到就绪表；中断处理不取锁，只记事件与重装定时器 |

### 3.3 数据模型

| 对象 | 内容 | 位置 |
|---|---|---|
| Task | 内核栈 + 私有 KContext + 首次入口身体 + pid | 调度器 Box；身体首次取出后为 None |
| ProcessRecord | 地址空间 + fs + 退出信息 + 父子关系 + 进程组与会话 + 组级信号状态 | 静态 REGISTRY，按线程组登记 |
| ThreadRecord | tid、所属线程组、屏蔽字与备用栈、清 tid 地址 | 静态 REGISTRY 的 threads 表；每个线程一条，单线程进程里 tid 等于 pid |
| SignalGroup / ThreadSig | 组级：处置表、pending、信息槽；线程级：屏蔽字、备用栈 | 分别为 `ProcessRecord.signal` 与 `ThreadRecord.signal`；线程定向挂起与组定向挂起经同一唤醒通道处理 |
| CURRENT | 当前任务地址（整数存址，绕开裸指针 !Send） | percpu |

Task 与 ProcessRecord 分离；地址空间只住注册表。pid
递增不复用，孵化失败允许空洞。`LocalSpace` 是 mm 提供的单核凭证，
`unsafe impl Send` 的依据集中在 mm，SMP 化时欠账也集中于此。
CURRENT 记录当前任务地址；调度器的 `current` Box 持有实体，切换时
核对两者一致。KContext 只向调度器提供裸地址，用户运行循环不得改写。

### 3.4 生命周期

- wait 收割即删；注册表只存活跃进程与未收割僵尸；重复 wait 得
  ECHILD。
- 孤儿过继内核 init；已退出的孤儿即收，活孤儿随后退出时即收，运行时间丢弃。
- 退出 Task 的内核栈先进入 dead 表，切到其他任务或 idle 栈后立即回收。
- 线程退出只回收自己的线程记录与内核栈，清零自己的 `clear_child_tid` 并唤醒该地址上的一个等待者；组长先退出时组内其他线程继续运行，最后一个线程退出才登记组终态并产生 SIGCHLD。
- 线程组退出由 exit_group 或默认动作为 Term/Core 的信号触发，与 Linux 的 `do_group_exit` 一致：登记组终态、删除组内全部线程记录、丢弃组内其他就绪与等待任务，当前任务随后切走。
- 终态行积攒到任务时代结束统一输出，不混入用户程序的测试输出；
  积攒预留失败时静默丢弃该行（终态汇总可能缺项，无日志、无计数）——
  降级路径：异常退出可能被掩盖，需失败计数与上报。
- 终态为 `ExitInfo::{Exited(n), Signaled{sig, fault}}`：exit(n) 为
  `Exited(n)`；死于信号（kill/默认动作/致命异常映射，见 §4.5）为
  `Signaled`，fault 携带硬件异常细节供终态报告。wait status 编码：
  `Exited(n) → (n&255)<<8`、`Signaled{sig} → sig`（WIFSIGNALED/WTERMSIG）；
  无 core 位（未实现 core dump，见 §4.5）。
- 子进程退出时向活跃父进程产生 SIGCHLD（槽含 CLD_EXITED/CLD_KILLED、
  子 pid 与状态）；父处置 IGN 或 SA_NOCLDWAIT 时不产生僵尸，记录即收，
  运行时间并入父（与收割口径一致）。自动收割不抑制通知：父装 handler
  时仍照常投递（含 SA_NOCLDWAIT 组合），IGN/DFL-Ign 由处置过滤丢弃；
  孤儿过继 init 的路径维持即收。

### 3.5 等待与唤醒

- `Flow::Wait(WaitReason::Deadline/Children/Pipe/PipeId/Signal/PollUntil/Futex/Vfork/Ipc)`：
  park 进等待
  表并切走，保留 syscall PC；醒来重执行重查条件（Mesa 风格）。
- Deadline 由调度边界按硬件时钟扫描；Children/Pipe/Signal/Ipc 由事件方置
  无锁原子标志（Pipe 与 Ipc 均含定向槽队列，槽满退回广播），在调度边界统一消费，避免在 REGISTRY 内反向取
  SCHED。Signal 标志在信号实际入队后置位；drain 持 REGISTRY 一次按
  "pending & !blocked 非空"精确判定等待者（SCHED→REGISTRY 唯一嵌套点，
  见 §5），集合外信号假唤醒由唤醒点重查消化，无害。
- 阻塞 syscall 的信号打断在 park 前后做两次快路径决策（第一次可落
  睡、睡醒后补一次不落睡重查）：sigsuspend/sigtimedwait/nanosleep 被
  handler 类信号打断一律以 -EINTR 完成，pipe/wait4 按 SA_RESTART 分
  重启与 -EINTR，ppoll 不重启；语义规范与偏差见 §4.5。
- 孵化预留 ready/waiting 各自容纳全部存活任务的容量；集中唤醒不分配。
- 私有 futex 以线程组和虚拟地址为键。共享匿名映射按对象和字节偏移匹配，共享文件映射按 inode 和文件偏移匹配。显式唤醒后 WAIT 返回零。重排队保留位掩码及绝对截止时间，返回唤醒和迁移的等待者总数。超时和显式唤醒以先移出等待队列的事件为准。
- init 在仍有活跃进程时等待 Children 事件，醒后重查条件。
- 等待表满时 park 退化为就绪让出；就绪空而等待非空时 idle 等时钟；
  互等即永久等待（QEMU 超时兜底）。

### 3.6 syscall 框架

内部一律 `Result<_, Errno>`，边界统一转负值。`Flow`（Continue /
Yield / Wait / Process / SigReturn / Exited / ExitedGroup）是调用对执行流的
全部影响。`Process` 表示需在 REGISTRY 借用解除后由运行循环处理（fork/
exec/wait4/nanosleep/times/kill/tgkill/sigsuspend/sigtimedwait/
sigqueueinfo）；`SigReturn` 表示用户现场已从信号帧整体恢复（SEPC 即
真实返回点），跳过 syscall PC 推进；非重入锁禁止在 dispatch 锁内
调用。

### 3.7 锁调试

见 §5。切换入口始终断言 DebugMutex 持锁深度为零；lock_debug 下
try_lock 失败即报告“持锁跨调度”。

### 3.8 已知妥协、欠账与非目标

| 项 | 状态 |
|---|---|
| #5/#7 分类器 | vendor 已修；模拟器内部/未知中断见 §2 #9/#10 |
| #8 polyhal percpu | 未修；selftest 用 `-Zub-checks=no` |
| la idle | 自旋等钟；Deadline 依赖硬件时钟读数，不阻塞正确性。取舍，理由待补，见 §4.4 |
| 进程间输出交错 | 时间片在两次 `write` 之间到期时让出，另一进程的输出会插入同一行。basic 的 `test_pipe` 自带 `printf` 一行发三次 `write`，判分要求整行完整，本机出现率约 6%，每次少 3 分。暂不处理 |

| 欠账 | 现状 / 计划 |
|---|---|
| pipe/子进程唤醒的精确订阅 | 单管道阻塞读写已改为按管道实例号定向唤醒（`WaitReason::PipeId`，16 槽无锁原子队列，槽满退回全局广播）；`ppoll`/`pselect6`、套接字与子进程退出仍用宽松匹配 + Mesa 重执行，新增状态变化须补 `request_pipe_wake`/`request_pipe_id_wake` |
| 锁序图 | lockdep 式环检测 |
| polyhal 本体 vendor | 修 #8；la idle 封装 |

**非目标：SMP/多核不做。** 单核下保留 !Send/LocalSpace、percpu、
全量 TLB flush 等不变量。若重开多核，须重审 TLB shootdown、调度器
与注册表的单核假设、锁序与 irq-off 模型、页表刷新策略；不为想象
中的 SMP 预留参数化或间接层。

## 4. syscall 与 Linux ABI 对照

### 4.1 框架协议

基线是 man 2 与 riscv64/loongarch64 通用 UAPI：a7=调用号，a0..a5=
参数，a0=结果或负 errno。内部 `Result<_, Errno>`，边界统一转负值；
`Flow` 见 §3.6。

### 4.2 已实现

| 组 | 调用 | 实现 |
|---|---|---|
| 文件 | setxattr、lsetxattr、fsetxattr、getxattr、lgetxattr、fgetxattr、listxattr、llistxattr、flistxattr、removexattr、lremovexattr、fremovexattr、getcwd、dup、dup3、fcntl、flock、mkdirat、mknodat、unlinkat、symlinkat、linkat、mount、umount2、chdir、fchdir、openat、close、pipe2、getdents64、lseek、read、write、readv、writev、pread64、pwrite64、preadv、pwritev、sendfile、vmsplice、splice、tee、copy_file_range、fadvise64、readlinkat、readahead、statfs、fstatfs、newfstatat、fstat、sync、fsync、statx、umask、utimensat、renameat、renameat2、truncate、ftruncate、fchmodat、fchmod、fchownat、fchown、eventfd2、signalfd4、timerfd_create、timerfd_settime、timerfd_gettime、epoll_create1、epoll_ctl、epoll_pwait、epoll_pwait2、inotify_init1、inotify_add_watch、inotify_rm_watch、io_setup、io_destroy、io_submit、io_cancel、io_getevents、io_pgetevents | `syscall/fs.rs`、`fs/xattr.rs`、`fs/inotify.rs`、`fs/aio.rs`、`fs/context.rs`、`fs/locks.rs`、`fs/event.rs`、`syscall/mod.rs`、`task::process_call` |
| futex | WAIT、WAKE、REQUEUE、CMP_REQUEUE、WAIT_BITSET、WAKE_BITSET；PRIVATE 标志按线程组和虚拟地址匹配，共享操作按映射后备匹配，私有映射在写时复制后保留等待键；普通等待的相对超时与 bitset 等待的绝对超时都换算成单调时刻；被信号打断返回 EINTR；支持 set_robust_list/get_robust_list 与线程退出健壮锁清理 | WAKE_OP 与 PI 系列返回 ENOSYS；线程退出先遍历 robust_list 置 FUTEX_OWNER_DIED 并唤醒等待者，再清零 `clear_child_tid` 并唤醒等待者 |
| vfork | 接受 CLONE_VM 与 CLONE_VFORK 加 SIGCHLD：子进程按复制地址空间创建，父进程挂起到子进程 exec 或退出后返回子进程号；posix_spawn 可用 | 缺陷 13：子进程按复制地址空间创建，不与父进程共享内存，见 §4.4 |
| 进程 | exit、nanosleep、sched_yield、times、getpid、getppid、gettid、getuid、geteuid、getgid、getegid、getresuid、getresgid、getgroups、setuid、setgid、setreuid、setregid、setresuid、setresgid、setfsuid、setfsgid、setgroups、setpgid、getpgid、setsid、getsid、clone、execve、wait4、waitid、capget、capset、pselect6、ppoll、getitimer、setitimer、timer_create、timer_gettime、timer_getoverrun、timer_settime、timer_delete、clock_settime、settimeofday、getrlimit、setrlimit、prlimit64、prctl、personality、ioprio_set、ioprio_get、process_vm_readv、process_vm_writev | `task::process_call`、`task::posix_timer` |
| 资源统计 | getrusage | `task::process_call` |
| 调度查询与亲和 | sched_getscheduler、sched_getparam、sched_setscheduler、sched_setparam、sched_setattr、sched_getattr、sched_get_priority_max、sched_get_priority_min、sched_rr_get_interval、sched_getaffinity、sched_setaffinity | `task::process_call` |
| 访问检查/日志 | faccessat、faccessat2、syslog(klogctl) | `syscall/fs.rs`、`dmesg.rs` |
| 设备/随机 | ioctl(29)（RTC 设备的 RTC_RD_TIME 与管道/普通文件的 FIONREAD，其余 ENOTTY）、getrandom(278)、/dev/urandom 与 /dev/random | `fs::context::ioctl`、`drivers/rtc.rs`、`entropy::fill_random` |
| 信号 | kill、tkill、tgkill、rt_sigaction、rt_sigprocmask、rt_sigpending、rt_sigsuspend、rt_sigtimedwait、rt_sigqueueinfo、rt_tgsigqueueinfo、sigaltstack、rt_sigreturn | `syscall/signal.rs`、`task/signal.rs`、`sigframe/`（契约与偏差见 §4.5） |
| 网络 | socket、socketpair、bind、listen、accept、accept4、connect、getsockname、getpeername、sendto、recvfrom、sendmsg、recvmsg、sendmmsg、recvmmsg、setsockopt、getsockopt、shutdown | `syscall/net.rs`、`net/mod.rs`（AF_INET 本地回环 UDP/TCP、AF_UNIX 匿名套接字对、SCM_RIGHTS 描述符传递与未连接 AF_UNIX 套接字） |
| 内存 | brk、mmap、munmap、mprotect、mremap、mincore、madvise、msync、锁页系列、shmget、shmctl、shmat、shmdt | `syscall/memory.rs`、`mm/shm.rs` |
| System V / POSIX IPC | msgget、msgctl、msgrcv、msgsnd、semget、semctl、semop、semtimedop、mq_open、mq_unlink、mq_timedsend、mq_timedreceive、mq_notify、mq_getsetattr | `ipc/msg.rs`、`ipc/sem.rs`、`ipc/mqueue.rs`、`task::process_call` |
| 其他 | uname、sethostname、setdomainname、getcpu、gettimeofday、set_tid_address(96) | `syscall/mod.rs` |
| 其余 | 未列出的调用号 | ENOSYS |

### 4.3 偏差对照

| 调用/类别 | 当前实现 | Linux 对照 / 说明 | 性质 |
|---|---|---|---|
| mknodat | 支持在 Ext4 线性目录创建普通文件（`S_IFREG`/0）、命名管道（`S_IFIFO`）、套接字节点（`S_IFSOCK`）与字符/块设备节点（`S_IFCHR`/`S_IFBLK`，非特权进程返回 `EPERM`，设备号按 Ext4 规范写入 `i_block`）；`/dev/` 下 `S_IFBLK` 保持内核块设备表登记供 `mount` 解析；非法文件类型返回 `EINVAL`；FAT 卷仅允许 `S_IFREG`，其余返回 `EOPNOTSUPP` | 打开 `S_IFIFO` 遵循 `fifo(7)` 语义（`O_RDWR` 不阻塞，`O_WRONLY\|O_NONBLOCK` 无读端返回 `ENXIO`，阻塞打开按两端会合唤醒）；打开 `S_IFCHR` 识别标准内存设备号 `1:3`/`1:5`/`1:8`/`1:9`，其余设备节点与 `S_IFSOCK` 返回 `ENXIO` | 语义兼容；未实现：除标准内存设备外的动态字符/块设备驱动绑定 |
| fchdir | 将当前工作目录切换到已打开的目录 FD（允许 `O_PATH` 目录 FD）；非目录 FD 返回 `ENOTDIR`，无效 FD 返回 `EBADF`，已删名目录返回 `ENOENT`；非特权进程（`euid != 0`）按目录属主/属组/其他执行位校验搜索权限，缺失返回 `EACCES` | 暂未接入补充组与 capabilities 校验 | 未实现：补充组与 CAP_DAC_OVERRIDE |
| faccessat/faccessat2 | 默认按真实 UID/GID 与补充组检查读、写、执行权限和沿途目录搜索权限；AT_EACCESS 沿用当前 fsuid/fsgid。支持 AT_SYMLINK_NOFOLLOW 与 AT_EMPTY_PATH，后者按 cwd 或 FD 的当前 inode 查询，含 O_PATH 和已删名文件。原始 faccessat 只有三个参数，不读取第四寄存器。 | 按属主、属组、其他用户的顺序选择权限位；选定 UID 为 0 时沿用特权规则，普通文件的 X_OK 仍要求至少一个执行位。根 Ext4 与辅助 Ext2 的只读状态拒绝普通文件、目录及链接的 W_OK；设备和 FIFO 不受此限制。身份选择和只读检查依据 Linux 6.12 fs/open.c、fs/namei.c。 | 未实现：ACL、细分 capabilities、immutable 与 noexec 挂载属性；沿用 UTF-8 路径及目录路径身份限制 |
| fchown/fchownat | Ext4 按 FD 或路径修改属主和属组，两个 ID 独立接受 -1 保留。支持 AT_SYMLINK_NOFOLLOW、空字符串配合 AT_EMPTY_PATH，以及已删名但仍打开的 inode。普通属主可保留原属主并改到原属组、文件系统组或补充组。 | 特权沿用进程有效 UID 为 0 的规则，普通属主按文件系统 UID 判断。暂未接入 CAP_CHOWN、目录搜索授权、FAT、虚拟对象或空指针形式的 AT_EMPTY_PATH。沿用后端 ctime、set-ID 位及日志更新规则。 | 缺陷 2；未实现 |
| fchmod/fchmodat | 保留 07777 权限位（含 setuid/setgid/sticky），类型位由 inode 持有；仅普通文件与目录可改。fchmod 按已打开对象的 inode 身份生效（rename/unlink 后仍有效，管道/procfs FD 返回 ENOENT）；fchmodat 按路径且总是跟随符号链接，不读取第四个参数，fchmodat2 未实现；FAT 卷返回 ENOTSUP | 通用调用表没有 chmod，libc 的 chmod 走 fchmodat；无属主校验与 ACL | 缺陷 2；未实现：ACL |
| syslog/klogctl | 按 man 2 action 编码：READ(2) 消耗式游标读取、READ_ALL(3) 全量、READ_CLEAR(4) 读后清空、CLEAR(5)、OPEN/CLOSE(0/1) 无操作返回 0、console 开关(6/7)无操作、SET_CONSOLE_LEVEL(8) 仅接受 1..=8 并记录（不变更实际输出）、SIZE_UNREAD(9)/SIZE_BUFFER(10) 返回未读/容量；其余 EINVAL | 日志环上限 8 KiB，只收集显式登记事件（启动报告/终态/panic），无内核分级日志 | 未实现：内核分级日志 |
| getrandom | 设备树 rng-seed 播种 ChaCha20 流（单次请求上限 64 KiB，可失败分配）；flags 仅接受 GRND_NONBLOCK/GRND_RANDOM；无种子时一律 EAGAIN（无合法阻塞唤醒来源），绝不以时间/常量伪造熵 | 缺少可信启动熵时 execve 返回 EIO，保留旧映像；启动阶段若因此无法创建任何用户任务，内核同步文件系统并关机。 | 设计：不伪造熵；未实现：等待熵就绪 |
| ioctl | 支持 `/dev/misc/rtc` 的 `RTC_RD_TIME` 、块设备的 BLKGETSIZE64 与管道/普通文件的 `FIONREAD`（`0x541B`，返回当前可读字节数 `i32`；cmd 按 `unsigned int` 截断比较）；其余命令与设备一律 ENOTTY | 终端 TCGETS/TCWINSZ、FIONBIO 等未实现（more 依赖的 isatty 降级为非终端） | 未实现 |
| read/write/readv/writev | 小读写（≤256 字节）使用栈缓冲免锁，大读写复用单槽 64 KiB 可失败堆缓冲区；向量描述符先复制到内核，最多 1024 项，总长度超过 ssize_t 返回 EINVAL；每次最多搬运 0x7ffff000 字节；遇短传输、EOF 或错误停止，已有进展时返回已完成长度 | 用户缓冲区按页交付，读只推进实际交付的偏移；完整调用持有打开文件锁；OOM 返回 ENOMEM，零长度不分配数据缓冲区 | 无偏差 |
| pread64/pwrite64/preadv/pwritev | 指定独立偏移，不修改共享文件偏移；负偏移 EINVAL，流式对象 ESPIPE；rv64/la64 原始向量定位 ABI 使用完整 pos_l，忽略 pos_h；O_APPEND 下定位写仍追加，与 Linux 已知行为一致 | 不支持 preadv2/pwritev2；Ext4 文件超限 EFBIG 独立于参数过长 E2BIG；部分错误仍按已完成字节数返回 | 未实现：preadv2/pwritev2 |
| fcntl / flock | 支持 F_DUPFD/F_DUPFD_CLOEXEC、F_GETFD/F_SETFD、F_GETFL/F_SETFL、F_GETPIPE_SZ/F_SETPIPE_SZ，以及 POSIX 记录锁（F_GETLK/F_SETLK/F_SETLKW，归属线程组，关闭同文件任一 FD 或进程退出自动释放）、OFD 记录锁（F_OFD_GETLK/F_OFD_SETLK/F_OFD_SETLKW，归属打开文件描述，最后引用关闭释放）与 BSD `flock(32)`（LOCK_SH/LOCK_EX/LOCK_UN/LOCK_NB，归属打开文件描述）；区间支持拆分与合并，阻塞冲突经调度器等待唤醒；从下界选最低空闲 FD，受进程 RLIMIT_NOFILE（默认软 1024 / 硬 4096）约束；cloexec 属于描述符，偏移与状态由 dup/fork 共享；F_SETPIPE_SZ 按页向上对齐并限 4 KiB..1 MiB，低于已缓冲字节数返回 EBUSY，非管道返回 EINVAL | F_SETFL 仅修改 O_APPEND/O_NONBLOCK，访问模式、创建与同步标志不变；请求 O_ASYNC/O_DIRECT/O_NOATIME 返回 EOPNOTSUPP 且不修改状态；未知命令返回 EINVAL；尚未实现死锁环检测（EDEADLK）、强制锁、F_SETLEASE 与异步通知 | 未实现：死锁环检测、强制锁、异步通知 |
| pipe | 默认容量 64 KiB（可经 F_SETPIPE_SZ 在 4 KiB..1 MiB 调整）；遵循 POSIX PIPE_BUF（4096 字节）原子写语义，超过 4096 字节的写请求在缓冲有余量时允许部分写入；读路径通过 `VecDeque::as_slices` 批量切片拷贝；读空或无空间时按实例定向等待，O_NONBLOCK 返回 EAGAIN；总长不超过 4 KiB 的 writev 合并后写入，空间不足不写入前缀；无读者返回 EPIPE | SIGPIPE 与 -EPIPE 并行产生同 Linux（§4.5，默认处置下写者死于信号、见不到 EPIPE）；运行期 VecDeque 扩容的不可失败分配仍待处理；复制失败只消费已交付数据 | 缺陷 6；欠账：扩容的不可失败分配 |
| wait4 | pid>0 指定孩子，-1 等任意孩子，0 等本进程组的孩子，<-1 等进程组 -pid 的孩子（pid==INT_MIN 返回 ESRCH）；无僵尸则阻塞，无孩子 ECHILD；WNOHANG 支持；status 按 ExitInfo：正常 `(code&255)<<8`、死于信号 `sig` | 语义接近；忽略 rusage；无 core 位 | 缺陷 4；未实现：core 位 |
| setpgid/getpgid/setsid/getsid | fork 继承进程组与会话，exec 保留；setpgid 只能作用于自身或尚未 exec 的同会话孩子，目标组须在同一会话，会话首领不能改组；setsid 以调用者为首领建立新会话与新进程组，调用者已是进程组首领时 EPERM | 无控制终端；孤儿进程组向停止成员发 SIGHUP/SIGCONT 的规则未实现 | 未实现：控制终端与孤儿进程组规则 |
| waitid | 支持 P_ALL、P_PID、P_PGID 与 WEXITED、WNOHANG、WNOWAIT；infop 填 si_signo、si_code、si_pid、si_status 与 CPU 时间；未指定 WNOHANG 且无僵尸时挂起；无匹配孩子 ECHILD | WSTOPPED 与 WCONTINUED 接受但不产生事件；第五参数 rusage 不填；infop 为 NULL 时返回子进程 pid | 缺陷 4、5；未实现：停止与继续事件 |
| getrusage | 支持 RUSAGE_SELF、RUSAGE_CHILDREN、RUSAGE_THREAD；ru_utime 与 ru_stime 取自任务记账，其余字段为 0 | 无 maxrss 与缺页统计；SIGCHLD 置 IGN 时自动收割的孩子，其时间仍计入 RUSAGE_CHILDREN | 缺陷 4 |
| prctl | 支持 `PR_SET_PDEATHSIG`/`PR_GET_PDEATHSIG`（父进程退出时向直接存活子进程投递信号，`fork` 清零）、`PR_SET_DUMPABLE`/`PR_GET_DUMPABLE`、`PR_SET_KEEPCAPS`/`PR_GET_KEEPCAPS`、`PR_SET_NAME`/`PR_GET_NAME`（16 字节 NUL 结尾进程名，`exec` 同步基名）、`PR_CAPBSET_READ`、`PR_SET_TIMERSLACK`/`PR_GET_TIMERSLACK`、`PR_SET_CHILD_SUBREAPER`/`PR_GET_CHILD_SUBREAPER`（孤儿与僵尸优先过继最近存活 subreaper 祖先，`fork` 清零）与 `PR_SET_NO_NEW_PRIVS`/`PR_GET_NO_NEW_PRIVS`（置位不可撤销，`fork`/`exec` 继承） | 其余选项（如 seccomp、cap_ambient、TSC/FP 模式）返回 EINVAL | 未实现：seccomp 与其余 prctl 选项 |
| sched_* 查询与亲和 | sched_setscheduler 与 sched_setparam 保存策略与优先级，并影响就绪表的选择：实时策略优先于普通策略，实时优先级数值大者先运行，SCHED_IDLE 最低；策略接受 SCHED_OTHER、SCHED_FIFO、SCHED_RR、SCHED_BATCH 与 SCHED_IDLE，实时策略的优先级限 1 到 99，其余策略必须为 0；fork、vfork 与 clone 产生的新任务继承创建者的策略、优先级与谦让值；sched_get_priority_max/min 对 SCHED_FIFO 与 SCHED_RR 返回 99/1，其余策略为 0；sched_rr_get_interval、sched_getaffinity 与 sched_setaffinity 支持按线程号查询并经调用方地址空间读写用户缓冲区；sched_rr_get_interval 返回一个时间片的长度；亲和掩码只含 0 号 CPU，sched_getaffinity 返回写入的字节数，sched_setaffinity 接受含 0 号 CPU 的掩码 | 普通策略的谦让值不参与选择（无 CFS 权重，仅保存并回读）；SCHED_FIFO 与 SCHED_RR 同样在时间片到期时轮转，FIFO 不续跑；无实时带宽限制；调度不读取亲和掩码 | 缺陷 7；未实现：谦让值不影响调度、实时带宽限制、亲和掩码 |
| 身份查询 | getpid 返回线程组号（tgid），同线程组内各线程一致；gettid 返回线程号；getuid、geteuid、getgid、getegid 取自进程记录里的凭证；getresuid 与 getresgid 写出真实、有效、保存的号；getgroups 返回补充组。`/proc/<pid>/stat` 的 pgrp 与 session、`/proc/<pid>/status` 的 Uid 与 Gid 取自同一来源，exec 的 AT_UID 等四项也取自凭证 | 语义兼容 | 无偏差 |
| 凭证切换 | setuid、setgid、setreuid、setregid、setresuid、setresgid、setfsuid、setfsgid、setgroups 按 Linux 6.12 的 `kernel/sys.c` 实现；凭证、补充组与能力集（effective/permitted/inheritable）经 fork 继承、跨 exec 保留；capget(90)/capset(91) 维护真实进程能力集并按 `cap_emulate_setxuid` 随 UID 切换联动（支持 PR_SET_KEEPCAPS），sethostname/setdomainname、settimeofday/clock_settime、prlimit64 与 PR_CAPBSET_DROP/PR_SET_SECUREBITS 按对应能力位鉴权 | 不按凭证做文件访问、kill 等权限检查；带 setuid 位或 setgid 位的可执行文件不会在 exec 时改变凭证，AT_SECURE 恒为 0；无文件能力扩展属性与用户命名空间 | 未实现：文件/信号权限检查、setuid 位、文件能力与用户命名空间 |
| clone | 进程 fork：退出信号必须 SIGCHLD，另接受 CLONE_CHILD_CLEARTID 与 CLONE_CHILD_SETTID；线程：退出信号必须为 0，必须同时带 CLONE_THREAD、CLONE_SIGHAND 与 CLONE_VM，另接受 CLONE_FS、CLONE_FILES、CLONE_SYSVSEM、CLONE_SETTLS 与三个 tid 标志，CLONE_DETACHED 按 Linux 忽略，其余组合返回 EINVAL；非零 stack 设置子 SP，CLONE_SETTLS 设置 TP | 不支持只共享部分资源的组合，例如共享文件表但不共享地址空间空间；无 CLONE_PARENT_SETTID | 未实现：部分共享组合、进程创建时的 CLONE_PARENT_SETTID |
| execve | argv/envp 各 ≤256 项、单串 ≤4095 字节；字符串总计最多 32 KiB；auxv 提供 AT_PHDR/PHENT/PHNUM、AT_BASE、AT_ENTRY、AT_PAGESZ、AT_RANDOM、AT_EXECFN、AT_UID/EUID/GID/EGID、AT_SECURE、AT_CLKTCK、AT_HWCAP、AT_FLAGS；ELF 支持 ET_EXEC 与 ET_DYN（装载基址固定 1 MiB，见 ELF 行）；PT_INTERP 请求的解释器缺失返回 ENOENT 并保留旧现场；`#!` 脚本按 binfmt_script 转交解释器（嵌套 ≤4 层，超限 ELOOP）；执行位统一校验（任一执行位缺失返回 EACCES，execve(2)；官方盘 basic/run-all.sh 为 0644，由用户态启动器按授权清单在运行副本 fchmodat 0755 并记录，见 §6.3 环境准备）；整镜像读入内核堆，镜像放不进内核堆时 ENOMEM | 无 shebang 的非 ELF 返回 ENOEXEC，动态库由用户态解释器加载，AT_EXECFN 为调用时给出的路径，三点与 Linux 一致 | 取舍，理由待补：镜像整体读入内核堆 |
| nanosleep | 到期返回 0；被打断返回 EINTR 并回写 rem；期限相对单调时钟 | 语义兼容 | 无偏差 |
| clock_gettime | 支持 CLOCK_REALTIME、MONOTONIC、BOOTTIME、MONOTONIC_RAW、两个 COARSE 时钟、TAI、进程与线程的 CPU 时间；未知或负的 clockid 返回 EINVAL | 闹钟类时钟未实现 | 未实现：闹钟类时钟 |
| clock_settime | 仅支持特权进程（euid==0）设置 CLOCK_REALTIME(0)；其余时钟或非法时间（负秒、越界纳秒或超过 MAX_SETTOD_SEC）返回 EINVAL；不修改单调时钟 | 不回溯重排已在 CLOCK_REALTIME 上挂起的绝对睡眠；不回写 RTC 硬件 | 未实现：绝对睡眠动态重算、RTC 同步 |
| clock_getres | 分辨率写 1 ns；地址为 0 时只检查 clockid | 语义兼容 | 无偏差 |
| clock_nanosleep | CLOCK_REALTIME、MONOTONIC、BOOTTIME、TAI 可睡，支持相对期限与 TIMER_ABSTIME，其余 flags 位被忽略；被打断返回 EINTR，相对期限回写剩余时间 | CPU 时间时钟、RAW 与 COARSE 时钟上的睡眠返回 EOPNOTSUPP；Linux 支持 CPU 时间时钟上的睡眠 | 未实现：CPU 时间、RAW 与 COARSE 时钟上的睡眠 |
| times | tms 四字段来自任务记账；返回启动以来 100Hz tick | 语义兼容 | 无偏差 |
| uname / sethostname / setdomainname | sysname=OuroOS、release=KERNEL_RELEASE（"6.1.0-OuroOS"，glibc 启动按 Linux 惯例解析该字段做最低内核版本检查，纯项目版本号会被判过旧）、version=OuroOS、machine=架构名；nodename 默认 "ouro"、domainname 默认 "local"，可由特权进程（euid==0）经 sethostname(161)/setdomainname(162) 修改（0..=64 字节，非特权 EPERM，越界 EINVAL） | 无 UTS 命名空间隔离，全局共享一份主机名与域名 | 设计：合成身份，理由见左栏；未实现：UTS 命名空间 |
| getcpu | 单核内核写入 cpu=0、node=0（指针可分别为空），忽略 tcache | 语义兼容（单核固定 0 号 CPU 与节点） | 无偏差 |
| gettimeofday / settimeofday | gettimeofday 返回墙钟（启动与 RTC 秒边界对齐后随单调时钟推进，tz 非空写零）；settimeofday(170) 支持特权进程（euid==0）设置亚秒级墙钟，校验 tv/tz 指针与范围（非特权 EPERM，负秒或非法 usec 返回 EINVAL），tv 与 tz 均为空返回 0 | 不跟随启动后 RTC 变化，settimeofday 亦不回写 RTC 或保存时区偏移 | 取舍，理由待补：不跟随 RTC 变化；未实现：时区持久化 |
| getrlimit / setrlimit / prlimit64 | 支持 Linux 全部 16 项资源限额（0..16）及跨进程查询修改（prlimit64 校验同属主或 euid==0，否则 EPERM）；DATA/STACK/MEMLOCK/AS 与 NOFILE 实时生效；非特权进程不得抬高任何资源的硬限额（EPERM），失败不修改目标也不产生半写入 | 其余 11 项资源限额（CPU/FSIZE/CORE/RSS/NPROC/LOCKS/SIGPENDING/MSGQUEUE/NICE/RTPRIO/RTTIME）仅保存、回读与跨 fork/exec 继承，尚未在对应子系统强制拦截 | 未实现：部分非内存/非 FD 限额的运行时强制拦截 |
| prctl | 支持 PR_SET/GET_PDEATHSIG（父进程退出时向存活子进程投递，fork/clone 清零）、PR_SET/GET_DUMPABLE（0/1，exec 重置为 1）、PR_SET/GET_KEEPCAPS（exec 清零）、PR_SET/GET_TIMING、PR_SET/GET_NAME（16 字节线程名，主线程同步至 `/proc/<pid>/{stat,status}`，exec 更新为可执行文件名）、PR_GET_ENDIAN、PR_GET_SECCOMP(0)、PR_CAPBSET_READ/DROP（0..=40）、PR_SET/GET_SECUREBITS（含锁位校验）、PR_SET/GET_TIMERSLACK（默认 50 µs）、PR_SET/GET_CHILD_SUBREAPER（最近存活 subreaper 祖先接管孤儿与僵尸并收 SIGCHLD，fork 清零）、PR_SET/GET_NO_NEW_PRIVS（不可撤销，同步 `/proc/<pid>/status` 的 `NoNewPrivs`）、PR_GET_TID_ADDRESS 与 PR_SET/GET_THP_DISABLE；其余选项返回 EINVAL | timerslack/thp_disable/securebits 仅保存状态，不改变内核调度或内存合并行为；seccomp 与 PR_SET_MM 等未实现 | 未实现：seccomp、PR_SET_MM 与定时器松弛合并 |
| newfstatat/fstat/statx | 共用 FS 元数据；Ext4 返回 UID/GID、atime/mtime/ctime（含纪元扩展与纳秒）及可用的 btime；FAT 权限 0777、所有者 0，时间未接通，statx 不置对应有效位；卷设备号为内核分配的合成标识 | rv64/la64 使用 asm-generic stat 布局；旧式 stat 的缺失时间填零；statx 不报告未提供的属性、挂载 ID、DIO 对齐等扩展字段 | 未实现：FAT 的时间与权限、statx 扩展字段 |
| umask | 仅保存 0777 权限位，返回旧值；初始 022；fork 复制且之后独立，exec 保留；openat 新建与 mkdirat 按 `(mode & 07777) & ~umask` 保留特殊权限位（setuid/setgid/sticky），已有文件不改权限 | 无默认 ACL 支持；FAT 沿用合成 0777，不能表达每文件的 POSIX 创建权限 | 未实现：默认 ACL |
| utimensat | 支持 NULL times、指定秒/纳秒、UTIME_NOW/UTIME_OMIT、cwd/dirfd 相对路径、中间链接及 AT_SYMLINK_NOFOLLOW；AT_EMPTY_PATH 和 NULL path 的 FD 形式支持仍打开但已删名的 inode；双方 OMIT 不访问路径或写入，参数先经 user_access 复制 | Ext4 更新 atime/mtime 并更新 ctime，不改变 btime 或文件偏移；128 字节 inode 为秒精度，扩展 inode 支持纳秒及纪元位，指定时间越界时限制到可表示范围；FAT、管道和控制台暂 EOPNOTSUPP。尚无 UID/GID/capability 身份检查、目录搜索权限或 immutable/append-only 属性校验；Now 使用 RTC 对齐的墙上时钟（无 RTC 时回退卷 s_wtime 加启动时长） | 未实现：身份检查、FAT 与管道上的时间更新 |
| statfs/fstatfs | 共用 FS 容量快照，路径跟随链接，FD 查询不修改共享偏移；rv64/la64 均编码 120 字节 asm-generic statfs，保留区清零；返回卷类型、分配单位、总量、空闲量、普通用户可用量、inode 计数、卷标识与只读标志 | Ext4 按当前后端计数并扣除超级块记录的元数据开销，可用量扣除保留块；若卷未记录开销则总量沿用原始块数，尚未补算，可能与 Linux df 有差异。FAT 使用实际簇统计，无固定 inode 池，files/ffree 为零。管道/控制台返回 EOPNOTSUPP；flags 仅报告 ST_VALID/ST_RDONLY，FAT 按现有可写挂载模式报告；无权限搜索及配额限制统计 | 缺陷 8；未实现：权限搜索与配额统计 |
| openat | 逐项解析路径并跟随符号链接，文件描述符指向解析后的目标。普通 O_NOFOLLOW 遇到末项链接返回 ELOOP，O_PATH 和 O_NOFOLLOW 组合可获得末项链接描述符。O_CREAT 可经悬空链接创建目标，O_CREAT 和 O_EXCL 组合对已存在的链接返回 EEXIST。 | 最多跟随 40 个链接，尾斜杠要求末项为目录。目录文件描述符仍受已删名的目录路径限制，O_PATH 的其他接口限制沿用各调用约定。 | execve 尚未复用此解析入口。 |
| readlinkat | 从现有路径查询取得末项链接，读取目标文本并按 bufsiz 截断，不补 NUL；支持绝对路径、cwd/目录 FD 相对路径，绝对路径忽略 dirfd；中间链接跟随，末项不跟随；bufsiz 按 Linux int ABI 解释，非正数 EINVAL | 非空路径指向非链接返回 EINVAL；空路径查询 FD，非链接 ENOENT；坏 FD/用户缓冲区分别 EBADF/EFAULT。复用 Ext4 链接读取，目标仍限 UTF-8 且小于 4 KiB，不更新链接 atime；O_PATH 打开语义及链接 FD 的完整生命周期尚未补齐，不据此宣称完整支持 | 取舍，理由待补：目标限 UTF-8 且小于 4 KiB；未实现：O_PATH 语义、链接 atime |
| 状态查询路径与标志 | 支持绝对路径、cwd/目录 FD 相对路径、AT_EMPTY_PATH（含 NULL）、AT_SYMLINK_NOFOLLOW、AT_NO_AUTOMOUNT；查询时逐级跟随链接，最多 40 次，保留点分量与尾斜杠约束；`openat`、`mkdirat`、`chdir` 与 `unlinkat` 共用同一解析路径，`openat` 支持 `O_NOFOLLOW`（命中链接返回 ELOOP，配 `O_PATH` 允许打开链接本身）及悬空链接配合 `O_CREAT`（无 `O_EXCL`）创建目标文件 | exec 仍沿用基础路径解析；cwd/目录 FD 仍按保存的路径字符串定位；沿用项目 UTF-8 路径限制，尚无进程身份驱动的目录搜索权限检查 | 取舍，理由待补：UTF-8 路径限制；未实现：目录搜索权限检查 |
| statx 同步与 mask | 本地卷按当前 inode 缓存查询；接受 AS_STAT/FORCE_SYNC/DONT_SYNC，后两者不触发远端同步或额外文件数据写回；互斥同步标志、未知 flags、保留 mask 位 0x80000000 返回 EINVAL，其余未知 mask 位忽略 | 返回 mask 反映实际提供字段，可以多于请求；缺失时间不标有效，填零；当前 atime 更新策略仍沿用 rsext4 挂载选项 | 无偏差 |
| fsync / fdatasync / syncfs / sync_file_range | `fsync(82)` 与 `fdatasync(83)` 写回 Ext4 inode 共享页并同步日志（`O_PATH` 返回 `EBADF`，管道/FIFO/套接字/虚拟节点返回 `EINVAL`）；`syncfs(267)` 校验 FD 后同步根卷；`sync_file_range(84)` 校验 flags（仅 `WAIT_BEFORE\|WRITE\|WAIT_AFTER`）、非负偏移/长度与溢出，拒绝管道/套接字/字符设备（`ESPIPE`）并对普通文件同步 | FAT 返回 ENOTSUP；`sync_file_range` 简化为整文件同步而非精确页区间异步刷盘 | 未实现：FAT、精确页区间异步回写 |
| preadv2 / pwritev2 / close_range | `preadv2(286)` 与 `pwritev2(287)` 支持 `offset == -1`（使用并更新共享偏移，支持管道/套接字）、`offset >= 0` 定位向量 I/O（不改偏移）、`RWF_HIPRI`/`RWF_DSYNC`/`RWF_SYNC`/`RWF_NOWAIT`（普通文件支持，管道/套接字返 `EOPNOTSUPP`）与 `RWF_APPEND`（追加至 EOF，`offset >= 0` 不改共享偏移，`offset == -1` 同步推进），未知 flags 返回 `EOPNOTSUPP`；`close_range(436)` 支持关闭 `[first, last]` 全部已打开 FD（同步释放 POSIX 锁）及 `CLOSE_RANGE_CLOEXEC`/`CLOSE_RANGE_UNSHARE` | 单核进程 FD 表无跨进程 `CLONE_FILES` 共享，`CLOSE_RANGE_UNSHARE` 为安全空操作；`RWF_HIPRI` 按同步 I/O 忽略 | 未实现：轮询式异步块 I/O 与跨进程共享 FD 表解绑 |
| mount/umount2 | FAT 接受 vfat/fat，只支持 flags 为 0。Ext2 以独立辅助磁盘或其 MBR 主分区为源，支持可写挂载、只读挂载和从可写重挂载为只读，仅有效 UID 为 0 的进程可操作。Ext2 挂载点有存活引用时拒绝卸载或重挂载。/proc/mounts 报告各卷。 | Ext2 挂载点限于根 Ext4 上未被占用的目录，禁止与现有卷共用磁盘。卷有独立设备号，已覆盖目录在卸载后恢复可见。 | 通用挂载标志、嵌套 Ext2、非根 Ext4 和重挂载为可写未接入。 |
| Ext2 辅助卷 | 支持 1 KiB 块、128 字节 inode 的干净无日志卷。支持线性目录遍历、文件和符号链接读取、普通文件创建、同卷硬链接与删名、容量查询和同步。 | 只写普通文件的前 12 个直接块，目录项插入使用现有目录空间。末次删名遇到存活引用返回 EBUSY。写入或刷盘失败时恢复受影响块，恢复失败后拒绝访问该卷。 | 散列目录、目录扩容、截断、重命名、符号链接创建与掉电恢复未实现。 |
| 原始块设备读写 | 已注册块设备支持顺序和定位读写。有效 UID 为 0 的进程可打开数据描述符。按分区容量截断跨尾请求，读至末尾返回 EOF，末尾继续写返回 ENOSPC。 | 已挂载卷占用的磁盘禁止原始写入，返回 EBUSY。只读构建返回 EROFS。 | 块设备专用同步待完善。 |
| 设备命名与根卷 | 设备号按总线枚举顺序分配，无内容特征重排；Ext4 根卷为扫描式选择：每盘先试分区 1..4 再试整盘，取第一个可挂载的 Ext4。官方 mount 测例写死的 `/dev/vda2`（辅助盘 FAT32 分区）由用户态启动器按授权清单 mknodat 建立块设备节点（major 254，minor=(盘<<4)\|分区，见 §6.3），内核按节点登记的真实设备身份解析挂载 | 设备节点是内核注册表条目而非文件系统实体；根卷语义与设备名无绑定；辅助盘由官方 harness 自动挂为第二块盘 | 取舍，理由待补 |
| mmap | 匿名映射、普通文件和 /dev/zero 均支持 PRIVATE/SHARED；非匿名映射先检查 FD 有效性及 O_PATH，再检查长度。/dev/zero 按需提供零页，共享写权限由打开模式决定；文件整页在 EOF 外允许建图，直接访问按 SIGBUS 终止；MAP_FIXED 事务替换 | 最后不足一页的尾部补零且不回写；MAP_FIXED 可覆盖用户栈；flags 白名单，MAP_DENYWRITE、MAP_EXECUTABLE 与 MAP_STACK 按 Linux 忽略 | 无偏差 |
| memfd_create / fallocate / fcntl(SEALS) | `memfd_create(279)` 创建匿名内存文件虚拟 inode（`0x3000_0000..=0x3FFF_FFFF`，单文件上限 8 MiB），支持 `MFD_CLOEXEC`/`MFD_ALLOW_SEALING`/`MFD_NOEXEC_SEAL`/`MFD_EXEC`、名称长度上限 249（超长返 `EINVAL`）、`/proc/self/fd/<n>` 重开、常规文件读写/截断/fstat/fchmod/`mmap(MAP_SHARED/MAP_PRIVATE)`；`fallocate(47)` 支持默认扩展、`FALLOC_FL_KEEP_SIZE`、`FALLOC_FL_PUNCH_HOLE\|KEEP_SIZE` 与 `FALLOC_FL_ZERO_RANGE`（同时覆盖 Ext4 普通文件与 memfd，并对盘上卷执行空闲块 `ENOSPC` 检查）；`fcntl` 支持 `F_ADD_SEALS(1033)`/`F_GET_SEALS(1034)` 及 `F_SEAL_SEAL`/`F_SEAL_SHRINK`/`F_SEAL_GROW`/`F_SEAL_WRITE`（活跃可写共享映射时返 `EBUSY`）/`F_SEAL_FUTURE_WRITE`/`F_SEAL_EXEC` 强制拦截 | 不支持 `MFD_HUGETLB` 大页（无 hugetlbfs，合法大页标志返 `ENODEV`，非法标志返 `EINVAL`）、`FALLOC_FL_COLLAPSE_RANGE`/`INSERT_RANGE`/`UNSHARE_RANGE`；单 memfd 受 32 MiB 固定内核堆约束限 8 MiB | 未实现：MFD_HUGETLB、fallocate 区间折叠/插入 |
| mprotect | 支持 PROT_NONE 和 R/W/X 组合；W 隐含 R，只读 FD 建立的共享映射禁止提升写权限（EACCES） | 两架构无 NX；VMA 记录请求权限，页表执行写保护，可访问页实际带 X | 取舍，理由待补：没有执行权限保护 |
| brk/munmap | brk 失败返回原 break；munmap 起址页对齐、长度向上取整、允许空洞 | 均无按需分页；brk 立即分配/释放物理页 | 取舍，理由待补：brk 立即分配 |
| ELF | ET_EXEC 固定地址与 ET_DYN（装载基址 0x10_0000：官方 basic 是 intptr_t 为 32 位 int 的无重定位 PIE，Linux 高位 ELF_ET_DYN_BASE 布局下其 brk 断言同样无法通过；低位基址同时保持空指针缺页）；段相位要求 p_vaddr 与 p_offset 按页同余且按 p_align 同余（不要求各自页对齐，busybox 第二段 offset/vaddr 均非对齐但同余）；PT_INTERP 支持；不同 PT_LOAD 落到同一用户页仍拒绝 | 无 NX，PT_GNU_* 忽略；AT_PHDR 要求程序头表在首个可读 PT_LOAD 内 | 设计：装载基址取 1 MiB，理由见左栏；取舍，理由待补：程序头表位置与同页段限制 |
| truncate/ftruncate | 支持 Ext4 普通文件缩短、稀疏扩展与清零；路径形式跟随符号链接，FD 形式要求可写并支持已删名的打开 inode，长度操作不改共享偏移；O_TRUNC 复用同一 FS 接口。扩展区读零，缩短清空尾块剩余字节，回收含 unwritten 的尾部 extent 及多余索引块，更新长度、块计数与 mtime/ctime，并沿用后端清除 set-ID 位 | 负长度 EINVAL，超出 u32::MAX 个 4 KiB 逻辑块 EFBIG；无效 FD EBADF，只读 FD 和非普通 FD EINVAL，O_PATH FD EBADF。长度改变且存在存活共享页时 EOPNOTSUPP，包括子进程仍保留映射的情况；同长度允许，避免未实现的映射失效和旧共享页写回。FAT 仅沿用清零，非零长度 EOPNOTSUPP；旧式映射仅支持直接块清零，外部 xattr 与 HUGE_FILE 编码暂不支持。尚无完整身份权限、文件锁、执行文件占用保护及 immutable/append-only 校验；MAP_PRIVATE 截断后越过 EOF 的 SIGBUS 仍未实现，掉电/OOM/全部设备失败未验证 | 设计：存活共享页时拒绝改长，理由见左栏；未实现：权限检查、文件锁与截断后的 SIGBUS |
| renameat/renameat2 | Ext4 支持同卷普通重命名、目标替换及 RENAME_NOREPLACE；按父目录 inode 更新目录项，末项链接自身被移动，中间链接跟随；跨挂载 EXDEV，目标非空目录 ENOTEMPTY，类型冲突分别 EISDIR/ENOTDIR；被替换但仍由 FD/映射引用的 inode 延迟回收 | EXCHANGE、WHITEOUT 和未知标志 EINVAL；FAT 卷内 EOPNOTSUPP；仍由任一进程 cwd、目录 FD 或挂载点引用的目录及其祖先返回 EBUSY，保护现有路径字符串身份。单核内核态串行化与根卷锁保证操作期间无其他任务观察中间状态；保存目录块及 inode 用于失败回滚，不保证掉电原子性，设备/回滚错误后拒绝继续访问卷；身份权限及 sticky/immutable/append-only 检查未实现；复杂分配失败回收及掉电恢复未验证。目标含外部 xattr 或有块的旧式映射暂不支持替换 | 设计：被引用的目录返回 EBUSY，理由见左栏；未实现：EXCHANGE、WHITEOUT 与权限检查 |
| symlinkat | 在 Ext4 上按路径或目录 FD 创建符号链接，原样存入目标，允许目标尚不存在。符号链接模式为 0777，属主使用文件系统 UID，属组按父目录 setgid 或文件系统 GID 确定。 | 支持非空 UTF-8 目标，长度小于 4096 字节。短目标内嵌于 inode，长目标使用一个 extent 块。重名 EEXIST，只读 EROFS，FAT 返回 EPERM。失败撤销已发布目录项，确认删名后才释放新 inode 和数据块。 | execve 的链接跟随、通用权限策略和掉电恢复待完善。 |
| linkat | Ext4 可为普通文件、符号链接、FIFO、设备和套接字节点增加名称。默认链接到源路径末项本身，AT_SYMLINK_FOLLOW 跟随末项。按 fsuid、fsgid 和补充组检查沿途目录搜索权限，以及目标父目录的写入与搜索权限，不足时返回 EACCES。源和新名称共享 inode，目标已存在返回 EEXIST，跨挂载返回 EXDEV，目录或不支持硬链接的文件系统返回 EPERM，只读根卷返回 EROFS，达到 65000 个链接返回 EMLINK。 | 相对路径从 cwd 或目录 FD 指向的目录开始检查，符号链接跟随时检查实际路径。fsuid 为 0 沿用特权绕过规则。按父 inode 插入目录项，更新源链接数及 ctime。失败回滚，回滚失败后拒绝继续访问卷。 | 支持 AT_EMPTY_PATH 按 FD 查询源 inode；ACL、细分能力模型和 protected_hardlinks 尚未接入，未验证掉电恢复。 |
| unlink/unlinkat | Ext4 普通文件、符号链接与特殊节点按末项自身删名。文件有其他链接时保留 inode，链接数为零时等待最后一个打开引用释放。AT_REMOVEDIR 移除空目录名并清零链接数，工作目录和目录 FD 保留原 inode，最后一个引用释放后回收。已删目录的 getcwd 返回 ENOENT，已有 FD 可查询原 inode，getdents64 返回 EOF。 | 非空 ENOTEMPTY、非目录 ENOTDIR、根与挂载点 EBUSY。已删目录的相对路径解析及路径型 fchmod 暂不支持。FAT 有句柄时 unlink 返回 EBUSY，目录删除返回 ENOTSUP。 | 未实现：FAT 上的删除语义 |
| getdents64 | fs 层提供目录项与续读位置，EXT4 后端按块解析，syscall 层打包 Linux dirent；单次最多 4KiB；FAT 返回 ENOTSUP | 后端目录块使用可失败堆分配；Linux 目录项打包的 4 KiB 栈缓冲区限制在不内联的 getdents64 函数内，避免普通文件 I/O 承担该栈帧；失败不推进文件偏移 | 无偏差；未实现：FAT |
| 套接字（AF_INET 回环与 AF_UNIX） | 支持 AF_INET 的 SOCK_STREAM（TCP）与 SOCK_DGRAM（UDP），`socket(AF_UNIX, SOCK_STREAM\|SOCK_DGRAM, 0)` 未连接套接字，以及 `socketpair(199)` 创建的 AF_UNIX 匿名 SOCK_STREAM/SOCK_DGRAM 互连对（对齐 Linux 类型与协议错误码顺序：非法 type 返回 EINVAL，协议不匹配返回 EPROTONOSUPPORT）；支持 SOCK_NONBLOCK/SOCK_CLOEXEC、bind（含端口 0 临时端口分配与 UDP SO_REUSEADDR 共享端口）、listen、accept/accept4、connect（非阻塞 TCP 返回 EINPROGRESS 且立即入监听队列；UDP 按精确对端优先解复用）、getsockname/getpeername（AF_UNIX 写回 2 字节地址族）、sendto/recvfrom（含 MSG_PEEK/MSG_DONTWAIT/MSG_NOSIGNAL 与 SIGPIPE；阻塞流式小包整块写入防短写）、read/write/ppoll/pselect6/close/fstat（S_IFSOCK）、shutdown，以及 SOL_SOCKET（SO_REUSEADDR/SO_REUSEPORT/SO_KEEPALIVE/SO_DONTROUTE/SO_LINGER/SO_RCVLOWAT/SO_SNDLOWAT/SO_TYPE/SO_ERROR/SO_SNDBUF/SO_RCVBUF/SO_RCVTIMEO/SO_SNDTIMEO）、IPPROTO_IP（IP_TOS/IP_TTL/IP_MTU_DISCOVER/IP_RECVERR）与 IPPROTO_TCP（TCP_NODELAY/TCP_MAXSEG/TCP_CORK/TCP_KEEPIDLE/TCP_KEEPINTVL/TCP_KEEPCNT/TCP_INFO/TCP_CONGESTION）；单 FD 套接字阻塞等待按套接字唯一唤醒键走调度器定向唤醒（64 槽位，满时退回广播） | AF_INET 仅支持本地回环（0.0.0.0 与 127.x.x.x）；AF_UNIX 仅支持匿名 socketpair 与基础未连接创建，不支持命名路径/抽象名绑定、listen/accept/connect 与 SCM_RIGHTS 辅助消息；无外部物理网卡、AF_INET6、sendmsg/recvmsg 与完整 TCP 拥塞/重传状态机 | 未实现：外部网卡、命名 AF_UNIX、AF_INET6、sendmsg/recvmsg |
| pselect6 / getitimer / setitimer | pselect6 支持最多 1024 个 FD 的 read/write/except 位图、可选相对超时与临时信号掩码（被打断返回 EINTR，不走 SA_RESTART）；getitimer/setitimer 支持 ITIMER_REAL 单次与周期触发 SIGALRM（fork 清零、exec 保留、退出清理） | ITIMER_VIRTUAL 与 ITIMER_PROF 返回 EOPNOTSUPP；超过 1024 FD 的位图返回 EINVAL | 未实现：ITIMER_VIRTUAL、ITIMER_PROF |
| eventfd2 / timerfd_* / epoll_* | `eventfd2` 支持 64 位计数、`EFD_SEMAPHORE`/`EFD_NONBLOCK`/`EFD_CLOEXEC` 与定向唤醒；`timerfd_{create,settime,gettime}` 支持 `CLOCK_REALTIME`/`MONOTONIC`/`BOOTTIME`、单次与周期到期累加、`TFD_TIMER_ABSTIME` 及硬件定时器唤醒（不忙等）；`epoll_{create1,ctl,pwait,pwait2}` 按 rv64/la64 16 字节非紧凑 `epoll_event` 编码，支持 `ADD`/`MOD`/`DEL`、普通文件拒加（`EPERM`）、嵌套深度与环检测（`ELOOP`）、`EPOLLET`/`EPOLLONESHOT`/`EPOLLEXCLUSIVE`、临时信号屏蔽字与已关闭对象自动清理 | 暂不支持 `TFD_TIMER_CANCEL_ON_SET` 的墙钟跳变 `ECANCELED` 通知与 `CLOCK_REALTIME_ALARM`/`BOOTTIME_ALARM` | 未实现：闹钟时钟与墙钟跳变取消 |
| pidfd_open / pidfd_send_signal / pidfd_getfd / kcmp / waitid(P_PIDFD) | `pidfd_open(434)` 为线程组 leader 创建带 `FD_CLOEXEC` 的进程描述符（支持 `PIDFD_NONBLOCK`，拒绝非 leader 线程返 `EINVAL`，进程实例经 `Arc<PidFdState>` 绑定以防 PID 复用，退出时立即可 `poll`/`epoll` 读就绪）；`pidfd_send_signal(424)` 支持 `pidfd_open` 与 `/proc/<pid>`（含 `/proc/self`）目录 FD、可选 `siginfo_t`（校验 `si_signo`、保留 `si_code` 与凭证权限，非 pidfd 返回 `EBADF`）；`pidfd_getfd(438)` 按凭证鉴权并跨进程复制打开文件描述（置位 `FD_CLOEXEC`）；`kcmp(272)` 支持 `KCMP_FILE` 与线程组级资源比较；`waitid(95)` 扩展支持 `P_PIDFD(3)` 与 `PIDFD_NONBLOCK` 返 `EAGAIN` | 暂不支持 `PIDFD_THREAD`、`CLONE_PIDFD`、`KCMP_EPOLL_TFD` 与 `/proc/<pid>/fdinfo/<fd>` 导出 | 未实现：PIDFD_THREAD、CLONE_PIDFD、KCMP_EPOLL_TFD 与 fdinfo |
| System V 共享内存（shmget/shmctl/shmat/shmdt） | 全局段表复用 `mm::shared::SharedPage` 与 `AreaKind::SharedAnonymous`；支持 `IPC_PRIVATE` 与具名 key（`IPC_CREAT`/`IPC_EXCL`）、`shmat`（含 `SHM_RDONLY`/`SHM_RND`/`SHM_REMAP`/`SHM_EXEC`）、`shmdt` 与 `shmctl`（`IPC_RMID`/`IPC_STAT`/`IPC_SET`，兼容剥离 `IPC_64` 标志）；`IPC_RMID` 立即解绑 key 并在 `nattch` 归零后回收，已挂接映射与 `fork` 继承映射持续有效直到解除或进程退出；`shmid64_ds` 按 asm-generic 64 位 112 字节编码 | 单段上限 256 MiB，总段数上限 1024；未实现 `IPC_INFO`/`SHM_INFO`/`SHM_STAT`/`SHM_LOCK`/`SHM_UNLOCK` 与按 uid/gid 的 IPC 权限校验 | 未实现：IPC_INFO、SHM_LOCK 与凭证权限校验 |
| System V 消息队列与信号量（msgget/msgctl/msgrcv/msgsnd、semget/semctl/semop/semtimedop） | 全局叶子锁表 `MSG_TABLE`/`SEM_TABLE`（循环槽与序号编码），按 `ipcperms()` 做 uid/gid/groups 权限检查（euid==0 特权放行）；消息队列支持 `msgtyp`（`0`/`>0`/`<0`）、`IPC_NOWAIT`/`MSG_NOERROR`/`MSG_EXCEPT`/`MSG_COPY`、`IPC_STAT`/`IPC_SET`/`IPC_RMID`/`IPC_INFO`/`MSG_INFO`/`MSG_STAT`/`MSG_STAT_ANY`；信号量集支持多操作原子执行、相对超时 `semtimedop`、精确 `GETNCNT`/`GETZCNT` 计数、`GETVAL`/`SETVAL`/`GETALL`/`SETALL`/`GETPID`/`IPC_STAT`/`IPC_SET`/`IPC_RMID`/`IPC_INFO`/`SEM_INFO`/`SEM_STAT`/`SEM_STAT_ANY` 与线程组退出 `SEM_UNDO` 自动回滚（`fork` 不继承、`exec` 保留、`SETVAL`/`SETALL` 清除）；阻塞调用走 `WaitReason::Ipc` 定向唤醒键，`IPC_RMID` 唤醒阻塞者返回 `EIDRM`，信号打断一律返回 `EINTR`（不走 `SA_RESTART`）；提供 `/proc/sysvipc/{msg,sem}` 与 `/proc/sys/kernel/{msgmni,msgmax,msgmnb,sem}` 只读快照，并同步 `/proc/<pid>/{stat,status}` 阻塞态 `'S'` | 默认上限 `MSGMAX=8192`、`MSGMNB=16384`、`MSGMNI=128`、`SEMMSL=512`、`SEMMNI=128`、`SEMMNS=32000`、`SEMOPM=500`、`SEMVMX=32767`（与 `IPC_INFO` 及 `/proc/sys/kernel/*` 一致）；暂不支持写入修改 `/proc/sys/kernel/*`、`/proc/sysvipc/shm` 与非同线程组 `CLONE_SYSVSEM` | 未实现：动态调参 `/proc/sys/kernel/*`、`/proc/sysvipc/shm` 与非同线程组 `CLONE_SYSVSEM` |
| sync | 同步已挂载可写 Ext4 根卷缓存并返回 0 | 语义兼容（无独立写回线程，同步落盘） | 无偏差 |
| 路径 | 必须是合法 UTF-8；总长 4096 字节，单分量 255 | 非 UTF-8 文件名不可访问 | 取舍，理由待补 |
| 其他 | stdin 读恒 EOF；fd=1/2 直通控制台；/dev/null（rdev 1:3）读与 pread 恒返回 EOF、写与 pwrite 丢弃并返回请求长度（null(4)）；/dev/urandom（1:9）与 /dev/random（1:8）读返回熵流、写丢弃；/dev/misc/rtc 提供墙上时钟查询（RV Goldfish RTC@0x101000 纳秒计数，LA LS7A TOY 双读一致法；ioctl RTC_RD_TIME 按 linux/rtc.h 拆 tm 字段，cmd 按 unsigned int 截断比较以兼容部分 libc 的符号扩展）；/proc/self/exe 在 exec/open 时重写为该进程最近一次 execve 的绝对路径（内嵌程序无路径时 ENOENT）；/proc/self 与 /proc/<pid>（及 `/proc/<pid>/task/<tid>`）支持 stat/cmdline/status/comm/timerslack_ns；sched_yield 轮转后可能立即再次调度；getpid 总成功，getppid 返回注册表 parent | 孤儿过继最近存活的 child_subreaper 祖先或 init；/proc 枚举来自 Task 维护的独立快照表（注册/退出/收割同步更新；FS 读路径经专用锁消费，锁序 REGISTRY→PROC_TABLE 单向）；cmdline 为 execve 提交后的真实 argv，未 exec 的任务以登记名近似；/proc/<pid>/stat 提供 proc(5) 全部 53 字段（CPU 记账与内存尺寸字段为 0，记账未导出为欠账）；/proc/<pid>/status 输出 Name/State/Pid/PPid/Uid/Gid/NoNewPrivs；RTC 不支持设置时间（RTC_SET_TIME ENOTTY） | 取舍，理由待补：stdin 恒 EOF、fd 1 与 2 直通控制台；未实现：RTC 设置时间、CPU 记账字段 |



文件 I/O 依据：[pread(2)](https://man7.org/linux/man-pages/man2/pread.2.html)、[readv(2)](https://man7.org/linux/man-pages/man2/readv.2.html) 与 [Linux 64 位定位向量 ABI](https://github.com/torvalds/linux/blob/v6.12/fs/read_write.c)。仅核对语义与 ABI，未复制实现代码。

FD 控制依据：[F_DUPFD](https://man7.org/linux/man-pages/man2/F_DUPFD.2const.html)、[F_GETFD/F_SETFD](https://man7.org/linux/man-pages/man2/F_GETFD.2const.html) 与 [F_GETFL/F_SETFL](https://man7.org/linux/man-pages/man2/F_GETFL.2const.html)。FD 表扩容使用可失败分配；成功 exec 关闭 cloexec，失败 exec 保留描述符。

创建掩码与时间更新依据：[umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)、[utimensat(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html) 与 [Linux v6.12 utimes ABI](https://github.com/torvalds/linux/blob/v6.12/fs/utimes.c)。双方 OMIT 的提前成功及 NULL path 的 FD 形式按原始系统调用处理；只核对语义，未复制实现代码。

容量查询依据：[statfs(2)](https://man7.org/linux/man-pages/man2/statfs.2.html) 与 [asm-generic statfs UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/statfs.h)。仅按 ABI 独立编码；Ext4 fsid 取 UUID 前八字节，FAT 取卷序号，均作为不透明标识。

链接读取依据：[readlink(2)](https://man7.org/linux/man-pages/man2/readlink.2.html) 与 [Linux v6.12 readlinkat ABI/空路径行为](https://github.com/torvalds/linux/blob/v6.12/fs/stat.c)。仅核对公开语义，未复制实现代码。

符号链接创建依据见 [symlinkat(2)](https://man7.org/linux/man-pages/man2/symlinkat.2.html)。硬链接与删名依据见 [linkat(2)](https://man7.org/linux/man-pages/man2/linkat.2.html) 和 [unlinkat(2)](https://man7.org/linux/man-pages/man2/unlinkat.2.html)。

截断依据：[truncate(2)](https://man7.org/linux/man-pages/man2/truncate.2.html)。按公开语义检查路径、FD、长度和偏移；存活共享映射下拒绝改长属于当前兼容性限制，不代表 Linux 的完整映射截断行为。

FS 通过 `fs::mapping` 注册 MM 映射钩子：注册后，长度改变先由 MM `prepare_resize` 校验并预分配，后端成功后再 `cache::resize_inode` 调整共享页、`commit_resize` 撤销旧映射；未注册钩子时仍按 EOPNOTSUPP 保守处理。普通 write 扩文件同样清零共享尾页的新暴露区间并通知 MM。`/proc/meminfo` 为只读快照，open 时捕获一次帧统计与共享页缓存量。


重命名依据：[rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html)。复用现有 FS 路径与引用管理，未复制 Linux 实现；当前支持范围见上表。

文件状态查询依据：[stat(2)](https://man7.org/linux/man-pages/man2/stat.2.html)、[statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html) 与 [Linux asm-generic stat UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/stat.h)。按公开 ABI 独立编码，未复制 Linux 实现代码。

### 4.4 下一里程碑缺口


| 类别 | 缺口 |
|---|---|
| 基础调用 | fcntl 文件锁和异步通知尚未实现；ioctl 仅支持 RTC_RD_TIME，TCGETS/TCWINSZ 等终端命令返回 ENOTTY |
| 信号残余 | 停止/继续状态机、RT 排队、core 位等偏差与欠账集中登记 §4.5 |
| ELF（动态库） | 内核不加载 DT_NEEDED 库（由用户态解释器完成）；libc-test 的 dlopen 等场景待验证 |
| mm | SIGBUS 用户投递；文件映射扩展；用户页执行禁止（NX） |
| fs | FAT getdents、句柄缓存与重命名；link/symlink；EXT4 日志重放 |

**待修缺陷**：行为与 Linux 不同，并经手册页或 Linux 6.12 源码确认属于错误。
只登记，暂不修复。一条修掉后从本表删除，并去掉对应条目“性质”栏里的标注。

| 编号 | 位置 | 本内核现状 | Linux 语义与依据 |
|---|---|---|---|
| 缺陷 2 | §4.3 fchmod、fchown | 不校验属主，任何进程都能改权限位和属主 | chmod(2)、chown(2)：有效号不是属主且没有特权时报 EPERM |
| 缺陷 3 | §4.5 kill 族 | 不检查发送方有没有权限 | kill(2)：发送方对目标没有权限时报 EPERM |
| 缺陷 4 | §4.3 wait4、waitid、getrusage | wait4 忽略 rusage，waitid 不填 rusage，maxrss 与缺页统计恒为 0 | wait4(2)、waitid(2)：rusage 非空时填入资源用量；getrusage(2)：ru_maxrss 是最大常驻集大小 |
| 缺陷 5 | §4.3 waitid | infop 为 NULL 时返回子进程号 | Linux 6.12 `kernel/exit.c` 的 `sys_waitid`：infop 为 NULL 时返回 0 |
| 缺陷 6 | §4.3 pipe | 阻塞写超过一个分块时，管道写满就返回已写入的长度 | pipe(7)：没有设 O_NONBLOCK 时，write 阻塞到 n 字节全部写完 |
| 缺陷 7 | §4.3 sched_* | SCHED_FIFO 线程时间片到期后与同级线程轮转 | sched(7)：SCHED_FIFO 没有时间片，线程运行到阻塞或被更高优先级抢占 |
| 缺陷 8 | §4.3 statfs/fstatfs | 管道和控制台上返回 EOPNOTSUPP | statfs(2)：fstatfs 在管道上自 Linux 3.1 之后正常返回 |
| 缺陷 9 | §4.5 sigpending | sigsetsize 只接受 8 | Linux 6.12 `kernel/signal.c` 的 `sys_rt_sigpending`：大于 8 才返回 EINVAL |
| 缺陷 11 | §4.5 sa_flags | SA_NOCLDSTOP 只保存不执行 | sigaction(2)：子进程停止/继续状态机未实现（SA_NODEFER 与 SA_RESETHAND 已修复） |
| 缺陷 12 | §4.5 sigaltstack | 备用栈不分线程；不检查 MINSIGSTKSZ；rt_sigreturn 不恢复登记 | sigaltstack(2)：备用栈属于线程；启用时 ss_size 小于 MINSIGSTKSZ 报 ENOMEM |
| 缺陷 13 | §4.2 vfork | 子进程不与父进程共享地址空间 | vfork(2)：子进程与父进程共享全部内存，父进程挂起到子进程 exec 或退出 |

**取舍与理由**：有意选择的做法。理由写不出的列为“待补”，补上之前不算
成立的设计。

| 项 | 现状 | 代价 | 理由 |
|---|---|---|---|
| 内核不可抢占 | §3.2 | 内核路径执行期间不投递信号，也不处理到期的等待 | 待补 |
| 没有执行权限保护 | §1.2、§2.2 | 可访问的页都可以执行 | 待补，原文只写了“团队决定不实现” |
| loongarch64 空闲时自旋等时钟 | §3.8 | 空闲时占满宿主 CPU | 待补 |
| 等待表满时挂起退化为就绪让出 | §3.5 | 该任务反复重查条件，占用时间片 | 待补 |
| 任务互等时永久等待 | §3.5 | 死锁不会被检测，靠 QEMU 超时结束 | 待补 |
| 设备节点只存在于内核注册表 | §4.3 | 重启后丢失，每次由启动器重建 | 待补 |
| 根卷按扫描顺序选择 | §6.3 | 有多块可挂载的卷时，取到哪块取决于枚举顺序 | 待补 |
| 路径必须是合法 UTF-8 | §4.3 | 非 UTF-8 的文件名不可访问 | 待补 |
| brk 立即分配物理页 | §4.3 | 申请后没有触碰的堆也占物理内存 | 待补 |
| execve 把整个镜像读入内核堆 | §4.3、§6.5 | 镜像放不进剩余堆空间时 exec 报 ENOMEM | 待补 |
| 进程间输出交错 | §3.8 | basic 的 test_pipe 偶发少 3 分 | 2026-11-25 决定暂不处理 |

### 4.5 信号契约

**范围**：kill/tkill/tgkill、rt_sigaction/procmask/pending/sigsuspend/
sigtimedwait/sigqueueinfo/sigaltstack/sigreturn(139) 全链路；SIGCHLD
（子退出）、SIGPIPE（pipe 无读者写入）、SIGSEGV/SIGILL/SIGBUS/SIGTRAP
（致命异常映射）三类内核内产生源；handler 建帧投递（sa_mask/siginfo/
浮点现场/备用栈）、EINTR 与 SA_RESTART、fork 继承与 execve 重置。

**投递模型**：信号分线程定向与组定向两类，可投递集合是两者挂起位图的并集减去该线程的屏蔽字；kill 发往整个线程组，tkill 与 tgkill 发往指定线程。回用户态唯一路径（任务运行循环）为投递检查点，每次至多
一个信号；阻塞 syscall 在 park 前后两次快路径决策（第二次不落睡，处理
睡中到达的信号）。产生统一经过滤：blocked 照常入队（屏蔽信号排队不丢）、
IGN 或 DFL 且默认动作属 Ign/Cont 静默丢弃。同步（硬件）信号走 force：
处置 IGN 重置 DFL、解除本信号屏蔽、必入队——防止装 IGN 的程序陷入无限
陷阱循环。帧内嵌 sigreturn stub（rv64 `li a7,139;ecall`、la64
`li.w a7,139;syscall 0`，本内核无 vDSO）；布局与魔数经 Linux UAPI 对照
与交叉 gcc offsetof 实测核验。sigsuspend 的帧屏蔽集为换入前旧集合
（Linux saved_sigmask），syscall 未完成时检查点先补 -EINTR 再建帧。

**偏差**（对照 Linux/POSIX）：

| 项 | 偏差 | 性质 |
|---|---|---|
| sa_flags | SA_NODEFER、SA_RESETHAND、SA_ONSTACK 已生效；SA_NOCLDSTOP 存而不执行（依赖停止/继续状态机） | 缺陷 11 |
| sigaltstack | 单进程无 per-thread；MINSIGSTKSZ 不查（size=0 即禁用）；SS_ONSTACK/AUTODISARM 输入 EINVAL；rt_sigreturn 不回改登记（Linux restore_altstack 会）；登记区间不可表达返回 EFAULT，SA_ONSTACK 运行时溢出防护未做 | 缺陷 12 |
| IGN 冲刷 | rt_sigaction 转 IGN/DFL-Ign 时无条件清除该信号的待处理位，被屏蔽的信号也清除 | 与 Linux 一致：Linux 6.12 `do_sigaction` 同样无条件冲刷，POSIX 3.3.1.3 要求被屏蔽的信号也丢弃 |
| sigtimedwait | 等待集命中时直接消费等待集内信号（含已屏蔽信号），调度器信号唤醒通道同步放宽到等待集 | 与 Linux 一致（原缺陷 10 已修复） |
| sigqueueinfo | RT 信号无排队（位图合并语义）；保留码 si_value 经 addr 槽落位 | 未实现：实时信号排队，见欠账 |
| 终止与 core | 无 core dump：Core 类信号死亡恒 CLD_KILLED，wait status 无 0x80 位（Linux CLD_DUMPED + WCOREDUMP） | 未实现 |
| 同步信号 si_code | 固定 SEGV_MAPERR/ILL_ILLOPC/BUS_ADRALN/TRAP_BRKPT，未细分 ACCERR/ADRERR；la handler 期间 FPU 异常回投 SIGFPE（fcsr_pending）未实现 | 未实现 |
| stub | 无 vDSO，stub 内嵌帧内，无 icache flush（QEMU 语义一致）；rt_sigreturn badframe 按 force_sigsegv 式收敛（处置复位、不重试投递；Linux force_sig 在装 SIGSEGV handler 时可循环） | 设计：无 icache flush，QEMU 语义一致；取舍，理由待补：badframe 时收敛不重试 |
| kill 族 | 不做权限检查；kill 的 pid 为正时发往该进程的整个线程组；pid<0 发往进程组 -pid，pid==0 发往调用者所在进程组，pid==-1 发往除 init 与调用者外的全部进程；tgkill 要求 tid 存在且属于给定 tgid，不匹配返回 ESRCH；tkill 按 tid 直接投递 | 缺陷 3；投递范围与 Linux 一致 |
| sigpending/sigsetsize | rt_sigpending sigsetsize 收紧为 ==8（Linux 允许 ≤8） | 缺陷 9 |

**欠账**（下一里程碑）：停止/继续状态机（SIGSTOP/SIGTSTP/SIGCONT、
Stopped 态、wait4 WUNTRACED/WCONTINUED）；控制终端与作业控制信号；RT 信号排队；ITIMER_VIRTUAL/ITIMER_PROF；
signalfd4；restart_syscall(219) 精确重启。验证方式：本地 21 项综合
自测（两架构，不入库）；libctest 信号用例已在双架构通过。

## 5. sync 锁模型

| 项 | 约定 |
|---|---|
| 前提 | 任务时代内核态关中断；单核无合法持锁等待；lock_debug 下 try_lock 失败即报告 bug |
| 检查 | DebugMutex 的 percpu 持锁深度及切换入口零深度检查始终启用；lock_debug 额外跟踪锁名/获取点（`#[track_caller]`） |
| 锁序 | SCHED→FRAME；REGISTRY→{FRAME, EXIT_REPORTS, PROC_TABLE, UTS_NAMES, SHM_TABLE, MSG_TABLE, SEM_TABLE, 打开文件 Handle, ROOT/MOUNTS/PAGES, NET}；Handle→{ROOT, MOUNTS, PAGES, NET}；PAGES→{ROOT, MOUNTS}；ROOT/MOUNTS→DISKS；SCHED→REGISTRY（信号唤醒 drain 与到期 ITIMER_REAL 触发的唯一嵌套方向，反向路径已核查不存在） |
| 反向 | 任何路径不得反向持有；fs/drivers 的 `spin::Mutex` 不受 DebugMutex 深度检查保护 |
| 唤醒 | 事件方不直接取 SCHED；用无锁原子标志，在调度边界消费。futex 的唤醒与重排队在注册表锁外按锁内算好的键执行 |
| 锁外析构 | 退出路径的 space/fs Drop 在 REGISTRY 锁外完成；exec 目前是例外 |
| 已知缺口 | 持有者 id 只更新不报告；dispatch 持 REGISTRY 做磁盘 I/O；exec 在 REGISTRY 锁内析构旧空间 |
| 欠账 | 锁序图（lockdep 式环检测）；SMP 化时全面重审 |

## 6. fs 与块设备

### 6.1 分层

| 层 | 职责 | 代码 |
|---|---|---|
| syscall | 用户参数、缓冲区访问、Linux 结果编码；调用语义见 §4 | `syscall/fs.rs` |
| context | 每进程 cwd、FD 表、打开文件对象与管道 | `fs/context.rs` |
| fs / metadata | 路径与 inode 分发、统一属性和目录接口、状态查询路径解析 | `fs/mod.rs`、`fs/metadata.rs` |
| cache | 文件共享页、普通读写与已有映射间的内容同步 | `fs/cache.rs` |
| 块层缓存 | 4 KiB 物理页帧承载的写回块缓存（16 MiB 上限、Clock 淘汰、`flush` 连续脏块合并写回），透明实现 `rsext4::BlockDevice` | `fs/block_cache.rs` |
| 文件系统适配 | Ext4 根卷、FAT 和 Ext2 辅助卷、后端错误转换 | `fs/ext4_rsext4.rs`、`fs/fat.rs`、`fs/ext2_mount.rs` |
| 第三方后端 | rsext4 0.8.1 的 inode、目录、数据块与日志；rust-fatfs 的 FAT 操作 | `third_party/rsext4/`、`kernel/Cargo.toml` |
| 块设备 | VirtIO Block 同步 I/O、字节访问与 MBR 分区解析 | `drivers/mod.rs` |

### 6.2 不变量

| 不变量 | 落地方式 |
|---|---|
| 用户地址访问收口 | syscall 经 `user_access` 复制；FS 接收内核缓冲区或交付回调，不直接解引用用户指针 |
| FD 与打开文件对象分离 | FD 表持有 `Arc<Mutex<OpenFile>>`；dup/fork 共享文件对象与偏移，CLOEXEC 保留在描述符中 |
| 打开引用配对释放 | inode 文件对象创建时 retain，最后一个文件对象引用释放时 release；dup/fork 不重复 retain |
| Ext4 删除不使已打开对象失效 | unlink 移除文件名；链接数和打开引用均为零时才回收 inode；FAT 不提供此保证 |
| 读位置按实际交付提交 | 只按成功交付的字节数推进文件偏移或消费管道数据；目录输出复制成功后才提交续读位置 |
| 定位 I/O 不改共享偏移 | `read_at/write_at` 接受独立偏移；普通 I/O 在打开文件锁内更新偏移 |
| 存活共享页唯一 | `PAGES` 锁下按 `(ino, offset)` 复用；映射持强引用，索引持弱引用 |
| 共享页初始化后才登记引用 | 分配、读入和填页完成后 retain；未完成登记的页析构时不写回、不 release |
| 分区访问有界 | Ext4 适配检查块范围，驱动检查扇区对齐、设备容量和地址溢出；同步请求返回后不再访问调用方缓冲区 |
| 等待交给调度边界 | FS 返回等待错误；系统调用释放锁后挂起重试；管道事件只置唤醒标志，锁序见 §5 |

### 6.3 补充约定

| 项 | 约定 |
|---|---|
| 执行前提 | 单核、内核路径不可抢占；FS 与驱动使用 `spin::Mutex`，不受 DebugMutex 持锁深度检查保护 |
| 根卷选择 | 扫描式：逐盘先试分区 1..4 再试整盘，取第一个可挂载的 Ext4；无可挂载卷允许继续启动。启动优先级：内嵌调试 ELF > 盘上 /init > 根卷无 /init 时启动内嵌 official-init（官方原盘布局）> 全无则 demo kthreads + 五任务 |
| Ext4 块大小与几何 | 仅 4 KiB 块；校验 magic、卷块数、非零 blocks/inodes_per_group，声明的块范围不得超过分区 |
| Ext4 可写准入 | incompat/ro_compat 使用适配器白名单，卷状态必须为 `EXT4_VALID_FS`；有日志时还要求日志 inode 为 8、无外部日志、卷块数不超过 2^32；JBD2 日志只允许两种写入布局：无特性 classic 与 64bit+checksum_v3 同时置位（crc32c 类型强制）；"仅 64BIT 无 checksum_v3"与"仅 checksum_v3 无 64BIT"均精确拒绝（两布局的 tag 步进/高块号与恢复端不兼容） |
| 只读与恢复 | `rsext4-readonly` 禁止 Ext4 适配层写入；挂载选项关闭日志重放，可写准入条件不作为只读卷的完整特性校验保证 |
| Ext4 元数据布局 | rsext4 按超级块的 `s_desc_size`、`s_inode_size` 读取布局，不固定为 64 字节描述符或 128 字节 inode；4 KiB 限制来自后端 `BLOCK_SIZE` |
| inode 标识 | 最高位区分 FAT 与 Ext4；Ext4 拒绝该位已置位的 inode，FAT 从 `0x8000_0000` 分配虚拟编号 |
| 共享页与普通读写 | read 叠加已有共享页，write 更新后端后同步已有共享页；truncate 改变长度前检查存活共享页，当前单核非抢占路径中检查后直接进入截断，不允许中途调度；成功初始化的共享页在最后释放时尝试写回，长度限于当前 EOF 内；失败限制见 §6.5 |
| 显式同步 | Ext4 fsync 先写回该 inode 的驻留共享页，再同步后端缓存、日志、`BlockCache` 全部脏块与底层块设备 `flush`；关机时同步并卸载可写根卷，释放块缓存物理页帧；FAT fsync 返回 ENOTSUP |
| 块缓存与帧记账 | `BlockCache` 数据存放于独占 `OwnedFrame`（上限 4096 块 = 16 MiB），按需分配，OOM 时淘汰既有槽或直通底层；持有帧数计入 `fs::retained_frames()`（任务退出帧守恒自检）与 `/proc/meminfo` 的 `Buffers`/`MemAvailable` 字段 |
| 字节块访问 | 完整对齐的扇区范围一次提交；不完整扇区先读后改，调用方负责串行化重叠写入 |
| 错误边界 | FS 对外返回项目 `Errno`，后端错误由适配层转换；不保证任意失败都无磁盘副作用，也不据此保证第三方内部无 panic |

### 6.4 已兑现

| 项 | 说明 |
|---|---|
| 文件调用分层 | 用户参数与 Linux ABI 在 syscall，FD 与打开文件操作在 context，磁盘格式在后端 |
| FD 与 inode 生命周期 | dup/fork 共享偏移，CLOEXEC 按描述符管理；Ext4 打开后 unlink 仍可访问，最后关闭回收 |
| Ext4 目录遍历 | 后端按块解析，统一返回文件名、类型、inode 与续读位置；缓冲区可失败分配并跨块复用，FAT 尚未接入 |
| 属性、容量与链接读取 | 统一 Metadata 提供所有者、大小、块数及可用时间；状态查询区分链接自身与目标，readlinkat 返回链接原文，statfs/fstatfs 查询 Ext4/FAT 卷容量，具体标志与限制见 §4 |
| 任意长度截断 | truncate/ftruncate 与 O_TRUNC 共用 inode 接口；Ext4 稀疏扩展不按逻辑长度分配块，缩短处理尾块及预分配回收；映射、后端及权限边界见 §4 |
| 定位与向量 I/O | 普通与定位读写共用搬运流程，iovec 先复制到内核；已有进展时返回短传输，支持范围见 §4 |
| 共享页初始化失败处理 | 分配或填页失败不触发未初始化数据写回，已登记的 inode 引用由页生命周期持有 |
| Ext4 日志同步 | 接入有日志卷的正常挂载、显式同步与卸载；JBD2 提交按盘上特性写 v3 tag（16 字节、64bit 块号、逐块 crc32c(uuid_seed + be32(seq) + 载荷)，首 tag 后 journal UUID、后续 SAME_UUID），描述符块尾与 commit 块整体校验；目录块修改统一经 `modify_via_journal`/`flush_via_journal` 入
  同一 JBD2 事务（插入/删除/重命名/新目录块全覆盖，cache 只持干净副本，
  提交所有权单一化）；commit 块落盘前先
  持久化 journal 超级块（s_start/s_sequence）。断电窗口经标准工具验证：
  commit 已落盘场景完整重放出 mkdir 新目录（inode/位图/目录块原子一致），
  commit 未落盘场景零应用；不包含异常关机后的自动日志恢复 |
| 有界块访问 | 对齐请求批量提交，分区与设备分别检查访问范围；rv 使用 MMIO，la 使用 PCI ECAM |

### 6.5 欠账

| 项 | 现状 / 计划 |
|---|---|
| inode 与挂载身份 | 最高位分流；FAT 依赖 `(mount, path)` 登记序号，cwd/目录 FD 保存路径字符串。需统一挂载与对象身份 |
| 路径与文件操作 | 状态查询已有链接与尾斜杠处理，open/exec 尚未统一；rename 目前保护在用目录并仅支持普通移动与 NOREPLACE；link/symlink、已删目录的相对路径及完整身份权限检查等缺口见 §4 |
| FAT 接口 | 无目录遍历与时间字段，每次 read/write/stat 按路径重开，打开后 unlink 返回 EBUSY；需补齐统一接口 |
| 共享页修改跟踪与写回 | 无脏状态，未修改页与只读映射也会尝试写回；只读 Ext4 根卷写回被拒绝并记日志。需 MM 提供修改跟踪，FS 保留失败数据并支持重试 |
| 共享页一致性失败 | `coherent` 的页内访问失败只记日志并跳过更新；最后释放时写回失败仍释放页。需明确错误传播、数据持有者和恢复策略 |
| 堆与栈预算 | exec 整镜像读入 Vec，rsext4 单次 extent run 可分配 1 MiB；I/O 和目录临时缓冲区虽可失败分配，仍有分配开销，部分路径保留页大小栈缓冲区。需测量内存与性能成本 |
| 分配失败覆盖 | 管道扩容及第三方部分分配不可失败；32 MiB 固定堆下可能触发分配失败终止。需与 §1.5 的全局 OOM 策略统一 |
| 脏卷启动与恢复 | 可写挂载拒绝需恢复的卷，入口对初始化错误使用 expect；无日志重放或降级策略。需确定恢复、只读降级或诊断退出方案 |
| FAT 卸载失败 | 先移除挂载记录，再调用消费式 unmount；失败时记录已丢失。需确定可重试的同步与卸载流程 |
| 目录完整性与后端审计 | 目录线性查找的校验和失败仍可能继续解析；第三方有 unwrap/panic 和不可失败分配，用户可达性及错误传播需逐项核对，不能沿用旧 ext4_rs 的审计结论 |
| 块设备框架边界 | 同步轮询，无中断驱动或请求队列；DMA 页仍走受限的裸 `frame_alloc`，初始化分配失败返回物理 0。需完善失败处理与请求生命周期 |

## 7. 自检与验证

### 7.1 自检清单

| 位置 | 不变量 | 运行时机 |
|---|---|---|
| main.rs（ebreak/BREAK_TICKS） | trap 回调链路：断点恰好送达一次 | 每次启动 |
| main.rs（BOOT_TICKS） | 时钟中断持续到达 | 每次启动 |
| mm/mod.rs::init | 帧账本：超量申请被拒且不改变空闲数 | 每次启动 |
| mm/self_test.rs | 页所有权/区间分裂/权限/边界/释放守恒 | 每次启动 |
| task/mod.rs::run（帧守恒） | 全部任务退出后帧统计回到基线（覆盖 kstack 与用户空间回收） | 每次启动 |
| task/sched.rs、task/mod.rs 的 debug 断言 | 切换后 dead 栈释放页数、集中唤醒容量、孤儿记录回收 | selftest 档执行相应路径时 |
| task/mod.rs::spawn_oom_probe | 孵化 OOM 无副作用：不改帧数、不登记 | 仅 selftest 档 |
| mm/frame.rs 预算注入 | 逐点 OOM 失败路径不变量 | 仅 selftest 档 |

自检代码注释以 `自检：` 开头，写明验证的不变量与运行时机。当前执
行尚不完整（`mm/self_test.rs` 模块头、`user_copy_tests`、`frame.rs`
预算函数），待统一。

### 7.2 验证入口

| 入口 | 内容 |
|---|---|
| `make run-rv` / `make run-la` | 默认以 release 内核无盘启动 QEMU，运行七个演示任务（kthread A/B、hello、sched×2、check、ill）；官方原盘判分见下方 test 入口 |
| `make selftest-rv` / `make selftest-la` | 构建 selftest 内核；启动该产物时启用 debug 断言、lock_debug、LOG=info 及额外 OOM 注入；polyhal #8 需 `-Zub-checks=no` |
| `make test-rv` / `make test-la` | 官方原盘八组验收（basic/busybox/lua/libcbench × musl/glibc）：官方 QEMU 命令、原版 judge 判分、每轮干净盘副本；`make test-setup` 准备评测器与原盘 |
| `tests/file_mapping.rs` | 用仓库固定的 Rust 执行 `rustc --edition=2021 --test tests/file_mapping.rs -o /tmp/ouro-file-mapping && /tmp/ouro-file-mapping`，覆盖缓存写回失败、重试与引用释放。 |
| `tests/fs_stat.py --metadata` | `make all` 后执行 `python3 tests/fs_stat.py --metadata --output target/fs-validation/metadata`，验证双架构 128/256 字节 inode 的创建掩码、fork/exec、NOW/OMIT、FD/链接时间更新与落盘；只读版本先构建相应 feature，添加 --readonly 并指定独立输出目录，结束后恢复默认内核 |
| `tests/fs_stat.py --truncate` | 构建后运行；验证双架构 128/256 字节 inode 的缩短、稀疏扩展、零尾部、预分配与索引回收、偏移不变、链接/已删名 FD、父子进程共享映射保护及错误参数；debugfs 独立核对落盘内容并运行 e2fsck/FAT fsck；只读构建增加 --readonly |
| `tests/fs_stat.py --rename` / `tests/fs_rename_backend.py` | 前者在双架构及两种 inode 大小验证重命名、替换后的旧 FD、目录链接数/父项、扩容、目录引用保护与跨挂载拒绝，运行前后 e2fsck；只读构建另加 --readonly。后者在宿主端逐次注入元数据时间源 EIO，验证替换、插入和扩容后的回滚及 e2fsck，不代表磁盘掉电或所有 I/O 失败验证 |
| `tests/fs_stat.py` | `make all` 后执行 `python3 tests/fs_stat.py`，验证双架构 128/256 字节 inode 的元数据、路径、readlinkat 和 statfs/fstatfs；容量与磁盘快照对照，并验证分配、最后关闭回收及 Ext4/FAT 隔离；镜像运行前后 e2fsck，FAT 卷运行后 fsck.fat。只读版本先构建 rsext4-readonly，同一脚本以 --output 指定独立输出目录 |
| `tests/fs_io.py` | `make all` 后执行 `python3 tests/fs_io.py`，构造独立 Ext4 盘验证双架构定位/向量 I/O、用户缓冲区错误、管道与落盘一致性；只读版本先 `make all FEATURES=rsext4-readonly` 再加 `--readonly`，结束后恢复默认构建 |
| `tests/fs_fcntl.py` | `make all` 后执行 `python3 tests/fs_fcntl.py`，验证双架构 FD 分配及耗尽、标志共享、追加写、非阻塞管道、fork 和成功/失败 exec；结束后运行 e2fsck；只读版本同样先构建相应 feature，再加 `--readonly` |
| `tests/mm_validate.py` | MMU/TLB 硬件探针；依赖 musl 交叉工具链与 `~/.config/ouroos/env.sh`，尚未纳入日常门禁 |

## 8. 工程与文档遗留（非 ostd 契约）

| 项 | 现状 | 处理 |
|---|---|---|
| `println!` | main/task/lang_items 用 `println!` 输出验收行，与 AGENTS §6 的 log 规则冲突 | 契约声明例外，或改 log 并在 Makefile 固定 LOG |
| README | “演示视频”“团队成员”为空 | 补内容或删除空节 |

### 存储调用链栈预算

文件 syscall 的目录输出与 read/write 暂存使用可失败分配的 4 KiB 堆缓冲（`transfer` 通过单槽全局池复用已分配的 4 KiB 堆缓冲以消除高频小读写分配开销，首次分配失败仍返回 ENOMEM，发生在读取、写入和目录游标推进之前）。RISC-V selftest 构建中分发栈帧由 8400 字节降为 512 字节。`user_access` 对 4 页以内的短传输使用栈上 64 字节数组并合并权限校验与单次页表翻译；`UserPageTable::activate` 在当前硬件页表已指向本空间时跳过冗余寄存器写回与全局 TLB 刷洗（所有 `map`/`protect`/`unmap` 修改处已即时刷 TLB）。JBD2 提交的三个暂存块也在首个磁盘写入前准备完成；不改变存储接口或内核栈配置。该修复不构成所有存储路径的栈上界证明，保护页防止向相邻栈页写入，当前没有独立的溢出恢复栈。

### madvise 支持范围

调用号 233 支持 NORMAL/RANDOM/SEQUENTIAL/WILLNEED 的完整映射范围校验；访问模式建议目前不改变预读策略。私有匿名、堆、栈接受 DONTNEED；丢弃时无需分配新物理页。DONTNEED 撤销 PTE 并释放物理页，保留区域；后续合法访问按需分配零页，mincore 可观察驻留位清除。文件 DONTNEED 撤销调用进程的 PTE 并丢弃驻留副本，再访问从文件后备取数；共享匿名 DONTNEED 撤销本地 PTE，后备对象保留已有内容。空洞在改内容前拒绝，不部分清零。语义参考 [madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html)。

### 匿名缺页与用户访问

地址空间页表与缺页新增页清单使用 RefCell 提供单核内部可变性；物理页不向调用者暴露可变引用。结构修改前将新增页合并至所有权清单，fork 同时复制两份清单中的私有页，未驻留区域保持未驻留。缺页先检查区域和实际权限，再准备数据页、元数据与页表；失败不发布新页。用户缓冲区复制仍先准备完整区间再复制，错误不产生部分数据写入；准备阶段可能使前面的合法页驻留。用户缺页分配失败仍沿用 task 的致命异常退出接口；信号投递尚待任务模块接入。

### 锁页与映射同步

mlock/munlock/mlock2 保存区域锁页属性，部分解锁拆分区域，ONFAULT 保持未驻留页延迟分配；普通锁页填充页后才提交锁属性。fork 不继承锁，DONTNEED 拒绝锁页，munmap 解除对应锁。已接入 RLIMIT_MEMLOCK 字节限额；缺少进程凭证模型，不能宣称通过 LTP 的凭证测例。mlockall 支持 CURRENT/FUTURE/ONFAULT，munlockall 同时清除未来策略；fork 不继承未来锁策略。

msync 按相交 VMA 的文件偏移选择缓存页，再同步 Ext4 后端，失败返回后端错误；私有页不回写。最后一个映射释放时若写失败，缓存继续持有页，可在 fsync 或关机前重试。MS_INVALIDATE 遇锁页返回 EBUSY。成功同步后共享别名继续使用同一缓存页，私有副本保留进程自己的修改。MS_ASYNC 仍同步等待，FAT 同步仍返回 EOPNOTSUPP。页写入获后端接受与设备持久化是两个阶段。

### 进程资源限额

getrlimit/setrlimit/prlimit64 支持全部 16 项 `RLIMIT_*`（0..=15），当前仅本进程。限额随 fork 复制并跨 exec 保留；其中 `RLIMIT_NOFILE` 约束 FD 分配，`AS` 约束新映射与 remap，`MEMLOCK` 按锁定区间去重，`DATA` 约束 brk 与可写私有非栈非执行映射的增长，`STACK` 在 exec 发布前检查固定栈；其余资源（`CPU`、`FSIZE`、`CORE`、`RSS`、`NPROC`、`LOCKS`、`SIGPENDING`、`MSGQUEUE`、`NICE`、`RTPRIO`、`RTTIME`）按 Linux 默认初值提供查询、修改与 `rlim_cur <= rlim_max` 校验，暂不强制拦截对应子系统行为。尚未实现跨进程 prlimit 与基于凭证的硬限额提升授权。

文件映射持有 inode；fork 复制已驻留私有页，共享页保持别名。mremap 增加的页按首次访问时的文件长度与内容填充。截断撤销超出新长度的驻留页，清除最后一页被截的字节。整页超出 EOF 和后端 I/O 失败分别产生 BUS_ADRERR 和 BUS_OBJERR；缺页内存不足终止当前任务（wait4 状态 9）。文件后备故障按默认 SIGBUS 退出，wait4 可见相应状态，尚无可捕获的用户信号处理器。存储分支原有 `tests/fs_truncate.rs::mappings` 断言存活映射下返回 EOPNOTSUPP。

### 原版 LTP 所需的跨模块接口

| 提供方 | 接口与约束 | 当前状态 |
|---|---|---|
| MM | `mm::frame::memory_snapshot() -> MemorySnapshot`，同一次帧分配器加锁中读取已登记和空闲 RAM，字段 total_kib/free_kib 的单位为 KiB。无换页、无可回收缓存估算时，MemAvailable 可取 free_kib 的保守值。 | 已提供 |
| procfs/VFS | 打开 /proc/meminfo 时取一次快照，生成 MemTotal、MemFree、MemAvailable、SwapFree 等字段；同一次打开按偏移读取，读尽返回 EOF。无交换设备时 SwapFree 为 0。 | 已接入只读 meminfo；brk01 越过临时目录的 chown，通过 1 条断言 |
| task | current_credentials(pid) 返回真实/有效 UID、GID，进程创建/exec 保留或更新凭证；getgid/getegid 等调用以及 VFS 授权共用此来源。 | 身份查询与切换调用已接入进程记录里的 `Credentials`；VFS 授权未接入 |
| fs | set_owner(inode, uid: Option<u32>, gid: Option<u32>, credentials) 返回 Result；None 对应 uid/gid 的 -1，检查调用者权限，成功后 stat 与重新挂载均应可观察更新。 | 已接入 Ext4 的 fchownat/fchown，chown01、chown05、fchown01 共通过 8 条断言；mincore01 已越过 chown，属旧接口用例，不打印 Summary |
| task/signal | 注册用户信号动作、投递访存异常与恢复用户上下文；无处理器时按相应信号终止进程。 | 已实现（§4.5）；原版 LTP 的信号用例接入与验收仍待 |

测试基线是 pre-2025 的 LTP 20240524。表中状态取自启动器逐例驱动的全量运行，见下文。

三层页表为信号只读返回页预留最高 1 GiB 根槽，普通用户映射上界为 2^38 − 2^30，可装入默认链接在 0x120000000 的 LoongArch 静态 ELF。exec 按继承的 STACK 软限额确定栈预留量，上限 8 MiB。mprotect 验证整段覆盖、文件写权限和限额后提交；空洞返回 ENOMEM，未对齐地址返回 EINVAL。/dev/zero 共享映射将 FD 的写权限上限保存在共享页对象中，权限修改前检查此上限。私有映射可写，写入不影响其他映射。

exec/spawn 从设备树启动熵派生独立的 16 字节，AT_RANDOM 指向新用户栈。静态 LoongArch glibc BusyBox 重定位后使用 mprotect(PROT_READ) 关闭写权限；页表保留执行权限。QEMU 10.0.2 上 `busybox sh -c exit` 成功。/dev/zero 支持打开、读写、设备属性查询及私有/共享映射。

固定地址映射支持 MAP_FIXED_NOREPLACE（重叠返回 EEXIST，原数据保留）。MAP_LOCKED 使用与 mlockall 相同的限额，在建立映射后尽力预取，不改变未来映射的锁策略；没有交换空间预留账本，MAP_NORESERVE 不额外预留。MAP_POPULATE 在 VMA 建立后尽力预取；与 MAP_NONBLOCK 同用时不预取。未锁定的私有匿名 mremap 扩展只增加虚拟区间。MADV_DONTFORK/DOFORK 控制子进程是否继承该区间；WIPEONFORK/KEEPONFORK 控制私有匿名、堆、栈页在子进程内是否重新取零页。父进程内容不变。共享匿名扩展仅增加虚拟页描述，物理数据页按需分配；fork 时私有匿名、堆和栈驻留页按写时复制共享。ELF 页和已驻留的私有文件页仍在 fork 时复制；尚无换出。

/proc/meminfo 每次打开保存一次帧分配器统计；Cached 只计文件页缓存的数据帧。MemTotal 为已登记的可分配物理内存；MemAvailable 为 MemFree 的保守估计；交换为零。sysinfo(179) 提供同口径的总量和空闲量，单位 1024 字节；尚未统计负载均值和共享内存用量。procfs 另提供根目录、`/proc/<pid>/`（stat/cmdline/status）、`/proc/self/maps`（按 Linux `%08lx-%08lx` 导出当前进程 VMA 快照）、`/proc/self/fd`（导出打开时刻存活 FD 列表目录快照）、`/proc/version`、`/proc/sys/kernel/pid_max`、`/proc/sys/kernel/tainted`、`/proc/sys/fs/pipe-max-size` 与设备节点，枚举来自 Task 维护的独立快照表（§4.3"其他"行）；/proc/mounts 报告根卷与 FAT 挂载。 /proc/cpuinfo 报告单核处理器编号与目标架构；挂载列表同时包含 Ext2 辅助卷。

LTP 组由启动器逐例驱动，不执行盘上的 ltp_testcode.sh：按名字排序遍历 ltp/testcases/bin 的普通文件，每例在独立会话里执行并套用 2 秒逐例时限，超时按会话逐进程 SIGKILL，回收等待上限 30 秒；用例超时或 /tmp 空闲低于 256 MiB 时清空 /tmp，单次最多两万次删除尝试。组结束后列出用例自建会话留下的进程，对它们发 SIGKILL 并等待退出，上限同样是 30 秒。截止时刻取启动器开始后 3400 秒，到点后不再启动新用例；该组只在 loongarch64 上启用，riscv64 上截止时刻已过、不启动任何用例并打印空的组标记，判分按两架构相加，所以该组分数只来自 loongarch64。glibc 组当前零分，调用位置保留但未启用。原版脚本无逐例时限，镜像中第一个不退出的用例是 cgroup_fj_proc，先 sigsuspend 等待信号，因此原版脚本在任何内核上都跑不到第 107 例之后；脚本也无超时保护，第 184 例 connect01 会 kill(0, SIGKILL) 终止同进程组的脚本 shell。

启动器在建立根目录布局时创建 /etc，写入 /etc/passwd 与 /etc/group，各含 root 与 nobody 两个条目，nobody 的 UID 与 GID 都是 65534。镜像不带这两个文件，按用户名查 UID/GID 的程序在其中找不到 nobody，会在准备阶段以 TBROK 结束，例如 access01、setreuid 族、setfsgid 族与 chown03。写入失败时启动器在串口打印 write FAILED 行，不影响后续测例启动。

loongarch64 实测，2026-11-26，内核含属主修改、rmdir 延迟回收、/dev/zero、capget、致命信号结束整个线程组与本次的账户数据库：musl 组 2820 例全部执行后来宾自行关机，组内约 772 秒，其中 261 例超时被杀；通过断言 1412 条，分布在 329 例，按判分公式折算的单架构组分约 178.1。另一轮相同代码上 clock_nanosleep01 的 11 条断言在 2 秒时限内完成，该轮为 1423 条、330 例、约 179.0，两轮差额只来自这一例。同一内核不写账户数据库时为 1102 条、288 例、约 149.6，组内 763 秒；差额来自 access01 的 147 条与 setreuid、setregid、setresuid、setfsgid、stat、chmod 等按用户名取凭证的用例。逐例时限取 2 秒而不是 5 秒：5 秒时限下正常结束的用例里只有 alarm05 到 alarm07 需要超过 2 秒，估计共少 3 条断言，换来组内时间少约 830 秒。退出状态为 TCONF 的 795 例与 TBROK 的 613 例不计分。glibc 组前 220 例零通过断言，未启用。

本地 pre-2025 的 ltp_testcode.sh 会枚举镜像实际安装的二进制。启动器逐例驱动下，mlock01 通过 4 条，brk01 通过 1 条，mmap17 通过 1 条；该次全量运行的 mprotect01 在第 3 条断言的 mmap 处中断；mincore01 与 msync01 打印了通过断言，但属旧接口用例，不打印 Summary，不计分。判分器只汇总 Summary 段的 passed 计数，不数 TPASS 行；本镜像全量里打印 TPASS 却没有 Summary 的用例有 109 例、693 行，其中 91 例没有任何 TFAIL，这些断言不进分数。TCONF、TBROK 均不计为通过；未修改测例、脚本或 uname 来绕过前置条件。

2026-11-26 单例复测：使用 pre-20250615 镜像中的原版 musl mprotect01，riscv64 和 loongarch64 均通过 3 条断言并退出 0。只读 FD 建立的 /dev/zero 共享映射在请求增加写权限时返回 EACCES。未重跑全量 LTP。

信号与 MM 联合路径：MM 先尝试修复用户缺页，再向信号模块交付未映射、权限不足或文件后备错误；内核代表 syscall 复制用户指针失败继续返回 EFAULT。
