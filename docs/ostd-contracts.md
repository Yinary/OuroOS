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

## 0. 总览

| 子系统 | 权威内容 | 主要实现 |
|---|---|---|
| mm | §1 不变量与失败模型 | `kernel/src/mm/` |
| polyhal 边界 | §2 可用原语与缺陷 | `third_party/polyhal-trap/` |
| task | §3 执行、调度、生命周期 | `kernel/src/task/` |
| 信号 | §3.4/§3.5/§4.5 投递模型与偏差 | `kernel/src/task/signal.rs`、`kernel/src/sigframe/`、`kernel/src/syscall/signal.rs` |
| syscall | §4 Linux ABI 对照 | `kernel/src/syscall/`、`fs/context.rs` |
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

### 1.2 十律

| 不变量 | 落地方式 |
|---|---|
| 物理内存唯一入口 | 只有 region → frame 登记；裸 `frame_alloc` 仅 kernel_pt、kstack、DMA 三处受限适配 |
| 唯一释放凭证 | `OwnedFrame` 不可 Clone；释放前必须撤销映射并刷 TLB |
| 分配即清零 | `OwnedFrame::new` 清零；kstack/DMA 显式清零 |
| 拥有页字节访问 | `OwnedFrame::read/write/copy_from` 校验页内范围并封装直映指针；`address_space::init_elf_page` 提供 ELF 初始页写入接口 |
| 期望权限 ≠ 实际权限 | 两架构无 NX；`mprotect` 撤 X 明确拒绝 |
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
| 内核堆 | 固定 8 MiB，TODO 在 `allocator.rs`；mm 元数据 try_reserve |
| user_access 并发前提 | 单核、内核不可抢占，复制期间无并发 munmap |
| kstack | 每栈独占窗口槽（低地址 guard + 8 栈页）；窗口下级表在全部地址空间共享，guard 不映射；rv 复制窗口根项，la 自建仅含窗口项的内核根 |
| ELF | ET_EXEC 静态小端 ELF64；差异见 §4 |

### 1.4 已兑现

| 项 | 说明 |
|---|---|
| brk 字节级记账 | `address_space::brk` |
| mmap 空洞 / MAP_FIXED | `find_free`、`replace_region` 事务替换 |
| fork 深拷贝 | `deep_copy`，建成才发布，无 COW |
| exec 先建后切 | 新空间含 argv/envp/auxv，成功才替换 |
| 页字节访问收口 | 拥有页复制及 ELF 初始页写入由 mm 封装；`elf.rs`、`fs/cache.rs`、`syscall/memory.rs`、`task/user_task.rs`、`task/exec.rs`、`task/task.rs` 拒绝 `unsafe` |
| MAP_SHARED 文件页缓存 | `fs/cache.rs`；映射持强引用、索引持弱引用、最后释放写回；无脏位，见 §6 |
| 内核栈虚拟窗口 + 底部保护页 | `mm/kstack.rs`；16 GiB 起共享窗口，槽 = guard + 8 栈页，逐页映射，溢出即页错误 |

### 1.5 欠账

| 项 | 现状 / 计划 |
|---|---|
| 直映硬化 | 直映区 base canary + 去可执行权限；未实现 |
| 数据页/区域线性扫描 | 规模大后换有序结构 |
| 按需分页 / COW / 通用页缓存 / swap / 远端 TLB | 未做；MAP_SHARED 文件页缓存已实现，不是通用读写页缓存 |
| 全局堆失败策略 | 8 MiB 固定；pipe 扩容、rsext4 的 `alloc::vec!` 不可失败，可耗尽→panic；需要统一 OOM 策略 |

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

### 2.3 vendor 补丁

polyhal-trap 0.4.0 整 crate vendor 至 `third_party/polyhal-trap`，
根 `[patch.crates-io]` 指向本地；polyhal 本体与 polyhal-boot 仍走
crates.io。补丁：#5 TrapType 直达、#7 Unhandled 转交、la `from_user`
补齐、la 非对齐事件交 OS 安全模拟、完整 FP 现场与显式用户返回状态。
清单与升级回归见该目录
README；不得直接编辑 `~/.cargo/registry`。上游 PR（MIT）待提。

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
- PC 推进归 HAL：断点 +2 由 polyhal 做，syscall 由 `syscall_ok` 恰
  好一次。
- 首次入口在调度器锁下取出 `TaskBody`；用户 TrapFrame 和 nanosleep
  截止时间由该任务内核栈上的运行循环局部持有，调度器不借用用户现场。

### 3.2 中断、抢占、时间片

| 项 | 约定 |
|---|---|
| 中断 | 任务时代内核态关中断；用户态与 idle 等待开；启动阶段（`IRQ::int_enable` 到 `task::run`）是例外，仅时钟到达 |
| 抢占 | 只发生在用户态逃逸点；内核路径不可抢占，内核任务协作让出 |
| 时钟 | 信号不丢失，挂起至少到调度边界送达；trap 回调不取锁 |
| 时间片 | 固定 1 tick（TICK_MS=100）轮转，无优先级；切入刷新 `slice_tick`；等待中不占就绪队列 |

### 3.3 数据模型

| 对象 | 内容 | 位置 |
|---|---|---|
| Task | 内核栈 + 私有 KContext + 首次入口身体 + pid | 调度器 Box；身体首次取出后为 None |
| ProcessRecord | 地址空间 + fs + 退出信息 + 父子关系 + 信号状态 | 静态 REGISTRY |
| SignalState | 处置表 / pending / blocked / 信息槽 / 备用栈 | `ProcessRecord.signal`；字段按共享侧（处置、pending）与私有侧（blocked、备用栈）分组注释，为线程化预留迁移形状（私有侧届时搬入线程记录） |
| CURRENT | 当前任务地址（整数存址，绕开裸指针 !Send） | percpu |

Task 与 ProcessRecord 分离是为线程预留；地址空间只住注册表。pid
递增不复用，孵化失败允许空洞。`LocalSpace` 是 mm 提供的单核凭证，
`unsafe impl Send` 的依据集中在 mm，SMP 化时欠账也集中于此。
CURRENT 记录当前任务地址；调度器的 `current` Box 持有实体，切换时
核对两者一致。KContext 只向调度器提供裸地址，用户运行循环不得改写。

### 3.4 生命周期

- wait 收割即删；注册表只存活跃进程与未收割僵尸；重复 wait 得
  ECHILD。
- 孤儿过继内核 init；已退出的孤儿即收，活孤儿随后退出时即收，运行时间丢弃。
- 退出 Task 的内核栈先进入 dead 表，切到其他任务或 idle 栈后立即回收。
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
  运行时间并入父（与收割口径一致）；孤儿过继 init 的路径维持即收。

### 3.5 等待与唤醒

- `Flow::Wait(WaitReason::Deadline/Children/Pipe/Signal)`：park 进等待
  表并切走，保留 syscall PC；醒来重执行重查条件（Mesa 风格）。
- Deadline 由调度边界按硬件时钟扫描；Children/Pipe/Signal 由事件方置
  无锁原子标志，在调度边界统一消费，避免 fs 在 REGISTRY 内反向取
  SCHED。Signal 标志在信号实际入队后置位；drain 持 REGISTRY 一次按
  "pending & !blocked 非空"精确判定等待者（SCHED→REGISTRY 唯一嵌套点，
  见 §5），集合外信号假唤醒由唤醒点重查消化，无害。
- 阻塞 syscall 的信号打断在 park 前后做两次快路径决策（第一次可落
  睡、睡醒后补一次不落睡重查）：sigsuspend/sigtimedwait/nanosleep 被
  handler 类信号打断一律以 -EINTR 完成，pipe/wait4 按 SA_RESTART 分
  重启与 -EINTR；语义规范与偏差见 §4.5。
- 孵化预留 ready/waiting 各自容纳全部存活任务的容量；集中唤醒不分配。
- init 在仍有活跃进程时等待 Children 事件，醒后重查条件。
- 等待表满时 park 退化为就绪让出；就绪空而等待非空时 idle 等时钟；
  互等即永久等待（QEMU 超时兜底）。

### 3.6 syscall 框架

内部一律 `Result<_, Errno>`，边界统一转负值。`Flow`（Continue /
Yield / Wait / Process / SigReturn / Exited）是调用对执行流的全部
影响。`Process` 表示需在 REGISTRY 借用解除后由运行循环处理（fork/
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
| la idle | 自旋等钟；Deadline 依赖硬件时钟读数，不阻塞正确性 |

| 欠账 | 现状 / 计划 |
|---|---|
| pipe/子进程唤醒的精确订阅 | 当前宽松匹配 + Mesa 重执行；新增 pipe 状态变化必须补 `request_pipe_wake`，否则等待者可能永久挂起 |
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
| 文件 | getcwd、dup、dup3、mkdirat、unlinkat、mount、umount2、chdir、openat、close、pipe2、getdents64、lseek、read、write、fstat、fsync、statx | `fs::context` |
| 进程 | exit、nanosleep、sched_yield、times、getpid、getppid、clone、execve、wait4 | `task::process_call` |
| 信号 | kill、tgkill、rt_sigaction、rt_sigprocmask、rt_sigpending、rt_sigsuspend、rt_sigtimedwait、rt_sigqueueinfo、sigaltstack、rt_sigreturn | `syscall/signal.rs`、`task/signal.rs`、`sigframe/`（契约与偏差见 §4.5） |
| 内存 | brk、mmap、munmap、mprotect | `syscall/memory.rs` |
| 其他 | uname、gettimeofday | `syscall/mod.rs` |
| 其余 | 未列出的调用号 | ENOSYS |

### 4.3 偏差对照

| 调用/类别 | 当前实现 | Linux 对照 / 说明 |
|---|---|---|
| read/write | 4KiB 内核栈分块循环至填满/写尽/EOF；出错且已有进展时返回短读/短写 | 语义兼容；无单次截断 |
| pipe | 64KiB；读空或剩余空间不足本次分块时阻塞，O_NONBLOCK 返回 EAGAIN；不做部分写；无读者时写返回 EPIPE 并产生 SIGPIPE（§4.5） | Linux 同容量；SIGPIPE 与 -EPIPE 并行产生同 Linux（默认处置下写者死于信号、见不到 EPIPE）；部分空间不足不做部分写 |
| wait4 | wanted<=0 等任意孩子，>0 指定 pid，<-1 EINVAL；无僵尸则阻塞，无孩子 ECHILD；WNOHANG 支持；status 按 ExitInfo：正常 `(code&255)<<8`、死于信号 `sig` | 语义接近；忽略 rusage；无进程组概念；无 core 位 |
| clone | 仅 flags 恰好为 SIGCHLD(17) 的进程 fork；非零 stack 设置子 SP | 仅为兼容传入栈顶的调用方；不支持线程/共享地址空间 |
| execve | argv/envp 各 ≤256 项、单串 ≤4095 字节；总受 4 页栈限制（字符串约 12KiB，超出 E2BIG）；auxv 仅 AT_PAGESZ/AT_NULL；整镜像读入内核堆 | 原 32KiB 上限不可达；AT_PHDR/AT_RANDOM 是 glibc 静态需要，静态 musl 不依赖 |
| nanosleep | 到期返回 0；rem 不回写；相对 now | 语义兼容 |
| times | tms 四字段来自任务记账；返回启动以来 100Hz tick | 语义兼容 |
| uname | sysname=OuroOS、nodename=ouro、release=内核版本、version=OuroOS、machine=架构名、domainname=local | 合成身份信息 |
| gettimeofday | 返回启动以来单调时间；ext4 时间从卷 `s_wtime` 起算 | 不是墙钟，无 RTC；两套时钟 |
| statx/fstat | statx 写 `stx_mask=0x307`、`stx_blksize=4096`，`st_dev`/`st_rdev` 为 0；FAT 权限 0777；用户可见 atime/ctime/mtime 恒 0 | 0x307 是 mask 不是 dev；ext4 写入路径的 mtime/ctime 由 rsext4 维护，atime 跳过 |
| fsync | EXT4 写回该 inode 的共享页并同步 rsext4 缓存/日志 | FAT 返回 ENOTSUP |
| mount | fstype 接受 vfat/fat；源设备 `/dev/vd<小写字母>[0-4]`（无后缀或 0 为整盘）；flags 必须 0，data 忽略 | 仅 MBR 主分区；不限于 a-d |
| mmap | 匿名仅 PRIVATE；文件 PRIVATE/SHARED；EOF 整页拒绝（ENOTSUP）；MAP_FIXED 事务替换 | 共享页无脏位，释放即回写（含 O_RDONLY 映射与 rsext4-readonly 的 EROFS 日志）；O_RDONLY+PROT_WRITE 返回 EBADF（Linux EACCES）；MAP_FIXED 可覆盖用户栈；flags 白名单 |
| mprotect | 支持 PROT_NONE 与含 X 的权限（W 必须同时有 R）；撤 X 返回 EOPNOTSUPP(95) | 两架构无 NX；实际可执行权限由 translate 报 |
| brk/munmap | brk 失败返回原 break；munmap 起址页对齐、长度向上取整、允许空洞 | 均无按需分页；brk 立即分配/释放物理页 |
| ELF | 仅 ET_EXEC 静态；p_vaddr 页对齐，p_filesz>0 时 p_offset 也页对齐；零地址允许 | 当前 basic ELF 只用 0x1000（rv 侧核对，两架构同链接脚本）；hint 与 MAP_FIXED 都可落到低址（低址并非不可达） |
| unlink/unlinkat | EXT4 unlink 后句柄存活、最后关闭回收；FAT 有句柄时 EBUSY；unlinkat flags 仅 0 | AT_REMOVEDIR 返回 ENOTSUP |
| getdents64 | syscall 层直接解析 EXT4 盘上 dirent；单次最多 4KiB；FAT 不支持 | 分层欠账，见 §6 |
| 路径 | 必须是合法 UTF-8；总长 4096 字节，单分量 255 | 非 UTF-8 文件名不可访问 |
| 其他 | stdin 读恒 EOF；fd=1/2 直通控制台；sched_yield 轮转后可能立即再次调度；getpid 总成功，getppid 返回注册表 parent | 无信号投递前的旧描述已过时，信号见 §4.5；孤儿过继 init |

### 4.4 下一里程碑缺口

| 类别 | 缺口 |
|---|---|
| 基础调用 | fstatat(79)、clock_gettime(113)、exit_group(94)、fcntl(25)、ioctl(29)、readv/writev(65/66)、set_tid_address(96) 等仍 ENOSYS |
| 信号残余 | 停止/继续状态机、RT 排队、core 位等偏差与欠账集中登记 §4.5 |
| ELF（静态） | busybox 等静态程序的段 vaddr-offset 相位（当前要求 p_vaddr 与 p_offset 都页对齐） |
| ELF（动态） | ET_DYN/PT_INTERP、动态链接（libc-test/glibc 动态）；与静态 busybox 无关 |
| mm | 按需分页、COW、SIGBUS、msync；mprotect 撤 X |
| fs | FAT getdents、句柄缓存；rename/link/symlink/chmod/目录删除；EXT4 日志重放 |

### 4.5 信号契约

**范围**：kill/tgkill、rt_sigaction/procmask/pending/sigsuspend/
sigtimedwait/sigqueueinfo/sigaltstack/sigreturn(139) 全链路；SIGCHLD
（子退出）、SIGPIPE（pipe 无读者写入）、SIGSEGV/SIGILL/SIGBUS/SIGTRAP
（致命异常映射）三类内核内产生源；handler 建帧投递（sa_mask/siginfo/
浮点现场/备用栈）、EINTR 与 SA_RESTART、fork 继承与 execve 重置。

**投递模型**：回用户态唯一路径（任务运行循环）为投递检查点，每次至多
一个信号；阻塞 syscall 在 park 前后两次快路径决策（第二次不落睡，处理
睡中到达的信号）。产生统一经过滤：blocked 照常入队（屏蔽信号排队不丢）、
IGN 或 DFL 且默认动作属 Ign/Cont 静默丢弃。同步（硬件）信号走 force：
处置 IGN 重置 DFL、解除本信号屏蔽、必入队——防止装 IGN 的程序陷入无限
陷阱循环。帧内嵌 sigreturn stub（rv64 `li a7,139;ecall`、la64
`li.w a7,139;syscall 0`，本内核无 vDSO）；布局与魔数经 Linux UAPI 对照
与交叉 gcc offsetof 实测核验。sigsuspend 的帧屏蔽集为换入前旧集合
（Linux saved_sigmask），syscall 未完成时检查点先补 -EINTR 再建帧。

**偏差**（对照 Linux/POSIX）：

| 项 | 偏差 |
|---|---|
| sa_flags | SA_NODEFER 恒加本信号位；SA_RESETHAND/SA_NOCLDSTOP 存而不执行；SA_ONSTACK 已生效（其余输入模式见 sigaltstack 行） |
| sigaltstack | 单进程无 per-thread；MINSIGSTKSZ 不查（size=0 即禁用）；SS_ONSTACK/AUTODISARM 输入 EINVAL；rt_sigreturn 不回改登记（Linux restore_altstack 会）；备用栈溢出防护未做 |
| IGN 冲刷 | rt_sigaction 转 IGN/DFL-Ign 时无条件清 pending；Linux flush_sigqueue_mask 仅冲刷未屏蔽部分（被屏蔽后设 IGN 再解蔽，本实现信号丢失、Linux 保留） |
| sigtimedwait | 等待集按 `set ∩ 未屏蔽` 判定（Linux 睡眠期临时放宽 blocked，可等"blocked 且在集"信号） |
| sigqueueinfo | RT 信号无排队（位图合并语义）；保留码 si_value 经 addr 槽落位 |
| 终止与 core | 无 core dump：Core 类信号死亡恒 CLD_KILLED，wait status 无 0x80 位（Linux CLD_DUMPED + WCOREDUMP） |
| 同步信号 si_code | 固定 SEGV_MAPERR/ILL_ILLOPC/BUS_ADRALN/TRAP_BRKPT，未细分 ACCERR/ADRERR；la handler 期间 FPU 异常回投 SIGFPE（fcsr_pending）未实现 |
| stub | 无 vDSO，stub 内嵌帧内，无 icache flush（QEMU 语义一致）；rt_sigreturn badframe 按 force_sigsegv 式收敛（处置复位、不重试投递；Linux force_sig 在装 SIGSEGV handler 时可循环） |
| kill 族 | 无权限检查（无 uid）；pid<0 一律 EINVAL（无进程组，含 -1 广播）；pid==0 近似为调用者自身；tgkill 要求 tgid==tid（Linux tgid 不匹配返回 ESRCH） |
| sigpending/sigsetsize | rt_sigpending sigsetsize 收紧为 ==8（Linux 允许 ≤8） |
| nanosleep | rem 仅被打断时回写（正常完成不回写，沿用原契约行） |

**欠账**（下一里程碑）：停止/继续状态机（SIGSTOP/SIGTSTP/SIGCONT、
Stopped 态、wait4 WUNTRACED/WCONTINUED——libc-test 前必须）；进程组/
会话/TTY（交互作业控制前置）；RT 信号排队；setitimer/SIGALRM；
signalfd4；restart_syscall(219) 精确重启。验证方式：本地 19 项综合
自测（两架构，不入库）；libc-test 信号用例待接入。

## 5. sync 锁模型

| 项 | 约定 |
|---|---|
| 前提 | 任务时代内核态关中断；单核无合法持锁等待；lock_debug 下 try_lock 失败即报告 bug |
| 检查 | DebugMutex 的 percpu 持锁深度及切换入口零深度检查始终启用；lock_debug 额外跟踪锁名/获取点（`#[track_caller]`） |
| 锁序 | SCHED→FRAME；REGISTRY→{FRAME, EXIT_REPORTS, 打开文件 Handle, ROOT/MOUNTS/PAGES}；Handle→{ROOT, MOUNTS, PAGES}；PAGES→{ROOT, MOUNTS}；ROOT/MOUNTS→DISKS；SCHED→REGISTRY（信号唤醒 drain 唯一嵌套点，反向路径已核查不存在） |
| 反向 | 任何路径不得反向持有；fs/drivers 的 `spin::Mutex` 不受 DebugMutex 深度检查保护 |
| 唤醒 | 事件方不直接取 SCHED；用无锁原子标志，在调度边界消费 |
| 锁外析构 | 退出路径的 space/fs Drop 在 REGISTRY 锁外完成；exec 目前是例外 |
| 已知缺口 | 持有者 id 只更新不报告；dispatch 持 REGISTRY 做磁盘 I/O；exec 在 REGISTRY 锁内析构旧空间 |
| 欠账 | 锁序图（lockdep 式环检测）；SMP 化时全面重审 |

## 6. fs 与块设备

### 6.1 结构

| 模块 | 职责 |
|---|---|
| `fs::context` | 每进程 cwd、fd 表、文件调用 dispatch；`Handle=Arc<Mutex<OpenFile>>`，dup/fork 共享偏移 |
| `fs::mod` | Ext4（rsext4）与 FAT 查找；先查 FAT 挂载再查 EXT4 根 |
| `fs::fat` | rust-fatfs；路径即身份；虚拟 inode 从 0x8000_0000 递增 |
| `fs::cache` | MAP_SHARED 文件页；映射持强引用、索引持弱引用、最后释放写回 |
| `drivers` | virtio-blk 同步 IO、字节层 RMW、MBR；rv MMIO 固定槽 / la PCI ECAM |

### 6.2 EXT4 挂载检查

- rsext4 0.8.1，含 JBD2、fsync、卸载同步；内核适配在
  `fs/ext4_rsext4.rs`。
- 仅 4 KiB 数据块（`s_log_block_size==2`）；非 4K 卷拒绝。
- blocks/inodes_per_group 非零；卷块数不超过分区。
- 可写构建：incompat/ro_compat 白名单、`s_state==EXT4_VALID_FS`、
  journal inode==8、无外部日志、块数 ≤2^32。
- rsext4 从超级块读 `s_desc_size`/`s_inode_size`，没有 64 描述符/
  128–256 inode 的硬限制；4K 限制来自 `rsext4::config::BLOCK_SIZE`。
- 需要日志重放的卷、外部日志、未知特性一律拒绝。

### 6.3 偏差与欠账

| 项 | 现状 / 影响 |
|---|---|
| inode 身份偷位 | 最高位区分 FAT/EXT4；FAT inode 是 (mount,path) 登记序号，非磁盘身份。计划：显式挂载表 + 全局 inode 命名空间 |
| FAT 能力 | 无目录列举（getdents 仅 EXT4）；每次 read/write/stat 全路径重开；unlink 有句柄时 EBUSY。busybox 前应统一 |
| getdents64 分层 | syscall 层解析 EXT4 盘上 dirent；应下沉为 fs 层 readdir |
| 块层 | 同步轮询，无中断驱动/请求队列；DMA 页用裸 `frame_alloc`（OwnedFrame 例外第三处）；`dma_alloc` 失败返回物理 0，仅初始化期 |
| 大文件堆 | exec 整镜像读入 Vec；rsext4 单次 extent run 最多分配 1 MiB `run_buf`；8 MiB 堆下大镜像可能 OOM；分块直填页为欠账 |
| 共享页无脏位 | 释放即回写整页（fsync 的回写是有意的）；只读映射/O_RDONLY fd 也会写；rsext4-readonly 每次释放记 EROFS。需要 dirty 标志或区分只读 |
| 一致性更新降级 | 共享页 `coherent` 的页内读写失败仅记 error 日志并跳过该页更新，后续 read/mmap 可能读到旧数据；无失败计数与恢复策略。需要计数上报与一致性恢复 |
| 脏卷启动 | `fs::init` 返回错，`main` 用 expect 直接 panic；可写挂载先置 dirty，掉电后卷不可引导，且无日志重放。需要回退策略（只读挂载/内嵌程序/诊断后关机） |
| rsext4 审计 | vendor 有大量 unwrap/panic，挂载、lookup、read/write、getdents 都会走到；损坏镜像/意外 I/O 下可能从用户路径 panic 内核；原 ext4_rs 的 9 处审计不适用 |
| FAT unmount | 先 `mounts.remove` 再 `fs.unmount()`；失败时挂载已消失，无法重试。应成功后再移除 |
| fs 契约化 | 当前是结构 + 偏差表；inode 引用计数（retain/release）、共享页生命周期、错误映射、Handle 所有权尚未写成带不变量的契约 |

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
| `make run-rv` / `make run-la` | release 七任务验收（kthread A/B、hello、sched×2、check、ill），末尾帧守恒与逐进程汇总 |
| `make selftest-rv` / `make selftest-la` | debug 断言 + lock_debug + LOG=info；额外 OOM 注入与调试锁检查；polyhal #8 需 `-Zub-checks=no` |
| loongarch64 debug 启动自检（`trap/unaligned.rs`） | 直接验证模拟器 load/store、符号扩展、r0、跨页原子失败与只读拒绝 |
| `tests/run_group.py` | 双架构 group/edges/selftest 整组验收：QEMU 10.0.2、官方 oracle、`e2fsck -fn` |
| `tests/mm_validate.py` | MMU/TLB 硬件探针；依赖 musl 交叉工具链与 `~/.config/ouroos/env.sh`，尚未纳入日常门禁 |

## 8. 工程与文档遗留（非 ostd 契约）

| 项 | 现状 | 处理 |
|---|---|---|
| `make fmt` | `cargo fmt --all` 会连带格式化 `third_party/rsext4`（8 个文件有 rustfmt diff） | 限定 `-p kernel`，vendor 保持上游风格 + 补丁标记 |
| `println!` | main/task/lang_items 用 `println!` 输出验收行，与 AGENTS §6 的 log 规则冲突 | 契约声明例外，或改 log 并在 Makefile 固定 LOG |
| `report_all` 注释 | 称“退出时即时输出”，实际时代末统一输出 | 修注释 |
| `allocator.rs` | 模块头不是 `//!` | 改 `//!` |
| README | “演示视频”“团队成员”为空 | 补内容或删除空节 |
