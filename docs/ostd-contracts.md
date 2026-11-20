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
- 私有匿名 mmap、brk 与文件映射按需分配。用户缺页和内核复制共用 ensure_access；共享匿名也按需分配，ELF 装载页预分配。暂无换出或 COW。
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
| 内核堆 | 固定 8 MiB，TODO 在 `allocator.rs`；mm 元数据 try_reserve |
| user_access 并发前提 | 单核、内核不可抢占，复制期间无并发 munmap |
| kstack | 每个任务占用高半区的一个栈槽，底部一页未映射。数据帧连续以支持跨页 DMA；RV 共享根项，LA 使用 PGDH。当前最多 512 个同时存活的任务栈 |
| ELF | ET_EXEC 静态小端 ELF64；差异见 §4 |

### 1.4 已兑现

| 项 | 说明 |
|---|---|
| brk 字节级记账 | `address_space::brk` |
| mmap 空洞 / MAP_FIXED | `find_free`、`replace_region` 事务替换 |
| fork 深拷贝 | `deep_copy`，建成才发布，无 COW |
| exec 先建后切 | 新空间含 argv/envp/auxv，成功才替换 |
| 页字节访问收口 | 拥有页复制及 ELF 初始页写入由 mm 封装；`elf.rs`、`fs/cache.rs`、`syscall/memory.rs`、`task/user_task.rs`、`task/exec.rs`、`task/task.rs` 拒绝 `unsafe` |
| MAP_SHARED 文件页缓存 | `fs/cache.rs`；索引独立持有页，比较有效字节和上次写回基线，失败后可重试。 |

### 1.5 欠账

| 项 | 现状 / 计划 |
|---|---|
| 数据页/区域线性扫描 | 区域和页清单均按地址排序，查找走二分；fork/remap 仍逐页遍历 |
| COW / 通用页缓存 / swap / 远端 TLB | 未做；MAP_SHARED 文件页缓存已实现，不是通用读写页缓存 |
| 全局堆失败策略 | 8 MiB 固定；pipe 扩容、rsext4 的 `alloc::vec!` 不可失败，可耗尽→panic；需要统一 OOM 策略 |

普通文件 readahead(213) 按指定偏移同步预读，单次最多 128 KiB，不推进打开文件的偏移。MADV_FREE 允许立即回收私有匿名页，MADV_POPULATE_READ/WRITE 按实际权限主动触页。

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
| ProcessRecord | 地址空间 + fs + 退出信息 + 父子关系 | 静态 REGISTRY |
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
- exit(n) 码为 n；致命异常以 128+11 占位；wait status 见 §4。

### 3.5 等待与唤醒

- `Flow::Wait(WaitReason::Deadline/Children/Pipe)`：park 进等待表并
  切走，保留 syscall PC；醒来重执行重查条件（Mesa 风格）。
- Deadline 由调度边界按硬件时钟扫描；Children/Pipe 由事件方置无锁
  原子标志，在调度边界统一消费，避免 fs 在 REGISTRY 内反向取 SCHED。
- 孵化预留 ready/waiting 各自容纳全部存活任务的容量；集中唤醒不分配。
- init 在仍有活跃进程时等待 Children 事件，醒后重查条件。
- 等待表满时 park 退化为就绪让出；就绪空而等待非空时 idle 等时钟；
  互等即永久等待（QEMU 超时兜底）。

### 3.6 syscall 框架

内部一律 `Result<_, Errno>`，边界统一转负值。`Flow`（Continue /
Yield / Wait / Process / Exited）是调用对执行流的全部影响。`Process`
表示需在 REGISTRY 借用解除后由运行循环处理（fork/exec/wait4/
nanosleep/times）；非重入锁禁止在 dispatch 锁内调用。

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
| 文件 | getcwd、dup、dup3、fcntl、mkdirat、unlinkat、mount、umount2、chdir、openat、close、pipe2、getdents64、lseek、read、write、readv、writev、pread64、pwrite64、preadv、pwritev、readlinkat、statfs、fstatfs、newfstatat、fstat、fsync、statx、umask、utimensat、renameat、renameat2、truncate、ftruncate | `syscall/fs.rs` 处理用户参数与 ABI，`fs::context` 管理 FD 与文件操作 |
| 进程 | exit、nanosleep、sched_yield、times、getpid、getppid、clone、execve、wait4 | `task::process_call` |
| 内存 | brk、mmap、munmap、mprotect、mremap、mincore、madvise、msync、锁页系列 | `syscall/memory.rs` |
| 其他 | uname、gettimeofday | `syscall/mod.rs` |
| 其余 | 未列出的调用号 | ENOSYS |

### 4.3 偏差对照

| 调用/类别 | 当前实现 | Linux 对照 / 说明 |
|---|---|---|
| read/write/readv/writev | 共用 4 KiB 可失败堆缓冲区，单次分配后复用；向量描述符先复制到内核，最多 1024 项，总长度超过 ssize_t 返回 EINVAL；每次最多搬运 0x7ffff000 字节；遇短传输、EOF 或错误停止，已有进展时返回已完成长度 | 用户缓冲区按页交付，读只推进实际交付的偏移；完整调用持有打开文件锁；OOM 返回 ENOMEM，零长度不分配数据缓冲区 |
| pread64/pwrite64/preadv/pwritev | 指定独立偏移，不修改共享文件偏移；负偏移 EINVAL，流式对象 ESPIPE；rv64/la64 原始向量定位 ABI 使用完整 pos_l，忽略 pos_h；O_APPEND 下定位写仍追加，与 Linux 已知行为一致 | 不支持 preadv2/pwritev2；Ext4 文件超限 EFBIG 独立于参数过长 E2BIG；部分错误仍按已完成字节数返回 |
| fcntl | 支持 F_DUPFD/F_DUPFD_CLOEXEC、F_GETFD/F_SETFD、F_GETFL/F_SETFL；从下界选最低空闲 FD，上限 1024；cloexec 属于描述符，偏移与状态由 dup/fork 共享；打开时的创建标志不保存在共享状态中 | F_SETFL 仅修改 O_APPEND/O_NONBLOCK，访问模式、创建与同步标志不变；请求 O_ASYNC/O_DIRECT/O_NOATIME 返回 EOPNOTSUPP 且不修改状态；未知命令（含锁命令）EINVAL；尚未实现 RLIMIT_NOFILE、O_PATH 专用规则、追加专用 inode 属性检查及强制 O_LARGEFILE |
| pipe | 容量 64 KiB；读空或空间不足当前分块时等待，O_NONBLOCK 返回 EAGAIN；总长不超过 4 KiB 的 writev 合并后写入，空间不足不写入前缀；更大请求可在分块间返回短写；无读者返回 EPIPE | 无 SIGPIPE；运行期 VecDeque 扩容的不可失败分配仍待处理；复制失败只消费已交付数据 |
| wait4 | wanted<=0 等任意孩子，>0 指定 pid，<-1 EINVAL；无僵尸则阻塞，无孩子 ECHILD；WNOHANG 支持；status：正常 `(code&255)<<8`，异常 11 | 语义接近；忽略 rusage；无进程组概念 |
| clone | 仅 flags 恰好为 SIGCHLD(17) 的进程 fork；非零 stack 设置子 SP | 仅为兼容传入栈顶的调用方；不支持线程/共享地址空间 |
| execve | argv/envp 各 ≤256 项、单串 ≤4095 字节；字符串总计最多 32 KiB，用户栈默认预留 8 MiB 并逐页填充；auxv 提供 AT_ENTRY、AT_PAGESZ、AT_NULL；程序头表位于可读 PT_LOAD 内时提供 AT_PHDR、AT_PHENT、AT_PHNUM；整镜像读入内核堆 | AT_RANDOM 依赖 HAL 熵源 |
| nanosleep | 到期返回 0；rem 不回写；相对 now | 语义兼容 |
| times | tms 四字段来自任务记账；返回启动以来 100Hz tick | 语义兼容 |
| uname | sysname=OuroOS、nodename=ouro、release=内核版本、version=OuroOS、machine=架构名、domainname=local | 合成身份信息 |
| gettimeofday | 返回启动以来单调时间；ext4 时间从卷 `s_wtime` 起算 | 不是墙钟，无 RTC；两套时钟 |
| newfstatat/fstat/statx | 共用 FS 元数据；Ext4 返回 UID/GID、atime/mtime/ctime（含纪元扩展与纳秒）及可用的 btime；FAT 权限 0777、所有者 0，时间未接通，statx 不置对应有效位；卷设备号为内核分配的合成标识 | rv64/la64 使用 asm-generic stat 布局；旧式 stat 的缺失时间填零；statx 不报告未提供的属性、挂载 ID、DIO 对齐等扩展字段 |
| umask | 仅保存 0777 权限位，返回旧值；初始 022；fork 复制且之后独立，exec 保留；openat 新建与 mkdirat 按 mode & ~umask 创建，已有文件不改权限 | 无共享 FS Context 的线程语义、默认 ACL 或特殊权限位支持；FAT 沿用合成 0777，不能表达每文件的 POSIX 创建权限 |
| utimensat | 支持 NULL times、指定秒/纳秒、UTIME_NOW/UTIME_OMIT、cwd/dirfd 相对路径、中间链接及 AT_SYMLINK_NOFOLLOW；AT_EMPTY_PATH 和 NULL path 的 FD 形式支持仍打开但已删名的 inode；双方 OMIT 不访问路径或写入，参数先经 user_access 复制 | Ext4 更新 atime/mtime 并更新 ctime，不改变 btime 或文件偏移；128 字节 inode 为秒精度，扩展 inode 支持纳秒及纪元位，指定时间越界时限制到可表示范围；FAT、管道和控制台暂 EOPNOTSUPP。尚无 UID/GID/capability 身份检查、目录搜索权限或 immutable/append-only 属性校验；Now 沿用卷 s_wtime 加启动时长，非完整 RTC 墙钟 |
| statfs/fstatfs | 共用 FS 容量快照，路径跟随链接，FD 查询不修改共享偏移；rv64/la64 均编码 120 字节 asm-generic statfs，保留区清零；返回卷类型、分配单位、总量、空闲量、普通用户可用量、inode 计数、卷标识与只读标志 | Ext4 按当前后端计数并扣除超级块记录的元数据开销，可用量扣除保留块；若卷未记录开销则总量沿用原始块数，尚未补算，可能与 Linux df 有差异。FAT 使用实际簇统计，无固定 inode 池，files/ffree 为零。管道/控制台返回 EOPNOTSUPP；flags 仅报告 ST_VALID/ST_RDONLY，FAT 按现有可写挂载模式报告；无权限搜索及配额限制统计 |
| readlinkat | 从现有路径查询取得末项链接，读取目标文本并按 bufsiz 截断，不补 NUL；支持绝对路径、cwd/目录 FD 相对路径，绝对路径忽略 dirfd；中间链接跟随，末项不跟随；bufsiz 按 Linux int ABI 解释，非正数 EINVAL | 非空路径指向非链接返回 EINVAL；空路径查询 FD，非链接 ENOENT；坏 FD/用户缓冲区分别 EBADF/EFAULT。复用 Ext4 链接读取，目标仍限 UTF-8 且小于 4 KiB，不更新链接 atime；O_PATH 打开语义及链接 FD 的完整生命周期尚未补齐，不据此宣称完整支持 |
| 状态查询路径与标志 | 支持绝对路径、cwd/目录 FD 相对路径、AT_EMPTY_PATH（含 NULL）、AT_SYMLINK_NOFOLLOW、AT_NO_AUTOMOUNT；查询时逐级跟随链接，最多 40 次，保留点分量与尾斜杠约束 | 查询与重命名父目录解析共用，不代表 open/exec 已支持跟随链接；cwd/目录 FD 仍按保存的路径字符串定位；沿用项目 UTF-8 路径限制，尚无进程身份驱动的目录搜索权限检查 |
| statx 同步与 mask | 本地卷按当前 inode 缓存查询；接受 AS_STAT/FORCE_SYNC/DONT_SYNC，后两者不触发远端同步或额外文件数据写回；互斥同步标志、未知 flags、保留 mask 位 0x80000000 返回 EINVAL，其余未知 mask 位忽略 | 返回 mask 反映实际提供字段，可以多于请求；缺失时间不标有效，填零；当前 atime 更新策略仍沿用 rsext4 挂载选项 |
| fsync | EXT4 写回该 inode 的共享页并同步 rsext4 缓存/日志 | FAT 返回 ENOTSUP |
| mount | fstype 接受 vfat/fat；源设备 `/dev/vd<小写字母>[0-4]`（无后缀或 0 为整盘）；flags 必须 0，data 忽略 | 仅 MBR 主分区；不限于 a-d |
| mmap | 匿名与文件均支持 PRIVATE/SHARED；文件整页在 EOF 外允许建图，直接访问按 SIGBUS 终止；MAP_FIXED 事务替换 | 最后不足一页的尾部补零且不回写；MAP_FIXED 可覆盖用户栈；flags 白名单 |
| mprotect | 支持 PROT_NONE 和 R/W/X 组合；W 隐含 R，只读 FD 建立的共享映射禁止提升写权限（EACCES） | 两架构无 NX；VMA 记录请求权限，页表执行写保护，可访问页实际带 X |
| brk/munmap | brk 失败返回原 break；munmap 起址页对齐、长度向上取整、允许空洞 | 均无按需分页；brk 立即分配/释放物理页 |
| ELF | 仅 ET_EXEC 静态；p_vaddr 页对齐，p_filesz>0 时 p_offset 也页对齐；零地址允许 | 当前 basic ELF 只用 0x1000（rv 侧核对，两架构同链接脚本）；hint 与 MAP_FIXED 都可落到低址（低址并非不可达） |
| truncate/ftruncate | 支持 Ext4 普通文件缩短、稀疏扩展与清零；路径形式跟随符号链接，FD 形式要求可写并支持已删名的打开 inode，长度操作不改共享偏移；O_TRUNC 复用同一 FS 接口。扩展区读零，缩短清空尾块剩余字节，回收含 unwritten 的尾部 extent 及多余索引块，更新长度、块计数与 mtime/ctime，并沿用后端清除 set-ID 位 | 负长度 EINVAL，超出 u32::MAX 个 4 KiB 逻辑块 EFBIG；无效 FD EBADF，只读 FD 和非普通 FD EINVAL，O_PATH FD EBADF。长度改变且存在存活共享页时 EOPNOTSUPP，包括子进程仍保留映射的情况；同长度允许，避免未实现的映射失效和旧共享页写回。FAT 仅沿用清零，非零长度 EOPNOTSUPP；旧式映射仅支持直接块清零，外部 xattr 与 HUGE_FILE 编码暂不支持。尚无完整身份权限、文件锁、执行文件占用保护及 immutable/append-only 校验；MAP_PRIVATE 截断后越过 EOF 的 SIGBUS 仍未实现，掉电/OOM/全部设备失败未验证 |
| renameat/renameat2 | Ext4 支持同卷普通重命名、目标替换及 RENAME_NOREPLACE；按父目录 inode 更新目录项，末项链接自身被移动，中间链接跟随；跨挂载 EXDEV，目标非空目录 ENOTEMPTY，类型冲突分别 EISDIR/ENOTDIR；被替换但仍由 FD/映射引用的 inode 延迟回收 | EXCHANGE、WHITEOUT 和未知标志 EINVAL；FAT 卷内 EOPNOTSUPP；仍由任一进程 cwd、目录 FD 或挂载点引用的目录及其祖先返回 EBUSY，保护现有路径字符串身份。单核内核态串行化与根卷锁保证操作期间无其他任务观察中间状态；保存目录块及 inode 用于失败回滚，不保证掉电原子性，设备/回滚错误后拒绝继续访问卷；身份权限及 sticky/immutable/append-only 检查未实现；复杂分配失败回收及掉电恢复未验证。目标含外部 xattr 或有块的旧式映射暂不支持替换 |
| unlink/unlinkat | EXT4 unlink 后句柄存活、最后关闭回收；FAT 有句柄时 EBUSY；unlinkat flags 仅 0 | AT_REMOVEDIR 返回 ENOTSUP |
| getdents64 | fs 层提供目录项与续读位置，EXT4 后端按块解析，syscall 层打包 Linux dirent；单次最多 4KiB；FAT 返回 ENOTSUP | 后端目录块使用可失败堆分配；Linux 目录项打包的 4 KiB 栈缓冲区限制在不内联的 getdents64 函数内，避免普通文件 I/O 承担该栈帧；失败不推进文件偏移 |
| 路径 | 必须是合法 UTF-8；总长 4096 字节，单分量 255 | 非 UTF-8 文件名不可访问 |
| 其他 | stdin 读恒 EOF；fd=1/2 直通控制台；sched_yield 轮转后可能立即再次调度；getpid 总成功，getppid 返回注册表 parent | 无信号；孤儿过继 init |

文件 I/O 依据：[pread(2)](https://man7.org/linux/man-pages/man2/pread.2.html)、[readv(2)](https://man7.org/linux/man-pages/man2/readv.2.html) 与 [Linux 64 位定位向量 ABI](https://github.com/torvalds/linux/blob/v6.12/fs/read_write.c)。仅核对语义与 ABI，未复制实现代码。

FD 控制依据：[F_DUPFD](https://man7.org/linux/man-pages/man2/F_DUPFD.2const.html)、[F_GETFD/F_SETFD](https://man7.org/linux/man-pages/man2/F_GETFD.2const.html) 与 [F_GETFL/F_SETFL](https://man7.org/linux/man-pages/man2/F_GETFL.2const.html)。FD 表扩容使用可失败分配；成功 exec 关闭 cloexec，失败 exec 保留描述符。

创建掩码与时间更新依据：[umask(2)](https://man7.org/linux/man-pages/man2/umask.2.html)、[utimensat(2)](https://man7.org/linux/man-pages/man2/utimensat.2.html) 与 [Linux v6.12 utimes ABI](https://github.com/torvalds/linux/blob/v6.12/fs/utimes.c)。双方 OMIT 的提前成功及 NULL path 的 FD 形式按原始系统调用处理；只核对语义，未复制实现代码。

容量查询依据：[statfs(2)](https://man7.org/linux/man-pages/man2/statfs.2.html) 与 [asm-generic statfs UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/statfs.h)。仅按 ABI 独立编码；Ext4 fsid 取 UUID 前八字节，FAT 取卷序号，均作为不透明标识。

链接读取依据：[readlink(2)](https://man7.org/linux/man-pages/man2/readlink.2.html) 与 [Linux v6.12 readlinkat ABI/空路径行为](https://github.com/torvalds/linux/blob/v6.12/fs/stat.c)。仅核对公开语义，未复制实现代码。

截断依据：[truncate(2)](https://man7.org/linux/man-pages/man2/truncate.2.html)。按公开语义检查路径、FD、长度和偏移；存活共享映射下拒绝改长属于当前兼容性限制，不代表 Linux 的完整映射截断行为。

FS 通过 `fs::mapping` 注册 MM 映射钩子：注册后，长度改变先由 MM `prepare_resize` 校验并预分配，后端成功后再 `cache::resize_inode` 调整共享页、`commit_resize` 撤销旧映射；未注册钩子时仍按 EOPNOTSUPP 保守处理。普通 write 扩文件同样清零共享尾页的新暴露区间并通知 MM。`/proc/meminfo` 为只读快照，open 时捕获一次帧统计与共享页缓存量。


重命名依据：[rename(2)](https://man7.org/linux/man-pages/man2/rename.2.html)。复用现有 FS 路径与引用管理，未复制 Linux 实现；当前支持范围见上表。

文件状态查询依据：[stat(2)](https://man7.org/linux/man-pages/man2/stat.2.html)、[statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html) 与 [Linux asm-generic stat UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/stat.h)。按公开 ABI 独立编码，未复制 Linux 实现代码。

### 4.4 下一里程碑缺口


| 类别 | 缺口 |
|---|---|
| 基础调用 | clock_gettime(113)、exit_group(94)、ioctl(29)、kill(129)、set_tid_address(96) 等仍 ENOSYS；fcntl 文件锁和异步通知尚未实现 |
| 信号 | 无投递；EPIPE 不产生 SIGPIPE；SIGSEGV/SIGCHLD 只体现为 wait status |
| ELF（静态） | busybox 等静态程序的段 vaddr-offset 相位（当前要求 p_vaddr 与 p_offset 都页对齐） |
| ELF（动态） | ET_DYN/PT_INTERP、动态链接（libc-test/glibc 动态）；与静态 busybox 无关 |
| mm | COW、SIGBUS 用户投递；文件映射扩展；用户页执行禁止（NX） |
| fs | FAT getdents、句柄缓存与重命名；link/symlink/chmod/目录删除；EXT4 日志重放 |

## 5. sync 锁模型

| 项 | 约定 |
|---|---|
| 前提 | 任务时代内核态关中断；单核无合法持锁等待；lock_debug 下 try_lock 失败即报告 bug |
| 检查 | DebugMutex 的 percpu 持锁深度及切换入口零深度检查始终启用；lock_debug 额外跟踪锁名/获取点（`#[track_caller]`） |
| 锁序 | SCHED→FRAME；REGISTRY→{FRAME, EXIT_REPORTS, 打开文件 Handle, ROOT/MOUNTS/PAGES}；Handle→{ROOT, MOUNTS, PAGES}；PAGES→{ROOT, MOUNTS}；ROOT/MOUNTS→DISKS |
| 反向 | 任何路径不得反向持有；fs/drivers 的 `spin::Mutex` 不受 DebugMutex 深度检查保护 |
| 唤醒 | 事件方不直接取 SCHED；用无锁原子标志，在调度边界消费 |
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
| 文件系统适配 | Ext4 根卷与 FAT 挂载卷、后端错误转换 | `fs/ext4_rsext4.rs`、`fs/fat.rs` |
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
| 根卷选择 | 设备 0 优先取 MBR 第一主分区；分区解析返回 Range 时尝试整盘；无设备允许继续启动 |
| Ext4 块大小与几何 | 仅 4 KiB 块；校验 magic、卷块数、非零 blocks/inodes_per_group，声明的块范围不得超过分区 |
| Ext4 可写准入 | incompat/ro_compat 使用适配器白名单，卷状态必须为 `EXT4_VALID_FS`；有日志时还要求日志 inode 为 8、无外部日志、卷块数不超过 2^32 |
| 只读与恢复 | `rsext4-readonly` 禁止 Ext4 适配层写入；挂载选项关闭日志重放，可写准入条件不作为只读卷的完整特性校验保证 |
| Ext4 元数据布局 | rsext4 按超级块的 `s_desc_size`、`s_inode_size` 读取布局，不固定为 64 字节描述符或 128 字节 inode；4 KiB 限制来自后端 `BLOCK_SIZE` |
| inode 标识 | 最高位区分 FAT 与 Ext4；Ext4 拒绝该位已置位的 inode，FAT 从 `0x8000_0000` 分配虚拟编号 |
| 共享页与普通读写 | read 叠加已有共享页，write 更新后端后同步已有共享页；truncate 改变长度前检查存活共享页，当前单核非抢占路径中检查后直接进入截断，不允许中途调度；成功初始化的共享页在最后释放时尝试写回，长度限于当前 EOF 内；失败限制见 §6.5 |
| 显式同步 | Ext4 fsync 先写回该 inode 的驻留共享页，再同步后端缓存、日志和设备；关机时同步并卸载可写根卷，FAT fsync 返回 ENOTSUP |
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
| Ext4 日志同步 | 接入有日志卷的正常挂载、显式同步与卸载；不包含异常关机后的日志恢复 |
| 有界块访问 | 对齐请求批量提交，分区与设备分别检查访问范围；rv 使用 MMIO，la 使用 PCI ECAM |

### 6.5 欠账

| 项 | 现状 / 计划 |
|---|---|
| inode 与挂载身份 | 最高位分流；FAT 依赖 `(mount, path)` 登记序号，cwd/目录 FD 保存路径字符串。需统一挂载与对象身份 |
| 路径与文件操作 | 状态查询已有链接与尾斜杠处理，open/exec 尚未统一；rename 目前保护在用目录并仅支持普通移动与 NOREPLACE；link/symlink、目录删除及完整身份权限检查等缺口见 §4 |
| FAT 接口 | 无目录遍历与时间字段，每次 read/write/stat 按路径重开，打开后 unlink 返回 EBUSY；需补齐统一接口 |
| 共享页修改跟踪与写回 | 无脏状态，未修改页与只读映射也会尝试写回；只读 Ext4 根卷写回被拒绝并记日志。需 MM 提供修改跟踪，FS 保留失败数据并支持重试 |
| 共享页一致性失败 | `coherent` 的页内访问失败只记日志并跳过更新；最后释放时写回失败仍释放页。需明确错误传播、数据持有者和恢复策略 |
| 堆与栈预算 | exec 整镜像读入 Vec，rsext4 单次 extent run 可分配 1 MiB；I/O 和目录临时缓冲区虽可失败分配，仍有分配开销，部分路径保留页大小栈缓冲区。需测量内存与性能成本 |
| 分配失败覆盖 | 管道扩容及第三方部分分配不可失败；8 MiB 固定堆下可能触发分配失败终止。需与 §1.5 的全局 OOM 策略统一 |
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
| `make run-rv` / `make run-la` | release 七任务验收（kthread A/B、hello、sched×2、check、ill），末尾帧守恒与逐进程汇总 |
| `make selftest-rv` / `make selftest-la` | debug 断言 + lock_debug + LOG=info；额外 OOM 注入与调试锁检查；polyhal #8 需 `-Zub-checks=no` |
| loongarch64 debug 启动自检（`trap/unaligned.rs`） | 直接验证模拟器 load/store、符号扩展、r0、跨页原子失败与只读拒绝 |
| `tests/run_group.py` | 双架构 group/edges/selftest 整组验收：QEMU 10.0.2、官方 oracle、`e2fsck -fn` |
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
| `make fmt` | `cargo fmt --all` 会连带格式化 `third_party/rsext4`（8 个文件有 rustfmt diff） | 限定 `-p kernel`，vendor 保持上游风格 + 补丁标记 |
| `println!` | main/task/lang_items 用 `println!` 输出验收行，与 AGENTS §6 的 log 规则冲突 | 契约声明例外，或改 log 并在 Makefile 固定 LOG |
| `report_all` 注释 | 称“退出时即时输出”，实际时代末统一输出 | 修注释 |
| `allocator.rs` | 模块头不是 `//!` | 改 `//!` |
| README | “演示视频”“团队成员”为空 | 补内容或删除空节 |

### 存储调用链栈预算

文件 syscall 的目录输出与 read/write 暂存使用可失败分配的 4 KiB 堆缓冲，分配失败返回 ENOMEM，发生在读取、写入和目录游标推进之前。RISC-V selftest 构建中分发栈帧由 8400 字节降为 512 字节。JBD2 提交的三个暂存块也在首个磁盘写入前准备完成；不改变存储接口或 16 KiB 内核栈配置。该修复不构成所有存储路径的栈上界证明，保护页防止向相邻栈页写入，当前没有独立的溢出恢复栈。

### madvise 支持范围

调用号 233 支持 NORMAL/RANDOM/SEQUENTIAL/WILLNEED 的完整映射范围校验；访问模式建议目前不改变预读策略。私有匿名、堆、栈接受 DONTNEED；丢弃时无需分配新物理页。DONTNEED 撤销 PTE 并释放物理页，保留区域；后续合法访问按需分配零页，mincore 可观察驻留位清除。文件 DONTNEED 撤销调用进程的 PTE 并丢弃驻留副本，再访问从文件后备取数；共享匿名 DONTNEED 撤销本地 PTE，后备对象保留已有内容。空洞在改内容前拒绝，不部分清零。语义参考 [madvise(2)](https://man7.org/linux/man-pages/man2/madvise.2.html)。

### 匿名缺页与用户访问

地址空间页表与缺页新增页清单使用 RefCell 提供单核内部可变性；物理页不向调用者暴露可变引用。结构修改前将新增页合并至所有权清单，fork 同时复制两份清单中的私有页，未驻留区域保持未驻留。缺页先检查区域和实际权限，再准备数据页、元数据与页表；失败不发布新页。用户缓冲区复制仍先准备完整区间再复制，错误不产生部分数据写入；准备阶段可能使前面的合法页驻留。用户缺页分配失败仍沿用 task 的致命异常退出接口；信号投递尚待任务模块接入。

### 锁页与映射同步

mlock/munlock/mlock2 保存区域锁页属性，部分解锁拆分区域，ONFAULT 保持未驻留页延迟分配；普通锁页填充页后才提交锁属性。fork 不继承锁，DONTNEED 拒绝锁页，munmap 解除对应锁。已接入 RLIMIT_MEMLOCK 字节限额；缺少进程凭证模型，不能宣称通过 LTP 的凭证测例。mlockall 支持 CURRENT/FUTURE/ONFAULT，munlockall 同时清除未来策略；fork 不继承未来锁策略。

msync 按相交 VMA 的文件偏移选择缓存页，再同步 Ext4 后端，失败返回后端错误；私有页不回写。最后一个映射释放时若写失败，缓存继续持有页，可在 fsync 或关机前重试。MS_INVALIDATE 遇锁页返回 EBUSY；MS_ASYNC 仍同步等待，FAT 同步仍返回 EOPNOTSUPP。页写入获后端接受与设备持久化是两个阶段。

### 进程内存限额

内存相关 getrlimit/setrlimit/prlimit64 支持 DATA、STACK、MEMLOCK、AS，当前仅本进程。限额随 fork 复制并跨 exec 保留；AS 约束新映射与 remap，MEMLOCK 按锁定区间去重，DATA 约束 brk 与可写私有非栈非执行映射的增长，STACK 在 exec 发布前检查固定栈。尚未实现凭证、硬限额提升授权、非内存资源、跨进程 prlimit；默认无限额，不据此宣称完整 Linux 资源控制。

文件映射持有 inode；fork 复制已驻留私有页，共享页保持别名。mremap 增加的页按首次访问时的文件长度与内容填充。截断撤销超出新长度的驻留页，清除最后一页被截的字节。整页超出 EOF 和后端 I/O 失败分别产生 BUS_ADRERR 和 BUS_OBJERR；缺页内存不足终止当前任务（wait4 状态 9）。本分支单独运行时文件后备故障按默认 SIGBUS 退出，wait4 可见状态 7，尚无可捕获的用户信号处理器。`tests/basic_edges.c` 验证用户路径；`tests/file_mapping.rs` 注入短写与 I/O 错误，验证缓存可重试、非零截断与引用回收。 `tests/mm_file_resize.c` 使用静态 musl 编译（`-static -no-pie`），通过真实系统调用验证跨映射驻留、跨进程缩短、SIGBUS、路径扩长及重新打开后的文件内容。存储分支原有 `tests/fs_truncate.rs::mappings` 断言存活映射下返回 EOPNOTSUPP，合入时需要与存储维护者对齐此项验收标准。

### 原版 LTP 所需的跨模块接口

| 提供方 | 接口与约束 | 当前状态 |
|---|---|---|
| MM | `mm::frame::memory_snapshot() -> MemorySnapshot`，同一次帧分配器加锁中读取已登记和空闲 RAM，字段 total_kib/free_kib 的单位为 KiB。无换页、无可回收缓存估算时，MemAvailable 可取 free_kib 的保守值。 | 已提供 |
| procfs/VFS | 打开 /proc/meminfo 时取一次快照，生成 MemTotal、MemFree、MemAvailable、SwapFree 等字段；同一次打开按偏移读取，读尽返回 EOF。无交换设备时 SwapFree 为 0。 | 已接入只读 meminfo；brk01 现在阻塞在其后临时目录的 chown，不算通过 |
| task | current_credentials(pid) 返回真实/有效 UID、GID，进程创建/exec 保留或更新凭证；getgid/getegid 等调用以及 VFS 授权共用此来源。 | 只定义契约 |
| fs | set_owner(inode, uid: Option<u32>, gid: Option<u32>, credentials) 返回 Result；None 对应 uid/gid 的 -1，检查调用者权限，成功后 stat 与重新挂载均应可观察更新。 | 只定义契约；mincore01 在两架构初始化临时目录时报告 chown ENOSYS |
| task/signal | 注册用户信号动作、投递访存异常与恢复用户上下文；无处理器时按相应信号终止进程。 | 两架构实测信号注册 ENOSYS；涉及用户处理器的断言尚未验收 |

测试基线是 pre-2025 的 LTP 20240524。上述 TBROK 发生于测试框架初始化阶段，未执行对应 MM 断言。

三层页表为信号只读返回页预留最高 1 GiB 根槽，普通用户映射上界为 2^38 − 2^30，可装入默认链接在 0x120000000 的 LoongArch 静态 ELF。exec 按继承的 STACK 软限额确定栈预留量，上限 8 MiB。mprotect 验证整段覆盖、文件写权限和限额后提交；空洞返回 ENOMEM，未对齐地址返回 EINVAL。两架构原版 mprotect01 的空洞与非对齐检查均通过；后续 /dev/zero 的打开及映射依赖设备文件接口。

exec/spawn 从设备树启动熵派生独立的 16 字节，AT_RANDOM 指向新用户栈。静态 LoongArch glibc BusyBox 重定位后使用 mprotect(PROT_READ) 关闭写权限；页表保留执行权限。QEMU 10.0.2 上 `busybox sh -c exit` 成功；运行本地 pre-2025 原版 BusyBox 脚本时，LoongArch 随后在 fork 报 EINVAL。两架构已实测 musl BusyBox free；不能据此推断整组通过。设备文件 /dev/zero 的打开和映射仍依赖 VFS。

固定地址映射支持 MAP_FIXED_NOREPLACE（重叠返回 EEXIST，原数据保留）。MAP_LOCKED 使用与 mlockall 相同的限额，在建立映射后尽力预取，不改变未来映射的锁策略；没有交换空间预留账本，MAP_NORESERVE 不额外预留。MAP_POPULATE 在 VMA 建立后尽力预取；与 MAP_NONBLOCK 同用时不预取。未锁定的私有匿名 mremap 扩展只增加虚拟区间。MADV_DONTFORK/DOFORK 控制子进程是否继承该区间；WIPEONFORK/KEEPONFORK 控制私有匿名、堆、栈页在子进程内是否重新取零页。父进程内容不变。共享匿名扩展仅增加虚拟页描述，物理数据页按需分配；私有页 fork 深拷贝，没有实现 COW 或换出。

/proc/meminfo 每次打开保存一次帧分配器统计；Cached 只计文件页缓存的数据帧。MemTotal 为已登记的可分配物理内存；MemAvailable 为 MemFree 的保守估计；交换为零。sysinfo(179) 提供同口径的总量和空闲量，单位 1024 字节；尚未统计负载均值和共享内存用量。这里只实现了 meminfo，没有通用 procfs 目录枚举或进程文件。

本地 pre-2025 的 ltp_testcode.sh 会枚举镜像实际安装的二进制。双架构原版 mremap05 七条断言通过；mmap17 在版本预检 TCONF，mprotect01 在 /dev/zero 前通过两条断言，brk01、mincore01、msync01 依赖临时目录属主，mlock01 依赖凭证。版本门槛、TCONF、TBROK 均不计为通过；未修改测例、脚本或 uname 来绕过这些前置条件。

信号子系统独立在 signal/user-faults 开发。两分支联合运行时，MM 先尝试修复用户缺页，再向信号模块交付未映射、权限不足或文件后备错误。内核代表 syscall 复制用户指针失败继续返回 EFAULT。测试入口是 tests/mm_signal_faults.c；单独运行 MM 分支不提供信号处理器注册。
