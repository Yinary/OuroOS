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
| kstack | 连续物理页 + 直映，无保护页；虚拟窗口见 §3 欠账 |
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

### 1.5 欠账

| 项 | 现状 / 计划 |
|---|---|
| 内核栈虚拟窗口 + 保护页 | 当前直映连续页，无保护页；见 §3 |
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
| 内核栈虚拟窗口 + 底部保护页 | 需 rv 共享页表窗口、la PGDL 映射与用户页表同步；当前直映无保护 |
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
| 文件 | getcwd、dup、dup3、mkdirat、unlinkat、mount、umount2、chdir、openat、close、pipe2、getdents64、lseek、read、write、readv、writev、pread64、pwrite64、preadv、pwritev、newfstatat、fstat、fsync、statx | `syscall/fs.rs` 处理用户参数与 ABI，`fs::context` 管理 FD 与文件操作 |
| 进程 | exit、nanosleep、sched_yield、times、getpid、getppid、clone、execve、wait4 | `task::process_call` |
| 内存 | brk、mmap、munmap、mprotect | `syscall/memory.rs` |
| 其他 | uname、gettimeofday | `syscall/mod.rs` |
| 其余 | 未列出的调用号 | ENOSYS |

### 4.3 偏差对照

| 调用/类别 | 当前实现 | Linux 对照 / 说明 |
|---|---|---|
| read/write/readv/writev | 共用 4 KiB 可失败堆缓冲区，单次分配后复用；向量描述符先复制到内核，最多 1024 项，总长度超过 ssize_t 返回 EINVAL；每次最多搬运 0x7ffff000 字节；遇短传输、EOF 或错误停止，已有进展时返回已完成长度 | 用户缓冲区按页交付，读只推进实际交付的偏移；完整调用持有打开文件锁；OOM 返回 ENOMEM，零长度不分配数据缓冲区 |
| pread64/pwrite64/preadv/pwritev | 指定独立偏移，不修改共享文件偏移；负偏移 EINVAL，流式对象 ESPIPE；rv64/la64 原始向量定位 ABI 使用完整 pos_l，忽略 pos_h；O_APPEND 下定位写仍追加，与 Linux 已知行为一致 | 不支持 preadv2/pwritev2；Ext4 文件超限 EFBIG 独立于参数过长 E2BIG；部分错误仍按已完成字节数返回 |
| pipe | 容量 64 KiB；读空或空间不足当前分块时等待，O_NONBLOCK 返回 EAGAIN；总长不超过 4 KiB 的 writev 合并后写入，空间不足不写入前缀；更大请求可在分块间返回短写；无读者返回 EPIPE | 无 SIGPIPE；运行期 VecDeque 扩容的不可失败分配仍待处理；复制失败只消费已交付数据 |
| wait4 | wanted<=0 等任意孩子，>0 指定 pid，<-1 EINVAL；无僵尸则阻塞，无孩子 ECHILD；WNOHANG 支持；status：正常 `(code&255)<<8`，异常 11 | 语义接近；忽略 rusage；无进程组概念 |
| clone | 仅 flags 恰好为 SIGCHLD(17) 的进程 fork；非零 stack 设置子 SP | 仅为兼容传入栈顶的调用方；不支持线程/共享地址空间 |
| execve | argv/envp 各 ≤256 项、单串 ≤4095 字节；总受 4 页栈限制（字符串约 12KiB，超出 E2BIG）；auxv 仅 AT_PAGESZ/AT_NULL；整镜像读入内核堆 | 原 32KiB 上限不可达；AT_PHDR/AT_RANDOM 是 glibc 静态需要，静态 musl 不依赖 |
| nanosleep | 到期返回 0；rem 不回写；相对 now | 语义兼容 |
| times | tms 四字段来自任务记账；返回启动以来 100Hz tick | 语义兼容 |
| uname | sysname=OuroOS、nodename=ouro、release=内核版本、version=OuroOS、machine=架构名、domainname=local | 合成身份信息 |
| gettimeofday | 返回启动以来单调时间；ext4 时间从卷 `s_wtime` 起算 | 不是墙钟，无 RTC；两套时钟 |
| newfstatat/fstat/statx | 共用 FS 元数据；Ext4 返回 UID/GID、atime/mtime/ctime（含纪元扩展与纳秒）及可用的 btime；FAT 权限 0777、所有者 0，时间未接通，statx 不置对应有效位；卷设备号为内核分配的合成标识 | rv64/la64 使用 asm-generic stat 布局；旧式 stat 的缺失时间填零；statx 不报告未提供的属性、挂载 ID、DIO 对齐等扩展字段 |
| 状态查询路径与标志 | 支持绝对路径、cwd/目录 FD 相对路径、AT_EMPTY_PATH（含 NULL）、AT_SYMLINK_NOFOLLOW、AT_NO_AUTOMOUNT；查询时逐级跟随链接，最多 40 次，保留点分量与尾斜杠约束 | 查询专用解析，不代表 open/exec 已支持跟随链接；cwd/目录 FD 仍按保存的路径字符串定位；沿用项目 UTF-8 路径限制，尚无进程身份驱动的目录搜索权限检查 |
| statx 同步与 mask | 本地卷按当前 inode 缓存查询；接受 AS_STAT/FORCE_SYNC/DONT_SYNC，后两者不触发远端同步或额外文件数据写回；互斥同步标志、未知 flags、保留 mask 位 0x80000000 返回 EINVAL，其余未知 mask 位忽略 | 返回 mask 反映实际提供字段，可以多于请求；缺失时间不标有效，填零；当前 atime 更新策略仍沿用 rsext4 挂载选项 |
| fsync | EXT4 写回该 inode 的共享页并同步 rsext4 缓存/日志 | FAT 返回 ENOTSUP |
| mount | fstype 接受 vfat/fat；源设备 `/dev/vd<小写字母>[0-4]`（无后缀或 0 为整盘）；flags 必须 0，data 忽略 | 仅 MBR 主分区；不限于 a-d |
| mmap | 匿名仅 PRIVATE；文件 PRIVATE/SHARED；EOF 整页拒绝（ENOTSUP）；MAP_FIXED 事务替换 | 共享页无脏位，释放即回写（含 O_RDONLY 映射与 rsext4-readonly 的 EROFS 日志）；O_RDONLY+PROT_WRITE 返回 EBADF（Linux EACCES）；MAP_FIXED 可覆盖用户栈；flags 白名单 |
| mprotect | 支持 PROT_NONE 与含 X 的权限（W 必须同时有 R）；撤 X 返回 EOPNOTSUPP(95) | 两架构无 NX；实际可执行权限由 translate 报 |
| brk/munmap | brk 失败返回原 break；munmap 起址页对齐、长度向上取整、允许空洞 | 均无按需分页；brk 立即分配/释放物理页 |
| ELF | 仅 ET_EXEC 静态；p_vaddr 页对齐，p_filesz>0 时 p_offset 也页对齐；零地址允许 | 当前 basic ELF 只用 0x1000（rv 侧核对，两架构同链接脚本）；hint 与 MAP_FIXED 都可落到低址（低址并非不可达） |
| unlink/unlinkat | EXT4 unlink 后句柄存活、最后关闭回收；FAT 有句柄时 EBUSY；unlinkat flags 仅 0 | AT_REMOVEDIR 返回 ENOTSUP |
| getdents64 | fs 层提供目录项与续读位置，EXT4 后端按块解析，syscall 层打包 Linux dirent；单次最多 4KiB；FAT 返回 ENOTSUP | 目录缓冲区使用可失败堆分配，失败不推进文件偏移 |
| 路径 | 必须是合法 UTF-8；总长 4096 字节，单分量 255 | 非 UTF-8 文件名不可访问 |
| 其他 | stdin 读恒 EOF；fd=1/2 直通控制台；sched_yield 轮转后可能立即再次调度；getpid 总成功，getppid 返回注册表 parent | 无信号；孤儿过继 init |

文件 I/O 依据：[pread(2)](https://man7.org/linux/man-pages/man2/pread.2.html)、[readv(2)](https://man7.org/linux/man-pages/man2/readv.2.html) 与 [Linux 64 位定位向量 ABI](https://github.com/torvalds/linux/blob/v6.12/fs/read_write.c)。仅核对语义与 ABI，未复制实现代码。

文件状态查询依据：[stat(2)](https://man7.org/linux/man-pages/man2/stat.2.html)、[statx(2)](https://man7.org/linux/man-pages/man2/statx.2.html) 与 [Linux asm-generic stat UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/stat.h)。按公开 ABI 独立编码，未复制 Linux 实现代码。

### 4.4 下一里程碑缺口


| 类别 | 缺口 |
|---|---|
| 基础调用 | clock_gettime(113)、exit_group(94)、fcntl(25)、ioctl(29)、kill(129)、set_tid_address(96) 等仍 ENOSYS |
| 信号 | 无投递；EPIPE 不产生 SIGPIPE；SIGSEGV/SIGCHLD 只体现为 wait status |
| ELF（静态） | busybox 等静态程序的段 vaddr-offset 相位（当前要求 p_vaddr 与 p_offset 都页对齐） |
| ELF（动态） | ET_DYN/PT_INTERP、动态链接（libc-test/glibc 动态）；与静态 busybox 无关 |
| mm | 按需分页、COW、SIGBUS、msync；mprotect 撤 X |
| fs | FAT getdents、句柄缓存；rename/link/symlink/chmod/目录删除；EXT4 日志重放 |

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
| 共享页与普通读写 | read 叠加已有共享页，write 更新后端后同步已有共享页；成功初始化的共享页在最后释放时尝试写回，长度限于当前 EOF 内；失败限制见 §6.5 |
| 显式同步 | Ext4 fsync 先写回该 inode 的驻留共享页，再同步后端缓存、日志和设备；关机时同步并卸载可写根卷，FAT fsync 返回 ENOTSUP |
| 字节块访问 | 完整对齐的扇区范围一次提交；不完整扇区先读后改，调用方负责串行化重叠写入 |
| 错误边界 | FS 对外返回项目 `Errno`，后端错误由适配层转换；不保证任意失败都无磁盘副作用，也不据此保证第三方内部无 panic |

### 6.4 已兑现

| 项 | 说明 |
|---|---|
| 文件调用分层 | 用户参数与 Linux ABI 在 syscall，FD 与打开文件操作在 context，磁盘格式在后端 |
| FD 与 inode 生命周期 | dup/fork 共享偏移，CLOEXEC 按描述符管理；Ext4 打开后 unlink 仍可访问，最后关闭回收 |
| Ext4 目录遍历 | 后端按块解析，统一返回文件名、类型、inode 与续读位置；缓冲区可失败分配并跨块复用，FAT 尚未接入 |
| Ext4 属性查询 | 统一 Metadata 提供所有者、大小、块数及可用时间；状态查询区分链接自身与目标，具体标志与限制见 §4 |
| 定位与向量 I/O | 普通与定位读写共用搬运流程，iovec 先复制到内核；已有进展时返回短传输，支持范围见 §4 |
| 共享页初始化失败处理 | 分配或填页失败不触发未初始化数据写回，已登记的 inode 引用由页生命周期持有 |
| Ext4 日志同步 | 接入有日志卷的正常挂载、显式同步与卸载；不包含异常关机后的日志恢复 |
| 有界块访问 | 对齐请求批量提交，分区与设备分别检查访问范围；rv 使用 MMIO，la 使用 PCI ECAM |

### 6.5 欠账

| 项 | 现状 / 计划 |
|---|---|
| inode 与挂载身份 | 最高位分流；FAT 依赖 `(mount, path)` 登记序号，cwd/目录 FD 保存路径字符串。需统一挂载与对象身份 |
| 路径与文件操作 | 状态查询已有链接与尾斜杠处理，open/exec 尚未统一；rename/link/symlink、目录删除及权限等缺口见 §4 |
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
| `tests/fs_io.py` | `make all` 后执行 `python3 tests/fs_io.py`，构造独立 Ext4 盘验证双架构定位/向量 I/O、用户缓冲区错误、管道与落盘一致性；只读版本先 `make all FEATURES=rsext4-readonly` 再加 `--readonly`，结束后恢复默认构建 |
| `tests/mm_validate.py` | MMU/TLB 硬件探针；依赖 musl 交叉工具链与 `~/.config/ouroos/env.sh`，尚未纳入日常门禁 |

## 8. 工程与文档遗留（非 ostd 契约）

| 项 | 现状 | 处理 |
|---|---|---|
| `make fmt` | `cargo fmt --all` 会连带格式化 `third_party/rsext4`（8 个文件有 rustfmt diff） | 限定 `-p kernel`，vendor 保持上游风格 + 补丁标记 |
| `println!` | main/task/lang_items 用 `println!` 输出验收行，与 AGENTS §6 的 log 规则冲突 | 契约声明例外，或改 log 并在 Makefile 固定 LOG |
| `report_all` 注释 | 称“退出时即时输出”，实际时代末统一输出 | 修注释 |
| `allocator.rs` | 模块头不是 `//!` | 改 `//!` |
| README | “演示视频”“团队成员”为空 | 补内容或删除空节 |
