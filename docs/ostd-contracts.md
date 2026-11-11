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

生命周期：wait 收割即删（注册表只存活跃进程与未收割僵尸）；孤儿过继
内核 init，已退出的孤儿即收（运行时间累归丢弃）；终态行积攒到任务
时代结束统一输出（不混入用户程序的测试输出块）。pid 递增不复用。
exit(n) 码为 n；被致命异常杀死以 128+11 占位（wait status 位域编码
见 §4）。

等待与唤醒（阻塞即让出协议的运行形态）：Flow 的 Wait 变体携带
WaitReason（Deadline/Children/Pipe），运行循环 park 进调度器等待表
并切走（syscall PC 保留）；唤醒是宽松匹配 + Mesa 风格重执行——醒来
后从 syscall 指令重新执行重查条件，不精确订阅。唤醒路径：Deadline
由调度边界按硬件时钟扫描；Children/Pipe 由事件方置无锁原子标志
（request_children_wake/request_pipe_wake），在调度边界统一消费，
避免 fs 层在 REGISTRY 锁内反向取 SCHED。等待表容量耗尽时 park 退化
为就绪让出（条件重查仍正确）。就绪空而等待非空时 idle 等时钟。
进程互等无解时表现为永久等待（与 Linux 死锁一致，QEMU 超时兑底）。
CURRENT（percpu，以整数存址绕开裸指针 !Send）是身份唯一来源。

孵化时机：rv 初始 TrapFrame 依赖开中断稳态（SPP=0/SPIE=1），
spawn 必须发生在 task::run 关中断之前；spawn 内有断言兜底。

时间片：固定 1 tick 轮转（TICK_MS=100），无优先级；切入刷新
slice_tick，逃逸点比较判定；等待中任务不占就绪队列与时间片。

syscall 框架协议：内部一律 Result<_, Errno>，边界统一转负值；
Flow（Continue/Yield/Wait(WaitReason)/Process/Exited）是调用对执行
流的全部影响——Wait 保留 syscall PC 挂起、醒来重执行重查，是
“阻塞即让出”协议的运行形态；Process 表示需在 REGISTRY 借用解除后
由运行循环处理（fork/exec/wait4/nanosleep/times 等，它们会再取
REGISTRY，非重入锁禁止在 dispatch 锁内调用）。

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
- pipe/子进程唤醒的精确订阅：当前宽松匹配 + Mesa 重执行（单核惊群
  可忽略）；新增 pipe 状态变化处必须补 request_pipe_wake，遗漏会导致
  等待者永久挂起（就绪空、等待非空时 idle 等时钟不退出）。
- 锁序图（lockdep 式环检测）。
- polyhal 本体 vendor（#8 修复）；la idle 指令封装（当前 idle 自旋
  等钟，但 Deadline 唤醒依赖硬件时钟读数而非中断，自旋不阻塞正确性）。

### 非目标（团队决定不做，区别于"欠账"）

**SMP/多核不做。** 与之相关的不变量在单核下各有职责、全部保留：
!Send/LocalSpace（所有权边界与静态容器约束）、percpu（访问形态）、
全量 TLB flush（正确性优先）。若将来重开多核，以下设计须重新审视：
TLB shootdown 协议、调度器与注册表的单核假设、锁序与 irq-off 模型、
页表全量刷新策略。不为想象中的 SMP 预留任何参数化或间接层——
可扩展性的证明是重构成本低（不变量清晰），不是预留钩子。

## 4. syscall 与用户 ABI 语义偏差

语义基线是 man 2（调用号与寄存器约定按 riscv64/loongarch64 通用
UAPI：a7=调用号、a0..a5=参数、a0=返回负 errno 或结果）。框架协议：
内核内部一律 `Result<_, Errno>`、ABI 边界统一转负 errno；`Flow`
（Continue/Yield/Wait/Process/Exited）是调用对执行流的全部影响
（见 §3 等待与唤醒）。已实现调用分三组：文件（getcwd/dup/dup3/
mkdirat/unlinkat/mount/vfat/umount2/chdir/openat/close/pipe2/
getdents64/lseek/read/write/fstat/statx，实现于 fs::context）；
进程（exit/nanosleep/sched_yield/times/getpid/getppid/clone/
execve/wait4，实现于 task 侧 process_call）；内存（brk/mmap/munmap/
mprotect）；另有 uname/gettimeofday。其余调用号一律 ENOSYS。

与 Linux 的已登记偏差：
- read/write：循环分块至缓冲区填满/写尽或 EOF（4KiB 内核栈缓冲分块，
  无单次截断）；部分成功后出错返回已完成量（短读/短写）。
- pipe：容量 64KiB（同 Linux 默认）；读空/写满阻塞等待（真挂起，
  醒来重执行），O_NONBLOCK 返回 EAGAIN；写满不做部分写。
- wait4：wanted<=0 等任意孩子（无进程组概念，0 与 -1 等价），>0 指定
  pid，<-1 EINVAL；无可收割孩子阻塞，无孩子 ECHILD；status 编码
  WEXITSTATUS=(code&255)<<8，被异常杀死 status=11（WIFSIGNALED 位域）；
  WNOHANG 支持；收割即从注册表删除，重复 wait 同一 pid 得 ECHILD。
- clone：仅 flags 低字节为 SIGCHLD(17) 的进程 fork；非零 stack 参数
  会设置子 SP（glibc 无此用法，仅为兼容传入栈顶的调用方）。
- execve：argv/envp 各限 256 项、总长 32KiB；auxv 仅 AT_PAGESZ +
  AT_NULL（静态 musl 够用，glibc 静态需要 AT_PHDR/AT_RANDOM——
  busybox 里程碑前置项）；可执行文件整体读入内核堆后加载。
- nanosleep：到期返回 0；rem（剩余时间）不回写；相对 now 计算。
- uname：sysname=OuroOS、nodename=ouro、release=内核版本、
  version=OuroOS、machine=架构名、domainname=local（合成的
  身份信息，dev/serial 同理为伪造值）。
- statx/fstat：dev=0x307、blksize=4096 等字段合成；FAT 权限硬编码
  0777；atime/ctime/mtime 不维护。
- mount：仅接受 vfat，且源设备仅识别 /dev/vd[a-d][1-4]。
- mmap：匿名仅 PRIVATE；文件映射仅 PRIVATE（写时复制到私有页）与
  SHARED（共享页缓存，最后映射释放时写回）；超出文件 EOF 的整页
  范围拒绝（ENOTSUP，Linux 为零页+SIGBUS）；MAP_FIXED 匿名走
  replace_region 事务替换。
- ELF 加载：仅 ET_EXEC 静态（ET_DYN/PT_INTERP 拒绝——busybox/
  动态链接里程碑前置项）；段起点要求严格页对齐（p_vaddr 与
  p_offset 同时 4K 对齐；Linux 只要求 vaddr-offset 同相位——busybox
  的常规段布局会被拒绝，待修）；USER_BASE=0 允许 ELF 头段占零地址
  （官方 basic 布局需要；运行时 mmap 分配起点 0x1000_0000，用户
  主动映射低址仍不可达）。
- unlink：EXT4 支持 unlink 后句柄存活（最后关闭回收）；FAT 在有
  打开句柄时返回 EBUSY（两文件系统语义不一致，登记）。
- getdents64：syscall 层直接解析 EXT4 盘上 dirent 格式（分层欠账，
  见 fs 欠账）；单次最多填充 4KiB，多次调用推进 offset。
- write：fd=1/2 直通控制台；stdin 读恒 EOF（返回 0）。
- sched_yield：单核轮转，让出后可能立即被再次调度（语义兼容）。
- getpid 总成功；getppid 返回注册表 parent（孤儿过继内核 init）。

## 5. sync 锁模型（DebugMutex，feature `lock_debug`）

前提：内核态一律关中断（见 §3），单核上不存在"另一执行流持锁"的
合法状态——try_lock 失败即 bug（持锁跨 context_switch），立即报告，
不做超时等待。提供的检查：持锁者与获取点（#[track_caller]）、
percpu 持锁深度、调度切换入口断言深度为零（might_sleep 内核版）。
release 构建零开销。欠账：锁序图（lockdep 式环检测）、SMP 化时
全面重审。

锁序总图：SCHED → REGISTRY → {FRAME, EXIT_REPORTS, fs 层 spin
锁（ROOT/PAGES/MOUNTS/DISKS/打开文件 Handle）}，任何路径不得反向
持有。fs/drivers 层的 spin::Mutex 不在 lock_debug 检查范围（登记为
已知缺口）；事件方（fs 层、退出路径）不得直接取 SCHED 唤醒等待者，
一律经无锁原子标志（request_children_wake/request_pipe_wake）在
调度边界消费。syscall dispatch 持 REGISTRY 期间内嵌 fs 锁与磁盘
I/O（单核关中断下无死锁，但锁持有时长覆盖完整磁盘操作——重构为
space/fs 出注册表是结构欠账）。进程退出的 space/fs Drop 在 REGISTRY
锁外完成。
## 6. fs 与块设备契约

结构：fs::context（每进程 cwd + fd 表 + 文件调用 dispatch，Handle=
Arc<Mutex<OpenFile>> 使 dup/fork 共享偏移）；fs::mod（EXT4 卷适配
ext4_rs，lookup 语义 = 先查 FAT 挂载再查 EXT4 根）；fs::fat（挂载的
FAT 卷，rust-fatfs，路径即身份、虚拟 inode 从 0x8000_0000 递增）；
fs::cache（MAP_SHARED 文件页，映射持强引用、索引持弱引用，最后
映射释放时写回）；drivers（virtio-blk 同步 IO + 字节层 RMW + MBR
分区解析，riscv MMIO 固定槽 / la PCI ECAM 枚举）。

已登记的妥协与欠账：
- 文件系统身份偷位：inode 号最高位区分 FAT（置位）/EXT4，FAT inode
  为 (mount, path) 的登记序号非磁盘身份。重构方向：显式挂载表 +
  全局 inode 命名空间（欠账）。
- FAT 无目录列举（getdents 仅支持 EXT4）；FAT 每次 read/write/stat
  全路径重开（无句柄缓存）；FAT unlink 语义 = EBUSY（EXT4 为延迟
  回收）。busybox 里程碑前应统一。
- getdents64 在 syscall 层解析 EXT4 盘上 dirent（分层欠账，应下沉
  为 fs 层 readdir 抽象）。
- EXT4 超级块几何校验限定：4KiB 数据块、64 描述符、128/256 inode；
  非 4K 块卷直接拒绝（ext4_rs 硬编码 BLOCK_SIZE）。
- 块层同步轮询（无中断驱动、无请求队列）；DMA 页用 frame_alloc 裸
  接口（OwnedFrame 例外清单的第三处，登记于此）；dma_alloc 失败
  返回物理 0（virtio-drivers Dma::new 的错误约定，仅初始化期发生）。
- exec/read 大文件整体经内核堆（8MiB）；分块直填页为欠账。

## 7. 自检清单与验证入口

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
