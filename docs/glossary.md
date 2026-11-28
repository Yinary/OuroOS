# OuroOS 术语表

本文件约定 OuroOS 代码注释与 `docs/` 文档中使用的通行术语，避免同一概念混用多种译名。编写文档与汇报时，英文缩写首次出现请写出中文全称、英文全称和缩写。

## 架构与框架层

| 术语 | 英文全称与缩写 | 本项目含义 |
|---|---|---|
| 框内核 | Framekernel | 将 `unsafe` 收束在极小可信框架层，上层操作系统服务以安全 Rust 实现的宏内核架构 |
| 操作系统标准库 | Operating System Standard Library (OSTD) | 框内核中封装硬件原语、提供类型化不变量的受信任底层框架层 |
| 硬件抽象层 | Hardware Abstraction Layer (HAL) | 隔离架构寄存器、中断、页表格式与引导细节的底层原语库，本项目使用 PolyHAL |
| 可信计算基 | Trusted Computing Base (TCB) | 决定内存安全与隔离正确性的最小 `unsafe` 代码集合 |
| 未定义行为 | Undefined Behavior (UB) | 违反 Rust 内存模型或别名规则、编译器不做语义保证的行为 |
| 应用程序二进制接口 | Application Binary Interface (ABI) | 用户态与内核态之间关于寄存器约定、结构体布局与错误码编码的二进制契约 |
| 系统调用 | System Call (syscall) | 用户态通过陷阱指令向内核请求服务的受控入口 |

## 内存管理

| 术语 | 英文全称与缩写 | 本项目含义 |
|---|---|---|
| 物理页帧 | Physical Page Frame | 4 KiB 对齐的物理内存分配单元，由 `OwnedFrame` 唯一持有 |
| 页表项 | Page Table Entry (PTE) | 硬件多级页表中的单个映射或下一级表指针槽位 |
| 转换后备缓冲区 | Translation Lookaside Buffer (TLB) | 处理器缓存虚拟地址到物理地址翻译结果的硬件结构 |
| 虚拟内存区域 | Virtual Memory Area (VMA) | 用户地址空间中具有一致属性与后备来源的连续虚拟页区间 |
| 写时复制 | Copy-on-Write (COW) | `fork` 后父子共享只读物理页，首次写入触发缺页时再分配私有副本的机制 |
| 内核直接映射 | Direct Mapping | 将物理内存线性映射到内核高半区虚拟地址的访问窗口（LoongArch64 经直接映射窗口 DMW） |
| 保护页 | Guard Page | 位于内核栈低地址端、保持未映射以硬件拦截栈溢出的虚拟页 |
| 内存不足 | Out of Memory (OOM) | 物理页帧或内核堆容量耗尽导致的分配失败 |

## 任务、调度与同步

| 术语 | 英文全称与缩写 | 本项目含义 |
|---|---|---|
| 线程组 | Thread Group | 共享地址空间与进程号（PID）的一组线程，对应 POSIX 进程概念 |
| 进程号 / 线程号 | Process ID (PID) / Thread ID (TID) | 分别标识线程组与单个执行线程；单线程进程两者相等 |
| 进程文件描述符 | Process File Descriptor (pidfd) | 指向特定进程实例、不受 PID 复用影响的内核句柄 |
| 陷阱帧 | Trap Frame | 进入内核时保存在内核栈上的用户态通用与浮点寄存器现场 |
| 内核上下文 | Kernel Context (`KContext`) | 任务切换时在内核栈间保存与恢复的被调用者保存寄存器及内核浮点现场 |
| 时间片 | Time Slice | 单个可运行任务连续占用处理器的时间预算，到期在调度检查点轮转 |
| 锁序 | Lock Ordering | 为防止死锁规定的多把互斥锁嵌套获取的唯一合法方向 |

## 文件系统、I/O 与进程间通信

| 术语 | 英文全称与缩写 | 本项目含义 |
|---|---|---|
| 虚拟文件系统 | Virtual File System (VFS) | 屏蔽 Ext4、Ext2、FAT、procfs、memfd 等后端差异的统一文件抽象层 |
| 索引节点 | Index Node (inode) | 标识文件或目录实体及其元数据的底层对象 |
| 文件描述符 | File Descriptor (FD) | 进程打开文件表的非负整数索引，指向共享的打开文件描述 |
| 扩展属性 | Extended Attributes (xattr) | 挂载在文件节点上的命名空间键值对元数据 |
| 匿名内存文件 | Memory File Descriptor (memfd) | 不依赖磁盘目录树、支持封存机制（sealing）的内存后备文件 |
| 异步输入输出 | Asynchronous I/O (AIO) | Linux 原生 `io_setup`/`io_submit`/`io_getevents` 异步 I/O 接口族 |
| 直接内存访问 | Direct Memory Access (DMA) | 外设绕过处理器直接读写连续物理内存的数据传输方式 |
| 内存映射输入输出 | Memory-Mapped I/O (MMIO) | 通过非缓存物理地址窗口访问外设控制寄存器的机制 |
| 进程间通信 | Inter-Process Communication (IPC) | 包含管道、信号、套接字、POSIX 消息队列及 System V 共享内存/消息队列/信号量 |
| 可执行与可链接格式 | Executable and Linkable Format (ELF) | 用户态静态或动态可执行映像的二进制格式 |
| Linux 测试项目 | Linux Test Project (LTP) | 用于核验 Linux 系统调用与内核行为兼容性的官方测试套件 |
