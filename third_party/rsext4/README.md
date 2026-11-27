# rsext4 0.8.1

源码来自 [crates.io 发布包](https://crates.io/crates/rsext4/0.8.1)，上游为 [Starry-OS/rsext4](https://github.com/Starry-OS/rsext4)。保留 Apache-2.0 许可证。

OuroOS 随库维护以下补丁。

- 工具链和缓存锁。为仓库固定 nightly 启用所需语言特性，使用 `spin::Mutex` 保护缓存。
- 只读挂载。检查不兼容特性，阻止日志重放和只读卷上的元数据写回。
- 目录和描述符解析。处理哈希目录校验、目录项查找和块组描述符。
- 只读文件访问。跳过访问时间更新，路径回退时同时恢复父目录 inode 编号和内容，经过普通文件时返回 ENOTDIR。
- 按父 inode 创建空普通文件。沿用 inode 分配、元数据写回和目录项插入，仅支持线性目录。
- 按父 inode 创建目录。复用目录块初始化、校验和与链接数更新，保留调用方传入的权限位。
- 父目录扩容分配目录块遇到 ENOSPC 时，回收尚未发布的子 inode 和数据块。
- 单独读取目录块中的目录项字节，供 OuroOS 实现 `getdents64`。
- 普通文件删除。单独移除目录项并更新链接数，由内核在最后一个打开引用释放后回收 inode、已写入和预分配的 extent。回收前丢弃对应的数据块缓存。暂不回收外部扩展属性块或旧式块映射。
- JBD2 同步。自动提交和显式同步使用日志 inode 的物理块映射。挂载时先落盘恢复标志，卸载时先提交并写回日志事务，再清除标志。
- 按父目录 inode 移除空目录名。更新父目录链接数和被移除目录的链接数，复用目录块与 inode 回滚，以及无引用时的 inode 回收。
- 按 inode 修改归属。新增 `metadata::chown_inode`，路径和 FD 共用现有属主、属组、ctime 和校验和更新。
- 按 inode 更新时间。新增 `metadata::utimens_inode`，复用已有时间字段、校验和与元数据更新流程，供 FD 和符号链接操作使用；双方均 Omit 时不写入，只读卷拒绝实际更新。

- 按父 inode 重命名。新增 `file::rename_entry` 与旧目标延迟回收接口，路径版 rename/mv 复用；替换时不先删除目标，校验类型与空目录，更新父目录链接数及 `..`。失败恢复保存的目录块和 inode，插入失败撤销已发布名称，已扩容空间保留作目录容量；不保证掉电原子性。外部 xattr 或有块的旧式映射目标暂拒绝替换。

- 按 inode 调整长度。`file/io.rs` 使用稀疏扩展，缩短时清零尾块并回收数据和索引块；`extents_tree/parse.rs` 提供包含 unwritten extent 的区间遍历，避免遗漏预分配或按稀疏文件逻辑长度展开。数据块归还后丢弃对应缓存，时间更新先在 inode 副本上完成。旧式映射仅保留直接块清零，外部 xattr 和 HUGE_FILE 编码暂拒绝截断。

Cargo 清单移除了随上游测试程序提供的目标。内核默认启用读写，通过 `rsext4-readonly` 选择只读模式。

可写构建挂载干净的无日志卷或使用经典格式内部 JBD2 的干净卷。它支持在线性目录中创建文件和目录，以及按偏移写入、任意长度截断和删除普通文件。`fsync` 先写回文件的共享页，再同步卷缓存并提交日志事务。外部日志、扩展日志特性和需要重放的镜像会被拒绝。重命名支持普通移动和 NOREPLACE；在用目录由 OuroOS 返回 EBUSY。独立目录删除和日志重放待后续接入。
- JBD2 checksum_v3 写入。挂载时放行 journal 特性 64bit + checksum_v3（crc32c
  类型强制），描述符按 16 字节 v3 tag 写入（64bit 块号、逐块
  crc32c(uuid_seed + be32(seq) + 载荷) 校验、首 tag 后 journal UUID 与后续
  SAME_UUID），描述符块尾与 commit 块整体校验；commit 块落盘前先持久化
  journal 超级块（s_start/s_sequence），保证已提交事务在任意断电时刻可被
  标准工具重放；未支持特性组合仍拒绝。已知上游缺陷：目录块经数据块缓存
  直写 home 块、绕过日志（data=writeback 式），断电窗口可留下指向未分配
  inode 的目录项，标准 e2fsck 会清理。
- 读写热路径优化（`fs/io-cache`）：
  1. `BlockDevice` 新增带默认实现的 `read_slice`/`write_slice`，`BlockDev`、`Jbd2Dev` 与 `DataBlockCache::read_block_slice`/`write_block_slice` 在未命中 32 块小缓存时透传底层块缓存切片直读直写，免除 4 KiB 堆分配、小缓存淘汰抖动与整块搬运；`write_block_static` 整块写回跳过冗余读块；
  2. `file/io.rs` 单块读直接走 `resolve_inode_block` 免除 `Vec<ExtentRun>` 堆分配，新增 `write_regular_inode_data` 合并类型校验与旧长度返回；
  3. `metadata/apply.rs` 采用 Linux `mount(8)` 默认 `relatime` 语义（仅当 `atime <= mtime/ctime` 或超过 24 小时才更新 `atime`）并复用已加载 inode；
  4. `cache/inode_table.rs` 与 `checksum/inode.rs` 优化命中单次 `BTreeMap` 查找，并将元数据校验和计算延迟至 `InodeCache` 落盘编码前统一执行（复用挂载时预计算的超级块校验种子与 256 字节栈缓冲），落盘结果与原逐次重算位级一致。
- 符号链接与硬链接补丁（`fs/link-symlink-sendfile`）：
  1. `file/create.rs` 新增 `create_symlink_inode`，按父 inode 在线性目录创建符号链接，允许相对与悬空目标（不校验目标存在性），同时支持 <60 字节内联快速链接与块存储长链接；
  2. `file/link.rs` 新增 `link_inode`，按目标 inode 与父目录 inode 创建硬链接（拒绝目录返回 `EPERM`，超 `65000` 链接数返回 `EMLINK`，更新链接计数失败时回滚目录项）；
  3. `file/delete.rs` 扩展 `unlink_regular_entry` 放行符号链接，并在 `free_inode` 中跳过内联快速符号链接的 `extent_block_map` 遍历，避免把内联目标文本误作块号释放。
- 命名管道与特殊节点补丁（`fs/fifo-fchdir-splice`）：
  1. `file/create.rs` 新增 `create_special_inode`（`create_regular_inode` 复用该实现），按父 inode 在线性目录创建普通文件（`S_IFREG`）、命名管道（`S_IFIFO`）、字符设备（`S_IFCHR`）、块设备（`S_IFBLK`）与套接字节点（`S_IFSOCK`），非普通节点不置 `EXT4_EXTENTS_FL`，字符/块设备按 Ext4 `old_encode_dev`/`new_encode_dev` 约定将设备号写入 `i_block[0]`/`i_block[1]` 并写入对应 `EXT4_FT_*` 目录项类型；
  2. `file/delete.rs` 扩展 `unlink_regular_entry` 放行命名管道、字符/块设备与套接字节点，并在 `free_inode` 中为无数据块的特殊节点跳过 `extent_block_map` 遍历；
  3. `file/link.rs` 扩展 `link_inode` 按目标 inode 类型写入对应 `EXT4_FT_*` 目录项类型。
