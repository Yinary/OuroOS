# OuroOS 官方评测说明与踩坑指南

本文档汇总全国大学生计算机系统能力大赛操作系统内核赛（OSComp）初赛原盘（`pre-20250615`）的评分口径、本地快速评测入口、发布盘与判分器常见陷阱，以及 `libctest`、`lmbench` 与 Linux 测试项目（Linux Test Project，LTP）的专项策略。文档只记录核对过官方评测脚本、原盘内容或本仓库实测的事实；尚未在 OuroOS 实测验证的外部环境注意事项会显式标注“待实测”。

---

## 1. 官方评测环境与评分结构

### 1.1 运行边界与交付物

- 官方评测使用 QEMU 10.0.2，单核（`-smp 1`）、1 GiB 内存，分别对 RISC-V 64 位（`rv`）与 LoongArch 64 位（`la`）挂载原盘镜像（`sdcard-rv.img` / `sdcard-la.img`，约 4 GiB）及可选辅助盘（`disk.img` / `disk-la.img`）。
- 官方框架以串口组标记切分各组输出，并喂给对应的 `judge_<组名>.py` 判分脚本：
  - 开始标记：`#### OS COMP TEST GROUP START <组名> ####`
  - 结束标记：`#### OS COMP TEST GROUP END <组名> ####`
- 单台虚拟机的线上整轮总时限约为 3,600 秒（以平台实际配置为准）；切换测试组不会重置整机倒计时。

### 1.2 全部 11 大组（22 组）评分公式与分值上限

核对官方评测仓库 `.cache/autotest-for-oskernel/kernel/postwork.py` 与各 `judge_*.py` 后，评分规则分为三类：

1. **正确性计数类（`basic`、`busybox`、`lua`、`libctest`）**：单架构按通过条数累计，`postwork.py` 将 `rv` 与 `la` 得分相加；`musl` 与 `glibc` 分别作为独立测试组计分（共 4 份配置）。
2. **性能基线类（`libcbench`、`lmbench`、`iozone`、`iperf`、`netperf`、`cyclictest`）**：每个子项得到大于 0 的有效结果即可获得 **保底 1.0 分**；若性能优于基线（比值 $\text{ratio} \ge 1$），得分为 $2 - 1/\text{ratio}$，渐近上限 **2.0 分**。因此**从 0 跑通整组的分值收益显著高于跑通后的局部调优**。
3. **LTP 对数映射类（`ltp-musl`、`ltp-glibc`）**：每个 C 标准库（C Library，libc）组先将 `rv` 与 `la` 两架构通过断言的原始计数相加得到 `raw`（裁剪至 `[0, 10000]`），再映射为组得分：
   $$\text{final} = 500 \times \log_{10}\left(1 + \frac{9 \times \text{raw}}{10000}\right)$$
   `ltp-musl` 与 `ltp-glibc` **各自独立封顶 500 分**（合计 1,000 分）。该公式为凹函数，低分段每增加一条通过断言的边际收益远高于高分段。

| 测试组 | 计分类型 | 单配置项数/满分 | 4 配置合计上限 | 关键说明 |
|---|---|---:|---:|---|
| `basic` | 正确性 | 32 项 / 102 分 | 408 | 每项含多条子断言 |
| `busybox` | 正确性 | 53 项清单（实测 54/55） | ~216 | `kill 10` 存在判分标签外部差异 |
| `lua` | 正确性 | 9 项 / 9 分 | 36 | 纯解释器与基础文件/数学调用 |
| `libcbench` | 性能 | 27 项 × (1~2 分) | 108~216 | 含内存分配、字符串、线程创建与锁 |
| `libctest` | 正确性 | 220 项（静态 109 + 动态 111） | **880** | 绝大部分为纯 C 库与基础系统调用，仅 1 项需套接字 |
| `ltp-musl` | 对数映射 | 双架构 `raw` 合计映射 | **500** | 双架构叠加放大收益明显 |
| `ltp-glibc` | 对数映射 | 双架构 `raw` 合计映射 | **500** | 独立于 `ltp-musl`，从 0 起步斜率最陡 |
| `lmbench` | 性能 | 36 项 × (1~2 分) | **144~288** | 系统调用、管道、信号、缺页、文件与上下文切换 |
| `iozone` | 性能 | 20 项 × (1~2 分) | 80~160 | 多进程文件吞吐测试，取单进程最大值 |
| `iperf` | 性能 | 6 项 × (1~2 分) | 24~48 | 仅连接 `127.0.0.1` 回环（TCP/UDP） |
| `netperf` | 性能 | 5 项 × (1~2 分) | 20~40 | 仅连接 `127.0.0.1` 回环（TCP/UDP 流与请求响应） |
| `cyclictest` | 性能 | 4 项 × (1~2 分) | 16~32 | 强依赖 `hackbench` 400 任务压测及收尾标记 |

---

## 2. 本地快速评测：QCOW2 覆盖层与拆组/拆例运行

修改单个系统调用或排查特定测例时，不应每轮拷贝 4 GiB 原盘或等待全量 LTP 跑完。仓库已在 [tests/run_official.py](file:///home/hoyouu/OuroOS/tests/run_official.py) 与 [user/src/bin/official_init.rs](file:///home/hoyouu/OuroOS/user/src/bin/official_init.rs) 提供两项本地提速机制，且**完全不影响默认 `make all` 的正式送测行为**。

### 2.1 QCOW2 写时复制覆盖层（默认启用）

- `tests/run_official.py` 默认调用 `qemu-img create -q -f qcow2 -b <原盘绝对路径> -F raw <覆盖层>` 为原盘和辅助盘秒级创建 QEMU 写时复制镜像（QEMU Copy-On-Write version 2，QCOW2），替代整盘复制，并在退出前通过 `finally` 自动删除覆盖层。
- 仅在显式传入 `--sha256` 时才计算原盘哈希，避免每轮顺序读取 4 GiB 镜像耗时。
- 如需严格复现原始镜像输入输出路径，可附加 `--raw-copy` 回退整盘拷贝。

### 2.2 本地拆组与 LTP 前缀过滤

`tests/run_official.py` 支持以下本地参数（未传入时行为与原有正式验收一致）：

- `--groups <逗号分隔组名>`：通过编译期环境变量 `OUROOS_INIT_GROUPS` 构造本地临时启动器内核（输出在 `--output` 下的临时文件并在运行结束后删除，**绝不覆盖**仓库根目录的 `kernel-rv` / `kernel-la`）。
- `--ltp-filter <逗号分隔前缀>`：仅在本地运行 `ltp-musl` / `ltp-glibc` 时按用例名前缀筛选（通过 `OUROOS_LTP_FILTER` 生效）。
- `--ltp-timeout <秒>`：覆盖本地 LTP 逐例时限（通过 `OUROOS_LTP_TIMEOUT` 生效，默认 2 秒）。

常用命令示例（先确保 `qemu-system-riscv64` / `qemu-system-loongarch64` 10.0.2 与 `cargo` 在 `PATH` 中）：

```bash
# 单跑 riscv64 的 lua-musl（冒烟校验，数秒内完成）
python3 tests/run_official.py rv --groups lua-musl --output target/official --timeout 60

# 单独摸底双库 libctest 或 lmbench
python3 tests/run_official.py rv --groups libctest-musl,libctest-glibc --output target/official --timeout 180
python3 tests/run_official.py la --groups lmbench-musl,lmbench-glibc --output target/official --timeout 180

# 本地按前缀拆测 LTP（例如只测 chown 与 statx 相关用例，放宽单项超时到 5 秒）
python3 tests/run_official.py la --groups ltp-musl --ltp-filter chown,statx --ltp-timeout 5 --output target/official --timeout 120
```

> **产物清理纪律**：本地运行固定复用 `target/official` 目录覆盖上一轮结果，不在 `target/` 下跨轮累积多份镜像副本；离开机器前执行 `du -sh target/` 检查磁盘占用。

---

## 3. 官方原盘、运行库与判分器常见踩坑清单

以下问题大多来自发布镜像打包方式、C 运行库差异或判分脚本规则，排查失败时应先核对是否属于此类外部前提，再追踪内核系统调用。

### 3.1 启动环境与动态链接器

- **`basic/run-all.sh` 缺少执行位**：发布盘上 `/musl/basic/run-all.sh` 与 `/glibc/basic/run-all.sh` 权限为 `0644`，内核按执行位校验会返回 `EACCES`，需由启动器在运行副本补 `0755`。
- **动态加载器路径固定**：可执行文件在 `PT_INTERP` 段写死了加载器路径（如 riscv64 的 `/lib/ld-linux-riscv64-lp64d.so.1`、`/lib/ld-musl-riscv64.so.1`、`/lib/ld-musl-riscv64-sf.so.1`，loongarch64 的 `/lib64/ld-linux-loongarch-lp64d.so.1`、`/lib64/ld-musl-loongarch-lp64d.so.1` 及 `/usr/lib64/libc.so.6`），缺失任一路径会直接加载失败。
- **缺少 `/etc/passwd` 与 `/etc/group`**：原盘默认无账户数据库，导致调用 `getpwnam("nobody")` 的测例（如 `access01`、`chown03`、`setreuid*`、`umount03` 等）在准备阶段报 `ENOENT` / `TBROK` 退出。`official_init.rs` 已在启动时写入 `root` 与 `nobody`（UID/GID 65534）。
- **静态 glibc 早期 `getrandom` 残留 `errno`（待实测）**：部分静态 glibc 程序在 `main` 之前由 `malloc` 初始化调用 `getrandom`，若此时内核熵源未就绪返回 `EAGAIN`，随后成功的系统调用不会清空 `errno`，可能引发依赖 `errno == 0` 的断言误判。排查 `glibc` 异常时应先确认当前架构下内核启动熵是否就绪。

### 3.2 各测试组特有陷阱

| 测试组 | 已核实陷阱与现象 | 判读与处理要点 |
|---|---|---|
| `busybox` | `kill 10` 恒差 1 分 | 判分脚本 [judge_busybox-musl.py](file:///home/hoyouu/OuroOS/.cache/autotest-for-oskernel/kernel/judge/judge_busybox-musl.py) 匹配固定文本 `kill 10`，而盘上脚本运行的是带动态进程号的 `kill $!`，属外部标签不对齐，非内核缺陷 |
| `libctest` | `run-static.sh` 与 `run-dynamic.sh` 缺少 `#!/bin/sh` | 已查验原盘脚本确认无 shebang；在直接 `execve` 或 LoongArch `musl` BusyBox `hush` 下会被拒绝执行，须由 `busybox sh` 显式解释这两个脚本 |
| `lmbench` | 硬编码路径与 `cp` 依赖 | 盘上 `lmbench_testcode.sh` 调用 `cp hello /tmp`（需保证 `PATH` 中存在 `cp`）；同时部分子流程依赖 `/code/lmbench_src/bin/build/lmbench_all` 指向当前 libc 的 `lmbench_all` |
| `iozone` | 计分取 `Max` 速率与提前停止 | [judge_iozone-musl.py](file:///home/hoyouu/OuroOS/.cache/autotest-for-oskernel/kernel/judge/judge_iozone-musl.py) 取 4 进程中的 `Max throughput per process`；优化时应以真实持久化完成边界与通用页缓存为基准，避免单看表面吞吐 |
| `cyclictest` | 缺 `hackbench` 收尾标记整组清零 | [judge_cyclictest-musl.py](file:///home/hoyouu/OuroOS/.cache/autotest-for-oskernel/kernel/judge/judge_cyclictest-musl.py#L67-L75) 强制要求串口出现 `kill hackbench: success`，否则即使前 4 项均打印数据也返回空结果（0 分） |
| `iperf` / `netperf` | 全部走本机回环 | 两个判分脚本基线均连接 `127.0.0.1`（`iperf` 端口 5001、`netperf` 端口 12865），核心依赖是 POSIX 套接字与回环 TCP/UDP 栈，而非外网或物理网卡通信 |
| LoongArch `musl` | 调度函数用户态桩（待实测） | 发布盘 LoongArch `musl` 将 `sched_setparam`、`sched_setscheduler`、`sched_getscheduler`、`sched_getparam` 直接实现为返回 `ENOSYS` 而不陷入内核；在 LoongArch `musl` 下遇到这 4 个接口报 `ENOSYS` 时需先确认是否根本未进内核 |

---

## 4. LTP 评测机制、问题归因与跳过策略研判

### 4.1 判分脚本与原盘脚本口径（已验证）

1. **只汇总 `Summary:` 段，不计纯 `TPASS` 行**：官方 [judge_ltp-musl.py](file:///home/hoyouu/OuroOS/.cache/autotest-for-oskernel/kernel/judge/judge_ltp-musl.py#L72-L86) 仅在读到 `Summary:` 行后累加 `passed <N>`，且仅在读到 `FAIL LTP CASE <name> : <code>` 结束行时结算该用例（该行中的 `FAIL` 是官方固定前缀，末尾 `0` 代表正常退出）。本镜像中有 109 个旧式接口测例仅打印 `TPASS` 而不打印 `Summary:`，即使全部断言通过也在官方判分器中恒计 0 分。
2. **原盘 `ltp_testcode.sh` 不可直接跑完**：原脚本平铺遍历 `ltp/testcases/bin` 且无逐例时限与会话隔离，第 107 例 `cgroup_fj_proc` 会阻塞在 `sigsuspend` 等待控制器信号，第 184 例 `connect01` 会执行 `kill(0, SIGKILL)` 杀掉同进程组的脚本 shell。因此 OuroOS 在 `official_init.rs` 中由启动器按独立会话逐例驱动并施加逐例超时。
3. **`PATH` 顺序冲突**：若执行 LTP 的 shell 类测例，需注意 `$LTPROOT/testcases/bin` 应排在 `/$libc` 之前，否则同名 `test.sh` 会误命中 Lua 目录脚本。
4. **发布镜像常见环境缺失（判读 `TCONF` / `TBROK` 时需先区分）**：
   - 缺少可反复格式化的独立测试块设备分区及 `mkfs.ext4` 工具，会导致大批文件系统与挂载测例进入 `TCONF`/`TBROK`；
   - `statx11` 在未挂载 `/sys` 时，会因测例自身回退截断循环缺少空串终止条件而进入越界死循环（待实测）；
   - `io_setup01` 因发布镜像交叉编译时缺少 `libaio` 直接报 `TCONF` 退出，未实际调用 `io_setup`；
   - `float_bessel`、`float_exp_log`、`float_iperb`、`float_power`、`float_trigo` 在 glibc 下依赖发布镜像缺失的 `libgcc_s.so.1`（且 musl 无计分摘要）。

### 4.2 跳过表的四类典型条目与团队策略边界

在平铺无参调用 `ltp/testcases/bin` 的场景下，最耗时或完全无计分价值的二进制可归纳为四类：

1. **缺少外部控制器或管道输入的伪独立辅助程序**：如 `cgroup_fj_proc`、`cgroup_regression_*`、`cpuctl_fj_cpu-hog`、`cpuhotplug_do_*`、`cpuset_*`、`doio`、`fs_racer_*`、`memcg_test_*`、`netstress`、`pthserv`、`timed_forkbomb`、`tst_hexdump` 等。这类程序原本由主测试框架传参、发信号或喂标准输入，无参直跑在参考 Linux 上也会挂起。
2. **明确无 `Summary:` 恒得 0 分的旧测例与基准**：如 `fcntl14`、`fcntl14_64`、`ftest01`–`ftest08`、`inode02`、`kill02`、`lchown03`、`mknodat02`、`nptl01`、`open12`、`rename11`、`rename14`、`renameat01`、`sendmsg02`、`umount2_01`、`epoll-ltp`、`semop05`、`hackbench` 等。
3. **发布镜像编译/运行依赖缺失**：`io_setup01` 与上述 5 个 `float_*` 程序。
4. **整轮预算内的极低分超长压力测试**：如 `dio_append`、`dio_sparse`、`fs_fill`、`fork14`、`mallocstress`、`mmapstress01`、`mmap1`、`mmap3`、`inotify09`、`starvation`、`copy_file_range01`、`cve-2016-7117`、`shm_test` 等（往往耗时数十秒至分钟级，单配置仅 0~2 原始分）。

**OuroOS 当前策略**：
- **本地开发排查**：使用第 2 节的 `--groups ltp-musl --ltp-filter <前缀>` 按模块拆分运行，避免反复等待无关用例超时。
- **正式送测路径**：遵循 [AGENTS.md](file:///home/hoyouu/OuroOS/AGENTS.md) §5“不按测例名做特判”的纪律，**当前不在正式启动器中引入按名跳过表**。按 `dev`（`b40bf5c`）实测，2 秒逐例时限下跑完全部 2,820 例仅耗约 772 秒，双库合计仍在 3,600 秒单机预算内；待后续需要放宽逐例时限（例如避免 `clock_nanosleep01`、`alarm05`–`alarm07` 在 2 秒线边缘被截断）且总预算吃紧时，再由全队评审是否仅在独立评测启动层排除无参必挂辅助程序。

---

## 5. `libctest` 与 `lmbench` 首轮摸底记录（2026-11-26）

测试基线：`dev` 分支 `b40bf5c`，使用 QEMU 10.0.2 + QCOW2 覆盖层本地拆组运行。

### 5.1 `libctest` 摸底与修复验证结果

- **首轮基线（`dev` `b40bf5c`）**：三配置（`rv`/`la` `musl`、`rv` `glibc`）均因 [docs/ostd-contracts.md](file:///home/hoyouu/OuroOS/docs/ostd-contracts.md) 原缺陷 10（`rt_sigtimedwait` 无法消费已屏蔽的 `SIGCHLD`）在 `runtest.exe` 空等 5 秒超时后报 `kill failed: No such process`，判分器全组 0/880。
- **修复后实测结果（`oscomp/libctest`，QEMU 10.0.2 + QCOW2 覆盖层，双架构全量跑完）**：
  - `rv` `libctest-musl`：**`217/220`**（全部 217 项盘上可执行测例 100% 通过）
  - `la` `libctest-musl`：**`217/220`**（全部 217 项盘上可执行测例 100% 通过）
  - `rv` `libctest-glibc`：**`179/220`**
  - `la` `libctest-glibc`：**`179/220`**
  - 四配置合计：**`792/880`**（相较基线提升 +792 分）。
- **剩余未通过项的已验证归因（宿主 Linux 下以 `qemu-riscv64` 直接运行原盘二进制核对）**：
  1. **盘上脚本未收录（3 项 × 4 配置 = 12 分）**：`static crypt`、`dynamic crypt`、`static pleval` 在发布盘 `run-static.sh` / `run-dynamic.sh` 中不存在，实际可运行上限为每配置 217 项。
  2. **发布盘缺少动态库 `libgcc_s.so.1`（3 项 × 2 架构 = 6 分）**：`glibc` 动态版 `pthread_cancel`、`pthread_cancel_points`、`pthread_exit_cancel` 在线程取消展开阶段尝试加载 `libgcc_s.so.1` 失败中止。
  3. **glibc 运行库 / locale 与 musl 测例预期差异（35 项 × 2 架构 = 70 分）**：`clocale_mbfuncs`、`daemon_failure`、`dn_expand_empty`、`dn_expand_ptr_0`、`fgetwc_buffering`、`fnmatch`、`fscanf`、`fwscanf`、`mbc`、`regex_ere_backref`、`regex_escaped_high_byte`、`setvbuf_unget`、`sscanf`、`strftime`、`strtol`、`swprintf`、`wcstol`（静态与动态共 34 项）及静态 `pthread_cancel_points` 的非阻塞 `pthread_join` 断言，在宿主 Linux 上运行发布盘 `glibc` 原版二进制同样失败或超时。

### 5.2 `lmbench` 摸底与修复验证结果

- **首轮基线（`dev` `b40bf5c`）**：三配置均打印 `latency measurements` 后卡死在 `lat_syscall -P 1 null`（0/36）。根因是 `benchmp_parent` 依赖 `pselect6(72)` 与 `setitimer(103)`，该部分已在 `net/loopback-stack`（`147f98b`）补齐。
- **二次摸底与内核修复（`oscomp/lmbench` 分支，基线 `147f98b`）**：
  1. **修复 `/dev/null` 写与定位读写语义**：`OpenFile::write_chunk` 原漏匹配 `Kind::DevNull`，导致 `lat_syscall write` 报 `Bad file descriptor`；同步补齐 `check_positioned` 与 `read_at` 对 `/dev/null` 的支持（对齐 Linux `null(4)`）。
  2. **管道按实例定向唤醒与单任务续期**：为每个管道分配唯一实例号并新增 `WaitReason::PipeId(u64)`，通过 16 槽无锁原子队列定向唤醒（槽满退回广播），消除 `lat_ctx` 最高 96 进程环路中的多管道惊群效应；同时在 `resume_check` 中就绪队列为空且无待消费唤醒时直接续期时间片。
- **验证口径与实测结果（QEMU 10.0.2 + QCOW2 覆盖层）**：
  - **无环境变量改动的原版脚本验证（未设 `ENOUGH`）**：实测 `rv` 的 `null`/`read`/`write` 与 `la` 的 `null`/`read` 均正常推进无挂死，但每条 `./lmbench_all` 子命令在 QEMU 极小代码生成器（Tiny Code Generator，TCG）下常耗 50–60 秒。对照宿主 Linux 下直接运行 `/usr/bin/qemu-riscv64 lmbench_all lat_syscall -P 1 null` 同样耗时 45.8–47.1 秒，反汇编确认根因是 `init_timing()` 对 `[1.015, 1.02, 1.035]` 倍率要求线性误差不超过 0.5%，QEMU TCG 抖动易令四档候选 `[5000, 10000, 50000, 100000]` 微秒全部失败并回退到 `enough = 1,000,000` 微秒（1 秒），导致 `l_overhead()` 与 `benchmp()` 各执行 11 轮 1 秒循环；整组 24 条子命令累计约需 15–25 分钟（单架构双库约 30–50 分钟）。
  - **全量 36 项功能覆盖诊断（本地临时设置 `ENOUGH=5000` 缩短标定窗口，验证后已还原，未写入正式启动器）**：双架构四配置全部 144/144 子项 100% 通过无崩溃与挂死：
    - `rv` `lmbench-musl`：**`43.88/36`**（36/36），`lat_ctx 96` 延迟由定向唤醒前的 `3440.87 us` 降至 **`309.94 us`**（降低约 91%）；
    - `rv` `lmbench-glibc`：**`43.79/36`**（36/36），`lat_ctx 96` 延迟由 `2481.23 us` 降至 **`264.63 us`**（降低约 89%）；
    - `la` `lmbench-musl`：**`45.59/36`**（36/36），`lat_ctx 96` 为 **`135.00 us`**；
    - `la` `lmbench-glibc`：**`44.54/36`**（36/36），`lat_ctx 96` 为 **`64.86 us`**。
  - **已知外部行为**：原盘 `/musl/hello` 与 `/glibc/hello` 是不含 `#!/bin/sh` 的脚本，内核按 Linux `execve(2)` 返回 `ENOEXEC`；`lat_proc shell` 下 `rv` BusyBox `ash` 打印 `sh: /tmp/hello: not found`，`la` BusyBox `hush` 打印 `sh: can't execute '/tmp/hello': Exec format error`，两者均不影响 `Process fork+/bin/sh -c` 正常计时得分。
  - **默认送测启用状态**：`official_init.rs` 已在默认送测流程中启用 `lmbench-musl` 与 `lmbench-glibc`，并在 `INSTALL_LIST` 统一安装 `/bin/cp`；严格遵循不设 `ENOUGH` 等测例环境变量特判的原则，整轮耗时视远端评测机 QEMU TCG 标定稳定性而定。

### 5.3 `iperf` 与 `netperf` 修复验证结果

- **实测范围**：`net/loopback-stack` 分支，QEMU 10.0.2 + QCOW2 覆盖层，双架构四组全量运行（`iperf-musl`、`iperf-glibc`、`netperf-musl`、`netperf-glibc`）。
- **已解决的关键缺口**：
  1. `/dev/urandom` 与 `/dev/random` 字符设备（`iperf3` 生成 cookie 依赖）及 `/dev/null` 标准设备号 `makedev(1, 3)`（glibc `daemon()` 严格校验）；
  2. `pselect6(72)`（`iperf3` 与 `netserver`/`netperf` 主事件循环依赖）与 `setitimer(103)`/`getitimer(102)` 的 `ITIMER_REAL` + `SIGALRM`（`netperf` 测试时长控制依赖）；
  3. 扩展本地回环 `AF_INET` 套接字选项（`SO_DONTROUTE`、`SO_LINGER`、`SO_RCVLOWAT`/`SO_SNDLOWAT`、`SO_SNDBUF`/`SO_RCVBUF` 翻倍语义、`IP_TOS`/`IP_TTL`/`IP_MTU_DISCOVER`/`IP_RECVERR`、`TCP_MAXSEG`/`TCP_CORK`/`TCP_KEEP*`/`TCP_INFO`/`TCP_CONGESTION`）、UDP `SO_REUSEADDR` 同端口绑定与对端优先解复用（支撑 `PARALLEL_UDP`）、阻塞 TCP 小包整块写入防短写（支撑 `netperf TCP_STREAM`）；
  4. `official_init.rs` 在测试组脚本退出后清理脱离会话的遗留后台守护进程（`iperf_testcode.sh` 启动的 `iperf3 -s -D` 未自行终止，避免占端口影响后续组或阻塞关机）。
- **实测结果（全部 8 组、44/44 子项 100% 通过）**：
  - `rv`：`iperf-musl` **6.38/6**（6/6）、`iperf-glibc` **6.37/6**（6/6）、`netperf-musl` **8.08/5**（5/5）、`netperf-glibc` **8.08/5**（5/5）；
  - `la`：`iperf-musl` **6.91/6**（6/6）、`iperf-glibc` **6.89/6**（6/6）、`netperf-musl` **8.57/5**（5/5）、`netperf-glibc` **8.68/5**（5/5）。

### 5.4 `iozone` 摸底与修复验证结果

- **首轮基线（`dev` `ba9e2b4`）**：双架构四配置下第 1 条自动模式 `./iozone -a -r 1k -s 4m` 均在约 10 秒内通过，但其余 7 条 4 进程计分命令（共 20 项）全部因缺少 `shmget(194)` 报 `Unable to get shared memory segment(shmget) ... Error 38` 退出（0/20）。
- **系统调用审计与修复（`ipc/sysv-shm` 分支）**：
  1. 宿主 Linux `qemu-riscv64 -strace` 与动态符号核对确认 `iozone` 共调用 33 个系统调用，仅缺 System V 共享内存（`shmget` 194、`shmctl` 195、`shmat` 196、`shmdt` 197）与 `sync`（81）。
  2. 新增 `kernel/src/mm/shm.rs` 全局共享内存段表，直接复用 `mm::shared::SharedPage` 与 `AreaKind::SharedAnonymous` 的缺页和 `fork` 共享机制，支持 `IPC_RMID` 延迟释放与 `UserAddressSpace` 的 `fork`/`Drop` 挂接计数配平；同时接入 `sync(81)` 转发至 Ext4 全局同步。
- **修复后实测结果（QEMU 10.0.2 + QCOW2 覆盖层，全部 4 配置 80/80 子项 100% 通过）**：
  - `rv`：`iozone-musl` **20.00/20**（20/20）、`iozone-glibc` **20.00/20**（20/20，单组实测耗时约 139 秒）；
  - `la`：`iozone-musl` **20.00/20**（20/20）、`iozone-glibc` **20.00/20**（20/20，双库合跑共耗时约 220 秒）。
  - 4 进程并发模式下单进程最大吞吐约 `1.1–2.7 MB/s`（低于官方 Linux 页缓存基线，当前 20 项均稳拿保底 1.0 分，合计 +80 分）；后续引入通用文件页缓存后可进一步拉高该组吞吐得分。
  - **默认送测启用状态**：`official_init.rs` 已在默认送测流程中启用 `iozone-musl` 与 `iozone-glibc`，顺序排在 `netperf` 之后、`lmbench` 之前，以在单机总预算内优先锁定稳定的 `iozone` 得分。

### 5.5 通用块层写回缓存与 I/O 热路径优化验证结果（`fs/io-cache`）

- **优化范围（均属通用操作系统机制，无测例特判、不弱化 `fsync`/`sync` 持久化语义）**：
  1. **通用 4 KiB 块层写回缓存（`kernel/src/fs/block_cache.rs`）**：在 `rsext4::Jbd2Dev` 之下包裹 `Partition`，以独占物理页帧 `OwnedFrame` 承载块数据（单卷上限 4,096 块 = 16 MiB，不占 32 MiB 固定内核堆），采用开放寻址哈希表（Knuth 后向移位无墓碑删除）与 Clock 淘汰策略；`flush()` 对所有脏块按块号排序并合并连续段（最多 16 块 = 64 KiB）批量写回后再调用 `drivers::flush`，保证 `fsync`/`sync`/`umount` 真实落盘；物理帧计入 `fs::retained_frames()` 与 `/proc/meminfo` 的 `Buffers`/`MemAvailable` 字段。
  2. **块内切片直读直写与 `rsext4` 热路径瘦身**：扩展 `rsext4::BlockDevice::{read_slice, write_slice}` 默认方法并透传至 `BlockCache` 原地切片读写，消除 32 块小 `datablock_cache` 淘汰抖动与整块搬运；单块读直走 `resolve_inode_block` 免 `Vec<ExtentRun>` 堆分配；`atime` 采用 Linux `mount(8)` 默认 `relatime` 语义；`InodeCache` 命中单次查找并将 inode CRC32C 重算延迟至落盘编码前统一执行（与原逐次重算位级一致）。
  3. **VFS/系统调用/内存热路径去冗余**：`OpenFile::check_type` 直接判定目录标记免除每次读写 `fs::stat` 加锁；`fs::write` 合并旧长度读取并用只读切片同步共享页（消除 4 KiB 栈数组清零与拷贝），`fs/cache` 无映射时原子快路径免锁跳过；`transfer` 通过单槽 4 KiB 堆缓冲池复用暂存区；`user_access` 对 ≤4 页短传输使用栈数组并合并单次页表翻译；`UserPageTable::activate` 在硬件页表已指向本空间时跳过冗余寄存器写回与全局 TLB 刷洗。
- **双架构 `iozone` 优化前后实测对比（QEMU 10.0.2 + QCOW2 覆盖层，满分口径 20 项 × 渐近上限 2.0 = 40.00/组，4 配置理论上限 160.00）**：
  - `rv` `iozone-musl`：**20.00 → 37.50/20**（+17.50；4 进程 `readers` 由 ~1.2 MB/s 升至 190.7 MB/s，`rewriters` 升至 162.2 MB/s）；
  - `rv` `iozone-glibc`：**20.00 → 37.34/20**（+17.34；双库总 CPU 时间降至 25.1 秒）；
  - `la` `iozone-musl`：**20.00 → 38.03/20**（+18.03；4 进程 `re-readers` 升至 244.0 MB/s）；
  - `la` `iozone-glibc`：**20.00 → 38.21/20**（+18.21；单进程 `reread` 达 300.2 MB/s）；
  - **四配置合计**：**80.00 → 151.08 / 160**（**+71.08 分**，达到理论渐近上限的 94.4%，全部 80/80 子项均超越官方 Linux 基线 3.2×–50.0×）。
- **关联组增益与回归验证**：
  - `rv` 9 组回归（总耗时约 58 秒）：`basic` 102/102、`busybox` 54/55、`lua` 9/9、`libctest-musl` 217/220 零回退，`iperf-musl` 由 `6.38` 升至 **7.23/6**、`netperf-musl` 由 `8.08` 升至 **8.74/5**；
  - `la` 9 组回归：`basic` 102/102、`busybox` 54/55、`lua` 9/9、`libctest-musl` 217/220 零回退，`iperf-musl` 由 `6.91` 升至 **7.96/6**、`netperf-musl` 由 `8.57` 升至 **9.25/5**；
  - `rv` `lmbench-musl` 前 7 项抽测（300 秒内）：`Simple syscall` 降至 **1.84 µs**、`Simple read` **3.41 µs**、`Simple write` **3.21 µs**、`Select on 100 fd's` **7.94 µs**（7 项得 12.91/14）；
  - 文件系统一致性专项：`fs_rename_backend.py`（15/15 故障注入回滚 + `e2fsck`）、`fs_stat.py`（默认及 `--metadata` 双架构 128/256 字节 inode + `e2fsck`）、`fs_fcntl.py`（双架构 + `e2fsck`）、`file_mapping.rs`（6/6）全部通过。
