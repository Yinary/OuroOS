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

核对官方评测仓库 `autotest-for-oskernel` 中 `kernel/postwork.py` 与各 `judge_*.py` 后，评分规则分为三类：

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

修改单个系统调用或排查特定测例时，不应每轮拷贝 4 GiB 原盘或等待全量 LTP 跑完。仓库已在 [tests/run_official.py](../tests/run_official.py) 与 [user/src/bin/official_init.rs](../user/src/bin/official_init.rs) 提供两项本地提速机制，且**完全不影响默认 `make all` 的正式送测行为**。

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
| `busybox` | `kill 10` 恒差 1 分 | 判分脚本 `judge_busybox-musl.py` 匹配固定文本 `kill 10`，而盘上脚本运行的是带动态进程号的 `kill $!`，属外部标签不对齐，非内核缺陷 |
| `libctest` | `run-static.sh` 与 `run-dynamic.sh` 缺少 `#!/bin/sh` | 已查验原盘脚本确认无 shebang；在直接 `execve` 或 LoongArch `musl` BusyBox `hush` 下会被拒绝执行，须由 `busybox sh` 显式解释这两个脚本 |
| `lmbench` | 硬编码路径与 `cp` 依赖 | 盘上 `lmbench_testcode.sh` 调用 `cp hello /tmp`（需保证 `PATH` 中存在 `cp`）；同时部分子流程依赖 `/code/lmbench_src/bin/build/lmbench_all` 指向当前 libc 的 `lmbench_all` |
| `iozone` | 计分取 `Max` 速率与提前停止 | `judge_iozone-musl.py` 取 4 进程中的 `Max throughput per process`；优化时应以真实持久化完成边界与通用页缓存为基准，避免单看表面吞吐 |
| `cyclictest` | 缺 `hackbench` 收尾标记整组清零 | `judge_cyclictest-musl.py` 强制要求串口出现 `kill hackbench: success`，否则即使前 4 项均打印数据也返回空结果（0 分） |
| `iperf` / `netperf` | 全部走本机回环 | 两个判分脚本基线均连接 `127.0.0.1`（`iperf` 端口 5001、`netperf` 端口 12865），核心依赖是 POSIX 套接字与回环 TCP/UDP 栈，而非外网或物理网卡通信 |
| LoongArch `musl` | 调度函数用户态桩（待实测） | 发布盘 LoongArch `musl` 将 `sched_setparam`、`sched_setscheduler`、`sched_getscheduler`、`sched_getparam` 直接实现为返回 `ENOSYS` 而不陷入内核；在 LoongArch `musl` 下遇到这 4 个接口报 `ENOSYS` 时需先确认是否根本未进内核 |

---

## 4. LTP 评测机制、问题归因与跳过策略研判

### 4.1 判分脚本与原盘脚本口径（已验证）

1. **只汇总 `Summary:` 段，不计纯 `TPASS` 行**：官方 `judge_ltp-musl.py` 仅在读到 `Summary:` 行后累加 `passed <N>`，且仅在读到 `FAIL LTP CASE <name> : <code>` 结束行时结算该用例（该行中的 `FAIL` 是官方固定前缀，末尾 `0` 代表正常退出）。本镜像中有 109 个旧式接口测例仅打印 `TPASS` 而不打印 `Summary:`，即使全部断言通过也在官方判分器中恒计 0 分。
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
- **正式送测路径**：遵循 [AGENTS.md](../AGENTS.md) §5“不按测例名做特判”的纪律，**当前不在正式启动器中引入按名跳过表**。逐例时限与预算控制在 `user/src/bin/official_init.rs` 中统一配置；若后续放宽逐例时限且总预算吃紧，需经全队评审后再决定是否在独立评测启动层排除无参必挂辅助程序。
