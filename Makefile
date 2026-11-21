# ============================================================
# OuroOS 顶层 Makefile
#
# `make all` 产出仓库根目录下的两个内核 ELF：
#   kernel-rv — riscv64 内核
#   kernel-la — loongarch64 内核
#
# 构建顺序：先构建用户程序（user/hello，独立于内核 workspace），
# 再构建内核；内核 build.rs 通过环境变量拿到用户 ELF 并内嵌。
#
# QEMU 加载方式：
#   rv: qemu-system-riscv64 -machine virt -bios default（OpenSBI）
#       -kernel kernel-rv，OpenSBI 从物理 0x80200000 交接执行
#   la: qemu-system-loongarch64 -kernel kernel-la（直启 ELF）
# ============================================================

# ---------- 构建 ----------
TARGET_RV := riscv64gc-unknown-none-elf
TARGET_LA := loongarch64-unknown-none
BIN_RV    := target/$(TARGET_RV)/release/kernel
BIN_LA    := target/$(TARGET_LA)/release/kernel
USER_REL  := release

# 用户程序 crate（独立 workspace，与内核共用 target/ 目录，
# cargo clean 可一并清理）
USER_CRATE := user/hello

# loongarch64 的发行版预编译 libcore 含 LSX 向量指令（基线仅 +f,+d），运行时会触发
# Disable 异常；且 polyhal-boot 只开 FPE。用 build-std 从源码自编 core/alloc，
# 并禁用 LSX/LASX 代码生成（两架构统一走 build-std；用户程序同样处理）。
BUILD_STD     := -Z build-std=core,alloc
USER_BUILD_STD := -Z build-std=core
RUSTFLAGS_LA := RUSTFLAGS="-Zunstable-options -C target-feature=-lsx,-lasx"

# ---------- 运行参数 ----------
# 注意：loongarch virt 的 0x80000000 物理地址仅在内存 > 256M 时存在（lowmem [0,256M) +
# highmem [0x80000000,...)），因此 la 侧内存必须 > 256M，这里统一默认 1G。
MEM ?= 1G
# 仅面向单核，默认 -smp 1
SMP ?= 1
LOG ?= warn         # 编译期日志级别: error|warn|info|debug|trace（boot 报告块由 polyhal 固定打印，不受此控）
FEATURES ?=         # 附加内核 feature，例如 rsext4-readonly
KERNEL_FEATURES = $(if $(strip $(FEATURES)),--features "$(strip $(FEATURES))")

# QEMU：默认取 PATH 中的可执行文件；不在 PATH 时用变量覆盖，例如：
#   make run-la QEMU_LA=/path/to/qemu-system-loongarch64
QEMU_RV ?= qemu-system-riscv64
QEMU_LA ?= qemu-system-loongarch64

# 离线构建（评测环境无外网，ENVIRONMENT.md：禁止在线下载、隐藏目录会被
# 评测机过滤）：第三方依赖以 vendor.tar.xz 归档随仓库提交（cargo vendor
# 产物；crate 内 .cargo-checksum.json 等点开头文件会被 Clone 过滤，必须
# 归档交付），make all 解压并把 CARGO_HOME 指到仓库内非隐藏目录（官方
# 注意事项：.cargo 需改名后在 Makefile 恢复）。
VENDOR_ARCHIVE := vendor.tar.xz
CARGO_HOME := $(CURDIR)/.cargo-home

$(CARGO_HOME)/config.toml: cargo-vendor-config.toml | vendor/.extracted
	@mkdir -p $(dir $@)
	@cp $< $@

vendor/.extracted: $(VENDOR_ARCHIVE)
	tar xJf $<
	@touch $@

# 更新归档（本机有网时）：cargo vendor vendor && tar cJf vendor.tar.xz vendor

.PHONY: all kernel-rv kernel-la build build-rv build-la \
	build-user-rv build-user-la selftest-rv selftest-la clippy clippy-rv clippy-la fmt \
	run run-rv run-la basic-bin basic-disk run-basic run-basic-rv run-basic-la \
	test-rv test-la test-regress fmt-check test \
	run-case-rv run-case-la clean help

all: kernel-rv kernel-la disk.img disk-la.img

# 先构建用户程序，内核构建时通过环境变量内嵌对应架构的 ELF
kernel-rv: build-user-rv build-rv
	cp $(BIN_RV) kernel-rv

kernel-la: build-user-la build-la
	cp $(BIN_LA) kernel-la

build-user-rv: $(CARGO_HOME)/config.toml vendor/.extracted
	CARGO_TARGET_DIR=target cargo build --manifest-path $(USER_CRATE)/Cargo.toml \
		$(USER_BUILD_STD) --release --target $(TARGET_RV)

build-user-la: $(CARGO_HOME)/config.toml vendor/.extracted
	$(RUSTFLAGS_LA) CARGO_TARGET_DIR=target cargo build --manifest-path $(USER_CRATE)/Cargo.toml \
		$(USER_BUILD_STD) --release --target $(TARGET_LA)

build-rv: $(CARGO_HOME)/config.toml vendor/.extracted
	OUROOS_HELLO_ELF=target/$(TARGET_RV)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_RV)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_RV)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_RV)/$(USER_REL)/ill \
	OUROOS_INIT_ELF=target/$(TARGET_RV)/$(USER_REL)/official_init \
	LOG=$(LOG) cargo build $(BUILD_STD) --release --target $(TARGET_RV) $(KERNEL_FEATURES)

build-la: $(CARGO_HOME)/config.toml vendor/.extracted
	$(RUSTFLAGS_LA) \
	OUROOS_HELLO_ELF=target/$(TARGET_LA)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_LA)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_LA)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_LA)/$(USER_REL)/ill \
	OUROOS_INIT_ELF=target/$(TARGET_LA)/$(USER_REL)/official_init \
	LOG=$(LOG) cargo build $(BUILD_STD) --release --target $(TARGET_LA) $(KERNEL_FEATURES)

# selftest：selftest 档（release 优化 + debug 断言）+ 调试锁，
# 让 OOM 注入/帧守恒/持锁跨切换检测进入验证流程；产物在
# target/<target>/selftest/kernel，不覆盖 release 产物。
#
# UB_CHECKS_OFF：polyhal 启动期（rust_main 之前）存在一处 ptr::add
# 地址计算回绕，debug 断言的 ub-check 会在此 panic（release 静默回绕，
# 预存缺陷，见 docs/ostd-contracts.md 已知缺陷表 #8）。定位修复归入
# polyhal patch 立项；selftest 档定向关闭 ub-check 保留其余断言。
UB_CHECKS_OFF := RUSTFLAGS="-Zunstable-options -Zub-checks=no"
# la 侧需同时保留 LSX/LASX 禁用，单独组合避免两个 RUSTFLAGS 赋值相杀
UB_CHECKS_OFF_LA := RUSTFLAGS="-Zunstable-options -C target-feature=-lsx,-lasx -Zub-checks=no"
selftest-rv: build-user-rv
	$(UB_CHECKS_OFF) \
	OUROOS_HELLO_ELF=target/$(TARGET_RV)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_RV)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_RV)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_RV)/$(USER_REL)/ill \
	LOG=info cargo build $(BUILD_STD) --profile selftest -p kernel --features lock_debug --target $(TARGET_RV) $(KERNEL_FEATURES)

selftest-la: build-user-la
	$(UB_CHECKS_OFF_LA) \
	OUROOS_HELLO_ELF=target/$(TARGET_LA)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_LA)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_LA)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_LA)/$(USER_REL)/ill \
	LOG=info cargo build $(BUILD_STD) --profile selftest -p kernel --features lock_debug --target $(TARGET_LA) $(KERNEL_FEATURES)

# ---------- 静态检查 ----------
clippy-rv: build-user-rv
	OUROOS_HELLO_ELF=target/$(TARGET_RV)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_RV)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_RV)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_RV)/$(USER_REL)/ill \
	OUROOS_INIT_ELF=target/$(TARGET_RV)/$(USER_REL)/official_init \
	LOG=$(LOG) cargo clippy $(BUILD_STD) --release --target $(TARGET_RV) $(KERNEL_FEATURES)

clippy-la: build-user-la
	$(RUSTFLAGS_LA) \
	OUROOS_HELLO_ELF=target/$(TARGET_LA)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_LA)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_LA)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_LA)/$(USER_REL)/ill \
	OUROOS_INIT_ELF=target/$(TARGET_LA)/$(USER_REL)/official_init \
	LOG=$(LOG) cargo clippy $(BUILD_STD) --release --target $(TARGET_LA) $(KERNEL_FEATURES)

clippy: clippy-rv clippy-la

# 覆盖内核 workspace 与独立的用户 crate
fmt:
	cargo fmt -p kernel
	cargo fmt --manifest-path $(USER_CRATE)/Cargo.toml --all

# ---------- 本地运行 ----------
run-rv: kernel-rv
	$(QEMU_RV) -machine virt -kernel kernel-rv -m $(MEM) -nographic -smp $(SMP) \
		-bios default -no-reboot -rtc base=utc

run-la: kernel-la
	$(QEMU_LA) -kernel kernel-la -m $(MEM) -nographic -smp $(SMP) \
		-no-reboot -rtc base=utc

run: run-rv run-la

# ---------- basic 测例运行 ----------
# 官方测例源码不入库，检出路径由 BASIC_SRC 传入（含 basic/user 的仓库根）：
#   make run-basic-rv BASIC_SRC=~/os-contest-ref/testsuits
# 编译测例需要 PATH 中有 riscv64/loongarch64 的 *-linux-gnu-gcc。
BASIC_SRC     ?=
BASIC_DIR     ?= target/test-basic
BASIC_BIN      = $(BASIC_DIR)/bin
BASIC_DISK_RV  = $(BASIC_DIR)/riscv64.img
BASIC_DISK_LA  = $(BASIC_DIR)/loongarch64.img
PYTHON        ?= python3
CASE          ?= open

# 编译官方 basic 测例 ELF（不做增量，每次全量重编）
basic-bin:
	@test -n "$(BASIC_SRC)" || { echo "错误：缺少 BASIC_SRC（官方测例源码路径，含 basic/user）"; exit 1; }
	@for t in riscv64-linux-gnu-gcc loongarch64-linux-gnu-gcc; do \
		command -v $$t >/dev/null || { echo "错误：PATH 中缺少 $$t"; exit 1; }; done
	$(PYTHON) tests/build_basic.py $(BASIC_SRC) $(BASIC_BIN)

# 制作 basic 组 MBR 测试盘（EXT4 主分区 + FAT16 副分区）
basic-disk: basic-bin
	$(PYTHON) tests/build_disk.py $(BASIC_SRC) $(BASIC_BIN) $(BASIC_DIR)

# 整组运行：从盘上 /init 启动，依次跑完官方全部用例（写入落盘，每次跑前重置盘副本）
run-basic-rv: kernel-rv
	@test -f "$(BASIC_DISK_RV)" || $(MAKE) --no-print-directory basic-disk
	cp "$(BASIC_DISK_RV)" "$(BASIC_DIR)/run-rv.img"
	$(QEMU_RV) -machine virt -bios default -kernel kernel-rv -m $(MEM) -nographic -smp $(SMP) \
		-no-reboot -rtc base=utc \
		-drive file=$(BASIC_DIR)/run-rv.img,format=raw,if=none,id=disk \
		-device virtio-blk-device,drive=disk

run-basic-la: kernel-la
	@test -f "$(BASIC_DISK_LA)" || $(MAKE) --no-print-directory basic-disk
	cp "$(BASIC_DISK_LA)" "$(BASIC_DIR)/run-la.img"
	$(QEMU_LA) -kernel kernel-la -m $(MEM) -nographic -smp $(SMP) \
		-no-reboot -rtc base=utc \
		-drive file=$(BASIC_DIR)/run-la.img,format=raw,if=none,id=disk \
		-device virtio-blk-pci,drive=disk

run-basic: run-basic-rv run-basic-la

# ---------- 官方原盘验收 ----------
# make all 后一键验收：原盘放 sdcard/pre-20250615/（git 忽略；从官方 release
# 下载解压），辅助盘由 all 生成并被官方 harness 语义挂载。判分为原版 judge。
#   make test-rv / make test-la
OFFICIAL_OUT ?= target/official
JUDGE_DIR    ?= $(HOME)/os-contest-ref/autotest-for-oskernel/kernel/judge
IMAGES_DIR   ?= sdcard/pre-20250615
OFF_TIMEOUT  ?= 600

# 组范围在 user/hello/src/bin/official_init.rs 里按行注释调整（默认四组全跑）
test-rv: check-qemu kernel-rv
	$(PYTHON) tests/run_official.py rv --images-dir $(IMAGES_DIR) \
		--judge-dir $(JUDGE_DIR) --output $(OFFICIAL_OUT) --timeout $(OFF_TIMEOUT)

test-la: check-qemu kernel-la
	$(PYTHON) tests/run_official.py la --images-dir $(IMAGES_DIR) \
		--judge-dir $(JUDGE_DIR) --output $(OFFICIAL_OUT) --timeout $(OFF_TIMEOUT)

# 评测辅助盘（官方 harness 检测到提交目录的 disk.img/disk-la.img 时自动挂
# 为第二块盘；本内核设备命名让分区盘优先编号，/dev/vda2 即其 FAT32 分区，
# mount 测例由此真实挂载）。同一内容两架构通用。
# 辅助盘模板（tests/official-disk-template.img.xz，64 MiB MBR+FAT32，
# 由 make_official_disk.py 离线生成一次后归档）：评测机无需 mkfs.vfat
disk.img disk-la.img: tests/official-disk-template.img.xz
	xz -dc $< > $@

# ---------- 测试入口（收拢 scripts/tests 调用）----------
# 自建盘回归：历届遗留的 FS 语义门禁（元数据/截断/重命名/定位 IO/FD），
# 验证 JBD2 v3 等存储改动不破坏 classic journal 路径；官方盘不覆盖此语义。
# 依赖 PATH 中的 QEMU 10.0.2（官方评测版本；缺失时 make check-qemu 给出指引）
check-qemu:
	@for q in qemu-system-riscv64 qemu-system-loongarch64; do \
		v=$$($$q --version 2>/dev/null | head -1); \
		case "$$v" in *10.0.2*) ;; *) echo "错误：$$q 须为官方评测版本 10.0.2"\
			"（当前：$${v:-未找到}）。安装后确保在 PATH，或 make QEMU=$$绝对路径 …"; exit 1;; esac; done

test-regress: check-qemu
	$(PYTHON) tests/fs_stat.py

# 官方盘回归的只读构建变体与注入实验保持原入口不变：
#   tests/fs_stat.py --readonly、tests/fs_rename_backend.py、
#   tests/fs_io.py、tests/fs_fcntl.py、tests/mm_validate.py（低频，按需手跑）

# 全量门禁：构建 + 格式检查 + clippy + 官方盘验收 + 自建盘回归
# （fs_stat 内部会重跑 make all；官方盘耗时约 2~3 分钟/架构，回归约 8 分钟）
fmt-check:
	cargo fmt -p kernel -- --check
	cargo fmt --manifest-path $(USER_CRATE)/Cargo.toml --all -- --check

test: check-qemu all fmt-check clippy test-rv test-la test-regress

# 单用例调试：测例 ELF 经 OUROOS_TEST_ELF 内嵌内核直接运行，不走盘上 /init；
# 盘挂 snapshot，运行写入不落盘。内核取 target/ 下的构建产物。
run-case-rv:
	@test -f "$(BASIC_BIN)/riscv64/$(CASE)" || $(MAKE) --no-print-directory basic-bin
	OUROOS_TEST_ELF=$(BASIC_BIN)/riscv64/$(CASE) LOG=$(LOG) \
		cargo build $(BUILD_STD) --release --target $(TARGET_RV) $(KERNEL_FEATURES)
	$(QEMU_RV) -machine virt -bios default -kernel $(BIN_RV) -m $(MEM) -nographic -smp $(SMP) \
		-no-reboot -rtc base=utc \
		-drive file=$(BASIC_DISK_RV),format=raw,if=none,id=disk,snapshot=on \
		-device virtio-blk-device,drive=disk

run-case-la:
	@test -f "$(BASIC_BIN)/loongarch64/$(CASE)" || $(MAKE) --no-print-directory basic-bin
	$(RUSTFLAGS_LA) OUROOS_TEST_ELF=$(BASIC_BIN)/loongarch64/$(CASE) LOG=$(LOG) \
		cargo build $(BUILD_STD) --release --target $(TARGET_LA) $(KERNEL_FEATURES)
	$(QEMU_LA) -kernel $(BIN_LA) -m $(MEM) -nographic -smp $(SMP) \
		-no-reboot -rtc base=utc \
		-drive file=$(BASIC_DISK_LA),format=raw,if=none,id=disk,snapshot=on \
		-device virtio-blk-pci,drive=disk

clean:
	cargo clean
	rm -f kernel-rv kernel-la

help:
	@echo "make all        - 构建内核与内嵌用户程序，产出 kernel-rv 与 kernel-la"
	@echo "make run-rv     - QEMU 启动 riscv64 内核"
	@echo "make run-la     - QEMU 启动 loongarch64 内核"
	@echo "make run        - 两个架构依次启动"
	@echo "make run-basic-rv/la  - 挂盘整组跑官方 basic（需 BASIC_SRC=<官方测例源码路径>）"
	@echo "make test-rv / test-la  - 官方原盘验收（原盘在 sdcard/pre-20250615/，git 忽略）"
	@echo "make test-regress      - 自建盘 FS 语义回归（历届门禁，需 QEMU 10.0.2）"
	@echo "make fmt-check         - 格式检查（不改动文件）"
	@echo "make test              - 全量门禁：all + fmt-check + clippy + 官方盘 + 回归"
	@echo "make run-case-rv/la CASE=<用例名> - 单用例内嵌调试（盘写入不落盘）"
	@echo "make clippy     - 双架构 clippy（含用户程序构建）"
	@echo "make selftest-rv/la - selftest 档构建（debug 断言 + 调试锁 + LOG=info）"
	@echo "make fmt        - 格式化内核与用户程序代码"
	@echo "make clean"
	@echo "变量: MEM=1G SMP=1 LOG=info QEMU_RV=... QEMU_LA=... BASIC_SRC=... CASE=... PYTHON=..."
