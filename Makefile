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
FEATURES ?=         # 附加 cargo feature，例如 make selftest-rv 无需手改

# QEMU：默认取 PATH 中的可执行文件；不在 PATH 时用变量覆盖，例如：
#   make run-la QEMU_LA=/path/to/qemu-system-loongarch64
QEMU_RV ?= qemu-system-riscv64
QEMU_LA ?= qemu-system-loongarch64

.PHONY: all kernel-rv kernel-la build build-rv build-la \
	build-user-rv build-user-la selftest-rv selftest-la clippy clippy-rv clippy-la fmt \
	run run-rv run-la clean help

all: kernel-rv kernel-la

# 先构建用户程序，内核构建时通过环境变量内嵌对应架构的 ELF
kernel-rv: build-user-rv build-rv
	cp $(BIN_RV) kernel-rv

kernel-la: build-user-la build-la
	cp $(BIN_LA) kernel-la

build-user-rv:
	CARGO_TARGET_DIR=target cargo build --manifest-path $(USER_CRATE)/Cargo.toml \
		$(USER_BUILD_STD) --release --target $(TARGET_RV)

build-user-la:
	$(RUSTFLAGS_LA) CARGO_TARGET_DIR=target cargo build --manifest-path $(USER_CRATE)/Cargo.toml \
		$(USER_BUILD_STD) --release --target $(TARGET_LA)

build-rv:
	OUROOS_HELLO_ELF=target/$(TARGET_RV)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_RV)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_RV)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_RV)/$(USER_REL)/ill \
	LOG=$(LOG) cargo build $(BUILD_STD) --release --target $(TARGET_RV)

build-la:
	$(RUSTFLAGS_LA) \
	OUROOS_HELLO_ELF=target/$(TARGET_LA)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_LA)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_LA)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_LA)/$(USER_REL)/ill \
	LOG=$(LOG) cargo build $(BUILD_STD) --release --target $(TARGET_LA)

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
	LOG=info cargo build $(BUILD_STD) --profile selftest -p kernel --features lock_debug --target $(TARGET_RV)

selftest-la: build-user-la
	$(UB_CHECKS_OFF_LA) \
	OUROOS_HELLO_ELF=target/$(TARGET_LA)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_LA)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_LA)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_LA)/$(USER_REL)/ill \
	LOG=info cargo build $(BUILD_STD) --profile selftest -p kernel --features lock_debug --target $(TARGET_LA)

# ---------- 静态检查 ----------
clippy-rv: build-user-rv
	OUROOS_HELLO_ELF=target/$(TARGET_RV)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_RV)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_RV)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_RV)/$(USER_REL)/ill \
	LOG=$(LOG) cargo clippy $(BUILD_STD) --release --target $(TARGET_RV)

clippy-la: build-user-la
	$(RUSTFLAGS_LA) \
	OUROOS_HELLO_ELF=target/$(TARGET_LA)/$(USER_REL)/hello \
	OUROOS_CHECK_ELF=target/$(TARGET_LA)/$(USER_REL)/check \
	OUROOS_SCHED_ELF=target/$(TARGET_LA)/$(USER_REL)/sched \
	OUROOS_ILL_ELF=target/$(TARGET_LA)/$(USER_REL)/ill \
	LOG=$(LOG) cargo clippy $(BUILD_STD) --release --target $(TARGET_LA)

clippy: clippy-rv clippy-la

# 覆盖内核 workspace 与独立的用户 crate
fmt:
	cargo fmt --all
	cargo fmt --manifest-path $(USER_CRATE)/Cargo.toml --all

# ---------- 本地运行 ----------
run-rv: kernel-rv
	$(QEMU_RV) -machine virt -kernel kernel-rv -m $(MEM) -nographic -smp $(SMP) \
		-bios default -no-reboot -rtc base=utc

run-la: kernel-la
	$(QEMU_LA) -kernel kernel-la -m $(MEM) -nographic -smp $(SMP) \
		-no-reboot -rtc base=utc

run: run-rv run-la

clean:
	cargo clean
	rm -f kernel-rv kernel-la

help:
	@echo "make all        - 构建内核与内嵌用户程序，产出 kernel-rv 与 kernel-la"
	@echo "make run-rv     - QEMU 启动 riscv64 内核"
	@echo "make run-la     - QEMU 启动 loongarch64 内核"
	@echo "make run        - 两个架构依次启动"
	@echo "make clippy     - 双架构 clippy（含用户程序构建）"
	@echo "make selftest-rv/la - selftest 档构建（debug 断言 + 调试锁 + LOG=info）"
	@echo "make fmt        - 格式化内核与用户程序代码"
	@echo "make clean"
	@echo "变量: MEM=1G SMP=1 LOG=info QEMU_RV=... QEMU_LA=..."
