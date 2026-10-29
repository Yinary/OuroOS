# ============================================================
# OuroOS 顶层 Makefile
#
# `make all` 产出仓库根目录下的两个内核 ELF：
#   kernel-rv — riscv64 内核
#   kernel-la — loongarch64 内核
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

# loongarch64 的发行版预编译 libcore 含 LSX 向量指令（基线仅 +f,+d），运行时会触发
# Disable 异常；且 polyhal-boot 只开 FPE。用 build-std 从源码自编 core/alloc，
# 并禁用 LSX/LASX 代码生成（两架构统一走 build-std）。
BUILD_STD     := -Z build-std=core,alloc
RUSTFLAGS_LA := RUSTFLAGS="-Zunstable-options -C target-feature=-lsx,-lasx"

# ---------- 运行参数 ----------
# 注意：loongarch virt 的 0x80000000 物理地址仅在内存 > 256M 时存在（lowmem [0,256M) +
# highmem [0x80000000,...)），因此 la 侧内存必须 > 256M，这里统一默认 1G。
MEM ?= 1G
SMP ?= 4
LOG ?= warn         # 编译期日志级别: error|warn|info|debug|trace（boot 报告块由 polyhal 固定打印，不受此控）

# 本地 QEMU：优先使用 10.x，否则回退 PATH
QEMU_PREFIX ?= $(shell [ -x "$(HOME)/oscontest/qemu-10.0.2/bin/qemu-system-riscv64" ] \
                    && echo "$(HOME)/oscontest/qemu-10.0.2/bin/")
QEMU_RV ?= $(QEMU_PREFIX)qemu-system-riscv64
QEMU_LA ?= $(QEMU_PREFIX)qemu-system-loongarch64

.PHONY: all kernel-rv kernel-la build build-rv build-la run run-rv run-la clean help

all: kernel-rv kernel-la

kernel-rv: build-rv
	cp $(BIN_RV) kernel-rv

kernel-la: build-la
	cp $(BIN_LA) kernel-la

build-rv:
	LOG=$(LOG) cargo build $(BUILD_STD) --release --target $(TARGET_RV)

build-la:
	$(RUSTFLAGS_LA) LOG=$(LOG) cargo build $(BUILD_STD) --release --target $(TARGET_LA)

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
	@echo "make all        - 构建 kernel-rv 与 kernel-la"
	@echo "make run-rv     - QEMU 启动 riscv64 内核"
	@echo "make run-la     - QEMU 启动 loongarch64 内核"
	@echo "make run        - 两个架构依次启动"
	@echo "make clean"
	@echo "变量: MEM=1G SMP=4 LOG=info QEMU_RV=... QEMU_LA=..."
