/*
 * 内核链接脚本模板（%ARCH% / %VIRT_BASE% / %PHYS_BASE% 由 build.rs 填充）。
 *
 * 参考来源：PolyHAL https://github.com/Byte-OS/polyhal example 目录
 * 原协议：MIT
 * 修改说明：按 OuroOS 的地址布局调整了段布局与注释。
 *
 * VMA = 内核运行的高位虚拟地址；LMA(AT) = ELF 的物理加载地址（paddr）。
 * QEMU riscv 按 ELF paddr 加载内核，并把入口掩码到物理地址后交给 OpenSBI 跳转；
 * QEMU loongarch 直启 ELF（addr & 物理位宽掩码），入口同理。
 * 若不设 AT()，paddr = 高位 VMA，riscv 侧会因 DTB 放置计算失败而拒载。
 *
 * 关键约束：跨段边界符号（etext/erodata/...）必须对齐（4K），否则 ld 会对各段
 * 独立做「LMA ≡ VMA (mod addralign)」修正，导致 paddr = vaddr - 偏移 的恒定关系
 * 被破坏（裸机代码无重定位，直接跑飞）。
 *
 * 注意：polyhal 依赖两个顶层自定义段 ph_init / percpu（ld 会为 C 标识符形式的
 * 输出段自动提供 __start_<sec> / __stop_<sec> 边界符号），必须显式放置。
 */
OUTPUT_ARCH(%ARCH%)
ENTRY(_start)

VIRT_BASE = %VIRT_BASE%;
PHYS_BASE = %PHYS_BASE%;

SECTIONS
{
    . = VIRT_BASE;
    _skernel = .;

    .text : AT(PHYS_BASE) {
        stext = .;
        *(.text.entry)
        *(.text .text.*)
        . = ALIGN(4K);
        etext = .;
    }

    .rodata : AT(etext - VIRT_BASE + PHYS_BASE) {
        srodata = .;
        *(.rodata .rodata.*)
        . = ALIGN(4K);
        erodata = .;
    }

    .got : AT(erodata - VIRT_BASE + PHYS_BASE) {
        sgot = .;
        *(.got .got.*)
        . = ALIGN(8);
        egot = .;
    }

    /* polyhal ctor 表（CtorType 系统初始化链） */
    ph_init : AT(egot - VIRT_BASE + PHYS_BASE) {
        sph_init = .;
        KEEP(*(ph_init .ph_init))
        . = ALIGN(8);
        eph_init = .;
    }

    .data : AT(eph_init - VIRT_BASE + PHYS_BASE) {
        _sdata = .;
        . = ALIGN(4K);
        *(.data.boot_page_table)

        *(.data .data.*)
        *(.sdata .sdata.*)
        . = ALIGN(4K);
        _edata = .;
    }

    /* polyhal percpu 变量段 */
    percpu : AT(_edata - VIRT_BASE + PHYS_BASE) {
        spercpu = .;
        *(percpu .percpu)
        . = ALIGN(8);
        epercpu = .;
    }

    . = ALIGN(4K);
    _load_end = .;

    .bss : {
        *(.bss.bstack .bss.bstack.*)
        _sbss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        _ebss = .;
    }

    . = ALIGN(4K);
    PROVIDE(_end = .);

    /DISCARD/ : {
        *(.comment) *(.gnu*) *(.note*) *(.eh_frame*)
    }
}
