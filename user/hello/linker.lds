/*
 * 最小用户程序链接脚本模板（%ARCH% 由 build.rs 填充）。
 *
 * 基址 0x10000（OuroOS 初版用户布局）。不同权限的段按 4K 页分开，
 * 使内核加载器能逐页设置权限且无页级重叠；不包含栈（栈由内核映射）。
 *
 * .data.cross：先垫 3/4 页再放置，使其内容横跨页边界，用于检查
 * 内核对跨页用户缓冲区的处理。
 */
OUTPUT_ARCH(%ARCH%)
ENTRY(_start)

SECTIONS
{
    . = 0x10000;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
        . = ALIGN(4K);
    }

    .rodata : {
        *(.rodata .rodata.*)
        . = ALIGN(4K);
    }

    .data : {
        /* 跨页检查缓冲区：页起点 + 3/4 页，2048 字节内容横跨下一个页边界 */
        . = ALIGN(4K);
        . += 0xC00;
        *(.data.cross)
        . = ALIGN(4K);
        *(.data .data.* .sdata .sdata.*)
        . = ALIGN(4K);
    }

    .bss : {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        . = ALIGN(4K);
    }

    /DISCARD/ : {
        *(.comment)
        *(.gnu*)
        *(.note*)
        *(.eh_frame*)
    }
}
