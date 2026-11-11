//! 最小用户程序共享库：系统调用封装、用户入口与 panic 处理。
//!
//! 程序以静态 ELF 从 0x10000 加载，不用 libc；系统调用遵循
//! riscv64 / loongarch64 通用 UAPI：a7=调用号、a0..a5=参数、a0=返回。

#![no_std]

use core::panic::PanicInfo;

// 系统调用桩（riscv64）：C 调用约定入参 a0=nr, a1..a3=参数，
// 重排到 UAPI 约定（a7=nr, a0..a2=参数）后 ecall。
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".globl __syscall3",
    "__syscall3:",
    "   mv a7, a0",
    "   mv a0, a1",
    "   mv a1, a2",
    "   mv a2, a3",
    "   ecall",
    "   ret",
);

// 系统调用桩（loongarch64）：$a7=nr, $a0..$a2=参数。
#[cfg(target_arch = "loongarch64")]
core::arch::global_asm!(
    ".globl __syscall3",
    "__syscall3:",
    "   move $a7, $a0",
    "   move $a0, $a1",
    "   move $a1, $a2",
    "   move $a2, $a3",
    "   syscall 0",
    "   jirl $zero, $ra, 0",
);

extern "C" {
    fn __syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> isize;
}

/// 通用系统调用（最多 3 个参数），返回值为正数结果或负 errno
pub fn syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> isize {
    // SAFETY: 纯汇编桩，不涉及内存安全；参数与返回按值传递
    unsafe { __syscall3(nr, a0, a1, a2) }
}

// 六参数桩保留 syscall3，mmap 直接使用完整通用 ABI。
#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    ".globl __syscall6",
    "__syscall6:",
    "mv a7, a0",
    "mv a0, a1",
    "mv a1, a2",
    "mv a2, a3",
    "mv a3, a4",
    "mv a4, a5",
    "mv a5, a6",
    "ecall",
    "ret"
);
#[cfg(target_arch = "loongarch64")]
core::arch::global_asm!(
    ".globl __syscall6",
    "__syscall6:",
    "move $a7, $a0",
    "move $a0, $a1",
    "move $a1, $a2",
    "move $a2, $a3",
    "move $a3, $a4",
    "move $a4, $a5",
    "move $a5, $a6",
    "syscall 0",
    "jirl $zero, $ra, 0"
);
extern "C" {
    fn __syscall6(
        nr: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        a4: usize,
        a5: usize,
    ) -> isize;
}
/// 六参数系统调用；不创建用户指针引用，原样返回 ABI 结果。
pub fn syscall6(nr: usize, args: [usize; 6]) -> isize {
    // SAFETY: 汇编桩依照 C ABI 按值搬运参数，并保留被调用者保存寄存器。
    unsafe { __syscall6(nr, args[0], args[1], args[2], args[3], args[4], args[5]) }
}
/// 原始 brk ABI，失败时返回旧地址；传零查询。
pub fn sys_brk(addr: usize) -> usize {
    syscall3(214, addr, 0, 0) as usize
}
/// mmap 的原始六参数包装，成功返回地址，失败返回负 errno。
pub fn sys_mmap(
    addr: usize,
    len: usize,
    prot: usize,
    flags: usize,
    fd: usize,
    offset: usize,
) -> isize {
    syscall6(222, [addr, len, prot, flags, fd, offset])
}
/// 解除映射，返回零或负 errno。
pub fn sys_munmap(addr: usize, len: usize) -> isize {
    syscall3(215, addr, len, 0)
}
/// 修改权限；本内核不支持 NX。
pub fn sys_mprotect(addr: usize, len: usize, prot: usize) -> isize {
    syscall3(226, addr, len, prot)
}

/// write(2)：把缓冲区写到 fd（内核当前只支持 1/2）
pub fn sys_write(fd: usize, buf: &[u8]) -> isize {
    syscall3(64, fd, buf.as_ptr() as usize, buf.len())
}

/// write(2) 的裸指针形式：用于传入非映射地址做错误路径检查
pub fn sys_write_raw(fd: usize, buf: usize, len: usize) -> isize {
    syscall3(64, fd, buf, len)
}

/// exit(2)：结束本用户任务。正常情况下不会返回。
pub fn sys_exit(status: isize) -> ! {
    syscall3(93, status as usize, 0, 0);
    // 若内核实现有误导致返回，原地自旋而不是继续执行用户代码
    loop {
        core::hint::spin_loop();
    }
}

/// sched_yield(2)：让出 CPU。内核单核轮转，返回 0（成功）。
pub fn sys_sched_yield() -> isize {
    syscall3(124, 0, 0, 0)
}

/// getpid(2)：返回调用者 pid。
pub fn sys_getpid() -> isize {
    syscall3(172, 0, 0, 0)
}

/// panic 时以 134 退出（128+SIGABRT，shell 惯例），与正常退出码区分
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    sys_exit(134)
}

/// 定义用户入口 `_start`：内核设置好用户栈 sp 后跳转到这里。
/// 入口只负责调用 `$main`（不返回）；栈由内核提供，无需自建。
#[macro_export]
macro_rules! define_user_entry {
    ($main:path) => {
        #[cfg(target_arch = "riscv64")]
        core::arch::global_asm!(
            ".section .text.start, \"ax\"",
            ".globl _start",
            "_start:",
            "   call {main}",
            "   j .",
            ".previous",
            main = sym $main,
        );
        #[cfg(target_arch = "loongarch64")]
        core::arch::global_asm!(
            ".section .text.start, \"ax\"",
            ".globl _start",
            "_start:",
            "   bl {main}",
            "   b .",
            ".previous",
            main = sym $main,
        );
    };
}
