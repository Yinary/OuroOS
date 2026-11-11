//! check：用户态系统调用错误路径与异常检查程序。
//!
//! 覆盖：
//! 1. write 成功路径与返回字节数校验；
//! 2. 跨页的有效用户缓冲区；
//! 3. 完全未映射的用户地址 → EFAULT；
//! 4. 内核高地址作为用户缓冲区 → EFAULT；
//! 5. 错误 fd → EBADF；
//! 6. 未实现的系统调用 → ENOSYS；
//! 7. 用户态非法访存：预期内核报告异常并终止本次运行，不无限重试、
//!    不把内核 panic 当成功；这是本程序的最后一步，不会 exit。
//!
//! 任一前置检查不符合预期立即 exit(1)；全部通过则输出提示后故意触发
//! 非法访存。

#![no_std]
#![no_main]

use hello::{define_user_entry, sys_exit, sys_write, sys_write_raw, syscall3};

/// Linux errno（负值形式，见 errno-base.h）
const EFAULT: isize = -14;
const EBADF: isize = -9;
const ENOSYS: isize = -38;

/// 任意未被分配的系统调用号（generic ABI 目前最大约 460+）
const SYS_BOGUS: usize = 9999;

/// 内核高位虚拟地址：作为用户缓冲区必须被拒绝（EFAULT）
#[cfg(target_arch = "riscv64")]
const KERNEL_ADDR: usize = 0xffff_ffc0_8000_0000;
#[cfg(target_arch = "loongarch64")]
const KERNEL_ADDR: usize = 0x9000_0001_0000_0000;

/// 跨页缓冲区：链接脚本把它垫在页起点 + 3/4 页处，2048 字节内容横跨
/// 页边界（见 user/hello/linker.lds 的 .data.cross）。
#[link_section = ".data.cross"]
#[used]
static CROSS: [u8; 2048] = [b'.'; 2048];

/// 检查结果不符则立即以 1 退出（内核日志中此前最后一条输出可定位失败项）
fn expect(got: isize, want: isize) {
    if got != want {
        sys_exit(1);
    }
}

/// 用户主函数（由 _start 调用，不返回）
#[no_mangle]
extern "C" fn ouro_main() -> ! {
    let msg: &[u8] = b"check: write ok\n";

    // 1) 正常写 + 返回字节数
    expect(sys_write(1, msg), msg.len() as isize);

    // 2) 跨页有效缓冲区
    expect(sys_write(1, &CROSS), CROSS.len() as isize);

    // 3) 完全未映射的用户地址（0x4000 位于零页与 ELF 基址之间的空洞）
    expect(sys_write_raw(1, 0x4000, 8), EFAULT);

    // 4) 内核高地址不能作为用户缓冲区读取
    expect(sys_write_raw(1, KERNEL_ADDR, 8), EFAULT);

    // 5) 错误 fd
    expect(sys_write_raw(9, msg.as_ptr() as usize, 8), EBADF);

    // 6) 未支持的 syscall
    expect(syscall3(SYS_BOGUS, 0, 0, 0), ENOSYS);

    mm_checks();
    expect(
        hello::sys_mmap(0x5000, 4096, 3, 0x32, usize::MAX, 0),
        0x5000,
    );
    expect(hello::sys_munmap(0x5000, 4096), 0);
    // 前置检查全部通过；随后故意访问未映射地址（0x5000），
    // 预期内核报告用户异常并终止本次运行，控制流不应回到这里
    sys_write(1, b"check: all syscall paths ok, faulting now\n");
    let sink = unsafe { core::ptr::read_volatile(0x5000usize as *const u64) };
    // 不应到达：若内核错误地放行，则以 3 退出暴露问题
    sys_exit(sink as _);
}

/// 覆盖内存 syscall 错误、固定替换和权限；末尾非法访存仍由既有流程检查。
fn mm_checks() {
    use hello::{sys_brk, sys_mmap, sys_mprotect, sys_munmap};
    let base = sys_brk(0);
    expect(sys_brk(base + 4097) as isize, (base + 4097) as isize);
    // SAFETY: brk 已成功扩展两页，字节指针仅在映射有效时使用。
    unsafe {
        (base as *mut u8).write_volatile(42);
    }
    expect(sys_brk(usize::MAX) as isize, (base + 4097) as isize);
    expect(sys_brk(base) as isize, base as isize);
    expect(sys_write_raw(1, base, 1), EFAULT);
    expect(sys_mmap(0, 0, 3, 0x22, usize::MAX, 0), -22);
    expect(sys_mmap(0, 4096, 3, 0x22, usize::MAX, 1), -22);
    expect(sys_mmap(0, 4096, 3, 0x21, usize::MAX, 0), -95);
    let p = sys_mmap(0, 12288, 3, 0x22, usize::MAX, 0);
    if p < 0 {
        sys_exit(11);
    }
    let p = p as usize;
    // SAFETY: 三页匿名映射成功，所有访问限定在该映射中。
    unsafe {
        (p as *mut u8).write_volatile(17);
        ((p + 4096) as *mut u8).write_volatile(23);
        ((p + 8192) as *mut u8).write_volatile(31);
    }
    expect(
        sys_mmap(p + 4096, 4096, 3, 0x32, usize::MAX, 0),
        (p + 4096) as isize,
    );
    // SAFETY: 固定映射替换中间页成功，两侧页面仍属于原映射。
    unsafe {
        expect((p as *const u8).read_volatile() as isize, 17);
        expect(((p + 4096) as *const u8).read_volatile() as isize, 0);
        expect(((p + 8192) as *const u8).read_volatile() as isize, 31);
    }
    expect(sys_mprotect(p, 4096, 3), -95);
    expect(sys_mprotect(p, 4096, 0), 0);
    expect(sys_write_raw(1, p, 1), EFAULT);
    expect(sys_mprotect(p, 4096, 7), 0);
    expect(sys_munmap(p + 1, 4096), -22);
    expect(sys_munmap(p, 0), -22);
    expect(sys_munmap(p, 12288), 0);
    expect(sys_munmap(p, 4096), 0);
    expect(sys_mprotect(p, 4096, 7), -12);
    expect(sys_write_raw(1, p, 1), EFAULT);
    sys_write(1, b"check: mm syscall paths ok\n");
}

define_user_entry!(ouro_main);
