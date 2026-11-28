//! check：系统调用错误路径检查（write/跨页缓冲/EFAULT/EBADF/ENOSYS），
//! 逐项不符立即 exit(1)；全部通过后故意触发非法访存收尾（预期被内核
//! 终止，不会 exit）。

#![no_std]
#![no_main]

use user::{define_user_entry, sys_exit, sys_write, sys_write_raw, syscall3};

const EFAULT: isize = -14;
const EBADF: isize = -9;
const ENOSYS: isize = -38;

const SYS_BOGUS: usize = 9999;

#[cfg(target_arch = "riscv64")]
const KERNEL_ADDR: usize = 0xffff_ffc0_8000_0000;
#[cfg(target_arch = "loongarch64")]
const KERNEL_ADDR: usize = 0x9000_0001_0000_0000;

#[link_section = ".data.cross"]
#[used]
static CROSS: [u8; 2048] = [b'.'; 2048];

fn expect(got: isize, want: isize) {
    if got != want {
        sys_exit(1);
    }
}

#[no_mangle]
extern "C" fn ouro_main() -> ! {
    if user::sys_readahead(usize::MAX, 0, 1) != EBADF {
        sys_exit(1);
    }
    let msg: &[u8] = b"check: write ok\n";

    expect(sys_write(1, msg), msg.len() as isize);

    expect(sys_write(1, &CROSS), CROSS.len() as isize);

    expect(sys_write_raw(1, 0x4000, 8), EFAULT);

    expect(sys_write_raw(1, KERNEL_ADDR, 8), EFAULT);

    expect(sys_write_raw(9, msg.as_ptr() as usize, 8), EBADF);

    expect(syscall3(SYS_BOGUS, 0, 0, 0), ENOSYS);

    mm_checks();
    clock_checks();
    expect(user::sys_mmap(0x5000, 4096, 3, 0x32, usize::MAX, 0), 0x5000);
    expect(user::sys_munmap(0x5000, 4096), 0);
    sys_write(1, b"check: all syscall paths ok, faulting now\n");
    let sink = unsafe { core::ptr::read_volatile(0x5000usize as *const u64) };
    sys_exit(sink as _);
}

fn clock_checks() {
    use user::{sys_clock_getres, sys_clock_gettime, sys_mmap, sys_mprotect, sys_munmap};
    let mut first = [-1, -1];
    let mut next = [-1, -1];
    let mut realtime_res = [0, 0];
    for clock in [0, 1] {
        let mut res = [-1, -1];
        expect(sys_clock_getres(clock, None), 0);
        expect(sys_clock_getres(clock, Some(&mut res)), 0);
        if res[0] < 0 || !(0..1_000_000_000).contains(&res[1]) || res == [0, 0] {
            sys_exit(1);
        }
        if clock == 0 {
            realtime_res = res;
        } else if res != realtime_res {
            sys_exit(1);
        }
        expect(sys_clock_gettime(clock, &mut first), 0);
        expect(sys_clock_gettime(clock, &mut next), 0);
        if first[0] < 0
            || !(0..1_000_000_000).contains(&first[1])
            || !(0..1_000_000_000).contains(&next[1])
            || next < first
        {
            sys_exit(1);
        }
    }
    expect(sys_clock_getres(-1, None), -22);
    expect(sys_clock_getres(-1, Some(&mut next)), -22);
    expect(sys_clock_gettime(-1, &mut next), -22);
    expect(syscall3(113, 0, 0, 0), EFAULT);
    let pages = sys_mmap(0, 8192, 3, 0x22, usize::MAX, 0);
    if pages < 0 {
        sys_exit(1);
    }
    let base = pages as usize;
    expect(syscall3(113, 1, base + 4096 - 8, 0), 0);
    expect(syscall3(114, 1, base + 4096 - 8, 0), 0);
    expect(sys_mprotect(base + 4096, 4096, 1), 0);
    expect(syscall3(113, 1, base + 4096 - 8, 0), EFAULT);
    expect(syscall3(114, 1, base + 4096 - 8, 0), EFAULT);
    expect(sys_munmap(base, 8192), 0);
    sys_write(1, b"check: clock syscall paths ok\n");
}

fn mm_checks() {
    use user::{sys_brk, sys_mmap, sys_mprotect, sys_munmap};
    let base = sys_brk(0);
    expect(sys_brk(base + 4097) as isize, (base + 4097) as isize);
    unsafe {
        (base as *mut u8).write_volatile(42);
    }
    expect(sys_brk(usize::MAX) as isize, (base + 4097) as isize);
    expect(sys_brk(base) as isize, base as isize);
    expect(sys_write_raw(1, base, 1), EFAULT);
    expect(sys_mmap(0, 0, 3, 0x22, usize::MAX, 0), -22);
    expect(sys_mmap(0, 4096, 3, 0x22, usize::MAX, 1), -22);
    let shared = sys_mmap(0, 4096, 3, 0x21, usize::MAX, 0);
    if shared < 0 {
        sys_exit(1);
    }
    expect(sys_mprotect(shared as usize, 4096, 1), 0);
    expect(sys_munmap(shared as usize, 4096), 0);
    let p = sys_mmap(0, 12288, 3, 0x22, usize::MAX, 0);
    if p < 0 {
        sys_exit(11);
    }
    let p = p as usize;
    unsafe {
        (p as *mut u8).write_volatile(17);
        ((p + 4096) as *mut u8).write_volatile(23);
        ((p + 8192) as *mut u8).write_volatile(31);
    }
    expect(
        sys_mmap(p + 4096, 4096, 3, 0x32, usize::MAX, 0),
        (p + 4096) as isize,
    );
    unsafe {
        expect((p as *const u8).read_volatile() as isize, 17);
        expect(((p + 4096) as *const u8).read_volatile() as isize, 0);
        expect(((p + 8192) as *const u8).read_volatile() as isize, 31);
    }
    expect(sys_mprotect(p, 4096, 1), 0);
    expect(sys_mprotect(p, 4096, 3), 0);
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
