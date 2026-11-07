#!/usr/bin/env python3
"""双架构 MM 验证：在临时源码副本添加用户态硬件探针，不修改原仓库/测例。
依赖仓库既有 Rust、QEMU、musl 交叉编译器；先 source ~/.config/ouroos/env.sh。
日志保留在 ~/oscontest/mm-validation-*，任何构建错误、超时或断言缺失均失败。
"""
from pathlib import Path
import os
import argparse
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cases", default="0,1,2,3,4", help="硬件用例编号；2 验证 NX 请求明确拒绝且原映射不变")
options = parser.parse_args()
CASES = sorted(set(int(n) for n in options.cases.split(",")))
if not CASES or any(n not in range(5) for n in CASES):
    parser.error("--cases 必须是 0..4 的非空子集")
QEMU = {"rv": os.environ.get("QEMU_RV", "qemu-system-riscv64"), "la": os.environ.get("QEMU_LA", "qemu-system-loongarch64")}
for arch, executable in QEMU.items():
    version = subprocess.check_output([executable, "--version"], text=True).splitlines()[0]
    if not version.startswith("QEMU emulator version 10.0.2 ") and version != "QEMU emulator version 10.0.2":
        raise RuntimeError(f"队伍验收仅允许 QEMU 10.0.2: {arch}: {version}")
ROOT = Path(__file__).resolve().parents[1]
BASE = Path.home() / "oscontest"
BASE.mkdir(exist_ok=True)
OUT = Path(tempfile.mkdtemp(prefix="mm-validation-", dir=BASE))
TREE = OUT / "source"
TREE.mkdir()
for name in subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).split(b"\0"):
    if name:
        relative = Path(os.fsdecode(name))
        dest = TREE / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, dest)
print(f"Validation evidence: {OUT}", flush=True)

def run(args, label, env=None, timeout=180):
    with (OUT / (label + ".log")).open("w") as log:
        subprocess.run(args, cwd=TREE, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout)

HARDWARE = r'''
//! 只存在于验证副本的实际用户态 MMU/TLB 探针。
use crate::{mm::{address_space::{UserAddressSpace, AreaKind, phys_to_kernel_vaddr}, frame, fence_icache}, trap::{self, UserFaultKind}};
use polyhal::pagetable::MappingFlags as F;
use polyhal_trap::{trap::run_user_task, trapframe::{TrapFrame, TrapFrameArgs}};
use core::sync::atomic::{AtomicBool, Ordering};
static ONCE: AtomicBool = AtomicBool::new(false);
#[cfg(target_arch="riscv64")]
const LOAD: &[u8] = include_bytes!("../../../probe-rv-load.bin");
#[cfg(target_arch="riscv64")]
const STORE: &[u8] = include_bytes!("../../../probe-rv-store.bin");
#[cfg(target_arch="riscv64")]
const JUMP: &[u8] = include_bytes!("../../../probe-rv-jump.bin");
#[cfg(target_arch="riscv64")]
const BREAK: &[u8] = include_bytes!("../../../probe-rv-break.bin");
#[cfg(target_arch="loongarch64")]
const LOAD: &[u8] = include_bytes!("../../../probe-la-load.bin");
#[cfg(target_arch="loongarch64")]
const STORE: &[u8] = include_bytes!("../../../probe-la-store.bin");
#[cfg(target_arch="loongarch64")]
const JUMP: &[u8] = include_bytes!("../../../probe-la-jump.bin");
#[cfg(target_arch="loongarch64")]
const BREAK: &[u8] = include_bytes!("../../../probe-la-break.bin");
fn enter() -> UserFaultKind {
    let mut cx = TrapFrame::new();
    cx[TrapFrameArgs::SEPC] = 0x10000;
    cx[TrapFrameArgs::SP] = 0x80000000;
    loop { run_user_task(&mut cx); if let Some(fault) = trap::take_user_fault() { return fault.kind; } }
}
fn put(space: &UserAddressSpace, va: usize, data: &[u8]) {
    let pa = space.translate(va).unwrap().0;
    // SAFETY: 测试空间持有该页，数据短于一页，尚未进入用户态。
    unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(),phys_to_kernel_vaddr(pa) as *mut u8,data.len()); }
    fence_icache();
}
pub(crate) fn run() {
    if ONCE.swap(true,Ordering::Relaxed) { return; }
    let before = frame::stats();
    for mode in 0..5 {
        let mut space = UserAddressSpace::new().unwrap();
        space.map_region(0x10000,1,F::URWX,AreaKind::Anonymous).unwrap();
        space.map_region(0x30000,1,F::URWX,AreaKind::Anonymous).unwrap();
        put(&space,0x10000,match mode { 0 => STORE, 2 => JUMP, _ => LOAD });
        put(&space,0x30000,BREAK);
        space.protect(0x10000,1,F::URX).unwrap();
        space.activate();
        // 先成功访问，保证后续测试覆盖已有 TLB 翻译的撤销。
        assert!(matches!(enter(),UserFaultKind::Breakpoint));
        match mode {
            0 => space.protect(0x30000,1,F::URX).unwrap(),
            1 => space.protect(0x30000,1,F::U).unwrap(),
            2 => {
                assert_eq!(space.protect(0x30000,1,F::URW), Err(crate::mm::address_space::MapError::UnsupportedPermissions));
                assert!(space.translate(0x30000).unwrap().1.contains(F::X));
            },
            3 => space.unmap(0x30000,1).unwrap(),
            // 可执行但不可读，证明权限检查不是简单的“页存在”。
            _ => space.protect(0x30000,1,F::U|F::X).unwrap(),
        }
        let fault = enter(); polyhal::println!("MM hardware fault {} {:?}",mode,fault);
        assert!(match mode { 0 => matches!(fault,UserFaultKind::StorePageFault), 2 => matches!(fault,UserFaultKind::Breakpoint), _ => matches!(fault,UserFaultKind::LoadPageFault) });
        space.deactivate(); drop(space);
        assert_eq!(frame::stats(),before);
        polyhal::println!("MM hardware case {} passed",mode);
    }
}
'''
(TREE / "kernel/src/mm/hardware_test.rs").write_text(HARDWARE.replace("for mode in 0..5", "for mode in [" + ",".join(map(str, CASES)) + "]"))
with (TREE / "kernel/src/mm/mod.rs").open("a") as f:
    f.write("\npub(crate) mod hardware_test;\n")
p = TREE / "kernel/src/user.rs"
p.write_text(p.read_text().replace("pub fn run_user_elf(name: &str, elf: &[u8]) -> TaskOutcome {", "pub fn run_user_elf(name: &str, elf: &[u8]) -> TaskOutcome {\n    crate::mm::hardware_test::run();"))
for arch, prefix in [("rv", "riscv64-linux-musl-"), ("la", "loongarch64-linux-musl-")]:
    for action in ["load", "store", "jump", "break"]:
        if arch == "rv":
            body = {"load": "li t0,0x30000\nld t1,0(t0)", "store": "li t0,0x30000\nsd zero,0(t0)", "jump": "li t0,0x30000\njr t0", "break": ""}[action] + "\nebreak\n"
            source = ".option norvc\n.option norelax\n.text\n" + body
        else:
            body = {"load": "li.d $t0,0x30000\nld.d $t1,$t0,0", "store": "li.d $t0,0x30000\nst.d $zero,$t0,0", "jump": "li.d $t0,0x30000\njirl $zero,$t0,0", "break": ""}[action] + "\nbreak 0\n"
            source = ".text\n" + body
        stem = f"probe-{arch}-{action}"
        (TREE / (stem + ".S")).write_text(source)
        run([prefix + "gcc", "-c", stem + ".S", "-o", stem + ".o"], stem + "-assemble")
        run([prefix + "objcopy", "-O", "binary", "-j", ".text", stem + ".o", stem + ".bin"], stem + "-binary")
run(["make", "all", "LOG=info"], "build")
for arch, target in [("rv", "riscv64gc-unknown-none-elf"), ("la", "loongarch64-unknown-none")]:
    env = dict(os.environ, LOG="info", OUROOS_HELLO_ELF=f"target/{target}/release/hello", OUROOS_CHECK_ELF=f"target/{target}/release/check")
    if arch == "la": env["RUSTFLAGS"] = "-Zunstable-options -C target-feature=-lsx,-lasx"
    run(["cargo", "rustc", "-p", "kernel", "-Z", "build-std=core,alloc", "--release", "--target", target, "--", "-C", "debug-assertions=yes"], arch + "-guarded-build", env)
    run([os.environ.get("QEMU_RV" if arch == "rv" else "QEMU_LA", "qemu-system-" + ("riscv64" if arch == "rv" else "loongarch64")), "--version"], arch + "-qemu-version")
    for smp, mem in [(1,"512M"),(4,"1G"),(8,"512M")]:
        label = f"{arch}-smp{smp}-{mem}"
        args = [os.environ.get("QEMU_RV" if arch == "rv" else "QEMU_LA", "qemu-system-" + ("riscv64" if arch == "rv" else "loongarch64"))]
        if arch == "rv": args += ["-machine", "virt", "-bios", "default"]
        args += ["-kernel",f"target/{target}/release/kernel","-m",mem,"-smp",str(smp),"-nographic","-no-reboot"]
        run(["timeout", "-k", "5", "30"] + args, label, timeout=40)
        output = (OUT / (label + ".log")).read_text()
        for expected in ["allocation failure rollback passed", "[user] hello: exited with status 0", "check: all syscall paths ok", "[user] check: killed by LoadPageFault"] + [f"MM hardware case {n} passed" for n in CASES]:
            assert expected in output, (label, expected)
        assert "[panic]" not in output and "panicked" not in output and "[ERROR]" not in output, label
        print(label + " PASS", flush=True)
print(f"Selected MM cases {CASES} passed. Unverified cases: {sorted(set(range(5)) - set(CASES))}", flush=True)
