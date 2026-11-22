#!/usr/bin/env python3
"""双架构基础 fcntl 回归；在 target 创建独立 Ext4 镜像。"""
import argparse
import os
from pathlib import Path
import shutil
import sys
sys.dont_write_bytecode = True
from fs_stat import run

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--readonly", action="store_true")
    args = parser.parse_args()
    out = ROOT / "target/fs-validation" / ("fcntl-readonly" if args.readonly else "fcntl")
    out.mkdir(parents=True, exist_ok=True)
    user = out / "user"
    shutil.copytree(ROOT / "user", user, dirs_exist_ok=True, ignore=shutil.ignore_patterns("target"))
    shutil.copyfile(ROOT / "tests/fs_fcntl.rs", user / "src/bin/smoke.rs")
    shutil.copyfile(ROOT / "tests/fs_fcntl_exec.rs", user / "src/bin/check.rs")
    payload = out / "payload"
    payload.write_bytes(b"abcdefgh")
    for arch, short, target, flags, machine, device in [
        ("riscv64", "rv", "riscv64gc-unknown-none-elf", "", ["-machine", "virt", "-bios", "default"], "virtio-blk-device"),
        ("loongarch64", "la", "loongarch64-unknown-none", "-Zunstable-options -C target-feature=-lsx,-lasx", [], "virtio-blk-pci"),
    ]:
        env = dict(os.environ, RUSTFLAGS=flags, CARGO_TARGET_DIR=str(out / "user-target"))
        run(["timeout", "180", "cargo", "build", "--manifest-path", str(user / "Cargo.toml"),
             "-Z", "build-std=core", "--release", "--target", target, "--bins"], out / f"{short}-user.log", env=env)
        image = out / f"{short}.img"
        with image.open("wb") as stream:
            stream.truncate(32 * 1024 * 1024)
        run(["mkfs.ext4", "-q", "-F", "-b", "4096", str(image)], out / f"{short}-mkfs.log")
        commands = [f'write "{out / "user-target" / target / "release/smoke"}" /init', f'write "{payload}" /io-data']
        commands.append(f'write "{out / "user-target" / target / "release/check"}" /after-exec')
        if args.readonly:
            commands.append(f'write "{payload}" /readonly')
        script = out / f"{short}-populate"
        script.write_text("\n".join(commands) + "\n")
        run(["debugfs", "-w", "-f", str(script), str(image)], out / f"{short}-populate.log")
        run(["timeout", "-k", "5", "90", f"qemu-system-{arch}", *machine, "-kernel", str(ROOT / f"kernel-{short}"),
             "-m", "1G", "-smp", "1", "-nographic", "-no-reboot", "-drive", f"file={image},format=raw,if=none,id=disk",
             "-device", f"{device},drive=disk"], out / f"{short}.log")
        text = (out / f"{short}.log").read_text(errors="replace")
        if "FCNTL PASS:" not in text or "FCNTL EXEC PASS" not in text or "basic-init): exited with status 0" not in text:
            raise RuntimeError(f"{short}: {text[-1800:]}")
        run(["e2fsck", "-fn", str(image)], out / f"{short}-fsck.log")
        print(f"{short}: FCNTL and e2fsck PASS", flush=True)


if __name__ == "__main__":
    main()
