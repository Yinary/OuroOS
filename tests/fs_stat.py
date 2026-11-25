#!/usr/bin/env python3
"""构造已知属性与容量的磁盘，双架构验证查询接口；产物只写入 target。"""
import argparse
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(args, log, **kwargs):
    with log.open("wb") as stream:
        subprocess.run(args, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                       check=True, timeout=240, **kwargs)


def verify_metadata(image, out, stem, small, readonly):
    log = out / f"{stem}-persisted-times.log"
    run(["debugfs", "-R", "stat /meta/data", str(image)], log)
    text = log.read_text()
    expected = ((-2147483647 if small else 2147483649, 2147483646)
                if readonly else (1700000001, -10))
    for field, seconds, nanos in zip(("atime", "mtime"), expected, (123456789, 987654321)):
        match = re.search(rf"{field}:\s+0x([0-9a-f]+)(?::([0-9a-f]+))?", text)
        if not match:
            raise RuntimeError(f"缺少落盘时间 {field}: {text}")
        base = int(match[1], 16)
        extra = int(match[2] or "0", 16)
        actual = (base if base < 1 << 31 else base - (1 << 32)) + ((extra & 3) << 32)
        if actual != seconds or extra >> 2 != (0 if small else nanos):
            raise RuntimeError(f"落盘时间不符 {field}: {actual}, {extra >> 2}")
    if not readonly:
        for name, mode in (("mask-file", 0o600), ("mask-dir", 0o700),
                           ("mask-other", 0o640), ("mask-child", 0o700)):
            log = out / f"{stem}-{name}-mode.log"
            run(["debugfs", "-R", f"stat /{name}", str(image)], log)
            match = re.search(r"Mode:\s+([0-7]+)", log.read_text())
            if not match or int(match[1], 8) != mode:
                raise RuntimeError(f"落盘权限不符: {name}")


def verify_truncate(image, out, stem, readonly):
    expected = {"/meta/data": b"testing"} if readonly else {
        "/meta/data": b"", "/prealloc": b"", "/prealloc-zero": b"",
        "/fragmented": b"", "/reused": b"", "/after-free": bytes([0x33]) * 4096,
        "/mapped": bytes(100) + bytes([0x7f]) + bytes(8192 - 101),
    }
    for number, (path, content) in enumerate(expected.items()):
        dumped = out / f"{stem}-truncate-{number}.bin"
        dumped.unlink(missing_ok=True)
        log = out / f"{stem}-truncate-{number}.log"
        run(["debugfs", "-R", f'dump {path} "{dumped}"', str(image)], log)
        if not dumped.exists() or dumped.read_bytes() != content:
            raise RuntimeError(f"截断落盘内容不符: {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "target/fs-validation/stat")
    parser.add_argument("--metadata", action="store_true", help="验证 umask 和 utimensat")
    parser.add_argument("--rename", action="store_true", help="验证 renameat 和 renameat2")
    parser.add_argument("--devzero", action="store_true", help="验证 /dev/zero 设备读写")
    parser.add_argument("--rmdir", action="store_true", help="验证空目录删除及引用释放")
    parser.add_argument("--chown", action="store_true", help="验证 fchown 与 fchownat")
    parser.add_argument("--truncate", action="store_true", help="验证 truncate 和 ftruncate")
    parser.add_argument("--readonly", action="store_true", help="metadata 专项要求只读内核")
    args = parser.parse_args()
    if sum((args.metadata, args.rename, args.truncate, args.chown, args.rmdir, args.devzero)) > 1:
        parser.error("一次只能选择一组专项")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    user = out / "user"
    shutil.copytree(ROOT / "user", user, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("target"))
    program = ("fs_truncate.rs" if args.truncate else "fs_rename.rs" if args.rename
               else "fs_metadata.rs" if args.metadata else "fs_chown.rs" if args.chown
               else "fs_rmdir.rs" if args.rmdir else "fs_devzero.rs" if args.devzero
               else "fs_stat.rs")
    shutil.copyfile(ROOT / "tests" / program, user / "src/bin/smoke.rs")
    if args.metadata:
        shutil.copyfile(ROOT / "tests/fs_metadata_exec.rs", user / "src/bin/check.rs")
    payload = out / "payload"
    payload.write_bytes(b"testing")
    empty = out / "empty"
    empty.write_bytes(b"")
    expected_capacity = out / "expected-capacity"
    expected_capacity.write_bytes(bytes([0xa5]) * 152)
    for arch, short, target, flags, machine, device in [
        ("riscv64", "rv", "riscv64gc-unknown-none-elf", "",
         ["-machine", "virt", "-bios", "default"], "virtio-blk-device"),
        ("loongarch64", "la", "loongarch64-unknown-none",
         "-Zunstable-options -C target-feature=-lsx,-lasx", [], "virtio-blk-pci"),
    ]:
        env = dict(os.environ, RUSTFLAGS=flags, CARGO_TARGET_DIR=str(out / "user-target"))
        run(["timeout", "180", "cargo", "build", "--manifest-path", str(user / "Cargo.toml"),
             "-Z", "build-std=core", "--release", "--target", target, *(["--bins"] if args.metadata else ["--bin", "smoke"])],
            out / f"{short}-user-build.log", env=env)
        for inode_size in (256, 128):
            stem = f"{short}-{inode_size}"
            ext = out / f"{stem}-ext4.img"
            with ext.open("wb") as stream:
                stream.truncate(32 * 1024 * 1024)
            run(["mkfs.ext4", "-q", "-F", "-b", "4096", "-I", str(inode_size), str(ext)],
                out / f"{stem}-mkfs.log")
            commands = ["mkdir /meta", "mkdir /meta/sub", "mkdir /mnt",
                        "cd /meta", "mknod char c 1 3", "cd /",
                        f'write "{out / "user-target" / target / "release/smoke"}" /init',
                        f'write "{payload}" /meta/data', f'write "{empty}" /meta/large',
                        f'write "{expected_capacity}" /fs-expected',
                        "set_inode_field /meta/large size 4294967303",
                        "set_inode_field /meta/data mode 0100640",
                        "set_inode_field /meta/data uid 4464",
                        "set_inode_field /meta/data uid_hi 1",
                        "set_inode_field /meta/data gid 8928",
                        "set_inode_field /meta/data gid_hi 2",
                        "set_inode_field /meta/data atime 0x80000001",
                        "set_inode_field /meta/data mtime 0x7ffffffe",
                        "set_inode_field /meta/data ctime 0xffffffff"]
            if inode_size == 256:
                commands += [f"set_inode_field /meta/data atime_extra {(123456789 << 2) | 1}",
                             f"set_inode_field /meta/data mtime_extra {987654321 << 2}",
                             f"set_inode_field /meta/data ctime_extra {(999999999 << 2) | 1}",
                             "set_inode_field /meta/data crtime 1700000000",
                             "set_inode_field /meta/data crtime_extra 168"]
            else:
                commands += [f'write "{empty}" /small-inode']
            targets = {"abs": "/meta/data", "rel": "data", "chain": "rel",
                       "dirlink": "/meta", "dangling": "missing", "loop": "loop",
                       "sub/up": "../data", "sixty": "/" * 50 + "/meta/data",
                       "long": "/" * 90 + "/meta/data"}
            commands += [f"symlink /meta/{name} {dest}" for name, dest in targets.items()]
            if args.metadata:
                commands.append(f'write "{out / "user-target" / target / "release/check"}" /mask-exec')
            if args.rename:
                commands += [f'write "{payload}" /hard-a', "link /hard-a /hard-b",
                             "set_inode_field /hard-a links_count 2", "mkdir /full"]
                commands += [f'write "{empty}" /full/f{i:03d}' for i in range(338)]
            if args.truncate:
                commands += [f'write "{empty}" /prealloc', "fallocate /prealloc 0 31",
                             "set_inode_field /prealloc size 65536",
                             f'write "{empty}" /prealloc-zero', "fallocate /prealloc-zero 0 7",
                             f'write "{empty}" /fragmented']
                commands += [f"fallocate /fragmented {i} {i}" for i in (0, 3, 9, 16, 25, 40, 60, 90)]
                commands += ["set_inode_field /fragmented size 372736"]
            script = out / f"{stem}-populate"
            script.write_text("\n".join(commands) + "\n")
            run(["debugfs", "-w", "-f", str(script), str(ext)], out / f"{stem}-populate.log")
            # 预分配后写入快照，避免保存期望值本身改变空闲计数。
            run(["debugfs", "-R", "bmap /fs-expected 0", str(ext)], out / f"{stem}-expected-block.log")
            block = int((out / f"{stem}-expected-block.log").read_text().splitlines()[-1])
            if block <= 0 or (block + 1) * 4096 > ext.stat().st_size:
                raise RuntimeError("容量快照文件没有分配有效数据块")
            with ext.open("r+b") as stream:
                stream.seek(1024)
                sb = stream.read(1024)
                word = lambda offset: struct.unpack_from("<I", sb, offset)[0]
                blocks = word(4) | word(336) << 32
                free = word(12) | word(344) << 32
                reserved = word(8) | word(340) << 32
                overhead = word(584) << (word(28) - word(24))
                expected = struct.pack("<15Q", 0xef53, 1024 << word(24), blocks - overhead,
                                       free, max(0, free - reserved), word(0), word(16),
                                       int.from_bytes(sb[104:112], "little"), 255,
                                       1024 << word(24), 0x20, 0, 0, 0, 0)
                stream.seek(block * 4096)
                stream.write(expected)
            run(["debugfs", "-R", "stat /meta/data", str(ext)], out / f"{stem}-expected.log")
            run(["e2fsck", "-fn", str(ext)], out / f"{stem}-before-fsck.log")
            image = ext
            start = 0
            if inode_size == 256:
                fat = out / f"{stem}-fat.img"
                with fat.open("wb") as stream:
                    stream.truncate(16 * 1024 * 1024)
                run(["mkfs.fat", "-F", "16", str(fat)], out / f"{stem}-fat-mkfs.log")
                with fat.open("rb") as stream:
                    boot = stream.read(512)
                    short_word = lambda offset: struct.unpack_from("<H", boot, offset)[0]
                    sector_size = short_word(11)
                    cluster_size = sector_size * boot[13]
                    sectors = short_word(19) or struct.unpack_from("<I", boot, 32)[0]
                    root_sectors = (short_word(17) * 32 + sector_size - 1) // sector_size
                    clusters = (sectors - short_word(14) - boot[16] * short_word(22) - root_sectors) // boot[13]
                    stream.seek(short_word(14) * sector_size)
                    table = stream.read(short_word(22) * sector_size)
                    free_clusters = sum(struct.unpack_from("<H", table, i * 2)[0] == 0 for i in range(2, clusters + 2))
                    fat_expected = struct.pack("<4Q", cluster_size, clusters, free_clusters,
                                               struct.unpack_from("<I", boot, 39)[0])
                with ext.open("r+b") as stream:
                    stream.seek(block * 4096 + 120)
                    stream.write(fat_expected)
                start = 2048
                count = ext.stat().st_size // 512
                second = start + count
                fat_count = fat.stat().st_size // 512
                mbr = bytearray(512)
                for n, kind, offset, length in [(0, 0x83, start, count), (1, 6, second, fat_count)]:
                    struct.pack_into("<BBBBBBBBII", mbr, 446 + n * 16,
                                     0, 0, 0, 0, kind, 0, 0, 0, offset, length)
                mbr[510:] = b"\x55\xaa"
                image = out / f"{stem}.img"
                with image.open("wb") as stream:
                    stream.truncate((second + fat_count) * 512)
                    stream.seek(0)
                    stream.write(mbr)
                    for part, offset in [(ext, start), (fat, second)]:
                        stream.seek(offset * 512)
                        with part.open("rb") as source:
                            shutil.copyfileobj(source, stream)
            run(["timeout", "-k", "5", "90", f"qemu-system-{arch}", *machine,
                 "-kernel", str(ROOT / f"kernel-{short}"), "-m", "1G", "-smp", "1",
                 "-nographic", "-no-reboot", "-drive", f"file={image},format=raw,if=none,id=disk",
                 "-device", f"{device},drive=disk"], out / f"{stem}.log")
            text = (out / f"{stem}.log").read_text(errors="replace")
            markers = (("TRUNCATE PASS:",) if args.truncate else
                       ("CHOWN PASS:",) if args.chown else
                       ("RMDIR PASS:",) if args.rmdir else
                       ("DEVZERO PASS:",) if args.devzero else
                       ("RENAME PASS:",) if args.rename else
                       ("METADATA PASS:", "MASK EXEC PASS") if args.metadata else
                       ("STAT PASS:", "READLINK PASS:", "STATFS PASS:"))
            if (not all(marker in text for marker in markers)
                    or "basic-init): exited with status 0" not in text):
                raise RuntimeError(f"{stem} failed: {text[-1600:]}")
            if args.rmdir and args.readonly != ("RMDIR READONLY" in text):
                raise RuntimeError(f"{stem}: 内核只读配置与测试要求不符")
            if args.chown and args.readonly != ("CHOWN READONLY" in text):
                raise RuntimeError(f"{stem}: 内核只读配置与测试要求不符")
            if args.metadata and args.readonly != ("METADATA READONLY" in text):
                raise RuntimeError(f"{stem}: 内核只读配置与测试要求不符")
            if args.rename and args.readonly != ("RENAME READONLY" in text):
                raise RuntimeError(f"{stem}: 内核只读配置与测试要求不符")
            if args.truncate and args.readonly != ("TRUNCATE READONLY" in text):
                raise RuntimeError(f"{stem}: 内核只读配置与测试要求不符")
            if start:
                with image.open("rb") as stream:
                    stream.seek(start * 512)
                    ext.write_bytes(stream.read(count * 512))
                    stream.seek(second * 512)
                    fat.write_bytes(stream.read(fat_count * 512))
                run(["fsck.fat", "-n", str(fat)], out / f"{stem}-after-fat-fsck.log")
            if args.metadata:
                verify_metadata(ext, out, stem, inode_size == 128, args.readonly)
            if args.truncate:
                verify_truncate(ext, out, stem, args.readonly)
            if args.chown:
                expected = (70000, 140000) if args.readonly else (70001, 1000)
                log = out / f"{stem}-owner.log"
                run(["debugfs", "-R", "stat /meta/data", str(ext)], log)
                match = re.search(r"User:\s+(\d+)\s+Group:\s+(\d+)", log.read_text())
                if not match or tuple(map(int, match.groups())) != expected:
                    raise RuntimeError(f"{stem}: 落盘属主或属组不符")
            if args.rmdir and not args.readonly:
                inode = re.search(r"RMDIR FREED INODE: (\d+)", text)
                if inode is None:
                    raise RuntimeError(f"{stem}: 缺少待核对的目录 inode")
                log = out / f"{stem}-reclaim.log"
                run(["debugfs", "-R", f"testi <{inode[1]}>", str(ext)], log)
                if "is not in use" not in log.read_text():
                    raise RuntimeError(f"{stem}: 最后一个目录引用释放后 inode 仍已分配")
            run(["e2fsck", "-fn", str(ext)], out / f"{stem}-after-fsck.log")
            suite = ("truncate" if args.truncate else "rename" if args.rename
                     else "metadata" if args.metadata else "chown" if args.chown
                     else "rmdir" if args.rmdir else "devzero" if args.devzero
                     else "status queries")
            print(f"{stem}: PASS ({suite} and e2fsck)", flush=True)


if __name__ == "__main__":
    main()
