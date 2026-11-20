#!/usr/bin/env python3
"""在宿主端注入元数据时间源错误，检查重命名回滚与落盘一致性。"""
from pathlib import Path
import shutil
import sys
sys.dont_write_bytecode = True
from fs_stat import ROOT, run


def main():
    out = ROOT / "target/fs-validation/rename-fault"
    project = out / "host"
    (project / "src").mkdir(parents=True, exist_ok=True)
    manifest = ('[package]\nname = "rename-fault"\nversion = "0.1.0"\nedition = "2021"\n'
                '[workspace]\n[dependencies]\nrsext4 = { path = "' +
                str(ROOT / "third_party/rsext4") + '" }\n')
    (project / "Cargo.toml").write_text(manifest)
    shutil.copyfile(ROOT / "Cargo.lock", project / "Cargo.lock")
    shutil.copyfile(ROOT / "tests/fs_rename_backend.rs", project / "src/main.rs")
    run(["cargo", "build", "--offline", "--manifest-path", str(project / "Cargo.toml"),
         "--target", "x86_64-unknown-linux-gnu"], out / "build.log")
    original = out / "original.img"
    with original.open("wb") as stream:
        stream.truncate(32 * 1024 * 1024)
    run(["mkfs.ext4", "-q", "-F", "-b", "4096", "-O", "^has_journal", str(original)], out / "mkfs.log")
    payload = out / "payload"
    payload.write_bytes(b"preserve old content")
    script = out / "populate"
    empty = out / "empty"
    empty.write_bytes(b"")
    script.write_text(f'write "{payload}" /a\nwrite "{payload}" /b\n'
                      'mkdir /p\nmkdir /p/moving\nmkdir /q\nmkdir /q/target\nmkdir /full\n' +
                      ''.join(f'write "{empty}" /full/f{i:03d}\n' for i in range(338)))
    run(["debugfs", "-w", "-f", str(script), str(original)], out / "populate.log")
    binary = project / "target/x86_64-unknown-linux-gnu/debug/rename-fault"
    for kind, count in (("file", 3), ("dir", 5), ("missing", 3), ("growth", 4)):
        for fault in range(count):
            stem = f"{kind}-{fault}"
            image = out / f"{stem}.img"
            shutil.copyfile(original, image)
            run(["timeout", "30", str(binary), str(image), str(fault), kind], out / f"{stem}.log")
            run(["e2fsck", "-fn", str(image)], out / f"{stem}-fsck.log")
            print(f"{stem}: PASS (rollback and e2fsck)", flush=True)


if __name__ == "__main__":
    main()
