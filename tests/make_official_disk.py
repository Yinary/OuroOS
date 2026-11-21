#!/usr/bin/env python3
"""生成评测辅助盘 disk.img：MBR，分区 2 为 FAT32。

官方评测器（autotest-for-oskernel kernel/run_qemu.py）检测到提交目录中的
disk.img / disk-la.img 时会将其作为第二块磁盘附加。本内核的设备命名约定
（drivers::reorder_partitioned_disks_first）让带分区表的盘优先编号为 vda，
于是 /dev/vda2 即本盘的 FAT32 分区，mount("/dev/vda2","vfat") 为真实挂载。
分区 1 保留为未格式化占位（1 MiB，类型 0x83），不参与任何挂载。
"""
import argparse
import pathlib
import struct
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--size-mib", type=int, default=64)
    args = parser.parse_args()

    total = args.size_mib * 1024 * 1024
    p1_start, p1_count = 2048, 2048          # 1 MiB 占位分区
    p2_start = p1_start + p1_count           # FAT32 到盘尾
    p2_count = total // 512 - p2_start

    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        fat = tmp / "fat.img"
        with fat.open("wb") as f:
            f.truncate(p2_count * 512)
        subprocess.run(["mkfs.vfat", "-F", "32", str(fat)], check=True)

        mbr = bytearray(total)
        # MBR 分区表：分区 1 占位（0x83），分区 2 FAT32 LBA（0x0c）
        for index, (boot, count, ptype) in enumerate(
            [(p1_start, p1_count, 0x83), (p2_start, p2_count, 0x0C)]
        ):
            entry = 446 + index * 16
            mbr[entry + 4] = ptype
            struct.pack_into("<II", mbr, entry + 8, boot, count)
        mbr[510:512] = b"\x55\xaa"
        with fat.open("rb") as src:
            mbr[p2_start * 512 : (p2_start + p2_count) * 512] = src.read()

        args.output.write_bytes(mbr)
    print(f"disk image written: {args.output} ({total // 1024 // 1024} MiB, "
          f"p2 FAT32 at sector {p2_start})")


if __name__ == "__main__":
    main()
