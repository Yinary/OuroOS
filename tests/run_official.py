#!/usr/bin/env python3
"""官方原盘正式验收：按官方评测器同款 QEMU 命令运行原盘镜像，串口交由
原版 judge 脚本判分。

判分协议与 autotest-for-oskernel kernel/run.py::parse_serial_out_new 一致：
串口按 `#### OS COMP TEST GROUP START <组> ####` / `#### ... END ...` 分段，
组内行写入 judge_<组>.py 的 stdin，judge 输出 JSON 分数；从未启动的组同样
以空输入调用 judge 计 0 分。本脚本不改动任何评分逻辑，只补充完整性诊断
（超时、缺组、重复组、截断、judge 失败）。

原盘只读保存：每次运行把镜像复制成干净副本再交给 QEMU，写入不回原文件。
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

GROUP_START = re.compile(r"#### OS COMP TEST GROUP START ([a-zA-Z0-9-]+) ####")
GROUP_END = re.compile(r"#### OS COMP TEST GROUP END ([a-zA-Z0-9-]+) ####")
# 官方评测使用 QEMU 10.0.2（LoongArch 带 2025-07 补丁），LA 侧 TLB 行为依赖该版本
QEMU_VERSION = re.compile(r"version 10\.0\.2\b")
# 本轮验收的四个目标组
TARGET_GROUPS = ("basic-musl", "basic-glibc", "busybox-musl", "busybox-glibc")
# 原盘目录约定：仓库内 sdcard/pre-20250615/（git 忽略），文件名对照官方
# testsuits-for-oskernel pre-20250615 发布页
IMAGES_DIR_DEFAULT = pathlib.Path("sdcard") / "pre-20250615"


def qemu_binary(arch, override):
    """按架构取 QEMU：PATH 查找 + 官方版本校验（10.0.2，见团队环境约定）。"""
    name = f"qemu-system-{'riscv64' if arch == 'rv' else 'loongarch64'}"
    qemu = override or shutil.which(name)
    if qemu is None:
        sys.exit(f"错误：PATH 中没有 {name}。官方评测要求 QEMU 10.0.2"
                 f"（可用 --qemu 指定绝对路径）")
    version = subprocess.run([str(qemu), "--version"], capture_output=True, text=True)
    if version.returncode != 0 or not QEMU_VERSION.search(version.stdout):
        sys.exit(f"错误：{qemu} 不是 QEMU 10.0.2（官方评测版本，"
                 f"实际输出：{version.stdout.strip().splitlines()[:1]}）")
    return str(qemu)


def qemu_command(qemu, arch, kernel, disk, extra_disk=None):
    """官方 run_qemu.py 的正式启动命令（含网络设备，保持设备拓扑一致）。

    extra_disk 模拟官方对提交目录 disk.img/disk-la.img 的附加行为：第二块
    盘按官方第二盘参数挂载（RV 用 mmio bus.1，LA 追加一个 virtio-blk-pci）。
    """
    cmd = [qemu, "-kernel", kernel, "-m", "1G", "-nographic",
           "-smp", "1", "-no-reboot", "-rtc", "base=utc",
           "-drive", f"file={disk},if=none,format=raw,id=x0"]
    if arch == "rv":
        cmd = [qemu, "-machine", "virt", "-kernel", kernel, "-m", "1G",
               "-nographic", "-smp", "1", "-bios", "default",
               "-drive", f"file={disk},if=none,format=raw,id=x0",
               "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
               "-no-reboot", "-device", "virtio-net-device,netdev=net",
               "-netdev", "user,id=net", "-rtc", "base=utc"]
        if extra_disk:
            cmd += ["-drive", f"file={extra_disk},if=none,format=raw,id=x1",
                    "-device", "virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1"]
        return cmd
    cmd += ["-device", "virtio-blk-pci,drive=x0",
            "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    if extra_disk:
        cmd += ["-drive", f"file={extra_disk},if=none,format=raw,id=x1",
                "-device", "virtio-blk-pci,drive=x1"]
    return cmd


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def judge_groups(judge_dir):
    """judge_<组>.py 清单，命名规则与 run.py::_get_name/_get_exec 相同。"""
    return {path.name[len("judge_"):-len(path.suffix)]: [sys.executable, str(path)]
            for path in judge_dir.glob("judge_*")
            if path.suffix == ".py" and path.name != "judge_config.py"}


def collect_group(judge, group):
    """收尾一个 judge 子进程：关 stdin、读 JSON、等待退出并核对退出码。
    非 JSON 输出或非零退出码都抛异常（由调用方记入 judge_errors 并判失败）。"""
    judge.stdin.close()
    raw = judge.stdout.read().decode()
    result = json.loads(raw)  # 非 JSON 直接抛
    judge.wait(5)
    if judge.returncode != 0:
        raise RuntimeError(f"judge exited {judge.returncode}")
    return result


def score_serial(judge_dir, serial_path):
    """按官方协议判分串口日志，返回 (每组分数表, 诊断信息)。

    组状态机：START 开启一组（嵌套 START、无活跃组的 END 均记入
    anomalies 并使验收失败）；judge 收到的是该组 END 之前的原始行。
    """
    judges = judge_groups(judge_dir)
    results, notes = {}, {
        "groups_seen": {}, "truncated": False, "judge_errors": [],
        "anomalies": [], "group_lines": {},
    }
    judge, group = None, None
    with open(serial_path, encoding="utf-8", errors="ignore") as stream:
        for line in stream:
            is_start = GROUP_START.findall(line)
            is_end = GROUP_END.findall(line)
            if is_end or is_start:
                # END 必须与当前活跃组名一致；嵌套/无配对/错名都判失败
                if is_end and judge is None:
                    notes["anomalies"].append(f"END {is_end[0]} without active group")
                elif is_end and judge is not None and is_end[0] != group:
                    notes["anomalies"].append(
                        f"END {is_end[0]} mismatches active {group}")
                if judge is not None and is_start:
                    notes["anomalies"].append(
                        f"nested START {is_start[0]} inside active {group}")
                if judge:
                    try:
                        results[group] = collect_group(judge, group)
                    except Exception as error:  # judge 崩溃/非 JSON/非零退出
                        notes["judge_errors"].append(f"{group}: {error}")
                    judge = group = None
            elif judge is not None:
                notes["group_lines"][group] = notes.get("group_lines", {}).get(group, 0) + 1
                judge.stdin.write(line.encode())
            if is_start:
                group = is_start[0]
                notes["groups_seen"][group] = notes["groups_seen"].get(group, 0) + 1
                notes["group_lines"].setdefault(group, 0)
                if group in judges:
                    judge = subprocess.Popen(judges[group], stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                elif group not in notes.get("missing_judges", []):
                    pass  # 无该组 judge：串口照常走，判分阶段按缺组处理
    if judge:  # 串口在最后一组 END 前结束
        notes["truncated"] = True
        try:
            results[group] = collect_group(judge, group)
        except Exception as error:
            notes["judge_errors"].append(f"{group}: {error}")
    # 从未启动的组同样以空输入判分（官方行为，计 0 分）
    for name, command in judges.items():
        if name not in notes["groups_seen"]:
            probe = subprocess.Popen(command, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                results[name] = collect_group(probe, name)
            except Exception as error:
                notes["judge_errors"].append(f"{name}: {error}")
    return results, notes


def group_score(result):
    """单组总分：judge 输出的明细列表求和（basic 逐测例、busybox 逐命令）。"""
    return (sum(item.get("score", 0) for item in result),
            sum(item.get("all", 0) for item in result))


def run_arch(arch, args):
    """运行单架构验收，返回汇总行。"""
    out = args.output / arch
    out.mkdir(parents=True, exist_ok=True)
    images_dir = args.images_dir
    disk = images_dir / ("sdcard-rv.img" if arch == "rv" else "sdcard-la.img")
    if not disk.exists():
        sys.exit(
            f"错误：原盘镜像不存在 {disk}\n"
            f"  从 https://github.com/oscomp/testsuits-for-oskernel/releases/tag/pre-20250615 "
            f"下载并解压到 {images_dir}/"
        )
    recorded_sha = sha256_of(disk)
    if args.sha256 and args.sha256 != recorded_sha:
        sys.exit(f"错误：镜像 SHA-256 不匹配：期望 {args.sha256}，实际 {recorded_sha}")
    # 环境检查全部前移到复制之前：QEMU 版本/辅助盘缺失时不会留下 4 GiB 副本
    qemu = qemu_binary(arch, args.qemu)
    default_extra = pathlib.Path("disk.img" if arch == "rv" else "disk-la.img")
    extra = str(args.extra_disk or default_extra) if (
        args.extra_disk or default_extra.exists()
    ) else None
    copy = out / f"sdcard-{arch}.img"
    print(f"[{arch}] 复制干净盘副本 {disk} -> {copy}", flush=True)
    shutil.copyfile(disk, copy)

    cmd = ["timeout", "-k", "5", str(args.timeout)] + qemu_command(
        qemu, arch, str(args.kernel), str(copy), extra)
    try:
        (out / "qemu-cmd.txt").write_text(" ".join(cmd) + "\n")
        with open(out / "serial.txt", "w", errors="ignore", buffering=1) as serial:
            run = subprocess.run(cmd, stdout=serial, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL, timeout=args.timeout + 30)
        timed_out = run.returncode == 124
        if timed_out:
            print(f"[{arch}] 警告：QEMU 到达超时 {args.timeout}s 被 kill",
                  flush=True)
        serial_text = (out / "serial.txt").read_text(errors="ignore")
    # 内核 panic / rust 运行时崩溃无论组标记是否齐全都判运行不完整
        panicked = "[panic]" in serial_text or "panicked at" in serial_text

        results, notes = score_serial(args.judge_dir, out / "serial.txt")

        summary = {
        "arch": arch, "kernel": str(args.kernel), "disk": str(disk),
        "disk_sha256": recorded_sha, "qemu": qemu, "timeout_sec": args.timeout,
        "qemu_timed_out": timed_out, "qemu_returncode": run.returncode,
        "panicked": panicked,
        "serial": str(out / "serial.txt"),
        "groups": notes["groups_seen"], "truncated": notes["truncated"],
        "anomalies": notes["anomalies"],
        "group_lines": notes["group_lines"],
        "judge_errors": notes["judge_errors"],
        "scores": {name: dict(zip(("score", "all"), group_score(result)))
                   for name, result in results.items()},
        "detail": results,
    }
        (out / "result.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        for name in TARGET_GROUPS:
            score = summary["scores"].get(name, {"score": None, "all": None})
            seen = notes["groups_seen"].get(name, 0)
            print(f"[{arch}] {name:16s} {score['score']}/{score['all']}"
                  f"（串口出现 {seen} 次组标记）", flush=True)
        if notes["judge_errors"]:
            print(f"[{arch}] judge 异常：{notes['judge_errors']}", flush=True)
    finally:
        # 运行副本用完即清（AGENTS §8）：文本证据已随写随落盘，GB 级镜像
        # 不保留；异常路径（判分崩溃等）同样清理
        copy.unlink(missing_ok=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arch", choices=["rv", "la", "both"])
    parser.add_argument("--kernel", type=pathlib.Path,
                        help="内核 ELF，默认按架构取仓库根目录 kernel-rv/kernel-la")
    parser.add_argument("--images-dir", type=pathlib.Path, default=IMAGES_DIR_DEFAULT,
                        help="原盘目录，默认 sdcard/pre-20250615/（缺失时含下载指引报错）")
    parser.add_argument("--sha256", help="原盘期望 SHA-256，提供时校验")
    parser.add_argument("--judge-dir", type=pathlib.Path,
                        default=pathlib.Path.home() /
                        "os-contest-ref/autotest-for-oskernel/kernel/judge")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("target/official"))
    parser.add_argument("--timeout", type=int, default=600, help="QEMU 超时秒数（默认 600）")
    parser.add_argument("--qemu", help="QEMU 可执行文件覆盖（须为 10.0.2）")
    parser.add_argument("--extra-disk", type=pathlib.Path,
                        help="第二块盘（默认取仓库 disk.img / disk-la.img，make all 生成）")
    args = parser.parse_args()
    if not args.judge_dir.is_dir():
        sys.exit(f"错误：judge 目录不存在 {args.judge_dir}")


    archs = ["rv", "la"] if args.arch == "both" else [args.arch]
    if args.arch == "both" and args.kernel is not None:
        sys.exit("错误：both 模式下 --kernel 有歧义（两架构需各自内核）；"
                 "请省略 --kernel（默认取 kernel-rv / kernel-la）或分架构单独运行")
    statuses = []
    for arch in archs:
        # both 模式强制按架构取内核（禁止污染）；单架构尊重 --kernel
        kernel = pathlib.Path(f"kernel-{arch}") if len(archs) > 1 else (
            args.kernel or pathlib.Path(f"kernel-{arch}")
        )
        if not kernel.exists():
            sys.exit(f"错误：内核不存在 {kernel}（先 make all 或用 --kernel 指定）")
        args.kernel = kernel
        statuses.append(run_arch(arch, args))

    # 退出码只反映运行完整性，不把分数当门禁：
    #   0 = 每个目标组恰出现一次、配对完整、无 panic/超时/QEMU 异常
    #   1 = 运行不完整（组缺失/重复/嵌套/截断/panic/超时/QEMU 非零返回）
    #   2 = judge 或基础设施失败
    exit_code = 0
    for status in statuses:
        if status["judge_errors"]:
            exit_code = max(exit_code, 2)
        groups_ok = all(
            status["groups"].get(name, 0) == 1 for name in TARGET_GROUPS
        ) and all(
            status["group_lines"].get(name, 0) > 0 for name in TARGET_GROUPS
        ) and not status["anomalies"] and not status["truncated"]
        run_ok = (
            groups_ok
            and not status["qemu_timed_out"]
            and not status["panicked"]
            and status["qemu_returncode"] == 0
        )
        if not run_ok:
            exit_code = max(exit_code, 1)
    print(f"target 占用：{pathlib.Path('target').resolve()}")
    import subprocess as _sp
    print(_sp.run(["du", "-sh", "target"], capture_output=True, text=True).stdout.strip())
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
