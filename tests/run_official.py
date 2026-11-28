#!/usr/bin/env python3
"""官方原盘验收：官方 QEMU 命令启动，串口按组标记喂原版 judge 判分
（协议与 autotest-for-oskernel run.py 一致），另附超时/缺组/嵌套/截断
等完整性诊断；原盘只读，运行用干净副本。
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
QEMU_VERSION = re.compile(r"version 10\.0\.2\b")
TARGET_GROUPS = ("basic-musl", "basic-glibc", "busybox-musl", "busybox-glibc")
IMAGES_DIR_DEFAULT = pathlib.Path("sdcard") / "pre-20250615"
JUDGE_DIR_CANDIDATES = (
    pathlib.Path(".cache/autotest-for-oskernel/kernel/judge"),
    pathlib.Path.home() / "os-contest-ref/autotest-for-oskernel/kernel/judge",
)

def resolve_judge_dir(explicit):
    """定位官方 judge 目录，找不到时给出 make test-setup 指引并退出。"""
    if explicit:
        judge = pathlib.Path(explicit)
        if not judge.is_dir():
            sys.exit(f"错误：--judge-dir 指定的目录不存在：{judge}")
        return judge
    for candidate in JUDGE_DIR_CANDIDATES:
        if candidate.is_dir():
            return candidate
    sys.exit(
        "错误：找不到官方 judge 目录。先执行 make test-setup 克隆官方评测器，\n"
        "  或 --judge-dir 指向已有的 judge 目录"
    )

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

def qemu_img_binary(qemu_path):
    """定位 qemu-img：优先取与 qemu 同目录或真实构建目录，再回退 PATH。"""
    q = pathlib.Path(qemu_path)
    for parent in (q.parent, q.resolve().parent):
        candidate = parent / "qemu-img"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which("qemu-img")
    if found is None:
        sys.exit("错误：未找到 qemu-img（无法创建 QCOW2 写时复制覆盖层；可传 --raw-copy 回退整盘复制）")
    return found

def create_qcow2_overlay(qemu_img, backing_path, overlay_path):
    """基于只读 raw 原盘秒级创建 QCOW2 写时复制覆盖层，避免整盘拷贝。"""
    backing = backing_path.resolve()
    overlay_path.unlink(missing_ok=True)
    res = subprocess.run(
        [qemu_img, "create", "-q", "-f", "qcow2",
         "-b", str(backing), "-F", "raw", str(overlay_path)],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        sys.exit(f"错误：创建 QCOW2 覆盖层失败：{res.stderr.strip() or res.stdout.strip()}")

def qemu_command(qemu, arch, kernel, disk, extra_disk=None,
                 disk_format="raw", extra_format="raw"):
    """官方 run_qemu.py 的正式启动命令；extra_disk 对应官方挂第二块盘的行为。"""
    cmd = [qemu, "-kernel", kernel, "-m", "1G", "-nographic",
           "-smp", "1", "-no-reboot", "-rtc", "base=utc",
           "-drive", f"file={disk},if=none,format={disk_format},id=x0"]
    if arch == "rv":
        cmd = [qemu, "-machine", "virt", "-kernel", kernel, "-m", "1G",
               "-nographic", "-smp", "1", "-bios", "default",
               "-drive", f"file={disk},if=none,format={disk_format},id=x0",
               "-device", "virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0",
               "-no-reboot", "-device", "virtio-net-device,netdev=net",
               "-netdev", "user,id=net", "-rtc", "base=utc"]
        if extra_disk:
            cmd += ["-drive", f"file={extra_disk},if=none,format={extra_format},id=x1",
                    "-device", "virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1"]
        return cmd
    cmd += ["-device", "virtio-blk-pci,drive=x0",
            "-device", "virtio-net-pci,netdev=net0", "-netdev", "user,id=net0"]
    if extra_disk:
        cmd += ["-drive", f"file={extra_disk},if=none,format={extra_format},id=x1",
                "-device", "virtio-blk-pci,drive=x1"]
    return cmd

def build_split_kernel(arch, out_dir, groups, ltp_filter, ltp_timeout):
    """按本地拆组/拆例参数编译临时测试内核，绝不覆盖根目录交付产物 kernel-rv/la。"""
    env = os.environ.copy()
    if groups:
        env["OUROOS_INIT_GROUPS"] = groups
    else:
        env.pop("OUROOS_INIT_GROUPS", None)
    if ltp_filter:
        env["OUROOS_LTP_FILTER"] = ltp_filter
    else:
        env.pop("OUROOS_LTP_FILTER", None)
    if ltp_timeout is not None:
        env["OUROOS_LTP_TIMEOUT"] = str(ltp_timeout)
    else:
        env.pop("OUROOS_LTP_TIMEOUT", None)
    targets = [f"build-user-{arch}", f"build-{arch}"]
    print(f"[{arch}] 构建本地拆组内核（groups={groups or 'default'}"
          f"{f', ltp_filter={ltp_filter}' if ltp_filter else ''}"
          f"{f', ltp_timeout={ltp_timeout}s' if ltp_timeout else ''}）", flush=True)
    res = subprocess.run(["make", "--no-print-directory", *targets], env=env)
    if res.returncode != 0:
        sys.exit(f"错误：本地拆组内核构建失败（arch={arch}）")
    triple = "riscv64gc-unknown-none-elf" if arch == "rv" else "loongarch64-unknown-none"
    built = pathlib.Path("target") / triple / "release" / "kernel"
    dst = out_dir / f"kernel-local-{arch}"
    shutil.copyfile(built, dst)
    return dst

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
    """收尾 judge 子进程：非 JSON 输出或非零退出码都抛异常判失败。"""
    judge.stdin.close()
    raw = judge.stdout.read().decode()
    result = json.loads(raw)
    judge.wait(5)
    if judge.returncode != 0:
        raise RuntimeError(f"judge exited {judge.returncode}")
    return result

def score_serial(judge_dir, serial_path):
    """按组标记状态机拆分串口并喂 judge，返回 (分数表, 诊断信息)。"""
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
                    except Exception as error:
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
                    pass
    if judge:
        notes["truncated"] = True
        try:
            results[group] = collect_group(judge, group)
        except Exception as error:
            notes["judge_errors"].append(f"{group}: {error}")
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
    """单组总分：judge 输出的明细列表求和（兼容 all/total/性能组）。"""
    total_score = sum(item.get("score", 0) for item in result)
    if any("all" in item for item in result):
        total_all = sum(item.get("all", 0) for item in result)
    elif any("total" in item for item in result):
        total_all = sum(item.get("total", 0) for item in result)
    else:
        total_all = len(result)
    return (total_score, total_all)

def format_score(val):
    if isinstance(val, float):
        return f"{val:.2f}"
    return str(val)

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
    recorded_sha = sha256_of(disk) if args.sha256 else None
    if args.sha256 and args.sha256 != recorded_sha:
        sys.exit(f"错误：镜像 SHA-256 不匹配：期望 {args.sha256}，实际 {recorded_sha}")
    qemu = qemu_binary(arch, args.qemu)
    default_extra = pathlib.Path("disk.img" if arch == "rv" else "disk-la.img")
    extra_src = args.extra_disk or (default_extra if default_extra.exists() else None)

    temp_kernel = None
    kernel_path = args.kernel
    if args.groups or args.ltp_filter or args.ltp_timeout is not None:
        if args.kernel_explicit:
            sys.exit("错误：--groups/--ltp-filter/--ltp-timeout 会按参数构建本地启动器内核，不能同时指定 --kernel")
        temp_kernel = build_split_kernel(
            arch, out, args.groups, args.ltp_filter, args.ltp_timeout
        )
        kernel_path = temp_kernel

    extra_overlay = None
    if args.raw_copy:
        run_disk = out / f"sdcard-{arch}.img"
        disk_format = "raw"
        print(f"[{arch}] 复制干净盘副本 {disk} -> {run_disk}", flush=True)
        shutil.copyfile(disk, run_disk)
        extra_arg = str(extra_src) if extra_src else None
        extra_format = "raw"
    else:
        qemu_img = qemu_img_binary(qemu)
        run_disk = out / f"sdcard-{arch}.qcow2"
        disk_format = "qcow2"
        create_qcow2_overlay(qemu_img, disk, run_disk)
        print(f"[{arch}] 已创建 QCOW2 覆盖层 {run_disk} -> {disk.resolve()}", flush=True)
        if extra_src:
            extra_overlay = out / f"extra-{arch}.qcow2"
            create_qcow2_overlay(qemu_img, extra_src, extra_overlay)
            extra_arg = str(extra_overlay)
            extra_format = "qcow2"
        else:
            extra_arg = None
            extra_format = "raw"

    cmd = ["timeout", "-k", "5", str(args.timeout)] + qemu_command(
        qemu, arch, str(kernel_path), str(run_disk), extra_arg,
        disk_format=disk_format, extra_format=extra_format,
    )
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
        panicked = "[panic]" in serial_text or "panicked at" in serial_text

        results, notes = score_serial(args.judge_dir, out / "serial.txt")

        summary = {
            "arch": arch, "kernel": str(kernel_path), "disk": str(disk),
            "disk_format": disk_format,
            "disk_sha256": recorded_sha, "qemu": qemu, "timeout_sec": args.timeout,
            "requested_groups": args.requested_groups,
            "ltp_filter": args.ltp_filter,
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
        display_groups = list(args.requested_groups or TARGET_GROUPS)
        for seen_group in notes["groups_seen"]:
            if seen_group not in display_groups:
                display_groups.append(seen_group)
        for name in display_groups:
            score = summary["scores"].get(name, {"score": None, "all": None})
            seen = notes["groups_seen"].get(name, 0)
            print(f"[{arch}] {name:16s} {format_score(score['score'])}/{score['all']}"
                  f"（串口出现 {seen} 次组标记）", flush=True)
        if notes["judge_errors"]:
            print(f"[{arch}] judge 异常：{notes['judge_errors']}", flush=True)
        print(f"[{arch}] 串口：{out / 'serial.txt'}  判分明细：{out / 'result.json'}",
              flush=True)
    finally:
        run_disk.unlink(missing_ok=True)
        if extra_overlay is not None:
            extra_overlay.unlink(missing_ok=True)
        if temp_kernel is not None:
            temp_kernel.unlink(missing_ok=True)
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
                        help="官方 judge 目录；缺省按搜索链取 .cache 克隆或本机历史位置")
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("target/official"))
    parser.add_argument("--timeout", type=int, default=600, help="QEMU 超时秒数（默认 600）")
    parser.add_argument("--qemu", help="QEMU 可执行文件覆盖（须为 10.0.2）")
    parser.add_argument("--extra-disk", type=pathlib.Path,
                        help="第二块盘（默认取仓库 disk.img / disk-la.img，make all 生成）")
    parser.add_argument("--raw-copy", action="store_true",
                        help="改用整盘 raw 拷贝（默认用 QCOW2 写时复制覆盖层）")
    parser.add_argument("--groups",
                        help="本地拆组运行，逗号分隔（如 libctest-musl,lmbench-musl）；不改根目录内核")
    parser.add_argument("--ltp-filter",
                        help="本地 LTP 前缀过滤，逗号分隔（如 chown,statx），须与 --groups ltp-* 同用")
    parser.add_argument("--ltp-timeout", type=int,
                        help="本地 LTP 逐例时限（秒），覆盖默认 2 秒")
    args = parser.parse_args()
    args.judge_dir = resolve_judge_dir(args.judge_dir)
    args.kernel_explicit = args.kernel is not None
    args.requested_groups = [
        g.strip() for g in args.groups.split(",") if g.strip()
    ] if args.groups else None

    archs = ["rv", "la"] if args.arch == "both" else [args.arch]
    if args.arch == "both" and args.kernel is not None:
        sys.exit("错误：both 模式下 --kernel 有歧义（两架构需各自内核）；"
                 "请省略 --kernel（默认取 kernel-rv / kernel-la）或分架构单独运行")
    statuses = []
    for arch in archs:
        kernel = pathlib.Path(f"kernel-{arch}") if len(archs) > 1 else (
            args.kernel or pathlib.Path(f"kernel-{arch}")
        )
        if not (args.groups or args.ltp_filter or args.ltp_timeout is not None) and not kernel.exists():
            sys.exit(f"错误：内核不存在 {kernel}（先 make all 或用 --kernel 指定）")
        args.kernel = kernel
        statuses.append(run_arch(arch, args))

    expected_groups = tuple(args.requested_groups) if args.requested_groups else TARGET_GROUPS
    exit_code = 0
    for status in statuses:
        if status["judge_errors"]:
            exit_code = max(exit_code, 2)
        groups_ok = all(
            status["groups"].get(name, 0) == 1 for name in expected_groups
        ) and all(
            status["group_lines"].get(name, 0) > 0 for name in expected_groups
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
