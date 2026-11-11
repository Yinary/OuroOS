#!/usr/bin/env python3
"""一次启动跑整套官方 basic，逐项调用官方 oracle，并检查持久化磁盘。"""
import argparse, importlib, json, os, pathlib, re, shutil, struct, subprocess, sys
p=argparse.ArgumentParser()
p.add_argument("source",type=pathlib.Path)
p.add_argument("binaries",type=pathlib.Path)
p.add_argument("disks",type=pathlib.Path)
p.add_argument("output",type=pathlib.Path)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
src=a.source/"basic/user/src/oscomp";sys.path.insert(0,str(src))
cases=re.search(r'tests="(.*?)"',(src/"run-all.sh").read_text(),re.S)[1].split()
rows=[]
for arch,short,target in [("riscv64","rv","riscv64gc-unknown-none-elf"),("loongarch64","la","loongarch64-unknown-none")]:
    qemu="qemu-system-"+arch
    assert re.search(r"version 10\.0\.2\b",subprocess.check_output([qemu,"--version"],text=True))
    for mode in ["group","edges","selftest"]:
        env=dict(os.environ)
        env.pop("OUROOS_TEST_ELF",None)
        if mode=="edges":env["OUROOS_TEST_ELF"]=str((a.binaries/arch/"basic_edges").resolve())
        build=("selftest-" if mode=="selftest" else "kernel-")+short
        with (a.output/f"{arch}-{mode}-build.log").open("w") as out:
            subprocess.run(["make",build],env=env,stdout=out,stderr=subprocess.STDOUT,check=True)
        disk=a.output/f"{arch}-{mode}.img"
        shutil.copyfile(a.disks/(arch+".img"),disk)
        kernel=f"target/{target}/selftest/kernel" if mode=="selftest" else "kernel-"+short
        cmd=["timeout","-k","5","120",qemu]
        if arch=="riscv64":cmd+=["-machine","virt","-bios","default"]
        cmd+=["-kernel",kernel,"-m","1G","-smp","1","-nographic","-no-reboot","-drive",
              f"file={disk.resolve()},format=raw,if=none,id=disk","-device",
              ("virtio-blk-device" if arch=="riscv64" else "virtio-blk-pci")+",drive=disk"]
        run=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=130)
        text=run.stdout.decode(errors="replace")
        (a.output/f"{arch}-{mode}.log").write_text(text)
        good=run.returncode==0 and "[panic]" not in text and "panicked" not in text
        if mode!="edges":
            good=good and "BASIC GROUP RESULT: 0 failed" in text and "(basic-init): exited with status 0" in text
            if mode=="group":
                for case in cases:
                    name=case.rstrip("_")
                    start=f"========== START test_{name} =========="
                    end=f"========== END test_{name} =========="
                    block=text.split(start,1)[1].lstrip("\r\n") if start in text else ""
                    if end in block:block=block.split(end,1)[0]
                    else:block=block.split("========== START",1)[0]
                    obj=getattr(importlib.import_module(name+"_test"),name+"_test")()
                    obj.start(block.splitlines());result=obj.get_result()
                    passed=result["passed"]==result["all"]
                    rows.append(dict(arch=arch,mode=mode,case=case,passed=passed,oracle=result))
                    good=good and passed
        else:good=good and "EDGE CHECKS PASSED" in text and "(test): exited with status 0" in text
        # 抽出 EXT4 分区做只读一致性检查；不修复镜像来掩盖问题。
        ext=a.output/f"{arch}-{mode}-ext4.img"
        with disk.open("rb") as stream,ext.open("wb") as out:
            mbr=stream.read(512);start,count=struct.unpack_from("<II",mbr,454)
            stream.seek(start*512);left=count*512
            while left:
                data=stream.read(min(left,1024*1024))
                if not data:raise RuntimeError("truncated disk")
                out.write(data);left-=len(data)
        check=subprocess.run(["e2fsck","-fn",str(ext)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        (a.output/f"{arch}-{mode}-fsck.log").write_bytes(check.stdout)
        good=good and check.returncode==0
        rows.append(dict(arch=arch,mode=mode,passed=good,qemu_exit=run.returncode,fsck_exit=check.returncode))
        (a.output/"results.json").write_text(json.dumps(rows,indent=2))
        print(arch,mode,"PASS" if good else "FAIL",flush=True)
sys.exit(0 if all(r["passed"] for r in rows) else 1)