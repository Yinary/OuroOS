#!/usr/bin/env python3
"""构建 EXT4 + FAT 两个 MBR 分区；只填充未修改的官方程序及自有启动器。"""
import argparse,pathlib,struct,subprocess,tempfile
p=argparse.ArgumentParser()
p.add_argument("source",type=pathlib.Path)
p.add_argument("binaries",type=pathlib.Path)
p.add_argument("output",type=pathlib.Path)
p.add_argument("--mkfs-fat",default="mkfs.fat")
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
for arch in ("riscv64","loongarch64"):
    with tempfile.TemporaryDirectory() as tmp:
        t=pathlib.Path(tmp);ext=t/"root.img";fat=t/"fat.img"
        with ext.open("wb") as f:f.truncate(128*1024*1024)
        with fat.open("wb") as f:f.truncate(16*1024*1024)
        subprocess.run(["mkfs.ext4","-q","-F","-b","4096",str(ext)],check=True)
        subprocess.run([a.mkfs_fat,"-F","16",str(fat)],check=True)
        commands=["mkdir /basic","mkdir /basic/mnt"]
        for file in sorted((a.binaries/arch).iterdir()):
            if file.is_file() and file.read_bytes()[:4]==b"ELF" and file.suffix!=".o":
                commands.append(f'write "{file.resolve()}" /basic/{file.name}')
        commands += [f'write "{(a.binaries/arch/"basic_init").resolve()}" /init',
                     f'write "{(a.source/"basic/user/src/oscomp/text.txt").resolve()}" /basic/text.txt']
        script=t/"populate";script.write_text("\n".join(commands)+"\n")
        subprocess.run(["debugfs","-w","-f",str(script),str(ext)],check=True,stdout=subprocess.DEVNULL)
        first=2048;count=ext.stat().st_size//512;second=first+count;size=fat.stat().st_size//512
        mbr=bytearray(512)
        for n,typ,start,length in [(0,0x83,first,count),(1,0x06,second,size)]:
            mbr[446+n*16:462+n*16]=struct.pack("<BBBBBBBBII",0,0,0,0,typ,0,0,0,start,length)
        mbr[510:]=bytes([0x55,0xaa])
        with (a.output/(arch+".img")).open("wb") as out:
            out.truncate((second+size)*512);out.seek(0);out.write(mbr)
            for image,start in [(ext,first),(fat,second)]:
                out.seek(start*512)
                with image.open("rb") as src:
                    while block:=src.read(1024*1024):out.write(block)