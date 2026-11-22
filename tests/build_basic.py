#!/usr/bin/env python3
"""使用现有交叉工具链构建未修改的官方 basic 源码；输出位于指定外部目录。"""
import argparse
import pathlib
import subprocess
import re
import json
p=argparse.ArgumentParser()
p.add_argument('source',type=pathlib.Path)
p.add_argument('output',type=pathlib.Path)
a=p.parse_args()
s=a.source.resolve()/'basic/user'
for arch,sub in [('riscv64','riscv'),('loongarch64','loongarch64')]:
    out=a.output.resolve()/arch
    out.mkdir(parents=True,exist_ok=True)
    ids=(s/'lib/arch'/sub/'syscall_ids.h.in').read_text()
    (out/'syscall_ids.h').write_text(ids+'\n'.join(line.replace('__NR_','SYS_',1) for line in ids.splitlines() if '__NR_' in line)+'\n')
    gcc=arch+'-linux-gnu-gcc'
    flags=['-I'+str(out),'-I'+str(s/'lib'),'-O2','-fno-builtin','-nostdinc','-fno-stack-protector','-fno-pie','-I'+str(s/'include'),'-I'+str(s/'lib/arch'/sub)]
    if arch=='riscv64': flags+=['-march=rv64imafdc','-mabi=lp64d','-mcmodel=medany']
    sources=sorted((s/'lib').glob('*.c'))+[s/'lib/arch'/sub/'crt.S',s/'lib/arch'/sub/'clone.s']
    objects=[]
    for src in sources:
        obj=out/(src.name+'.o')
        subprocess.run([gcc,*flags,'-c',str(src),'-o',str(obj)],check=True)
        objects.append(str(obj))
    cases=re.search(r'tests="(.*?)"',(s/'src/oscomp/run-all.sh').read_text(),re.S)[1].split()
    (out/'basic_cases.h').write_text('static const char *cases[] = {'+','.join(json.dumps(n) for n in cases)+'};')
    for src in [*sorted((s/'src/oscomp').glob('*.c')),*sorted(pathlib.Path(__file__).parent.glob('basic_*.c'))]:

        subprocess.run([gcc,*flags,'-nostdlib','-static','-no-pie','-Wl,--build-id=none','-Wl,-Ttext=0x1000','-T',str(s/'lib/arch'/sub/'user.ld'),str(src),*objects,'-o',str(out/src.stem)],check=True)
    print(arch+' basic compilation passed',flush=True)