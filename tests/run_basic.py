#!/usr/bin/env python3
"""逐项启动原始 basic ELF，调用官方判分器，并保存完整日志与 JSON。"""
import argparse,importlib,os,pathlib,re,subprocess,sys,json
p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('binaries',type=pathlib.Path);p.add_argument('output',type=pathlib.Path);p.add_argument('--cases');p.add_argument('--disk',type=pathlib.Path);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True)
s=a.source/'basic/user/src/oscomp';sys.path.insert(0,str(s))
cases=a.cases.split(',') if a.cases else re.search(r'tests="(.*?)"',(s/'run-all.sh').read_text(),re.S)[1].split()
rows=[]
for arch,target in [('riscv64','riscv64gc-unknown-none-elf'),('loongarch64','loongarch64-unknown-none')]:
    qemu='qemu-system-'+arch
    version=subprocess.check_output([qemu,'--version'],text=True)
    if not re.search(r'version 10\.0\.2\b',version):raise RuntimeError(version)
    for case in cases:
        env=dict(os.environ,OUROOS_TEST_ELF=str((a.binaries/arch/case).resolve()),LOG='warn')
        if arch=='loongarch64':env['RUSTFLAGS']='-Zunstable-options -C target-feature=-lsx,-lasx'
        label=arch+'-'+case
        with (a.output/(label+'-build.log')).open('w') as out:
            subprocess.run(['cargo','build','-Z','build-std=core,alloc','--release','--target',target],env=env,stdout=out,stderr=subprocess.STDOUT,check=True)
        cmd=['timeout','-k','5','15',qemu]
        if arch=='riscv64':cmd+=['-machine','virt','-bios','default']
        cmd+=['-kernel',f'target/{target}/release/kernel','-m','1G','-smp','1','-nographic','-no-reboot']
        if a.disk:
            disk = pathlib.Path(str(a.disk).replace('{arch}',arch))
            cmd+=['-drive',f'file={disk.resolve()},format=raw,if=none,id=disk,snapshot=on','-device',('virtio-blk-device' if arch=='riscv64' else 'virtio-blk-pci')+',drive=disk']
        run=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=25)
        text=run.stdout.decode(errors='replace');(a.output/(label+'.log')).write_text(text)
        name=case.rstrip('_'); blocks=re.findall(r'========== START test_'+name+r' ==========\r?\n(.*?)========== END test_'+name+r' ==========',text,re.S)
        if not blocks:blocks=re.findall(r'========== START test_'+name+r' ==========\r?\n(.*?)(?:\[task\]|$)',text,re.S)
        try:
            obj=getattr(importlib.import_module(name+'_test'),name+'_test')();obj.start(blocks[0].splitlines() if blocks else []);result=obj.get_result()
        except Exception as e:result={'passed':0,'all':1,'error':str(e)}
        passed=result['passed']==result['all'] and run.returncode==0 and 'panicked' not in text and '[panic]' not in text and '(test): exited with status 0' in text
        rows.append({'arch':arch,'case':case,'pass':passed,'exit':run.returncode,'oracle':result});print(label, 'PASS' if passed else 'FAIL',flush=True)
        (a.output/'results.json').write_text(json.dumps(rows,indent=2))
sys.exit(0 if all(r['pass'] for r in rows) else 1)