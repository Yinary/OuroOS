/* 自有错误路径和共享状态回归，不修改官方程序。 */
#include "unistd.h"
#include "stdio.h"
#include "string.h"
#include "syscall.h"
#define CHECK(x) do { if (!(x)) { printf("EDGE FAIL line %d\n",__LINE__); return 1; } } while(0)
/* 自有 MM 集成回归：通过实际 syscall 和用户访问检查状态变化。 */
static int protect_pages(void) {
    const int page = 4096;
    char *p = mmap(0, 2 * page, PROT_READ | PROT_WRITE, 0x22, -1, 0);
    CHECK(p != MAP_FAILED);
    p[0] = 41;
    CHECK(syscall(226, p, 2 * page, PROT_READ) == 0);
    CHECK(p[0] == 41 && p[page] == 0);
    int child = fork(), status;
    CHECK(child >= 0);
    if (child == 0) {
        if (syscall(226, p, page, PROT_WRITE) != 0) exit(1);
        *(volatile char *)p = 42;
        if (*p != 42 || syscall(226, p, page, PROT_READ) != 0) exit(2);
        *(volatile char *)p = 43;
        exit(3);
    }
    CHECK(waitpid(child, &status, 0) == child && status == 11);
    CHECK(syscall(226, p, 2 * page, PROT_WRITE) == 0);
    p[0] = 42;
    CHECK(p[0] == 42 && munmap(p, 2 * page) == 0);
    return 0;
}

static int mm_checks(void) {
    char *p=mmap(0,12288,3,0x22,-1,0);
    unsigned char residency[3]={9,9,9};
    CHECK(p!=MAP_FAILED);
    CHECK(syscall(232,p,12288,residency)==0 && residency[0]==0 && residency[1]==0);
    CHECK(syscall(222,p,4096,3,0x100022,-1,0)==-17);
    CHECK(munmap(p+4096,4096)==0);
    CHECK(syscall(222,p+4096,4096,3,0x100022,-1,0)==(long)(p+4096));
    char *pop=mmap(0,8192,3,0x8022,-1,0); CHECK(pop!=MAP_FAILED);
    CHECK(syscall(232,pop,8192,residency)==0 && residency[0] && residency[1]);
    CHECK(munmap(pop,8192)==0);
    pop=mmap(0,4096,3,0x18022,-1,0); CHECK(pop!=MAP_FAILED);
    CHECK(syscall(232,pop,4096,residency)==0 && !residency[0]);
    CHECK(munmap(pop,4096)==0);
    p[0]=41;
    CHECK(syscall(232,p,12288,residency)==0 && residency[0]==1 && residency[1]==0);
    CHECK(syscall(284,p+4096,4096,1)==0);
    CHECK(syscall(233,p+4096,4096,4)==-22);
    CHECK(syscall(232,p,12288,residency)==0 && residency[1]==0);
    CHECK(syscall(228,p+4096,4096)==0);
    CHECK(syscall(232,p,12288,residency)==0 && residency[1]==1);
    CHECK(syscall(227,p+4096,4096,6)==-16);
    CHECK(syscall(229,p+4096,4096)==0);
    CHECK(syscall(233,p,8192,4)==0);
    CHECK(syscall(232,p,12288,residency)==0 && residency[0]==0 && residency[1]==0);
    CHECK(p[0]==0);
    p[0]=72;
    char *target=mmap(0,16384,3,0x22,-1,0);
    CHECK(target!=MAP_FAILED);
    target[0]=99;
    CHECK(syscall(216,p,12288,16384,3,target)==(long)target);
    CHECK(target[0]==72 && target[12288]==0);
    CHECK(syscall(232,p,4096,residency)==-12);
    CHECK(munmap(target,16384)==0);
    unsigned long old_limit[2], small_limit[2]={4096,~0UL};
    CHECK(syscall(261,0,8,small_limit,old_limit)==0);
    char *limited=mmap(0,8192,3,0x22,-1,0);
    CHECK(limited!=MAP_FAILED);
    int mi=open("/proc/meminfo",0); CHECK(mi>=0);
    char snapshot[384], again[384];
    int n=read(mi,snapshot,9); CHECK(n==9);
    int rest=read(mi,snapshot+9,sizeof(snapshot)-9); CHECK(rest>0);
    CHECK(read(mi,again,1)==0 && syscall(62,mi,0,0)==0);
    CHECK(read(mi,again,sizeof(again))==rest+9);
    for(int i=0;i<rest+9;i++) CHECK(again[i]==snapshot[i]);
    CHECK(close(mi)==0 && open("/proc/meminfo",2)==-30);
    unsigned long si[14]={0};
    CHECK(syscall(179,si)==0 && si[4]>=si[5] && si[5]>0 && (unsigned int)si[13]==1024);
    CHECK(syscall(222,0,8192,3,0x2022,-1,0)==-12);
    char *one=mmap(0,4096,3,0x2022,-1,0);
    CHECK(one!=MAP_FAILED && syscall(232,one,4096,residency)==0 && residency[0]);
    CHECK(syscall(233,one,4096,4)==-22 && munmap(one,4096)==0);
    char *normal=mmap(0,8192,3,0x4022,-1,0);
    CHECK(normal!=MAP_FAILED && syscall(233,normal,8192,4)==0 && munmap(normal,8192)==0);
    CHECK(syscall(228,limited,8192)==-12);
    CHECK(syscall(228,limited,4096)==0);
    CHECK(syscall(228,limited,4096)==0);
    CHECK(syscall(229,limited,4096)==0);
    CHECK(syscall(261,0,8,old_limit,0)==0);
    CHECK(munmap(limited,8192)==0);
    CHECK(syscall(164,8,0)==-14);
    CHECK(syscall(230,2)==0);
    char *locked=mmap(0,8192,3,0x22,-1,0);
    CHECK(locked!=MAP_FAILED);
    CHECK(syscall(232,locked,8192,residency)==0 && residency[0]==1 && residency[1]==1);
    CHECK(syscall(233,locked,8192,4)==-22);
    CHECK(syscall(231)==0);
    CHECK(syscall(233,locked,8192,4)==0);
    CHECK(munmap(locked,8192)==0);
    char *shared=mmap(0,4096,3,0x21,-1,0);
    CHECK(shared!=MAP_FAILED);
    int pid=fork(), status=-1;
    CHECK(pid>=0);
    if(pid==0){shared[0]=33;exit(0);}
    CHECK(waitpid(pid,&status,0)==pid && status==0 && shared[0]==33);
    CHECK(munmap(shared,4096)==0);
    char *f=mmap(0,12288,3,0x22,-1,0);
    CHECK(f!=MAP_FAILED);
    f[0]=11; f[4096]=22; f[8192]=33;
    CHECK(syscall(233,f,4096,10)==0 && syscall(233,f+4096,4096,18)==0);
    pid=fork(); CHECK(pid>=0);
    if(!pid){exit(!(syscall(232,f,4096,residency)==-12 && f[4096]==0 && f[8192]==33));}
    CHECK(waitpid(pid,&status,0)==pid && status==0 && f[0]==11 && f[4096]==22);
    CHECK(syscall(233,f,4096,11)==0 && syscall(233,f+4096,4096,19)==0);
    pid=fork(); CHECK(pid>=0);
    if(!pid){exit(!(f[0]==11 && f[4096]==22));}
    CHECK(waitpid(pid,&status,0)==pid && status==0 && munmap(f,12288)==0);
    return 0;
}
/* 通过真正的 load、fork 和 O_TRUNC 检查文件失效及 wait 状态。 */
static int shared_growth(void) {
    unsigned char res[2];
    char *a=mmap(0,4096,3,0x21,-1,0);
    CHECK(a!=MAP_FAILED && syscall(232,a,4096,res)==0 && !res[0]);
    char *b=(char*)syscall(216,a,0,8192,1,0);
    CHECK((long)b>0 && b!=a); b[0]=75; b[4096]=91;
    CHECK(a[0]==75 && syscall(233,a,4096,4)==0 && a[0]==75);
    char *dest=mmap(0,8192,3,0x22,-1,0);
    CHECK(dest!=MAP_FAILED && syscall(216,a,4096,8192,3,dest)==(long)dest);
    CHECK(dest[4096]==91 && munmap(b,8192)==0);
    CHECK(syscall(228,dest+4096,4096)==0 && syscall(229,dest+4096,4096)==0);
    CHECK(syscall(216,dest,8192,4096,0,0)==(long)dest && dest[0]==75 && munmap(dest,4096)==0);
    a=mmap(0,4096,3,0x22,-1,0);CHECK(a!=MAP_FAILED);a[0]=29;
    CHECK(syscall(216,a,0,4096,1,0)==-22);
    b=(char*)syscall(216,a,4096,4096,5,0);
    CHECK((long)b>0 && b!=a && b[0]==29 && a[0]==0);
    a[0]=44;CHECK(b[0]==29 && munmap(a,4096)==0 && munmap(b,4096)==0);
    a=mmap(0,8192,3,0x22,-1,0);CHECK(a!=MAP_FAILED);
    CHECK(syscall(233,a,8192,23)==0 && syscall(232,a,8192,res)==0 && res[0] && res[1]);
    a[0]=52;CHECK(syscall(233,a,4096,8)==0 && syscall(232,a,8192,res)==0 && !res[0] && res[1] && a[0]==0);

    CHECK(munmap(a,8192)==0);
    unsigned long saved[2],limit[2]={0,~0UL};
    a=mmap(0,8192,3,0x22,-1,0); CHECK(a!=MAP_FAILED); a[0]=51;
    CHECK(syscall(261,0,9,limit,saved)==0);
    CHECK(syscall(216,a,8192,8192,5,0)==-12 && a[0]==51);
    CHECK(syscall(216,a,8192,4096,0,0)==(long)a && a[0]==51);
    CHECK(syscall(261,0,9,saved,0)==0 && munmap(a,4096)==0);
    CHECK(syscall(261,0,2,limit,saved)==0);
    CHECK(syscall(222,0,4096,3,0x22,-1,0)==-12);
    a=mmap(0,4096,3,0x21,-1,0);CHECK(a!=MAP_FAILED && munmap(a,4096)==0);
    CHECK(syscall(261,0,2,saved,0)==0);
    return 0;
}

static int fault_status(volatile char *address, int signal) {
    int pid = fork(), status = -1;
    CHECK(pid >= 0);
    if (pid == 0) {
        (void)*address;
        exit(99);
    }
    CHECK(waitpid(pid, &status, 0) == pid && status == signal);
    return 0;
}

static int file_end_checks(void) {
    int fd = open("mm-file-eof", O_CREATE | O_RDWR | 0x200);
    CHECK(fd >= 0);
    char *shared = mmap(0, 8192, 3, MAP_SHARED, fd, 0);
    char *priv = mmap(0, 8192, 3, 2, fd, 0);
    CHECK(shared != MAP_FAILED && priv != MAP_FAILED);
    CHECK(fault_status(shared, 7) == 0);
    CHECK(write(fd, "ab", 2) == 2 && shared[0] == 'a' && priv[0] == 'a');
    CHECK(shared[2] == 0 && priv[4095] == 0);
    /* 同一文件偏移的另一个映射尚未触碰，也能查到共享页在内存中。 */
    char *cold = mmap(0, 8192, 1, MAP_SHARED, fd, 0);
    unsigned char cached[2] = {9, 9};
    CHECK(cold != MAP_FAILED && syscall(232, cold, 8192, cached) == 0);
    CHECK(cached[0] == 1 && cached[1] == 0 && munmap(cold, 8192) == 0);
    CHECK(syscall(213,fd,0,8192)==0 && syscall(62,fd,0,1)==2);
    CHECK(syscall(213,fd,8192,4096)==0 && syscall(213,-1,0,4096)==-9);
    int ro = open("mm-file-eof", 0);
    CHECK(ro >= 0);
    char *readonly = mmap(0, 4096, PROT_READ, MAP_SHARED, ro, 0);
    CHECK(readonly != MAP_FAILED && close(ro) == 0);
    CHECK(syscall(226, readonly, 4096, PROT_WRITE) == -13);
    CHECK(readonly[0] == 'a' && munmap(readonly, 4096) == 0);
    int wo=open("mm-file-eof",1);
    CHECK(wo>=0 && syscall(213,wo,0,1)==-9);
    CHECK(wo>=0 && syscall(222,0,4096,1,2,wo,0)==-13 && close(wo)==0);
    CHECK(syscall(222,0,4096,1,2,-1,0)==-9);
    CHECK(syscall(222,0,4096,1,0x400003,fd,0)==-95);
    char *alias=(char*)syscall(216,shared,0,4096,1,0);
    CHECK((long)alias>0 && alias[0]=='a');
    alias[0]='Q'; CHECK(shared[0]=='Q' && munmap(alias,4096)==0);
    priv[0] = 'P';
    shared[0] = 'S';
    shared[100] = 'T';
    CHECK(syscall(227, shared, 8192, 4) == 0);
    CHECK(syscall(62, fd, 0, 2) == 2);
    CHECK(fault_status(priv + 4096, 7) == 0);
#ifdef __loongarch__
    /* 非对齐 8 字节加载跨入完全位于 EOF 外的第二页。 */
    int child = fork(), bus_status = -1;
    CHECK(child >= 0);
    if (child == 0) {
        long result;
        __asm__ volatile("ld.d %0, %1, 0" : "=r"(result) : "r"(priv + 4093) : "memory");
        exit(99);
    }
    CHECK(waitpid(child, &bus_status, 0) == child && bus_status == 7);
#endif
    CHECK(syscall(62, fd, 4096, 0) == 4096 && write(fd, "x", 1) == 1);
    CHECK(shared[4096] == 'x' && priv[4096] == 'x' && shared[100] == 0);
    int status = -1, pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        int other = open("mm-file-eof", O_RDWR | 0x200);
        exit(other < 0 || close(other) != 0);
    }
    CHECK(waitpid(pid, &status, 0) == pid && status == 0);
    unsigned char residency[2] = {9, 9};
    CHECK(syscall(232, shared, 8192, residency) == 0 && !residency[0] && !residency[1]);
    CHECK(fault_status(priv, 7) == 0 && fault_status(shared + 4096, 7) == 0);
    CHECK(syscall(62, fd, 0, 0) == 0 && write(fd, "new", 3) == 3);
    CHECK(priv[0] == 'n' && shared[0] == 'n' && shared[100] == 0);
    priv[0]='X';
    CHECK(syscall(233,priv,4096,4)==0 && priv[0]=='n');
    shared[0]='Y';
    CHECK(syscall(233,shared,4096,4)==0 && shared[0]=='Y');
    shared[1] = '!';
    CHECK(munmap(shared, 8192) == 0 && munmap(priv, 8192) == 0);
    CHECK(syscall(62, fd, 0, 0) == 0);
    char result[4];
    CHECK(read(fd, result, sizeof(result)) == 3 && result[1] == '!');
    CHECK(close(fd) == 0 && unlink("mm-file-eof") == 0);
    return 0;
}
int main(int argc, char **argv) {
    if (argc > 1) {
        char b;
        CHECK(read(100,&b,1)==-9);
        CHECK(read(101,&b,1)==1);
        return 0;
    }
    char *removed = mmap(0, 4096, 3, 0x22, -1, 0);
    CHECK(removed != MAP_FAILED);
    removed[0] = 1;
    CHECK(munmap(removed, 4096) == 0 && fault_status(removed, 11) == 0);
    CHECK(protect_pages()==0); CHECK(mm_checks()==0); CHECK(shared_growth()==0);
    CHECK(chdir("/basic")==0);
    CHECK(file_end_checks()==0);
    CHECK(open("text.txt/child",0)==-20);
    CHECK(open("missing/../text.txt",0)==-2);
    CHECK(open("text.txt/../text.txt",0)==-20);
    int filefd=open("mm-private-file",O_CREATE|O_RDWR);
    CHECK(filefd>=0);
    char block[256];
    memset(block,'K',sizeof(block));
    for(int i=0;i<32;i++) CHECK(write(filefd,block,sizeof(block))==sizeof(block));
    char *private_map=mmap(0,4096,3,2,filefd,0);
    CHECK(private_map!=MAP_FAILED && private_map[0]=='K');
    char *share_file=mmap(0,4096,3,1,filefd,0);
    CHECK(share_file!=MAP_FAILED);
    private_map[0]='P';
    CHECK(close(filefd)==0 && unlink("mm-private-file")==0);
    char *expanded=(char *)syscall(216,private_map,4096,8192,1,0);
    CHECK(expanded!=MAP_FAILED && expanded[0]=='P' && expanded[4096]=='K');
    CHECK(munmap(expanded,8192)==0);
    expanded=(char *)syscall(216,share_file,4096,8192,1,0);
    CHECK(expanded!=MAP_FAILED && expanded[0]=='K' && expanded[4096]=='K');
    CHECK(munmap(expanded,8192)==0);
    int fd=open("edge-data",O_CREATE|O_RDWR);
    CHECK(fd>=0);
    CHECK(write(fd,"abcdef",6)==6);
    char *m=mmap(0,6,3,MAP_SHARED,fd,0);
    CHECK(m!=MAP_FAILED && m[0]=='a');
    char *n=mmap(0,6,3,MAP_SHARED,fd,0);
    CHECK(n!=MAP_FAILED);
    m[0]='X'; CHECK(n[0]=='X');
    CHECK(syscall(227,m,6,4)==0);
    int other=open("edge-data",0);char b[8]={0};
    CHECK(read(other,b,6)==6 && b[0]=='X');close(other);
    other=open("edge-data",O_RDWR);
    CHECK(write(other,"Y",1)==1 && m[0]=='Y');close(other);
    int pid=fork(),status=-1;
    CHECK(pid>=0);
    if(pid==0){m[1]='Z';exit(0);}
    CHECK(waitpid(pid,&status,0)==pid && status==0 && n[1]=='Z');
    CHECK(unlink("edge-data")==0);
    CHECK(open("edge-data",0)==-2);
    CHECK(syscall(62,fd,0,0)==0);
    CHECK(read(fd,b,6)==6 && b[0]=='Y' && b[1]=='Z');
    CHECK(close(fd)==0);
    CHECK(munmap(m,6)==0 && munmap(n,6)==0);
    fd=open("text.txt",0);
    CHECK(syscall(24,fd,100,0x80000)==100);
    CHECK(syscall(24,fd,101,0)==101);
    pid=fork();CHECK(pid>=0);
    if(pid==0){
        char *a[]={"basic_edges","child",0};char *e[]={0};
        execve("basic_edges",a,e);exit(99);
    }
    CHECK(waitpid(pid,&status,0)==pid && status==0);
    char *bad[]={"no-such",0};char *env[]={0};
    CHECK(execve("no-such",bad,env)==-2);
    CHECK(read(fd,b,1)==1);
    close(fd);close(100);close(101);
    CHECK(syscall(40,"/dev/vda2","mnt","vfat",0,0)==0);
    fd=open("mnt/edge-fat",O_CREATE|O_RDWR);
    CHECK(fd>=0 && write(fd,"fat",3)==3);
    CHECK(syscall(39,"mnt",0)==-16);
    CHECK(syscall(62,fd,0,0)==0 && read(fd,b,3)==3 && b[0]=='f');
    close(fd);
    CHECK(unlink("mnt/edge-fat")==0);
    CHECK(syscall(39,"mnt",0)==0);
    for(int i=0;i<40;i++){
        fd=open("edge-reuse",O_CREATE|O_RDWR);CHECK(fd>=0);
        CHECK(write(fd,"reuse",5)==5 && close(fd)==0);
        CHECK(unlink("edge-reuse")==0);
    }
    printf("EDGE CHECKS PASSED\n");
    return 0;
}