/* 自有错误路径和共享状态回归，不修改官方程序。 */
#include "unistd.h"
#include "stdio.h"
#include "string.h"
#include "syscall.h"
#define CHECK(x) do { if (!(x)) { printf("EDGE FAIL line %d\n",__LINE__); return 1; } } while(0)
int main(int argc, char **argv) {
    if (argc > 1) {
        char b;
        CHECK(read(100,&b,1)==-9);
        CHECK(read(101,&b,1)==1);
        return 0;
    }
    CHECK(chdir("/basic")==0);
    CHECK(open("text.txt/child",0)==-20);
    CHECK(open("missing/../text.txt",0)==-2);
    CHECK(open("text.txt/../text.txt",0)==-20);
    int fd=open("edge-data",O_CREATE|O_RDWR);
    CHECK(fd>=0);
    CHECK(write(fd,"abcdef",6)==6);
    char *m=mmap(0,6,3,MAP_SHARED,fd,0);
    CHECK(m!=MAP_FAILED && m[0]=='a');
    char *n=mmap(0,6,3,MAP_SHARED,fd,0);
    CHECK(n!=MAP_FAILED);
    m[0]='X'; CHECK(n[0]=='X');
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