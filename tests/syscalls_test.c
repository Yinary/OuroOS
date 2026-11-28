#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_kcmp
#define SYS_kcmp 272
#endif
#ifndef SYS_execveat
#define SYS_execveat 281
#endif
#ifndef SYS_membarrier
#define SYS_membarrier 283
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
#endif
#ifndef SYS_openat2
#define SYS_openat2 437
#endif

struct open_how_u {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct clone_args_u {
    uint64_t flags;
    uint64_t pidfd;
    uint64_t child_tid;
    uint64_t parent_tid;
    uint64_t exit_signal;
    uint64_t stack;
    uint64_t stack_size;
    uint64_t tls;
    uint64_t set_tid;
    uint64_t set_tid_size;
    uint64_t cgroup;
};

static void die(const char *msg) {
    printf("FAIL: %s (errno=%d)\n", msg, errno);
    _exit(1);
}

int main(void) {
    mkdir("/tmp", 0777);
    mkdir("/tmp/o2dir", 0755);

    long mask = syscall(SYS_membarrier, 0, 0);
    if (mask <= 0 || !(mask & (1 << 3)))
        die("membarrier query");
    if (syscall(SYS_membarrier, 1 << 3, 0) != -1 || errno != EPERM)
        die("membarrier unreg EPERM");
    if (syscall(SYS_membarrier, 1 << 4, 0) != 0)
        die("membarrier register private");
    if (syscall(SYS_membarrier, 1 << 3, 0) != 0)
        die("membarrier private expedited");
    if (syscall(SYS_membarrier, 0, 1) != -1 || errno != EINVAL)
        die("membarrier bad flags");

    int dfd = open("/tmp/o2dir", O_RDONLY | O_DIRECTORY);
    if (dfd < 0)
        die("open /tmp/o2dir");
    struct open_how_u how = {.flags = O_CREAT | O_RDWR | O_TRUNC, .mode = 0644, .resolve = 0x08};
    int f1 = syscall(SYS_openat2, dfd, "hello.txt", &how, sizeof(how));
    if (f1 < 0)
        die("openat2 create beneath");
    how.flags = O_RDONLY;
    how.mode = 0;
    if (syscall(SYS_openat2, dfd, "../o2dir/hello.txt", &how, sizeof(how)) != -1 || errno != EXDEV)
        die("openat2 RESOLVE_BENEATH escape");
    how.resolve = 0x10;
    int f2 = syscall(SYS_openat2, dfd, "/../../hello.txt", &how, sizeof(how));
    if (f2 < 0)
        die("openat2 RESOLVE_IN_ROOT");
    how.mode = 0644;
    how.resolve = 0;
    if (syscall(SYS_openat2, dfd, "hello.txt", &how, sizeof(how)) != -1 || errno != EINVAL)
        die("openat2 nonzero mode without O_CREAT");
    how.mode = 0;
    if (syscall(SYS_openat2, dfd, "hello.txt", &how, 8) != -1 || errno != EINVAL)
        die("openat2 small size");

    int f1_dup = dup(f1);
    if (f1_dup < 0)
        die("dup f1");
    pid_t me = getpid();
    if (syscall(SYS_kcmp, me, me, 0, f1, f1_dup) != 0)
        die("kcmp dup same file");
    long diff = syscall(SYS_kcmp, me, me, 0, f1, f2);
    if (diff != 1 && diff != 2)
        die("kcmp distinct opens");
    if (syscall(SYS_kcmp, me, me, 1, 0, 0) != 0)
        die("kcmp VM self");
    if (syscall(SYS_kcmp, me, me, 99, 0, 0) != -1 || errno != EINVAL)
        die("kcmp bad type");

    struct clone_args_u ca;
    memset(&ca, 0, sizeof(ca));
    ca.exit_signal = SIGCHLD;
    if (syscall(SYS_clone3, &ca, 16) != -1 || errno != EINVAL)
        die("clone3 small size");
    ca.stack = 0x1000;
    ca.stack_size = 0;
    if (syscall(SYS_clone3, &ca, sizeof(ca)) != -1 || errno != EINVAL)
        die("clone3 stack without size");
    ca.stack = 0;
    pid_t cpid = syscall(SYS_clone3, &ca, sizeof(ca));
    if (cpid < 0)
        die("clone3 fork");
    if (cpid == 0)
        _exit(42);
    int st = 0;
    if (waitpid(cpid, &st, 0) != cpid || !WIFEXITED(st) || WEXITSTATUS(st) != 42)
        die("clone3 waitpid");

    char *const argv[] = {"test", NULL};
    char *const envp[] = {NULL};
    if (syscall(SYS_execveat, dfd, "", argv, envp, 0x1000) != -1 || errno != EACCES)
        die("execveat dirfd AT_EMPTY_PATH EACCES");
    if (syscall(SYS_execveat, dfd, "hello.txt", argv, envp, 0x1234) != -1 || errno != EINVAL)
        die("execveat invalid flags");

    close(f1_dup);
    close(f2);
    close(f1);
    close(dfd);
    unlink("/tmp/o2dir/hello.txt");
    rmdir("/tmp/o2dir");
    printf("syscalls_test: ALL PASS\n");
    return 0;
}
