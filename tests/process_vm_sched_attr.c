#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

struct sched_attr_uapi {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
    uint32_t sched_util_min;
    uint32_t sched_util_max;
};

static volatile sig_atomic_t got_sig = 0;
static volatile int got_code = 0;

static void sig_handler(int sig, siginfo_t *si, void *ucontext) {
    (void)ucontext;
    got_sig = sig;
    got_code = si->si_code;
}

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static void check_process_vm(void) {
    char src[32] = "OuroOS-process-vm-test!";
    char dst[32];
    memset(dst, 0, sizeof(dst));

    struct iovec liov = { .iov_base = dst, .iov_len = strlen(src) };
    struct iovec riov = { .iov_base = src, .iov_len = strlen(src) };
    ssize_t n = process_vm_readv(getpid(), &liov, 1, &riov, 1, 0);
    if (n != (ssize_t)strlen(src) || strcmp(dst, src) != 0)
        die("process_vm_readv self");

    char patch[] = "PATCH";
    struct iovec wliov = { .iov_base = patch, .iov_len = 5 };
    struct iovec wriov = { .iov_base = src, .iov_len = 5 };
    n = process_vm_writev(getpid(), &wliov, 1, &wriov, 1, 0);
    if (n != 5 || memcmp(src, "PATCH", 5) != 0)
        die("process_vm_writev self");

    int p[2];
    if (pipe(p) != 0)
        die("pipe");
    char child_secret[32] = "child-secret-payload";
    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid == 0) {
        close(p[0]);
        uintptr_t addr = (uintptr_t)child_secret;
        if (write(p[1], &addr, sizeof(addr)) != sizeof(addr))
            _exit(2);
        usleep(100000);
        _exit(0);
    }
    close(p[1]);
    uintptr_t caddr = 0;
    if (read(p[0], &caddr, sizeof(caddr)) != sizeof(caddr))
        die("read caddr");
    close(p[0]);

    char cbuf[32];
    memset(cbuf, 0, sizeof(cbuf));
    struct iovec cl = { .iov_base = cbuf, .iov_len = 20 };
    struct iovec cr = { .iov_base = (void *)caddr, .iov_len = 20 };
    n = process_vm_readv(pid, &cl, 1, &cr, 1, 0);
    if (n != 20 || memcmp(cbuf, "child-secret-payload", 20) != 0)
        die("process_vm_readv child");

    int st = 0;
    if (waitpid(pid, &st, 0) != pid)
        die("waitpid");
    printf("process_vm ok\n");
}

static void check_sched_attr(void) {
    struct sched_attr_uapi attr;
    memset(&attr, 0, sizeof(attr));
    if (syscall(SYS_sched_getattr, 0, &attr, sizeof(attr), 0) != 0)
        die("sched_getattr");
    if (attr.size < 48 || attr.sched_policy != 0)
        die("sched_getattr initial");

    attr.sched_policy = 1;
    attr.sched_priority = 10;
    if (syscall(SYS_sched_setattr, 0, &attr, 0) != 0)
        die("sched_setattr FIFO");

    memset(&attr, 0, sizeof(attr));
    if (syscall(SYS_sched_getattr, 0, &attr, sizeof(attr), 0) != 0)
        die("sched_getattr FIFO");
    if (attr.sched_policy != 1 || attr.sched_priority != 10)
        die("sched_getattr verify FIFO");

    attr.sched_policy = 0;
    attr.sched_priority = 0;
    attr.sched_nice = 5;
    if (syscall(SYS_sched_setattr, 0, &attr, 0) != 0)
        die("sched_setattr OTHER");
    memset(&attr, 0, sizeof(attr));
    if (syscall(SYS_sched_getattr, 0, &attr, sizeof(attr), 0) != 0 || attr.sched_nice != 5)
        die("sched_getattr verify nice");
    printf("sched_attr ok\n");
}

static void check_tgsigqueue_ioprio_personality(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sig_handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR1, &sa, NULL) != 0)
        die("sigaction");

    siginfo_t si;
    memset(&si, 0, sizeof(si));
    si.si_signo = SIGUSR1;
    si.si_code = SI_QUEUE;
    si.si_pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);
    if (syscall(SYS_rt_tgsigqueueinfo, getpid(), tid, SIGUSR1, &si) != 0)
        die("rt_tgsigqueueinfo");
    if (got_sig != SIGUSR1 || got_code != SI_QUEUE)
        die("rt_tgsigqueueinfo delivery");

    int be3 = (2 << 13) | 3;
    if (syscall(SYS_ioprio_set, 1, 0, be3) != 0)
        die("ioprio_set");
    if (syscall(SYS_ioprio_get, 1, 0) != be3)
        die("ioprio_get");

    long orig = personality(0xffffffffUL);
    if (orig < 0)
        die("personality query");
    if (personality((unsigned long)orig | ADDR_NO_RANDOMIZE) != orig)
        die("personality set");
    if (personality(0xffffffffUL) != (orig | ADDR_NO_RANDOMIZE))
        die("personality verify");
    personality((unsigned long)orig);
    printf("tgsigqueue_ioprio_personality ok\n");
}

int main(void) {
    check_process_vm();
    check_sched_attr();
    check_tgsigqueue_ioprio_personality();
    printf("process_vm_sched_attr PASS\n");
    return 0;
}
