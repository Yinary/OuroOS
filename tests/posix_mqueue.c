#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct kernel_mq_attr {
    long mq_flags;
    long mq_maxmsg;
    long mq_msgsize;
    long mq_curmsgs;
    long __reserved[4];
};

struct kernel_sigevent {
    union sigval sigev_value;
    int sigev_signo;
    int sigev_notify;
    int sigev_tid;
    int _pad[11];
};

static volatile sig_atomic_t got_sig = 0;
static volatile int got_code = 0;
static volatile long got_val = 0;

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    got_sig = sig;
    got_code = si->si_code;
    got_val = (long)si->si_value.sival_int;
}

static void check_cond(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno);
        _exit(1);
    }
}

static long sys_mq_open(const char *name, int oflag, mode_t mode, struct kernel_mq_attr *attr) {
    return syscall(SYS_mq_open, name, oflag, mode, attr);
}
static long sys_mq_unlink(const char *name) {
    return syscall(SYS_mq_unlink, name);
}
static long sys_mq_timedsend(int mqd, const char *buf, size_t len, unsigned int prio, const struct timespec *ts) {
    return syscall(SYS_mq_timedsend, mqd, buf, len, prio, ts);
}
static long sys_mq_timedreceive(int mqd, char *buf, size_t len, unsigned int *prio, const struct timespec *ts) {
    return syscall(SYS_mq_timedreceive, mqd, buf, len, prio, ts);
}
static long sys_mq_notify(int mqd, const void *sevp) {
    return syscall(SYS_mq_notify, mqd, sevp);
}
static long sys_mq_getsetattr(int mqd, const struct kernel_mq_attr *newa, struct kernel_mq_attr *olda) {
    return syscall(SYS_mq_getsetattr, mqd, newa, olda);
}

int main(void) {
    const char *qname = "ouro_mq_test";
    sys_mq_unlink(qname);

    /* 1. Error paths */
    check_cond(sys_mq_open("", O_RDONLY, 0600, NULL) == -1 && errno == ENOENT, "empty name ENOENT");
    check_cond(sys_mq_open("a/b", O_RDONLY | O_CREAT, 0600, NULL) == -1 && errno == EACCES, "slash name EACCES");
    check_cond(sys_mq_open(qname, O_RDONLY, 0600, NULL) == -1 && errno == ENOENT, "nonexistent ENOENT");
    check_cond(sys_mq_unlink(qname) == -1 && errno == ENOENT, "unlink nonexistent ENOENT");

    struct kernel_mq_attr bad = {0, 0, 16, 0, {0}};
    check_cond(sys_mq_open(qname, O_RDWR | O_CREAT, 0600, &bad) == -1 && errno == EINVAL, "maxmsg 0 EINVAL");

    /* 2. Create with custom attrs & O_EXCL */
    struct kernel_mq_attr attr = {0, 4, 64, 0, {0}};
    int mqd = (int)sys_mq_open(qname, O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK, 0644, &attr);
    check_cond(mqd >= 0, "mq_open create");
    check_cond(sys_mq_open(qname, O_RDWR | O_CREAT | O_EXCL, 0644, &attr) == -1 && errno == EEXIST, "O_EXCL EEXIST");

    /* Check FD_CLOEXEC auto-set */
    int fdflags = fcntl(mqd, F_GETFD);
    check_cond((fdflags & FD_CLOEXEC) != 0, "FD_CLOEXEC auto-set");

    /* 3. getsetattr */
    struct kernel_mq_attr olda;
    memset(&olda, 0, sizeof(olda));
    check_cond(sys_mq_getsetattr(mqd, NULL, &olda) == 0, "getsetattr query");
    check_cond(olda.mq_maxmsg == 4 && olda.mq_msgsize == 64 && olda.mq_curmsgs == 0 && (olda.mq_flags & O_NONBLOCK), "attr values");

    /* 4. Priority ordering + FIFO + EMSGSIZE + EAGAIN */
    check_cond(sys_mq_timedsend(mqd, "lo", 2, 1, NULL) == 0, "send prio 1");
    check_cond(sys_mq_timedsend(mqd, "hi1", 3, 10, NULL) == 0, "send prio 10 #1");
    check_cond(sys_mq_timedsend(mqd, "hi2", 3, 10, NULL) == 0, "send prio 10 #2");
    check_cond(sys_mq_timedsend(mqd, "mid", 3, 5, NULL) == 0, "send prio 5");
    check_cond(sys_mq_timedsend(mqd, "full", 4, 1, NULL) == -1 && errno == EAGAIN, "full EAGAIN");

    char big[128];
    memset(big, 'x', sizeof(big));
    check_cond(sys_mq_timedsend(mqd, big, 65, 1, NULL) == -1 && errno == EMSGSIZE, "send > msgsize EMSGSIZE");

    /* poll sees readable */
    struct pollfd pfd = {mqd, POLLIN | POLLOUT, 0};
    check_cond(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN) && !(pfd.revents & POLLOUT), "poll full -> POLLIN only");

    char buf[64];
    unsigned int prio = 0;
    check_cond(sys_mq_timedreceive(mqd, buf, 16, &prio, NULL) == -1 && errno == EMSGSIZE, "recv < msgsize EMSGSIZE");

    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, NULL) == 3 && memcmp(buf, "hi1", 3) == 0 && prio == 10, "recv hi1");
    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, NULL) == 3 && memcmp(buf, "hi2", 3) == 0 && prio == 10, "recv hi2");
    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, NULL) == 3 && memcmp(buf, "mid", 3) == 0 && prio == 5, "recv mid");
    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, NULL) == 2 && memcmp(buf, "lo", 2) == 0 && prio == 1, "recv lo");
    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, NULL) == -1 && errno == EAGAIN, "empty EAGAIN");

    /* 5. mq_notify (SIGEV_SIGNAL + EBUSY + one-shot + SI_MESGQ) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    check_cond(sigaction(SIGUSR2, &sa, NULL) == 0, "sigaction SIGUSR2");

    struct kernel_sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR2;
    sev.sigev_value.sival_int = 0x777;
    check_cond(sys_mq_notify(mqd, &sev) == 0, "mq_notify register");
    check_cond(sys_mq_notify(mqd, &sev) == -1 && errno == EBUSY, "mq_notify duplicate EBUSY");

    got_sig = 0;
    check_cond(sys_mq_timedsend(mqd, "ping", 4, 2, NULL) == 0, "send triggers notify");
    check_cond(got_sig == SIGUSR2 && got_code == SI_MESGQ && got_val == 0x777, "received SI_MESGQ");
    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, NULL) == 4, "drain ping");

    /* 6. Blocking receive with timeout -> ETIMEDOUT, and cross-process blocking wake */
    struct kernel_mq_attr blk = {0, 0, 0, 0, {0}};
    check_cond(sys_mq_getsetattr(mqd, &blk, NULL) == 0, "clear O_NONBLOCK");
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_nsec += 30 * 1000 * 1000;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, &ts) == -1 && errno == ETIMEDOUT, "timedreceive ETIMEDOUT");

    pid_t pid = fork();
    check_cond(pid >= 0, "fork");
    if (pid == 0) {
        struct timespec d = {0, 30 * 1000 * 1000};
        nanosleep(&d, NULL);
        sys_mq_timedsend(mqd, "from_child", 10, 7, NULL);
        _exit(0);
    }
    check_cond(sys_mq_timedreceive(mqd, buf, 64, &prio, NULL) == 10 && memcmp(buf, "from_child", 10) == 0 && prio == 7, "blocking cross-proc recv");
    int st = 0;
    check_cond(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0, "wait child");

    check_cond(close(mqd) == 0, "close mqd");
    check_cond(sys_mq_unlink(qname) == 0, "mq_unlink");
    printf("posix_mqueue regression passed\n");
    return 0;
}
