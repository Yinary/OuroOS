#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t got_sig = 0;
static volatile int got_code = 0;
static volatile int got_tid = -1;
static volatile int got_overrun = -1;
static volatile long got_val = 0;

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    got_sig = sig;
    got_code = si->si_code;
    got_tid = si->si_timerid;
    got_overrun = si->si_overrun;
    got_val = (long)si->si_value.sival_int;
}

static void check_cond(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s (errno=%d)\n", msg, errno);
        _exit(1);
    }
}

struct kernel_sigevent {
    union sigval sigev_value;
    int sigev_signo;
    int sigev_notify;
    int sigev_tid;
    int _pad[11];
};

static long sys_timer_create(clockid_t clk, void *sevp, int *tid) {
    return syscall(SYS_timer_create, clk, sevp, tid);
}
static long sys_timer_settime(int tid, int flags, const struct itimerspec *n, struct itimerspec *o) {
    return syscall(SYS_timer_settime, tid, flags, n, o);
}
static long sys_timer_gettime(int tid, struct itimerspec *c) {
    return syscall(SYS_timer_gettime, tid, c);
}
static long sys_timer_getoverrun(int tid) {
    return syscall(SYS_timer_getoverrun, tid);
}
static long sys_timer_delete(int tid) {
    return syscall(SYS_timer_delete, tid);
}

int main(void) {
    int tid = -1;

    /* 1. Error paths on timer_create / delete / gettime / settime / getoverrun */
    check_cond(sys_timer_create(-1, NULL, &tid) == -1 && errno == EINVAL, "invalid clockid -1");
    check_cond(sys_timer_create(16, NULL, &tid) == -1 && errno == EINVAL, "invalid clockid 16");
    check_cond(sys_timer_create(CLOCK_MONOTONIC_RAW, NULL, &tid) == -1 && errno == EOPNOTSUPP, "MONOTONIC_RAW EOPNOTSUPP");
    check_cond(sys_timer_create(CLOCK_MONOTONIC, NULL, NULL) == -1 && errno == EFAULT, "NULL timerid EFAULT");
    check_cond(sys_timer_delete(999) == -1 && errno == EINVAL, "delete nonexistent");
    check_cond(sys_timer_getoverrun(999) == -1 && errno == EINVAL, "getoverrun nonexistent");
    struct itimerspec its;
    check_cond(sys_timer_gettime(999, &its) == -1 && errno == EINVAL, "gettime nonexistent");
    check_cond(sys_timer_settime(999, 0, NULL, NULL) == -1 && errno == EINVAL, "settime NULL new_value");

    /* 2. SIGEV_SIGNAL + SI_TIMER + sigval + old_value */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = handler;
    check_cond(sigaction(SIGUSR1, &sa, NULL) == 0, "sigaction SIGUSR1");

    struct kernel_sigevent sev;
    memset(&sev, 0, sizeof(sev));
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGUSR1;
    sev.sigev_value.sival_int = 0x1234;
    check_cond(sys_timer_create(CLOCK_MONOTONIC, &sev, &tid) == 0, "create MONOTONIC");

    /* Check bad timespec */
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 1000000000L;
    check_cond(sys_timer_settime(tid, 0, &its, NULL) == -1 && errno == EINVAL, "bad nsec EINVAL");

    /* Arm one-shot 30ms */
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 30 * 1000 * 1000;
    struct itimerspec oldv;
    memset(&oldv, 0xff, sizeof(oldv));
    check_cond(sys_timer_settime(tid, 0, &its, &oldv) == 0, "arm 30ms");
    check_cond(oldv.it_value.tv_sec == 0 && oldv.it_value.tv_nsec == 0, "old_value initially zero");

    /* Query remaining */
    struct itimerspec cur;
    check_cond(sys_timer_gettime(tid, &cur) == 0, "gettime armed");
    check_cond(cur.it_value.tv_sec == 0 && cur.it_value.tv_nsec > 0 && cur.it_value.tv_nsec <= 30000000L, "remaining in range");

    /* Sleep 80ms to let it fire */
    struct timespec slp = {0, 80 * 1000 * 1000};
    nanosleep(&slp, NULL);
    check_cond(got_sig == SIGUSR1, "received SIGUSR1");
    check_cond(got_code == SI_TIMER, "si_code == SI_TIMER");
    check_cond(got_tid == tid, "si_timerid matches");
    check_cond(got_val == 0x1234, "si_value matches");
    check_cond(got_overrun == 0, "one-shot overrun 0");
    check_cond(sys_timer_getoverrun(tid) == 0, "timer_getoverrun 0");

    /* 3. Periodic timer overrun while signal blocked */
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    check_cond(sigprocmask(SIG_BLOCK, &mask, &oldmask) == 0, "block SIGUSR1");

    got_sig = 0;
    got_overrun = -1;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 10 * 1000 * 1000;
    its.it_interval.tv_nsec = 10 * 1000 * 1000;
    check_cond(sys_timer_settime(tid, 0, &its, NULL) == 0, "arm periodic 10ms");

    struct timespec slp2 = {0, 65 * 1000 * 1000};
    nanosleep(&slp2, NULL);
    check_cond(got_sig == 0, "signal held while blocked");

    /* Unblock -> deliver with overrun >= 2 */
    check_cond(sigprocmask(SIG_SETMASK, &oldmask, NULL) == 0, "unblock SIGUSR1");
    check_cond(got_sig == SIGUSR1, "delivered after unblock");
    long ov = sys_timer_getoverrun(tid);
    check_cond(ov >= 1 && got_overrun == ov, "overrun >= 1 and matches si_overrun");

    /* Disarm */
    memset(&its, 0, sizeof(its));
    check_cond(sys_timer_settime(tid, 0, &its, &oldv) == 0, "disarm");
    check_cond(oldv.it_interval.tv_nsec == 10000000L, "old_value interval preserved");
    check_cond(sys_timer_gettime(tid, &cur) == 0 && cur.it_value.tv_nsec == 0 && cur.it_interval.tv_nsec == 0, "disarmed zero");

    /* 4. Large ktime tv_sec (overflow guard, like timer_settime03) must not fire immediately */
    got_sig = 0;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = 0x7fffffffLL;
    check_cond(sys_timer_settime(tid, 0, &its, NULL) == 0, "large tv_sec succeeds");
    struct timespec slp3 = {0, 20 * 1000 * 1000};
    nanosleep(&slp3, NULL);
    check_cond(got_sig == 0, "large tv_sec did not fire prematurely");

    /* 5. Fork does not inherit timers */
    pid_t child = fork();
    check_cond(child >= 0, "fork");
    if (child == 0) {
        if (sys_timer_gettime(tid, &cur) != -1 || errno != EINVAL) _exit(2);
        _exit(0);
    }
    int status = 0;
    check_cond(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child has no parent timers");

    check_cond(sys_timer_delete(tid) == 0, "delete timer");
    check_cond(sys_timer_delete(tid) == -1 && errno == EINVAL, "double delete EINVAL");

    /* 6. SIGEV_NONE + CLOCK_REALTIME + TIMER_ABSTIME + CPU clocks */
    int tid_rt = -1, tid_cpu = -1;
    sev.sigev_notify = SIGEV_NONE;
    check_cond(sys_timer_create(CLOCK_REALTIME, &sev, &tid_rt) == 0, "create REALTIME SIGEV_NONE");
    struct timespec now_rt;
    check_cond(clock_gettime(CLOCK_REALTIME, &now_rt) == 0, "clock_gettime REALTIME");
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = now_rt.tv_sec + 2;
    its.it_value.tv_nsec = now_rt.tv_nsec;
    check_cond(sys_timer_settime(tid_rt, TIMER_ABSTIME, &its, NULL) == 0, "settime REALTIME ABSTIME");
    check_cond(sys_timer_gettime(tid_rt, &cur) == 0 && cur.it_value.tv_sec >= 1, "REALTIME ABSTIME remaining");
    check_cond(sys_timer_delete(tid_rt) == 0, "delete REALTIME timer");

    check_cond(sys_timer_create(CLOCK_PROCESS_CPUTIME_ID, &sev, &tid_cpu) == 0, "create PROCESS_CPUTIME");
    check_cond(sys_timer_delete(tid_cpu) == 0, "delete PROCESS_CPUTIME");

    /* 7. SIGEV_THREAD_ID to self */
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = SIGUSR1;
    sev.sigev_tid = (int)syscall(SYS_gettid);
    sev.sigev_value.sival_int = 0x5678;
    int tid_th = -1;
    check_cond(sys_timer_create(CLOCK_BOOTTIME, &sev, &tid_th) == 0, "create BOOTTIME SIGEV_THREAD_ID");
    got_sig = 0;
    got_val = 0;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 20 * 1000 * 1000;
    check_cond(sys_timer_settime(tid_th, 0, &its, NULL) == 0, "arm SIGEV_THREAD_ID");
    struct timespec slp4 = {0, 60 * 1000 * 1000};
    nanosleep(&slp4, NULL);
    check_cond(got_sig == SIGUSR1 && got_val == 0x5678, "SIGEV_THREAD_ID delivered");
    check_cond(sys_timer_delete(tid_th) == 0, "delete BOOTTIME timer");

    printf("posix_timers regression passed\n");
    return 0;
}
