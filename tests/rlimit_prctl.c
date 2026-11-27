/* 用户态回归：覆盖 prlimit64/getrlimit/setrlimit、prctl、getcpu、sethostname/setdomainname、
 * settimeofday 与 clock_settime 的正常语义、边界错误码与 fork/权限继承。 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_getrlimit
#define SYS_getrlimit 163
#endif
#ifndef SYS_setrlimit
#define SYS_setrlimit 164
#endif

#define CHECK(expr)                                                                 \
    do {                                                                            \
        if (!(expr)) {                                                              \
            fprintf(stderr, "line %d: %s (errno %d)\n", __LINE__, #expr, errno);    \
            exit(1);                                                                \
        }                                                                           \
    } while (0)

static volatile sig_atomic_t got_pdeath = 0;
static void on_pdeath(int sig) {
    if (sig == SIGUSR1)
        got_pdeath = 1;
}

static void check_rlimits(void) {
    struct rlimit rl;
    for (int res = 0; res < 16; res++) {
        CHECK(syscall(SYS_getrlimit, res, &rl) == 0);
        CHECK(rl.rlim_cur <= rl.rlim_max);
    }
    CHECK(syscall(SYS_getrlimit, 16, &rl) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_getrlimit, RLIMIT_CORE, NULL) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_setrlimit, 16, &rl) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_setrlimit, RLIMIT_CORE, NULL) == -1 && errno == EFAULT);

    struct rlimit bad = { .rlim_cur = 200, .rlim_max = 100 };
    CHECK(syscall(SYS_setrlimit, RLIMIT_CORE, &bad) == -1 && errno == EINVAL);

    struct rlimit core_new = { .rlim_cur = 4096, .rlim_max = 8192 };
    struct rlimit core_old = { 0 };
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, &core_new, &core_old) == 0);
    struct rlimit core_cur = { 0 };
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, NULL, &core_cur) == 0);
    CHECK(core_cur.rlim_cur == 4096 && core_cur.rlim_max == 8192);

    /* old_limit 指针非法时不得修改目标限额（原子回滚） */
    struct rlimit core_try = { .rlim_cur = 1024, .rlim_max = 2048 };
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, &core_try, (void *)0x1000) == -1 &&
          errno == EFAULT);
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, NULL, &core_cur) == 0);
    CHECK(core_cur.rlim_cur == 4096 && core_cur.rlim_max == 8192);

    /* 负 pid 与不存在的 pid 返回 ESRCH */
    CHECK(syscall(SYS_prlimit64, -1, RLIMIT_CORE, NULL, &core_cur) == -1 && errno == ESRCH);
    CHECK(syscall(SYS_prlimit64, 999999, RLIMIT_CORE, NULL, &core_cur) == -1 && errno == ESRCH);

    /* 跨进程 prlimit64 + 非特权抬高硬限额 EPERM */
    int p2c[2], c2p[2];
    CHECK(pipe(p2c) == 0 && pipe(c2p) == 0);
    pid_t parent_pid = getpid();
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        close(p2c[1]);
        close(c2p[0]);
        struct rlimit inherited = { 0 };
        CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, NULL, &inherited) == 0);
        CHECK(inherited.rlim_cur == 4096 && inherited.rlim_max == 8192);
        CHECK(write(c2p[1], "k", 1) == 1);
        close(c2p[1]);
        char b;
        CHECK(read(p2c[0], &b, 1) == 1);
        close(p2c[0]);
        CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, NULL, &inherited) == 0);
        CHECK(inherited.rlim_cur == 2048 && inherited.rlim_max == 4096);
        /* 降权后不得抬高硬限额，也不得读取 root 父进程限额 */
        CHECK(setresuid(1000, 1000, 1000) == 0);
        struct rlimit raise = { .rlim_cur = 2048, .rlim_max = 8192 };
        CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, &raise, NULL) == -1 && errno == EPERM);
        CHECK(syscall(SYS_prlimit64, parent_pid, RLIMIT_CORE, NULL, &inherited) == -1 &&
              errno == EPERM);
        _exit(0);
    }
    close(p2c[0]);
    close(c2p[1]);
    char ack = 0;
    CHECK(read(c2p[0], &ack, 1) == 1 && ack == 'k');
    close(c2p[0]);
    struct rlimit child_set = { .rlim_cur = 2048, .rlim_max = 4096 };
    struct rlimit child_old = { 0 };
    CHECK(syscall(SYS_prlimit64, child, RLIMIT_CORE, &child_set, &child_old) == 0);
    CHECK(child_old.rlim_cur == 4096 && child_old.rlim_max == 8192);
    CHECK(write(p2c[1], "x", 1) == 1);
    close(p2c[1]);
    int st = 0;
    CHECK(waitpid(child, &st, 0) == child && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_CORE, &core_old, NULL) == 0);
}

static void check_prctl(void) {
    /* NAME + /proc/self/stat 同步 */
    char name[16] = { 0 };
    CHECK(prctl(PR_SET_NAME, "ouro-test-123456789", 0, 0, 0) == 0);
    CHECK(prctl(PR_GET_NAME, name, 0, 0, 0) == 0);
    CHECK(strcmp(name, "ouro-test-12345") == 0);
    CHECK(prctl(PR_SET_NAME, (void *)0x1000, 0, 0, 0) == -1 && errno == EFAULT);
    CHECK(prctl(PR_GET_NAME, (void *)0x1000, 0, 0, 0) == -1 && errno == EFAULT);
    int sfd = open("/proc/self/stat", O_RDONLY);
    CHECK(sfd >= 0);
    char statbuf[512] = { 0 };
    ssize_t sn = read(sfd, statbuf, sizeof(statbuf) - 1);
    close(sfd);
    CHECK(sn > 0 && strstr(statbuf, "(ouro-test-12345)") != NULL);

    /* DUMPABLE / KEEPCAPS / TIMING / ENDIAN / SECCOMP / THP_DISABLE / TIMERSLACK */
    CHECK(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 1);
    CHECK(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
    CHECK(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
    CHECK(prctl(PR_SET_DUMPABLE, 2, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0);

    CHECK(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0);
    CHECK(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
    CHECK(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 1);
    CHECK(prctl(PR_SET_KEEPCAPS, 2, 0, 0, 0) == -1 && errno == EINVAL);
    CHECK(prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) == 0);

    CHECK(prctl(PR_GET_TIMING, 0, 0, 0, 0) == 0);
    CHECK(prctl(PR_SET_TIMING, 0, 0, 0, 0) == 0);
    CHECK(prctl(PR_SET_TIMING, 1, 0, 0, 0) == -1 && errno == EINVAL);

    int endian = -1;
    CHECK(prctl(PR_GET_ENDIAN, &endian, 0, 0, 0) == 0 && endian == PR_ENDIAN_LITTLE);
    CHECK(prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == 0);

    CHECK(prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000);
    CHECK(prctl(PR_SET_TIMERSLACK, 70000, 0, 0, 0) == 0);
    CHECK(prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 70000);
    /* fork 后子进程 default_timer_slack_ns 继承父当前值（70000），重置为 0 时回到 70000 */
    pid_t slack_child = fork();
    CHECK(slack_child >= 0);
    if (slack_child == 0) {
        CHECK(prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 70000);
        CHECK(prctl(PR_SET_TIMERSLACK, 12345, 0, 0, 0) == 0);
        CHECK(prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0) == 0);
        CHECK(prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 70000);
        _exit(0);
    }
    int st = 0;
    CHECK(waitpid(slack_child, &st, 0) == slack_child && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(prctl(PR_SET_TIMERSLACK, 0, 0, 0, 0) == 0);
    CHECK(prctl(PR_GET_TIMERSLACK, 0, 0, 0, 0) == 50000);

    /* /proc/self/comm 与 /proc/self/timerslack_ns */
    int cfd = open("/proc/self/comm", O_RDONLY);
    CHECK(cfd >= 0);
    char commbuf[64] = { 0 };
    ssize_t cn = read(cfd, commbuf, sizeof(commbuf) - 1);
    close(cfd);
    CHECK(cn > 0 && strcmp(commbuf, "ouro-test-12345\n") == 0);

    CHECK(prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 0);
    CHECK(prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0) == 0);
    CHECK(prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 1);
    CHECK(prctl(PR_SET_THP_DISABLE, 0, 0, 0, 0) == 0);

    /* CAPBSET & SECUREBITS */
    CHECK(prctl(PR_CAPBSET_READ, 0, 0, 0, 0) == 1);
    CHECK(prctl(PR_CAPBSET_READ, 99, 0, 0, 0) == -1 && errno == EINVAL);
    pid_t cap_child = fork();
    CHECK(cap_child >= 0);
    if (cap_child == 0) {
        CHECK(prctl(PR_CAPBSET_DROP, 0, 0, 0, 0) == 0);
        CHECK(prctl(PR_CAPBSET_READ, 0, 0, 0, 0) == 0);
        CHECK(prctl(PR_SET_SECUREBITS, 0x3, 0, 0, 0) == 0);
        CHECK(prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == 0x3);
        CHECK(prctl(PR_SET_SECUREBITS, 0x0, 0, 0, 0) == -1 && errno == EPERM);
        CHECK(prctl(PR_SET_SECUREBITS, 0x100, 0, 0, 0) == -1 && errno == EINVAL);
        /* capset(91) 撤掉 CAP_SYS_TIME 后 settimeofday 必须返回 EPERM */
        struct {
            uint32_t version;
            int pid;
        } hdr = { 0x20080522u, 0 };
        struct {
            uint32_t effective;
            uint32_t permitted;
            uint32_t inheritable;
        } data[2] = { { 0 } };
        CHECK(syscall(SYS_capget, &hdr, data) == 0);
        data[0].effective &= ~(1u << 25);
        CHECK(syscall(SYS_capset, &hdr, data) == 0);
        struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 0 };
        CHECK(syscall(SYS_settimeofday, &tv, NULL) == -1 && errno == EPERM);
        _exit(0);
    }
    CHECK(waitpid(cap_child, &st, 0) == cap_child && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* PDEATHSIG：父进程退出时向子进程投递 SIGUSR1，且 fork 清零 */
    int pdeath_pipe[2], ready_pipe[2];
    CHECK(pipe(pdeath_pipe) == 0 && pipe(ready_pipe) == 0);
    pid_t mid = fork();
    CHECK(mid >= 0);
    if (mid == 0) {
        close(pdeath_pipe[0]);
        pid_t grand = fork();
        CHECK(grand >= 0);
        if (grand == 0) {
            close(ready_pipe[0]);
            struct sigaction sa = { .sa_handler = on_pdeath };
            sigemptyset(&sa.sa_mask);
            CHECK(sigaction(SIGUSR1, &sa, NULL) == 0);
            CHECK(prctl(PR_SET_PDEATHSIG, 65, 0, 0, 0) == -1 && errno == EINVAL);
            CHECK(prctl(PR_SET_PDEATHSIG, SIGUSR1, 0, 0, 0) == 0);
            int got = -1;
            CHECK(prctl(PR_GET_PDEATHSIG, &got, 0, 0, 0) == 0 && got == SIGUSR1);
            CHECK(write(ready_pipe[1], "r", 1) == 1);
            close(ready_pipe[1]);
            for (int i = 0; i < 200 && !got_pdeath; i++) {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
                nanosleep(&ts, NULL);
            }
            char res = got_pdeath ? 'Y' : 'N';
            CHECK(write(pdeath_pipe[1], &res, 1) == 1);
            close(pdeath_pipe[1]);
            _exit(got_pdeath ? 0 : 2);
        }
        close(pdeath_pipe[1]);
        close(ready_pipe[1]);
        char rch = 0;
        CHECK(read(ready_pipe[0], &rch, 1) == 1 && rch == 'r');
        close(ready_pipe[0]);
        /* 孙子已装好 PDEATHSIG，父进程立即退出触发投递 */
        _exit(0);
    }
    close(pdeath_pipe[1]);
    close(ready_pipe[0]);
    close(ready_pipe[1]);
    char res_ch = 0;
    CHECK(waitpid(mid, &st, 0) == mid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(read(pdeath_pipe[0], &res_ch, 1) == 1 && res_ch == 'Y');
    close(pdeath_pipe[0]);

    /* CHILD_SUBREAPER：祖父接管孙子并可 waitpid 收割 */
    pid_t sub_root = fork();
    CHECK(sub_root >= 0);
    if (sub_root == 0) {
        CHECK(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
        int sr = 0;
        CHECK(prctl(PR_GET_CHILD_SUBREAPER, &sr, 0, 0, 0) == 0 && sr == 1);
        pid_t me = getpid();
        int sp[2];
        CHECK(pipe(sp) == 0);
        pid_t p1 = fork();
        CHECK(p1 >= 0);
        if (p1 == 0) {
            close(sp[0]);
            /* fork 必须清零 child_subreaper */
            int child_sr = 1;
            CHECK(prctl(PR_GET_CHILD_SUBREAPER, &child_sr, 0, 0, 0) == 0 && child_sr == 0);
            pid_t p2 = fork();
            CHECK(p2 >= 0);
            if (p2 == 0) {
                /* 等 p1 退出，确认被 sub_root 接管 */
                for (int i = 0; i < 200 && getppid() != me; i++) {
                    struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000 };
                    nanosleep(&ts, NULL);
                }
                pid_t mypid = getpid();
                CHECK(write(sp[1], &mypid, sizeof(mypid)) == sizeof(mypid));
                close(sp[1]);
                _exit(getppid() == me ? 42 : 99);
            }
            close(sp[1]);
            _exit(0);
        }
        close(sp[1]);
        CHECK(waitpid(p1, &st, 0) == p1 && WIFEXITED(st) && WEXITSTATUS(st) == 0);
        pid_t gpid = 0;
        CHECK(read(sp[0], &gpid, sizeof(gpid)) == sizeof(gpid));
        close(sp[0]);
        CHECK(waitpid(gpid, &st, 0) == gpid && WIFEXITED(st) && WEXITSTATUS(st) == 42);
        _exit(0);
    }
    CHECK(waitpid(sub_root, &st, 0) == sub_root && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* NO_NEW_PRIVS + /proc/self/status */
    pid_t nnp = fork();
    CHECK(nnp >= 0);
    if (nnp == 0) {
        CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 0);
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) == -1 && errno == EINVAL);
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 1, 0, 0) == -1 && errno == EINVAL);
        CHECK(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
        int fd = open("/proc/self/status", O_RDONLY);
        CHECK(fd >= 0);
        char buf[512] = { 0 };
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        CHECK(n > 0 && strstr(buf, "NoNewPrivs:\t1") != NULL);
        _exit(0);
    }
    CHECK(waitpid(nnp, &st, 0) == nnp && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void check_getcpu_uts_time(void) {
    unsigned cpu = 99, node = 99;
    CHECK(syscall(SYS_getcpu, &cpu, &node, NULL) == 0 && cpu == 0 && node == 0);
    CHECK(syscall(SYS_getcpu, NULL, NULL, NULL) == 0);
    CHECK(syscall(SYS_getcpu, (void *)0x1000, NULL, NULL) == -1 && errno == EFAULT);

    struct utsname orig = { 0 }, now = { 0 };
    CHECK(uname(&orig) == 0);
    CHECK(syscall(SYS_sethostname, "ouro-host", 9) == 0);
    CHECK(syscall(SYS_setdomainname, "ouro-dom", 8) == 0);
    CHECK(uname(&now) == 0);
    CHECK(strcmp(now.nodename, "ouro-host") == 0);
    CHECK(strcmp(now.domainname, "ouro-dom") == 0);
    CHECK(syscall(SYS_sethostname, "x", 65) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_setdomainname, "x", (size_t)-1) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_sethostname, (void *)0x1000, 4) == -1 && errno == EFAULT);

    pid_t unpriv = fork();
    CHECK(unpriv >= 0);
    if (unpriv == 0) {
        CHECK(setresuid(1000, 1000, 1000) == 0);
        CHECK(syscall(SYS_sethostname, "denied", 6) == -1 && errno == EPERM);
        CHECK(syscall(SYS_setdomainname, "denied", 6) == -1 && errno == EPERM);
        struct timeval tv = { .tv_sec = 1700000000, .tv_usec = 0 };
        CHECK(syscall(SYS_settimeofday, &tv, NULL) == -1 && errno == EPERM);
        struct timespec ts = { .tv_sec = 1700000000, .tv_nsec = 0 };
        CHECK(syscall(SYS_clock_settime, CLOCK_REALTIME, &ts) == -1 && errno == EPERM);
        _exit(0);
    }
    int st = 0;
    CHECK(waitpid(unpriv, &st, 0) == unpriv && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(syscall(SYS_sethostname, orig.nodename, strlen(orig.nodename)) == 0);
    CHECK(syscall(SYS_setdomainname, orig.domainname, strlen(orig.domainname)) == 0);

    /* settimeofday & clock_settime */
    struct timespec saved_real = { 0 }, mono_before = { 0 }, mono_after = { 0 };
    CHECK(clock_gettime(CLOCK_REALTIME, &saved_real) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &mono_before) == 0);
    CHECK(syscall(SYS_settimeofday, NULL, NULL) == 0);
    struct timeval bad_tv = { .tv_sec = 100, .tv_usec = 1000000 };
    CHECK(syscall(SYS_settimeofday, &bad_tv, NULL) == -1 && errno == EINVAL);
    bad_tv.tv_sec = -1;
    bad_tv.tv_usec = 0;
    CHECK(syscall(SYS_settimeofday, &bad_tv, NULL) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_settimeofday, (void *)0x1000, NULL) == -1 && errno == EFAULT);

    struct timeval target_tv = { .tv_sec = 1730000000, .tv_usec = 250000 };
    CHECK(syscall(SYS_settimeofday, &target_tv, NULL) == 0);
    struct timeval got_tv = { 0 };
    CHECK(gettimeofday(&got_tv, NULL) == 0);
    CHECK(got_tv.tv_sec >= 1730000000 && got_tv.tv_sec <= 1730000005);

    struct timespec bad_ts = { .tv_sec = 100, .tv_nsec = 1000000000 };
    CHECK(syscall(SYS_clock_settime, CLOCK_REALTIME, &bad_ts) == -1 && errno == EINVAL);
    struct timespec ok_ts = { .tv_sec = 1740000000, .tv_nsec = 500000000 };
    CHECK(syscall(SYS_clock_settime, CLOCK_MONOTONIC, &ok_ts) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_clock_settime, CLOCK_REALTIME, &ok_ts) == 0);
    struct timespec got_ts = { 0 };
    CHECK(clock_gettime(CLOCK_REALTIME, &got_ts) == 0);
    CHECK(got_ts.tv_sec >= 1740000000 && got_ts.tv_sec <= 1740000005);

    /* 恢复墙钟并确认单调时钟未回退 */
    CHECK(syscall(SYS_clock_settime, CLOCK_REALTIME, &saved_real) == 0);
    CHECK(clock_gettime(CLOCK_MONOTONIC, &mono_after) == 0);
    CHECK(mono_after.tv_sec > mono_before.tv_sec ||
          (mono_after.tv_sec == mono_before.tv_sec && mono_after.tv_nsec >= mono_before.tv_nsec));
}

int main(void) {
    check_rlimits();
    check_prctl();
    check_getcpu_uts_time();
    puts("rlimit/prctl/uts/time regression passed");
    return 0;
}
