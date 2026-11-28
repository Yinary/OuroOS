#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_epoll_pwait2
#define SYS_epoll_pwait2 441
#endif

static void die(const char *msg, int line) {
    printf("FAIL line %d: %s (errno=%d)\n", line, msg, errno);
    _exit(1);
}

#define CHECK(cond) do { if (!(cond)) die(#cond, __LINE__); } while (0)

static uint64_t mono_ms(void) {
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void test_eventfd(void) {
    CHECK(eventfd(0, 0x12345) == -1 && errno == EINVAL);

    int efd = eventfd(3, EFD_NONBLOCK | EFD_CLOEXEC);
    CHECK(efd >= 0);
    CHECK((fcntl(efd, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK((fcntl(efd, F_GETFL) & O_NONBLOCK) != 0);

    uint32_t small = 0;
    CHECK(read(efd, &small, sizeof(small)) == -1 && errno == EINVAL);
    CHECK(write(efd, &small, sizeof(small)) == -1 && errno == EINVAL);

    uint64_t v = 0;
    CHECK(read(efd, &v, sizeof(v)) == 8 && v == 3);
    CHECK(read(efd, &v, sizeof(v)) == -1 && errno == EAGAIN);

    v = UINT64_MAX;
    CHECK(write(efd, &v, sizeof(v)) == -1 && errno == EINVAL);

    v = 10;
    CHECK(write(efd, &v, sizeof(v)) == 8);
    v = 5;
    CHECK(write(efd, &v, sizeof(v)) == 8);
    CHECK(read(efd, &v, sizeof(v)) == 8 && v == 15);
    close(efd);

    int sfd = eventfd(2, EFD_SEMAPHORE | EFD_NONBLOCK);
    CHECK(sfd >= 0);
    CHECK(read(sfd, &v, sizeof(v)) == 8 && v == 1);
    CHECK(read(sfd, &v, sizeof(v)) == 8 && v == 1);
    CHECK(read(sfd, &v, sizeof(v)) == -1 && errno == EAGAIN);
    close(sfd);

    int bfd = eventfd(0, 0);
    CHECK(bfd >= 0);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        sleep_ms(30);
        uint64_t one = 7;
        if (write(bfd, &one, 8) != 8) _exit(2);
        _exit(0);
    }
    CHECK(read(bfd, &v, sizeof(v)) == 8 && v == 7);
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    close(bfd);
}

static void test_timerfd(void) {
    CHECK(timerfd_create(999, 0) == -1 && errno == EINVAL);
    CHECK(timerfd_create(CLOCK_MONOTONIC, 0x1234) == -1 && errno == EINVAL);

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    CHECK(tfd >= 0);

    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 40 * 1000 * 1000;
    its.it_interval.tv_nsec = 25 * 1000 * 1000;
    uint64_t t0 = mono_ms();
    CHECK(timerfd_settime(tfd, 0, &its, NULL) == 0);

    struct itimerspec cur;
    CHECK(timerfd_gettime(tfd, &cur) == 0);
    CHECK(cur.it_interval.tv_nsec == 25 * 1000 * 1000);

    uint64_t exp = 0;
    CHECK(read(tfd, &exp, 8) == 8 && exp >= 1);
    uint64_t dt = mono_ms() - t0;
    CHECK(dt >= 30);

    struct pollfd pfd = { .fd = tfd, .events = POLLIN, .revents = 0 };
    CHECK(poll(&pfd, 1, 200) == 1 && (pfd.revents & POLLIN));
    CHECK(read(tfd, &exp, 8) == 8 && exp >= 1);

    struct itimerspec zero, old;
    memset(&zero, 0, sizeof(zero));
    CHECK(timerfd_settime(tfd, 0, &zero, &old) == 0);
    CHECK(old.it_interval.tv_nsec == 25 * 1000 * 1000);

    CHECK(write(tfd, &exp, 8) == -1 && errno == EINVAL);
    close(tfd);
}

static void test_epoll(void) {
    CHECK(epoll_create1(0x1234) == -1 && errno == EINVAL);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    CHECK(ep >= 0);

    int p[2];
    CHECK(pipe(p) == 0);

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.u64 = 0x1122334455667788ULL;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, ep, &ev) == -1 && errno == EINVAL);

    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) == -1 && errno == EEXIST);

    struct epoll_event out[4];
    CHECK(epoll_pwait(ep, out, 4, 0, NULL) == 0);

    CHECK(epoll_pwait(ep, out, 0, 0, NULL) == -1 && errno == EINVAL);
    CHECK(epoll_pwait(ep, NULL, 1, 0, NULL) == -1 && errno == EFAULT);

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        sleep_ms(30);
        if (write(p[1], "ok", 2) != 2) _exit(2);
        _exit(0);
    }
    int n = epoll_pwait(ep, out, 4, 500, NULL);
    CHECK(n == 1 && (out[0].events & EPOLLIN) && out[0].data.u64 == 0x1122334455667788ULL);
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    ev.events = EPOLLIN | EPOLLET;
    ev.data.u64 = 42;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &ev) == 0);
    CHECK(epoll_pwait(ep, out, 4, 0, NULL) == 1 && out[0].data.u64 == 42);
    CHECK(epoll_pwait(ep, out, 4, 0, NULL) == 0);
    char buf[8];
    CHECK(read(p[0], buf, 2) == 2);
    CHECK(write(p[1], "ab", 2) == 2);
    CHECK(epoll_pwait(ep, out, 4, 0, NULL) == 1);
    CHECK(read(p[0], buf, 2) == 2);

    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.u64 = 99;
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &ev) == 0);
    CHECK(write(p[1], "x", 1) == 1);
    CHECK(epoll_pwait(ep, out, 4, 0, NULL) == 1 && out[0].data.u64 == 99);
    CHECK(epoll_pwait(ep, out, 4, 0, NULL) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_MOD, p[0], &ev) == 0);
    CHECK(epoll_pwait(ep, out, 4, 0, NULL) == 1 && out[0].data.u64 == 99);
    CHECK(read(p[0], buf, 1) == 1);

    int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    CHECK(tfd >= 0);
    ev.events = EPOLLIN;
    ev.data.u64 = 777;
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev) == 0);
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_nsec = 35 * 1000 * 1000;
    CHECK(timerfd_settime(tfd, 0, &its, NULL) == 0);
    struct timespec pwait2_ts = { 0, 500 * 1000 * 1000 };
    n = syscall(SYS_epoll_pwait2, ep, out, 4, &pwait2_ts, NULL, 8);
    CHECK(n == 1 && (out[0].events & EPOLLIN) && out[0].data.u64 == 777);
    uint64_t exp = 0;
    CHECK(read(tfd, &exp, 8) == 8 && exp >= 1);

    int ep2 = epoll_create1(0);
    CHECK(ep2 >= 0);
    ev.events = EPOLLIN;
    ev.data.u64 = 888;
    CHECK(epoll_ctl(ep2, EPOLL_CTL_ADD, ep, &ev) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, ep2, &ev) == -1 && errno == ELOOP);

    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, p[0], NULL) == 0);
    CHECK(epoll_ctl(ep, EPOLL_CTL_DEL, p[0], NULL) == -1 && errno == ENOENT);

    close(ep2);
    close(tfd);
    close(p[0]);
    close(p[1]);
    close(ep);
}

int main(void) {
    test_eventfd();
    test_timerfd();
    test_epoll();
    printf("epoll/eventfd/timerfd regression passed\n");
    return 0;
}
