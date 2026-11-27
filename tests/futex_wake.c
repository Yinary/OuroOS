/* 用户态回归：fork 后 join、共享别名、重排队和超时。用原始 futex 结果识别漏唤醒。 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { WAIT = 0, WAKE = 1, CMP_REQUEUE = 4, WAIT_BITS = 9, WAKE_BITS = 10, PRIVATE = 128 };
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s (errno %d)\n", __LINE__, #expr, errno); exit(1); } } while (0)

static long futex(int *p, int op, int value, uintptr_t fourth, int *to, int bits) {
    return syscall(SYS_futex, p, op, value, fourth, to, bits);
}

static void *fork_worker(void *mapping) {
    volatile int *word = mapping;
    *word = 41;
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (*word != 41) _exit(2);
        *word = 77;
        _exit(*word == 77 ? 0 : 3);
    }
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && status == 0 && *word == 41);
    *word = 42;
    return NULL;
}

enum completion { BY_WAKE, BY_TIMEOUT, BY_SIGNAL };
static volatile sig_atomic_t interrupted;

static void on_signal(int sig) {
    interrupted = (sig == SIGUSR1);
}

/* REQUEUE 的返回值确认子进程已经入队，消除对父子运行顺序的假设。 */
static void shared_queue(int *child_words, int *parent_words, enum completion how) {
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (how == BY_SIGNAL) {
            struct sigaction action = { .sa_handler = on_signal };
            sigemptyset(&action.sa_mask);
            CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        }
        struct timespec until;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &until) == 0);
        until.tv_sec += how == BY_TIMEOUT ? 1 : 3;
        long ret = futex(child_words, WAIT_BITS, 0, (uintptr_t)&until, NULL, 2);
        if (how == BY_SIGNAL) _exit(!(ret == -1 && errno == EINTR && interrupted));
        if (how == BY_TIMEOUT) _exit(!(ret == -1 && errno == ETIMEDOUT));
        _exit(ret != 0);
    }
    struct timespec start, now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
    long moved;
    do {
        moved = futex(parent_words, CMP_REQUEUE, 0, 1, parent_words + 1, 0);
        CHECK(moved >= 0);
        if (!moved) {
            sched_yield();
            CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0 && now.tv_sec - start.tv_sec < 4);
        }
    } while (!moved);
    CHECK(moved == 1);
    CHECK(futex(parent_words, WAKE, 1, 0, NULL, 0) == 0);
    CHECK(futex(parent_words + 1, WAKE_BITS | PRIVATE, 1, 0, NULL, 2) == 0);
    CHECK(futex(parent_words + 1, WAKE_BITS, 1, 0, NULL, 1) == 0);
    if (how == BY_SIGNAL) CHECK(kill(pid, SIGUSR1) == 0);
    if (how == BY_WAKE)
        CHECK(futex(parent_words + 1, WAKE_BITS, 1, 0, NULL, 2) == 1);
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main(void) {
    int *word = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(word != MAP_FAILED);
    pthread_t worker;
    CHECK(pthread_create(&worker, NULL, fork_worker, word) == 0);
    CHECK(pthread_join(worker, NULL) == 0 && *word == 42);
    struct timespec zero = {0};
    CHECK(futex(word, WAIT | PRIVATE, 41, 0, NULL, 0) == -1 && errno == EAGAIN);
    CHECK(futex(word, WAIT | PRIVATE, 42, (uintptr_t)&zero, NULL, 0) == -1 && errno == ETIMEDOUT);
    CHECK(futex((int *)((char *)word + 1), WAKE, 1, 0, NULL, 0) == -1 && errno == EINVAL);
    CHECK(futex(word, CMP_REQUEUE, 0, 1, word + 1, 41) == -1 && errno == EAGAIN);
    CHECK(munmap(word, 4096) == 0);

    int *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED);
    shared_queue(shared, shared, BY_WAKE);
    shared_queue(shared, shared, BY_TIMEOUT);
    shared_queue(shared, shared, BY_SIGNAL);
    CHECK(munmap(shared, 4096) == 0);

    char path[] = "./futex-map-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0 && unlink(path) == 0);
    char zeros[4096] = {0};
    CHECK(write(fd, zeros, sizeof(zeros)) == sizeof(zeros));
    CHECK(write(fd, zeros, sizeof(zeros)) == sizeof(zeros));
    int *first = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int *alias = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 4096);
    CHECK(first != MAP_FAILED && alias != MAP_FAILED && close(fd) == 0);
    shared_queue(first + 4096 / sizeof(*first), alias, BY_WAKE);
    CHECK(munmap(first, 8192) == 0 && munmap(alias, 4096) == 0);
    puts("futex wake regression passed");
    return 0;
}
