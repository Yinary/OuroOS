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
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static void check_signalfd(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0)
        die("sigprocmask");

    /* Invalid flags / sizemask checks */
    errno = 0;
    if (syscall(SYS_signalfd4, -1, &mask, 4, 0) != -1 || errno != EINVAL)
        die("signalfd4 bad sizemask");
    errno = 0;
    if (syscall(SYS_signalfd4, -1, &mask, 8, 0x1234) != -1 || errno != EINVAL)
        die("signalfd4 bad flags");

    int sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sfd < 0)
        die("signalfd create");

    int fl = fcntl(sfd, F_GETFD);
    if ((fl & FD_CLOEXEC) == 0)
        die("signalfd cloexec");
    int st = fcntl(sfd, F_GETFL);
    if ((st & O_NONBLOCK) == 0)
        die("signalfd nonblock");

    /* Nonblocking read with no pending signals -> EAGAIN */
    struct signalfd_siginfo info;
    errno = 0;
    if (read(sfd, &info, sizeof(info)) != -1 || errno != EAGAIN)
        die("signalfd empty EAGAIN");

    /* Too-small buffer -> EINVAL */
    errno = 0;
    if (read(sfd, &info, 64) != -1 || errno != EINVAL)
        die("signalfd short read EINVAL");

    /* Send SIGUSR1 and check poll + epoll + read */
    if (kill(getpid(), SIGUSR1) != 0)
        die("kill SIGUSR1");

    struct pollfd pfd = { .fd = sfd, .events = POLLIN };
    if (poll(&pfd, 1, 100) != 1 || !(pfd.revents & POLLIN))
        die("poll signalfd ready");

    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0)
        die("epoll_create1");
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = sfd };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &ev) != 0)
        die("epoll_ctl");
    struct epoll_event out;
    if (epoll_wait(ep, &out, 1, 100) != 1 || out.data.fd != sfd || !(out.events & EPOLLIN))
        die("epoll_wait signalfd");
    close(ep);

    memset(&info, 0, sizeof(info));
    ssize_t n = read(sfd, &info, sizeof(info));
    if (n != (ssize_t)sizeof(info) || info.ssi_signo != SIGUSR1 || info.ssi_pid != (uint32_t)getpid())
        die("signalfd read SIGUSR1");

    /* Update existing signalfd mask to only SIGUSR2, clear NONBLOCK, test blocking wake from child */
    sigset_t mask2;
    sigemptyset(&mask2);
    sigaddset(&mask2, SIGUSR2);
    if (signalfd(sfd, &mask2, 0) != sfd)
        die("signalfd update");
    if (fcntl(sfd, F_SETFL, 0) != 0)
        die("fcntl clear nonblock");

    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid == 0) {
        usleep(20000);
        kill(getppid(), SIGUSR2);
        _exit(0);
    }
    memset(&info, 0, sizeof(info));
    n = read(sfd, &info, sizeof(info));
    if (n != (ssize_t)sizeof(info) || info.ssi_signo != SIGUSR2 || info.ssi_pid != (uint32_t)pid)
        die("signalfd blocking read SIGUSR2");

    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) != pid)
        die("waitpid");
    close(sfd);
    printf("signalfd ok\n");
}

static void check_vmsplice(void) {
    int p[2];
    if (pipe(p) != 0)
        die("pipe");

    const char *a = "hello ";
    const char *b = "vmsplice!";
    struct iovec wiov[2] = {
        { .iov_base = (void *)a, .iov_len = strlen(a) },
        { .iov_base = (void *)b, .iov_len = strlen(b) },
    };
    ssize_t wn = vmsplice(p[1], wiov, 2, 0);
    if (wn != (ssize_t)(strlen(a) + strlen(b)))
        die("vmsplice write");

    char buf1[6], buf2[16];
    memset(buf1, 0, sizeof(buf1));
    memset(buf2, 0, sizeof(buf2));
    struct iovec riov[2] = {
        { .iov_base = buf1, .iov_len = sizeof(buf1) },
        { .iov_base = buf2, .iov_len = sizeof(buf2) - 1 },
    };
    ssize_t rn = vmsplice(p[0], riov, 2, SPLICE_F_NONBLOCK);
    if (rn != wn || memcmp(buf1, "hello ", 6) != 0 || strcmp(buf2, "vmsplice!") != 0)
        die("vmsplice read");

    /* Empty pipe + SPLICE_F_NONBLOCK -> EAGAIN */
    errno = 0;
    if (vmsplice(p[0], riov, 1, SPLICE_F_NONBLOCK) != -1 || errno != EAGAIN)
        die("vmsplice nonblock EAGAIN");

    /* Non-pipe FD -> EBADF */
    errno = 0;
    if (vmsplice(STDOUT_FILENO, wiov, 1, 0) != -1 || errno != EBADF)
        die("vmsplice non-pipe EBADF");

    /* Closed read end -> EPIPE + SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
    close(p[0]);
    errno = 0;
    if (vmsplice(p[1], wiov, 1, 0) != -1 || errno != EPIPE)
        die("vmsplice EPIPE");

    close(p[1]);
    printf("vmsplice ok\n");
}

int main(void) {
    check_signalfd();
    check_vmsplice();
    printf("signalfd_vmsplice PASS\n");
    return 0;
}
