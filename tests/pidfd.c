#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

#ifndef PIDFD_NONBLOCK
#define PIDFD_NONBLOCK O_NONBLOCK
#endif
#ifndef P_PIDFD
#define P_PIDFD 3
#endif

static volatile sig_atomic_t got_sig = 0;
static volatile int got_val = 0;

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)uc;
    got_sig = sig;
    got_val = si ? si->si_value.sival_int : -1;
}

static void die(const char *msg) {
    printf("FAIL: %s (errno=%d)\n", msg, errno);
    exit(1);
}

int main(void) {
    /* 1. pidfd_open validation */
    if (syscall(SYS_pidfd_open, 0, 0) != -1 || errno != EINVAL)
        die("pidfd_open(0) EINVAL");
    if (syscall(SYS_pidfd_open, -1, 0) != -1 || errno != EINVAL)
        die("pidfd_open(-1) EINVAL");
    if (syscall(SYS_pidfd_open, getpid(), 1) != -1 || errno != EINVAL)
        die("pidfd_open bad flags EINVAL");
    if (syscall(SYS_pidfd_open, 999999, 0) != -1 || errno != ESRCH)
        die("pidfd_open nonexistent ESRCH");

    int self_fd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (self_fd < 0) die("pidfd_open(self)");
    if ((fcntl(self_fd, F_GETFD) & FD_CLOEXEC) == 0)
        die("pidfd FD_CLOEXEC not set");

    /* 2. pidfd_send_signal to self with siginfo */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) die("sigaction");

    siginfo_t sinfo;
    memset(&sinfo, 0, sizeof(sinfo));
    sinfo.si_signo = SIGUSR1;
    sinfo.si_code = SI_QUEUE;
    sinfo.si_pid = getpid();
    sinfo.si_value.sival_int = 42;
    if (syscall(SYS_pidfd_send_signal, self_fd, SIGUSR1, &sinfo, 0) != 0)
        die("pidfd_send_signal(self)");
    if (got_sig != SIGUSR1 || got_val != 42)
        die("pidfd_send_signal siginfo mismatch");

    /* error paths */
    if (syscall(SYS_pidfd_send_signal, self_fd, 0, NULL, 1) != -1 || errno != EINVAL)
        die("pidfd_send_signal bad flags");
    if (syscall(SYS_pidfd_send_signal, 0, SIGUSR1, NULL, 0) != -1 || errno != EBADF)
        die("pidfd_send_signal non-pidfd EBADF");
    if (syscall(SYS_pidfd_send_signal, 999, SIGUSR1, NULL, 0) != -1 || errno != EBADF)
        die("pidfd_send_signal closed fd EBADF");
    sinfo.si_signo = SIGUSR2;
    if (syscall(SYS_pidfd_send_signal, self_fd, SIGUSR1, &sinfo, 0) != -1 || errno != EINVAL)
        die("pidfd_send_signal mismatched si_signo EINVAL");

    /* kcmp(KCMP_FILE) on pidfd_getfd */
    int dup_self = (int)syscall(SYS_pidfd_getfd, self_fd, self_fd, 0);
    if (dup_self < 0) die("pidfd_getfd self");
    if (syscall(272, getpid(), getpid(), 0, self_fd, dup_self) != 0)
        die("kcmp KCMP_FILE equal");
    close(dup_self);

    /* 3. pidfd_getfd from child + poll + waitid(P_PIDFD) + PIDFD_NONBLOCK */
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        /* child waits for SIGTERM from parent */
        char c;
        (void)read(pfd[0], &c, 1);
        _exit(17);
    }

    int cfd = (int)syscall(SYS_pidfd_open, pid, PIDFD_NONBLOCK);
    if (cfd < 0) die("pidfd_open(child, NONBLOCK)");

    /* waitid(P_PIDFD) on nonblock pidfd before exit => EAGAIN */
    siginfo_t winfo;
    memset(&winfo, 0, sizeof(winfo));
    if (waitid(P_PIDFD, (id_t)cfd, &winfo, WEXITED) != -1 || errno != EAGAIN)
        die("waitid(P_PIDFD, NONBLOCK) EAGAIN");

    /* pidfd_getfd duplicates child's write end of pipe with FD_CLOEXEC */
    int dup_w = (int)syscall(SYS_pidfd_getfd, cfd, pfd[1], 0);
    if (dup_w < 0) die("pidfd_getfd");
    if ((fcntl(dup_w, F_GETFD) & FD_CLOEXEC) == 0)
        die("pidfd_getfd FD_CLOEXEC not set");
    if (syscall(SYS_pidfd_getfd, cfd, 999, 0) != -1 || errno != EBADF)
        die("pidfd_getfd bad targetfd");
    if (syscall(SYS_pidfd_getfd, cfd, pfd[1], 1) != -1 || errno != EINVAL)
        die("pidfd_getfd bad flags");

    /* Unblock child via the duplicated fd */
    if (write(dup_w, "x", 1) != 1) die("write dup_w");
    close(dup_w);

    /* Poll pidfd until child exits */
    struct pollfd pf = { .fd = cfd, .events = POLLIN, .revents = 0 };
    if (poll(&pf, 1, 2000) != 1 || !(pf.revents & POLLIN))
        die("poll pidfd");

    /* Reap child via waitid(P_PIDFD) */
    memset(&winfo, 0, sizeof(winfo));
    if (waitid(P_PIDFD, (id_t)cfd, &winfo, WEXITED) != 0)
        die("waitid(P_PIDFD) reap");
    if (winfo.si_pid != pid || winfo.si_code != CLD_EXITED || winfo.si_status != 17)
        die("waitid(P_PIDFD) info mismatch");

    /* After reaping, pidfd_send_signal and pidfd_getfd must return ESRCH */
    if (syscall(SYS_pidfd_send_signal, cfd, 0, NULL, 0) != -1 || errno != ESRCH)
        die("pidfd_send_signal reaped ESRCH");
    if (syscall(SYS_pidfd_getfd, cfd, pfd[1], 0) != -1 || errno != ESRCH)
        die("pidfd_getfd reaped ESRCH");

    close(cfd);
    close(self_fd);
    close(pfd[0]);
    close(pfd[1]);

    printf("pidfd regression passed\n");
    return 0;
}
