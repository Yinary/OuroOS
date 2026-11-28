#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef SYS_fdatasync
#define SYS_fdatasync 83
#endif
#ifndef SYS_sync_file_range
#define SYS_sync_file_range 84
#endif
#ifndef SYS_syncfs
#define SYS_syncfs 267
#endif
#ifndef SYS_preadv2
#define SYS_preadv2 286
#endif
#ifndef SYS_pwritev2
#define SYS_pwritev2 287
#endif
#ifndef SYS_close_range
#define SYS_close_range 436
#endif

#ifndef RWF_HIPRI
#define RWF_HIPRI 0x01
#define RWF_DSYNC 0x02
#define RWF_SYNC 0x04
#define RWF_NOWAIT 0x08
#define RWF_APPEND 0x10
#endif

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

static void die(const char *msg) {
    printf("FAIL: %s (errno=%d)\n", msg, errno);
    exit(1);
}

static long sys_preadv2(int fd, const struct iovec *iov, int iovcnt, long off, unsigned int flags) {
    return syscall(SYS_preadv2, fd, iov, iovcnt, off, 0L, flags);
}

static long sys_pwritev2(int fd, const struct iovec *iov, int iovcnt, long off, unsigned int flags) {
    return syscall(SYS_pwritev2, fd, iov, iovcnt, off, 0L, flags);
}

int main(void) {
    int pfd[2];
    if (pipe(pfd) != 0) die("pipe");

    const char *msg = "hello";
    struct iovec wv = { .iov_base = (void *)msg, .iov_len = 5 };
    if (sys_pwritev2(pfd[1], &wv, 1, 0, 0) != -1 || errno != ESPIPE)
        die("pwritev2 pipe offset=0 ESPIPE");
    if (sys_pwritev2(pfd[1], &wv, 1, -1, 0x80) != -1 || errno != EOPNOTSUPP)
        die("pwritev2 bad flags EOPNOTSUPP");
    if (sys_pwritev2(pfd[1], &wv, 1, -1, RWF_NOWAIT) != -1 || errno != EOPNOTSUPP)
        die("pwritev2 pipe RWF_NOWAIT EOPNOTSUPP");
    if (sys_pwritev2(pfd[1], &wv, 1, -2, 0) != -1 || errno != EINVAL)
        die("pwritev2 offset=-2 EINVAL");
    if (sys_pwritev2(pfd[1], &wv, 1, -1, 0) != 5)
        die("pwritev2 pipe offset=-1");

    char rbuf[16] = {0};
    struct iovec rv = { .iov_base = rbuf, .iov_len = 5 };
    if (sys_preadv2(pfd[0], &rv, 1, 0, 0) != -1 || errno != ESPIPE)
        die("preadv2 pipe offset=0 ESPIPE");
    if (sys_preadv2(pfd[0], &rv, 1, -1, 0x100) != -1 || errno != EOPNOTSUPP)
        die("preadv2 bad flags EOPNOTSUPP");
    if (sys_preadv2(pfd[0], &rv, 1, -1, RWF_NOWAIT) != -1 || errno != EOPNOTSUPP)
        die("preadv2 pipe RWF_NOWAIT EOPNOTSUPP");
    if (sys_preadv2(pfd[0], &rv, 1, -1, 0) != 5 || memcmp(rbuf, "hello", 5) != 0)
        die("preadv2 pipe offset=-1");

    if (syscall(SYS_fdatasync, -1) != -1 || errno != EBADF)
        die("fdatasync bad fd EBADF");
    if (syscall(SYS_fdatasync, pfd[0]) != -1 || errno != EINVAL)
        die("fdatasync pipe EINVAL");
    if (syscall(SYS_syncfs, -1) != -1 || errno != EBADF)
        die("syncfs bad fd EBADF");
    if (syscall(SYS_syncfs, pfd[0]) != 0)
        die("syncfs valid fd");
    if (syscall(SYS_sync_file_range, pfd[0], 0, 0, 8) != -1 || errno != EINVAL)
        die("sync_file_range bad flags EINVAL");
    if (syscall(SYS_sync_file_range, pfd[0], -1, 0, 0) != -1 || errno != EINVAL)
        die("sync_file_range neg offset EINVAL");
    if (syscall(SYS_sync_file_range, pfd[0], 0, -1, 0) != -1 || errno != EINVAL)
        die("sync_file_range neg nbytes EINVAL");
    if (syscall(SYS_sync_file_range, pfd[0], 0, 0, 0) != -1 || errno != ESPIPE)
        die("sync_file_range pipe ESPIPE");
    if (syscall(SYS_sync_file_range, 999, 0, 0, 0) != -1 || errno != EBADF)
        die("sync_file_range bad fd EBADF");

    int d1 = dup(pfd[0]);
    int d2 = dup(pfd[0]);
    int d3 = dup(pfd[0]);
    if (d1 < 0 || d2 < 0 || d3 < 0) die("dup");

    if (syscall(SYS_close_range, 10, 5, 0) != -1 || errno != EINVAL)
        die("close_range first>last EINVAL");
    if (syscall(SYS_close_range, d1, d3, 0x80) != -1 || errno != EINVAL)
        die("close_range bad flags EINVAL");

    if (syscall(SYS_close_range, d1, d2, CLOSE_RANGE_CLOEXEC) != 0)
        die("close_range CLOEXEC");
    if ((fcntl(d1, F_GETFD) & FD_CLOEXEC) == 0) die("d1 cloexec not set");
    if ((fcntl(d2, F_GETFD) & FD_CLOEXEC) == 0) die("d2 cloexec not set");
    if ((fcntl(d3, F_GETFD) & FD_CLOEXEC) != 0) die("d3 cloexec unexpectedly set");

    if (syscall(SYS_close_range, d1, d3, CLOSE_RANGE_UNSHARE) != 0)
        die("close_range close");
    if (fcntl(d1, F_GETFD) != -1 || errno != EBADF) die("d1 not closed");
    if (fcntl(d2, F_GETFD) != -1 || errno != EBADF) die("d2 not closed");
    if (fcntl(d3, F_GETFD) != -1 || errno != EBADF) die("d3 not closed");
    if (fcntl(pfd[0], F_GETFD) < 0) die("pfd[0] unexpectedly closed");

    if (syscall(SYS_close_range, 500, 1000, 0) != 0)
        die("close_range high empty range");

    close(pfd[0]);
    close(pfd[1]);

    printf("preadv2_sync_closerange regression passed\n");
    return 0;
}
