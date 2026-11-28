#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

struct aio_sigset {
    const sigset_t *sigmask;
    size_t sigsetsize;
};

static void die(const char *msg) {
    printf("FAIL: %s (errno=%d)\n", msg, errno);
    _exit(1);
}

int main(void) {
    mkdir("/tmp", 0777);
    const char *path = "/tmp/aio_test_file";
    unlink(path);

    /* 1. io_setup error paths */
    aio_context_t ctx = 123;
    if (syscall(SYS_io_setup, 8, &ctx) != -1 || errno != EINVAL)
        die("io_setup nonzero ctx");
    ctx = 0;
    if (syscall(SYS_io_setup, 0, &ctx) != -1 || errno != EINVAL)
        die("io_setup zero nr");
    if (syscall(SYS_io_setup, (unsigned)-1, &ctx) != -1 || errno != EINVAL)
        die("io_setup neg nr");
    if (syscall(SYS_io_setup, 100000, &ctx) != -1 || errno != EAGAIN)
        die("io_setup over aio-max-nr");

    /* 2. io_setup success & /proc/sys/fs/aio-nr */
    if (syscall(SYS_io_setup, 8, &ctx) != 0 || ctx == 0)
        die("io_setup success");
    /* Verify libaio ring magic read does not fault */
    uint32_t magic = *(volatile uint32_t *)(uintptr_t)(ctx + 12);
    if (magic != 0)
        die("ring magic nonzero");

    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0)
        die("open file");
    int efd = eventfd(0, EFD_NONBLOCK);
    if (efd < 0)
        die("eventfd");

    /* 3. io_submit PWRITE + IOCB_FLAG_RESFD */
    char wbuf[16] = "hello-linux-aio";
    struct iocb cb;
    memset(&cb, 0, sizeof(cb));
    cb.aio_data = 0x11223344ULL;
    cb.aio_lio_opcode = IOCB_CMD_PWRITE;
    cb.aio_fildes = (uint32_t)fd;
    cb.aio_buf = (uintptr_t)wbuf;
    cb.aio_nbytes = 15;
    cb.aio_offset = 0;
    cb.aio_flags = IOCB_FLAG_RESFD;
    cb.aio_resfd = (uint32_t)efd;
    struct iocb *cbs[2] = {&cb, NULL};
    if (syscall(SYS_io_submit, ctx, 1, cbs) != 1)
        die("io_submit pwrite");

    uint64_t evcnt = 0;
    if (read(efd, &evcnt, sizeof(evcnt)) != 8 || evcnt != 1)
        die("resfd eventfd count");

    struct io_event evs[4];
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 0};
    long got = syscall(SYS_io_getevents, ctx, 1, 4, evs, &ts);
    if (got != 1 || evs[0].data != 0x11223344ULL || evs[0].obj != (uintptr_t)&cb || evs[0].res != 15)
        die("io_getevents pwrite");

    /* 4. io_submit PREADV + io_pgetevents */
    char r1[6] = {0}, r2[10] = {0};
    struct iovec iov[2] = {{r1, 5}, {r2, 10}};
    memset(&cb, 0, sizeof(cb));
    cb.aio_data = 0x55667788ULL;
    cb.aio_lio_opcode = IOCB_CMD_PREADV;
    cb.aio_fildes = (uint32_t)fd;
    cb.aio_buf = (uintptr_t)iov;
    cb.aio_nbytes = 2;
    cb.aio_offset = 0;
    if (syscall(SYS_io_submit, ctx, 1, cbs) != 1)
        die("io_submit preadv");

    sigset_t mask;
    sigemptyset(&mask);
    struct aio_sigset asig = {.sigmask = &mask, .sigsetsize = 8};
    got = syscall(SYS_io_pgetevents, ctx, 1, 4, evs, &ts, &asig);
    if (got != 1 || evs[0].res != 15 || memcmp(r1, "hello", 5) != 0 || memcmp(r2, "-linux-aio", 10) != 0)
        die("io_pgetevents preadv");

    /* 5. io_cancel & invalid submit/destroy */
    struct io_event cres;
    if (syscall(SYS_io_cancel, ctx, &cb, &cres) != -1 || errno != EAGAIN)
        die("io_cancel EAGAIN");
    if (syscall(SYS_io_cancel, ctx, (void *)0, &cres) != -1 || errno != EFAULT)
        die("io_cancel NULL EFAULT");

    cb.aio_lio_opcode = IOCB_CMD_NOOP;
    if (syscall(SYS_io_submit, ctx, 1, cbs) != -1 || errno != EINVAL)
        die("io_submit NOOP EINVAL");

    if (syscall(SYS_io_destroy, ctx) != 0)
        die("io_destroy");
    if (syscall(SYS_io_destroy, ctx) != -1 || errno != EINVAL)
        die("double io_destroy");

    close(efd);
    close(fd);
    unlink(path);
    printf("aio_test: ALL PASS\n");
    return 0;
}
