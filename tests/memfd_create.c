#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_memfd_create
#define SYS_memfd_create 279
#endif
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#define MFD_ALLOW_SEALING 0x0002U
#define MFD_HUGETLB 0x0004U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#endif
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#endif

static void die(const char *msg) {
    printf("FAIL: %s (errno=%d)\n", msg, errno);
    exit(1);
}

int main(void) {
    /* 1. Validation: NULL name, >249 name, invalid flags */
    if (syscall(SYS_memfd_create, NULL, 0) != -1 || errno != EFAULT)
        die("NULL name EFAULT");
    char long_name[256];
    memset(long_name, 'a', 250);
    long_name[250] = '\0';
    if (syscall(SYS_memfd_create, long_name, 0) != -1 || errno != EINVAL)
        die("250-byte name EINVAL");
    long_name[249] = '\0';
    int fd249 = (int)syscall(SYS_memfd_create, long_name, MFD_CLOEXEC);
    if (fd249 < 0) die("249-byte name ok");
    if ((fcntl(fd249, F_GETFD) & FD_CLOEXEC) == 0) die("MFD_CLOEXEC not set");
    /* Without MFD_ALLOW_SEALING, initial seals == F_SEAL_SEAL */
    if (fcntl(fd249, F_GET_SEALS) != F_SEAL_SEAL) die("default F_SEAL_SEAL");
    if (fcntl(fd249, F_ADD_SEALS, F_SEAL_WRITE) != -1 || errno != EPERM)
        die("add seal without MFD_ALLOW_SEALING EPERM");
    close(fd249);

    if (syscall(SYS_memfd_create, "bad", 0x1000) != -1 || errno != EINVAL)
        die("bad flags EINVAL");

    /* 2. Basic read/write/ftruncate/fstat/mmap + seals */
    int fd = (int)syscall(SYS_memfd_create, "test", MFD_ALLOW_SEALING);
    if (fd < 0) die("memfd_create MFD_ALLOW_SEALING");
    if (fcntl(fd, F_GET_SEALS) != 0) die("initial seals 0");

    if (ftruncate(fd, 4096) != 0) die("ftruncate 4096");
    if (write(fd, "hello", 5) != 5) die("write");

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size != 4096) die("fstat size");

    /* MAP_SHARED writable blocks F_SEAL_WRITE with EBUSY */
    char *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) die("mmap MAP_SHARED RW");
    if (memcmp(p, "hello", 5) != 0) die("mmap sees write");
    memcpy(p + 5, "world", 5);

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) != -1 || errno != EBUSY)
        die("F_SEAL_WRITE while RW mapped EBUSY");

    if (munmap(p, 4096) != 0) die("munmap");

    char buf[16] = {0};
    if (pread(fd, buf, 10, 0) != 10 || memcmp(buf, "helloworld", 10) != 0)
        die("pread sees mmap write");

    /* Now F_SEAL_SHRINK & F_SEAL_GROW & F_SEAL_WRITE */
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK) != 0) die("add F_SEAL_SHRINK");
    if (ftruncate(fd, 2048) != -1 || errno != EPERM) die("shrink blocked EPERM");
    if (ftruncate(fd, 8192) != 0) die("grow still allowed");

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW) != 0) die("add F_SEAL_GROW");
    if (ftruncate(fd, 16384) != -1 || errno != EPERM) die("grow blocked EPERM");
    if (ftruncate(fd, 8192) != 0) die("same size allowed");

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) != 0) die("add F_SEAL_WRITE");
    if (pwrite(fd, "x", 1, 0) != -1 || errno != EPERM) die("write blocked EPERM");
    if (mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0) != MAP_FAILED || errno != EPERM)
        die("mmap RW blocked EPERM");

    /* Read-only MAP_SHARED still allowed */
    char *ro = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (ro == MAP_FAILED) die("mmap RO after F_SEAL_WRITE");
    if (memcmp(ro, "helloworld", 10) != 0) die("RO mmap data");
    munmap(ro, 4096);

    /* F_SEAL_SEAL locks seals */
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL) != 0) die("add F_SEAL_SEAL");
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_EXEC) != -1 || errno != EPERM)
        die("sealed F_ADD_SEALS EPERM");

    close(fd);
    printf("memfd_create regression passed\n");
    return 0;
}
