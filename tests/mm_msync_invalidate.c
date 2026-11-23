/* 用户态回归：同步后私有副本、共享别名、区间外页和原文件的可见内容。 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { perror(#x); return 1; } } while (0)

int main(void) {
    const size_t page = 4096;
    char path[] = "/msync-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    /* 普通写入建立文件，两个描述符的打开权限不同。 */
    static unsigned char zeros[4096 * 2];
    CHECK(write(fd, zeros, sizeof zeros) == sizeof zeros);
    int ro = open(path, O_RDONLY);
    CHECK(ro >= 0);
    volatile unsigned char *writer = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    volatile unsigned char *reader = mmap(NULL, page, PROT_READ, MAP_SHARED, ro, page);
    volatile unsigned char *private = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, page);
    CHECK(writer != MAP_FAILED && reader != MAP_FAILED && private != MAP_FAILED);
    CHECK(*reader == 0 && *private == 0);
    *private = 92;
    writer[0] = 11;
    writer[page] = 23;
    CHECK(msync((void *)private, page, MS_SYNC | MS_INVALIDATE) == 0);
    CHECK(*private == 92 && *reader == 23);
    CHECK(msync((void *)reader, page, MS_SYNC | MS_INVALIDATE) == 0);
    CHECK(writer[0] == 11 && writer[page] == 23 && *reader == 23);
    writer[page] = 42;
    CHECK(*reader == 42);
    CHECK(msync((void *)(writer + page), page, MS_SYNC | MS_INVALIDATE) == 0);
    CHECK(*reader == 42 && writer[page] == 42 && *private == 92);
    CHECK(munmap((void *)writer, 2 * page) == 0 && munmap((void *)reader, page) == 0);
    CHECK(munmap((void *)private, page) == 0);
    unsigned char saved = 0;
    CHECK(pread(ro, &saved, 1, page) == 1 && saved == 42);
    CHECK(close(ro) == 0 && close(fd) == 0 && unlink(path) == 0);
    puts("msync invalidation regression passed");
    return 0;
}
