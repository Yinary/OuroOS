/* 通过真实文件描述符验证 mincore 别名、截断失效以及重新扩长后的写回。 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "file mapping check failed at line %d: %s (errno=%d)\n", \
            __LINE__, #expr, errno); return 1; } } while (0)

int main(void) {
    const size_t page = 4096, cut = page / 2;
    char path[] = "mm-file-resize-XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(ftruncate(fd, 2 * page) == 0);
    int ro = open(path, O_RDONLY);
    CHECK(ro >= 0);
    volatile unsigned char *shared = mmap(NULL, 3 * page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    volatile unsigned char *alias = mmap(NULL, 3 * page, PROT_READ, MAP_SHARED, ro, 0);
    volatile unsigned char *priv = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(shared != MAP_FAILED && alias != MAP_FAILED && priv != MAP_FAILED);
    shared[0] = 11;
    shared[cut] = 22;
    shared[page] = 33;
    CHECK(msync((void *)shared, 2 * page, MS_SYNC) == 0);
    shared[0] = 12;
    shared[cut] = 23;
    shared[page] = 34;
    unsigned char vec[3];
    CHECK(mincore((void *)alias, 3 * page, vec) == 0);
    CHECK((vec[0] & 1) && (vec[1] & 1) && !(vec[2] & 1));
    CHECK(alias[cut] == 23 && alias[page] == 34);
    CHECK(priv[0] == 12 && priv[page] == 34);
    priv[0] = 44;
    CHECK(ftruncate(ro, cut) == -1 && alias[page] == 34);
    CHECK(ftruncate(fd, -1) == -1 && errno == EINVAL && alias[cut] == 23);
    CHECK(close(ro) == 0);

    /* 子进程截断父子均已触碰的页。父进程恢复运行时必须看见失效。 */
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        if (ftruncate(fd, cut) != 0) _exit(2);
        (void)shared[page];
        _exit(3);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGBUS);
    CHECK(mincore((void *)alias, 3 * page, vec) == 0);
    CHECK((vec[0] & 1) && !(vec[1] & 1) && !(vec[2] & 1));
    CHECK(shared[0] == 12 && alias[cut] == 0 && priv[0] == 44);

    /* 通过路径扩长两次，跨过整页边界，随后在旧尾页新暴露的位置写回。 */
    CHECK(truncate(path, cut + 2) == 0 && shared[cut] == 0);
    shared[cut] = 55;
    CHECK(truncate(path, 2 * page) == 0);
    CHECK(alias[cut] == 55 && alias[page] == 0 && priv[page] == 0);
    CHECK(ftruncate(fd, 2 * page) == 0 && alias[cut] == 55);
    shared[page] = 66;
    CHECK(msync((void *)shared, 2 * page, MS_SYNC) == 0);
    CHECK(munmap((void *)priv, 2 * page) == 0 && munmap((void *)alias, 3 * page) == 0);
    CHECK(munmap((void *)shared, 3 * page) == 0 && close(fd) == 0);

    fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    unsigned char value;
    CHECK(read(fd, &value, 1) == 1 && value == 12);
    CHECK(lseek(fd, cut, SEEK_SET) == (off_t)cut && read(fd, &value, 1) == 1 && value == 55);
    CHECK(lseek(fd, page, SEEK_SET) == (off_t)page && read(fd, &value, 1) == 1 && value == 66);
    CHECK(close(fd) == 0 && unlink(path) == 0);
    puts("file mapping resize checks passed");
    return 0;
}
