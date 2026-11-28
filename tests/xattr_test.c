#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

int main(void) {
    mkdir("/tmp", 0777);
    const char *path = "/tmp/xattr_reg_test";
    const char *linkp = "/tmp/xattr_reg_sym";
    unlink(linkp);
    unlink(path);

    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0)
        die("open");

    if (setxattr(path, "user.alpha", "hello", 5, XATTR_CREATE) != 0)
        die("setxattr create");
    errno = 0;
    if (setxattr(path, "user.alpha", "dup", 3, XATTR_CREATE) != -1 || errno != EEXIST)
        die("setxattr EEXIST");
    if (fsetxattr(fd, "user.alpha", "world!", 6, XATTR_REPLACE) != 0)
        die("fsetxattr replace");
    if (fsetxattr(fd, "trusted.k", "v", 1, 0) != 0)
        die("fsetxattr trusted");

    ssize_t sz = getxattr(path, "user.alpha", NULL, 0);
    if (sz != 6)
        die("getxattr size query");
    char buf[32];
    errno = 0;
    if (fgetxattr(fd, "user.alpha", buf, 3) != -1 || errno != ERANGE)
        die("fgetxattr ERANGE");
    memset(buf, 0, sizeof(buf));
    if (fgetxattr(fd, "user.alpha", buf, sizeof(buf)) != 6 || strcmp(buf, "world!") != 0)
        die("fgetxattr value");

    ssize_t lsz = listxattr(path, NULL, 0);
    if (lsz != (ssize_t)(strlen("trusted.k") + 1 + strlen("user.alpha") + 1))
        die("listxattr size");
    char lbuf[64];
    if (flistxattr(fd, lbuf, sizeof(lbuf)) != lsz)
        die("flistxattr read");

    if (symlink(path, linkp) != 0)
        die("symlink");
    errno = 0;
    if (lsetxattr(linkp, "user.sym", "x", 1, 0) != -1 || errno != EPERM)
        die("lsetxattr user on symlink EPERM");
    errno = 0;
    if (lgetxattr(linkp, "user.alpha", buf, sizeof(buf)) != -1 || errno != ENODATA)
        die("lgetxattr user on symlink ENODATA");
    if (lsetxattr(linkp, "trusted.sym", "ok", 2, 0) != 0)
        die("lsetxattr trusted on symlink");
    memset(buf, 0, sizeof(buf));
    if (lgetxattr(linkp, "trusted.sym", buf, sizeof(buf)) != 2 || strcmp(buf, "ok") != 0)
        die("lgetxattr trusted on symlink");
    if (lremovexattr(linkp, "trusted.sym") != 0)
        die("lremovexattr");

    if (fremovexattr(fd, "user.alpha") != 0)
        die("fremovexattr");
    errno = 0;
    if (removexattr(path, "user.alpha") != -1 || errno != ENODATA)
        die("removexattr ENODATA");

    errno = 0;
    if (setxattr(path, "bogus.x", "1", 1, 0) != -1 || errno != EOPNOTSUPP)
        die("setxattr bad prefix");
    errno = 0;
    if (getxattr(path, "", buf, sizeof(buf)) != -1 || errno != ERANGE)
        die("getxattr empty name");

    close(fd);
    unlink(linkp);
    unlink(path);
    printf("xattr_test PASS\n");
    return 0;
}
