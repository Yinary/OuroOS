#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

static void die(const char *msg) {
    printf("FAIL: %s (errno=%d)\n", msg, errno);
    _exit(1);
}

int main(void) {
    mkdir("/tmp", 0777);
    const char *dir = "/tmp/ino_test_dir";
    const char *f1 = "/tmp/ino_test_dir/a.txt";
    const char *f2 = "/tmp/ino_test_dir/b.txt";
    unlink(f1);
    unlink(f2);
    rmdir(dir);
    if (mkdir(dir, 0755) != 0)
        die("mkdir dir");

    if (inotify_init1(0x1234) != -1 || errno != EINVAL)
        die("invalid init1 flags");

    int ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (ifd < 0)
        die("inotify_init1");

    char buf[4096];
    if (read(ifd, buf, sizeof(buf)) != -1 || errno != EAGAIN)
        die("empty nonblock read");
    if (write(ifd, "x", 1) != -1 || errno != EBADF)
        die("write to inotify fd");

    if (inotify_add_watch(ifd, dir, 0) != -1 || errno != EINVAL)
        die("zero mask");
    if (inotify_add_watch(ifd, dir, IN_OPEN | IN_MASK_ADD | IN_MASK_CREATE) != -1 ||
        errno != EINVAL)
        die("MASK_ADD + MASK_CREATE");
    if (inotify_rm_watch(ifd, 999) != -1 || errno != EINVAL)
        die("rm invalid wd");

    int wd_dir = inotify_add_watch(ifd, dir, IN_ALL_EVENTS | IN_MASK_CREATE);
    if (wd_dir <= 0)
        die("add_watch dir");
    if (inotify_add_watch(ifd, dir, IN_OPEN | IN_MASK_CREATE) != -1 || errno != EEXIST)
        die("IN_MASK_CREATE duplicate");

    int fd = open(f1, O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0)
        die("open create f1");
    if (write(fd, "hello", 5) != 5)
        die("write f1");
    if (lseek(fd, 0, SEEK_SET) != 0)
        die("lseek f1");
    char tmp[16];
    if (read(fd, tmp, 5) != 5)
        die("read f1");
    close(fd);

    if (rename(f1, f2) != 0)
        die("rename f1 -> f2");
    if (unlink(f2) != 0)
        die("unlink f2");

    int avail = 0;
    if (ioctl(ifd, FIONREAD, &avail) != 0 || avail <= 0)
        die("ioctl FIONREAD");
    struct pollfd pfd = {.fd = ifd, .events = POLLIN};
    if (poll(&pfd, 1, 0) != 1 || !(pfd.revents & POLLIN))
        die("poll POLLIN");

    if (read(ifd, buf, 8) != -1 || errno != EINVAL)
        die("small buf EINVAL");

    ssize_t n = read(ifd, buf, sizeof(buf));
    if (n <= 0)
        die("read events");
    uint32_t seen = 0;
    uint32_t cookie_from = 0, cookie_to = 0;
    for (ssize_t off = 0; off < n;) {
        struct inotify_event *ev = (struct inotify_event *)(buf + off);
        seen |= ev->mask;
        if (ev->mask & IN_MOVED_FROM)
            cookie_from = ev->cookie;
        if (ev->mask & IN_MOVED_TO)
            cookie_to = ev->cookie;
        off += (ssize_t)(sizeof(*ev) + ev->len);
    }
    uint32_t expected = IN_CREATE | IN_OPEN | IN_MODIFY | IN_ACCESS | IN_CLOSE_WRITE |
                        IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE;
    if ((seen & expected) != expected)
        die("missing expected dir events");
    if (cookie_from == 0 || cookie_from != cookie_to)
        die("rename cookie mismatch");

    fd = open(f1, O_CREAT | O_RDWR, 0644);
    if (fd < 0)
        die("recreate f1");
    close(fd);
    if (inotify_add_watch(ifd, f1, IN_OPEN | IN_ONLYDIR) != -1 || errno != ENOTDIR)
        die("IN_ONLYDIR on reg file");
    int wd_f = inotify_add_watch(ifd, f1, IN_OPEN | IN_ONESHOT);
    if (wd_f <= 0)
        die("add_watch oneshot");
    while (read(ifd, buf, sizeof(buf)) > 0) {
    }
    fd = open(f1, O_RDONLY);
    close(fd);
    n = read(ifd, buf, sizeof(buf));
    if (n <= 0)
        die("read oneshot events");
    int got_open = 0, got_ignored = 0;
    for (ssize_t off = 0; off < n;) {
        struct inotify_event *ev = (struct inotify_event *)(buf + off);
        if (ev->wd == wd_f && (ev->mask & IN_OPEN))
            got_open = 1;
        if (ev->wd == wd_f && (ev->mask & IN_IGNORED))
            got_ignored = 1;
        off += (ssize_t)(sizeof(*ev) + ev->len);
    }
    if (!got_open || !got_ignored)
        die("oneshot did not fire OPEN + IGNORED");

    if (inotify_rm_watch(ifd, wd_dir) != 0)
        die("rm_watch dir");
    n = read(ifd, buf, sizeof(buf));
    if (n <= 0)
        die("read rm_watch IGNORED");
    struct inotify_event *rm_ev = (struct inotify_event *)buf;
    if (rm_ev->wd != wd_dir || !(rm_ev->mask & IN_IGNORED))
        die("rm_watch missing IN_IGNORED");

    int p = open("/proc/sys/fs/inotify/max_queued_events", O_RDONLY);
    if (p < 0)
        die("open /proc/sys/fs/inotify/max_queued_events");
    ssize_t pn = read(p, tmp, sizeof(tmp) - 1);
    close(p);
    if (pn <= 0 || atoi(tmp) <= 0)
        die("read max_queued_events");

    unlink(f1);
    rmdir(dir);
    close(ifd);
    printf("inotify_test: ALL PASS\n");
    return 0;
}
