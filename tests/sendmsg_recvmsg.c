#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static void check_udp_sendmsg_mmsg(void) {
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    int cli = socket(AF_INET, SOCK_DGRAM, 0);
    if (srv < 0 || cli < 0)
        die("socket");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("bind");
    socklen_t alen = sizeof(addr);
    if (getsockname(srv, (struct sockaddr *)&addr, &alen) != 0)
        die("getsockname");

    char p1[] = "hello ";
    char p2[] = "sendmsg!";
    struct iovec siov[2] = {
        { .iov_base = p1, .iov_len = strlen(p1) },
        { .iov_base = p2, .iov_len = strlen(p2) },
    };
    struct msghdr smsg;
    memset(&smsg, 0, sizeof(smsg));
    smsg.msg_name = &addr;
    smsg.msg_namelen = sizeof(addr);
    smsg.msg_iov = siov;
    smsg.msg_iovlen = 2;
    ssize_t sn = sendmsg(cli, &smsg, 0);
    if (sn != (ssize_t)(strlen(p1) + strlen(p2)))
        die("sendmsg udp");

    char rbuf[5];
    struct iovec riov = { .iov_base = rbuf, .iov_len = sizeof(rbuf) };
    struct sockaddr_in src;
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_name = &src;
    rmsg.msg_namelen = sizeof(src);
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    ssize_t rn = recvmsg(srv, &rmsg, MSG_TRUNC);
    if (rn != sn || memcmp(rbuf, "hello", 5) != 0 || !(rmsg.msg_flags & MSG_TRUNC))
        die("recvmsg MSG_TRUNC");

    char m1[] = "pkt-one";
    char m2[] = "pkt-two";
    struct iovec miov1 = { .iov_base = m1, .iov_len = strlen(m1) };
    struct iovec miov2 = { .iov_base = m2, .iov_len = strlen(m2) };
    struct mmsghdr sm[2];
    memset(sm, 0, sizeof(sm));
    sm[0].msg_hdr.msg_name = &addr;
    sm[0].msg_hdr.msg_namelen = sizeof(addr);
    sm[0].msg_hdr.msg_iov = &miov1;
    sm[0].msg_hdr.msg_iovlen = 1;
    sm[1].msg_hdr.msg_name = &addr;
    sm[1].msg_hdr.msg_namelen = sizeof(addr);
    sm[1].msg_hdr.msg_iov = &miov2;
    sm[1].msg_hdr.msg_iovlen = 1;
    int sc = sendmmsg(cli, sm, 2, 0);
    if (sc != 2 || sm[0].msg_len != strlen(m1) || sm[1].msg_len != strlen(m2))
        die("sendmmsg");

    char rb1[16], rb2[16];
    memset(rb1, 0, sizeof(rb1));
    memset(rb2, 0, sizeof(rb2));
    struct iovec rmiov1 = { .iov_base = rb1, .iov_len = sizeof(rb1) };
    struct iovec rmiov2 = { .iov_base = rb2, .iov_len = sizeof(rb2) };
    struct mmsghdr rm[2];
    memset(rm, 0, sizeof(rm));
    rm[0].msg_hdr.msg_iov = &rmiov1;
    rm[0].msg_hdr.msg_iovlen = 1;
    rm[1].msg_hdr.msg_iov = &rmiov2;
    rm[1].msg_hdr.msg_iovlen = 1;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000 };
    int rc = recvmmsg(srv, rm, 2, 0, &ts);
    if (rc != 2 || rm[0].msg_len != strlen(m1) || strcmp(rb1, "pkt-one") != 0 ||
        rm[1].msg_len != strlen(m2) || strcmp(rb2, "pkt-two") != 0)
        die("recvmmsg");

    struct timespec short_ts = { .tv_sec = 0, .tv_nsec = 20000000 };
    rc = recvmmsg(srv, rm, 1, 0, &short_ts);
    if (rc != 0)
        die("recvmmsg timeout");

    close(cli);
    close(srv);
    printf("udp sendmsg/mmsg ok\n");
}

static void check_unix_scm_rights(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        die("socketpair");

    int p[2];
    if (pipe(p) != 0)
        die("pipe");
    if (write(p[1], "fdpass!", 7) != 7)
        die("pipe write");

    char dummy = 'X';
    struct iovec siov = { .iov_base = &dummy, .iov_len = 1 };
    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } cmsg_u;
    memset(&cmsg_u, 0, sizeof(cmsg_u));

    struct msghdr smsg;
    memset(&smsg, 0, sizeof(smsg));
    smsg.msg_iov = &siov;
    smsg.msg_iovlen = 1;
    smsg.msg_control = cmsg_u.buf;
    smsg.msg_controllen = sizeof(cmsg_u.buf);

    struct cmsghdr *cm = CMSG_FIRSTHDR(&smsg);
    cm->cmsg_level = SOL_SOCKET;
    cm->cmsg_type = SCM_RIGHTS;
    cm->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cm), &p[0], sizeof(int));

    if (sendmsg(sv[0], &smsg, 0) != 1)
        die("sendmsg SCM_RIGHTS");
    close(p[0]);

    char rdummy = 0;
    struct iovec riov = { .iov_base = &rdummy, .iov_len = 1 };
    memset(&cmsg_u, 0, sizeof(cmsg_u));
    struct msghdr rmsg;
    memset(&rmsg, 0, sizeof(rmsg));
    rmsg.msg_iov = &riov;
    rmsg.msg_iovlen = 1;
    rmsg.msg_control = cmsg_u.buf;
    rmsg.msg_controllen = sizeof(cmsg_u.buf);

    if (recvmsg(sv[1], &rmsg, MSG_CMSG_CLOEXEC) != 1 || rdummy != 'X')
        die("recvmsg SCM_RIGHTS");
    struct cmsghdr *rcm = CMSG_FIRSTHDR(&rmsg);
    if (!rcm || rcm->cmsg_level != SOL_SOCKET || rcm->cmsg_type != SCM_RIGHTS)
        die("recvmsg cmsg header");
    int rfd = -1;
    memcpy(&rfd, CMSG_DATA(rcm), sizeof(int));
    if (rfd < 0)
        die("recvmsg rfd");
    if ((fcntl(rfd, F_GETFD) & FD_CLOEXEC) == 0)
        die("MSG_CMSG_CLOEXEC");

    char pbuf[16];
    memset(pbuf, 0, sizeof(pbuf));
    if (read(rfd, pbuf, 7) != 7 || strcmp(pbuf, "fdpass!") != 0)
        die("read passed pipe fd");

    close(rfd);
    close(p[1]);
    close(sv[0]);
    close(sv[1]);
    printf("unix SCM_RIGHTS ok\n");
}

int main(void) {
    check_udp_sendmsg_mmsg();
    check_unix_scm_rights();
    printf("sendmsg_recvmsg PASS\n");
    return 0;
}
