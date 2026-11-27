#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_COPY
#define MSG_COPY 040000
#endif

static void die(const char *msg, int line) {
    printf("FAIL line %d: %s (errno=%d)\n", line, msg, errno);
    _exit(1);
}

#define CHECK(cond) do { if (!(cond)) die(#cond, __LINE__); } while (0)

struct test_msg {
    long mtype;
    char mtext[128];
};

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};

static volatile sig_atomic_t got_sig = 0;
static void sig_handler(int sig) {
    got_sig = sig;
}

static uint64_t mono_ms(void) {
    struct timespec ts;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void test_msg_basic(void) {
    key_t k = 0x12345;
    int q = msgget(k, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(q >= 0);
    CHECK(msgget(k, IPC_CREAT | IPC_EXCL | 0600) == -1 && errno == EEXIST);
    CHECK(msgget(k, 0) == q);
    CHECK(msgget(0x12346, 0) == -1 && errno == ENOENT);

    struct msqid_ds ds;
    memset(&ds, 0, sizeof(ds));
    CHECK(msgctl(q, IPC_STAT, &ds) == 0);
    CHECK(ds.msg_perm.__ipc_perm_key == k);
    CHECK((ds.msg_perm.mode & 0777) == 0600);
    CHECK(ds.msg_qnum == 0 && ds.msg_cbytes == 0 && ds.msg_qbytes > 0);

    struct msginfo mi;
    int max_idx = msgctl(0, IPC_INFO, (struct msqid_ds *)&mi);
    CHECK(max_idx >= 0 && mi.msgmax >= 1024 && mi.msgmnb >= 1024);
    int stat_id = msgctl(max_idx, MSG_STAT, &ds);
    CHECK(stat_id >= 0);

    struct test_msg m1 = { .mtype = 10, .mtext = "ten" };
    struct test_msg m2 = { .mtype = 5, .mtext = "five" };
    struct test_msg m3 = { .mtype = 20, .mtext = "twenty-long-payload" };
    CHECK(msgsnd(q, &m1, strlen(m1.mtext) + 1, 0) == 0);
    CHECK(msgsnd(q, &m2, strlen(m2.mtext) + 1, 0) == 0);
    CHECK(msgsnd(q, &m3, strlen(m3.mtext) + 1, 0) == 0);

    /* Invalid mtype */
    struct test_msg bad = { .mtype = 0, .mtext = "x" };
    CHECK(msgsnd(q, &bad, 1, 0) == -1 && errno == EINVAL);

    /* MSG_COPY non-destructive peek */
    struct test_msg r;
    memset(&r, 0, sizeof(r));
    ssize_t n = msgrcv(q, &r, sizeof(r.mtext), 1, MSG_COPY | IPC_NOWAIT);
    CHECK(n == (ssize_t)(strlen("five") + 1) && r.mtype == 5 && strcmp(r.mtext, "five") == 0);

    /* E2BIG without MSG_NOERROR, truncation with MSG_NOERROR */
    CHECK(msgrcv(q, &r, 4, 20, IPC_NOWAIT) == -1 && errno == E2BIG);
    memset(&r, 0, sizeof(r));
    n = msgrcv(q, &r, 6, 20, IPC_NOWAIT | MSG_NOERROR);
    CHECK(n == 6 && r.mtype == 20 && memcmp(r.mtext, "twenty", 6) == 0);

    /* msgtyp < 0: smallest type <= 10 -> type 5 first */
    memset(&r, 0, sizeof(r));
    n = msgrcv(q, &r, sizeof(r.mtext), -10, IPC_NOWAIT);
    CHECK(n == (ssize_t)(strlen("five") + 1) && r.mtype == 5 && strcmp(r.mtext, "five") == 0);

    /* MSG_EXCEPT: type != 99 -> gets type 10 */
    memset(&r, 0, sizeof(r));
    n = msgrcv(q, &r, sizeof(r.mtext), 99, IPC_NOWAIT | MSG_EXCEPT);
    CHECK(n == (ssize_t)(strlen("ten") + 1) && r.mtype == 10 && strcmp(r.mtext, "ten") == 0);

    /* Now empty -> ENOMSG */
    CHECK(msgrcv(q, &r, sizeof(r.mtext), 0, IPC_NOWAIT) == -1 && errno == ENOMSG);

    /* IPC_SET lower qbytes, verify full -> EAGAIN */
    CHECK(msgctl(q, IPC_STAT, &ds) == 0);
    ds.msg_qbytes = 16;
    CHECK(msgctl(q, IPC_SET, &ds) == 0);
    CHECK(msgsnd(q, &m1, 16, IPC_NOWAIT) == 0);
    CHECK(msgsnd(q, &m1, 1, IPC_NOWAIT) == -1 && errno == EAGAIN);

    CHECK(msgctl(q, IPC_RMID, NULL) == 0);
    CHECK(msgctl(q, IPC_STAT, &ds) == -1 && errno == EINVAL);
}

static void test_msg_blocking_and_rmid(void) {
    int q = msgget(IPC_PRIVATE, 0600);
    CHECK(q >= 0);

    /* Blocking msgrcv woken by parent msgsnd */
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct test_msg r;
        memset(&r, 0, sizeof(r));
        ssize_t n = msgrcv(q, &r, sizeof(r.mtext), 7, 0);
        if (n != 6 || r.mtype != 7 || strcmp(r.mtext, "hello") != 0) _exit(2);
        _exit(0);
    }
    sleep_ms(30);
    struct test_msg s = { .mtype = 7, .mtext = "hello" };
    CHECK(msgsnd(q, &s, 6, 0) == 0);
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* Blocking msgrcv interrupted by signal -> EINTR even with SA_RESTART */
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig_handler;
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGUSR1, &sa, NULL) != 0) _exit(2);
        struct test_msg r;
        ssize_t n = msgrcv(q, &r, sizeof(r.mtext), 0, 0);
        if (n != -1 || errno != EINTR || got_sig != SIGUSR1) _exit(3);
        _exit(0);
    }
    sleep_ms(30);
    CHECK(kill(pid, SIGUSR1) == 0);
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* Blocking msgrcv woken by IPC_RMID -> EIDRM */
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct test_msg r;
        ssize_t n = msgrcv(q, &r, sizeof(r.mtext), 0, 0);
        if (n != -1 || errno != EIDRM) _exit(4);
        _exit(0);
    }
    sleep_ms(30);
    CHECK(msgctl(q, IPC_RMID, NULL) == 0);
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void test_sem_basic_and_atomic(void) {
    key_t k = 0x23456;
    int s = semget(k, 3, IPC_CREAT | IPC_EXCL | 0600);
    CHECK(s >= 0);
    CHECK(semget(k, 3, IPC_CREAT | IPC_EXCL | 0600) == -1 && errno == EEXIST);
    CHECK(semget(k, 4, 0) == -1 && errno == EINVAL);
    CHECK(semget(k, 0, 0) == s);

    union semun arg;
    unsigned short init_vals[3] = { 2, 0, 5 };
    arg.array = init_vals;
    CHECK(semctl(s, 0, SETALL, arg) == 0);
    CHECK(semctl(s, 0, GETVAL) == 2);
    CHECK(semctl(s, 1, GETVAL) == 0);
    CHECK(semctl(s, 2, GETVAL) == 5);
    CHECK(semctl(s, 0, GETPID) == getpid());

    unsigned short read_vals[3] = { 0, 0, 0 };
    arg.array = read_vals;
    CHECK(semctl(s, 0, GETALL, arg) == 0);
    CHECK(read_vals[0] == 2 && read_vals[1] == 0 && read_vals[2] == 5);

    arg.val = 40000;
    CHECK(semctl(s, 0, SETVAL, arg) == -1 && errno == ERANGE);

    /* Atomic multi-op: op 0 (-1 on sem 0) would succeed, op 1 (-1 on sem 1) fails EAGAIN */
    struct sembuf ops[2] = {
        { .sem_num = 0, .sem_op = -1, .sem_flg = 0 },
        { .sem_num = 1, .sem_op = -1, .sem_flg = IPC_NOWAIT },
    };
    CHECK(semop(s, ops, 2) == -1 && errno == EAGAIN);
    CHECK(semctl(s, 0, GETVAL) == 2); /* unchanged! */

    /* Out-of-range sem_num -> EFBIG */
    struct sembuf badop = { .sem_num = 3, .sem_op = 1, .sem_flg = 0 };
    CHECK(semop(s, &badop, 1) == -1 && errno == EFBIG);

    /* semtimedop timeout */
    struct sembuf waitop = { .sem_num = 1, .sem_op = -1, .sem_flg = 0 };
    struct timespec ts = { 0, 50 * 1000 * 1000 }; /* 50 ms */
    uint64_t t0 = mono_ms();
    CHECK(semtimedop(s, &waitop, 1, &ts) == -1 && errno == EAGAIN);
    uint64_t dt = mono_ms() - t0;
    CHECK(dt >= 35);

    /* GETNCNT / GETZCNT while children block */
    pid_t p_ncnt = fork();
    CHECK(p_ncnt >= 0);
    if (p_ncnt == 0) {
        struct sembuf op = { .sem_num = 1, .sem_op = -1, .sem_flg = 0 };
        if (semop(s, &op, 1) != 0) _exit(2);
        _exit(0);
    }
    pid_t p_zcnt = fork();
    CHECK(p_zcnt >= 0);
    if (p_zcnt == 0) {
        struct sembuf op = { .sem_num = 0, .sem_op = 0, .sem_flg = 0 };
        if (semop(s, &op, 1) != 0) _exit(3);
        _exit(0);
    }
    sleep_ms(40);
    CHECK(semctl(s, 1, GETNCNT) == 1);
    CHECK(semctl(s, 0, GETZCNT) == 1);

    /* Wake both children */
    struct sembuf wake[2] = {
        { .sem_num = 1, .sem_op = 1, .sem_flg = 0 },
        { .sem_num = 0, .sem_op = -2, .sem_flg = 0 },
    };
    CHECK(semop(s, wake, 2) == 0);
    int st = 0;
    CHECK(waitpid(p_ncnt, &st, 0) == p_ncnt && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(waitpid(p_zcnt, &st, 0) == p_zcnt && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    CHECK(semctl(s, 1, GETNCNT) == 0);
    CHECK(semctl(s, 0, GETZCNT) == 0);

    /* SEM_UNDO rollback on child exit wakes blocked parent/sibling */
    arg.val = 3;
    CHECK(semctl(s, 2, SETVAL, arg) == 0);
    pid_t p_undo = fork();
    CHECK(p_undo >= 0);
    if (p_undo == 0) {
        struct sembuf op = { .sem_num = 2, .sem_op = -3, .sem_flg = SEM_UNDO };
        if (semop(s, &op, 1) != 0) _exit(4);
        sleep_ms(40);
        _exit(0); /* exiting should restore sem 2 by +3 */
    }
    sleep_ms(15);
    CHECK(semctl(s, 2, GETVAL) == 0);
    struct sembuf wait_undo = { .sem_num = 2, .sem_op = -2, .sem_flg = 0 };
    CHECK(semop(s, &wait_undo, 1) == 0);
    CHECK(semctl(s, 2, GETVAL) == 1);
    CHECK(waitpid(p_undo, &st, 0) == p_undo && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    /* IPC_RMID wakes blocked semop with EIDRM */
    pid_t p_rm = fork();
    CHECK(p_rm >= 0);
    if (p_rm == 0) {
        struct sembuf op = { .sem_num = 1, .sem_op = -1, .sem_flg = 0 };
        if (semop(s, &op, 1) != -1 || errno != EIDRM) _exit(5);
        _exit(0);
    }
    sleep_ms(30);
    CHECK(semctl(s, 0, IPC_RMID) == 0);
    CHECK(waitpid(p_rm, &st, 0) == p_rm && WIFEXITED(st) && WEXITSTATUS(st) == 0);
}

static void test_ipc_perms(void) {
    int q = msgget(IPC_PRIVATE, 0600);
    int s = semget(IPC_PRIVATE, 1, 0600);
    CHECK(q >= 0 && s >= 0);

    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        if (setgid(65534) != 0 || setuid(65534) != 0) _exit(2);
        struct test_msg m = { .mtype = 1, .mtext = "no" };
        if (msgsnd(q, &m, 2, IPC_NOWAIT) != -1 || errno != EACCES) _exit(3);
        if (msgctl(q, IPC_RMID, NULL) != -1 || errno != EPERM) _exit(4);
        if (semctl(s, 0, GETVAL) != -1 || errno != EACCES) _exit(5);
        if (semctl(s, 0, IPC_RMID) != -1 || errno != EPERM) _exit(6);
        _exit(0);
    }
    int st = 0;
    CHECK(waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);

    CHECK(msgctl(q, IPC_RMID, NULL) == 0);
    CHECK(semctl(s, 0, IPC_RMID) == 0);
}

int main(void) {
    test_msg_basic();
    test_msg_blocking_and_rmid();
    test_sem_basic_and_atomic();
    test_ipc_perms();
    printf("sysv ipc msg/sem regression passed\n");
    return 0;
}
