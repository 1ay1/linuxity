// sysvipc.c -- System V message queues, semaphores and shared memory.
//
// Every step is a fixed yes/no (or a stable errno), so native Linux and
// linuxity give byte-identical traces. Android's kernel has no SysV IPC
// (ENOSYS natively); linuxity serves it there, and the law exempts that
// direction only.
#define _GNU_SOURCE
#include "probe.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>

#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

#ifndef SIGCHLD
#define SIGCHLD 17
#endif

static long do_fork(void) {
    fflush(stdout);
#ifdef SYS_fork
    return LX_SYS0(SYS_fork);
#else
    return LX_SYS5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}
static int reap(long pid) {
    int st = 0;
    LX_SYS4(SYS_wait4, pid, &st, 0, 0);
    return (st & 0x7f) == 0 ? (st >> 8) & 0xff : 128;
}
static void nap(void) {
    static const long ts[2] = {0, 30000000};
    LX_SYS2(SYS_nanosleep, ts, 0);
}

int main(void) {
    // ---- message queues -------------------------------------------------
    const long q = LX_SYS2(SYS_msgget, IPC_PRIVATE, IPC_CREAT | 0600);
    lx_emit("msgget", q >= 0 ? 1 : q, "msgget IPC_PRIVATE");
    const int hq = q >= 0;
    static struct { long t; char s[32]; } m, r;
    m.t = 2; strcpy(m.s, "two");
    lx_emit("msgsnd", hq ? LX_SYS4(SYS_msgsnd, q, &m, 4, 0) : LX_NA, "msgsnd type 2");
    m.t = 1; strcpy(m.s, "one");
    lx_emit("msgsnd", hq ? LX_SYS4(SYS_msgsnd, q, &m, 4, 0) : LX_NA, "msgsnd type 1");
    long n = hq ? LX_SYS5(SYS_msgrcv, q, &r, sizeof r.s, 1, 0) : -1;
    lx_emit("msgrcv", LX_CHECK(hq, n == 4 && r.t == 1 && !strcmp(r.s, "one")), "msgrcv picks by type");
    lx_emit("msgrcv", hq ? LX_SYS5(SYS_msgrcv, q, &r, 2, 0, IPC_NOWAIT) : LX_NA, "a short buffer is E2BIG");
    n = hq ? LX_SYS5(SYS_msgrcv, q, &r, 2, 0, MSG_NOERROR) : -1;
    lx_emit("msgrcv", LX_CHECK(hq, n == 2 && r.t == 2), "MSG_NOERROR truncates");
    lx_emit("msgrcv", hq ? LX_SYS5(SYS_msgrcv, q, &r, sizeof r.s, 0, IPC_NOWAIT) : LX_NA,
            "an empty queue with IPC_NOWAIT is ENOMSG");
    static struct msqid_ds ds;
    n = hq ? LX_SYS3(SYS_msgctl, q, IPC_STAT, &ds) : -1;
    lx_emit("msgctl", LX_CHECK(hq, n == 0 && ds.msg_qnum == 0 && ds.msg_qbytes > 0 &&
                                   (ds.msg_perm.mode & 0777) == 0600),
            "IPC_STAT: empty, mode 0600");
    // a child blocks in msgrcv until the parent sends
    if (hq) {
        const long p = do_fork();
        if (p == 0) {
            static struct { long t; char s[8]; } x;
            const long got = LX_SYS5(SYS_msgrcv, q, &x, 8, 7, 0);
            LX_SYS1(SYS_exit_group, got == 3 && !strcmp(x.s, "hi") ? 0 : 1);
        }
        nap();
        static struct { long t; char s[8]; } x = {7, "hi"};
        LX_SYS4(SYS_msgsnd, q, &x, 3, 0);
        lx_emit("msgrcv", reap(p) == 0, "a blocked child gets the parent's message");
    } else {
        lx_emit("msgrcv", LX_NA, "a blocked child gets the parent's message");
    }
    lx_emit("msgctl", hq ? LX_SYS3(SYS_msgctl, q, IPC_RMID, 0) : LX_NA, "IPC_RMID");
    lx_emit("msgsnd", hq ? LX_SYS4(SYS_msgsnd, q, &m, 4, 0) : LX_NA, "a removed queue is EINVAL");
    const long k1 = LX_SYS2(SYS_msgget, 0x4c58ab01, IPC_CREAT | 0600);
    const long k2 = k1 >= 0 ? LX_SYS2(SYS_msgget, 0x4c58ab01, 0600) : -1;
    lx_emit("msgget", LX_CHECK(k1 >= 0, k1 == k2), "the same key finds the same queue");
    lx_emit("msgget", k1 >= 0 ? LX_SYS2(SYS_msgget, 0x4c58ab01, IPC_CREAT | IPC_EXCL | 0600) : LX_NA,
            "IPC_EXCL on a taken key is EEXIST");
    if (k1 >= 0) LX_SYS3(SYS_msgctl, k1, IPC_RMID, 0);
    lx_emit("msgget", hq ? LX_SYS2(SYS_msgget, 0x4c58ab02, 0600) : LX_NA, "a missing key is ENOENT");

    // ---- semaphores ------------------------------------------------------
    const long s = LX_SYS3(SYS_semget, IPC_PRIVATE, 2, IPC_CREAT | 0600);
    lx_emit("semget", s >= 0 ? 1 : s, "semget 2 semaphores");
    const int hs = s >= 0;
    lx_emit("semctl", hs ? LX_SYS4(SYS_semctl, s, 0, SETVAL, 1) : LX_NA, "SETVAL 1");
    lx_emit("semctl", hs ? LX_SYS4(SYS_semctl, s, 0, GETVAL, 0) : LX_NA, "GETVAL");
    static struct sembuf down = {0, -1, 0}, up = {0, 1, 0}, nw = {0, -1, IPC_NOWAIT};
    lx_emit("semop", hs ? LX_SYS3(SYS_semop, s, &down, 1) : LX_NA, "semop down");
    lx_emit("semop", hs ? LX_SYS3(SYS_semop, s, &nw, 1) : LX_NA, "would block with IPC_NOWAIT is EAGAIN");
    static const long ts[2] = {0, 50000000};
    lx_emit("semtimedop", hs ? LX_SYS4(SYS_semtimedop, s, &down, 1, ts) : LX_NA,
            "semtimedop times out with EAGAIN");
    if (hs) {
        const long p = do_fork();
        if (p == 0) LX_SYS1(SYS_exit_group, LX_SYS3(SYS_semop, s, &down, 1) == 0 ? 0 : 1);
        nap();
        LX_SYS3(SYS_semop, s, &up, 1);
        lx_emit("semop", reap(p) == 0, "a blocked child wakes when the parent ups");
    } else {
        lx_emit("semop", LX_NA, "a blocked child wakes when the parent ups");
    }
    static unsigned short vals[2] = {5, 0};
    lx_emit("semctl", hs ? LX_SYS4(SYS_semctl, s, 0, SETALL, vals) : LX_NA, "SETALL 5, 0");
    static struct sembuf two[2] = {{0, -1, IPC_NOWAIT}, {1, -1, IPC_NOWAIT}};
    n = hs ? LX_SYS3(SYS_semop, s, two, 2) : 0;
    lx_emit("semop", LX_CHECK(hs, n == -EAGAIN && LX_SYS4(SYS_semctl, s, 0, GETVAL, 0) == 5),
            "semop is all or nothing");
    if (hs) {
        const long p = do_fork();
        if (p == 0) {
            static struct sembuf u = {0, -2, SEM_UNDO};
            LX_SYS3(SYS_semop, s, &u, 1);
            LX_SYS1(SYS_exit_group, 0);
        }
        reap(p);
    }
    lx_emit("semctl", LX_CHECK(hs, LX_SYS4(SYS_semctl, s, 0, GETVAL, 0) == 5), "SEM_UNDO reverts on exit");
    static struct semid_ds sds;
    n = hs ? LX_SYS4(SYS_semctl, s, 0, IPC_STAT, &sds) : -1;
    lx_emit("semctl", LX_CHECK(hs, n == 0 && sds.sem_nsems == 2), "IPC_STAT nsems 2");
    lx_emit("semctl", hs ? LX_SYS4(SYS_semctl, s, 0, IPC_RMID, 0) : LX_NA, "IPC_RMID");

    // ---- shared memory ---------------------------------------------------
    const long h = LX_SYS3(SYS_shmget, IPC_PRIVATE, 8192, IPC_CREAT | 0600);
    lx_emit("shmget", h >= 0 ? 1 : h, "shmget 8 KiB");
    const int hh = h >= 0;
    char* mem = hh ? (char*)LX_SYS3(SYS_shmat, h, 0, 0) : (char*)-1;
    const int at = hh && (long)mem > 0;
    lx_emit("shmat", LX_CHECK(hh, at), "shmat");
    if (at) strcpy(mem, "parent");
    static struct shmid_ds hds;
    n = at ? LX_SYS3(SYS_shmctl, h, IPC_STAT, &hds) : -1;
    lx_emit("shmctl", LX_CHECK(at, n == 0 && hds.shm_segsz == 8192 && hds.shm_nattch == 1),
            "IPC_STAT size and nattch");
    if (at) {
        const long p = do_fork();
        if (p == 0) {
            char* m2 = (char*)LX_SYS3(SYS_shmat, h, 0, 0);
            const int okc = (long)m2 > 0 && !strcmp(mem, "parent") && !strcmp(m2, "parent");
            if ((long)m2 > 0) { strcpy(m2 + 100, "child"); LX_SYS1(SYS_shmdt, m2); }
            LX_SYS1(SYS_exit_group, okc ? 0 : 1);
        }
        lx_emit("shmat", reap(p) == 0, "a child shares the parent's pages");
    } else {
        lx_emit("shmat", LX_NA, "a child shares the parent's pages");
    }
    lx_emit("shmat", LX_CHECK(at, !strcmp(mem + 100, "child")), "the parent sees the child's write");
    lx_emit("shmctl", at ? LX_SYS3(SYS_shmctl, h, IPC_RMID, 0) : LX_NA, "IPC_RMID while attached");
    lx_emit("shmctl", LX_CHECK(at, !strcmp(mem, "parent")), "the memory lives until the last detach");
    lx_emit("shmdt", at ? LX_SYS1(SYS_shmdt, mem) : LX_NA, "shmdt");
    lx_emit("shmdt", at ? LX_SYS1(SYS_shmdt, mem) : LX_NA, "shmdt twice is EINVAL");
    return 0;
}
