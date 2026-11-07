"""System V IPC: message queues, semaphores and shared memory, via ctypes."""
import ctypes
import errno
import os

from lxt import check, eq, expect_errno, libc, reap, spawn, test

IPC_PRIVATE, IPC_CREAT, IPC_NOWAIT, IPC_RMID, IPC_STAT = 0, 0o1000, 0o4000, 0, 2
GETVAL, SETVAL, SEM_UNDO = 12, 16, 0o10000

for name, res, args in (("msgget", ctypes.c_int, [ctypes.c_int, ctypes.c_int]),
                        ("msgsnd", ctypes.c_int, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]),
                        ("msgrcv", ctypes.c_ssize_t, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_long, ctypes.c_int]),
                        ("msgctl", ctypes.c_int, [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]),
                        ("semget", ctypes.c_int, [ctypes.c_int, ctypes.c_int, ctypes.c_int]),
                        ("semop", ctypes.c_int, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]),
                        ("semctl", ctypes.c_int, [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]),
                        ("shmget", ctypes.c_int, [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]),
                        ("shmat", ctypes.c_void_p, [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]),
                        ("shmdt", ctypes.c_int, [ctypes.c_void_p]),
                        ("shmctl", ctypes.c_int, [ctypes.c_int, ctypes.c_int, ctypes.c_void_p])):
    f = getattr(libc, name)
    f.restype, f.argtypes = res, args


def ok(rc, what):
    if rc == -1:
        e = ctypes.get_errno()
        raise AssertionError(f"{what}: {errno.errorcode.get(e, e)}")
    return rc


class Msg(ctypes.Structure):
    _fields_ = [("mtype", ctypes.c_long), ("mtext", ctypes.c_char * 64)]


class SemBuf(ctypes.Structure):
    _fields_ = [("num", ctypes.c_ushort), ("op", ctypes.c_short), ("flg", ctypes.c_short)]


@test
def message_queue():
    """msgsnd/msgrcv by type, across fork, and IPC_RMID."""
    q = ok(libc.msgget(IPC_PRIVATE, IPC_CREAT | 0o600), "msgget")
    try:
        for t, s in ((3, b"three"), (1, b"one")):
            m = Msg(t, s)
            ok(libc.msgsnd(q, ctypes.byref(m), len(s), 0), "msgsnd")
        r = Msg()
        eq(libc.msgrcv(q, ctypes.byref(r), 64, 1, 0), 3, "msgrcv by type")
        eq(r.mtext, b"one", "message text")

        def child():
            m = Msg()
            return 0 if libc.msgrcv(q, ctypes.byref(m), 64, 9, 0) == 2 and m.mtext == b"hi" else 1
        pid = spawn(child)
        os.sched_yield()
        ok(libc.msgsnd(q, ctypes.byref(Msg(9, b"hi")), 2, 0), "msgsnd to the child")
        eq(reap(pid), 0, "a blocked child gets the message")
    finally:
        libc.msgctl(q, IPC_RMID, None)
    check(libc.msgsnd(q, ctypes.byref(Msg(1, b"x")), 1, 0) == -1, "removed queue refuses")
    return "by type, blocking across fork, IPC_RMID"


@test
def semaphores():
    """semop up/down, IPC_NOWAIT, a blocked child, SEM_UNDO."""
    s = ok(libc.semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600), "semget")
    try:
        ok(libc.semctl(s, 0, SETVAL, 1), "SETVAL")
        down, up = SemBuf(0, -1, 0), SemBuf(0, 1, 0)
        ok(libc.semop(s, ctypes.byref(down), 1), "down")
        check(libc.semop(s, ctypes.byref(SemBuf(0, -1, IPC_NOWAIT)), 1) == -1 and
              ctypes.get_errno() == errno.EAGAIN, "IPC_NOWAIT is EAGAIN")
        pid = spawn(lambda: 0 if libc.semop(s, ctypes.byref(SemBuf(0, -1, 0)), 1) == 0 else 1)
        os.sched_yield()
        ok(libc.semop(s, ctypes.byref(up), 1), "up")
        eq(reap(pid), 0, "the blocked child woke")
        ok(libc.semctl(s, 0, SETVAL, 4), "SETVAL 4")
        pid = spawn(lambda: libc.semop(s, ctypes.byref(SemBuf(0, -3, SEM_UNDO)), 1) and 0)
        reap(pid)
        eq(libc.semctl(s, 0, GETVAL, 0), 4, "SEM_UNDO reverted on exit")
    finally:
        libc.semctl(s, 0, IPC_RMID, 0)
    return "down/up, EAGAIN, blocking, SEM_UNDO"


@test
def shared_memory():
    """A segment really is shared with a forked child and a second attach."""
    h = ok(libc.shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0o600), "shmget")
    try:
        addr = libc.shmat(h, None, 0)
        check(addr not in (None, ctypes.c_void_p(-1).value), "shmat")
        buf = (ctypes.c_char * 4096).from_address(addr)
        buf[0:6] = b"parent"

        def child():
            a2 = libc.shmat(h, None, 0)
            b2 = (ctypes.c_char * 4096).from_address(a2)
            good = bytes(buf[0:6]) == b"parent" and bytes(b2[0:6]) == b"parent"
            b2[100:105] = b"child"
            libc.shmdt(a2)
            return 0 if good else 1
        eq(reap(spawn(child)), 0, "the child saw the parent's write")
        eq(bytes(buf[100:105]), b"child", "the parent sees the child's write")
        ok(libc.shmctl(h, IPC_RMID, None), "IPC_RMID while attached")
        eq(bytes(buf[0:6]), b"parent", "memory lives until the last detach")
        ok(libc.shmdt(addr), "shmdt")
    finally:
        libc.shmctl(h, IPC_RMID, None)
    return "shared across fork and attaches, IPC_RMID while attached"


@test
def proc_sysvipc():
    """/proc/sysvipc lists the same objects IPC_STAT sees, in the kernel's layout."""
    heads = {
        "msg": "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
        "sem": "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
        "shm": "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n",
    }
    for f, h in heads.items():
        with open(f"/proc/sysvipc/{f}") as fh:
            eq(fh.readline(), h, f"{f} header")
    q = ok(libc.msgget(0x4c58ab07, IPC_CREAT | 0o640), "msgget")
    h = ok(libc.shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0o600), "shmget")
    try:
        ok(libc.msgsnd(q, ctypes.byref(Msg(1, b"abc")), 3, 0), "msgsnd")
        with open("/proc/sysvipc/msg") as fh:
            row = next(l for l in fh if l.split()[1:2] == [str(q)])
        want = "%10d %10d  %4o  %10d %10d %5d %5d %5d %5d %5d %5d %10d %10d %10d\n"
        f = row.split()
        eq(row, want % (0x4c58ab07, q, 0o640, 3, 1, int(f[5]), 0, *map(int, f[7:11]), int(f[11]), 0, int(f[13])),
           "msg row, byte for byte")
        eq(int(f[5]), os.getpid(), "lspid is the sender")
        with open("/proc/sysvipc/shm") as fh:
            srow = next(l.split() for l in fh if l.split()[1:2] == [str(h)])
        eq((srow[2], srow[3], srow[6]), ("600", "8192", "0"), "shm perms, size, nattch")
    finally:
        libc.msgctl(q, IPC_RMID, None)
        libc.shmctl(h, IPC_RMID, None)
    with open("/proc/sysvipc/msg") as fh:
        check(not any(l.split()[1:2] == [str(q)] for l in fh), "a removed queue leaves the file")
    return "headers, an exact row, shm columns, removal"
