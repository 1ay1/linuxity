#!/usr/bin/env python3
"""ipc_torture.py -- Linux inter-process communication: pipes, SysV shm /
semaphores / message queues, POSIX shm, semaphores and message queues,
eventfd, and multiprocessing's process-shared primitives.
See torture.py for how to run it."""
import sys
sys.dont_write_bytecode = True
import ctypes
import errno
import fcntl
import mmap
import os
import select
import signal
import struct
import time

from torture import *  # noqa: F401,F403
from torture import check, ok, eq, expect_errno, child, status, run_in_child, Skip, main, libc

IPC_PRIVATE, IPC_CREAT, IPC_EXCL, IPC_NOWAIT, IPC_RMID, IPC_STAT = 0, 0o1000, 0o2000, 0o4000, 0, 2
F_SETPIPE_SZ, F_GETPIPE_SZ = 1031, 1032

for name, res, args in (("shmget", ctypes.c_int, [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]),
                        ("shmat", ctypes.c_void_p, [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]),
                        ("shmdt", ctypes.c_int, [ctypes.c_void_p]),
                        ("shmctl", ctypes.c_int, [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]),
                        ("semget", ctypes.c_int, [ctypes.c_int, ctypes.c_int, ctypes.c_int]),
                        ("semop", ctypes.c_int, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]),
                        ("msgget", ctypes.c_int, [ctypes.c_int, ctypes.c_int]),
                        ("msgsnd", ctypes.c_int, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]),
                        ("msgrcv", ctypes.c_ssize_t, [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_long, ctypes.c_int]),
                        ("msgctl", ctypes.c_int, [ctypes.c_int, ctypes.c_int, ctypes.c_void_p])):
    f = getattr(libc, name)
    f.restype, f.argtypes = res, args


def err():
    return errname(ctypes.get_errno())


# ---------------------------------------------------------------- pipes

@check
def pipe_capacity_atomicity_and_eof():
    r, w = os.pipe()
    eq(fcntl.fcntl(w, F_GETPIPE_SZ), 65536, "default pipe size")
    os.set_blocking(w, False)
    n = 0
    try:
        while True:
            n += os.write(w, b"x" * 4096)
    except BlockingIOError:
        pass
    eq(n, 65536, "a non-blocking writer fills exactly the capacity")
    fcntl.fcntl(w, F_SETPIPE_SZ, 1 << 20)
    ok(fcntl.fcntl(w, F_GETPIPE_SZ) >= 1 << 20, "F_SETPIPE_SZ grows it")
    os.read(r, 1 << 20)
    os.close(w)
    eq(os.read(r, 10), b"", "EOF once the last writer is gone")

    r, w = os.pipe()

    def writer(tag):
        for _ in range(200):
            os.write(w, tag * 4096)              # exactly PIPE_BUF: must land whole
        return 0
    kids = [child(writer, t) for t in (b"a", b"b", b"c")]
    os.close(w)
    data = b""
    while (b := os.read(r, 1 << 16)):
        data += b
    for k in kids:
        eq(status(k), 0, "writer")
    eq(len(data), 3 * 200 * 4096, "all bytes")
    chunks = [data[i:i + 4096] for i in range(0, len(data), 4096)]
    eq(sum(1 for c in chunks if len(set(c)) != 1), 0, "writes of PIPE_BUF (4096) never interleave")


@check
def pipe_epipe_and_poll_states():
    r, w = os.pipe()
    p = select.poll()
    p.register(w, select.POLLOUT)
    eq(p.poll(0)[0][1] & select.POLLOUT, select.POLLOUT, "an empty pipe is writable")
    os.close(r)
    ev = p.poll(0)
    ok(ev and ev[0][1] & select.POLLERR, f"writer sees POLLERR once readers are gone: {ev}")
    eq(run_in_child(lambda: os.write(w, b"x")), -signal.SIGPIPE, "writing kills with SIGPIPE")
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    expect_errno(errno.EPIPE, "with SIGPIPE ignored, EPIPE", os.write, w, b"x")
    r2, w2 = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
    ok(not os.get_blocking(r2) and not os.get_inheritable(r2), "pipe2 flags")
    expect_errno(errno.EAGAIN, "reading an empty non-blocking pipe", os.read, r2, 1)


# ---------------------------------------------------------------- SysV

@check
def sysv_shared_memory():
    sid = libc.shmget(IPC_PRIVATE, 1 << 20, IPC_CREAT | 0o600)
    ok(sid >= 0, f"shmget: {err()}")
    try:
        a = libc.shmat(sid, None, 0)
        ok(a not in (None, ctypes.c_void_p(-1).value), f"shmat: {err()}")
        ctypes.memmove(a, b"parent", 6)

        def kid():
            ctypes.memmove(a + 100, b"child", 5)
            b = libc.shmat(sid, None, 0)             # a second attach in the child
            return 0 if ctypes.string_at(b, 6) == b"parent" else 1
        eq(run_in_child(kid), 0, "the child sees the segment")
        eq(ctypes.string_at(a + 100, 5), b"child", "the parent sees the child's store")
        ds = ctypes.create_string_buffer(256)
        eq(libc.shmctl(sid, IPC_STAT, ds), 0, f"IPC_STAT: {err()}")
        segsz = struct.unpack_from("Q", ds.raw, 48)[0]
        eq(segsz, 1 << 20, "shm_segsz")
        with open("/proc/sysvipc/shm") as f:
            ok(any(l.split()[1] == str(sid) for l in f.readlines()[1:]), "/proc/sysvipc/shm lists it")
        eq(libc.shmdt(a), 0, "shmdt")
    finally:
        libc.shmctl(sid, IPC_RMID, None)
    eq(libc.shmat(sid, None, 0), ctypes.c_void_p(-1).value, "attach after IPC_RMID")


@check
def sysv_semaphores_block_and_wake():
    sem = libc.semget(IPC_PRIVATE, 1, IPC_CREAT | 0o600)
    ok(sem >= 0, f"semget: {err()}")
    try:
        def op(delta, flags=0):
            buf = struct.pack("HhH", 0, delta, flags)
            return libc.semop(sem, buf, 1)
        eq(op(-1, IPC_NOWAIT), -1, "taking from 0 with IPC_NOWAIT")
        eq(ctypes.get_errno(), errno.EAGAIN, "is EAGAIN")

        def releaser():
            time.sleep(0.3)
            return 0 if op(1) == 0 else 1
        pid = child(releaser)
        t = time.monotonic()
        eq(op(-1), 0, "a blocking take")
        ok(time.monotonic() - t >= 0.2, "it waited for the child's release")
        eq(status(pid), 0, "releaser")
    finally:
        libc.semctl(sem, 0, IPC_RMID)


@check
def sysv_message_queues():
    q = libc.msgget(IPC_PRIVATE, IPC_CREAT | 0o600)
    ok(q >= 0, f"msgget: {err()}")
    try:
        def send(mtype, text):
            m = struct.pack("q", mtype) + text
            eq(libc.msgsnd(q, m, len(text), 0), 0, f"msgsnd: {err()}")

        def recv(mtype, flags=0):
            buf = ctypes.create_string_buffer(8 + 64)
            n = libc.msgrcv(q, buf, 64, mtype, flags)
            return None if n < 0 else (struct.unpack_from("q", buf.raw)[0], buf.raw[8:8 + n])
        send(2, b"two"); send(1, b"one"); send(3, b"three")
        eq(recv(1), (1, b"one"), "by type")
        eq(recv(0), (2, b"two"), "type 0: the first in the queue")
        eq(recv(-5), (3, b"three"), "negative type: lowest <= 5")
        eq(recv(0, IPC_NOWAIT), None, "an empty queue")
        eq(ctypes.get_errno(), errno.ENOMSG, "is ENOMSG")
        eq(run_in_child(lambda: send(9, b"from kid")), 0, "a child sends")
        eq(recv(9), (9, b"from kid"), "the parent receives it")
    finally:
        libc.msgctl(q, IPC_RMID, None)


# ---------------------------------------------------------------- POSIX

@check
def posix_shared_memory():
    name = f"/torture-{os.getpid()}"
    libc.shm_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    fd = libc.shm_open(name.encode(), os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    ok(fd >= 0, f"shm_open: {err()}")
    try:
        os.ftruncate(fd, 4096)
        m = mmap.mmap(fd, 4096)
        ok(os.path.exists("/dev/shm" + name), "it lives in /dev/shm")

        def kid():
            f2 = libc.shm_open(name.encode(), os.O_RDWR, 0)
            m2 = mmap.mmap(f2, 4096)
            m2[:3] = b"kid"
            return 0
        eq(run_in_child(kid), 0, "a child opens it by name")
        eq(m[:3], b"kid", "and its store is shared")
    finally:
        libc.shm_unlink(name.encode())
    ok(not os.path.exists("/dev/shm" + name), "shm_unlink removed it")


@check
def posix_named_semaphores():
    libc.sem_open.restype = ctypes.c_void_p
    libc.sem_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    for f in ("sem_wait", "sem_post", "sem_close", "sem_trywait"):
        getattr(libc, f).argtypes = [ctypes.c_void_p]
    name = f"/torture-sem-{os.getpid()}".encode()
    s = libc.sem_open(name, os.O_CREAT | os.O_EXCL, 0o600, 0)
    ok(s and s != ctypes.c_void_p(-1).value, f"sem_open: {err()}")
    try:
        eq(libc.sem_trywait(s), -1, "trywait on 0")

        def poster():
            time.sleep(0.2)
            s2 = libc.sem_open(name, 0, 0, 0)
            return libc.sem_post(s2)
        pid = child(poster)
        t = time.monotonic()
        eq(libc.sem_wait(s), 0, "sem_wait")
        ok(time.monotonic() - t >= 0.1, "it waited for the other process")
        eq(status(pid), 0, "poster")
    finally:
        libc.sem_unlink(name)


@check
def posix_message_queues():
    class Attr(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_long), ("maxmsg", ctypes.c_long),
                    ("msgsize", ctypes.c_long), ("curmsgs", ctypes.c_long), ("pad", ctypes.c_long * 4)]
    libc.mq_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(Attr)]
    libc.mq_send.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint]
    libc.mq_receive.restype = ctypes.c_ssize_t
    libc.mq_receive.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_uint)]
    name = f"/torture-mq-{os.getpid()}".encode()
    attr = Attr(0, 8, 64, 0)
    q = libc.mq_open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600, ctypes.byref(attr))
    ok(q >= 0, f"mq_open: {err()}")
    try:
        for text, prio in ((b"low", 1), (b"high", 9), (b"mid", 5)):
            eq(libc.mq_send(q, text, len(text), prio), 0, f"mq_send: {err()}")
        got = []
        for _ in range(3):
            buf, pr = ctypes.create_string_buffer(64), ctypes.c_uint()
            n = libc.mq_receive(q, buf, 64, ctypes.byref(pr))
            got.append((buf.raw[:n], pr.value))
        eq(got, [(b"high", 9), (b"mid", 5), (b"low", 1)], "highest priority first")

        def kid():
            q2 = libc.mq_open(name, os.O_WRONLY, 0, None)
            return libc.mq_send(q2, b"cross", 5, 0)
        eq(run_in_child(kid), 0, "another process sends")
        buf = ctypes.create_string_buffer(64)
        n = libc.mq_receive(q, buf, 64, None)
        eq(buf.raw[:n], b"cross", "and we receive")
        p = select.poll(); p.register(q, select.POLLIN)
        eq(p.poll(0), [], "an empty mqueue is not readable")
    finally:
        libc.mq_unlink(name)


# ---------------------------------------------------------------- eventfd & friends

@check
def eventfd_counter_and_semaphore():
    e = os.eventfd(0, os.EFD_NONBLOCK)
    expect_errno(errno.EAGAIN, "reading a zero counter", os.eventfd_read, e)
    os.eventfd_write(e, 3); os.eventfd_write(e, 4)
    eq(os.eventfd_read(e), 7, "writes add up; a read takes all")
    s = os.eventfd(3, os.EFD_SEMAPHORE | os.EFD_NONBLOCK)
    eq([os.eventfd_read(s) for _ in range(3)], [1, 1, 1], "EFD_SEMAPHORE gives one at a time")
    expect_errno(errno.EAGAIN, "then nothing", os.eventfd_read, s)
    w = os.eventfd(0)
    eq(run_in_child(lambda: os.eventfd_write(w, 5) or 0), 0, "a child signals")
    eq(os.eventfd_read(w), 5, "across fork")
    expect_errno(errno.EINVAL, "a write of 2^64-1", os.write, e, struct.pack("Q", 2**64 - 1))


@check
def multiprocessing_primitives():
    import multiprocessing as mp
    ctx = mp.get_context("fork")
    lock, val, q = ctx.Lock(), ctx.Value("i", 0), ctx.Queue()

    def work(n):
        for _ in range(500):
            with lock:
                val.value += 1
        q.put(n * n)
    ps = [ctx.Process(target=work, args=(i,)) for i in range(4)]
    for p in ps:
        p.start()
    got = sorted(q.get(timeout=20) for _ in ps)
    for p in ps:
        p.join(20)
        eq(p.exitcode, 0, "worker")
    eq(val.value, 2000, "a process-shared lock serialised every increment")
    eq(got, [0, 1, 4, 9], "results through a Queue")
    with ctx.Pool(4) as pool:
        eq(pool.map(abs, range(-50, 0)), list(range(50, 0, -1)), "Pool.map")
    a, b = ctx.Pipe()
    p = ctx.Process(target=lambda c: c.send(c.recv()[::-1]), args=(b,))
    p.start()
    a.send(b"pipe!")
    eq(a.recv(), b"!epip", "a multiprocessing Pipe")
    p.join(10)


if __name__ == "__main__":
    sys.exit(main("ipc"))
