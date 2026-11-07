"""Concurrent filesystem use: appends, renames, locks and FIFOs under load."""
import errno
import fcntl
import os
import struct
import subprocess

from lxt import check, eq, expect_errno, must, reap, reap_within, spawn, test


@test
def append_atomicity():
    """8 processes x 2000 O_APPEND lines: none torn, none lost, order kept per writer."""
    def writer(i):
        fd = os.open("append.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        for j in range(2000):
            os.write(fd, f"{i:02d}:{j:06d}:".encode() + b"#" * 89 + b"\n")

    for p in [spawn(writer, i) for i in range(8)]:
        must(p)
    with open("append.log", "rb") as f:
        lines = f.read().split(b"\n")[:-1]
    eq(len(lines), 16000, "lines")
    seen = {i: [] for i in range(8)}
    for ln in lines:
        check(len(ln) == 99 and ln.endswith(b"#" * 89), f"torn line {ln[:30]!r}")
        seen[int(ln[:2])].append(int(ln[3:9]))
    for i in range(8):
        eq(seen[i], list(range(2000)), f"writer {i} order")
    return "16000 lines intact"


@test
def rename_never_gaps():
    """Readers never see a missing or torn file while writers rename over it."""
    with open("current", "w") as f:
        f.write("v0" * 1000)

    def writer(k):
        for i in range(1500):
            tmp = f"tmp-{k}-{i}"
            with open(tmp, "w") as f:
                f.write(f"v{k}" * 1000)
            os.rename(tmp, "current")

    def reader():
        for _ in range(4000):
            with open("current") as f:
                d = f.read()
            if len(d) != 2000 or len(set(d[i:i + 2] for i in range(0, 2000, 2))) != 1:
                return 5

    ws = [spawn(writer, k) for k in range(4)]
    rs = [spawn(reader) for _ in range(4)]
    for p in ws:
        must(p, "writer")
    for p in rs:
        eq(reap(p), 0, "a reader saw a gap or a torn file")
    return "6000 renames, 16000 reads"


@test
def flock_and_posix_locks():
    """flock, POSIX close semantics, F_GETLK owner, OFD locks and EDEADLK."""
    p1r, p1w = os.pipe()
    p2r, p2w = os.pipe()
    fd = os.open("lockfile", os.O_RDWR | os.O_CREAT, 0o644)

    def holder():
        f = os.open("lockfile", os.O_RDWR)
        fcntl.flock(f, fcntl.LOCK_EX)
        os.write(p1w, b"L")
        os.read(p2r, 1)

    pid = spawn(holder)
    os.read(p1r, 1)
    expect_errno((errno.EWOULDBLOCK, errno.EAGAIN), "flock held elsewhere", fcntl.flock, fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(p2w, b"go")
    must(pid)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    fa = os.open("posix", os.O_RDWR | os.O_CREAT, 0o644)
    fb = os.open("posix", os.O_RDWR)
    fcntl.lockf(fa, fcntl.LOCK_EX)
    me = os.getpid()

    def probe():
        f = os.open("posix", os.O_RDWR)
        res = fcntl.fcntl(f, fcntl.F_GETLK, struct.pack("hhqqi4x", fcntl.F_WRLCK, 0, 0, 0, 0))
        typ, _, _, _, owner = struct.unpack("hhqqi4x", res)
        os.write(p1w, struct.pack("i", owner))
        return 1 if typ != fcntl.F_UNLCK else 0

    eq(reap(spawn(probe)), 1, "a child sees our POSIX lock")
    eq(struct.unpack("i", os.read(p1r, 4))[0], me, "F_GETLK l_pid")
    os.close(fb)     # closing ANY fd of the file drops our POSIX locks
    eq(reap(spawn(probe)), 0, "lock after closing another fd")
    os.read(p1r, 4)

    o1 = os.open("ofd", os.O_RDWR | os.O_CREAT, 0o644)
    o2 = os.open("ofd", os.O_RDWR)
    lk = struct.pack("hhqqi4x", fcntl.F_WRLCK, 0, 0, 0, 0)
    fcntl.fcntl(o1, fcntl.F_OFD_SETLK, lk)
    expect_errno((errno.EAGAIN, errno.EACCES), "OFD lock from a second open", fcntl.fcntl, o2, fcntl.F_OFD_SETLK, lk)

    dl = os.open("deadlock", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(dl, b"ab")
    fcntl.lockf(dl, fcntl.LOCK_EX, 1, 0)

    def other():
        f = os.open("deadlock", os.O_RDWR)
        fcntl.lockf(f, fcntl.LOCK_EX, 1, 1)
        os.write(p1w, b"1")
        try:
            fcntl.lockf(f, fcntl.LOCK_EX, 1, 0)
        except OSError as e:
            return 9 if e.errno == errno.EDEADLK else 8

    pid = spawn(other)
    os.read(p1r, 1)
    try:
        fcntl.lockf(dl, fcntl.LOCK_EX, 1, 1)
        mine = False
    except OSError as e:
        eq(e.errno, errno.EDEADLK, "deadlock errno")
        mine = True
        fcntl.lockf(dl, fcntl.LOCK_UN, 1, 0)
    eq(reap_within(pid, 10), 0 if mine else 9, "EDEADLK detected exactly once")
    return "flock, POSIX close trap, l_pid, OFD, EDEADLK"


@test
def fifos():
    """FIFO rendezvous in both orders, many rounds, O_RDWR, and from a shell."""
    os.mkfifo("f")

    def writer(rounds):
        for i in range(rounds):
            with open("f", "wb") as f:
                f.write(b"%06d\n" % i)

    pid = spawn(writer, 1)
    with open("f", "rb") as f:
        eq(f.read(), b"000000\n", "writer first")
    must(pid)

    def reader():
        with open("f", "rb") as f:
            return 0 if f.read() == b"reader-first\n" else 1

    pid = spawn(reader)
    with open("f", "wb") as f:
        f.write(b"reader-first\n")
    must(pid)

    def big_writer():
        with open("f", "wb") as f:
            for i in range(1000):
                f.write(b"%06d\n" % i)

    pid = spawn(big_writer)
    with open("f", "rb") as f:
        lines = f.read().split()
    must(pid)
    eq(lines, [b"%06d" % i for i in range(1000)], "1000 lines")
    fd = os.open("f", os.O_RDWR)
    os.write(fd, b"loop")
    eq(os.read(fd, 4), b"loop", "O_RDWR on a FIFO")
    os.close(fd)
    r = subprocess.run(["/bin/sh", "-c", "echo from-sh > f & cat f; wait"],
                       capture_output=True, text=True, timeout=20)
    eq(r.stdout, "from-sh\n", "shell writer and reader")
    return "both orders, 1000 lines, O_RDWR, shell"
