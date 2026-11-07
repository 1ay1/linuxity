#!/usr/bin/env python3
# crazy.py: a mean Linux conformance + stress test.
# Every test runs in its own forked process group with a deadline, so a hang
# or crash in one can't take down the rest.
#   python3 crazy.py              run everything
#   python3 crazy.py pty_session  run some tests by name
#   >>> exec(open('crazy.py').read())   from a python prompt

import asyncio, ctypes, errno, fcntl, hashlib, json, mmap, os, pty, random
import resource, select, shutil, signal, socket, stat, struct, subprocess, sys
import termios, threading, time, traceback, warnings
import multiprocessing as mp
from multiprocessing import shared_memory

warnings.simplefilter("ignore")

ROOT = os.environ.get("CRAZY_ROOT") or (
    "/root/crazy-test" if os.access("/root", os.W_OK) else "/tmp/crazy-test")
TIMEOUT = 60
TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def expect_errno(codes, label, fn, *a, **kw):
    codes = codes if isinstance(codes, tuple) else (codes,)
    want = "/".join(errno.errorcode[c] for c in codes)
    try:
        fn(*a, **kw)
    except OSError as e:
        if e.errno in codes:
            return
        raise AssertionError(f"{label}: got {errno.errorcode.get(e.errno, e.errno)}, want {want}")
    raise AssertionError(f"{label}: succeeded, want {want}")


def spawn(fn, *a):
    """fork; the child runs fn(*a) and exits with its int result (or 0)."""
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            r = fn(*a)
            code = r if isinstance(r, int) else 0
        except BaseException as e:
            print(f"    ! child {getattr(fn, '__name__', fn)}: {type(e).__name__}: {e}",
                  file=sys.stderr, flush=True)
        finally:
            os._exit(code)
    return pid


def reap(pid):
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)


def must(pid, what="child"):
    rc = reap(pid)
    check(rc == 0, f"{what} exited with {rc}")


def reap_within(pid, secs):
    def boom(*_):
        raise TimeoutError(f"pid {pid} still running after {secs}s")
    old = signal.signal(signal.SIGALRM, boom)
    signal.setitimer(signal.ITIMER_REAL, secs)
    try:
        return reap(pid)
    except TimeoutError:
        os.kill(pid, signal.SIGKILL)
        reap(pid)
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old)


def read_exact(fd, n):
    buf = b""
    while len(buf) < n:
        d = os.read(fd, n - len(buf))
        check(d, f"EOF after {len(buf)}/{n} bytes")
        buf += d
    return buf


def napper(pgid=None):
    if pgid is not None:
        os.setpgid(0, pgid)
    while True:
        time.sleep(1)


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE 0


def proc_status(pid="self"):
    with open(f"/proc/{pid}/status") as f:
        return dict(l.rstrip("\n").split(":\t", 1) for l in f if ":\t" in l)


# ---------------------------------------------------------------- processes

@test
def fork_tree():
    r, w = os.pipe()

    def node(depth):
        if depth:
            kids = [spawn(node, depth - 1) for _ in range(4)]
            for k in kids:
                check(reap(k) == 0, "a subtree failed")
        os.write(w, b"x")

    must(spawn(node, 4))
    os.close(w)
    n = 0
    while (b := os.read(r, 4096)):
        n += len(b)
    check(n == 341, f"{n}/341 processes reported in")
    return "341 processes, 4 levels deep"


@test
def zombie_horde():
    want = {spawn(lambda c: c, i % 256): i % 256 for i in range(300)}
    got = {}
    while len(got) < len(want):
        pid, st = os.wait()
        got[pid] = os.waitstatus_to_exitcode(st)
    check(got == want, f"{sum(got.get(p) != c for p, c in want.items())} exit codes mixed up")
    expect_errno(errno.ECHILD, "wait with no children", os.wait)
    return "300 zombies reaped with the right exit codes"


@test
def orphan_reparent():
    sub = ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
    me = os.getpid()
    r, w = os.pipe()
    hr, hw = os.pipe()

    def middle():
        def grandchild():
            parent = os.getppid()
            pfd = None
            try:
                pfd = os.pidfd_open(parent)
            except OSError:
                pass
            os.write(hw, b"k")
            if pfd is not None:
                select.select([pfd], [], [], 10)
            for _ in range(5000):  # fallback if pidfd is missing
                if os.getppid() != parent:
                    break
                time.sleep(0.001)
            os.write(w, struct.pack("ii", parent, os.getppid()))
        spawn(grandchild)
        os.read(hr, 1)

    mid = spawn(middle)
    must(mid, "middle")
    first, second = struct.unpack("ii", read_exact(r, 8))
    check(first == mid, f"grandchild saw ppid {first}, its parent was {mid}")
    if sub:
        check(second == me, f"orphan went to {second}, but the subreaper is {me}")
        pid, st = os.waitpid(-1, 0)
        check(pid != mid and os.waitstatus_to_exitcode(st) == 0, "couldn't reap adopted orphan")
        return "orphan adopted by subreaper and reaped"
    check(second != mid, "never reparented")
    return f"orphan reparented to {second}"


@test
def stop_and_continue():
    pid = spawn(napper)
    os.kill(pid, signal.SIGSTOP)
    _, st = os.waitpid(pid, os.WUNTRACED)
    check(os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGSTOP, f"not stopped: status {st:#x}")
    with open(f"/proc/{pid}/stat") as f:
        state = f.read().rsplit(")", 1)[1].split()[0]
    check(state == "T", f"/proc/{pid}/stat state {state!r}, want 'T'")
    os.kill(pid, signal.SIGCONT)
    _, st = os.waitpid(pid, os.WCONTINUED)
    check(os.WIFCONTINUED(st), f"no WCONTINUED: status {st:#x}")
    os.kill(pid, signal.SIGTERM)
    check(reap(pid) == -signal.SIGTERM, "SIGTERM didn't kill")

    leader = spawn(napper, 0)
    try:
        os.setpgid(leader, leader)
    except OSError:
        pass
    members = [leader]
    for _ in range(4):
        p = spawn(napper, leader)
        try:
            os.setpgid(p, leader)
        except OSError:
            pass
        members.append(p)
    check(all(os.getpgid(p) == leader for p in members), "process group not formed")
    os.killpg(leader, signal.SIGTERM)
    codes = [reap(p) for p in members]
    check(codes == [-signal.SIGTERM] * 5, f"killpg results {codes}")
    return "SIGSTOP/SIGCONT seen by waitpid and /proc, killpg hit all 5"


@test
def exec_chain():
    code = ("import os,sys\n"
            "n=int(sys.argv[1])\n"
            "exe='/proc/self/exe' if n==1 else sys.executable\n"
            "if n: os.execv(exe,[sys.executable,'-S','-c',os.environ['CRAZY_HOP'],str(n-1)])\n"
            "print(os.getpid(),os.getppid(),flush=True)\n")
    env = dict(os.environ, CRAZY_HOP=code)
    p = subprocess.Popen([sys.executable, "-S", "-c", code, "25"], env=env, stdout=subprocess.PIPE)
    out, _ = p.communicate(timeout=50)
    check(p.returncode == 0, f"chain exited {p.returncode}")
    pid, ppid = map(int, out.split())
    check(pid == p.pid, f"pid changed across exec: {pid} vs {p.pid}")
    check(ppid == os.getpid(), f"ppid {ppid} after exec chain, want {os.getpid()}")
    return "25 execs (one via /proc/self/exe) kept the same pid"


@test
def huge_argv_env():
    args = ["y" * 20] * 40000
    env = dict(os.environ, BIG="z" * 100000)
    r = subprocess.run(["/bin/sh", "-c", 'echo $#; printf %s "$*" | wc -c; printf %s "$BIG" | wc -c',
                        "sh", *args], env=env, capture_output=True, text=True, timeout=30)
    out = r.stdout.split()
    check(out == ["40000", str(40000 * 21 - 1), "100000"], f"got {out} {r.stderr[-200:]}")
    return "40000 args + 100 KB env var survived exec"


@test
def shell_pipelines():
    def sh(c):
        return subprocess.run(["/bin/sh", "-c", c], capture_output=True, timeout=30)

    r = sh("seq 1 200000 | sort -rn | head -n1")
    check(r.stdout.strip() == b"200000", f"seq|sort|head gave {r.stdout[:50]!r}")
    r = sh("yes crazy | head -c 5000000 | sha256sum")
    want = hashlib.sha256((b"crazy\n" * 1000000)[:5000000]).hexdigest()
    check(r.stdout.split()[:1] == [want.encode()], "yes|head|sha256sum mismatch")
    r = sh("trap 'echo trapped; exit 3' TERM; kill -TERM $$; sleep 5")
    check(r.returncode == 3 and r.stdout == b"trapped\n", f"trap: rc {r.returncode} out {r.stdout!r}")
    r = sh('x=$( (echo a; echo b) | tr a-z A-Z | paste -sd, ); echo "$x"')
    check(r.stdout == b"A,B\n", f"subshell pipeline gave {r.stdout!r}")
    ps = [subprocess.Popen(["/bin/sh", "-c", f"exit {i}"]) for i in range(64)]
    check([p.wait(timeout=30) for p in ps] == list(range(64)), "64 parallel exit codes wrong")
    pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 42"], os.environ)
    check(reap(pid) == 42, "posix_spawn exit code")
    return "pipelines, traps, 64 parallel shells, posix_spawn"


@test
def crashes_and_limits():
    def segv():
        no_core()
        ctypes.memset(8, 0, 1)  # string_at(0) doesn't fault on 3.14

    def abort():
        no_core()
        os.abort()

    def handled():
        signal.signal(signal.SIGTERM, lambda *_: os._exit(42))
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(5)
        return 1

    def cpu_hog():
        no_core()
        resource.setrlimit(resource.RLIMIT_CPU, (1, 5))
        while True:
            pass

    def fsize():
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
        fd = os.open("big", os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        if os.write(fd, bytes(1 << 20)) != 1 << 20:
            return 2
        try:
            os.write(fd, b"x")
            return 3
        except OSError as e:
            return 0 if e.errno == errno.EFBIG else 4

    def nofile():
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
        fds = []
        try:
            while len(fds) < 1000:
                fds.append(os.open("/dev/null", os.O_RDONLY))
        except OSError as e:
            return 0 if e.errno == errno.EMFILE and max(fds) < 64 else 5
        return 6

    cases = [("SIGSEGV", segv, -signal.SIGSEGV), ("abort", abort, -signal.SIGABRT),
             ("SIGKILL self", lambda: os.kill(os.getpid(), signal.SIGKILL), -signal.SIGKILL),
             ("handled SIGTERM", handled, 42), ("RLIMIT_CPU", cpu_hog, -signal.SIGXCPU),
             ("RLIMIT_FSIZE", fsize, 0), ("RLIMIT_NOFILE", nofile, 0)]
    for label, fn, want in cases:
        got = reap_within(spawn(fn), 20)
        check(got == want, f"{label}: status {got}, want {want}")
    return "segv, abort, kill, handler, CPU/FSIZE/NOFILE limits"


# ------------------------------------------------------------------ signals

@test
def realtime_signal_queue():
    rt = signal.SIGRTMIN + 3
    signal.pthread_sigmask(signal.SIG_BLOCK, {rt, signal.SIGUSR1})
    me = os.getpid()

    def shooter():
        for _ in range(500):
            os.kill(me, rt)
        for _ in range(100):
            os.kill(me, signal.SIGUSR1)

    pid = spawn(shooter)
    must(pid)
    got, senders = 0, set()
    while (info := signal.sigtimedwait({rt}, 0)) is not None:
        got += 1
        senders.add(info.si_pid)
    usr1 = 0
    while signal.sigtimedwait({signal.SIGUSR1}, 0) is not None:
        usr1 += 1
    check(got == 500, f"{got}/500 realtime signals queued")
    check(senders == {pid}, f"si_pid says {senders}, sender was {pid}")
    check(usr1 == 1, f"100 SIGUSR1s should merge into 1, got {usr1}")
    return "500 RT signals queued with right si_pid, 100 SIGUSR1 merged to 1"


@test
def signal_pingpong():
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    parent = os.getpid()
    n = 2000

    def child():
        for _ in range(n):
            signal.sigwait({signal.SIGUSR1})
            os.kill(parent, signal.SIGUSR1)

    pid = spawn(child)
    t = time.perf_counter()
    for _ in range(n):
        os.kill(pid, signal.SIGUSR1)
        signal.sigwait({signal.SIGUSR1})
    dt = time.perf_counter() - t
    must(pid)
    return f"{n} round trips, {dt / n * 1e6:.0f} us each"


@test
def itimer_vs_eintr():
    hits = 0

    def h(*_):
        nonlocal hits
        hits += 1

    signal.signal(signal.SIGALRM, h)
    signal.setitimer(signal.ITIMER_REAL, 0.002, 0.002)
    t = time.monotonic()
    time.sleep(0.3)
    dt = time.monotonic() - t
    r, w = os.pipe()
    th = threading.Thread(target=lambda: (time.sleep(0.1), os.write(w, b"ok")))
    th.start()
    data = os.read(r, 2)
    th.join()
    signal.setitimer(signal.ITIMER_REAL, 0)
    check(dt >= 0.3, f"sleep cut short by signals: {dt:.3f}s")
    check(data == b"ok", "blocking read lost to EINTR")
    check(hits >= 50, f"only {hits} SIGALRMs in ~0.4s")
    return f"{hits} SIGALRMs, sleep and read both survived"


# ---------------------------------------------------------------- pipes/IPC

@test
def pipe_firehose():
    r, w = os.pipe()
    sz = fcntl.fcntl(w, fcntl.F_SETPIPE_SZ, 1 << 20)
    check(fcntl.fcntl(w, fcntl.F_GETPIPE_SZ) == sz >= 1 << 20, f"pipe size {sz}")
    block = random.Random(7).randbytes(1 << 20)

    def writer():
        os.close(r)
        rnd = random.Random(3)
        for _ in range(64):
            mv = memoryview(block)
            while mv:
                mv = mv[os.write(w, mv[:rnd.randint(1, 300000)]):]

    t = time.perf_counter()
    pid = spawn(writer)
    os.close(w)
    h, total, rnd = hashlib.sha256(), 0, random.Random(5)
    while (b := os.read(r, rnd.randint(1, 1 << 17))):
        h.update(b)
        total += len(b)
    dt = time.perf_counter() - t
    must(pid)
    e = hashlib.sha256()
    for _ in range(64):
        e.update(block)
    check(total == 64 << 20, f"{total} bytes arrived")
    check(h.digest() == e.digest(), "pipe data corrupted")
    return f"64 MiB in {dt:.2f}s ({64 / dt:.0f} MiB/s), ragged chunk sizes"


@test
def fd_passing():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    fds = []
    for i in range(200):
        if i % 2:
            fd = os.open(f"f{i}", os.O_RDWR | os.O_CREAT, 0o644)
        else:
            fd = os.memfd_create(f"crazy{i}")
        os.write(fd, f"payload-{i}".encode())
        os.lseek(fd, 0, 0)
        fds.append(fd)

    def child():
        a.close()
        _, got, _, _ = socket.recv_fds(b, 1024, 253)
        check(len(got) == 200, f"received {len(got)}/200 fds")
        for i, fd in enumerate(got):
            check(os.read(fd, 100) == f"payload-{i}".encode(), f"passed fd {i} reads wrong data")
        pr, pw = os.pipe()
        socket.send_fds(b, [b"p"], [pr])
        os.write(pw, b"through-a-passed-pipe")

    pid = spawn(child)
    b.close()
    socket.send_fds(a, [b"files"], fds)
    _, back, _, _ = socket.recv_fds(a, 16, 1)
    check(len(back) == 1, "no fd came back")
    data = os.read(back[0], 100)
    must(pid)
    check(data == b"through-a-passed-pipe", f"pipe passed back read {data!r}")
    return "200 fds (memfds + files) sent, a pipe sent back"


@test
def peer_credentials():
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind("sock")
    srv.listen()
    check(stat.S_ISSOCK(os.stat("sock").st_mode), "bound path isn't a socket node")

    def client():
        c = socket.socket(socket.AF_UNIX)
        c.connect("sock")
        c.sendall(str(os.getpid()).encode())
        c.recv(1)

    pid = spawn(client)
    conn, _ = srv.accept()
    cpid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    said = int(conn.recv(32))
    conn.send(b"k")
    must(pid)
    check(said == pid, f"child's getpid {said} != fork's {pid}")
    check(cpid == pid, f"SO_PEERCRED pid {cpid}, child is {pid}")
    check((uid, gid) == (os.getuid(), os.getgid()), f"SO_PEERCRED uid/gid {uid}/{gid}")
    return "SO_PEERCRED matches the guest pid"


def echo_swarm(family, addr, srv, clients=32):
    def handle(c):
        with c:
            while (d := c.recv(65536)):
                c.sendall(d)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()

    def client(n):
        data = random.Random(n).randbytes(256 << 10)
        s = socket.socket(family, socket.SOCK_STREAM)
        s.connect(addr)

        def send():
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)

        t = threading.Thread(target=send)
        t.start()
        got = bytearray()
        while (d := s.recv(65536)):
            got += d
        t.join()
        check(got == data, f"client {n}: {len(got)} bytes back, mismatch")

    t = time.perf_counter()
    bad = [p for p in [spawn(client, i) for i in range(clients)] if reap(p) != 0]
    check(not bad, f"{len(bad)}/{clients} clients failed")
    return f"{clients} procs x 256 KiB echoed in {time.perf_counter() - t:.2f}s"


@test
def unix_path_swarm():
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind("echo.sock")
    srv.listen(64)
    return echo_swarm(socket.AF_UNIX, "echo.sock", srv)


@test
def unix_abstract_swarm():
    addr = b"\0crazy-%d" % os.getpid()
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(addr)
    srv.listen(64)
    return echo_swarm(socket.AF_UNIX, addr, srv)


@test
def tcp_swarm():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(128)
    return echo_swarm(socket.AF_INET, srv.getsockname(), srv)


@test
def datagrams():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))

    def echo():
        while True:
            d, a = srv.recvfrom(65536)
            if d == b"bye":
                return
            srv.sendto(d, a)

    pid = spawn(echo)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(5)
    c.connect(srv.getsockname())
    rnd = random.Random(11)
    for i in range(1000):
        d = rnd.randbytes(rnd.randint(1, 60000))
        c.send(d)
        check(c.recv(65536) == d, f"udp datagram {i} mangled")
    c.send(b"bye")
    must(pid)
    for kind, name in ((socket.SOCK_DGRAM, "DGRAM"), (socket.SOCK_SEQPACKET, "SEQPACKET")):
        a, b = socket.socketpair(socket.AF_UNIX, kind)
        sizes = [1, 7, 4096, 30000, 1, 2]
        for n in sizes:
            a.send(bytes([n % 256]) * n)
        got = [len(b.recv(65536)) for _ in sizes]
        check(got == sizes, f"unix {name} boundaries: {got}")
        a.send(b"peekaboo")
        check(b.recv(4, socket.MSG_PEEK) == b"peek" and b.recv(100) == b"peekaboo", f"{name} MSG_PEEK")
    return "1000 UDP datagrams up to 60 KB, unix DGRAM/SEQPACKET boundaries"


@test
def epoll_maze():
    ep = select.epoll()
    pipes = [os.pipe() for _ in range(256)]
    for r, _ in pipes:
        ep.register(r, select.EPOLLIN)
    ready = set(random.Random(9).sample(range(256), 77))
    for i in ready:
        os.write(pipes[i][1], b"x")
    want = {pipes[i][0] for i in ready}
    got = {fd for fd, _ in ep.poll(1, maxevents=1024)}
    check(got == want, f"epoll: {len(got)} ready, want {len(want)}")
    po = select.poll()
    for r, _ in pipes:
        po.register(r, select.POLLIN)
    check({fd for fd, _ in po.poll(1000)} == want, "poll disagrees with epoll")

    et = select.epoll()
    r0, w0 = os.pipe()
    et.register(r0, select.EPOLLIN | select.EPOLLET)
    os.write(w0, b"a")
    check(len(et.poll(1)) == 1, "ET: first edge missing")
    check(et.poll(0) == [], "ET: fired again with no new data")
    os.write(w0, b"b")
    check(len(et.poll(1)) == 1, "ET: second edge missing")
    os.close(w0)
    evs = et.poll(1)
    check(evs and evs[0][1] & select.EPOLLHUP, f"no EPOLLHUP after writer closed: {evs}")

    one = select.epoll()
    r1, w1 = os.pipe()
    one.register(r1, select.EPOLLIN | select.EPOLLONESHOT)
    os.write(w1, b"x")
    check(len(one.poll(1)) == 1, "ONESHOT: no first event")
    os.write(w1, b"y")
    check(one.poll(0) == [], "ONESHOT fired twice")
    one.modify(r1, select.EPOLLIN | select.EPOLLONESHOT)
    check(len(one.poll(1)) == 1, "ONESHOT: no event after re-arm")

    x = select.epoll()
    r2, w2 = os.pipe()
    x.register(r2, select.EPOLLIN)
    pid = spawn(lambda: os.write(w2, b"z") and 0)
    evs = x.poll(5)
    must(pid)
    check(evs, "epoll never woke for a write from another process")
    return "level, edge, oneshot, hup, cross-process wakeups"


@test
def mmap_games():
    nslot, slot = 8, 1 << 20
    m = mmap.mmap(-1, nslot * slot)

    def pattern(i):
        return hashlib.sha256(bytes([i])).digest() * (slot // 32)

    def fill(i):
        m[i * slot:(i + 1) * slot] = pattern(i)

    for p in [spawn(fill, i) for i in range(nslot)]:
        must(p)
    for i in range(nslot):
        check(m[i * slot:(i + 1) * slot] == pattern(i), f"shared slot {i} not visible to parent")

    fd = os.open("mapped", os.O_RDWR | os.O_CREAT, 0o644)
    os.ftruncate(fd, 1 << 20)
    fm = mmap.mmap(fd, 1 << 20)

    def scribble():
        fm[123456:123462] = b"hello!"

    must(spawn(scribble))
    check(os.pread(fd, 6, 123456) == b"hello!", "child's mmap write not visible through read()")
    os.pwrite(fd, b"BACK", 0)
    check(fm[:4] == b"BACK", "write() not visible through mmap")

    pm = mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    pm[:5] = b"mine!"

    def clobber():
        pm[:5] = b"yours"
        return 0 if pm[:5] == b"yours" else 1

    must(spawn(clobber))
    check(pm[:5] == b"mine!", "MAP_PRIVATE write leaked across fork")

    big = mmap.mmap(-1, 1 << 30, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | getattr(mmap, "MAP_NORESERVE", 0))
    offs = range(0, 1 << 30, 16 << 20)
    for off in offs:
        big[off] = 0x5A
    check(all(big[o] == 0x5A and big[o + 1] == 0 for o in offs), "lazy 1 GiB mapping wrong")
    return "shared, file-backed, private COW, 1 GiB lazy mapping"


def _square(x):
    return x * x


@test
def multiprocessing_zoo():
    ctx = mp.get_context("fork")
    with ctx.Pool(8) as pool:
        check(pool.map(_square, range(5000), chunksize=13) == [x * x for x in range(5000)], "Pool.map")

    v = ctx.Value("i", 0)

    def bump():
        for _ in range(2000):
            with v.get_lock():
                v.value += 1

    ps = [ctx.Process(target=bump) for _ in range(6)]
    for p in ps:
        p.start()
    for p in ps:
        p.join()
    check(v.value == 12000, f"locked counter {v.value}/12000")

    q = ctx.Queue()

    def produce(k):
        for i in range(2500):
            q.put((k, i))

    ps = [ctx.Process(target=produce, args=(k,)) for k in range(4)]
    for p in ps:
        p.start()
    got = [q.get(timeout=20) for _ in range(10000)]
    for p in ps:
        p.join()
    for k in range(4):
        check([i for kk, i in got if kk == k] == list(range(2500)), f"Queue lost/reordered producer {k}")

    bar, arrived = ctx.Barrier(6), ctx.Value("i", 0)

    def meet():
        with arrived.get_lock():
            arrived.value += 1
        bar.wait(10)
        if arrived.value != 6:
            os._exit(3)

    ps = [ctx.Process(target=meet) for _ in range(6)]
    for p in ps:
        p.start()
    for p in ps:
        p.join()
    check([p.exitcode for p in ps] == [0] * 6, f"Barrier exit codes {[p.exitcode for p in ps]}")

    with ctx.Manager() as mgr:
        d = mgr.dict()
        ps = [ctx.Process(target=d.__setitem__, args=(i, i ** 3)) for i in range(8)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        check(dict(d) == {i: i ** 3 for i in range(8)}, "Manager dict")

    shm = shared_memory.SharedMemory(create=True, size=1 << 20)
    try:
        def writer(name):
            try:
                s = shared_memory.SharedMemory(name=name, track=False)
            except TypeError:
                s = shared_memory.SharedMemory(name=name)
            s.buf[:11] = b"from-child!"
            s.close()

        p = ctx.Process(target=writer, args=(shm.name,))
        p.start()
        p.join()
        check(bytes(shm.buf[:11]) == b"from-child!", "SharedMemory write not visible")
    finally:
        shm.close()
        shm.unlink()
    return "Pool, locked Value, Queue, Barrier, Manager, SharedMemory"


# --------------------------------------------------------------------- ttys

def pty_read_until(fd, needle=None, timeout=10):
    out, end = b"", time.monotonic() + timeout
    while needle is None or needle not in out:
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError(f"pty never printed {needle!r}; got {out[-200:]!r}")
        if not select.select([fd], [], [], left)[0]:
            continue
        try:
            d = os.read(fd, 4096)
        except OSError as e:
            if e.errno == errno.EIO:
                break
            raise
        if not d:
            break
        out += d
    return out


@test
def pty_session():
    pid, fd = pty.fork()
    if pid == 0:
        try:
            ok = os.getsid(0) == os.getpid() and os.tcgetpgrp(0) == os.getpgrp() and os.isatty(0)
            os.write(1, b"SESSION-OK\n" if ok else b"SESSION-BAD\n")
            os.execv("/bin/sh", ["sh", "-c", 'stty -echo; read x; echo "got:$x"; stty size; exit 7'])
        finally:
            os._exit(127)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 41, 133, 0, 0))
    out = pty_read_until(fd, b"SESSION-")
    os.write(fd, b"hello\n")
    out += pty_read_until(fd)
    rc = reap_within(pid, 10)
    check(b"SESSION-OK" in out, f"child isn't a session leader with a ctty: {out!r}")
    check(b"got:hello" in out, f"line didn't arrive: {out!r}")
    check(b"41 133" in out, f"window size lost: {out!r}")
    check(rc == 7, f"exit {rc}, want 7")
    return "new session, ctty, termios, TIOCSWINSZ"


@test
def pty_ctrl_c():
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execv("/bin/sh", ["sh", "-c", "echo READY; exec sleep 30"])
        finally:
            os._exit(127)
    pty_read_until(fd, b"READY")
    os.write(fd, b"\x03")
    rc = reap_within(pid, 10)
    check(rc == -signal.SIGINT, f"^C gave status {rc}, want -SIGINT")
    return "^C on the pty killed the foreground job"


# --------------------------------------------------------------- filesystem

@test
def append_atomicity():
    def writer(i):
        fd = os.open("append.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        for j in range(2000):
            os.write(fd, f"{i:02d}:{j:06d}:".encode() + b"#" * 89 + b"\n")

    for p in [spawn(writer, i) for i in range(8)]:
        must(p)
    with open("append.log", "rb") as f:
        lines = f.read().split(b"\n")
    check(lines[-1] == b"", "file doesn't end in newline")
    lines = lines[:-1]
    check(len(lines) == 16000, f"{len(lines)}/16000 lines")
    seen = {i: [] for i in range(8)}
    for ln in lines:
        check(len(ln) == 99 and ln.endswith(b"#" * 89), f"torn line {ln[:30]!r}")
        seen[int(ln[:2])].append(int(ln[3:9]))
    for i in range(8):
        check(seen[i] == list(range(2000)), f"writer {i} lines lost or reordered")
    return "8 procs x 2000 O_APPEND lines, none torn"


@test
def rename_never_gaps():
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
        check(reap(p) == 0, "a reader saw a missing or torn file mid-rename")
    return "6000 renames over a file while 4 readers never saw a gap"


@test
def path_torture():
    os.close(os.open("n" * 255, os.O_CREAT | os.O_WRONLY, 0o644))
    expect_errno(errno.ENAMETOOLONG, "256-byte name", os.open, "n" * 256, os.O_CREAT | os.O_WRONLY, 0o644)
    weird = "ünïcødé 🚀 \t新\x01name"
    with open(weird, "w") as f:
        f.write("x")
    check(weird in os.listdir("."), "unicode name lost")

    base = os.getcwd()
    part = "d" * 60
    fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    for _ in range(80):
        os.mkdir(part, dir_fd=fd)
        nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
    leaf = os.open("leaf", os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=fd)
    os.write(leaf, b"deep")
    os.close(leaf)
    os.close(fd)
    expect_errno(errno.ENAMETOOLONG, "path over PATH_MAX", os.stat, "/".join([part] * 80 + ["leaf"]))
    os.chdir("/".join([part] * 40))
    with open("/".join([part] * 40 + ["leaf"]), "rb") as f:
        check(f.read() == b"deep", "deep leaf via relative path")
    os.chdir(base)
    shutil.rmtree(part)
    check(not os.path.exists(part), "rmtree of 80-deep tree left junk")

    os.symlink("loop-b", "loop-a")
    os.symlink("loop-a", "loop-b")
    expect_errno(errno.ELOOP, "symlink loop", os.open, "loop-a", os.O_RDONLY)
    with open("target", "w") as f:
        f.write("end")
    prev = "target"
    for i in range(50):
        os.symlink(prev, f"chain{i}")
        prev = f"chain{i}"
    with open("chain29") as f:
        check(f.read() == "end", "30-link chain")
    expect_errno(errno.ELOOP, "50-link chain", os.open, "chain49", os.O_RDONLY)
    expect_errno(errno.ELOOP, "O_NOFOLLOW on symlink", os.open, "chain0", os.O_RDONLY | os.O_NOFOLLOW)
    os.symlink("nowhere", "dangling")
    check(os.path.lexists("dangling") and not os.path.exists("dangling"), "dangling symlink")

    os.makedirs("real/sub")
    os.symlink("real/sub", "lnk")
    check(os.stat("lnk/..").st_ino == os.stat("real").st_ino,
          "'lnk/..' resolved lexically instead of through the symlink")
    return "255/256 names, unicode, 80-deep tree, ELOOP, physical '..'"


@test
def file_tricks():
    fd = os.open("ghost", os.O_RDWR | os.O_CREAT, 0o600)
    os.write(fd, b"boo")
    os.unlink("ghost")
    check(os.pread(fd, 3, 0) == b"boo", "unlinked file unreadable")
    link = os.readlink(f"/proc/self/fd/{fd}")
    check(link.endswith("ghost (deleted)"), f"/proc/self/fd says {link!r}")
    check(os.fstat(fd).st_nlink == 0, "nlink after unlink")

    with open("orig", "w") as f:
        f.write("same")
    for i in range(10):
        os.link("orig", f"hl{i}")
    st = os.stat("orig")
    check(st.st_nlink == 11, f"nlink {st.st_nlink}/11")
    check(all(os.stat(f"hl{i}").st_ino == st.st_ino for i in range(10)), "hard link inode differs")
    os.rename("hl0", "hl1")
    check(os.path.exists("hl0") and os.path.exists("hl1"), "rename between hard links of one inode must be a no-op")

    t = os.open(".", os.O_TMPFILE | os.O_RDWR, 0o600)
    os.write(t, b"born anonymous")
    os.link(f"/proc/self/fd/{t}", "materialized")
    with open("materialized", "rb") as f:
        check(f.read() == b"born anonymous", "O_TMPFILE + linkat")

    fd = os.open("sparse", os.O_RDWR | os.O_CREAT, 0o644)
    os.pwrite(fd, b"!", 1 << 30)
    st = os.fstat(fd)
    check(st.st_size == (1 << 30) + 1, f"sparse size {st.st_size}")
    check(st.st_blocks * 512 < 1 << 20, f"1 GiB hole uses {st.st_blocks * 512} bytes")
    check(os.pread(fd, 4096, 1 << 29) == bytes(4096), "hole isn't zeros")
    check(os.lseek(fd, 0, os.SEEK_HOLE) == 0, "SEEK_HOLE")
    check((1 << 30) - (1 << 20) <= os.lseek(fd, 0, os.SEEK_DATA) <= 1 << 30, "SEEK_DATA")
    os.pwrite(fd, b"0123456789ABCDEF", 0)
    os.ftruncate(fd, 10)
    os.ftruncate(fd, 20)
    check(os.pread(fd, 100, 0) == b"0123456789" + bytes(10), "truncate didn't zero the tail")
    os.posix_fallocate(fd, 0, 1 << 20)
    check(os.fstat(fd).st_size == 1 << 20, "fallocate size")

    data = random.Random(4).randbytes(3 << 20)
    src = os.open("src", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(src, data)
    dst = os.open("cfr", os.O_RDWR | os.O_CREAT, 0o644)
    n = 0
    while n < len(data):
        k = os.copy_file_range(src, dst, len(data) - n, n, n)
        check(k > 0, "copy_file_range stalled")
        n += k
    check(os.pread(dst, len(data) + 1, 0) == data, "copy_file_range content")
    dst = os.open("sf", os.O_RDWR | os.O_CREAT, 0o644)
    off = 0
    while off < len(data):
        k = os.sendfile(dst, src, off, len(data) - off)
        check(k > 0, "sendfile stalled")
        off += k
    check(os.pread(dst, len(data) + 1, 0) == data, "sendfile content")
    dst = os.open("spl", os.O_RDWR | os.O_CREAT, 0o644)
    r, w = os.pipe()

    def feed():
        os.write(w, data)
        os.close(w)

    th = threading.Thread(target=feed)
    th.start()
    while os.splice(r, dst, 1 << 16):
        pass
    th.join()
    check(os.pread(dst, len(data) + 1, 0) == data, "splice content")

    os.utime("orig", ns=(1_000_000_123, 1_700_000_000_987_654_321))
    st = os.stat("orig")
    check((st.st_atime_ns, st.st_mtime_ns) == (1_000_000_123, 1_700_000_000_987_654_321),
          f"utime ns {st.st_atime_ns} {st.st_mtime_ns}")
    old = os.umask(0o027)
    fd = os.open("masked", os.O_CREAT | os.O_WRONLY, 0o777)
    os.umask(old)
    check(stat.S_IMODE(os.fstat(fd).st_mode) == 0o750, f"umask gave {oct(os.fstat(fd).st_mode)}")
    expect_errno(errno.EEXIST, "O_EXCL on existing", os.open, "orig", os.O_CREAT | os.O_EXCL | os.O_WRONLY)

    os.makedirs("ra/inner")
    os.makedirs("rb/full")
    expect_errno((errno.ENOTEMPTY, errno.EEXIST), "rename onto non-empty dir", os.rename, "ra", "rb")
    expect_errno(errno.EINVAL, "rename dir into itself", os.rename, "ra", "ra/inner/x")
    expect_errno(errno.ENOTDIR, "rename dir over file", os.rename, "ra", "orig")
    expect_errno(errno.EISDIR, "rename file over dir", os.rename, "orig", "ra")
    expect_errno(errno.ENOTEMPTY, "rmdir non-empty", os.rmdir, "ra")
    return "deleted-but-open, links, O_TMPFILE, holes, copy/sendfile/splice, utime ns, rename rules"


@test
def big_directory():
    out = []
    for base in dict.fromkeys((os.getcwd(), "/tmp")):
        d = os.path.join(base, f"crazy-bigdir-{os.getpid()}")
        os.mkdir(d)
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for i in range(10000):
                os.close(os.open(f"f{i:05d}", os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=dfd))
            names = os.listdir(d)
            check(len(names) == len(set(names)) == 10000, f"{d}: listdir saw {len(names)} ({len(set(names))} unique)")
            check(sum(1 for _ in os.scandir(d)) == 10000, f"{d}: scandir count")
            with os.scandir(d) as it:
                for e in it:
                    os.unlink(e.name, dir_fd=dfd)
            left = os.listdir(d)
            check(left == [], f"{d}: {len(left)} left after delete-while-iterating")
            out.append(base)
        finally:
            os.close(dfd)
            shutil.rmtree(d, ignore_errors=True)
    return "10000 entries listed and deleted mid-scan in " + ", ".join(out)


@test
def locks_and_fifos():
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
    expect_errno((errno.EWOULDBLOCK, errno.EAGAIN), "flock while child holds it",
                 fcntl.flock, fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
        typ, _, _, _, pid_ = struct.unpack("hhqqi4x", res)
        os.write(p1w, struct.pack("i", pid_))
        return 1 if typ != fcntl.F_UNLCK else 0

    check(reap(spawn(probe)) == 1, "child can't see our POSIX lock")
    owner = struct.unpack("i", os.read(p1r, 4))[0]
    check(owner == me, f"F_GETLK says lock owner is {owner}, we are {me}")
    os.close(fb)
    check(reap(spawn(probe)) == 0, "closing another fd didn't drop the POSIX lock")
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
        check(e.errno == errno.EDEADLK, f"got {errno.errorcode.get(e.errno)} instead of EDEADLK")
        mine = True
        fcntl.lockf(dl, fcntl.LOCK_UN, 1, 0)
    rc = reap_within(pid, 10)
    check(rc == (0 if mine else 9), f"deadlock not detected exactly once (parent {mine}, child rc {rc})")

    os.mkfifo("fifo")
    check(stat.S_ISFIFO(os.stat("fifo").st_mode), "mkfifo didn't make a fifo")
    expect_errno(errno.ENXIO, "fifo write-open with no reader", os.open, "fifo", os.O_WRONLY | os.O_NONBLOCK)

    def fifo_writer():
        with open("fifo", "wb") as f:
            for i in range(1000):
                f.write(b"%06d\n" % i)

    pid = spawn(fifo_writer)
    with open("fifo", "rb") as f:
        lines = f.read().split()
    must(pid)
    check(lines == [b"%06d" % i for i in range(1000)], f"fifo delivered {len(lines)} lines")
    return "flock, POSIX close trap, F_GETLK owner, OFD, EDEADLK, fifos"


@test
def modern_fds():
    efd = os.eventfd(0, os.EFD_SEMAPHORE | os.EFD_NONBLOCK)

    def poster():
        for _ in range(100):
            os.eventfd_write(efd, 1)

    must(spawn(poster))
    n = 0
    while True:
        try:
            os.eventfd_read(efd)
            n += 1
        except BlockingIOError:
            break
    check(n == 100, f"eventfd semaphore gave {n}/100")

    tfd = os.timerfd_create(time.CLOCK_MONOTONIC)
    os.timerfd_settime(tfd, initial=0.01, interval=0.01)
    t0, ticks = time.monotonic(), 0
    while time.monotonic() - t0 < 0.2:
        ticks += struct.unpack("Q", os.read(tfd, 8))[0]
    expect = (time.monotonic() - t0) / 0.01
    check(abs(ticks - expect) <= 3, f"timerfd {ticks} ticks, expected ~{expect:.0f}")

    pid = spawn(napper)
    pfd = os.pidfd_open(pid)
    check(not select.select([pfd], [], [], 0)[0], "pidfd readable while child alive")
    signal.pidfd_send_signal(pfd, signal.SIGTERM)
    check(select.select([pfd], [], [], 5)[0], "pidfd never became readable")
    res = os.waitid(os.P_PIDFD, pfd, os.WEXITED)
    check(res.si_pid == pid and res.si_status == signal.SIGTERM, f"waitid(P_PIDFD) {res}")

    sfd = os.memfd_create("crazy-sealed", os.MFD_ALLOW_SEALING)
    os.write(sfd, b"sealed!")
    link = os.readlink(f"/proc/self/fd/{sfd}")
    check(link.startswith("/memfd:crazy-sealed"), f"memfd link {link!r}")
    fcntl.fcntl(sfd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW)
    expect_errno(errno.EPERM, "write to sealed memfd", os.pwrite, sfd, b"x", 0)
    check(fcntl.fcntl(sfd, fcntl.F_GET_SEALS) & fcntl.F_SEAL_WRITE, "seals not reported")

    mfd = os.memfd_create("crazy-shared")
    os.ftruncate(mfd, 1 << 16)
    mm = mmap.mmap(mfd, 1 << 16)

    def poke():
        mm[100:105] = b"memfd"

    must(spawn(poke))
    check(os.pread(mfd, 5, 100) == b"memfd", "memfd mmap write not shared")

    libc = ctypes.CDLL(None, use_errno=True)
    ifd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    check(ifd >= 0, f"inotify_init1: {os.strerror(ctypes.get_errno())}")
    wd = libc.inotify_add_watch(ifd, os.getcwd().encode(), 0x100 | 0x200 | 0x8)
    check(wd >= 0, f"inotify_add_watch: {os.strerror(ctypes.get_errno())}")
    with open("watched", "w") as f:
        f.write("hi")
    os.unlink("watched")
    check(select.select([ifd], [], [], 5)[0], "no inotify events")
    buf, off, events = os.read(ifd, 4096), 0, []
    while off < len(buf):
        _, mask, _, ln = struct.unpack_from("iIII", buf, off)
        events.append((mask, buf[off + 16:off + 16 + ln].rstrip(b"\0")))
        off += 16 + ln
    got = [m for m, nm in events if nm == b"watched"]
    check(got == [0x100, 0x8, 0x200], f"inotify events {[hex(m) for m in got]}, want create/close_write/delete")
    return "eventfd, timerfd, pidfd, sealed memfd, inotify"


# ---------------------------------------------------- threads, proc, clocks

@test
def threads_galore():
    results = [None] * 256

    def work(i):
        h = hashlib.sha256()
        for _ in range(20):
            h.update(i.to_bytes(4, "little") * 4096)
        results[i] = h.hexdigest()

    ts = [threading.Thread(target=work, args=(i,)) for i in range(256)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    want = []
    for i in range(256):
        h = hashlib.sha256()
        for _ in range(20):
            h.update(i.to_bytes(4, "little") * 4096)
        want.append(h.hexdigest())
    check(results == want, "256 threads computed wrong results")

    cv, turn, n = threading.Condition(), [0], 10000

    def player(me):
        for _ in range(n):
            with cv:
                while turn[0] % 2 != me:
                    cv.wait()
                turn[0] += 1
                cv.notify()

    ps = [threading.Thread(target=player, args=(k,)) for k in (0, 1)]
    for t in ps:
        t.start()
    for t in ps:
        t.join()
    check(turn[0] == 2 * n, f"condvar handoffs {turn[0]}/{2 * n}")

    stop, lk = threading.Event(), threading.Lock()

    def hammer():
        while not stop.is_set():
            with lk:
                pass

    hs = [threading.Thread(target=hammer) for _ in range(8)]
    for t in hs:
        t.start()
    tasks = os.listdir("/proc/self/task")
    check(len(tasks) == threading.active_count(), f"/proc/self/task has {len(tasks)}, python has {threading.active_count()}")
    check(all(str(t.native_id) in tasks for t in hs), "thread tids missing from /proc/self/task")

    def child():
        # only the forking thread survives fork
        if len(os.listdir("/proc/self/task")) != 1:
            return 1
        out = []
        t = threading.Thread(target=lambda: out.append(sum(range(1000))))
        t.start()
        t.join()
        return 0 if out == [499500] else 2

    bad = sum(reap(spawn(child)) != 0 for _ in range(40))
    stop.set()
    for t in hs:
        t.join()
    check(bad == 0, f"{bad}/40 forks from a busy multithreaded parent failed")
    return "256 threads, 20k condvar handoffs, 40 forks under lock contention"


@test
def proc_truth():
    me = os.getpid()
    check(os.readlink("/proc/self") == str(me), f"/proc/self -> {os.readlink('/proc/self')}, pid {me}")
    with open("/proc/self/stat") as f:
        raw = f.read()
    f = raw.rsplit(")", 1)[1].split()
    check(int(raw.split()[0]) == me, "stat pid")
    check((int(f[1]), int(f[2]), int(f[3])) == (os.getppid(), os.getpgrp(), os.getsid(0)),
          f"stat ppid/pgrp/sid {f[1:4]}")
    st = proc_status()
    check((int(st["Pid"]), int(st["PPid"])) == (me, os.getppid()), "status Pid/PPid")
    check(os.path.realpath("/proc/self/exe") == os.path.realpath(sys.executable),
          f"/proc/self/exe -> {os.readlink('/proc/self/exe')}")
    with open("/proc/self/cmdline", "rb") as fh:
        cmd = fh.read().split(b"\0")
    check(b"python" in os.path.basename(cmd[0]), f"cmdline {cmd[:2]}")
    with open("/proc/self/maps") as fh:
        check("[stack]" in fh.read(), "no [stack] in maps")
    with open("/proc/self/mountinfo") as fh:
        check(any(l.split()[4] == "/" for l in fh), "no / in mountinfo")

    fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(50)]
    check(all(os.readlink(f"/proc/self/fd/{x}") == "/dev/null" for x in fds), "/proc/self/fd links")
    for x in fds:
        os.close(x)
    for x in fds[1:]:
        expect_errno(errno.ENOENT, "closed fd in /proc", os.readlink, f"/proc/self/fd/{x}")
    wf = os.open("pos", os.O_WRONLY | os.O_CREAT, 0o644)
    os.write(wf, b"x" * 1234)
    with open(f"/proc/self/fdinfo/{wf}") as fh:
        check("pos:\t1234" in fh.read(), "fdinfo pos")

    ev = threading.Event()
    ts = [threading.Thread(target=ev.wait) for _ in range(5)]
    for t in ts:
        t.start()
    check(int(proc_status()["Threads"]) == 6, f"Threads: {proc_status()['Threads']}")
    ev.set()
    for t in ts:
        t.join()

    pid = spawn(napper)
    check(int(proc_status(pid)["PPid"]) == me, "child's PPid")
    check(os.readlink(f"/proc/{pid}/cwd") == os.getcwd(), "child's cwd link")
    os.kill(pid, signal.SIGKILL)
    reap(pid)
    check(not os.path.exists(f"/proc/{pid}"), "reaped child still in /proc")
    return "stat, status, exe, cmdline, maps, mountinfo, fd, fdinfo, task, other pids"


@test
def asyncio_flood():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    lim = hard if hard != resource.RLIM_INFINITY else 8192
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(soft, 4096), lim), hard))
    clients = max(10, min(500, (resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 100) // 3))

    async def main():
        async def handle(r, w):
            while (d := await r.read(65536)):
                w.write(d)
                await w.drain()
            w.close()

        srv = await asyncio.start_server(handle, "127.0.0.1", 0, backlog=1024)
        port = srv.sockets[0].getsockname()[1]

        async def client(i):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            data = random.Random(i).randbytes(16384)
            w.write(data)
            await w.drain()
            w.write_eof()
            got = await r.read()
            w.close()
            return got == data

        ok = sum(await asyncio.gather(*(client(i) for i in range(clients))))
        p = await asyncio.create_subprocess_exec("sh", "-c", "cat; echo done",
                                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = await p.communicate(b"abc\n")
        srv.close()
        await srv.wait_closed()
        return ok, out

    ok, out = asyncio.run(asyncio.wait_for(main(), 45))
    check(ok == clients, f"{ok}/{clients} async clients echoed correctly")
    check(out == b"abc\ndone\n", f"asyncio subprocess gave {out!r}")
    return f"{clients} concurrent asyncio connections + async subprocess"


@test
def clocks():
    bad = []

    def mono():
        last = time.monotonic_ns()
        for _ in range(50000):
            now = time.monotonic_ns()
            if now < last:
                bad.append(last - now)
            last = now

    ts = [threading.Thread(target=mono) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    check(not bad, f"monotonic went backwards {len(bad)} times")
    m = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    check(time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= m, "BOOTTIME < MONOTONIC")
    check(time.time() > 1.6e9, f"wall clock is {time.time()}")
    c0, w0 = time.process_time(), time.monotonic()
    while time.process_time() - c0 < 0.1:
        check(time.monotonic() - w0 < 10, "process_time never advanced while spinning")
    cpu, wall = time.process_time() - c0, time.monotonic() - w0
    check(wall >= cpu * 0.98, f"one thread charged {cpu:.3f}s CPU in {wall:.3f}s wall")
    t = time.monotonic()
    for _ in range(20):
        time.sleep(0.01)
    dt = time.monotonic() - t
    check(0.2 <= dt < 1.0, f"20 x sleep(10ms) took {dt:.3f}s")
    return f"400k monotonic reads, 0.1s cpu took {wall:.2f}s, sleeps {dt:.3f}s"


@test
def sched_and_creds():
    every = os.sched_getaffinity(0)
    check(every and len(every) <= os.cpu_count(), f"affinity {every}")
    one = min(every)
    os.sched_setaffinity(0, {one})
    check(os.sched_getaffinity(0) == {one}, "sched_setaffinity didn't read back")
    r, w = os.pipe()

    def child():
        os.write(w, str(sorted(os.sched_getaffinity(0))).encode())
        time.sleep(5)

    pid = spawn(child)
    check(os.read(r, 100) == str([one]).encode(), "a forked child didn't inherit the mask")
    os.sched_setaffinity(pid, every)
    check(os.sched_getaffinity(pid) == every, "sched_setaffinity(child pid) missed the child")
    os.kill(pid, signal.SIGKILL)
    reap(pid)
    expect_errno(errno.ESRCH, "affinity of a pid that doesn't exist",
                 os.sched_getaffinity, 4_000_000)

    if os.getuid() == 0:
        os.setgroups([0, 10, 998])
        check(sorted(os.getgroups()) == [0, 10, 998], f"setgroups read back {os.getgroups()}")
        pid = spawn(lambda: 0 if sorted(os.getgroups()) == [0, 10, 998] else 1)
        check(reap(pid) == 0, "a forked child didn't inherit the groups")

    for f in ("interrupts", "softirqs", "swaps", "partitions", "devices", "modules"):
        with open(f"/proc/{f}") as fh:
            fh.read()
    with open("/proc/interrupts") as fh:
        head = fh.readline().split()
    check(head == [f"CPU{i}" for i in range(os.cpu_count())], f"/proc/interrupts header {head}")
    return "affinity set/inherit/by pid, setgroups/getgroups, system procfs files"


# ------------------------------------------------------------------- runner

def run_one(fn, wake):
    r, w = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    t0 = time.monotonic()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        signal.set_wakeup_fd(-1)
        for x in wake:
            os.close(x)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        res = {"ok": False, "info": "?"}
        try:
            os.setpgid(0, 0)
            d = os.path.join(ROOT, fn.__name__)
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
            os.chdir(d)
            res = {"ok": True, "info": str(fn() or "")}
        except BaseException as e:
            here = fn.__code__.co_filename
            lines = [f.lineno for f in traceback.extract_tb(e.__traceback__) if f.filename == here]
            res = {"ok": False, "info": f"{type(e).__name__}: {e}" + (f" [line {lines[-1]}]" if lines else "")}
        try:
            os.write(w, (json.dumps(res) + "\n").encode())
        finally:
            os._exit(0)

    os.close(w)
    buf, status, watch = b"", None, [r, wake[0]]
    while status is None:
        left = t0 + TIMEOUT - time.monotonic()
        if left <= 0:
            break
        ready = select.select(watch, [], [], left)[0]
        if r in ready:
            d = os.read(r, 65536)
            buf += d
            if not d:
                watch.remove(r)
        if wake[0] in ready:
            os.read(wake[0], 4096)
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            status = os.waitstatus_to_exitcode(st)
    secs = time.monotonic() - t0
    try:
        os.killpg(pid, signal.SIGKILL)  # stragglers
    except OSError:
        pass
    if status is None:
        reap(pid)
        os.close(r)
        return "TIMEOUT", secs, f"no result after {TIMEOUT}s"
    os.set_blocking(r, False)
    try:
        while (d := os.read(r, 65536)):
            buf += d
    except BlockingIOError:
        pass
    os.close(r)
    line = buf.split(b"\n", 1)[0]
    if not line:
        why = f"signal {signal.Signals(-status).name}" if status < 0 else f"exit {status}"
        return "CRASH", secs, f"test process died: {why}"
    res = json.loads(line)
    return ("PASS" if res["ok"] else "FAIL"), secs, res["info"]


def main():
    names = [a for a in sys.argv[1:] if a and not a.startswith("-")]
    unknown = set(names) - {t.__name__ for t in TESTS}
    if unknown:
        print("unknown tests:", ", ".join(sorted(unknown)))
        print("available:", ", ".join(t.__name__ for t in TESTS))
        return 2
    chosen = [t for t in TESTS if not names or t.__name__ in names]
    os.makedirs(ROOT, exist_ok=True)
    u = os.uname()
    print(f"CRAZY LINUX TEST  {u.sysname} {u.release} {u.machine}  python {sys.version.split()[0]}"
          f"  {os.cpu_count()} cpus  root {ROOT}\n", flush=True)

    wake = os.pipe()
    for x in wake:
        os.set_blocking(x, False)
    old_chld = signal.signal(signal.SIGCHLD, lambda *_: None)
    old_wake = signal.set_wakeup_fd(wake[1])
    counts, t_all = {}, time.monotonic()
    try:
        for fn in chosen:
            verdict, secs, info = run_one(fn, wake)
            counts[verdict] = counts.get(verdict, 0) + 1
            print(f"  {verdict:<7} {fn.__name__:<22} {secs:6.2f}s  {info}", flush=True)
    finally:
        signal.set_wakeup_fd(old_wake)
        signal.signal(signal.SIGCHLD, old_chld)
        for x in wake:
            os.close(x)
        shutil.rmtree(ROOT, ignore_errors=True)
    passed = counts.get("PASS", 0)
    print(f"\n{passed}/{len(chosen)} passed in {time.monotonic() - t_all:.1f}s"
          + "".join(f", {n} {v.lower()}" for v, n in counts.items() if v != "PASS"))
    return 0 if passed == len(chosen) else 1


if __name__ == "__main__":
    rc = main()
    if not hasattr(sys, "ps1"):
        sys.exit(rc)
