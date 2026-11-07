"""Signal delivery, queueing, masks, handlers and job control."""
import ctypes
import errno
import os
import signal
import struct
import threading
import time

from lxt import check, eq, expect_errno, libc, must, napper, no_core, proc_status, reap, reap_within, spawn, syscall, test, wait_until


@test
def realtime_queue():
    """RT signals queue (500 of them) with si_pid; classic ones merge."""
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
    eq(got, 500, "RT signals queued")
    eq(senders, {pid}, "si_pid")
    eq(usr1, 1, "SIGUSR1s merged")
    sq = libc.sigqueue
    sq.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    check(sq(me, rt, ctypes.c_void_p(0xBEEF)) == 0, "sigqueue")
    info = signal.sigtimedwait({rt}, 1)
    check(info and info.si_code == -1, f"sigqueue si_code {info and info.si_code}")   # SI_QUEUE
    return "500 queued, si_pid right, SIGUSR1 merged, sigqueue SI_QUEUE"


@test
def handlers_and_masks():
    """Handlers, pending sets, per-thread delivery and the default action."""
    hits = []
    signal.signal(signal.SIGUSR1, lambda s, f: hits.append(s))
    os.kill(os.getpid(), signal.SIGUSR1)
    eq(hits, [signal.SIGUSR1], "handler ran")
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
    os.kill(os.getpid(), signal.SIGUSR2)
    eq(signal.sigpending(), {signal.SIGUSR2}, "pending while blocked")
    with open("/proc/self/status") as f:
        shdpnd = [l for l in f if l.startswith(("SigPnd", "ShdPnd"))]
    check(any(int(l.split()[1], 16) & (1 << (signal.SIGUSR2 - 1)) for l in shdpnd), "status pending mask")
    signal.signal(signal.SIGUSR2, lambda s, f: hits.append(s))
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR2})
    eq(hits[-1], signal.SIGUSR2, "delivered on unblock")
    # a signal aimed at one thread goes to that thread
    seen = []
    ev = threading.Event()

    def worker():
        seen.append(signal.sigwait({signal.SIGUSR1}))   # mask inherited: blocked
        ev.set()

    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    t = threading.Thread(target=worker)
    t.start()
    signal.pthread_kill(t.ident, signal.SIGUSR1)
    check(ev.wait(5), "thread never got its signal")
    t.join()
    eq(seen, [signal.SIGUSR1], "sigwait in the target thread")
    eq(signal.sigpending(), set(), "a thread-directed signal leaked to the process")

    def default_again():
        # the handler restores SIG_DFL, so the second SIGTERM kills
        signal.signal(signal.SIGTERM, lambda *_: signal.signal(signal.SIGTERM, signal.SIG_DFL))
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(1)
        return 9

    eq(reap(spawn(default_again)), -signal.SIGTERM, "second SIGTERM with default action")
    return "handler, pending, status mask, unblock, pthread_kill, default action"


@test(serial=True)
def interrupted_syscalls():
    """With SA_RESTART a blocked read survives 100s of SIGALRMs; sleep too."""
    hits = 0

    def h(*_):
        nonlocal hits
        hits += 1

    signal.signal(signal.SIGALRM, h)
    signal.siginterrupt(signal.SIGALRM, False)
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
    check(dt >= 0.3, f"sleep cut short: {dt:.3f}s")
    eq(data, b"ok", "read across signals")
    check(hits >= 50, f"only {hits} SIGALRMs")
    return f"{hits} SIGALRMs, sleep and read both survived"


@test
def pingpong():
    """2000 signal round trips between two processes."""
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    parent, n = os.getpid(), 2000

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
def fatal_signals():
    """Faults, aborts and limits kill with the right signal."""
    def segv():
        no_core()
        ctypes.memset(8, 0, 1)

    def abort():
        no_core()
        os.abort()

    def bus():
        no_core()
        import mmap
        fd = os.open("short", os.O_RDWR | os.O_CREAT, 0o644)
        os.ftruncate(fd, 8192)
        m = mmap.mmap(fd, 8192)
        os.ftruncate(fd, 4096)
        m[5000] = 1     # past the new EOF: SIGBUS

    def cpu():
        no_core()
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (1, 5))
        while True:
            pass

    def pipe_write():
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
        r, w = os.pipe()
        os.close(r)
        os.write(w, b"x")

    for label, fn, want in [("SIGSEGV", segv, -signal.SIGSEGV), ("abort", abort, -signal.SIGABRT),
                            ("SIGBUS past EOF", bus, -signal.SIGBUS), ("RLIMIT_CPU", cpu, -signal.SIGXCPU),
                            ("SIGPIPE", pipe_write, -signal.SIGPIPE),
                            ("SIGKILL", lambda: os.kill(os.getpid(), signal.SIGKILL), -signal.SIGKILL)]:
        eq(reap_within(spawn(fn), 20), want, label)
    return "SEGV, ABRT, BUS, XCPU, PIPE, KILL"


@test
def job_control_signals():
    """SIGSTOP/SIGCONT seen by waitpid and /proc; killpg reaches a whole group."""
    pid = spawn(napper)
    os.kill(pid, signal.SIGSTOP)
    _, st = os.waitpid(pid, os.WUNTRACED)
    check(os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGSTOP, f"not stopped: {st:#x}")
    check(proc_status(pid)["State"].startswith("T"), "/proc state while stopped")
    os.kill(pid, signal.SIGCONT)
    _, st = os.waitpid(pid, os.WCONTINUED)
    check(os.WIFCONTINUED(st), "no WCONTINUED")
    wait_until(lambda: not proc_status(pid)["State"].startswith("T"), 5, "state after SIGCONT")
    os.kill(pid, signal.SIGTERM)
    eq(reap(pid), -signal.SIGTERM, "SIGTERM")
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
    wait_until(lambda: all(os.getpgid(p) == leader for p in members), 5, "group to form")
    os.killpg(leader, signal.SIGTERM)
    eq([reap(p) for p in members], [-signal.SIGTERM] * 5, "killpg")
    return "STOP/CONT via waitpid and /proc, killpg x5"


@test
def signalfd_and_pidfd():
    """signalfd reads queued signals; pidfd_send_signal and waitid(P_PIDFD)."""
    mask = ctypes.c_uint64(1 << (signal.SIGUSR1 - 1))
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    fd = syscall("signalfd4", -1, ctypes.addressof(mask), 8, os.O_NONBLOCK | os.O_CLOEXEC)
    os.kill(os.getpid(), signal.SIGUSR1)
    info = os.read(fd, 128)
    signo, _, _, pid, uid = struct.unpack_from("IiiII", info)
    eq((signo, pid, uid), (signal.SIGUSR1, os.getpid(), os.getuid()), "signalfd_siginfo")
    expect_errno(errno.EAGAIN, "empty signalfd", os.read, fd, 128)
    child = spawn(napper)
    pfd = os.pidfd_open(child)
    signal.pidfd_send_signal(pfd, signal.SIGTERM)
    res = os.waitid(os.P_PIDFD, pfd, os.WEXITED)
    eq((res.si_pid, res.si_status), (child, signal.SIGTERM), "waitid(P_PIDFD)")
    return "signalfd siginfo, EAGAIN, pidfd signal + wait"
