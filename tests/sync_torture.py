#!/usr/bin/env python3
"""sync_torture.py -- threads, futexes, clocks, timers and event fds:
everything a runtime (Go, the JVM, Node, asyncio) builds its scheduler on.
See torture.py for how to run it."""
import sys
sys.dont_write_bytecode = True
import ctypes
import errno
import os
import select
import signal
import struct
import threading
import time

from torture import *  # noqa: F401,F403
from torture import check, ok, eq, expect_errno, child, status, run_in_child, Skip, main, libc, ARCH

CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID = 0, 1, 2, 3
CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME = 4, 5, 6, 7


class Timespec(ctypes.Structure):
    _fields_ = [("sec", ctypes.c_long), ("nsec", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("interval", Timespec), ("value", Timespec)]


# ---------------------------------------------------------------- threads

@check
def many_threads_share_memory_under_a_lock():
    lock, n = threading.Lock(), [0]

    def work():
        for _ in range(2000):
            with lock:
                n[0] += 1
    ts = [threading.Thread(target=work) for _ in range(64)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    eq(n[0], 64 * 2000, "every increment counted")


@check
def threads_have_their_own_tids_in_proc():
    tids, ev = [], threading.Event()
    ready = threading.Barrier(9)

    def park():
        tids.append(threading.get_native_id())
        ready.wait()
        ev.wait(10)
    ts = [threading.Thread(target=park) for _ in range(8)]
    for t in ts:
        t.start()
    ready.wait()
    tasks = {int(x) for x in os.listdir("/proc/self/task")}
    ok(set(tids) <= tasks, f"/proc/self/task lists every thread: {sorted(tasks)}")
    eq(len(set(tids) | {os.getpid()}), 9, "nine distinct tids")
    with open("/proc/self/status") as f:
        eq(int(next(l for l in f if l.startswith("Threads:")).split()[1]), 9, "Threads: 9")
    eq(threading.get_native_id(), os.getpid(), "the main thread's tid is the pid")
    with open(f"/proc/self/task/{tids[0]}/stat") as f:
        eq(int(f.read().split()[0]), tids[0], "a thread's own stat")
    ev.set()
    for t in ts:
        t.join(10)


@check
def condition_ping_pong():
    cv, turn = threading.Condition(), [0]

    def player(me):
        for _ in range(1000):
            with cv:
                while turn[0] % 2 != me:
                    cv.wait(5)
                turn[0] += 1
                cv.notify()
    a, b = threading.Thread(target=player, args=(0,)), threading.Thread(target=player, args=(1,))
    t = time.monotonic()
    a.start(); b.start(); a.join(20); b.join(20)
    eq(turn[0], 2000, "2000 hand-offs")
    ok(time.monotonic() - t < 15, f"futex wake/wait is quick ({time.monotonic() - t:.1f}s)")


@check
def lock_and_wait_timeouts():
    lk = threading.Lock()
    lk.acquire()
    t = time.monotonic()
    eq(lk.acquire(timeout=0.25), False, "a timed acquire of a held lock")
    d = time.monotonic() - t
    ok(0.2 <= d < 1.5, f"took {d:.2f}s")
    e = threading.Event()
    t = time.monotonic()
    eq(e.wait(0.2), False, "Event.wait times out")
    ok(0.15 <= time.monotonic() - t < 1.5, "after ~0.2s")
    q = __import__("queue").Queue()
    threading.Timer(0.1, q.put, args=("late",)).start()
    eq(q.get(timeout=5), "late", "a Timer thread delivers")


@check
def a_signal_for_nobody_does_not_end_a_timeout():
    # SIGCHLD at its default disposition is discarded, and a signal another
    # thread takes wakes nobody here: neither may end select/poll early.
    # linuxity's signal wake made them return 0 (a timeout) at once, so
    # asyncio's pidfd watcher, waiting 5 s for a quick child, gave up in
    # 3 ms while other threads' children exited around it.
    errors = []

    def spawner(k):
        for i in range(8):
            pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 3"], os.environ)
            time.sleep(((i + k) % 4) * 0.003)
            fd = os.pidfd_open(pid)
            t0 = time.monotonic()
            if select.select([fd], [], [], 5)[0] != [fd]:
                errors.append(f"{k}/{i}: select gave up after {time.monotonic() - t0:.3f}s")
            os.close(fd)
            os.waitpid(pid, 0)
    ts = [threading.Thread(target=spawner, args=(k,)) for k in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    eq(errors, [], "every wait lasted until the child exited")
    r, _ = os.pipe()
    p = select.poll()
    p.register(r, select.POLLIN)
    t0 = time.monotonic()
    os.kill(os.getpid(), signal.SIGCHLD)
    eq(p.poll(300), [], "poll times out with nothing ready")
    ok(time.monotonic() - t0 >= 0.25, "despite a SIGCHLD to the process")


@check
def signals_reach_the_main_thread_while_others_run():
    got = []
    signal.signal(signal.SIGUSR1, lambda s, f: got.append(threading.get_native_id()))
    stop = threading.Event()
    ts = [threading.Thread(target=lambda: [time.sleep(0.01) for _ in iter(stop.is_set, True)]) for _ in range(4)]
    for t in ts:
        t.start()
    for _ in range(5):
        os.kill(os.getpid(), signal.SIGUSR1)
        time.sleep(0.02)
    stop.set()
    for t in ts:
        t.join(5)
    ok(got and all(x == os.getpid() for x in got), f"handlers ran in the main thread: {got}")


@check
def thread_exit_and_join_with_process_exit():
    def body():
        def stuck():
            time.sleep(60)
        threading.Thread(target=stuck, daemon=True).start()
        threading.Thread(target=lambda: os._exit(7)).start()
        time.sleep(10)
        return 1
    t = time.monotonic()
    eq(run_in_child(body), 7, "a thread's _exit ends the whole process")
    ok(time.monotonic() - t < 5, "at once, despite a sleeping thread")


@check
def fork_from_a_thread():
    r = []

    def t():
        pid = os.fork()
        if pid == 0:
            os._exit(42 if threading.active_count() == 1 else 1)
        r.append(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]))
    th = threading.Thread(target=t)
    th.start(); th.join(10)
    eq(r, [42], "the child of a thread's fork has exactly one thread")


# ---------------------------------------------------------------- clocks

@check
def clocks_are_sane():
    def now(c):
        ts = Timespec()
        eq(libc.clock_gettime(c, ctypes.byref(ts)), 0, f"clock_gettime({c})")
        return ts.sec + ts.nsec / 1e9
    real = now(CLOCK_REALTIME)
    ok(abs(real - time.time()) < 1, "CLOCK_REALTIME vs time.time")
    ok(real > 1.6e9, f"the wall clock is a plausible date ({time.ctime(real)})")
    for c in (CLOCK_MONOTONIC, CLOCK_MONOTONIC_RAW, CLOCK_BOOTTIME, CLOCK_MONOTONIC_COARSE):
        a = now(c); time.sleep(0.02); b = now(c)
        ok(0.01 < b - a < 1, f"clock {c} advances ({b - a:.3f}s)")
    ok(now(CLOCK_BOOTTIME) >= now(CLOCK_MONOTONIC) - 0.01, "BOOTTIME >= MONOTONIC")
    with open("/proc/uptime") as f:
        up = float(f.read().split()[0])
    ok(abs(up - now(CLOCK_BOOTTIME)) < 2, f"/proc/uptime ({up}) vs CLOCK_BOOTTIME")
    res = Timespec()
    eq(libc.clock_getres(CLOCK_MONOTONIC, ctypes.byref(res)), 0, "clock_getres")
    ok(res.sec == 0 and 0 < res.nsec <= 1_000_000, f"resolution {res.nsec}ns")
    ok(libc.clock_gettime(99, ctypes.byref(res)) == -1 and ctypes.get_errno() == errno.EINVAL,
       "a bad clock id is EINVAL")


@check
def cpu_clocks_count_cpu_not_sleep():
    def cpu(c):
        ts = Timespec(); libc.clock_gettime(c, ctypes.byref(ts)); return ts.sec + ts.nsec / 1e9
    a = cpu(CLOCK_PROCESS_CPUTIME_ID)
    time.sleep(0.3)
    b = cpu(CLOCK_PROCESS_CPUTIME_ID)
    ok(b - a < 0.15, f"sleeping costs no CPU ({b - a:.3f}s)")
    t = time.monotonic()
    while time.monotonic() - t < 0.3:
        pass
    c = cpu(CLOCK_PROCESS_CPUTIME_ID)
    ok(0.15 < c - b < 0.6, f"spinning 0.3s costs ~0.3s CPU ({c - b:.3f}s)")
    th = cpu(CLOCK_THREAD_CPUTIME_ID)
    ok(0 < th <= c + 0.01, "thread CPU <= process CPU")
    ru = __import__("resource").getrusage(__import__("resource").RUSAGE_SELF)
    ok(ru.ru_utime + ru.ru_stime >= 0.15, f"getrusage agrees ({ru.ru_utime:.2f}+{ru.ru_stime:.2f})")


@check
def sleeps_are_accurate():
    for want in (0.001, 0.05, 0.2):
        t = time.monotonic()
        time.sleep(want)
        d = time.monotonic() - t
        ok(want <= d < want + 0.1, f"sleep({want}) took {d:.4f}s")
    ts = Timespec(0, 0)
    eq(libc.nanosleep(ctypes.byref(Timespec(0, 1000)), None), 0, "nanosleep(1us)")
    TIMER_ABSTIME = 1
    libc.clock_gettime(CLOCK_MONOTONIC, ctypes.byref(ts))
    ts.nsec += 100_000_000
    if ts.nsec >= 1_000_000_000:
        ts.sec += 1; ts.nsec -= 1_000_000_000
    t = time.monotonic()
    eq(libc.clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, ctypes.byref(ts), None), 0, "absolute sleep")
    ok(0.05 < time.monotonic() - t < 0.5, "until the deadline")


@check
def timezones():
    if not os.path.exists("/usr/share/zoneinfo/Asia/Kolkata"):
        raise Skip("no tzdata in this environment")
    os.environ["TZ"] = "UTC"; time.tzset()
    eq(time.localtime(0).tm_hour, 0, "UTC at the epoch")
    os.environ["TZ"] = "Asia/Kolkata"; time.tzset()
    eq((time.localtime(0).tm_hour, time.localtime(0).tm_min), (5, 30), "IST is +5:30")
    eq(time.strftime("%Z", time.localtime(0)), "IST", "zone name")


# ---------------------------------------------------------------- timers and fds

@check
def posix_timer_and_alarm_signals():
    got = []
    signal.signal(signal.SIGALRM, lambda s, f: got.append(time.monotonic()))
    t = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, 0.05, 0.05)
    while len(got) < 5 and time.monotonic() - t < 3:
        time.sleep(0.01)
    signal.setitimer(signal.ITIMER_REAL, 0)
    eq(len(got) >= 5, True, f"5 periodic SIGALRMs ({len(got)})")
    gaps = [b - a for a, b in zip(got, got[1:])]
    ok(all(0.02 < g < 0.2 for g in gaps), f"~50ms apart: {[round(g, 3) for g in gaps]}")


@check
def timerfd_periodic():
    libc.timerfd_create.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.timerfd_settime.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(Itimerspec), ctypes.c_void_p]
    fd = libc.timerfd_create(CLOCK_MONOTONIC, os.O_NONBLOCK | os.O_CLOEXEC)
    ok(fd >= 0, f"timerfd_create: {errname(ctypes.get_errno())}")
    spec = Itimerspec(Timespec(0, 20_000_000), Timespec(0, 20_000_000))
    eq(libc.timerfd_settime(fd, 0, ctypes.byref(spec), None), 0, "timerfd_settime")
    expect_errno(errno.EAGAIN, "not yet expired", os.read, fd, 8)
    p = select.poll(); p.register(fd, select.POLLIN)
    ok(p.poll(2000), "becomes readable")
    time.sleep(0.1)
    n = struct.unpack("Q", os.read(fd, 8))[0]
    ok(4 <= n <= 8, f"expirations counted while we slept: {n}")
    ep = select.epoll(); ep.register(fd, select.EPOLLIN)
    ok(ep.poll(2), "epoll on a timerfd")
    old = Itimerspec()
    libc.timerfd_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(Itimerspec)]
    eq(libc.timerfd_gettime(fd, ctypes.byref(old)), 0, "timerfd_gettime")
    eq(old.interval.nsec, 20_000_000, "the interval reads back")


@check
def signalfd_reads_signals():
    class SigInfo(ctypes.Structure):
        _fields_ = [("signo", ctypes.c_uint32), ("errno", ctypes.c_int32), ("code", ctypes.c_int32),
                    ("pid", ctypes.c_uint32), ("uid", ctypes.c_uint32), ("rest", ctypes.c_uint8 * 108)]
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1, signal.SIGUSR2})
    mask = (ctypes.c_uint64 * 16)()
    mask[0] = (1 << (signal.SIGUSR1 - 1)) | (1 << (signal.SIGUSR2 - 1))
    libc.signalfd.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
    fd = libc.signalfd(-1, mask, os.O_NONBLOCK)
    ok(fd >= 0, f"signalfd: {errname(ctypes.get_errno())}")
    expect_errno(errno.EAGAIN, "nothing pending", os.read, fd, 128)
    os.kill(os.getpid(), signal.SIGUSR2)
    pid = child(lambda: os.kill(os.getppid(), signal.SIGUSR1) or 0)
    eq(status(pid), 0, "sender")
    ok(select.select([fd], [], [], 2)[0], "readable")
    got = []
    while True:
        try:
            b = os.read(fd, 128)
        except BlockingIOError:
            break
        si = SigInfo.from_buffer_copy(b)
        got.append((si.signo, si.pid))
    eq(sorted(s for s, _ in got), [signal.SIGUSR1, signal.SIGUSR2], "both signals, as records")
    eq(dict(got)[signal.SIGUSR1], pid, "ssi_pid names the sender")


@check
def a_reused_fd_number_forgets_its_timerfd():
    # Fd numbers come back at once (lowest free). A runtime that keyed
    # timerfd state by number and kept it past close made the next eventfd
    # with that number refuse writes (foot: "failed to send terminal
    # shutdown event: Invalid argument", then a window that never closed).
    libc.timerfd_create.argtypes = [ctypes.c_int, ctypes.c_int]
    t = libc.timerfd_create(CLOCK_MONOTONIC, os.O_NONBLOCK | os.O_CLOEXEC)
    ok(t >= 0, "timerfd_create")
    os.close(t)
    e = os.eventfd(0, os.EFD_NONBLOCK)
    eq(e, t, "the eventfd takes the timerfd's number")
    os.eventfd_write(e, 5)
    eq(os.eventfd_read(e), 5, "and works as an eventfd")
    t2 = libc.timerfd_create(CLOCK_MONOTONIC, os.O_NONBLOCK)
    os.dup2(e, t2)
    os.eventfd_write(t2, 2)
    eq(os.eventfd_read(e), 2, "dup2 over a timerfd makes an eventfd of it too")
    os.close(t2)
    os.close(e)


@check
def epoll_pwait_opens_its_sigmask_for_the_wait():
    # The p-variants exist for this: keep SIGCHLD blocked, open it only
    # inside the wait. foot's event loop does exactly this; ignoring the
    # mask meant it never heard its shell exit.
    def run():
        libc.epoll_pwait.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        got = []
        signal.signal(signal.SIGCHLD, lambda *a: got.append(1))
        old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
        ep = select.epoll()
        r, _w = os.pipe()
        ep.register(r, select.EPOLLIN)
        orig = (ctypes.c_uint64 * 16)()
        for s in old:
            orig[0] |= 1 << (s - 1)
        pid = os.fork()
        if pid == 0:
            time.sleep(0.2)
            os._exit(4)
        events = (ctypes.c_uint8 * 64)()
        t = time.monotonic()
        n = libc.epoll_pwait(ep.fileno(), events, 4, 5000, orig)
        e = ctypes.get_errno()
        waited = time.monotonic() - t
        eq((n, e), (-1, errno.EINTR), "SIGCHLD interrupts the wait")
        ok(waited < 3, f"promptly ({waited:.2f}s)")
        eq(got, [1], "its handler ran")
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        ok(signal.SIGCHLD in blocked, "the caller's mask is back afterwards")
        _, st = os.waitpid(pid, 0)
        eq(os.waitstatus_to_exitcode(st), 4, "the child is reaped")
        return 0
    eq(run_in_child(run), 0, "in a child")


@check
def an_epoll_fd_works_from_every_thread():
    # Go's netpoller makes its epoll fd on one thread and waits on it from
    # another; fd objects are the process's, not a thread's. A runtime that
    # kept them per thread answered EINVAL: "epollwait on fd 4 failed with
    # 22", and every Go binary (snap, docker, gh) died.
    ep = select.epoll()
    r, w = os.pipe()
    out = []
    def other():
        ep.register(r, select.EPOLLIN)
        os.write(w, b"x")
        out.append(ep.poll(2))
    t = threading.Thread(target=other)
    t.start(); t.join()
    eq(len(out[0]), 1, "registered and waited on by a thread that didn't create it")
    ep.close(); os.close(r); os.close(w)


@check
def a_handler_without_sa_restorer_returns_on_any_thread():
    # Go on arm64 installs handlers with raw rt_sigaction and no
    # SA_RESTORER; the kernel returns through the vDSO's rt_sigreturn. A
    # trampoline written onto the stack ran only on the thread that
    # published it -- signals on other threads crashed in it.
    def run():
        class Sigaction(ctypes.Structure):
            _fields_ = [("handler", ctypes.c_void_p), ("flags", ctypes.c_ulong),
                        ("restorer", ctypes.c_void_p), ("mask", ctypes.c_uint64)]
        got = []
        HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_int)
        h = HANDLER(lambda s: got.append(s))
        sa = Sigaction(ctypes.cast(h, ctypes.c_void_p), 0, None, 0)
        NR = 134 if ARCH == "aarch64" else 13
        eq(libc.syscall(NR, signal.SIGUSR2, ctypes.byref(sa), None, 8), 0, "raw rt_sigaction, no SA_RESTORER")
        def worker():
            libc.syscall(131 if ARCH == "aarch64" else 234, os.getpid(), threading.get_native_id(), signal.SIGUSR2)
            time.sleep(0.05)
        ts = [threading.Thread(target=worker) for _ in range(4)]
        for t in ts: t.start()
        for t in ts: t.join()
        time.sleep(0.1)
        ok(len(got) == 4, f"each thread's handler returned ({len(got)} of 4)")
        return 0
    eq(run_in_child(run), 0, "in a child")


@check
def a_unix_socket_under_a_long_path():
    # sun_path is 108 bytes on Linux, but the PATH that names a socket can be
    # anything a bind() through a relative name reaches. And a short guest
    # path may be long on the host: linuxity's macOS overlay lives under
    # $TMPDIR, so Firefox's $XDG_RUNTIME_DIR/wayland-proxy-N failed with
    # "bind() error: File name too long".
    import socket
    import tempfile
    d = tempfile.mkdtemp()
    deep = os.path.join(d, *["a-fairly-long-directory"] * 3)
    os.makedirs(deep)
    p = os.path.join(deep, "s")
    ok(len(p) < 108, f"guest path fits sun_path ({len(p)} bytes)")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(p)
    srv.listen(1)
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.connect(p)
    a, _ = srv.accept()
    c.sendall(b"hi")
    eq(a.recv(2), b"hi", "bound, connected and talking")
    for s in (a, c, srv):
        s.close()


_THREADS_FORKS_C = r"""
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile int stop;
static void* sleeper(void* a) { (void)a; sleep(2); return 0; }
static void* churn(void* a) { (void)a; while (!stop) { int f = open("/dev/null", O_RDONLY); close(f); } return 0; }
static int fork_fail;
static void* forker(void* a) {
    (void)a;
    for (int i = 0; i < 8; i++) {
        pid_t p = fork();
        if (p == 0) _exit(3);
        if (p < 0) { __atomic_fetch_add(&fork_fail, 1, 0); continue; }
        int st; waitpid(p, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 3) __atomic_fetch_add(&fork_fail, 1, 0);
    }
    return 0;
}
int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "threads")) {
        pthread_t t[300]; int n = 0;
        for (int i = 0; i < 300; i++) if (pthread_create(&t[i], 0, sleeper, 0) == 0) n++;
        for (int i = 0; i < n; i++) pthread_join(t[i], 0);
        printf("%d\n", n);
    } else {
        pthread_t c[3], f[4];
        for (int i = 0; i < 3; i++) pthread_create(&c[i], 0, churn, 0);
        for (int i = 0; i < 4; i++) pthread_create(&f[i], 0, forker, 0);
        for (int i = 0; i < 4; i++) pthread_join(f[i], 0);
        stop = 1;
        for (int i = 0; i < 3; i++) pthread_join(c[i], 0);
        printf("%d\n", fork_fail);
    }
    fflush(stdout);
    return 0;
}
"""


def _build_threads_forks():
    from torture import sh, have
    cc = next((c for c in ("cc", "gcc", "clang") if have(c)), None)
    if not cc:
        raise Skip("no C compiler")
    import tempfile
    d = tempfile.mkdtemp()
    src, exe = os.path.join(d, "tf.c"), os.path.join(d, "tf")
    with open(src, "w") as f:
        f.write(_THREADS_FORKS_C)
    eq(sh(f"{cc} -O1 -pthread -o {exe} {src}")[0], 0, "compiles")
    return exe


@check(timeout=120)
def hundreds_of_live_threads():
    # Linux runs thousands of threads; programs (Firefox's thread pools, Go,
    # the JVM) assume hundreds. Most sleep in a syscall at any moment. A
    # runtime that gives each thread a hypervisor vCPU must not stop at the
    # vCPU limit (64 on macOS): it hung at 63, then failed EAGAIN, and
    # Firefox died in "nsThreadPool::PutEvent() - Failed to create a new
    # thread when pool is empty".
    from torture import sh
    rc, out, _ = sh(_build_threads_forks() + " threads", timeout=100)
    eq((rc, out.strip()), (0, "300"), "300 threads alive at once")


@check(timeout=120)
def forks_from_many_threads_at_once():
    # Four threads forking while three others open and close fds: fork must
    # not trip on an fd another thread just closed (EBADF -> EAGAIN) or on
    # two forks drawing the same rendezvous name.
    from torture import sh
    rc, out, _ = sh(_build_threads_forks() + " forks", timeout=100)
    eq((rc, out.strip()), (0, "0"), "no fork failed")


@check
def pollpri_means_urgent_data_only():
    # A pipe with data is POLLIN, never POLLPRI (Linux sets that for urgent
    # data alone). Darwin's poll says POLLPRI for any readable fd when asked;
    # Firefox's socket thread took that as an error on its wakeup pipe and
    # rebuilt the pipe in a tight loop, forever.
    r, w = os.pipe()
    os.write(w, b"x")
    p = select.poll()
    p.register(r, select.POLLIN | select.POLLPRI)
    eq(p.poll(1000), [(r, select.POLLIN)], "a readable pipe is POLLIN only")
    _, _, x = select.select([], [], [r], 0)
    eq(x, [], "and is no select() exception")
    os.close(r); os.close(w)
    import socket
    a, b = socket.socketpair()
    b.send(b"y")
    p = select.poll()
    p.register(a, select.POLLIN | select.POLLPRI)
    eq(p.poll(1000), [(a.fileno(), select.POLLIN)], "a readable socket is POLLIN only")
    a.close(); b.close()


@check
def epoll_over_every_kind_of_fd():
    import socket
    ep = select.epoll()
    r, w = os.pipe()
    a, b = socket.socketpair()
    e = os.eventfd(0)
    for fd in (r, a.fileno(), e):
        ep.register(fd, select.EPOLLIN)
    os.write(w, b"p"); b.send(b"s"); os.eventfd_write(e, 1)
    ready = {fd for fd, _ in ep.poll(2)}
    eq(ready, {r, a.fileno(), e}, "pipe, socket and eventfd all report")
    eq(ep.poll(0, 1).__len__(), 1, "maxevents is honoured")
    ep.unregister(r)
    expect_errno(errno.ENOENT, "unregistering twice", ep.unregister, r)
    nested = select.epoll()
    nested.register(ep.fileno(), select.EPOLLIN)
    ok(nested.poll(1), "an epoll inside an epoll")


@check
def getrandom_and_entropy():
    a, b = os.getrandom(32), os.getrandom(32, os.GRND_NONBLOCK)
    ok(a != b and len(a) == 32, "getrandom")
    with open("/proc/sys/kernel/random/boot_id") as f:
        ok(len(f.read().strip()) == 36, "boot_id is a UUID")
    with open("/proc/sys/kernel/random/uuid") as f:
        u1 = f.read().strip()
    with open("/proc/sys/kernel/random/uuid") as f:
        ok(f.read().strip() != u1, "random/uuid changes each read")


@check(timeout=60)
def asyncio_servers_subprocesses_and_timers():
    import asyncio

    async def run():
        async def handle(reader, writer):
            writer.write((await reader.readline()).upper())
            await writer.drain(); writer.close()
        srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        outs = []
        for i in range(20):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(f"hello {i}\n".encode()); await w.drain()
            outs.append(await r.readline()); w.close()
        p = await asyncio.create_subprocess_exec("sh", "-c", "echo sub; exit 3",
                                                 stdout=asyncio.subprocess.PIPE)
        out, _ = await p.communicate()
        t = time.monotonic()
        await asyncio.sleep(0.1)
        slept = time.monotonic() - t
        srv.close(); await srv.wait_closed()
        return outs, out, p.returncode, slept
    outs, out, rc, slept = asyncio.run(asyncio.wait_for(run(), 40))
    eq(outs[7], b"HELLO 7\n", "an asyncio TCP server")
    eq((out, rc), (b"sub\n", 3), "an asyncio subprocess (child watcher, pidfd or SIGCHLD)")
    ok(0.09 <= slept < 0.5, f"asyncio.sleep ({slept:.3f})")


if __name__ == "__main__":
    sys.exit(main("threads & time"))
