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
from torture import check, ok, eq, expect_errno, child, status, run_in_child, Skip, main, libc

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
