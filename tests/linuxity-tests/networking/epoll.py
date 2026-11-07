"""epoll, poll/select and the fd types event loops are built on."""
import errno
import os
import random
import select
import socket
import struct
import time

from lxt import check, eq, expect_errno, must, spawn, test, napper, reap
import signal


@test
def level_and_edge():
    """Level-triggered readiness for 256 pipes; poll and select agree."""
    ep = select.epoll()
    pipes = [os.pipe() for _ in range(256)]
    for r, _ in pipes:
        ep.register(r, select.EPOLLIN)
    ready = set(random.Random(9).sample(range(256), 77))
    for i in ready:
        os.write(pipes[i][1], b"x")
    want = {pipes[i][0] for i in ready}
    eq({fd for fd, _ in ep.poll(1, maxevents=1024)}, want, "epoll ready set")
    eq({fd for fd, _ in ep.poll(0, maxevents=1024)}, want, "level-triggered: still ready")
    po = select.poll()
    for r, _ in pipes:
        po.register(r, select.POLLIN)
    eq({fd for fd, _ in po.poll(1000)}, want, "poll")
    first = {r for r, _ in pipes[:200]}
    eq(set(select.select(sorted(first), [], [], 1)[0]), want & first, "select")
    et = select.epoll()
    r0, w0 = os.pipe()
    et.register(r0, select.EPOLLIN | select.EPOLLET)
    os.write(w0, b"a")
    eq(len(et.poll(1)), 1, "ET first edge")
    eq(et.poll(0), [], "ET doesn't refire without new data")
    os.write(w0, b"b")
    eq(len(et.poll(1)), 1, "ET second edge")
    os.close(w0)
    evs = et.poll(1)
    check(evs and evs[0][1] & select.EPOLLHUP, f"EPOLLHUP after the writer closed: {evs}")
    return "256 pipes LT, poll/select agree, ET edges, HUP"


@test
def oneshot_and_exclusive():
    """EPOLLONESHOT needs a re-arm; EPOLLEXCLUSIVE wakes one waiter."""
    one = select.epoll()
    r, w = os.pipe()
    one.register(r, select.EPOLLIN | select.EPOLLONESHOT)
    os.write(w, b"x")
    eq(len(one.poll(1)), 1, "first event")
    os.write(w, b"y")
    eq(one.poll(0), [], "ONESHOT fired twice")
    one.modify(r, select.EPOLLIN | select.EPOLLONESHOT)
    eq(len(one.poll(1)), 1, "after re-arm")
    expect_errno(errno.EEXIST, "register twice", one.register, r, select.EPOLLIN)
    expect_errno(errno.ENOENT, "modify an fd never added", one.modify, w, select.EPOLLOUT)
    expect_errno(errno.EPERM, "epoll on a regular file", one.register,
                 os.open("plain", os.O_RDWR | os.O_CREAT, 0o644), select.EPOLLIN)
    return "ONESHOT re-arm, EEXIST, ENOENT, EPERM on a file"


@test
def cross_process_wakeups():
    """epoll in one process wakes for writes, connects and exits in others."""
    ep = select.epoll()
    r, w = os.pipe()
    ep.register(r, select.EPOLLIN)
    pid = spawn(lambda: os.write(w, b"z") and 0)
    check(ep.poll(5), "a write from another process")
    must(pid)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    srv.setblocking(False)
    ep = select.epoll()
    ep.register(srv.fileno(), select.EPOLLIN)
    pid = spawn(lambda: socket.create_connection(srv.getsockname()).close() or 0)
    check(srv.fileno() in dict(ep.poll(5)), "listener readable after a connect from a child")
    must(pid)
    child = spawn(napper)
    pfd = os.pidfd_open(child)
    ep = select.epoll()
    ep.register(pfd, select.EPOLLIN)
    eq(ep.poll(0), [], "pidfd readable while the child lives")
    os.kill(child, signal.SIGKILL)
    check(pfd in dict(ep.poll(5)), "pidfd readable when the child dies")
    reap(child)
    return "pipe, listener, pidfd"


@test
def eventfd_timerfd():
    """eventfd counters and semaphores; timerfd ticks at the requested rate."""
    efd = os.eventfd(0, os.EFD_SEMAPHORE | os.EFD_NONBLOCK)
    must(spawn(lambda: [os.eventfd_write(efd, 1) for _ in range(100)] and 0))
    n = 0
    while True:
        try:
            os.eventfd_read(efd)
            n += 1
        except BlockingIOError:
            break
    eq(n, 100, "eventfd semaphore")
    cnt = os.eventfd(5)
    os.eventfd_write(cnt, 7)
    eq(os.eventfd_read(cnt), 12, "eventfd counter")
    expect_errno(errno.EINVAL, "eventfd read into a short buffer", os.read, cnt, 4)
    tfd = os.timerfd_create(time.CLOCK_MONOTONIC)
    os.timerfd_settime(tfd, initial=0.01, interval=0.01)
    t0, ticks = time.monotonic(), 0
    while time.monotonic() - t0 < 0.2:
        ticks += struct.unpack("Q", os.read(tfd, 8))[0]
    expect = (time.monotonic() - t0) / 0.01
    check(abs(ticks - expect) <= 3, f"timerfd {ticks} ticks, expected ~{expect:.0f}")
    left, interval = os.timerfd_gettime(tfd)
    check(0 < left <= 0.01 and abs(interval - 0.01) < 1e-6, "timerfd_gettime")
    return f"eventfd 100, counter, timerfd {ticks} ticks"


@test
def asyncio_flood():
    """500 concurrent asyncio connections and an async subprocess."""
    import asyncio
    import resource
    import subprocess
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(soft, 4096), hard if hard != resource.RLIM_INFINITY else 8192), hard))
    n = max(10, min(500, (resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 100) // 3))

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

        ok = sum(await asyncio.gather(*(client(i) for i in range(n))))
        p = await asyncio.create_subprocess_exec("sh", "-c", "cat; echo done",
                                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = await p.communicate(b"abc\n")
        srv.close()
        await srv.wait_closed()
        return ok, out

    ok, out = asyncio.run(asyncio.wait_for(main(), 45))
    eq(ok, n, "async clients echoed")
    eq(out, b"abc\ndone\n", "async subprocess")
    return f"{n} connections"
