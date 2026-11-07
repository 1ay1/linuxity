"""Scheduling: affinity, priorities, policies and CPU accounting."""
import errno
import os
import signal
import threading
import time

from lxt import check, eq, expect_errno, napper, reap, spawn, test


@test
def affinity():
    """sched_setaffinity reads back, is inherited, and works by pid."""
    every = os.sched_getaffinity(0)
    check(every and len(every) <= os.cpu_count(), f"affinity {every}")
    one = min(every)
    os.sched_setaffinity(0, {one})
    eq(os.sched_getaffinity(0), {one}, "read back")
    r, w = os.pipe()

    def child():
        os.write(w, str(sorted(os.sched_getaffinity(0))).encode())
        time.sleep(5)

    pid = spawn(child)
    eq(os.read(r, 100), str([one]).encode(), "inherited by a fork")
    os.sched_setaffinity(pid, every)
    eq(os.sched_getaffinity(pid), every, "set and get by pid")
    os.kill(pid, signal.SIGKILL)
    reap(pid)
    expect_errno(errno.ESRCH, "a pid that doesn't exist", os.sched_getaffinity, 4_000_000)
    expect_errno(errno.EINVAL, "an empty mask", os.sched_setaffinity, 0, set())
    # threads have their own mask
    os.sched_setaffinity(0, every)
    got = []
    t = threading.Thread(target=lambda: (os.sched_setaffinity(0, {one}), got.append(os.sched_getaffinity(0))))
    t.start()
    t.join()
    eq((got, os.sched_getaffinity(0)), ([{one}], every), "a thread's mask is its own")
    return f"{len(every)} cpus; set/read/inherit/by pid/per thread"


@test
def nice_and_priority():
    """nice and setpriority move the right task and read back."""
    base = os.getpriority(os.PRIO_PROCESS, 0)
    os.nice(3)
    eq(os.getpriority(os.PRIO_PROCESS, 0), base + 3, "nice(3)")
    pid = spawn(napper)
    eq(os.getpriority(os.PRIO_PROCESS, pid), base + 3, "child inherits nice")
    os.setpriority(os.PRIO_PROCESS, pid, base + 7)
    eq(os.getpriority(os.PRIO_PROCESS, pid), base + 7, "setpriority by pid")
    with open(f"/proc/{pid}/stat") as f:
        eq(int(f.read().rsplit(")", 1)[1].split()[16]), base + 7, "nice in /proc/pid/stat")
    eq(os.getpriority(os.PRIO_PROCESS, 0), base + 3, "the parent didn't move")
    os.kill(pid, signal.SIGKILL)
    reap(pid)
    expect_errno(errno.ESRCH, "setpriority on a missing pid", os.setpriority, os.PRIO_PROCESS, 4_000_000, 1)
    return "nice, inherit, by pid, /proc stat field"


@test
def policies():
    """Scheduler policy queries and the classes a normal process may pick."""
    eq(os.sched_getscheduler(0), os.SCHED_OTHER, "default policy")
    eq((os.sched_get_priority_min(os.SCHED_FIFO), os.sched_get_priority_max(os.SCHED_FIFO)), (1, 99), "FIFO range")
    eq(os.sched_get_priority_max(os.SCHED_OTHER), 0, "OTHER range")
    os.sched_setscheduler(0, os.SCHED_BATCH, os.sched_param(0))
    eq(os.sched_getscheduler(0), os.SCHED_BATCH, "SCHED_BATCH")
    os.sched_setscheduler(0, os.SCHED_IDLE, os.sched_param(0))
    eq(os.sched_getscheduler(0), os.SCHED_IDLE, "SCHED_IDLE")
    expect_errno(errno.EINVAL, "FIFO with priority 0", os.sched_setscheduler, 0, os.SCHED_FIFO, os.sched_param(0))
    check(os.sched_rr_get_interval(0) >= 0, "rr interval")
    os.sched_yield()
    return "OTHER/BATCH/IDLE, ranges, EINVAL, rr interval, yield"


@test(serial=True)
def cpu_accounting():
    """CPU time is charged to the thread and process that burned it."""
    c0, w0 = time.process_time(), time.monotonic()
    while time.process_time() - c0 < 0.2:
        check(time.monotonic() - w0 < 10, "process_time never advanced")
    cpu, wall = time.process_time() - c0, time.monotonic() - w0
    check(wall >= cpu * 0.98, f"{cpu:.3f}s cpu in {wall:.3f}s wall")
    with open("/proc/self/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    ticks = int(fields[11]) + int(fields[12])
    check(ticks >= 15, f"/proc/self/stat utime+stime {ticks} ticks after 0.2s of spinning")
    busy = []

    def spin():
        t = time.thread_time()
        while time.thread_time() - t < 0.1:
            pass
        busy.append(time.thread_time())

    th = threading.Thread(target=spin)
    t0 = time.thread_time()
    th.start()
    th.join()
    check(busy and busy[0] >= 0.1, "thread_time in the spinning thread")
    check(time.thread_time() - t0 < 0.05, "the idle main thread was charged the spinner's time")
    def burn():
        while time.process_time() < 0.2:
            pass

    reap(spawn(burn))
    import resource
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    check(ru.ru_utime + ru.ru_stime >= 0.15, f"RUSAGE_CHILDREN {ru.ru_utime:.2f}")
    return f"0.2s cpu took {wall:.2f}s; per-thread and children accounting"
