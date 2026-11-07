"""Syscall contracts: the errno a program gets back is part of the ABI."""
import ctypes
import errno
import os
import resource
import time

from lxt import ENV, SYS, check, eq, expect_errno, libc, skip, spawn, reap, syscall, test


@test
def errno_contracts():
    """The kernel's error answers for the common misuses."""
    fd = os.open("/dev/null", os.O_RDONLY)
    os.close(fd)
    expect_errno(errno.EBADF, "read on a closed fd", os.read, fd, 1)
    expect_errno(errno.EBADF, "close twice", os.close, fd)
    expect_errno(errno.ENOENT, "open a missing file", os.open, "nope/nope", os.O_RDONLY)
    expect_errno(errno.ENOTDIR, "path through a file", os.stat, "/dev/null/x")
    expect_errno(errno.EISDIR, "write-open a directory", os.open, ".", os.O_WRONLY)
    expect_errno(errno.ENOTDIR, "O_DIRECTORY on a file", os.open, "/dev/null", os.O_RDONLY | os.O_DIRECTORY)
    expect_errno(errno.EINVAL, "lseek negative", os.lseek,
                 os.open("seekme", os.O_RDWR | os.O_CREAT, 0o644), -1, os.SEEK_SET)
    r, w = os.pipe()
    expect_errno(errno.ESPIPE, "lseek on a pipe", os.lseek, r, 0, os.SEEK_SET)
    expect_errno(errno.EBADF, "write to a pipe's read end", os.write, r, b"x")
    expect_errno(errno.ECHILD, "wait with no children", os.wait)
    expect_errno(errno.ESRCH, "kill a pid that doesn't exist", os.kill, 4_000_000, 0)
    expect_errno(errno.EINVAL, "kill with a bad signal", os.kill, os.getpid(), 1000)
    libc.syscall.restype = ctypes.c_long
    # EFAULT: the kernel checks user pointers rather than crashing
    r2 = libc.syscall(SYS.get("getrandom", 318), ctypes.c_void_p(8), 16, 0)
    eq((r2, ctypes.get_errno()), (-1, errno.EFAULT), "getrandom into a bad pointer")
    rc = libc.write(w, ctypes.c_void_p(8), 16)
    eq((rc, ctypes.get_errno()), (-1, errno.EFAULT), "write from a bad pointer")
    expect_errno(errno.ENOSYS, "a syscall number that doesn't exist", syscall, "bad")
    return "EBADF ENOENT ENOTDIR EISDIR EINVAL ESPIPE ECHILD ESRCH EFAULT ENOSYS"


@test
def identity_and_uname():
    """Raw getpid/gettid/getppid match libc, and uname matches /proc."""
    eq(syscall("getpid"), os.getpid(), "raw getpid")
    eq(syscall("gettid"), os.getpid(), "raw gettid in the main thread")
    eq(syscall("getppid"), os.getppid(), "raw getppid")
    u = os.uname()
    with open("/proc/sys/kernel/ostype") as f:
        eq(f.read().strip(), u.sysname, "ostype vs uname")
    check(u.machine in ("x86_64", "aarch64"), f"machine {u.machine}")
    me = os.getpid()
    pid = spawn(lambda: 0 if syscall("getppid") == me else 1)
    eq(reap(pid), 0, "child's raw getppid")
    return f"{u.sysname} {u.release} {u.machine}"


@test
def randomness():
    """getrandom and /dev/urandom give fresh bytes, and GRND_NONBLOCK works."""
    a, b = os.getrandom(64), os.getrandom(64)
    check(a != b, "getrandom repeated itself")
    check(len(os.getrandom(32, os.GRND_NONBLOCK)) == 32, "GRND_NONBLOCK")
    with open("/dev/urandom", "rb") as f:
        x, y = f.read(4096), f.read(4096)
    check(x != y and len(set(x)) > 200, "urandom looks wrong")
    with open("/dev/random", "rb") as f:
        check(len(f.read(16)) == 16, "/dev/random")
    with open("/dev/zero", "rb") as f:
        eq(f.read(8192), bytes(8192), "/dev/zero")
    try:
        f = open("/dev/full", "wb", buffering=0)
    except PermissionError:
        # Android's SELinux won't let an app open it; only on someone else's kernel
        if not ENV["host_kernel"]:
            raise
        return "getrandom, urandom, random, zero; full refused by the host [host]"
    with f:
        expect_errno(errno.ENOSPC, "write to /dev/full", f.write, b"x")
    return "getrandom, urandom, random, zero, full"


@test
def prctl_and_limits():
    """prctl state and rlimits round-trip, and children inherit them."""
    buf = ctypes.create_string_buffer(16)
    check(libc.prctl(15, b"lxt-renamed", 0, 0, 0) == 0, "PR_SET_NAME")
    check(libc.prctl(16, buf, 0, 0, 0) == 0, "PR_GET_NAME")
    eq(buf.value, b"lxt-renamed", "PR_GET_NAME")
    with open("/proc/self/comm") as f:
        eq(f.read().strip(), "lxt-renamed", "comm after PR_SET_NAME")
    check(libc.prctl(1, 9, 0, 0, 0) == 0, "PR_SET_PDEATHSIG")
    v = ctypes.c_int()
    check(libc.prctl(2, ctypes.byref(v), 0, 0, 0) == 0 and v.value == 9, "PR_GET_PDEATHSIG")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    new = min(hard, 1000)
    resource.setrlimit(resource.RLIMIT_NOFILE, (new, hard))
    eq(resource.getrlimit(resource.RLIMIT_NOFILE), (new, hard), "NOFILE round trip")
    pid = spawn(lambda: 0 if resource.getrlimit(resource.RLIMIT_NOFILE) == (new, hard) else 1)
    eq(reap(pid), 0, "child inherits RLIMIT_NOFILE")
    eq(resource.prlimit(0, resource.RLIMIT_NOFILE), (new, hard), "prlimit(0)")
    ru = resource.getrusage(resource.RUSAGE_SELF)
    check(ru.ru_maxrss > 0, "getrusage maxrss")
    return "PR_SET/GET_NAME, PDEATHSIG, rlimits inherit, getrusage"


@test
def clocks_and_timers():
    """The clocks a program sees are consistent with each other."""
    for c in (time.CLOCK_REALTIME, time.CLOCK_MONOTONIC, time.CLOCK_BOOTTIME,
              time.CLOCK_PROCESS_CPUTIME_ID, time.CLOCK_THREAD_CPUTIME_ID,
              getattr(time, "CLOCK_MONOTONIC_RAW", 4), 5, 6):   # 5/6: *_COARSE
        t = time.clock_gettime(c)
        check(t >= 0, f"clock {c} gave {t}")
        check(time.clock_getres(c) > 0, f"clock {c} resolution")
    m = time.clock_gettime(time.CLOCK_MONOTONIC)
    check(time.clock_gettime(time.CLOCK_BOOTTIME) >= m - 0.001, "BOOTTIME behind MONOTONIC")
    check(abs(time.time() - time.clock_gettime(time.CLOCK_REALTIME)) < 0.1, "time() vs REALTIME")
    expect_errno(errno.EINVAL, "an invalid clock id", time.clock_gettime, 9999)
    t0 = time.monotonic()
    time.sleep(0.05)
    dt = time.monotonic() - t0
    check(0.05 <= dt < 0.5, f"sleep(0.05) took {dt:.3f}s")
    return "realtime/monotonic/boottime/cputime/raw/coarse, EINVAL, sleep"


@test
def close_range_and_dup():
    """close_range, dup3 and F_DUPFD_CLOEXEC follow the kernel's rules."""
    fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(10)]
    lo, hi = fds[2], fds[7]
    try:
        syscall("close_range", lo, hi, 0)
    except OSError as e:
        if e.errno == errno.ENOSYS:
            skip("close_range missing (kernel < 5.9)")
        raise
    for f in fds:
        alive = True
        try:
            os.fstat(f)
        except OSError:
            alive = False
        eq(alive, not (lo <= f <= hi), f"fd {f} after close_range({lo},{hi})")
    a = fds[0]
    import fcntl
    b = fcntl.fcntl(a, fcntl.F_DUPFD_CLOEXEC, 100)
    check(b >= 100 and fcntl.fcntl(b, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, "F_DUPFD_CLOEXEC")
    c = os.dup2(a, 200, inheritable=False)
    check(c == 200 and not os.get_inheritable(200), "dup3 with O_CLOEXEC")
    eq(os.dup2(a, a), a, "dup2 onto itself is a no-op")
    return "close_range, F_DUPFD_CLOEXEC, dup3, dup2 self"
