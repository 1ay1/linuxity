"""lxt: a small test framework for checking that an environment behaves like Linux.

Tests are plain functions registered with @test. Each one runs in its own
forked process group with a deadline (see run.py), so a hang, a crash or a
leaked child in one test can't take the others down.

A test passes by returning (optionally a one-line summary), fails by raising,
and skips by calling skip(). Helpers here are what the tests share.
"""
import ctypes
import errno
import os
import platform
import resource
import select
import shutil
import signal
import subprocess
import sys
import time

__all__ = [
    "test", "Skip", "skip", "check", "eq", "expect_errno", "spawn", "reap",
    "reap_within", "must", "read_exact", "napper", "no_core", "proc_status",
    "wait_until", "sh", "need_cmd", "libc", "syscall", "SYS", "ENV", "REGISTRY",
]


# ------------------------------------------------------------------ registry

class Case:
    def __init__(self, fn, timeout, serial, host, root, note):
        mod = fn.__module__.split(".")
        self.fn = fn
        self.area = mod[0] if len(mod) > 1 else "misc"
        self.module = mod[-1]
        self.name = fn.__name__
        self.id = f"{self.area}/{self.module}:{self.name}"
        self.timeout = timeout
        self.serial = serial      # timing-sensitive: run with nothing beside it
        self.host = host          # answers about the HOST kernel, not this one
        self.root = root          # needs uid 0 (skipped otherwise)
        self.note = note
        self.doc = (fn.__doc__ or "").strip().splitlines()[0] if fn.__doc__ else ""


REGISTRY = []


def test(fn=None, *, timeout=60, serial=False, host=False, root=False, note=""):
    """Register a test. host=True marks a result that reflects the host
    kernel's abilities rather than the environment's own (see ENV)."""
    def wrap(f):
        REGISTRY.append(Case(f, timeout, serial, host, root, note))
        return f
    return wrap(fn) if fn else wrap


class Skip(Exception):
    pass


def skip(why):
    raise Skip(why)


# -------------------------------------------------------------- assertions

def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def eq(got, want, what):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, want {want!r}")


def expect_errno(codes, label, fn, *a, **kw):
    """fn(*a) must fail with one of `codes` (an errno or a tuple of them)."""
    codes = codes if isinstance(codes, tuple) else (codes,)
    want = "/".join(errno.errorcode.get(c, str(c)) for c in codes)
    try:
        fn(*a, **kw)
    except OSError as e:
        if e.errno in codes:
            return e
        raise AssertionError(
            f"{label}: got {errno.errorcode.get(e.errno, e.errno)}, want {want}") from None
    raise AssertionError(f"{label}: succeeded, want {want}")


def wait_until(pred, timeout, what, step=0.002):
    """Poll pred() until true; fail after `timeout` seconds."""
    end = time.monotonic() + timeout
    while True:
        v = pred()
        if v:
            return v
        if time.monotonic() > end:
            raise AssertionError(f"timed out after {timeout}s waiting for {what}")
        time.sleep(step)


# --------------------------------------------------------------- processes

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
            try:
                print(f"    ! child {getattr(fn, '__name__', fn)}: {type(e).__name__}: {e}",
                      file=sys.stderr, flush=True)
            except BaseException:
                pass
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
    """Reap pid, SIGKILLing it if it is still running after `secs`."""
    end = time.monotonic() + secs
    while True:
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            return os.waitstatus_to_exitcode(st)
        if time.monotonic() > end:
            os.kill(pid, signal.SIGKILL)
            reap(pid)
            raise AssertionError(f"pid {pid} still running after {secs}s")
        time.sleep(0.002)


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
    """Crash quietly: no core file, no systemd-coredump run."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc.prctl(4, 0, 0, 0, 0)   # PR_SET_DUMPABLE 0


def proc_status(pid="self"):
    with open(f"/proc/{pid}/status") as f:
        return dict(l.rstrip("\n").split(":\t", 1) for l in f if ":\t" in l)


# ------------------------------------------------------------------- tools

def need_cmd(*names):
    for n in names:
        if shutil.which(n) is None:
            skip(f"{n} not installed")


def sh(cmd, timeout=30, input=None, check_rc=None):
    """Run a /bin/sh command line; returns CompletedProcess (text mode)."""
    r = subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True,
                       timeout=timeout, input=input)
    if check_rc is not None and r.returncode != check_rc:
        raise AssertionError(f"`{cmd}` exited {r.returncode}, want {check_rc}: {r.stderr.strip()[-300:]}")
    return r


# --------------------------------------------------------- raw syscalls

libc = ctypes.CDLL(None, use_errno=True)
_syscall = libc.syscall
_syscall.restype = ctypes.c_long

# Numbers that differ between the two ABIs we run on; the newer ones are
# shared (the "generic" table starts at 424 on both).
SYS = {
    "x86_64": dict(getpid=39, gettid=186, getppid=110, capget=125, sethostname=170,
                   unshare=272, io_uring_setup=425, io_uring_enter=426, signalfd4=289,
                   pidfd_open=434, clone3=435, close_range=436, getrandom=318,
                   membarrier=324, rseq=334, prctl=157, seccomp=317, openat2=437,
                   pivot_root=155, bad=1023),
    "aarch64": dict(getpid=172, gettid=178, getppid=173, capget=90, sethostname=161,
                    unshare=97, io_uring_setup=425, io_uring_enter=426, signalfd4=74,
                    pidfd_open=434, clone3=435, close_range=436, getrandom=278,
                    membarrier=283, rseq=293, prctl=167, seccomp=277, openat2=437,
                    pivot_root=41, bad=1023),
}.get(platform.machine(), {})


def syscall(name, *args):
    """Raw syscall by name; returns the result or raises OSError."""
    if name not in SYS:
        skip(f"no syscall number for {name} on {platform.machine()}")
    cargs = [ctypes.c_long(a) if isinstance(a, int) else a for a in args]
    r = _syscall(ctypes.c_long(SYS[name]), *cargs)
    if r == -1:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


# ------------------------------------------------------------ environment

def _detect():
    u = os.uname()
    env = {"kernel": f"{u.sysname} {u.release}", "machine": u.machine,
           "python": sys.version.split()[0], "cpus": os.cpu_count(),
           "uid": os.getuid(), "kind": "native"}
    try:
        status = proc_status()
    except OSError:
        status = {}
    tracer = status.get("TracerPid", "0").strip()
    if "linuxity" in u.release:
        env["kind"] = "linuxity"
    elif os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        env["kind"] = "container"
    elif tracer not in ("", "0"):
        env["kind"] = "ptraced (proot-like)"
    else:
        try:
            if os.stat("/").st_ino != os.stat("/proc/1/root/.").st_ino:
                env["kind"] = "chroot"
        except OSError:
            pass
    # Anything but bare metal/VM runs on someone else's kernel: what those
    # tests report is the host's ability, passed through.
    env["host_kernel"] = env["kind"] != "native"
    return env


ENV = _detect()
