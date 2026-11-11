"""torture.py -- the harness every *_torture.py suite shares.

A suite is a list of @check functions. Each runs in its own forked process,
in its own process group, in a fresh scratch directory, with default signal
dispositions and an empty signal mask, under a deadline -- so a hang, a
crash or a stray signal fails that one check and the rest go on.

    python3 some_torture.py              # everything
    python3 some_torture.py -v           # full tracebacks
    python3 some_torture.py word ...     # checks whose name contains a word
    python3 some_torture.py --list
    python3 some_torture.py --dir=/path  # scratch somewhere else

Exit status 0 when nothing failed (skips are fine), 1 otherwise. The last
line is always "N passed, M failed, K skipped of T in S s", which oracle.py
parses.
"""
import ctypes
import ctypes.util
import errno
import os
import select
import shutil
import signal
import sys
import tempfile
import time
import traceback

libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
libc.syscall.restype = ctypes.c_long
ROOT = os.geteuid() == 0
ARCH = os.uname().machine
CHECKS = []
VERBOSE = False


class Skip(Exception):
    """Raise to report a check that cannot run here (and why)."""


def check(fn=None, *, timeout=30):
    def add(f):
        f.timeout = timeout
        CHECKS.append(f)
        return f
    return add(fn) if fn else add


def ok(cond, why):
    if not cond:
        raise AssertionError(why)


def eq(got, want, what):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, want {want!r}")


def errname(e):
    return errno.errorcode.get(e, str(e)) if e else "success"


def expect_errno(want, what, fn, *a, **k):
    wants = want if isinstance(want, tuple) else (want,)
    try:
        fn(*a, **k)
        got = 0
    except OSError as e:
        got = e.errno
    if got not in wants:
        raise AssertionError(f"{what}: got {errname(got)}, want {'/'.join(map(errname, wants))}")


def need_root():
    if not ROOT:
        raise Skip("needs root")


def child(fn, *a):
    """fork; the child runs fn(*a) and exits with its int result (or 0, or
    99 after printing a traceback)."""
    sys.stdout.flush(); sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            r = fn(*a)
            code = r if isinstance(r, int) else 0
        except BaseException:
            traceback.print_exc()
            code = 99
        os._exit(code)
    return pid


def status(pid):
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)


def run_in_child(fn, *a):
    """child() + status(): fn's exit code, -signal if it died of one."""
    return status(child(fn, *a))


def wait_until(cond, secs, what):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if cond():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out after {secs}s waiting for {what}")


def sh(cmd, timeout=60, **kw):
    """Run a shell command; (returncode, stdout, stderr) as text."""
    import subprocess
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, **kw)
    return r.returncode, r.stdout, r.stderr


def have(prog):
    return shutil.which(prog) is not None


def _reset_process_state():
    for s in signal.valid_signals():
        if s not in (signal.SIGKILL, signal.SIGSTOP):
            try:
                signal.signal(s, signal.SIG_DFL)
            except (OSError, ValueError):
                pass
    signal.pthread_sigmask(signal.SIG_SETMASK, set())
    os.umask(0o022)


def run_one(fn, base):
    scratch = tempfile.mkdtemp(prefix=f"t-{fn.__name__[:24]}-", dir=base)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.setpgid(0, 0)
        os.dup2(w, 2)
        os.chdir(scratch)
        _reset_process_state()
        try:
            fn()
            os._exit(0)
        except Skip as e:
            os.write(2, f"SKIP:{e}".encode()); os._exit(77)
        except BaseException:
            os.write(2, traceback.format_exc().encode()); os._exit(1)
    os.close(w)
    end = time.monotonic() + fn.timeout
    out, res, st = b"", None, 0
    while True:
        done, st = os.waitpid(pid, os.WNOHANG)
        if select.select([r], [], [], 0.05)[0]:
            out += os.read(r, 65536)
        if done:
            os.set_blocking(r, False)
            try:
                while (b := os.read(r, 65536)):
                    out += b
            except BlockingIOError:
                pass                        # a grandchild still holds the pipe
            break
        if time.monotonic() > end:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            res = ("FAIL", f"timed out after {fn.timeout}s")
            break
    try:
        os.killpg(pid, signal.SIGKILL)      # stragglers
    except (ProcessLookupError, PermissionError):
        pass
    os.close(r)
    for root, dirs, _ in os.walk(scratch):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), 0o700)
            except OSError:
                pass
    shutil.rmtree(scratch, ignore_errors=True)
    if res:
        return res
    code = os.waitstatus_to_exitcode(st)
    text = out.decode(errors="replace").strip()
    if code == 0:
        return "PASS", ""
    if code == 77:
        return "SKIP", text.replace("SKIP:", "")
    if code < 0:
        return "FAIL", f"died of signal {-code} ({signal.Signals(-code).name})\n{text}".strip()
    lines = [l for l in text.splitlines() if "DeprecationWarning" not in l and "os.fork()" not in l]
    last = lines[-1] if lines else f"exit {code}"
    return "FAIL", (text if VERBOSE else last)


def main(title, argv=None):
    global VERBOSE
    argv = sys.argv[1:] if argv is None else argv
    VERBOSE = "-v" in argv
    base = next((a.split("=", 1)[1] for a in argv if a.startswith("--dir=")), tempfile.gettempdir())
    words = [a for a in argv if not a.startswith("-")]
    chosen = [c for c in CHECKS if not words or any(w in c.__name__ for w in words)]
    if "--list" in argv:
        for c in chosen:
            print(c.__name__)
        return 0
    who = "root" if ROOT else f"uid {os.getuid()}"
    print(f"  {title}: {len(chosen)} checks, scratch in {base}, {who}", flush=True)
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    t0 = time.monotonic()
    for c in chosen:
        t = time.monotonic()
        res, why = run_one(c, base)
        counts[res] += 1
        line = f"  {res}  {c.__name__:42} {time.monotonic() - t:6.2f}s  {why if res != 'PASS' else ''}"
        print(line if VERBOSE else line[:260], flush=True)
    print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped "
          f"of {len(chosen)} in {time.monotonic() - t0:.1f}s", flush=True)
    return 1 if counts["FAIL"] else 0
