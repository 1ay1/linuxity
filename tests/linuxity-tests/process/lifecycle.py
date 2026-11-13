"""The parts of the process lifecycle other modules don't pin down: zombies
seen from /proc, SIGCHLD's details, kill permission, strict seccomp and
rlimit raises. Each was a real difference from Linux."""
import ctypes
import os
import resource
import signal
import time

from lxt import check, eq, expect_errno, libc, reap, skip, spawn, test, wait_until
import errno


def proc_state(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
    except FileNotFoundError:
        return None
    return s[s.rindex(")") + 2]


@test
def zombie_seen_until_reaped():
    """An exited child is Z in /proc and listed until its parent waits."""
    pid = spawn(lambda: 0)
    wait_until(lambda: proc_state(pid) == "Z", 5, "the child to be a zombie")
    check(str(pid) in os.listdir("/proc"), "a zombie is listed in /proc")
    eq(reap(pid), 0, "exit code")
    check(proc_state(pid) is None, "gone from /proc once reaped")
    return "Z, listed, gone"


@test
def waitid_wnowait_leaves_the_zombie():
    """waitid(WNOWAIT) reports the child and leaves it to be reaped."""
    pid = spawn(lambda: 7)
    r = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
    eq((r.si_pid, r.si_status), (pid, 7), "WNOWAIT result")
    eq(proc_state(pid), "Z", "still a zombie")
    eq(os.waitid(os.P_PID, pid, os.WEXITED).si_status, 7, "then reaped")
    check(proc_state(pid) is None, "gone")
    return "peek, then reap"


@test
def sigchld_names_the_child():
    """SIGCHLD read with sigtimedwait carries the child's pid and status."""
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
    pid = spawn(lambda: 9)
    info = signal.sigtimedwait({signal.SIGCHLD}, 5)
    check(info is not None, "SIGCHLD arrived")
    eq((info.si_pid, info.si_status, info.si_code), (pid, 9, 1), "si_pid, si_status, CLD_EXITED")
    eq(reap(pid), 9, "reaped")
    return "pid, status, code"


@test
def kill_needs_permission():
    """An ordinary user can't signal another user's process: EPERM."""
    if os.getuid() == 0:
        skip("needs an ordinary user")
    if os.stat("/proc/1").st_uid == os.getuid():
        skip("pid 1 is ours here")
    expect_errno(errno.EPERM, "kill(1, 0)", os.kill, 1, 0)
    expect_errno(errno.ESRCH, "kill of a pid nobody has", os.kill, 2**30, 0)
    return "EPERM, ESRCH"


@test
def strict_seccomp_kills():
    """SECCOMP_MODE_STRICT: write works, anything else is SIGKILL."""
    exit_nr = 60 if os.uname().machine == "x86_64" else 93   # before: uname is a syscall

    def strict(then):
        r, w = os.pipe()
        if libc.prctl(22, 1, 0, 0, 0) != 0:
            return 2
        os.write(w, b"x")
        if then:
            os.getpid()
        # exit(2) itself: os._exit is exit_group, which strict mode kills
        libc.syscall(exit_nr, 0)
    eq(reap(spawn(strict, False)), 0, "write and exit are allowed")
    eq(reap(spawn(strict, True)), -signal.SIGKILL, "getpid is fatal")
    return "write ok, getpid killed"


@test
def exe_link_is_the_real_file():
    """/proc/self/exe names the file the kernel ran: symlinks resolved."""
    import subprocess, tempfile
    d = tempfile.mkdtemp()
    real = os.path.realpath("/bin/sh")
    os.symlink("/bin/sh", os.path.join(d, "link"))
    out = subprocess.run([os.path.join(d, "link"), "-c", "readlink /proc/$$/exe; true"],
                         capture_output=True, text=True).stdout.strip()
    eq(out, real, "exe after exec through a symlink")
    eq(os.readlink("/proc/self/exe"), os.path.realpath(os.readlink("/proc/self/exe")), "ours is canonical")
    return real


@test
def hard_limit_raise():
    """Only root may raise a hard rlimit once it's lowered."""
    def body():
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 256))
        except (ValueError, OSError):
            return 0 if os.geteuid() != 0 else 1
        if os.geteuid() != 0:
            return 1
        return 0 if resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 256) else 3
    eq(reap(spawn(body)), 0, "raise allowed for root only, and read back")
    return "root raises, users can't"
