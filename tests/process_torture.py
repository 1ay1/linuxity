#!/usr/bin/env python3
"""process_torture.py -- every corner of Linux process management, one script.

Runs anywhere Python 3.9+ runs on Linux: natively, in a container, or under
linuxity. Each check runs in its own forked process (own process group, own
deadline), so a hang or a crash fails that check alone and the rest go on.

    python3 process_torture.py            # everything
    python3 process_torture.py -v         # with tracebacks
    python3 process_torture.py fork sig   # checks whose name contains any word
    python3 process_torture.py --list

Exit status: 0 if everything passed (skips are fine), 1 otherwise.
"""
import ctypes
import ctypes.util
import errno
import os
import resource
import select
import signal
import struct
import sys
import tempfile
import threading
import time
import traceback

libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
CHECKS = []
SIGRT = signal.SIGRTMIN


class Skip(Exception):
    pass


def check(fn):
    CHECKS.append(fn)
    return fn


def ok(cond, why):
    if not cond:
        raise AssertionError(why)


def eq(got, want, what):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, want {want!r}")


def child(fn, *a):
    """fork; the child runs fn(*a) and exits with its int result (or 0)."""
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


def status(pid, opts=0):
    _, st = os.waitpid(pid, opts)
    return os.waitstatus_to_exitcode(st)


def wait_until(pred, secs, what):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.005)
    raise AssertionError(f"timed out after {secs}s waiting for {what}")


def proc_state(pid):
    with open(f"/proc/{pid}/stat") as f:
        s = f.read()
    return s[s.rindex(")") + 2]


def prctl(*a):
    a = list(a) + [0] * (5 - len(a))
    r = libc.prctl(*[ctypes.c_ulong(x) for x in a])
    if r < 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    return r


# ---------------------------------------------------------------- fork/exit

@check
def fork_returns_twice_and_pids_differ():
    r, w = os.pipe()
    me = os.getpid()
    pid = child(lambda: os.write(w, struct.pack("ii", os.getpid(), os.getppid())) and 0)
    cpid, cppid = struct.unpack("ii", os.read(r, 8))
    eq(status(pid), 0, "child")
    eq(cpid, pid, "child's getpid == fork's return")
    eq(cppid, me, "child's getppid")
    ok(pid != me, "child pid differs")


@check
def exit_codes_0_to_255():
    for code in (0, 1, 2, 42, 127, 128, 200, 255):
        eq(status(child(lambda c=code: c)), code, f"exit {code}")
    eq(status(child(lambda: 256 + 7)), 7, "exit 263 is 7 (low byte)")


@check
def death_by_each_fatal_signal():
    for sig in (signal.SIGTERM, signal.SIGKILL, signal.SIGINT, signal.SIGUSR1,
                signal.SIGSEGV, signal.SIGABRT, signal.SIGHUP, signal.SIGALRM):
        def die(s=sig):
            prctl(4, 0)                         # no core dump
            signal.signal(s, signal.SIG_DFL) if s not in (signal.SIGKILL,) else None
            os.kill(os.getpid(), s)
            time.sleep(5)
            return 3
        eq(status(child(die)), -sig, f"killed by {signal.Signals(sig).name}")


@check
def zombie_until_reaped():
    pid = child(lambda: 0)
    wait_until(lambda: proc_state(pid) == "Z", 5, "child to become a zombie")
    eq(status(pid), 0, "reaped")
    ok(not os.path.exists(f"/proc/{pid}"), "gone from /proc after reaping")


@check
def many_zombies_reaped_in_any_order():
    kids = {child(lambda c=i: c): i for i in range(200)}
    got = {}
    while len(got) < len(kids):
        pid, st = os.wait()
        got[pid] = os.waitstatus_to_exitcode(st)
    eq(got, kids, "every child's own exit code")
    try:
        os.wait()
        raise AssertionError("wait with no children didn't fail")
    except ChildProcessError:
        pass


@check
def deep_and_wide_fork_tree():
    r, w = os.pipe()
    def node(d):
        if d:
            ks = [child(node, d - 1) for _ in range(3)]
            for k in ks:
                if status(k) != 0:
                    return 1
        os.write(w, b"x")
        return 0
    eq(status(child(node, 4)), 0, "tree")
    os.close(w)
    n = 0
    while (b := os.read(r, 4096)):
        n += len(b)
    eq(n, 1 + 3 + 9 + 27 + 81, "every node reported")


@check
def fork_in_a_threaded_process():
    stop = threading.Event()
    t = threading.Thread(target=lambda: [time.sleep(0.001) for _ in iter(lambda: stop.is_set(), True)])
    t.start()
    try:
        def kid():
            return 0 if threading.active_count() == 1 else 5   # only the forking thread
        for _ in range(20):
            eq(status(child(kid)), 0, "child has one thread")
    finally:
        stop.set(); t.join()


# ---------------------------------------------------------------- wait family

@check
def waitpid_wnohang():
    r, w = os.pipe()
    pid = child(lambda: os.read(r, 1) and 0)
    eq(os.waitpid(pid, os.WNOHANG), (0, 0), "still running")
    os.write(w, b"x")
    eq(status(pid), 0, "then exits")


@check
def waitid_wnowait_then_reap():
    pid = child(lambda: 9)
    info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
    eq((info.si_pid, info.si_status, info.si_code), (pid, 9, os.CLD_EXITED), "peek")
    ok(os.path.exists(f"/proc/{pid}"), "WNOWAIT left the zombie")
    eq(status(pid), 9, "reap")


@check
def wait_for_stop_and_continue():
    pid = child(lambda: time.sleep(10) or 0)
    os.kill(pid, signal.SIGSTOP)
    _, st = os.waitpid(pid, os.WUNTRACED)
    ok(os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGSTOP, f"stopped {st:#x}")
    eq(proc_state(pid), "T", "/proc state while stopped")
    os.kill(pid, signal.SIGCONT)
    _, st = os.waitpid(pid, os.WCONTINUED)
    ok(os.WIFCONTINUED(st), f"continued {st:#x}")
    os.kill(pid, signal.SIGKILL)
    eq(status(pid), -signal.SIGKILL, "killed")


@check
def waitpid_by_process_group():
    a = child(lambda: (os.setpgid(0, 0), time.sleep(0.2), 1)[2])
    os.setpgid(a, a) if os.getpgid(a) != a else None
    b = child(lambda: (time.sleep(0.05), 2)[1])
    pid, st = os.waitpid(-a, 0)          # only a's group
    eq((pid, os.waitstatus_to_exitcode(st)), (a, 1), "wait(-pgid)")
    eq(status(b), 2, "other child")


@check
def wait4_rusage_counts_child_cpu():
    def burn():
        end = time.process_time() + 0.2
        while time.process_time() < end:
            pass
    pid = child(burn)
    _, st, ru = os.wait4(pid, 0)
    eq(os.waitstatus_to_exitcode(st), 0, "child")
    ok(ru.ru_utime + ru.ru_stime >= 0.1, f"rusage cpu {ru.ru_utime + ru.ru_stime:.3f}s")
    cr = resource.getrusage(resource.RUSAGE_CHILDREN)
    # the loop's clock reads are syscalls, so much of it is SYSTEM time
    ok(cr.ru_utime + cr.ru_stime >= 0.1, f"RUSAGE_CHILDREN {cr.ru_utime:.3f}+{cr.ru_stime:.3f}s")


@check
def sigchld_ignored_means_auto_reap():
    def body():
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        pid = child(lambda: 0)
        time.sleep(0.2)
        try:
            os.waitpid(pid, 0)
            return 1
        except ChildProcessError:
            return 0
    eq(status(child(body)), 0, "SIG_IGN SIGCHLD: no zombies, wait is ECHILD")


@check
def sigchld_is_delivered():
    def body():
        got = []
        signal.signal(signal.SIGCHLD, lambda s, f: got.append(s))
        status(child(lambda: 0))
        wait_until(lambda: got, 3, "SIGCHLD")
        return 0
    eq(status(child(body)), 0, "SIGCHLD handler ran")


# ---------------------------------------------------------------- exec

@check
def exec_keeps_pid_and_replaces_image():
    r, w = os.pipe()
    def run():
        os.dup2(w, 1)
        os.execv("/bin/sh", ["sh", "-c", 'echo $$; read c < /proc/$$/comm; echo $c'])
    pid = child(run)
    os.close(w)
    out = b""
    while (b := os.read(r, 100)):
        out += b
    eq(status(pid), 0, "sh")
    lines = out.decode().split()
    eq(int(lines[0]), pid, "pid after exec")
    eq(lines[1], "sh", "comm after exec")


@check
def exec_errors():
    for path, want in (("/nonexistent", errno.ENOENT), ("/etc/passwd", errno.EACCES), ("/", errno.EACCES)):
        def run(p=path):
            try:
                os.execv(p, [p])
            except OSError as e:
                return e.errno
            return 0
        eq(status(child(run)), want, f"execv({path})")


@check
def cloexec_closes_on_exec_only():
    r, w = os.pipe()
    os.set_inheritable(w, True)
    r2, w2 = os.pipe()               # non-inheritable (O_CLOEXEC)
    def run():
        os.execv("/bin/sh", ["sh", "-c", f'[ -e /proc/self/fd/{w} ] && [ ! -e /proc/self/fd/{w2} ]'])
    eq(status(child(run)), 0, "inheritable kept, CLOEXEC closed")


@check
def big_argv_and_env():
    args = ["x" * 50] * 20000
    env = dict(os.environ, BIG="y" * 100000)
    def run():
        os.execve("/bin/sh", ["sh", "-c", '[ $# -eq 20000 ] && [ ${#BIG} -eq 100000 ]', "sh"] + args, env)
    eq(status(child(run)), 0, "20000 args + 100 KB env")


@check
def shebang_scripts():
    path = f"/tmp/pt-script-{os.getpid()}"
    with open(path, "w") as f:
        f.write("#!/bin/sh -e\necho \"$0:$1\"\n")
    os.chmod(path, 0o755)
    try:
        r, w = os.pipe()
        pid = child(lambda: (os.dup2(w, 1), os.execv(path, [path, "arg"])))
        os.close(w)
        eq(os.read(r, 200).decode().strip(), f"{path}:arg", "script output")
        eq(status(pid), 0, "script")
    finally:
        os.unlink(path)


@check
def posix_spawn_many_at_once():
    pids = [os.posix_spawn("/bin/true", ["true"], os.environ) for _ in range(64)]
    for p in pids:
        eq(status(p), 0, "spawned /bin/true")
    p = os.posix_spawnp("sh", ["sh", "-c", "exit 7"], os.environ)
    eq(status(p), 7, "posix_spawnp through PATH")


@check
def vfork_style_spawn_shares_nothing_visible():
    # posix_spawn uses CLONE_VM|CLONE_VFORK in glibc and musl
    marker = [0]
    p = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 3"], os.environ)
    eq(status(p), 3, "exit code through vfork")
    eq(marker[0], 0, "parent memory untouched")


# ---------------------------------------------------------------- signals

@check
def kill_permission_and_existence():
    eq(os.kill(os.getpid(), 0), None, "kill(self, 0)")
    try:
        os.kill(999999, 0)
        raise AssertionError("kill of a missing pid succeeded")
    except ProcessLookupError:
        pass


@check
def handlers_masks_and_pending():
    got = []
    signal.signal(signal.SIGUSR1, lambda s, f: got.append(s))
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    os.kill(os.getpid(), signal.SIGUSR1)
    ok(signal.SIGUSR1 in signal.sigpending(), "pending while blocked")
    eq(got, [], "not delivered while blocked")
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGUSR1})
    wait_until(lambda: got, 2, "delivery on unblock")


@check
def standard_signals_coalesce_realtime_queue():
    # Counted with sigtimedwait: Python's own handlers merge repeated
    # deliveries of one signal into one call, on real Linux too.
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2, SIGRT})
    for _ in range(5):
        os.kill(os.getpid(), signal.SIGUSR2)
        os.kill(os.getpid(), SIGRT)
    got = []
    while (i := signal.sigtimedwait({signal.SIGUSR2, SIGRT}, 0.2)) is not None:
        got.append(i.si_signo)
    eq(got.count(signal.SIGUSR2), 1, "standard signal coalesced")
    eq(got.count(SIGRT), 5, "realtime signal queued")


@check
def sigqueue_carries_a_value():
    class Info(ctypes.Structure):
        _fields_ = [("signo", ctypes.c_int), ("errno", ctypes.c_int), ("code", ctypes.c_int),
                    ("pad", ctypes.c_int), ("pid", ctypes.c_int), ("uid", ctypes.c_uint),
                    ("value", ctypes.c_long), ("rest", ctypes.c_byte * 96)]
    signal.pthread_sigmask(signal.SIG_BLOCK, {SIGRT})
    val = ctypes.c_long(0xBEEF)
    if libc.sigqueue(os.getpid(), int(SIGRT), val) != 0:
        raise Skip(f"sigqueue: {os.strerror(ctypes.get_errno())}")
    info = signal.sigtimedwait({SIGRT}, 2)
    ok(info is not None, "sigtimedwait got it")
    eq(info.si_signo, SIGRT, "signo")
    eq(info.si_pid, os.getpid(), "si_pid")
    eq(info.si_code, -1, "SI_QUEUE")


@check
def sigtimedwait_times_out():
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    t = time.monotonic()
    eq(signal.sigtimedwait({signal.SIGUSR1}, 0.2), None, "nothing arrived")
    ok(0.15 < time.monotonic() - t < 2, "waited about 0.2 s")


@check
def interrupted_syscall_eintr_vs_restart():
    def body(restart):
        signal.signal(signal.SIGALRM, lambda s, f: None)
        signal.siginterrupt(signal.SIGALRM, not restart)
        r, w = os.pipe()
        signal.setitimer(signal.ITIMER_REAL, 0.1)
        if restart:
            threading.Timer(0.3, lambda: os.write(w, b"x")).start()
        try:
            libc.read(r, ctypes.create_string_buffer(1), 1)
            return 0 if restart else (0 if ctypes.get_errno() == errno.EINTR else 4)
        except InterruptedError:
            return 0
    eq(status(child(body, False)), 0, "read interrupted with EINTR")
    eq(status(child(body, True)), 0, "read restarted by SA_RESTART")


@check
def waits_interrupted_even_under_sa_restart():
    # epoll_wait / poll / select are never restarted (signal(7)): EINTR
    # even with SA_RESTART. Called raw, so Python's PEP 475 retry can't hide it.
    def body():
        signal.signal(signal.SIGALRM, lambda s, f: None)
        signal.siginterrupt(signal.SIGALRM, False)
        e = select.epoll()
        r, w = os.pipe()
        e.register(r, select.EPOLLIN)
        buf = ctypes.create_string_buffer(64)
        pfd = (ctypes.c_int * 2)(r, select.POLLIN)
        for name, call in (
                ("epoll_pwait", lambda: libc.epoll_pwait(e.fileno(), buf, 4, 3000, None)),
                ("poll", lambda: libc.poll(pfd, 1, 3000))):
            signal.setitimer(signal.ITIMER_REAL, 0.1)
            t = time.monotonic()
            rc = call()
            if rc != -1 or ctypes.get_errno() != errno.EINTR or time.monotonic() - t > 2:
                os.write(2, f"{name}: rc={rc} errno={ctypes.get_errno()}".encode())
                return 1
        return 0
    eq(status(child(body)), 0, "EINTR from epoll_pwait and poll")


@check
def fifo_hangup_wakes_poll_select_epoll():
    # The last writer closing a FIFO is POLLHUP / readable / EPOLLHUP --
    # and read() then gives EOF. (macOS hosts never report it natively.)
    d = tempfile.mkdtemp()
    path = os.path.join(d, "f")
    os.mkfifo(path)
    def writer():
        w = os.open(path, os.O_WRONLY)
        time.sleep(0.1)
        os.close(w)
        return 0
    def waiter(kind):
        pid = child(writer)
        r = os.open(path, os.O_RDONLY)
        t = time.monotonic()
        if kind == "poll":
            p = select.poll(); p.register(r, select.POLLIN)
            got = p.poll(3000)
            ok(got and got[0][1] & select.POLLHUP, f"poll: {got}")
        elif kind == "select":
            ok(select.select([r], [], [], 3)[0], "select says readable")
        else:
            e = select.epoll(); e.register(r, select.EPOLLIN)
            got = e.poll(3)
            ok(got and got[0][1] & select.EPOLLHUP, f"epoll: {got}")
            e.close()
        ok(time.monotonic() - t < 2, f"{kind} woke promptly")
        eq(os.read(r, 10), b"", f"{kind}: EOF")
        os.close(r)
        eq(status(pid), 0, "writer")
    try:
        for kind in ("poll", "select", "epoll"):
            waiter(kind)
    finally:
        os.unlink(path); os.rmdir(d)


@check
def alarm_and_itimers():
    got = []
    signal.signal(signal.SIGALRM, lambda s, f: got.append(time.monotonic()))
    t = time.monotonic()
    signal.setitimer(signal.ITIMER_REAL, 0.05, 0.05)
    wait_until(lambda: len(got) >= 4, 3, "4 periodic SIGALRMs")
    signal.setitimer(signal.ITIMER_REAL, 0)
    ok(got[-1] - t >= 0.15, "they were periodic, not all at once")


@check
def ping_pong_between_processes():
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    parent = os.getpid()
    def kid():
        for _ in range(200):
            signal.sigwait({signal.SIGUSR1})
            os.kill(parent, signal.SIGUSR1)
        return 0
    pid = child(kid)
    for _ in range(200):
        os.kill(pid, signal.SIGUSR1)
        signal.sigwait({signal.SIGUSR1})
    eq(status(pid), 0, "200 round trips")


@check
def signal_to_a_specific_thread():
    got = []
    signal.signal(signal.SIGUSR1, lambda s, f: got.append(threading.get_ident()))
    ev = threading.Event()
    def t_body():
        ev.wait(2)
    t = threading.Thread(target=t_body)
    t.start()
    signal.pthread_kill(t.ident, signal.SIGUSR1)
    ev.set(); t.join()
    wait_until(lambda: got, 2, "handler")   # Python runs handlers on the main thread


@check
def exec_resets_handlers_keeps_ignored_and_mask():
    def run():
        signal.signal(signal.SIGUSR1, lambda s, f: None)    # caught -> SIG_DFL after exec
        signal.signal(signal.SIGUSR2, signal.SIG_IGN)       # ignored -> stays ignored
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGHUP})
        os.execv("/bin/sh", ["sh", "-c",
                 "g=$(grep ^SigIgn /proc/self/status | cut -f2); b=$(grep ^SigBlk /proc/self/status | cut -f2);"
                 "[ $((0x$g & 0x800)) -ne 0 ] && [ $((0x$g & 0x200)) -eq 0 ] && [ $((0x$b & 0x1)) -ne 0 ]"])
    eq(status(child(run)), 0, "SigIgn has USR2 not USR1; SigBlk has HUP")


@check
def sigkill_and_sigstop_cannot_be_caught():
    for s in (signal.SIGKILL, signal.SIGSTOP):
        try:
            signal.signal(s, signal.SIG_IGN)
            raise AssertionError(f"could set a handler for {s}")
        except OSError as e:
            eq(e.errno, errno.EINVAL, f"signal({signal.Signals(s).name})")


@check
def pdeathsig_fires_when_parent_dies():
    r, w = os.pipe()
    def middle():
        def grandchild():
            prctl(1, signal.SIGUSR1)                         # PR_SET_PDEATHSIG
            signal.signal(signal.SIGUSR1, lambda s, f: (os.write(w, b"D"), os._exit(0)))
            os.write(w, b"R")
            time.sleep(10)
            return 2
        child(grandchild)
        os.read(r, 1)                                         # it's ready
        return 0                                              # and we die
    pid = child(middle)
    eq(status(pid), 0, "middle")
    wait_until(lambda: os.read(r, 1) == b"D", 5, "PDEATHSIG in the orphan")


# ---------------------------------------------------------------- groups, sessions

@check
def setpgid_and_getpgid():
    pid = child(lambda: time.sleep(5) or 0)
    os.setpgid(pid, pid)
    eq(os.getpgid(pid), pid, "child leads its group")
    os.killpg(pid, signal.SIGKILL)
    eq(status(pid), -signal.SIGKILL, "killpg reached it")


@check
def killpg_reaches_every_member():
    def leader():
        os.setpgid(0, 0)
        kids = [child(lambda: time.sleep(10) or 0) for _ in range(5)]
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        os.killpg(os.getpgrp(), signal.SIGTERM)
        return 0 if all(status(k) == -signal.SIGTERM for k in kids) else 1
    eq(status(child(leader)), 0, "5 group members died")


@check
def setsid_makes_a_new_session():
    def body():
        os.setsid()
        return 0 if os.getpid() == os.getsid(0) == os.getpgrp() else 1
    eq(status(child(body)), 0, "session leader of a new session and group")
    try:
        os.setsid()                    # the runner made us a group leader
        raise AssertionError("a group leader could setsid")
    except PermissionError:
        pass


@check
def setpgid_rules():
    def body():
        os.setsid()
        k = child(lambda: (os.setsid(), time.sleep(2), 0)[2])
        time.sleep(0.1)
        try:
            os.setpgid(k, os.getpid())   # a child in ANOTHER session
            return 1
        except PermissionError:
            pass
        os.kill(k, signal.SIGKILL); status(k)
        return 0
    eq(status(child(body)), 0, "setpgid across sessions is EPERM")


# ---------------------------------------------------------------- terminal / job control

@check
def ctrl_c_and_ctrl_z_on_a_pty():
    import pty
    for key, want in ((b"\x03", -signal.SIGINT), (b"\x1c", -signal.SIGQUIT)):
        pid, fd = pty.fork()
        if pid == 0:
            prctl(4, 0)
            os.execv(sys.executable, [sys.executable, "-S", "-c",
                     "import signal,time; signal.signal(signal.SIGINT, signal.SIG_DFL); print('R', flush=True); time.sleep(20)"])
        buf = b""
        while b"R" not in buf:
            buf += os.read(fd, 100)
        os.write(fd, key)
        eq(status(pid), want, f"key {key!r}")


@check
def background_read_gets_sigttin():
    import pty
    pid, fd = pty.fork()
    if pid == 0:
        bg = os.fork()
        if bg == 0:
            os.setpgid(0, 0)
            os.read(0, 1)
            os._exit(0)
        os.setpgid(bg, bg)
        _, st = os.waitpid(bg, os.WUNTRACED)
        ok_ = os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGTTIN
        os.kill(bg, signal.SIGKILL); os.waitpid(bg, 0)
        os._exit(0 if ok_ else 1)
    eq(status(pid), 0, "background reader stopped by SIGTTIN")


# ---------------------------------------------------------------- reparenting

@check
def orphans_go_to_init_or_subreaper():
    def as_subreaper(sub):
        if sub:
            prctl(36, 1)                                      # PR_SET_CHILD_SUBREAPER
        me = os.getpid()
        r, w = os.pipe()
        def middle():
            mid = os.getpid()            # NOT the gc's first getppid: middle may be gone by then
            def gc():
                wait_until(lambda: os.getppid() != mid, 5, "reparenting")
                os.write(w, struct.pack("i", os.getppid()))
            child(gc)
            return 0
        eq(status(child(middle)), 0, "middle")
        os.close(w)                      # a gc that dies early gives EOF, not a hang
        got = os.read(r, 4)
        ok(len(got) == 4, "the orphan reported its new parent")
        new = struct.unpack("i", got)[0]
        if sub:
            eq(new, me, "adopted by the subreaper")
            pid, st = os.waitpid(-1, 0)
            eq(os.waitstatus_to_exitcode(st), 0, "subreaper reaps the orphan")
        else:
            ok(new != me, f"not adopted by its grandparent (went to {new})")
        return 0
    eq(status(child(as_subreaper, True)), 0, "with a subreaper")
    eq(status(child(as_subreaper, False)), 0, "without one")


# ---------------------------------------------------------------- pidfd

@check
def pidfd_poll_and_signal():
    if not hasattr(os, "pidfd_open"):
        raise Skip("no os.pidfd_open")
    pid = child(lambda: time.sleep(10) or 0)
    fd = os.pidfd_open(pid)
    eq(select.select([fd], [], [], 0.1)[0], [], "not readable while alive")
    signal.pidfd_send_signal(fd, signal.SIGTERM)
    ok(select.select([fd], [], [], 5)[0] == [fd], "readable once it exits")
    eq(status(pid), -signal.SIGTERM, "pidfd_send_signal")
    os.close(fd)


@check
def pidfd_on_an_exited_child():
    # a child that exits before pidfd_open (asyncio's watcher racing a
    # quick subprocess): still opens, readable at once; reaped -> ESRCH
    if not hasattr(os, "pidfd_open"):
        raise Skip("no os.pidfd_open")
    pid = child(lambda: 3)
    time.sleep(0.2)
    fd = os.pidfd_open(pid)
    eq(select.select([fd], [], [], 1)[0], [fd], "readable at once")
    eq(status(pid), 3, "the zombie's status")
    os.close(fd)
    try:
        os.close(os.pidfd_open(pid))
        raise AssertionError("pidfd_open of a reaped pid succeeded")
    except ProcessLookupError:
        pass


@check
def pidfd_open_races_quick_children():
    # asyncio's watcher: spawn, then pidfd_open at once. Children that are
    # mid-exit (alive, not yet zombies) at that moment must still open --
    # a window that opens under load, so six spawners run at once.
    if not hasattr(os, "pidfd_open"):
        raise Skip("no os.pidfd_open")
    errors = []

    def spawner(k):
        try:
            for i in range(8):
                pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 3"], os.environ)
                time.sleep(((i + k) % 4) * 0.003)
                fd = os.pidfd_open(pid)
                if select.select([fd], [], [], 5)[0] != [fd]:
                    errors.append(f"spawner {k} child {i}: never readable")
                os.close(fd)
                st = os.waitpid(pid, 0)[1]
                if os.waitstatus_to_exitcode(st) != 3:
                    errors.append(f"spawner {k} child {i}: status {st}")
        except OSError as e:
            errors.append(f"spawner {k}: {e!r}")

    ts = [threading.Thread(target=spawner, args=(k,)) for k in range(6)]
    for t in ts: t.start()
    for t in ts: t.join()
    eq(errors, [], "every pidfd_open of a just-spawned child")


@check
def thread_counts_agree():
    # stat's num_threads, status's Threads and task/ are one count -- python
    # warns on every fork() when stat says more than one
    def counts():
        stat = int(open("/proc/self/stat").read().rsplit(")", 1)[1].split()[17])
        st = [int(l.split()[1]) for l in open("/proc/self/status") if l.startswith("Threads:")][0]
        return stat, st, len(os.listdir("/proc/self/task"))
    def single():
        eq(counts(), (1, 1, 1), "a single-threaded process")
        return 0
    eq(status(child(single)), 0, "in a fresh child")


@check
def another_process_as_ps_sees_it():
    # what ps/top read about a process that is NOT the reader: whose it is
    # (the owner of /proc/<pid>, status Uid/Gid), its threads and memory
    me = os.geteuid()
    want = 65534 if me == 0 else me          # root: the child drops to nobody
    r, w = os.pipe()
    go_r, go_w = os.pipe()

    def body():
        os.close(r); os.close(go_w)
        if me == 0:
            os.setgid(want); os.setuid(want)
        buf = bytearray(8 << 20)              # 8 MiB, touched: resident
        for i in range(0, len(buf), 4096):
            buf[i] = 1
        for _ in range(2):
            threading.Thread(target=os.read, args=(go_r, 1), daemon=True).start()
        time.sleep(0.2)
        os.write(w, b"r")
        os.read(go_r, 1)
        return 0

    pid = child(body)
    os.close(w); os.close(go_r)
    try:
        eq(os.read(r, 1), b"r", "the child is set up")
        st = os.stat(f"/proc/{pid}")
        eq((st.st_uid, st.st_gid), (want, want), "/proc/<pid> is owned by the process")
        if me != 0:
            # (a process that changed credentials is non-dumpable, and Linux
            # gives its files to root -- only the directory says whose it is)
            eq(os.stat(f"/proc/{pid}/status").st_uid, want, "and so are its files")
        f = {l.split(":")[0]: l.split(":", 1)[1].split() for l in open(f"/proc/{pid}/status")}
        eq(int(f["Uid"][1]), want, "status: effective uid")
        eq(int(f["Gid"][1]), want, "status: effective gid")
        eq(int(f["Threads"][0]), 3, "status: its threads, not the runtime's")
        stat = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        eq(int(stat[17]), 3, "stat: num_threads")
        size, res = (int(x) for x in open(f"/proc/{pid}/statm").read().split()[:2])
        ok(res < size, f"resident ({res}) is less than the size ({size}) pages")
        ok(res * os.sysconf("SC_PAGE_SIZE") >= 8 << 20, "the touched 8 MiB are resident")
        eq(len(os.listdir(f"/proc/{pid}/task")), 3, "task/ lists its threads")
    finally:
        os.write(go_w, b"xxx")
        status(pid)


# ---------------------------------------------------------------- identity, /proc

@check
def proc_self_describes_us():
    with open("/proc/self/status") as f:
        st = dict(l.split(":\t", 1) for l in f.read().splitlines() if ":\t" in l)
    eq(int(st["Pid"]), os.getpid(), "Pid")
    eq(int(st["PPid"]), os.getppid(), "PPid")
    eq(os.readlink("/proc/self"), str(os.getpid()), "/proc/self link")
    eq(os.path.realpath("/proc/self/exe"), os.path.realpath(sys.executable), "/proc/self/exe")
    cmd = open("/proc/self/cmdline", "rb").read().split(b"\0")
    ok(any(b"python" in c for c in cmd), f"cmdline {cmd[:2]}")


@check
def proc_lists_children_and_states():
    pid = child(lambda: time.sleep(5) or 0)
    wait_until(lambda: proc_state(pid) in "SR", 2, "sleeping child")
    ok(str(pid) in os.listdir("/proc"), "child listed in /proc")
    with open(f"/proc/{pid}/stat") as f:
        eq(int(f.read().split(")")[1].split()[1]), os.getpid(), "ppid field of /proc/pid/stat")
    os.kill(pid, signal.SIGKILL)
    status(pid)


@check
def thread_names_and_tids():
    prctl(15, ctypes.addressof(name := ctypes.create_string_buffer(b"pt-main")))   # PR_SET_NAME
    eq(open("/proc/self/comm").read().strip(), "pt-main", "PR_SET_NAME -> comm")
    tids = []
    t = threading.Thread(target=lambda: tids.append(threading.get_native_id()))
    t.start(); t.join()
    ok(tids and tids[0] != os.getpid(), "a thread has its own tid")
    ok(os.path.isdir("/proc/self/task"), "/proc/self/task")


# ---------------------------------------------------------------- scheduling, limits

@check
def nice_and_inheritance():
    base = os.nice(0)
    os.nice(3)
    eq(os.getpriority(os.PRIO_PROCESS, 0), base + 3, "nice")
    eq(status(child(lambda: 0 if os.getpriority(os.PRIO_PROCESS, 0) == base + 3 else 1)), 0, "inherited")


@check
def affinity_and_policy():
    cpus = os.sched_getaffinity(0)
    ok(cpus, "some CPU")
    one = {min(cpus)}
    os.sched_setaffinity(0, one)
    eq(os.sched_getaffinity(0), one, "affinity set")
    try:
        eq(os.sched_getscheduler(0), os.SCHED_OTHER, "default policy")
    except OSError as e:
        if e.errno != errno.ENOSYS:
            raise
        raise Skip("libc has no sched_getscheduler (musl)")
    os.sched_yield()


@check
def rlimit_nofile_enforced():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    def body():
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, hard))
        fds = []
        try:
            while True:
                fds.append(os.open("/dev/null", os.O_RDONLY))
        except OSError as e:
            return 0 if e.errno == errno.EMFILE and len(fds) < 32 else 1
    eq(status(child(body)), 0, "EMFILE at the soft limit")


@check
def rlimit_cpu_kills_a_spinner():
    def body():
        resource.setrlimit(resource.RLIMIT_CPU, (1, 2))
        while True:
            pass
    pid = child(body)
    eq(status(pid), -signal.SIGXCPU, "SIGXCPU after 1 s of CPU")


@check
def rlimits_inherit():
    def body():
        resource.setrlimit(resource.RLIMIT_NOFILE, (77, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
        return status(child(lambda: 0 if resource.getrlimit(resource.RLIMIT_NOFILE)[0] == 77 else 1))
    eq(status(child(body)), 0, "child sees the limit")


# ---------------------------------------------------------------- stress

@check
def fork_storm_concurrent():
    pids = []
    for _ in range(100):
        try:
            pids.append(child(lambda: (time.sleep(0.2), 0)[1]))
        except BlockingIOError:
            break                                            # EAGAIN is a fair answer
    ok(len(pids) >= 50, f"only {len(pids)} concurrent children")
    eq(sorted(status(p) for p in pids), [0] * len(pids), "all exited cleanly")


@check
def shell_pipelines_and_subshells():
    pid = child(lambda: os.execv("/bin/sh", ["sh", "-c",
        "n=$(seq 1 2000 | awk '{s+=$1} END {print s}'); [ $n -eq 2001000 ] && "
        "x=$( (exit 3); echo $?) && [ $x -eq 3 ] && "
        "i=0; while [ $i -lt 30 ]; do ( : ) & i=$((i+1)); done; wait"]))
    eq(status(pid), 0, "pipelines, $(), subshells, 30 background jobs")


@check
def exec_storm():
    for _ in range(50):
        eq(status(child(lambda: os.execv("/bin/true", ["true"]))), 0, "exec /bin/true")


# ---------------------------------------------------------------- runner

def run_one(fn, timeout):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.setpgid(0, 0)
        for s in signal.valid_signals():
            if s not in (signal.SIGKILL, signal.SIGSTOP):
                try:
                    signal.signal(s, signal.SIG_DFL)
                except (OSError, ValueError):
                    pass
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        os.dup2(w, 2)
        try:
            fn()
            os._exit(0)
        except Skip as e:
            os.write(2, f"SKIP:{e}".encode()); os._exit(77)
        except BaseException:
            os.write(2, traceback.format_exc().encode()); os._exit(1)
    os.close(w)
    end = time.monotonic() + timeout
    out = b""
    while True:
        done, st = os.waitpid(pid, os.WNOHANG)
        if select.select([r], [], [], 0.05)[0]:
            b = os.read(r, 65536)
            out += b
        if done:
            while (b := os.read(r, 65536)):
                out += b
            break
        if time.monotonic() > end:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            return "FAIL", f"timed out after {timeout}s"
    try:
        os.killpg(pid, signal.SIGKILL)              # stragglers
    except (ProcessLookupError, PermissionError):
        pass
    os.close(r)
    code = os.waitstatus_to_exitcode(st)
    text = out.decode(errors="replace").strip()
    if code == 0:
        return "PASS", ""
    if code == 77:
        return "SKIP", text.replace("SKIP:", "")
    last = text.splitlines()[-1] if text else f"exit {code}"
    return "FAIL", (text if VERBOSE else last)


VERBOSE = False


def main(argv):
    global VERBOSE
    VERBOSE = "-v" in argv
    words = [a for a in argv if not a.startswith("-")]
    chosen = [c for c in CHECKS if not words or any(w in c.__name__ for w in words)]
    if "--list" in argv:
        for c in chosen:
            print(f"{c.__name__:45} {(c.__doc__ or '').strip()}")
        return 0
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    t0 = time.monotonic()
    for c in chosen:
        t = time.monotonic()
        res, why = run_one(c, 20)
        counts[res] += 1
        print(f"  {res}  {c.__name__:45} {time.monotonic() - t:6.2f}s  {why if res != 'PASS' else ''}"[:220 if not VERBOSE else None],
              flush=True)
    print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped "
          f"of {len(chosen)} in {time.monotonic() - t0:.1f}s")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
