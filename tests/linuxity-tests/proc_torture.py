#!/usr/bin/env python3
"""proc_torture.py - deep checks of the Linux process model.

  python3 proc_torture.py            all tests
  python3 proc_torture.py -v         with tracebacks for failures
  python3 proc_torture.py zombie pg  only tests whose name contains a word

Each test runs in its own forked process group with a deadline, inside a
fresh temp dir that is removed afterwards. Everything here passes on real
Linux, so any failure is a difference from Linux.
"""
import ctypes, os, resource, select, shutil, signal, subprocess, sys
import tempfile, threading, time, traceback

libc = ctypes.CDLL(None, use_errno=True)
libc.sigqueue.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
TIMEOUT = 30
TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


class Skip(Exception):
    pass


def eq(got, want, what):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, want {want!r}")


def ok(cond, what):
    if not cond:
        raise AssertionError(what)


def wait_until(pred, timeout, what):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


def child(fn):
    """fork; the child runs fn and exits with its int result (0 if None)."""
    pid = os.fork()
    if pid == 0:
        try:
            r = fn()
            os._exit(r if isinstance(r, int) else 0)
        except BaseException:
            traceback.print_exc()
            os._exit(99)
    return pid


def status(pid):
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)


def proc_state(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
    except FileNotFoundError:
        return None
    return s[s.rindex(")") + 2]


def proc_status(pid="self"):
    out = {}
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            k, _, v = line.partition(":")
            out[k] = v.strip()
    return out


def sh_output(script, env=None):
    """exec /bin/sh -c script in a child, return its stdout."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(w, 1)
        os.execve("/bin/sh", ["sh", "-c", script], env or dict(os.environ))
    os.close(w)
    out = b""
    while chunk := os.read(r, 65536):
        out += chunk
    os.close(r)
    eq(status(pid), 0, f"sh -c {script!r}")
    return out.decode()


# ------------------------------------------------------------ fork / exit / wait

@test
def exit_codes():
    for code in (0, 1, 42, 127, 255):
        eq(status(child(lambda c=code: c)), code, f"exit {code}")
    eq(status(child(lambda: os._exit(256))), 0, "exit 256 wraps to 0")
    return "0 1 42 127 255, 256 -> 0"


@test
def fork_tree():
    r, w = os.pipe()

    def node(depth):
        if depth:
            kids = [child(lambda d=depth: node(d - 1)) for _ in range(4)]
            for k in kids:
                if status(k) != 0:
                    return 1
        os.write(w, b"x")
        return 0

    eq(status(child(lambda: node(4))), 0, "tree exit")
    os.close(w)
    n = 0
    while b := os.read(r, 4096):
        n += len(b)
    eq(n, 341, "processes that reported in")
    return "341 processes, 4 levels"


@test
def wait_in_any_order():
    kids = {child(lambda c=i: c % 256): i % 256 for i in range(150)}
    got = {}
    while len(got) < len(kids):
        pid, st = os.wait()
        got[pid] = os.waitstatus_to_exitcode(st)
    eq(got, kids, "each child's own code")
    try:
        os.wait()
        raise AssertionError("wait with no children succeeded")
    except ChildProcessError:
        pass
    return "150 children, ECHILD after"


@test
def waitpid_variants():
    pid = child(lambda: time.sleep(30))
    eq(os.waitpid(pid, os.WNOHANG), (0, 0), "WNOHANG on a live child")
    os.kill(pid, signal.SIGKILL)
    eq(status(pid), -9, "killed")
    try:
        os.waitpid(1, 0)
        raise AssertionError("waitpid on a non-child succeeded")
    except ChildProcessError:
        pass
    # wait by process group
    os.setpgid(0, 0)
    kid = child(lambda: 5)
    p, st = os.waitpid(-os.getpgrp(), 0)
    eq((p, os.waitstatus_to_exitcode(st)), (kid, 5), "waitpid(-pgid)")
    # rusage from wait4
    kid = child(lambda: sum(range(3_000_000)) and 0)
    p, st, ru = os.wait4(kid, 0)
    ok(ru.ru_utime + ru.ru_stime > 0, "wait4 reports cpu time")
    return "WNOHANG, ECHILD, by group, wait4"


@test
def zombie_until_reaped():
    pid = child(lambda: 0)
    wait_until(lambda: proc_state(pid) == "Z", 5, "zombie state")
    ok(str(pid) in os.listdir("/proc"), "zombie listed in /proc")
    eq(status(pid), 0, "reaped")
    ok(not os.path.exists(f"/proc/{pid}"), "gone after reaping")
    return "Z, listed, gone"


@test
def waitid_wnowait():
    pid = child(lambda: 7)
    r = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
    eq((r.si_pid, r.si_status), (pid, 7), "WNOWAIT result")
    eq(proc_state(pid), "Z", "still a zombie after WNOWAIT")
    r = os.waitid(os.P_PID, pid, os.WEXITED)
    eq(r.si_status, 7, "reaped by waitid")
    ok(proc_state(pid) is None, "gone")
    return "peek then reap"


@test
def many_alive_at_once():
    kids = [child(lambda: time.sleep(30)) for _ in range(200)]
    listed = set(os.listdir("/proc"))
    ok(all(str(k) in listed for k in kids), "all 200 in /proc")
    eq(len(set(kids)), 200, "distinct pids")
    for k in kids:
        os.kill(k, signal.SIGKILL)
    ok(all(status(k) == -9 for k in kids), "all killed")
    return "200 live children"


# ------------------------------------------------------------ signals

@test
def death_by_signal():
    eq(status(child(lambda: os.kill(os.getpid(), signal.SIGKILL))), -9, "SIGKILL")
    eq(status(child(lambda: os.kill(os.getpid(), signal.SIGTERM))), -15, "SIGTERM")

    def segv():
        signal.signal(signal.SIGSEGV, signal.SIG_DFL)
        os.kill(os.getpid(), signal.SIGSEGV)
    eq(status(child(segv)), -11, "SIGSEGV")

    def handled():
        hit = []
        signal.signal(signal.SIGUSR1, lambda *a: hit.append(1))
        os.kill(os.getpid(), signal.SIGUSR1)
        return 0 if hit else 1
    eq(status(child(handled)), 0, "handler ran")
    return "KILL TERM SEGV, handler"


@test
def sigchld_carries_details():
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
    pid = child(lambda: 9)
    info = signal.sigtimedwait({signal.SIGCHLD}, 5)
    ok(info is not None, "SIGCHLD arrived")
    eq(info.si_pid, pid, "si_pid")
    eq(info.si_status, 9, "si_status")
    eq(info.si_code, 1, "si_code CLD_EXITED")
    eq(status(pid), 9, "reaped")
    return "pid, status, code"


@test
def stop_and_continue():
    pid = child(lambda: time.sleep(30))
    os.kill(pid, signal.SIGSTOP)
    p, st = os.waitpid(pid, os.WUNTRACED)
    ok(os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGSTOP, "WUNTRACED sees the stop")
    eq(proc_state(pid), "T", "/proc state T")
    os.kill(pid, signal.SIGCONT)
    p, st = os.waitpid(pid, os.WCONTINUED)
    ok(os.WIFCONTINUED(st), "WCONTINUED sees the continue")
    os.kill(pid, signal.SIGKILL)
    eq(status(pid), -9, "killed")
    return "STOP, T, CONT"


@test
def sigqueue_value_and_sender():
    sig = signal.SIGRTMIN
    signal.pthread_sigmask(signal.SIG_BLOCK, {sig})
    if libc.sigqueue(os.getpid(), int(sig), 0xBEEF) != 0:
        raise Skip(f"sigqueue: {os.strerror(ctypes.get_errno())}")
    info = signal.sigtimedwait({sig}, 2)
    ok(info is not None, "got it")
    eq(info.si_pid, os.getpid(), "si_pid")
    eq(info.si_uid, os.getuid(), "si_uid")
    eq(info.si_code, -1, "si_code SI_QUEUE")
    return "pid, uid, SI_QUEUE"


@test
def realtime_signals_queue_up():
    sig = signal.SIGRTMIN + 1
    signal.pthread_sigmask(signal.SIG_BLOCK, {sig, signal.SIGUSR1})
    for _ in range(5):
        os.kill(os.getpid(), sig)
        os.kill(os.getpid(), signal.SIGUSR1)
    n_rt = n_std = 0
    while (i := signal.sigtimedwait({sig, signal.SIGUSR1}, 0.2)) is not None:
        if i.si_signo == sig:
            n_rt += 1
        else:
            n_std += 1
    eq((n_rt, n_std), (5, 1), "rt signals queue, standard ones merge")
    return "5 rt queued, SIGUSR1 merged"


@test
def masks_across_fork_and_exec():
    def body():
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        signal.signal(signal.SIGUSR1, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, lambda *a: None)
        st = {}
        # exec: dash resets the mask for commands it forks, exec keeps ours
        for line in sh_output("exec cat /proc/self/status").splitlines():
            k, _, v = line.partition(":")
            if k in ("SigBlk", "SigIgn", "SigCgt"):
                st[k] = int(v, 16)
        bit = lambda s: 1 << (s - 1)
        if not st["SigBlk"] & bit(signal.SIGUSR2): return 1   # mask kept
        if not st["SigIgn"] & bit(signal.SIGUSR1): return 2   # SIG_IGN kept
        if st["SigCgt"] & bit(signal.SIGHUP): return 3        # handler reset
        if st["SigIgn"] & bit(signal.SIGHUP): return 4
        return 0
    eq(status(child(body)), 0, "mask kept, ignore kept, handler reset by exec")
    return "SigBlk/SigIgn/SigCgt after exec"


@test
def pending_not_inherited():
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    os.kill(os.getpid(), signal.SIGUSR1)
    ok(signal.SIGUSR1 in signal.sigpending(), "pending in parent")
    eq(status(child(lambda: 0 if signal.SIGUSR1 not in signal.sigpending() else 1)), 0,
       "fork child has nothing pending")
    signal.sigtimedwait({signal.SIGUSR1}, 1)
    return "pending stays with the parent"


@test
def kill_errors():
    try:
        os.kill(2**30, 0)
        raise AssertionError("kill of a nonexistent pid succeeded")
    except ProcessLookupError:
        pass
    pid = child(lambda: time.sleep(30))
    os.kill(pid, 0)
    os.kill(pid, signal.SIGKILL)
    status(pid)
    if os.getuid() != 0 and os.stat("/proc/1").st_uid != os.getuid():
        try:
            os.kill(1, 0)
            raise AssertionError("kill(1, 0) as an ordinary user succeeded")
        except PermissionError:
            pass
    return "ESRCH, probe, EPERM"


@test
def timers():
    got = []
    signal.signal(signal.SIGALRM, lambda *a: got.append(1))
    signal.setitimer(signal.ITIMER_REAL, 0.05)
    wait_until(lambda: got, 2, "SIGALRM")
    signal.setitimer(signal.ITIMER_REAL, 5)
    eq(status(child(lambda: 0 if signal.getitimer(signal.ITIMER_REAL)[0] == 0 else 1)), 0,
       "itimers not inherited by fork")
    signal.setitimer(signal.ITIMER_REAL, 0)
    return "fires, not inherited"


# ------------------------------------------------------------ groups, sessions, parents

@test
def process_groups():
    a = os.fork()
    if a == 0:
        os.setpgid(0, 0)
        time.sleep(30)
        os._exit(0)
    try:
        os.setpgid(a, a)
    except OSError:
        pass
    b = os.fork()
    if b == 0:
        try:
            os.setpgid(0, a)
        except OSError:
            pass
        time.sleep(30)
        os._exit(0)
    try:
        os.setpgid(b, a)
    except OSError:
        pass
    c = child(lambda: time.sleep(30))
    wait_until(lambda: os.getpgid(a) == a and os.getpgid(b) == a, 2, "group formed")
    eq(os.getpgid(c), os.getpgrp(), "c stays in our group")
    os.killpg(a, signal.SIGTERM)
    eq((status(a), status(b)), (-15, -15), "killpg reached the group")
    eq(os.waitpid(c, os.WNOHANG), (0, 0), "and nothing else")
    os.kill(c, signal.SIGKILL)
    status(c)
    return "setpgid, killpg"


@test
def sessions():
    def new_session():
        os.setsid()   # returns None in Python
        return 0 if os.getpid() == os.getsid(0) == os.getpgrp() else 1
    eq(status(child(new_session)), 0, "setsid makes a session and group")

    def leader_cant():
        os.setpgid(0, 0)
        try:
            os.setsid()
            return 1
        except PermissionError:
            return 0
    eq(status(child(leader_cant)), 0, "a group leader can't setsid")
    return "setsid, EPERM for a leader"


@test
def orphans_go_to_subreaper():
    if libc.prctl(36, 1, 0, 0, 0) != 0:   # PR_SET_CHILD_SUBREAPER
        raise Skip("no subreaper")
    me = os.getpid()

    def middle():
        def grandchild():
            wait_until(lambda: os.getppid() == me, 5, "reparent")
            return 7
        child(grandchild)
        return 0
    m = child(middle)
    eq(status(m), 0, "middle exited")
    pid, st = os.wait()
    eq(os.waitstatus_to_exitcode(st), 7, "grandchild reparented and reaped by us")
    return "reparented to the subreaper"


@test
def parent_death_signal():
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise Skip("no subreaper")
    r, w = os.pipe()

    def middle():
        def grandchild():
            libc.prctl(1, signal.SIGKILL, 0, 0, 0)   # PR_SET_PDEATHSIG
            os.write(w, b"x")
            time.sleep(30)
            return 0
        child(grandchild)
        os.read(r, 1)
        return 0
    m = child(middle)
    eq(status(m), 0, "middle exited")
    pid, st = os.wait()
    eq(os.waitstatus_to_exitcode(st), -9, "grandchild got SIGKILL when its parent died")
    return "PDEATHSIG fires"


@test
def sigchld_ignored_auto_reaps():
    def body():
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        g = os.fork()
        if g == 0:
            os._exit(0)
        try:
            os.waitpid(g, 0)
            return 1
        except ChildProcessError:
            return 0
    eq(status(child(body)), 0, "SIG_IGN SIGCHLD: no zombie, ECHILD")
    return "auto-reaped"


# ------------------------------------------------------------ exec

@test
def exec_keeps_pid_argv_env():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.dup2(w, 1)
        os.execve("/bin/sh", ["sh", "-c", 'printf "%s|%s|%s|%s" $$ "$0" "$1" "$LXT_X"', "zero", "one"],
                  {"LXT_X": "env ok", "PATH": "/usr/bin:/bin"})
    os.close(w)
    out = os.read(r, 4096).decode()
    eq(status(pid), 0, "sh")
    eq(out, f"{pid}|zero|one|env ok", "pid, argv and env after exec")
    return "pid, $0, $1, env"


@test
def exec_errors():
    eq(status(child(lambda: os.execv("/nonexistent/prog", ["x"]))), 99, "sanity")  # raises -> 99

    def try_exec(path):
        try:
            os.execv(path, [path])
        except OSError as e:
            return 100 + e.errno
        return 0
    eq(status(child(lambda: try_exec("/nonexistent/prog"))), 102, "ENOENT")
    with open("noexec", "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod("noexec", 0o644)
    eq(status(child(lambda: try_exec("./noexec"))), 113, "EACCES without x")
    with open("badinterp", "w") as f:
        f.write("#!/nonexistent/interp\n")
    os.chmod("badinterp", 0o755)
    eq(status(child(lambda: try_exec("./badinterp"))), 102, "missing interpreter is ENOENT")
    return "ENOENT, EACCES, bad #!"


@test
def cloexec():
    with open("f", "w") as f:
        f.write("x")
    a = os.open("f", os.O_RDONLY | os.O_CLOEXEC)
    b = os.open("f", os.O_RDONLY)
    os.set_inheritable(b, True)

    def body():
        os.execv("/bin/sh", ["sh", "-c",
                 f"test -e /proc/self/fd/{a} && exit 1; test -e /proc/self/fd/{b} || exit 2; exit 0"])
    eq(status(child(body)), 0, "CLOEXEC closed, inheritable kept")
    return "O_CLOEXEC on exec only"


@test
def exec_from_a_thread():
    r, w = os.pipe()

    def body():
        os.dup2(w, 1)
        t = threading.Thread(target=lambda: os.execv("/bin/sh", ["sh", "-c", "echo $$"]))
        t.start()
        time.sleep(30)
    pid = child(body)
    os.close(w)
    out = os.read(r, 4096).decode().strip()
    eq(status(pid), 0, "sh exited")
    eq(out, str(pid), "exec from a thread keeps the process's pid")
    return "thread exec takes the leader's pid"


# ------------------------------------------------------------ threads

@test
def threads():
    tids = []
    in_ = threading.Barrier(17)
    out = threading.Barrier(17)

    def worker():
        tids.append(threading.get_native_id())
        in_.wait()
        out.wait()
    ts = [threading.Thread(target=worker) for _ in range(16)]
    for t in ts:
        t.start()
    in_.wait()
    eq(len(set(tids)), 16, "distinct tids")
    ok(os.getpid() not in tids, "main thread's tid is the pid")
    eq(threading.get_native_id(), os.getpid(), "main tid == pid")
    eq(len(os.listdir("/proc/self/task")), 17, "/proc/self/task")
    eq(proc_status()["Threads"], "17", "Threads: in status")
    ok(all(os.path.exists(f"/proc/{t}") for t in tids), "/proc/<tid> exists")
    out.wait()
    for t in ts:
        t.join()
    eq(len(os.listdir("/proc/self/task")), 1, "threads gone after join")
    return "16 threads, task/, status"


@test
def signal_to_one_thread():
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
    got = []
    t = threading.Thread(target=lambda: got.append(signal.sigwait({signal.SIGUSR1})))
    t.start()
    time.sleep(0.05)
    signal.pthread_kill(t.ident, signal.SIGUSR1)
    t.join(5)
    eq(got, [signal.SIGUSR1], "the thread got its signal")
    return "pthread_kill + sigwait"


@test
def exit_from_a_thread_ends_all():
    def body():
        threading.Thread(target=lambda: (time.sleep(0.05), os._exit(5))).start()
        time.sleep(30)
    eq(status(child(body)), 5, "exit_group from a thread")
    return "whole process exits"


# ------------------------------------------------------------ /proc, resources, spawn

@test
def proc_facts():
    r, w = os.pipe()

    def body():
        libc.prctl(15, b"lxt-proc", 0, 0, 0)   # PR_SET_NAME
        os.write(w, b"x")
        time.sleep(30)
    pid = child(body)
    os.read(r, 1)
    eq(open(f"/proc/{pid}/comm").read(), "lxt-proc\n", "comm")
    eq(open(f"/proc/{pid}/cmdline", "rb").read(), open("/proc/self/cmdline", "rb").read(),
       "fork shares the cmdline")
    st = proc_status(pid)
    eq(st["Pid"], str(pid), "Pid")
    eq(st["PPid"], str(os.getpid()), "PPid")
    eq(st["Uid"].split()[0], str(os.getuid()), "Uid")
    stat = open(f"/proc/{pid}/stat").read()
    eq(stat[stat.rindex(")") + 2:].split()[1], str(os.getpid()), "stat ppid field")
    eq(os.readlink(f"/proc/{pid}/exe"), os.readlink("/proc/self/exe"), "exe")
    eq(os.readlink(f"/proc/{pid}/cwd"), os.getcwd(), "cwd")
    os.kill(pid, signal.SIGKILL)
    status(pid)
    return "comm, cmdline, status, stat, exe, cwd"


@test
def rlimits():
    def nofile():
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (16, hard))
        fds = []
        try:
            while True:
                fds.append(os.open("/dev/null", os.O_RDONLY))
        except OSError as e:
            return 0 if e.errno == 24 and max(fds) < 16 else 1
    eq(status(child(nofile)), 0, "EMFILE at the soft limit")

    def lower_then_raise():
        soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        if hard == 0:
            return 0
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 1))
            return 0 if os.geteuid() == 0 else 1
        except ValueError:
            return 0 if os.geteuid() != 0 else 1
    eq(status(child(lower_then_raise)), 0, "only root raises a hard limit")
    return "NOFILE, hard limits"


@test
def nice_and_affinity():
    def body():
        base = os.getpriority(os.PRIO_PROCESS, 0)
        os.nice(5)
        return 0 if os.getpriority(os.PRIO_PROCESS, 0) == min(base + 5, 19) else 1
    eq(status(child(body)), 0, "nice")
    aff = os.sched_getaffinity(0)
    ok(aff, "affinity not empty")
    one = min(aff)
    eq(status(child(lambda: (os.sched_setaffinity(0, {one}),
                              0 if os.sched_getaffinity(0) == {one} else 1)[1])), 0,
       "setaffinity to one cpu")
    return f"nice, {len(aff)} cpus"


@test
def child_cpu_usage():
    def cpu():
        r = resource.getrusage(resource.RUSAGE_CHILDREN)
        return r.ru_utime + r.ru_stime
    before = cpu()

    def burn():
        end = time.process_time() + 0.3
        while time.process_time() < end:
            pass
    eq(status(child(burn)), 0, "burner")
    used = cpu() - before
    ok(used > 0.15, f"RUSAGE_CHILDREN counted {used:.2f}s of 0.3s")
    return f"{used:.2f}s counted"


@test
def pidfds():
    if not hasattr(os, "pidfd_open"):
        raise Skip("no pidfd_open")
    pid = child(lambda: (time.sleep(0.1), 3)[1])
    fd = os.pidfd_open(pid)
    r, _, _ = select.select([fd], [], [], 5)
    ok(r, "pidfd readable on exit")
    eq(status(pid), 3, "exit code")
    pid = child(lambda: time.sleep(30))
    fd = os.pidfd_open(pid)
    signal.pidfd_send_signal(fd, signal.SIGKILL)
    eq(status(pid), -9, "pidfd_send_signal")
    return "poll, send_signal"


@test
def posix_spawn_and_subprocess():
    r, w = os.pipe()
    pid = os.posix_spawn("/bin/sh", ["sh", "-c", "echo spawned; exit 4"], os.environ,
                         file_actions=[(os.POSIX_SPAWN_DUP2, w, 1)])
    os.close(w)
    eq(os.read(r, 100), b"spawned\n", "output")
    eq(status(pid), 4, "exit code")
    procs = [subprocess.Popen(["sh", "-c", f"exit {i % 7}"]) for i in range(64)]
    eq([p.wait() for p in procs], [i % 7 for i in range(64)], "64 at once")
    out = subprocess.run(["sh", "-c", "echo $PPID"], capture_output=True, text=True).stdout
    eq(out.strip(), str(os.getpid()), "spawned child's parent is us")
    return "posix_spawn, 64 subprocesses"


# ------------------------------------------------------------ runner

def run_one(fn, base):
    msg_file = os.path.join(base, fn.__name__ + ".msg")
    pid = os.fork()
    if pid == 0:
        os.setpgid(0, 0)
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGCHLD):
            signal.signal(s, signal.SIG_DFL)
        d = tempfile.mkdtemp(dir=base)
        os.chdir(d)
        try:
            msg, code = fn() or "", 0
        except Skip as e:
            msg, code = str(e), 2
        except BaseException:
            msg, code = traceback.format_exc(), 1
        with open(msg_file, "w") as f:
            f.write(msg)
        os._exit(code)
    t0 = time.time()
    while True:
        p, st = os.waitpid(pid, os.WNOHANG)
        if p:
            break
        if time.time() - t0 > TIMEOUT:
            os.killpg(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            st = None
            break
        time.sleep(0.005)
    try:
        os.killpg(pid, signal.SIGKILL)   # leftovers
    except (ProcessLookupError, PermissionError):
        pass
    msg = open(msg_file).read() if os.path.exists(msg_file) else ""
    if st is None:
        return "TIMEOUT", f"no result after {TIMEOUT}s", time.time() - t0
    code = os.waitstatus_to_exitcode(st)
    kind = {0: "PASS", 2: "SKIP"}.get(code, "FAIL")
    if kind == "FAIL" and not msg:
        msg = f"test process ended with {code}"
    return kind, msg, time.time() - t0


def main():
    args = [a for a in sys.argv[1:] if a != "-v"]
    verbose = "-v" in sys.argv
    tests = [t for t in TESTS if not args or any(a in t.__name__ for a in args)]
    base = tempfile.mkdtemp(prefix="proc-torture-")
    print(f"process torture: {len(tests)} tests, uid {os.getuid()}, "
          f"{os.uname().sysname} {os.uname().release} {os.uname().machine}")
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0, "TIMEOUT": 0}
    t_all = time.time()
    try:
        for fn in tests:
            kind, msg, dt = run_one(fn, base)
            counts[kind] += 1
            first = msg.strip().splitlines()[-1] if msg.strip() else ""
            print(f"  {kind:7s} {fn.__name__:30s} {dt:6.2f}s  {first[:90]}")
            if verbose and kind in ("FAIL", "TIMEOUT"):
                print("\n".join("        | " + l for l in msg.rstrip().splitlines()))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"\n{counts['PASS']} passed, {counts['FAIL'] + counts['TIMEOUT']} failed, "
          f"{counts['SKIP']} skipped of {len(tests)} in {time.time() - t_all:.1f}s")
    return 1 if counts["FAIL"] or counts["TIMEOUT"] else 0


if __name__ == "__main__":
    sys.exit(main())
