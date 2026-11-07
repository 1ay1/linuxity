"""fork, exec, wait, and the process tree."""
import ctypes
import os
import select
import signal
import struct
import subprocess
import sys
import time

from lxt import check, eq, expect_errno, libc, must, napper, read_exact, reap, spawn, test
import errno


@test
def fork_tree():
    """341 processes, 4 levels deep, all report in and exit cleanly."""
    r, w = os.pipe()

    def node(depth):
        if depth:
            kids = [spawn(node, depth - 1) for _ in range(4)]
            for k in kids:
                check(reap(k) == 0, "a subtree failed")
        os.write(w, b"x")

    must(spawn(node, 4))
    os.close(w)
    n = 0
    while (b := os.read(r, 4096)):
        n += len(b)
    eq(n, 341, "processes reported")
    return "341 processes, 4 levels"


@test
def zombies_and_exit_codes():
    """300 zombies reaped with the right exit codes; ECHILD after."""
    want = {spawn(lambda c: c, i % 256): i % 256 for i in range(300)}
    got = {}
    while len(got) < len(want):
        pid, st = os.wait()
        got[pid] = os.waitstatus_to_exitcode(st)
    check(got == want, f"{sum(got.get(p) != c for p, c in want.items())} exit codes mixed up")
    expect_errno(errno.ECHILD, "wait with no children", os.wait)
    pid = spawn(lambda: 7)
    r = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
    eq((r.si_pid, r.si_status, r.si_code), (pid, 7, os.CLD_EXITED), "waitid WNOWAIT")
    eq(reap(pid), 7, "the zombie survives WNOWAIT")
    return "300 zombies, ECHILD, waitid WNOWAIT"


@test
def wait_variants():
    """waitpid by pid, by group, any child, WNOHANG and wait4 rusage."""
    a = spawn(lambda: 1)
    b = spawn(napper)
    eq(os.waitpid(b, os.WNOHANG), (0, 0), "WNOHANG on a live child")
    eq(reap(a), 1, "waitpid(pid)")
    os.kill(b, signal.SIGTERM)
    pid, st, ru = os.wait4(b, 0)
    eq((pid, os.waitstatus_to_exitcode(st)), (b, -signal.SIGTERM), "wait4")
    check(ru.ru_utime >= 0, "wait4 rusage")
    # waitpid(0) only takes children in our own process group
    kids = [spawn(lambda: 3) for _ in range(3)]
    for _ in kids:
        pid, st = os.waitpid(0, 0)
        check(pid in kids and os.waitstatus_to_exitcode(st) == 3, f"waitpid(0) gave {pid}")
    g = spawn(lambda: (os.setpgid(0, 0), 5)[1])
    os.waitid(os.P_PID, g, os.WEXITED | os.WNOWAIT)   # a zombie in its own group now
    expect_errno(errno.ECHILD, "waitpid(0) with only an other-group child", os.waitpid, 0, os.WNOHANG)
    eq(reap(g), 5, "waitpid(pid) still gets it")
    return "pid, WNOHANG, wait4 rusage, own group only"


@test
def orphans_reparent():
    """An orphan goes to the nearest subreaper, which can reap it."""
    check(libc.prctl(36, 1, 0, 0, 0) == 0, "PR_SET_CHILD_SUBREAPER")
    me = os.getpid()
    r, w = os.pipe()
    hr, hw = os.pipe()

    def middle():
        def grandchild():
            parent = os.getppid()
            pfd = os.pidfd_open(parent)
            os.write(hw, b"k")
            select.select([pfd], [], [], 10)
            for _ in range(5000):
                if os.getppid() != parent:
                    break
                time.sleep(0.001)
            os.write(w, struct.pack("ii", parent, os.getppid()))
        spawn(grandchild)
        os.read(hr, 1)

    mid = spawn(middle)
    must(mid, "middle")
    first, second = struct.unpack("ii", read_exact(r, 8))
    eq(first, mid, "grandchild's first parent")
    eq(second, me, "orphan's new parent (the subreaper)")
    pid, st = os.waitpid(-1, 0)
    check(pid != mid and os.waitstatus_to_exitcode(st) == 0, "couldn't reap the adopted orphan")
    return "adopted by the subreaper and reaped"


@test
def exec_paths():
    """execve keeps the pid; 25 chained execs; /proc/self/exe re-exec."""
    code = ("import os,sys\n"
            "n=int(sys.argv[1])\n"
            "exe='/proc/self/exe' if n==1 else sys.executable\n"
            "if n: os.execv(exe,[sys.executable,'-S','-c',os.environ['LXT_HOP'],str(n-1)])\n"
            "print(os.getpid(),os.getppid(),flush=True)\n")
    env = dict(os.environ, LXT_HOP=code)
    p = subprocess.Popen([sys.executable, "-S", "-c", code, "25"], env=env, stdout=subprocess.PIPE)
    out, _ = p.communicate(timeout=50)
    eq(p.returncode, 0, "chain exit")
    pid, ppid = map(int, out.split())
    eq((pid, ppid), (p.pid, os.getpid()), "pid/ppid after 25 execs")
    r = subprocess.run(["/bin/sh", "-c", "exec /bin/sh -c 'echo $$'; echo unreachable"],
                       capture_output=True, text=True, timeout=10)
    check(r.stdout.strip().isdigit() and "unreachable" not in r.stdout, "exec replaced the shell")
    expect_errno(errno.ENOENT, "exec of a missing file", os.execv, "/nonexistent/x", ["x"])
    with open("noexec", "w") as f:
        f.write("plain text\n")
    os.chmod("noexec", 0o644)
    if os.getuid() != 0:
        expect_errno(errno.EACCES, "exec without +x", os.execv, "./noexec", ["x"])
    os.chmod("noexec", 0o755)
    expect_errno(errno.ENOEXEC, "exec of text with no #!", os.execv, "./noexec", ["x"])
    return "25 execs keep the pid, exec in sh, ENOENT/EACCES/ENOEXEC"


@test
def scripts_and_interpreters():
    """#! lines: arguments, relative interpreters, env, and a missing interpreter."""
    with open("s1", "w") as f:
        f.write(f"#!{sys.executable} -S\nimport sys; print(' '.join(sys.argv[1:]))\n")
    with open("s2", "w") as f:
        f.write("#!/usr/bin/env sh\necho \"$0|$1\"\n")
    with open("s3", "w") as f:
        f.write("#!/no/such/interpreter\n")
    for s in ("s1", "s2", "s3"):
        os.chmod(s, 0o755)
    eq(subprocess.run(["./s1", "a", "b c"], capture_output=True, text=True).stdout, "a b c\n", "#! python args")
    eq(subprocess.run(["./s2", "x"], capture_output=True, text=True).stdout, "./s2|x\n", "#!/usr/bin/env")
    expect_errno(errno.ENOENT, "#! with a missing interpreter", os.execv, "./s3", ["s3"])
    return "#! args, env, missing interpreter"


@test
def big_argv_env():
    """40000 args and a 100 KB variable survive exec; E2BIG past the limit."""
    args = ["y" * 20] * 40000
    env = dict(os.environ, BIG="z" * 100000)
    r = subprocess.run(["/bin/sh", "-c", 'echo $#; printf %s "$*" | wc -c; printf %s "$BIG" | wc -c',
                        "sh", *args], env=env, capture_output=True, text=True, timeout=30)
    eq(r.stdout.split(), ["40000", str(40000 * 21 - 1), "100000"], "argv/env across exec")
    expect_errno(errno.E2BIG, "argv beyond the stack limit",
                 subprocess.run, ["/bin/true", "x" * (200 << 20)])
    return "40000 args + 100 KB env; E2BIG"


@test
def spawn_apis():
    """posix_spawn, vfork via subprocess, and 64 shells at once."""
    pid = os.posix_spawn("/bin/sh", ["sh", "-c", "exit 42"], os.environ)
    eq(reap(pid), 42, "posix_spawn")
    pid = os.posix_spawnp("sh", ["sh", "-c", "exit 43"], os.environ,
                          file_actions=[(os.POSIX_SPAWN_OPEN, 1, "out", os.O_WRONLY | os.O_CREAT, 0o644)])
    eq(reap(pid), 43, "posix_spawnp with file actions")
    ps = [subprocess.Popen(["/bin/sh", "-c", f"exit {i}"]) for i in range(64)]
    eq([p.wait(timeout=30) for p in ps], list(range(64)), "64 parallel exit codes")
    return "posix_spawn(p), 64 parallel"
