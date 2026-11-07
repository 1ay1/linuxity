"""ptrace: tracing a child, the way strace and gdb do."""
import ctypes
import os
import shutil
import signal
import subprocess

from lxt import check, eq, libc, skip, test

PTRACE_TRACEME, PTRACE_PEEKDATA, PTRACE_CONT, PTRACE_SYSCALL = 0, 2, 7, 24
PTRACE_SETOPTIONS, PTRACE_O_TRACESYSGOOD = 0x4200, 1
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]


@test
def traceme_and_syscall_stops():
    """TRACEME + exec stops with SIGTRAP; PTRACE_SYSCALL stops in pairs."""
    pid = os.fork()
    if pid == 0:
        try:
            libc.ptrace(PTRACE_TRACEME, 0, None, None)
            os.execv("/bin/true", ["true"])
        finally:
            os._exit(9)
    _, st = os.waitpid(pid, os.WUNTRACED)
    check(os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGTRAP, f"exec stop {st:#x}")
    libc.ptrace(PTRACE_SETOPTIONS, pid, None, PTRACE_O_TRACESYSGOOD)
    stops = 0
    while True:
        libc.ptrace(PTRACE_SYSCALL, pid, None, None)
        _, st = os.waitpid(pid, os.WUNTRACED)
        if os.WIFEXITED(st):
            break
        check(os.WSTOPSIG(st) == (signal.SIGTRAP | 0x80), f"syscall stop {st:#x}")
        stops += 1
        check(stops < 10000, "endless stops")
    eq(os.WEXITSTATUS(st), 0, "traced /bin/true exits 0")
    check(stops > 10 and stops % 2 == 1, f"{stops} stops: entry/exit pairs plus exit_group")
    return f"{stops} syscall stops"


@test
def tracer_pid_and_state():
    """TracerPid names the tracer; a parked tracee shows 't (tracing stop)'."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            libc.ptrace(PTRACE_TRACEME, 0, None, None)
            os.kill(os.getpid(), signal.SIGSTOP)
            with open("/proc/self/status") as f:
                tp = next(l.split()[1] for l in f if l.startswith("TracerPid"))
            os.write(w, tp.encode())
        finally:
            os._exit(0)
    _, st = os.waitpid(pid, os.WUNTRACED)
    check(os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGSTOP, "SIGSTOP stop")
    with open(f"/proc/{pid}/status") as f:
        state = next(l for l in f if l.startswith("State")).split(None, 1)[1].strip()
    eq(state, "t (tracing stop)", "state while stopped for us")
    libc.ptrace(PTRACE_CONT, pid, None, None)
    os.waitpid(pid, 0)
    eq(int(os.read(r, 32)), os.getpid(), "TracerPid")
    return "TracerPid, t (tracing stop)"


@test
def strace_runs():
    """strace sees a program's syscalls, and -f follows forks."""
    if not shutil.which("strace"):
        skip("no strace installed")
    out = subprocess.run(["strace", "-f", "-e", "trace=execve,exit_group", "sh", "-c", "/bin/true"],
                         capture_output=True, text=True, timeout=30)
    eq(out.returncode, 0, "strace exit code")
    check(out.stderr.count("execve(") == 2, f"two execves: {out.stderr[-300:]}")
    check("exit_group(0)" in out.stderr, "exit_group seen")
    return "execve x2 and exit_group under -f"


@test
def gdb_breakpoint():
    """gdb stops at a breakpoint and reads locals."""
    if not shutil.which("gdb") or not shutil.which("cc"):
        skip("no gdb or cc")
    with open("t.c", "w") as f:
        f.write("int add(int a, int b) { return a + b; }\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n")
    subprocess.run(["cc", "-g", "-O0", "-o", "t", "t.c"], check=True, timeout=60)
    out = subprocess.run(["gdb", "-batch", "-ex", "set startup-with-shell off", "-ex", "break add",
                          "-ex", "run", "-ex", "print a+b", "./t"],
                         capture_output=True, text=True, timeout=60)
    text = out.stdout + out.stderr
    check("Breakpoint 1, add (a=2, b=3)" in text, f"breakpoint: {text[-300:]}")
    check("$1 = 5" in text, "print a+b")
    return "break, run, print"
