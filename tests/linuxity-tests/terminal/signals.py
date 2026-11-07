"""Terminal-generated signals: ^C, ^Z, ^\\, SIGWINCH, and job control in a shell."""
import fcntl
import os
import signal
import struct
import sys
import termios

from lxt import check, eq, need_cmd, reap_within, test, wait_until
from terminal._pty import fork_on_pty, read_until


@test
def interrupt_keys():
    """^C, ^\\ and ^Z reach the foreground job as SIGINT, SIGQUIT and SIGTSTP."""
    def waiter():
        # dumpable resets on exec, so turn core dumps off from inside
        # SIG_DFL: python's own SIGINT handler can miss a ^C that lands just
        # before time.sleep starts sleeping, on native Linux too
        os.execv(sys.executable, [sys.executable, "-S", "-c",
                  "import ctypes, signal, time; ctypes.CDLL(None).prctl(4, 0, 0, 0, 0); "
                  "signal.signal(signal.SIGINT, signal.SIG_DFL); "
                  "print('READY', flush=True); time.sleep(30)"])

    for key, sig in ((b"\x03", signal.SIGINT), (b"\x1c", signal.SIGQUIT)):
        pid, fd = fork_on_pty(waiter)
        read_until(fd, b"READY")
        os.write(fd, key)
        eq(reap_within(pid, 10), -sig, f"key {key!r}")

    # ^Z stops a JOB: a group under a session leader in the same session.
    # The leader's own group is orphaned, and the kernel drops SIGTSTP there.
    def shell_like():
        job = os.fork()
        if job == 0:
            os.setpgid(0, 0)
            while os.tcgetpgrp(0) != os.getpgrp():
                pass
            os.write(1, b"READY\n")
            while True:
                signal.pause()
        os.setpgid(job, job)
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        os.tcsetpgrp(0, job)
        _, st = os.waitpid(job, os.WUNTRACED)
        ok = os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGTSTP
        os.kill(job, signal.SIGKILL)
        os.waitpid(job, 0)
        os.write(1, b"TSTP-OK\n" if ok else f"TSTP-BAD {st:#x}\n".encode())
        os._exit(0)

    pid, fd = fork_on_pty(shell_like)
    read_until(fd, b"READY")
    os.write(fd, b"\x1a")
    out = read_until(fd, b"TSTP-")
    out += read_until(fd)
    eq(reap_within(pid, 10), 0, "job leader")
    check(b"TSTP-OK" in out, f"^Z: {out!r}")
    return "^C SIGINT, ^\\ SIGQUIT, ^Z stops the foreground job"


@test
def winch_on_resize():
    """Resizing the pty sends SIGWINCH to the foreground group."""
    def child():
        got = []
        signal.signal(signal.SIGWINCH, lambda *_: got.append(1))
        os.write(1, b"READY\n")
        while not got:
            signal.pause()
        rows, cols = struct.unpack("HHHH", fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))[:2]
        os.write(1, f"WINCH {rows}x{cols}\n".encode())
        os._exit(0)

    pid, fd = fork_on_pty(child)
    read_until(fd, b"READY")
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 160, 0, 0))
    out = read_until(fd, b"WINCH")
    out += read_until(fd)
    eq(reap_within(pid, 10), 0, "child")
    check(b"WINCH 50x160" in out, f"output {out!r}")
    return "SIGWINCH 50x160"


@test
def background_tty_access():
    """A background job that reads the terminal gets SIGTTIN."""
    def child():
        os.write(1, b"READY\n")
        bg = os.fork()
        if bg == 0:
            os.setpgid(0, 0)
            os.read(0, 1)          # not the foreground group: SIGTTIN stops us
            os._exit(5)
        try:
            os.setpgid(bg, bg)
        except OSError:
            pass
        _, st = os.waitpid(bg, os.WUNTRACED)
        ok = os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGTTIN
        os.kill(bg, signal.SIGKILL)
        os.waitpid(bg, 0)
        os.write(1, b"TTIN-OK\n" if ok else f"TTIN-BAD {st:#x}\n".encode())
        os._exit(0)

    pid, fd = fork_on_pty(child)
    out = read_until(fd, b"TTIN-")
    out += read_until(fd)
    eq(reap_within(pid, 10), 0, "child")
    check(b"TTIN-OK" in out, f"output {out!r}")
    return "SIGTTIN for a background reader"


@test
def interactive_shell_job_control():
    """bash -i on a pty: job control on, ^Z/bg/fg/jobs/kill %1 all work."""
    need_cmd("bash")
    env = dict(os.environ, TERM="xterm", PS1="PROMPT> ")

    def child():
        os.execve("/bin/bash", ["bash", "--norc", "--noprofile", "-i"], env)

    pid, fd = fork_on_pty(child)
    out = read_until(fd, b"PROMPT> ")

    def fg():
        return struct.unpack("i", fcntl.ioctl(fd, termios.TIOCGPGRP, b"\0" * 4))[0]

    shell_group = wait_until(fg, 10, "bash to take the terminal")
    os.write(fd, b"sleep 30\n")
    # ^Z only stops the job once bash has handed it the terminal
    wait_until(lambda: fg() not in (0, shell_group), 10, "bash to give the terminal to the job")
    for line, want in ((b"\x1a", b"Stopped"), (b"jobs", b"sleep 30"),
                       (b"bg", b"sleep 30 &"), (b"kill %1; wait", b"Terminated"),
                       (b"set -o | grep monitor", b"on"), (b"exit", None)):
        os.write(fd, line + (b"" if line == b"\x1a" else b"\n"))
        if want:
            out += read_until(fd, want)
    out += read_until(fd)
    check(b"no job control" not in out, f"bash complained: {out!r}")
    check(b"cannot set terminal process group" not in out, f"bash complained: {out!r}")
    reap_within(pid, 10)
    return "^Z Stopped, jobs, bg, kill %1, monitor on"
