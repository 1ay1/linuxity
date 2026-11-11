#!/usr/bin/env python3
"""tty_torture.py -- Linux terminals: ptys, the line discipline, termios,
window size, controlling terminals, and an interactive shell driven through
a pty the way a terminal emulator drives it. See torture.py for running."""
import sys
sys.dont_write_bytecode = True
import errno
import fcntl
import os
import pty
import select
import signal
import struct
import termios
import time
import tty

from torture import *  # noqa: F401,F403
from torture import check, ok, eq, expect_errno, child, status, run_in_child, Skip, main


def read_until(fd, want, secs=5):
    buf, end = b"", time.monotonic() + secs
    while want not in buf and time.monotonic() < end:
        if select.select([fd], [], [], 0.05)[0]:
            try:
                b = os.read(fd, 4096)
            except OSError:
                break
            if not b:
                break
            buf += b
    return buf


def spawn_on_pty(argv, env=None):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env or os.environ)
    return pid, fd


def reap(pid, secs=10):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(st)
        time.sleep(0.02)
    os.kill(pid, signal.SIGKILL)
    return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])


@check
def openpty_names_and_types():
    m, s = os.openpty()
    ok(os.isatty(s) and os.isatty(m), "both ends are ttys")
    name = os.ttyname(s)
    ok(name.startswith("/dev/pts/"), f"ttyname: {name}")
    st = os.stat(name)
    ok(__import__("stat").S_ISCHR(st.st_mode), "the slave is a char device")
    eq(os.stat(name).st_rdev, os.fstat(s).st_rdev, "the name is the open slave")
    ok(os.path.exists("/dev/ptmx") and os.path.isdir("/dev/pts"), "/dev/ptmx and /dev/pts")
    r, w = os.pipe()
    ok(not os.isatty(r), "a pipe is not a tty")
    try:
        termios.tcgetattr(r)
        raise AssertionError("termios on a pipe succeeded")
    except termios.error as e:
        eq(e.args[0], errno.ENOTTY, "termios on a pipe is ENOTTY")


@check
def canonical_mode_edits_lines():
    m, s = os.openpty()
    os.write(m, b"abc\x7fd\n")                 # DEL erases the c
    eq(os.read(s, 100), b"abd\n", "VERASE")
    os.write(m, b"junk\x15good\n")             # ^U kills the line
    eq(os.read(s, 100), b"good\n", "VKILL")
    os.write(m, b"one two\x17three\n")         # ^W erases a word
    eq(os.read(s, 100), b"one three\n", "VWERASE")
    os.write(m, b"partial")
    eq(select.select([s], [], [], 0.2)[0], [], "no line yet, nothing to read")
    os.write(m, b"\x04")                       # ^D: push what's there
    eq(os.read(s, 100), b"partial", "VEOF delivers a partial line")
    os.write(m, b"\x04")
    eq(os.read(s, 100), b"", "VEOF at line start reads as EOF")


@check
def echo_and_output_processing():
    m, s = os.openpty()
    os.write(m, b"hi\n")
    eq(read_until(m, b"hi\r\n"), b"hi\r\n", "ECHO, with \\n echoed as \\r\\n")
    os.read(s, 10)
    os.write(s, b"out\n")
    eq(read_until(m, b"out\r\n"), b"out\r\n", "ONLCR maps \\n to \\r\\n")
    a = termios.tcgetattr(s)
    a[1] &= ~termios.OPOST
    a[3] &= ~termios.ECHO
    termios.tcsetattr(s, termios.TCSANOW, a)
    os.write(s, b"raw\n")
    eq(read_until(m, b"raw\n"), b"raw\n", "without OPOST no translation")
    os.write(m, b"quiet\n")
    os.read(s, 10)
    eq(select.select([m], [], [], 0.2)[0], [], "without ECHO nothing comes back")


@check
def raw_mode_byte_at_a_time():
    m, s = os.openpty()
    tty.setraw(s)
    os.write(m, b"\x03x")                      # ^C is just a byte in raw mode
    eq(os.read(s, 10), b"\x03x", "raw: control chars pass through")
    a = termios.tcgetattr(s)
    a[6][termios.VMIN], a[6][termios.VTIME] = 0, 2   # read returns after 0.2s idle
    termios.tcsetattr(s, termios.TCSANOW, a)
    t = time.monotonic()
    eq(os.read(s, 10), b"", "VMIN=0 VTIME=2: an empty read after the timeout")
    ok(0.1 < time.monotonic() - t < 1, f"~0.2s ({time.monotonic() - t:.2f})")
    termios.tcflush(s, termios.TCIOFLUSH)
    os.write(m, b"z")
    termios.tcdrain(s)


@check
def window_size_and_sigwinch():
    pid, m = spawn_on_pty([sys.executable, "-S", "-c",
        "import signal,fcntl,termios,struct,sys,time\n"
        "signal.signal(signal.SIGWINCH, lambda *a: print('WINCH', struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\\0'*8))[:2], flush=True))\n"
        "print('READY', flush=True); time.sleep(5)"])
    ok(b"READY" in read_until(m, b"READY"), "child started")
    fcntl.ioctl(m, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 132, 0, 0))
    out = read_until(m, b")")
    ok(b"WINCH (40, 132)" in out, f"the foreground job got SIGWINCH and the new size: {out!r}")
    os.kill(pid, signal.SIGKILL); reap(pid)
    mm, s = os.openpty()
    fcntl.ioctl(mm, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    eq(os.get_terminal_size(s), os.terminal_size((80, 24)), "get_terminal_size")


@check
def control_keys_signal_the_foreground_job():
    for key, sig in ((b"\x03", signal.SIGINT), (b"\x1c", signal.SIGQUIT)):
        pid, m = spawn_on_pty([sys.executable, "-S", "-c",
            "import time,resource; resource.setrlimit(resource.RLIMIT_CORE,(0,0)); print('R',flush=True); time.sleep(20)"])
        read_until(m, b"R")
        os.write(m, key)
        eq(reap(pid), -sig, f"{key!r}")
    # ^Z: the session leader pty.fork makes is an ORPHANED process group
    # (its parent is in another session), and the kernel won't stop those --
    # so put the job in its own group under a shell, as a terminal does.
    pid, m = spawn_on_pty(["/bin/sh", "-c", "set -m; python3 -S -c \"import time; print('R',flush=True); time.sleep(20)\"; echo rc=$?"])
    read_until(m, b"R")
    os.write(m, b"\x1a")
    out = read_until(m, b"rc=", 5)
    ok(b"rc=148" in out, f"^Z stops the job: the shell sees 128+SIGTSTP ({out!r})")
    os.kill(pid, signal.SIGKILL); reap(pid)


@check
def controlling_terminal_and_sessions():
    pid, m = spawn_on_pty([sys.executable, "-S", "-c",
        "import os\n"
        "fd = os.open('/dev/tty', os.O_RDWR)\n"
        "print('SID', os.getsid(0) == os.getpid(), 'FG', os.tcgetpgrp(0) == os.getpgrp(),\n"
        "      'TTY', os.isatty(fd) and os.tcgetpgrp(fd) == os.getpgrp(), flush=True)"])
    out = read_until(m, b"TTY True")
    ok(b"SID True FG True TTY True" in out, f"session leader, foreground, /dev/tty: {out!r}")
    reap(pid)

    def no_ctty():
        os.setsid()
        try:
            os.open("/dev/tty", os.O_RDWR)
            return 1
        except OSError as e:
            return 0 if e.errno == errno.ENXIO else 2
    eq(run_in_child(no_ctty), 0, "a new session has no /dev/tty (ENXIO)")


@check
def hangup_when_the_master_closes():
    pid, m = spawn_on_pty([sys.executable, "-S", "-c", "import time; print('R',flush=True); time.sleep(20)"])
    read_until(m, b"R")
    os.close(m)
    eq(reap(pid), -signal.SIGHUP, "the session leader gets SIGHUP")
    mm, s = os.openpty()
    os.close(mm)
    # Linux: once the master is gone a slave read returns EOF (0) -- or EIO
    # if it had already hung up; either way no data and no block.
    try:
        eq(os.read(s, 1), b"", "a read of a slave whose master is gone")
    except OSError as e:
        eq(e.errno, errno.EIO, "a read of a slave whose master is gone")


@check(timeout=60)
def interactive_bash_through_a_pty():
    if not os.path.exists("/bin/bash"):
        raise Skip("no bash")
    env = dict(os.environ, PS1="PROMPT$ ", TERM="xterm-256color", HOME=os.getcwd())
    pid, m = spawn_on_pty(["/bin/bash", "--norc", "--noprofile", "-i"], env)
    ok(b"PROMPT$ " in read_until(m, b"PROMPT$ ", 10), "bash shows its prompt")
    os.write(m, b"echo $((6*7)) $$\n")
    out = read_until(m, b"PROMPT$ ", 10)
    ok(b"42" in out, f"a command runs: {out!r}")
    os.write(m, b"sleep 30 &\n")
    read_until(m, b"PROMPT$ ")
    os.write(m, b"jobs; kill %1; wait %1; echo done=$?\n")
    out = read_until(m, b"done=", 10) + read_until(m, b"PROMPT$ ")
    ok(b"sleep 30" in out and b"done=143" in out, f"job control: {out!r}")
    os.write(m, b"cat\n")
    time.sleep(0.3)
    os.write(m, b"typed\n")
    ok(b"typed" in read_until(m, b"typed\r\ntyped"), "cat echoes what we type")
    os.write(m, b"\x03")
    ok(b"PROMPT$ " in read_until(m, b"PROMPT$ "), "^C kills cat, bash survives")
    os.write(m, b"exit 5\n")
    eq(reap(pid), 5, "exit status")


@check
def exit_does_not_wait_for_the_output_to_be_read():
    # Linux ends a session leader at once and leaves its last output
    # buffered for the master (XNU would block the exit until it drains):
    # a parent that reaps before reading -- pexpect, any harness -- works
    for argv in (["/bin/sh", "-c", "echo bye; exit 5"],
                 ["/bin/bash", "--norc", "--noprofile", "+m", "-i", "-c", "echo bye; exit 5"]):
        pid, m = spawn_on_pty(argv)
        end = time.monotonic() + 3
        while time.monotonic() < end:
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            time.sleep(0.02)
        else:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise AssertionError(f"{argv[0]}: not reapable until its output is read")
        eq(os.waitstatus_to_exitcode(st), 5, f"{argv[0]}: exit status")
        ok(b"bye" in read_until(m, b"bye", 3), f"{argv[0]}: the output is still there")
        os.close(m)


@check
def epoll_on_stdin_sees_keys():
    # Every TUI event loop (agentty, crossterm, libuv, Go) waits on fd 0
    # with epoll. fd 0 is the one fd whose number is 0 -- which an
    # implementation storing the fd as an opaque tag can mistake for "none".
    rp, wp = os.pipe()
    pid, m = pty.fork()
    if pid == 0:
        try:
            tty.setraw(0)
            ep = select.epoll()
            ep.register(0, select.EPOLLIN)
            os.write(wp, b"g")
            ev = ep.poll(5)
            got = os.read(0, 10) if ev else b""
            os.write(wp, repr((ev, got)).encode())
        finally:
            os._exit(0)
    os.close(wp)
    eq(os.read(rp, 1), b"g", "the child is waiting")
    time.sleep(0.1)
    os.write(m, b"k")
    res = os.read(rp, 200).decode()
    reap(pid)
    eq(res, repr(([(0, select.EPOLLIN)], b"k")), "epoll reports the key on fd 0")
    os.close(m)


if __name__ == "__main__":
    sys.exit(main("terminals"))
