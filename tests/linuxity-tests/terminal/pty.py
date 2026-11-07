"""Pseudo-terminals: sessions, controlling ttys, names, hangup."""
import errno
import fcntl
import os
import pty
import struct
import termios

from lxt import check, eq, expect_errno, reap_within, test
from terminal._pty import fork_on_pty, read_until


@test
def session_and_ctty():
    """A pty.fork child leads a new session with the pty as its terminal."""
    def child():
        ok = (os.getsid(0) == os.getpid() and os.tcgetpgrp(0) == os.getpgrp()
              and os.isatty(0) and os.ttyname(0) == os.ttyname(1) and os.ttyname(0).startswith("/dev/pts/"))
        fd = os.open("/dev/tty", os.O_RDWR)
        same = os.tcgetpgrp(fd) == os.getpgrp()
        os.write(fd, b"via-dev-tty\n")
        os.write(1, b"SESSION-OK\n" if ok and same else b"SESSION-BAD\n")
        os._exit(0)

    pid, fd = fork_on_pty(child)
    out = read_until(fd, b"SESSION-")
    eq(reap_within(pid, 10), 0, "child exit")
    check(b"SESSION-OK" in out, f"child view of its terminal: {out!r}")
    return "setsid, ctty, tcgetpgrp, ttyname, /dev/tty"


@test
def openpty_pair():
    """openpty: data both ways, the slave's name, and TIOCGPTN agreeing."""
    m, s = pty.openpty()
    name = os.ttyname(s)
    check(name.startswith("/dev/pts/"), f"slave name {name}")
    n = struct.unpack("I", fcntl.ioctl(m, 0x80045430, b"\0" * 4))[0]   # TIOCGPTN
    eq(name, f"/dev/pts/{n}", "TIOCGPTN")
    check(os.path.exists(name), "slave node exists")
    attrs = termios.tcgetattr(s)
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(s, termios.TCSANOW, attrs)
    os.write(m, b"to-slave\n")
    eq(os.read(s, 100), b"to-slave\n", "master -> slave (canonical line)")
    os.write(s, b"to-master")
    eq(read_until(m, b"to-master", 5)[-9:], b"to-master", "slave -> master")
    s2 = os.open(name, os.O_RDWR | os.O_NOCTTY)
    check(os.isatty(s2), "reopen the slave by name")
    expect_errno(errno.ENOTTY, "isatty-style ioctl on a file", fcntl.ioctl,
                 os.open("plain", os.O_RDWR | os.O_CREAT, 0o644), termios.TIOCGWINSZ, b"\0" * 8)
    return name


@test
def hangup():
    """Closing the master gives the slave EIO on read and SIGHUP to the session."""
    def child():
        import signal
        import time
        got = []
        signal.signal(signal.SIGHUP, lambda *_: got.append(1))
        os.write(1, b"READY\n")
        how = 3
        try:
            while os.read(0, 100):
                pass
            how = 20
        except OSError as e:
            how = 10 if e.errno == errno.EIO else 3
        for _ in range(200):     # the signal may land just after the read returns
            if got:
                break
            time.sleep(0.005)
        os._exit(how + (1 if got else 0))

    pid, fd = fork_on_pty(child)
    read_until(fd, b"READY")
    os.close(fd)
    rc = reap_within(pid, 10)
    check(rc in (11, 21), f"after hangup the child saw rc {rc} (want EIO/EOF with SIGHUP)")
    return "EIO/EOF + SIGHUP"


@test
def window_size():
    """TIOCSWINSZ on the master is what the slave reads, including from a shell."""
    def child():
        os.execv("/bin/sh", ["sh", "-c", "read x; stty size; exit 0"])

    pid, fd = fork_on_pty(child)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 41, 133, 0, 0))
    os.write(fd, b"go\n")
    out = read_until(fd)
    eq(reap_within(pid, 10), 0, "sh exit")
    check(b"41 133" in out, f"stty size printed {out!r}")
    return "41x133"
