"""Helpers for driving a child on a fresh pty."""
import errno
import os
import pty
import select
import time


def read_until(fd, needle=None, timeout=10):
    """Read the master until `needle` shows up (or EOF/EIO if needle is None)."""
    out, end = b"", time.monotonic() + timeout
    while needle is None or needle not in out:
        left = end - time.monotonic()
        if left <= 0:
            raise AssertionError(f"pty never printed {needle!r}; got {out[-300:]!r}")
        if not select.select([fd], [], [], left)[0]:
            continue
        try:
            d = os.read(fd, 4096)
        except OSError as e:
            if e.errno == errno.EIO:
                break
            raise
        if not d:
            break
        out += d
    return out


def fork_on_pty(child_fn):
    """pty.fork(); the child runs child_fn() (which should exec or _exit)."""
    pid, fd = pty.fork()
    if pid == 0:
        try:
            child_fn()
        finally:
            os._exit(127)
    return pid, fd
