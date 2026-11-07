"""inotify: the event stream editors, build tools and file managers rely on."""
import ctypes
import os
import select
import struct

from lxt import check, eq, libc, test

IN_ACCESS, IN_MODIFY, IN_ATTRIB, IN_CLOSE_WRITE = 0x1, 0x2, 0x4, 0x8
IN_CLOSE_NOWRITE, IN_OPEN, IN_MOVED_FROM, IN_MOVED_TO = 0x10, 0x20, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_MOVE_SELF = 0x100, 0x200, 0x400, 0x800
IN_IGNORED, IN_ISDIR, IN_ONESHOT, IN_ALL = 0x8000, 0x40000000, 0x80000000, 0xFFF


class Watcher:
    def __init__(self):
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        check(self.fd >= 0, f"inotify_init1: {os.strerror(ctypes.get_errno())}")

    def add(self, path, mask=IN_ALL):
        wd = libc.inotify_add_watch(self.fd, os.fsencode(path), mask)
        check(wd >= 0, f"inotify_add_watch({path}): {os.strerror(ctypes.get_errno())}")
        return wd

    def events(self, settle=0.3):
        out = []
        while select.select([self.fd], [], [], settle)[0]:
            buf = os.read(self.fd, 65536)
            off = 0
            while off < len(buf):
                wd, mask, cookie, ln = struct.unpack_from("iIII", buf, off)
                name = buf[off + 16:off + 16 + ln].rstrip(b"\0").decode()
                out.append((wd, mask, cookie, name))
                off += 16 + ln
            settle = 0.05
        return out


def masks(evs, name):
    return [m & ~IN_ISDIR for _, m, _, n in evs if n == name]


@test
def file_lifecycle():
    """create, open, modify, close_write, attrib, delete -- in order."""
    w = Watcher()
    w.add(".")
    with open("f", "w") as f:
        f.write("hi")
    os.chmod("f", 0o600)
    with open("f") as f:
        f.read()
    os.unlink("f")
    got = masks(w.events(), "f")
    want = [IN_CREATE, IN_OPEN, IN_MODIFY, IN_CLOSE_WRITE, IN_ATTRIB,
            IN_OPEN, IN_ACCESS, IN_CLOSE_NOWRITE, IN_DELETE]
    eq(got, want, "events for f")
    return "9 events in order"


@test
def moves_pair_up():
    """A rename gives MOVED_FROM and MOVED_TO with the same cookie, across dirs too."""
    os.mkdir("a")
    os.mkdir("b")
    open("a/x", "w").close()
    w = Watcher()
    wa, wb = w.add("a"), w.add("b")
    os.rename("a/x", "b/y")
    os.rename("b/y", "b/z")
    ev = w.events()
    frm = [(wd, c) for wd, m, c, n in ev if m & IN_MOVED_FROM and n == "x"]
    to = [(wd, c) for wd, m, c, n in ev if m & IN_MOVED_TO and n == "y"]
    check(frm and to, f"move events {ev}")
    eq((frm[0][0], to[0][0]), (wa, wb), "watch descriptors")
    check(frm[0][1] == to[0][1] != 0, "cookies don't pair up")
    c2 = [c for _, m, c, n in ev if n in ("y", "z") and m & (IN_MOVED_FROM | IN_MOVED_TO) and c != to[0][1]]
    check(len(c2) == 2 and c2[0] == c2[1], "in-dir rename cookie")
    return "cross-dir and in-dir moves paired"


@test
def directories_and_self_events():
    """Subdir events carry IN_ISDIR; deleting a watched dir gives DELETE_SELF then IGNORED."""
    os.mkdir("top")
    w = Watcher()
    wtop = w.add("top")
    os.mkdir("top/sub")
    wsub = w.add("top/sub")
    open("top/sub/inner", "w").close()
    os.unlink("top/sub/inner")
    os.rmdir("top/sub")
    ev = w.events()
    check(any(wd == wtop and m == IN_CREATE | IN_ISDIR and n == "sub" for wd, m, _, n in ev), "CREATE|ISDIR")
    check(any(wd == wsub and m & IN_CREATE and n == "inner" for wd, m, _, n in ev), "event in the sub watch")
    self_ev = [m for wd, m, _, n in ev if wd == wsub and not n]
    check(IN_DELETE_SELF in self_ev and IN_IGNORED in self_ev, f"self events {self_ev}")
    check(self_ev.index(IN_DELETE_SELF) < self_ev.index(IN_IGNORED), "DELETE_SELF before IGNORED")
    check(any(wd == wtop and m == IN_DELETE | IN_ISDIR for wd, m, _, n in ev), "DELETE|ISDIR on the parent")
    return "ISDIR, nested watch, DELETE_SELF + IGNORED"


@test
def oneshot_and_rm_watch():
    """IN_ONESHOT fires once then IGNORED; inotify_rm_watch stops events."""
    open("o", "w").close()
    w = Watcher()
    w.add("o", IN_MODIFY | IN_ONESHOT)
    for _ in range(3):
        with open("o", "a") as f:
            f.write("x")
    ev = [m for _, m, _, _ in w.events()]
    eq(ev, [IN_MODIFY, IN_IGNORED], "oneshot")
    wd = w.add("o", IN_MODIFY)
    check(libc.inotify_rm_watch(w.fd, wd) == 0, "rm_watch")
    with open("o", "a") as f:
        f.write("y")
    eq([m for _, m, _, _ in w.events()], [IN_IGNORED], "events after rm_watch")
    return "oneshot, rm_watch"


@test
def changes_from_other_processes():
    """Writes from a child and from a shell show up like our own."""
    import subprocess
    w = Watcher()
    w.add(".", IN_CREATE | IN_CLOSE_WRITE)
    subprocess.run(["/bin/sh", "-c", "echo hi > from_sh; touch from_touch"], check=True)
    names = [(m, n) for _, m, _, n in w.events()]
    for n in ("from_sh", "from_touch"):
        check((IN_CREATE, n) in names and (IN_CLOSE_WRITE, n) in names, f"{n}: {names}")
    return "shell redirect and touch seen"
