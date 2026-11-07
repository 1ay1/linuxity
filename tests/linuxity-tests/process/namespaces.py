"""Namespaces: what the environment's pid/mount/uts views look like.

A namespace test answers two different questions depending on where it runs.
Natively it asks whether the kernel lets us create namespaces. Inside a
container, chroot or linuxity it mostly asks how closed the view we were
given is -- creating new ones is the host kernel's call ([host]).
"""
import errno
import os
import socket

from lxt import check, eq, libc, reap, skip, spawn, syscall, test

CLONE_NEWUTS, CLONE_NEWNS, CLONE_NEWUSER = 0x04000000, 0x00020000, 0x10000000


def enter(flags):
    """unshare(flags), adding a user namespace (with our ids mapped) when not root.
    Returns 0, or 100+errno if refused."""
    uid, gid = os.getuid(), os.getgid()
    if uid != 0:
        flags |= CLONE_NEWUSER
    try:
        syscall("unshare", flags)
    except OSError as e:
        return 100 + e.errno
    if uid != 0:
        for f, body in (("setgroups", "deny"), ("uid_map", f"0 {uid} 1"), ("gid_map", f"0 {gid} 1")):
            with open(f"/proc/self/{f}", "w") as fh:
                fh.write(body)
    return 0


@test
def pid_view_is_closed():
    """Every pid we can see chains up to pid 1, and pid 1 has no parent."""
    pids = [int(p) for p in os.listdir("/proc") if p.isdigit()]
    check(1 in pids, "no pid 1 in /proc")
    with open("/proc/1/stat") as f:
        eq(int(f.read().rsplit(")", 1)[1].split()[1]), 0, "pid 1's ppid")
    for pid in pids:
        seen = set()
        p = pid
        try:
            while p not in (0, 1):
                check(p not in seen, f"ppid loop at {p}")
                seen.add(p)
                with open(f"/proc/{p}/stat") as f:
                    p = int(f.read().rsplit(")", 1)[1].split()[1])
        except FileNotFoundError:
            continue    # exited while we walked
        check(p in (0, 1), f"pid {pid} doesn't reach pid 1")
    chain, p = [], os.getpid()
    while p > 1:
        chain.append(p)
        with open(f"/proc/{p}/stat") as f:
            p = int(f.read().rsplit(")", 1)[1].split()[1])
    return f"{len(pids)} pids visible, we are {len(chain)} below pid 1"


@test
def ns_links():
    """/proc/self/ns has the namespace links, and a child shares ours."""
    d = "/proc/self/ns"
    if not os.path.isdir(d):
        skip("no /proc/self/ns")
    names = set(os.listdir(d))
    # pid/user/... exist only if the kernel was built with them (Android often isn't)
    for n in ("mnt", "net"):
        check(n in names, f"/proc/self/ns lacks {n}")
    mine = {n: os.readlink(f"{d}/{n}") for n in sorted(names) if not n.endswith("_for_children")}
    check(all(v.startswith(f"{k}:[") for k, v in mine.items()), f"ns link format {mine}")
    r, w = os.pipe()
    pid = spawn(lambda: os.write(w, repr({n: os.readlink(f"{d}/{n}") for n in mine}).encode()) and 0)
    eq(os.read(r, 4096).decode(), repr(mine), "a child's namespaces")
    reap(pid)
    return ", ".join(sorted(names))


@test(host=True)
def new_uts_namespace():
    """unshare(CLONE_NEWUTS) gives a private hostname, root or user-ns."""
    def child():
        rc = enter(CLONE_NEWUTS)
        if rc:
            return rc
        name = b"lxt-ns-host"
        if libc.sethostname(name, len(name)) != 0:
            return 2
        return 0 if socket.gethostname() == "lxt-ns-host" else 3

    before = socket.gethostname()
    rc = reap(spawn(child))
    if rc >= 100:
        skip(f"unshare refused: {errno.errorcode.get(rc - 100, rc - 100)}")
    eq(rc, 0, "hostname inside the new uts namespace")
    eq(socket.gethostname(), before, "hostname outside")
    return f"private hostname; outside still {before!r}"


@test(host=True)
def new_mount_namespace():
    """unshare(CLONE_NEWNS) + a private tmpfs mount nobody else sees."""
    os.mkdir("m")
    here = os.path.abspath("m")

    def child():
        rc = enter(CLONE_NEWNS)
        if rc:
            return rc
        if libc.mount(b"none", b"/", None, 0x40000 | 0x4000, None) != 0:   # MS_REC|MS_PRIVATE
            return 2
        if libc.mount(b"tmpfs", here.encode(), b"tmpfs", 0, None) != 0:
            return 3
        with open(os.path.join(here, "inside"), "w") as f:
            f.write("x")
        return 0

    rc = reap(spawn(child))
    if rc >= 100:
        skip(f"unshare refused: {errno.errorcode.get(rc - 100, rc - 100)}")
    eq(rc, 0, "mount inside the new namespace")
    eq(os.listdir("m"), [], "the private mount leaked out")
    return "private tmpfs stayed private"


@test
def hostname_is_consistent():
    """uname, gethostname and /proc agree on the hostname."""
    n = os.uname().nodename
    eq(socket.gethostname(), n, "gethostname vs uname")
    with open("/proc/sys/kernel/hostname") as f:
        eq(f.read().strip(), n, "/proc/sys/kernel/hostname")
    return n
