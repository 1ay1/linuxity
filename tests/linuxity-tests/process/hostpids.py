"""--host-pids: the guest shares the host's pid space. Only meaningful when
linuxity runs with that flag (or natively, where it is simply true)."""
import os
import signal
import subprocess
import time

import lxt
from lxt import check, eq, skip, test


def host_pids():
    # Natively every process is visible. Under linuxity the pids are shared
    # only with --host-pids, and then linuxity itself shows up in /proc; in its
    # own pid space it never does. (Counting processes misleads: -j8 alone
    # makes our tree bigger than any threshold.)
    if lxt.ENV["kind"] != "linuxity":
        return True
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            with open(f"/proc/{p}/cmdline", "rb") as f:
                argv0 = f.read().split(b"\0")[0]
        except OSError:
            continue
        if os.path.basename(argv0).startswith((b"linuxity", b"liblinuxity")):
            return True
    return False


@test
def sees_other_processes():
    """/proc lists processes outside our tree, with real stat and cmdline."""
    if not host_pids():
        skip("private pid space")
    me = os.getpid()
    mine = {me}
    others = [int(p) for p in os.listdir("/proc") if p.isdigit() and int(p) not in mine]
    check(len(others) > 10, f"only {len(others)} other processes")
    named = 0
    for p in others[:50]:
        try:
            with open(f"/proc/{p}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            check(fields[0] in "RSDZTtIXKWP", f"/proc/{p}/stat state {fields[0]!r}")
            named += 1
        except (FileNotFoundError, ProcessLookupError):
            pass    # exited between listdir and open
    check(named > 5, "could read almost no other process's stat")
    return f"{len(others)} others, {named} read"


@test
def own_identity_consistent():
    """getpid, /proc/self and a child's getppid agree on one number."""
    me = os.getpid()
    eq(os.readlink("/proc/self"), str(me), "/proc/self link")
    with open("/proc/self/stat") as f:
        eq(int(f.read().split()[0]), me, "/proc/self/stat pid")
    out = subprocess.run(["sh", "-c", "echo $PPID"], capture_output=True, text=True).stdout
    eq(int(out), me, "child's PPID")
    return f"pid {me}"


@test
def child_gone_after_reap():
    """A reaped child leaves /proc at once, as the host says."""
    p = subprocess.Popen(["sleep", "10"])
    check(os.path.exists(f"/proc/{p.pid}"), "child missing from /proc")
    p.kill()
    p.wait()
    check(not os.path.exists(f"/proc/{p.pid}"), "reaped child still in /proc")
    return "gone after wait"


@test
def signal_permission_is_the_hosts():
    """Signalling a process we may not touch fails as the host decides."""
    if not host_pids():
        skip("private pid space")
    if os.geteuid() == 0 and os.path.exists("/proc/1/stat"):
        with open("/proc/1/status") as f:
            uid = int([l for l in f if l.startswith("Uid:")][0].split()[1])
        if uid == os.getuid():
            skip("we own pid 1")
    try:
        os.kill(1, 0)
        skip("allowed to signal pid 1 here")
    except PermissionError:
        pass
    return "EPERM for pid 1"
