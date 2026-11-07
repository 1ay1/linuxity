"""/proc: the kernel's view of processes and the machine."""
import mmap
import os
import signal
import sys
import threading
import time

from lxt import check, eq, expect_errno, napper, proc_status, reap, spawn, test, wait_until
import errno


@test
def self_identity():
    """/proc/self, stat, status, exe and cmdline agree with the syscalls."""
    me = os.getpid()
    eq(os.readlink("/proc/self"), str(me), "/proc/self")
    with open("/proc/self/stat") as f:
        raw = f.read()
    eq(int(raw.split()[0]), me, "stat pid")
    comm = raw[raw.index("(") + 1:raw.rindex(")")]
    with open("/proc/self/comm") as f:
        eq(f.read().strip(), comm, "comm vs stat's (comm)")
    fields = raw.rsplit(")", 1)[1].split()
    eq((int(fields[1]), int(fields[2]), int(fields[3])),
       (os.getppid(), os.getpgrp(), os.getsid(0)), "stat ppid/pgrp/sid")
    st = proc_status()
    eq((int(st["Pid"]), int(st["PPid"]), int(st["Tgid"])), (me, os.getppid(), me), "status ids")
    eq(st["Uid"].split()[0], str(os.getuid()), "status Uid")
    eq(os.path.realpath("/proc/self/exe"), os.path.realpath(sys.executable), "exe")
    with open("/proc/self/cmdline", "rb") as f:
        argv = f.read().rstrip(b"\0").split(b"\0")
    check(b"python" in os.path.basename(argv[0]), f"cmdline argv0 {argv[0]!r}")
    eq(os.readlink("/proc/self/cwd"), os.getcwd(), "cwd link")
    with open("/proc/self/environ", "rb") as f:
        env = dict(kv.split(b"=", 1) for kv in f.read().split(b"\0") if b"=" in kv)
    check(b"PATH" in env, "environ has no PATH")
    return f"pid {me}, comm {comm!r}"


@test
def fd_table():
    """/proc/self/fd and fdinfo track opens, closes, offsets and deleted files."""
    fds = [os.open("/dev/null", os.O_RDONLY) for _ in range(50)]
    check(all(os.readlink(f"/proc/self/fd/{x}") == "/dev/null" for x in fds), "fd links")
    listed = set(os.listdir("/proc/self/fd"))
    check(all(str(x) in listed for x in fds), "fd dir listing")
    for x in fds:
        os.close(x)
    for x in fds:
        expect_errno(errno.ENOENT, "closed fd in /proc", os.readlink, f"/proc/self/fd/{x}")
    fd = os.open("pos", os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)
    os.write(fd, b"x" * 1234)
    with open(f"/proc/self/fdinfo/{fd}") as f:
        info = f.read()
    check("pos:\t1234" in info, f"fdinfo pos: {info!r}")
    flags = int(info.split("flags:")[1].split()[0], 8)
    check(flags & os.O_APPEND and flags & 3 == os.O_RDWR, f"fdinfo flags {oct(flags)}")
    os.unlink("pos")
    check(os.readlink(f"/proc/self/fd/{fd}").endswith("/pos (deleted)"), "deleted file's link")
    r, w = os.pipe()
    check(os.readlink(f"/proc/self/fd/{r}").startswith("pipe:["), "pipe link")
    with open(f"/proc/self/fd/{fd}", "rb") as f:
        eq(f.read(), b"x" * 1234, "reopen a deleted file through /proc")
    return "links, listing, fdinfo pos/flags, (deleted), pipe:[], reopen"


@test
def maps_follow_mmap():
    """/proc/self/maps shows a mapping appear, change protection and go."""
    def find(addr):
        with open("/proc/self/maps") as f:
            for ln in f:
                lo, hi = (int(x, 16) for x in ln.split()[0].split("-"))
                if lo <= addr < hi:
                    return ln.split()[1]
        return None

    import ctypes
    m = mmap.mmap(-1, 1 << 20, prot=mmap.PROT_READ | mmap.PROT_WRITE)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(m))
    check(find(addr) and find(addr).startswith("rw"), f"new mapping perms {find(addr)}")
    libc = ctypes.CDLL(None, use_errno=True)
    check(libc.mprotect(ctypes.c_void_p(addr), 4096, 1) == 0, "mprotect")
    eq(find(addr)[:3], "r--", "perms after mprotect(PROT_READ)")
    with open("/proc/self/maps") as f:
        text = f.read()
    for want in ("[stack]", "python"):
        check(want in text, f"maps lacks {want!r}")
    check(libc.munmap(ctypes.c_void_p(addr), 1 << 20) == 0, "munmap")
    eq(find(addr), None, "mapping after munmap")
    return "appear, mprotect, [stack], exe, munmap"


@test
def threads_in_task():
    """task/ and Threads: list every live thread, and only those."""
    ev = threading.Event()
    ts = [threading.Thread(target=ev.wait) for _ in range(7)]
    for t in ts:
        t.start()
    tasks = sorted(os.listdir("/proc/self/task"), key=int)
    eq(len(tasks), 8, "task/ entries with 7 threads")
    check(all(str(t.native_id) in tasks for t in ts), "thread tids missing from task/")
    eq(int(proc_status()["Threads"]), 8, "Threads:")
    with open(f"/proc/self/task/{ts[0].native_id}/stat") as f:
        eq(int(f.read().split()[0]), ts[0].native_id, "a thread's own stat")
    ev.set()
    for t in ts:
        t.join()
    wait_until(lambda: len(os.listdir("/proc/self/task")) == 1, 5, "exited threads to leave task/")
    return "8 tasks listed, Threads: 8, then 1"


@test
def comm_renames():
    """Writing comm renames the thread, like PR_SET_NAME, cut to 15 bytes."""
    import ctypes
    libc = ctypes.CDLL(None)

    def get():
        b = ctypes.create_string_buffer(16)
        libc.prctl(16, b, 0, 0, 0)
        return b.value

    def comm(p="/proc/self/comm"):
        with open(p) as f:
            return f.read()

    with open("/proc/self/comm", "w") as f:
        f.write("lxt-a")
    eq(comm(), "lxt-a\n", "comm after a write")
    eq(get(), b"lxt-a", "PR_GET_NAME after a write")
    with open("/proc/self/comm", "w") as f:
        f.write("a-very-long-name-here")
    eq(comm(), "a-very-long-nam\n", "comm is cut to 15 bytes")
    libc.prctl(15, b"lxt-prctl", 0, 0, 0)
    eq(comm(), "lxt-prctl\n", "comm after PR_SET_NAME")
    seen = {}

    def worker():
        with open("/proc/thread-self/comm", "w") as f:
            f.write("lxt-worker")
        seen["get"] = get()
        seen["tid"] = threading.get_native_id()
        seen["task"] = comm(f"/proc/self/task/{seen['tid']}/comm")

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    eq(seen.get("get"), b"lxt-worker", "the thread's own name")
    eq(seen.get("task"), "lxt-worker\n", "task/<tid>/comm")
    eq(comm(), "lxt-prctl\n", "a thread's rename leaves the process name")
    return "write, 15-byte cut, PR_SET_NAME, per thread"


@test
def other_processes():
    """A child's /proc entry: parent, state, cwd, and gone once reaped."""
    me = os.getpid()
    pid = spawn(napper)
    wait_until(lambda: os.path.exists(f"/proc/{pid}/status"), 5, "child's /proc entry")
    eq(int(proc_status(pid)["PPid"]), me, "child's PPid")
    eq(os.readlink(f"/proc/{pid}/cwd"), os.getcwd(), "child's cwd")
    eq(os.path.realpath(f"/proc/{pid}/exe"), os.path.realpath(sys.executable), "child's exe")
    check(str(pid) in os.listdir("/proc"), "child missing from /proc listing")
    os.kill(pid, signal.SIGSTOP)
    wait_until(lambda: proc_status(pid)["State"].startswith("T"), 5, "state T")
    os.kill(pid, signal.SIGKILL)
    reap(pid)
    check(not os.path.exists(f"/proc/{pid}"), "reaped child still in /proc")
    eq(proc_status(1)["Pid"], "1", "/proc/1")
    return "PPid, cwd, exe, listing, state T, gone after reap"


@test
def system_files():
    """The machine-wide files parse the way tools parse them, and agree."""
    ncpu = os.cpu_count()
    with open("/proc/stat") as f:
        stat = f.read().splitlines()
    eq(sum(1 for l in stat if l.startswith("cpu") and l[3].isdigit()), ncpu, "cpuN lines in /proc/stat")
    check(any(l.startswith("btime ") for l in stat), "/proc/stat btime")
    with open("/proc/meminfo") as f:
        mem = {l.split(":")[0]: int(l.split()[1]) for l in f if l.split()[1:2] and l.split()[1].isdigit()}
    for k in ("MemTotal", "MemFree", "MemAvailable", "Cached", "SwapTotal"):
        check(k in mem, f"meminfo lacks {k}")
    check(0 < mem["MemAvailable"] <= mem["MemTotal"], "MemAvailable vs MemTotal")
    import ctypes

    class Sysinfo(ctypes.Structure):
        _fields_ = [("uptime", ctypes.c_long), ("loads", ctypes.c_ulong * 3),
                    ("totalram", ctypes.c_ulong), ("freeram", ctypes.c_ulong),
                    ("sharedram", ctypes.c_ulong), ("bufferram", ctypes.c_ulong),
                    ("totalswap", ctypes.c_ulong), ("freeswap", ctypes.c_ulong),
                    ("procs", ctypes.c_ushort), ("pad", ctypes.c_ushort),
                    ("totalhigh", ctypes.c_ulong), ("freehigh", ctypes.c_ulong),
                    ("mem_unit", ctypes.c_uint), ("_f", ctypes.c_char * 8)]
    si = Sysinfo()
    check(ctypes.CDLL(None).sysinfo(ctypes.byref(si)) == 0, "sysinfo")
    eq(si.totalram * si.mem_unit // 1024, mem["MemTotal"], "sysinfo totalram vs MemTotal")
    with open("/proc/uptime") as f:
        up1 = float(f.read().split()[0])
    time.sleep(0.2)
    with open("/proc/uptime") as f:
        up2 = float(f.read().split()[0])
    check(0.1 <= up2 - up1 < 2, f"uptime moved {up2 - up1:.2f}s in 0.2s")
    check(abs(si.uptime - up2) < 3, "sysinfo uptime vs /proc/uptime")
    with open("/proc/cpuinfo") as f:
        key = "processor"
        eq(sum(1 for l in f if l.split(":")[0].strip() == key), ncpu, "cpuinfo processors")
    with open("/proc/loadavg") as f:
        la = f.read().split()
    check(len(la) == 5 and "/" in la[3], f"loadavg {la}")
    with open("/proc/version") as f:
        check(os.uname().release in f.read(), "/proc/version lacks the release")
    with open("/proc/sys/kernel/osrelease") as f:
        eq(f.read().strip(), os.uname().release, "osrelease")
    with open("/proc/sys/kernel/hostname") as f:
        eq(f.read().strip(), os.uname().nodename, "hostname")
    for name in ("interrupts", "softirqs", "filesystems", "mounts", "swaps", "partitions"):
        with open(f"/proc/{name}") as f:
            f.read()
    with open("/proc/interrupts") as f:
        eq(f.readline().split(), [f"CPU{i}" for i in range(ncpu)], "/proc/interrupts header")
    with open("/proc/sys/kernel/random/uuid") as f:
        a = f.read().strip()
    with open("/proc/sys/kernel/random/uuid") as f:
        check(a != f.read().strip() and len(a) == 36, "random/uuid")
    return f"{ncpu} cpus, {mem['MemTotal'] // 1024} MiB, uptime/sysinfo agree"


@test
def mountinfo():
    """mounts and mountinfo list / and /proc, and agree with each other."""
    with open("/proc/self/mountinfo") as f:
        info = [l.split() for l in f]
    with open("/proc/self/mounts") as f:
        mounts = [l.split() for l in f]
    points = {l[4] for l in info}
    for p in ("/", "/proc"):
        check(p in points, f"mountinfo lacks {p}")
    eq({m[1] for m in mounts}, points, "mounts vs mountinfo mount points")
    check(all(" - " in " ".join(l) for l in info), "mountinfo lines lack the ' - ' separator")
    if os.path.islink("/etc/mtab"):
        with open("/etc/mtab") as f:
            eq([l.split()[1] for l in f], [m[1] for m in mounts], "/etc/mtab vs /proc/self/mounts")
    return f"{len(info)} mounts"
