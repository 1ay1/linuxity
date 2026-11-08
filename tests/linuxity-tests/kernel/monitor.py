"""What a system monitor reads: live /proc files, the hardware in /sys, the
mount table, per-process memory. Each check is one a real kernel passes."""
import os
import socket
import stat
import subprocess
import time

from lxt import check, eq, skip, test


def read(p):
    with open(p) as f:
        return f.read()


def spin(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        pass


@test
def reread_kept_open():
    """A kept-open /proc file reread from offset 0 gives fresh data, as top
    and rb read /proc/<pid>/stat every tick."""
    fd = os.open("/proc/self/stat", os.O_RDONLY)
    try:
        before = int(os.pread(fd, 4096, 0).split()[13])
        spin(0.4)
        after = int(os.pread(fd, 4096, 0).split()[13])
        check(after > before, f"utime frozen on pread: {before} then {after}")
        spin(0.2)
        os.lseek(fd, 0, os.SEEK_SET)
        again = int(os.read(fd, 4096).split()[13])
        check(again >= after, f"utime went back after lseek: {after} then {again}")
    finally:
        os.close(fd)
    return f"utime {before} -> {after} -> {again}"


@test
def proc_per_process_memory():
    """statm and smaps_rollup are the task's real memory, not placeholders."""
    blob = bytearray(64 << 20)          # touch 64 MiB
    for i in range(0, len(blob), 4096):
        blob[i] = 1
    page = os.sysconf("SC_PAGE_SIZE")
    size, resident = (int(x) for x in read("/proc/self/statm").split()[:2])
    check(resident * page >= 60 << 20, f"statm resident {resident * page >> 20} MiB < 60")
    check(size >= resident, "statm size below resident")
    rss = int(read("/proc/self/status").split("VmRSS:")[1].split()[0])
    check(abs(rss * 1024 - resident * page) < 16 << 20, "statm and VmRSS disagree")
    if os.path.exists("/proc/self/smaps_rollup"):
        roll = read("/proc/self/smaps_rollup")
        check("Rss:" in roll and "Pss:" in roll, "smaps_rollup lacks Rss/Pss")
    del blob
    return f"resident {resident * page >> 20} MiB"


@test
def proc_per_process_counters():
    """io counts real reads, children lists real children, fd shows sockets."""
    before = int(read("/proc/self/io").split("rchar:")[1].split()[0])
    r, w = os.pipe()
    os.write(w, b"x" * 60000)
    got = len(os.read(r, 65536))
    os.close(r)
    os.close(w)
    after = int(read("/proc/self/io").split("rchar:")[1].split()[0])
    check(after - before >= got, f"rchar grew {after - before}, read {got}")
    p = subprocess.Popen(["sleep", "5"])
    try:
        kids = read(f"/proc/{os.getpid()}/task/{os.getpid()}/children").split()
        check(str(p.pid) in kids, f"children {kids} lacks {p.pid}")
    finally:
        p.kill()
        p.wait()
    s = socket.socket()
    try:
        links = [os.readlink(f"/proc/self/fd/{n}") for n in os.listdir("/proc/self/fd")
                 if n.isdigit() and os.path.exists(f"/proc/self/fd/{n}")]
        ino = os.fstat(s.fileno()).st_ino
        check(f"socket:[{ino}]" in links, f"socket:[{ino}] not among fd links")
    finally:
        s.close()
    return f"rchar +{after - before}, child listed, socket in fd/"


@test
def oom_score_adj_writable():
    """oom_score_adj reads back what was written (raising needs no privilege)."""
    cur = int(read("/proc/self/oom_score_adj"))
    new = min(cur + 100, 1000)
    with open("/proc/self/oom_score_adj", "w") as f:
        f.write(str(new))
    eq(int(read("/proc/self/oom_score_adj")), new, "oom_score_adj after write")
    return f"{cur} -> {new}"


@test
def mount_table():
    """The root is a real filesystem with a device, and statvfs agrees with it."""
    rows = [l.split() for l in read("/proc/self/mounts").splitlines()]
    root = [r for r in rows if r[1] == "/"]
    check(root, "no / in /proc/self/mounts")
    dev, fstype = root[0][0], root[0][2]
    check(fstype not in ("rootfs", ""), f"root fstype is {fstype!r}")
    st = os.statvfs("/")
    check(st.f_blocks > 0, "statvfs(/) reports no blocks")
    info = [l.split() for l in read("/proc/self/mountinfo").splitlines()]
    mi = [r for r in info if r[4] == "/"]
    check(mi, "no / in mountinfo")
    sep = mi[0].index("-")
    eq(mi[0][sep + 1], fstype, "mountinfo fstype vs mounts")
    return f"/ is {fstype} on {dev}"


@test
def statx_mount_id():
    """statx reports a mount id and marks mount roots (systemd's path walk,
    and so libudev and lsusb, depend on both)."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "statx"):
        skip("libc has no statx")
    buf = ctypes.create_string_buffer(256)
    STATX_MNT_ID, AT_FDCWD = 0x1000, -100
    ids = {}
    for p in ("/", "/proc", "/proc/self/stat"):
        r = libc.statx(AT_FDCWD, p.encode(), 0, STATX_MNT_ID, buf)
        check(r == 0, f"statx({p}) failed: errno {ctypes.get_errno()}")
        mask = int.from_bytes(buf.raw[0:4], "little")
        check(mask & STATX_MNT_ID, f"statx({p}) did not return a mount id")
        attrs = int.from_bytes(buf.raw[8:16], "little")
        ids[p] = (int.from_bytes(buf.raw[144:152], "little"), bool(attrs & 0x2000))
    check(ids["/"][1] and ids["/proc"][1], "/ and /proc not marked mount roots")
    check(not ids["/proc/self/stat"][1], "/proc/self/stat marked a mount root")
    eq(ids["/proc"][0], ids["/proc/self/stat"][0], "mount id inside /proc")
    check(ids["/"][0] != ids["/proc"][0], "/ and /proc share a mount id")
    return f"/ {ids['/'][0]}, /proc {ids['/proc'][0]}"


@test
def sys_class_links_follow():
    """A /sys/class entry is a symlink to its device, and following it lands
    on a directory whose files read (sensors and lsusb walk these)."""
    seen = 0
    for cls in ("hwmon", "net", "block", "thermal", "power_supply"):
        base = f"/sys/class/{cls}"
        if not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base))[:4]:
            p = f"{base}/{name}"
            lst = os.lstat(p)
            if not stat.S_ISLNK(lst.st_mode):
                continue
            check(os.path.isdir(p), f"{p} does not follow to a directory")
            try:
                files = os.listdir(p)
            except PermissionError:
                continue        # the host's sandbox (Android) refuses it
            check(files and files != [name], f"{p} lists {files[:3]}")
            check(os.path.realpath(p).startswith("/sys/devices/"),
                  f"{p} resolves to {os.path.realpath(p)}")
            seen += 1
    if not seen:
        skip("no symlinked /sys/class entries here")
    return f"{seen} class links followed"


@test
def sys_missing_under_device():
    """A file a real device lacks is ENOENT, not a fallback from elsewhere."""
    base = "/sys/class/net/lo"
    if not os.path.isdir(base):
        skip("no /sys/class/net/lo")
    check(not os.path.exists(f"{base}/no_such_attribute"), "invented attribute under lo")
    try:
        state = read(f"{base}/operstate").strip()
    except PermissionError:
        return "lo attributes refused by the host, as natively"
    eq(state in ("unknown", "up", "down"), True, "lo operstate")
    return "lo has what it has"


@test
def cpu_topology_matches_cpuinfo():
    """The SMT layout in /sys agrees with /proc/cpuinfo's siblings and cores."""
    info = read("/proc/cpuinfo")
    if "siblings" not in info:
        skip("cpuinfo has no siblings line (arm64)")
    siblings = int(info.split("siblings")[1].split(":")[1].split()[0])
    cores = int(info.split("cpu cores")[1].split(":")[1].split()[0])
    t = read("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list").strip()
    per_core = sum(len(range(int(a), int(b or a) + 1))
                   for a, _, b in (x.partition("-") for x in t.split(",")))
    eq(per_core, siblings // cores, "threads per core: /sys vs cpuinfo")
    return f"{cores} cores x {per_core} threads"


@test
def pressure_matches_listing():
    """/proc/pressure lists what exists, and each listed file opens or is
    refused, never missing (Android hides some, which is EACCES)."""
    if not os.path.isdir("/proc/pressure"):
        skip("no PSI on this kernel")
    names = os.listdir("/proc/pressure")
    check(names, "empty /proc/pressure")
    opened = 0
    for n in names:
        try:
            body = read(f"/proc/pressure/{n}")
            check(body.startswith(("some ", "full ")), f"{n} reads {body[:20]!r}")
            opened += 1
        except PermissionError:
            pass
    return f"{opened}/{len(names)} readable"


@test
def landlock_walls_hold():
    """A Landlock ruleset is the kernel's: a write outside the granted tree is
    refused, inside it works, and a virtual /etc file still reads."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.syscall(444, None, 0, 1) < 1:
        skip("no landlock on this kernel")
    import tempfile
    ok_dir = tempfile.mkdtemp(dir=os.getcwd())
    no_dir = tempfile.mkdtemp(dir=os.getcwd())
    pid = os.fork()
    if pid == 0:
        class Attr(ctypes.Structure):
            _fields_ = [("h", ctypes.c_uint64)]
        class Rule(ctypes.Structure):
            _pack_ = 1
            _layout_ = "ms"
            _fields_ = [("a", ctypes.c_uint64), ("fd", ctypes.c_int32)]
        RF, RD, WF, MKREG, EXE = 4, 8, 2, 256, 1
        a = Attr(RF | RD | WF | MKREG | EXE)
        rs = libc.syscall(444, ctypes.byref(a), 8, 0)
        for p, acc in (("/usr", RF | RD | EXE), ("/etc", RF | RD), (ok_dir, RF | RD | WF | MKREG)):
            r = Rule(acc, os.open(p, os.O_PATH))
            if libc.syscall(445, rs, 1, ctypes.byref(r), 0) != 0:
                os._exit(10)
        libc.prctl(38, 1, 0, 0, 0)
        if libc.syscall(446, rs, 0) != 0:
            os._exit(11)
        try:
            open(os.path.join(ok_dir, "f"), "w").write("x")
        except OSError:
            os._exit(12)
        try:
            open(os.path.join(no_dir, "f"), "w").write("x")
            os._exit(13)
        except PermissionError:
            pass
        try:
            open("/etc/passwd").read(1)
        except OSError:
            os._exit(14)
        os._exit(0)
    _, st = os.waitpid(pid, 0)
    eq(os.waitstatus_to_exitcode(st), 0, "landlock child (10-14 name the failing step)")
    return "inside allowed, outside refused, /etc readable"


def _landlock(libc, handled_fs, rules, scoped=0):
    """In the calling (child) process: restrict to `rules`, a list of
    (path, access). Returns False if any step failed."""
    import ctypes
    class Attr(ctypes.Structure):
        _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("sc", ctypes.c_uint64)]
    class Rule(ctypes.Structure):
        _pack_ = 1
        _layout_ = "ms"
        _fields_ = [("a", ctypes.c_uint64), ("fd", ctypes.c_int32)]
    a = Attr(handled_fs, 0, scoped)
    rs = libc.syscall(444, ctypes.byref(a), 24, 0)
    if rs < 0:
        return False
    for p, acc in rules:
        r = Rule(acc, os.open(p, os.O_PATH))
        if libc.syscall(445, rs, 1, ctypes.byref(r), 0) != 0:
            return False
    libc.prctl(38, 1, 0, 0, 0)
    return libc.syscall(446, rs, 0) == 0


@test
def landlock_finer_points():
    """Landlock as the kernel does it: a rule follows its directory through a
    rename, ftruncate is judged by the rights the file was opened with, and
    the abstract-socket scope keeps a walled process from reaching a socket
    bound outside its walls."""
    import ctypes
    import errno
    import tempfile
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, None, 0, 1)
    if abi < 6:
        skip(f"landlock ABI {abi}, need 6")
    RF, WF, RD, RMF, MKREG, MKDIR, REFER, TRUNC = 4, 2, 8, 32, 256, 128, 1 << 13, 1 << 14
    base = tempfile.mkdtemp(dir=os.getcwd())
    os.makedirs(f"{base}/a/inner")
    with open(f"{base}/keep", "w") as f:
        f.write("x")
    early = os.open(f"{base}/keep", os.O_RDWR)    # opened before the walls
    outside = socket.socket(socket.AF_UNIX)
    name = b"\0lxt-scope-%d" % os.getpid()
    outside.bind(name)
    outside.listen(1)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        res = {}
        ok = _landlock(libc, RF | WF | RD | RMF | MKREG | MKDIR | REFER | TRUNC,
                       [("/", RF | RD), (base, RF | WF | RD | RMF | MKREG | MKDIR | REFER),
                        (f"{base}/a", TRUNC)], scoped=1)
        res["restrict"] = ok
        def e(fn):
            try:
                fn()
                return "ok"
            except OSError as x:
                return errno.errorcode.get(x.errno, str(x.errno))
        # the TRUNCATE rule on a/ follows a/ to b/
        res["rename"] = e(lambda: os.rename(f"{base}/a", f"{base}/b"))
        with open(f"{base}/b/inner/t", "w") as f:   # made in b: MKREG from base
            pass
        res["trunc in b"] = e(lambda: os.truncate(f"{base}/b/inner/t", 0))
        with open(f"{base}/n", "w"):
            pass
        res["trunc outside"] = e(lambda: os.truncate(f"{base}/n", 0))
        # ftruncate: a file opened after the walls keeps their rights; one
        # opened before keeps none of them
        fd = os.open(f"{base}/n", os.O_WRONLY)
        res["ftrunc new fd"] = e(lambda: os.ftruncate(fd, 0))
        res["ftrunc early fd"] = e(lambda: os.ftruncate(early, 0))
        # abstract sockets: one bound by the parent is outside the walls,
        # one bound by ourselves is inside
        s = socket.socket(socket.AF_UNIX)
        res["connect outside"] = e(lambda: s.connect(name))
        mine = socket.socket(socket.AF_UNIX)
        mine.bind(name + b"-in")
        mine.listen(1)
        s2 = socket.socket(socket.AF_UNIX)
        res["connect inside"] = e(lambda: s2.connect(name + b"-in"))
        os.write(w, repr(res).encode())
        os._exit(0)
    os.waitpid(pid, 0)
    got = eval(os.read(r, 4096).decode())
    want = {"restrict": True, "rename": "ok", "trunc in b": "ok", "trunc outside": "EACCES",
            "ftrunc new fd": "EACCES", "ftrunc early fd": "ok",
            "connect outside": "EPERM", "connect inside": "ok"}
    eq(got, want, "landlock answers")
    return "rename, ftruncate, abstract scope"
