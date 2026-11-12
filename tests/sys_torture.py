#!/usr/bin/env python3
"""sys_torture.py -- the kernel's own interfaces: identity (uname, hostname,
os-release), credentials, capabilities, rlimits, /proc, /sys, sysconf,
namespaces, seccomp, landlock and ptrace. See torture.py for running."""
import sys
sys.dont_write_bytecode = True
import ctypes
import errno
import grp
import os
import platform
import pwd
import re
import resource
import signal
import struct
import time

from torture import *  # noqa: F401,F403
from torture import check, ok, eq, expect_errno, child, status, run_in_child, Skip, main, libc, ROOT, ARCH, need_root


def read(p):
    with open(p) as f:
        return f.read()


def status_field(name, pid="self"):
    for l in read(f"/proc/{pid}/status").splitlines():
        if l.startswith(name + ":"):
            return l.split(":", 1)[1].strip()
    return None


# ---------------------------------------------------------------- identity

@check
def uname_and_friends_agree():
    u = os.uname()
    eq(u.sysname, "Linux", "sysname")
    ok(re.match(r"\d+\.\d+", u.release), f"release looks like a kernel version: {u.release}")
    ok(u.machine in ("aarch64", "x86_64"), f"machine {u.machine}")
    eq(read("/proc/sys/kernel/ostype").strip(), u.sysname, "/proc/sys/kernel/ostype")
    eq(read("/proc/sys/kernel/osrelease").strip(), u.release, "/proc/sys/kernel/osrelease")
    eq(read("/proc/sys/kernel/hostname").strip(), u.nodename, "/proc/sys/kernel/hostname")
    ok(u.release in read("/proc/version"), "/proc/version names the release")
    eq(platform.machine(), u.machine, "platform.machine")
    rel = dict(l.split("=", 1) for l in read("/etc/os-release").splitlines() if "=" in l)
    ok("ID" in rel and "VERSION_ID" in rel or "NAME" in rel, "/etc/os-release")


@check
def hostname_in_a_uts_namespace():
    def body():
        try:
            os.unshare(os.CLONE_NEWUTS | (0 if ROOT else os.CLONE_NEWUSER))
            __import__("socket").sethostname("torture-ns")
        except OSError:
            return 77                                # refused: say so, below
        return 0 if os.uname().nodename == "torture-ns" == read("/proc/sys/kernel/hostname").strip() else 1
    before = os.uname().nodename
    rc = run_in_child(body)
    if rc == 77:
        raise Skip("unshare(CLONE_NEWUTS) or sethostname refused here")
    eq(rc, 0, "sethostname inside the namespace")
    eq(os.uname().nodename, before, "outside, the name is unchanged")


# ---------------------------------------------------------------- credentials

@check
def credentials_are_consistent():
    uid, gid = os.getuid(), os.getgid()
    pw = pwd.getpwuid(uid)
    eq(pw.pw_uid, uid, "getpwuid")
    eq(grp.getgrgid(gid).gr_gid, gid, "getgrgid")
    r, e, s = os.getresuid()
    eq((r, e, s), (uid, os.geteuid(), uid), "getresuid")
    eq(status_field("Uid").split(), [str(uid), str(os.geteuid()), str(uid), str(os.geteuid())],
       "/proc/self/status Uid")
    eq(status_field("Gid").split()[0], str(gid), "/proc/self/status Gid")
    groups = set(os.getgroups())
    eq(set(map(int, status_field("Groups").split())), groups, "Groups:")
    ok(gid in groups or not groups or ROOT, "the primary group is a member")
    eq(pwd.getpwnam(pw.pw_name).pw_uid, uid, "getpwnam round-trips")
    if os.environ.get("HOME"):
        eq(os.path.expanduser("~"), os.environ["HOME"], "~ is $HOME")


@check
def root_can_drop_privileges_for_good():
    need_root()

    def body():
        os.setgroups([])
        os.setresgid(1000, 1000, 1000)
        os.setresuid(1000, 1000, 1000)
        if os.getresuid() != (1000, 1000, 1000):
            return 1
        try:
            os.setuid(0)
            return 2
        except PermissionError:
            pass
        if status_field("CapEff") != "0000000000000000":
            return 3
        try:
            open("/etc/shadow").close()
            return 4
        except PermissionError:
            return 0
    eq(run_in_child(body), 0, "setuid(1000) is final: no way back, no capabilities, no /etc/shadow")

    def saved():
        os.setresuid(1000, 1000, 0)                # keep root as the SAVED uid
        os.seteuid(0)                              # ...so this is allowed
        return 0 if os.geteuid() == 0 else 1
    eq(run_in_child(saved), 0, "a saved uid of 0 can be returned to")


@check
def capabilities_match_the_uid():
    eff = int(status_field("CapEff"), 16)
    bnd = int(status_field("CapBnd"), 16)
    if ROOT:
        ok(eff & 1 and eff & (1 << 21), f"root holds CAP_CHOWN and CAP_SYS_ADMIN ({eff:#x})")
    else:
        eq(eff, 0, "an ordinary user holds no capabilities")
    ok(bnd & 1, "CAP_CHOWN is in the bounding set")
    PR_CAPBSET_READ, PR_GET_NO_NEW_PRIVS, PR_SET_NO_NEW_PRIVS = 23, 39, 38
    eq(libc.prctl(PR_CAPBSET_READ, 0, 0, 0, 0), 1, "PR_CAPBSET_READ(CAP_CHOWN)")

    def nnp():
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        return 0 if libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 and status_field("NoNewPrivs") == "1" else 1
    eq(run_in_child(nnp), 0, "PR_SET_NO_NEW_PRIVS sticks and shows in status")


@check
def rlimits_obey_soft_and_hard():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    ok(0 < soft <= hard, f"NOFILE {soft}/{hard}")
    eq(os.sysconf("SC_OPEN_MAX"), soft, "sysconf(SC_OPEN_MAX) is the soft limit")
    limits = read("/proc/self/limits")
    ok(re.search(rf"Max open files\s+{soft}\s+{hard if hard != resource.RLIM_INFINITY else 'unlimited'}", limits),
       "/proc/self/limits agrees")

    def body():
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, hard))
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))      # soft back up to hard: fine
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 256))     # raising hard
            return 0 if ROOT else 1
        except (ValueError, OSError):
            return 1 if ROOT else 0
    eq(run_in_child(body), 0, "only root may raise a hard limit")
    pr = resource.prlimit(os.getpid(), resource.RLIMIT_STACK)
    eq(pr, resource.getrlimit(resource.RLIMIT_STACK), "prlimit on ourselves")


# ---------------------------------------------------------------- /proc and /sys

@check
def proc_system_files_parse():
    cpus = [l for l in read("/proc/cpuinfo").splitlines() if l.startswith("processor")]
    eq(len(cpus), os.cpu_count(), "/proc/cpuinfo processors == cpu_count")
    st = read("/proc/stat").splitlines()
    eq(len([l for l in st if re.match(r"cpu\d+ ", l)]), os.cpu_count(), "/proc/stat per-cpu lines")
    ok(any(l.startswith("btime ") for l in st), "/proc/stat btime")
    la = read("/proc/loadavg").split()
    ok(len(la) == 5 and "/" in la[3], f"/proc/loadavg: {la}")
    ok(abs(os.getloadavg()[0] - float(la[0])) < 0.1, "getloadavg (glibc reads sysinfo; /proc rounds)")
    u1 = float(read("/proc/uptime").split()[0]); time.sleep(0.2)
    ok(float(read("/proc/uptime").split()[0]) > u1, "/proc/uptime advances")
    ok("proc" in read("/proc/filesystems"), "/proc/filesystems")
    pid_max = int(read("/proc/sys/kernel/pid_max"))
    ok(pid_max >= 32768, f"pid_max {pid_max}")
    ok(int(read("/proc/sys/fs/file-max")) > 0, "fs/file-max")
    mounts = [l.split() for l in read("/proc/self/mounts").splitlines()]
    kinds = {m[1]: m[2] for m in mounts}
    eq(kinds.get("/proc"), "proc", "/proc is a proc mount")
    eq(kinds.get("/sys"), "sysfs", "/sys is sysfs")
    ok(kinds.get("/dev/pts") == "devpts", "/dev/pts is devpts")
    mi = read("/proc/self/mountinfo").splitlines()
    ok(all(" - " in l for l in mi), "mountinfo lines have the separator")


@check
def proc_self_and_a_child():
    eq(os.readlink("/proc/self"), str(os.getpid()), "/proc/self")
    eq(os.readlink("/proc/self/cwd"), os.getcwd(), "/proc/self/cwd")
    eq(os.path.realpath("/proc/self/exe"), os.path.realpath(sys.executable), "/proc/self/exe")
    env = read("/proc/self/environ").split("\0")
    ok("PATH=" + os.environ["PATH"] in env, "/proc/self/environ has PATH")
    cmd = read("/proc/self/cmdline").split("\0")
    ok(any(sys.argv[0] in c for c in cmd), f"/proc/self/cmdline: {cmd[:3]}")
    statm = read("/proc/self/statm").split()
    ok(len(statm) == 7 and int(statm[1]) > 0, "statm")
    io = read("/proc/self/io")
    ok("rchar:" in io and "write_bytes:" in io, "/proc/self/io")
    cg = read("/proc/self/cgroup")
    ok(cg.startswith("0::") or ":" in cg, f"/proc/self/cgroup: {cg[:40]!r}")
    ok(os.listdir("/proc/self/fd"), "/proc/self/fd")
    r, w = os.pipe()

    def kid():
        os.read(r, 1)
        return 0
    pid = child(kid)
    time.sleep(0.2)
    s = read(f"/proc/{pid}/stat")
    fields = s[s.rindex(")") + 2:].split()
    eq((fields[0], int(fields[1])), ("S", os.getpid()), "a blocked child is S with us as parent")
    eq(read(f"/proc/{pid}/comm").strip(), read("/proc/self/comm").strip(), "a fork's comm is its parent's")
    ok(str(pid) in os.listdir("/proc"), "the child is listed in /proc")
    os.write(w, b"x"); status(pid)
    ok(not os.path.exists(f"/proc/{pid}"), "and gone once reaped")


@check
def sys_and_sysconf_agree():
    n = os.cpu_count()
    online = read("/sys/devices/system/cpu/online").strip()
    eq(online, "0" if n == 1 else f"0-{n - 1}", "/sys/.../cpu/online")
    eq(os.sysconf("SC_NPROCESSORS_ONLN"), n, "SC_NPROCESSORS_ONLN")
    # pinned (taskset, or linuxity keeping a phone on its fast cores) the
    # affinity is a subset, natively too
    aff = os.sched_getaffinity(0)
    ok(aff and aff <= set(range(n)), "affinity is a set of online cpus")
    eq(os.sysconf("SC_CLK_TCK"), 100, "USER_HZ")
    ok(os.path.exists("/sys/class/net/lo"), "/sys/class/net/lo")
    try:
        eq(read("/sys/class/net/lo/address").strip(), "00:00:00:00:00:00", "lo's address")
    except PermissionError:
        pass   # the host refuses it (Android's SELinux), natively too
    ok(os.path.isdir("/sys/fs/cgroup"), "/sys/fs/cgroup")
    ok(os.listdir("/sys/devices/system/cpu/cpu0"), "cpu0 has attributes")


@check
def locale_and_encodings():
    import locale
    eq(sys.getfilesystemencoding(), "utf-8", "filesystem encoding")
    for name in ("C.UTF-8", "C"):
        locale.setlocale(locale.LC_ALL, name)
    ok(locale.nl_langinfo(locale.CODESET) in ("ANSI_X3.4-1968", "UTF-8"), "nl_langinfo")
    locale.setlocale(locale.LC_ALL, "C.UTF-8")
    eq(locale.nl_langinfo(locale.CODESET), "UTF-8", "C.UTF-8 is UTF-8")
    eq("Straße".upper(), "STRASSE", "unicode works")


# ---------------------------------------------------------------- namespaces & sandboxes

@check
def namespaces_are_listed():
    names = os.listdir("/proc/self/ns")
    for n in ("pid", "mnt", "net", "uts", "ipc", "user"):
        ok(n in names, f"/proc/self/ns/{n}")
        ok(re.match(rf"{n}:\[\d+\]", os.readlink(f"/proc/self/ns/{n}")), f"ns/{n} link format")
    eq(os.readlink("/proc/self/ns/pid"), os.readlink(f"/proc/{os.getppid()}/ns/pid") if
       os.path.exists(f"/proc/{os.getppid()}/ns/pid") else os.readlink("/proc/self/ns/pid"),
       "our parent shares our pid namespace")


@check
def pid_namespace_makes_its_own_init():
    def body():
        flags = os.CLONE_NEWPID | (0 if ROOT else os.CLONE_NEWUSER)
        try:
            os.unshare(flags)
        except OSError:
            return 77
        pid = os.fork()
        if pid == 0:
            os._exit(0 if os.getpid() == 1 else 1)
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
    rc = run_in_child(body)
    if rc == 77:
        raise Skip("unshare(CLONE_NEWPID) refused here")
    eq(rc, 0, "the first child in a new pid namespace is pid 1")


@check
def seccomp_strict_and_filter():
    PR_SET_SECCOMP, SECCOMP_MODE_STRICT = 22, 1

    def strict():
        r, w = os.pipe()
        libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0, 0, 0)
        os.write(w, b"x")                            # write is allowed
        os.getpid()                                  # not on the list: SIGKILL
        return 1
    eq(run_in_child(strict), -signal.SIGKILL, "strict mode kills on any other syscall")
    eq(status_field("Seccomp"), "0", "and we ourselves are unfiltered")


@check
def landlock_restricts_paths():
    LANDLOCK_CREATE_RULESET, LANDLOCK_ADD_RULE, LANDLOCK_RESTRICT_SELF = {
        "aarch64": (444, 445, 446), "x86_64": (444, 445, 446)}[ARCH]
    abi = libc.syscall(LANDLOCK_CREATE_RULESET, None, 0, 1)     # LANDLOCK_CREATE_RULESET_VERSION
    if abi < 1:
        raise Skip(f"no landlock ({errname(ctypes.get_errno())})")
    os.mkdir("allowed"); os.mkdir("denied")
    open("allowed/f", "w").write("ok"); open("denied/f", "w").write("no")

    def body():
        READ_FILE, READ_DIR = 1 << 2, 1 << 3
        WRITE_FILE = 1 << 1
        handled = READ_FILE | READ_DIR | WRITE_FILE
        attr = struct.pack("Q", handled)
        rs = libc.syscall(LANDLOCK_CREATE_RULESET, attr, len(attr), 0)
        if rs < 0:
            return 10
        fd = os.open("allowed", os.O_PATH)
        rule = struct.pack("=Qi", READ_FILE | READ_DIR, fd)
        if libc.syscall(LANDLOCK_ADD_RULE, rs, 1, rule, 0) != 0:   # LANDLOCK_RULE_PATH_BENEATH
            return 11
        libc.prctl(38, 1, 0, 0, 0)                                  # no_new_privs
        if libc.syscall(LANDLOCK_RESTRICT_SELF, rs, 0) != 0:
            return 12
        if open("allowed/f").read() != "ok":
            return 13
        try:
            open("denied/f").read()
            return 14
        except PermissionError:
            pass
        try:
            open("allowed/f", "w")
            return 15
        except PermissionError:
            return 0
    eq(run_in_child(body), 0, "read beneath allowed/ only, no writes (10-15 name the failing step)")


@check
def ptrace_traceme_exec_and_syscall_stops():
    PTRACE_TRACEME, PTRACE_CONT, PTRACE_SYSCALL, PTRACE_PEEKUSER = 0, 7, 24, 3
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
    pid = os.fork()
    if pid == 0:
        libc.ptrace(PTRACE_TRACEME, 0, None, None)
        os.execv("/bin/true", ["true"])
        os._exit(127)
    _, st = os.waitpid(pid, 0)
    ok(os.WIFSTOPPED(st) and os.WSTOPSIG(st) == signal.SIGTRAP, f"stopped by SIGTRAP at exec ({st:#x})")
    eq(status_field("State", pid).split()[0], "t", "state t (tracing stop) while stopped for us")
    eq(int(status_field("TracerPid", pid)), os.getpid(), "TracerPid names us")
    stops = 0
    while True:
        eq(libc.ptrace(PTRACE_SYSCALL, pid, None, None), 0, f"PTRACE_SYSCALL ({errname(ctypes.get_errno())})")
        _, st = os.waitpid(pid, 0)
        if os.WIFEXITED(st):
            break
        stops += 1
        if stops > 100000:
            break
    eq(os.WEXITSTATUS(st), 0, "the tracee ran to completion")
    ok(stops >= 4, f"syscall entry/exit stops seen ({stops})")


if __name__ == "__main__":
    sys.exit(main("kernel interfaces"))
