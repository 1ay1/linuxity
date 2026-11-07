"""Credentials and capabilities."""
import ctypes
import errno
import os

from lxt import check, eq, expect_errno, libc, proc_status, reap, spawn, syscall, test


@test
def credential_sets():
    """getres[ug]id, groups and /proc/self/status tell the same story."""
    ruid, euid, suid = os.getresuid()
    rgid, egid, sgid = os.getresgid()
    st = proc_status()
    eq([int(x) for x in st["Uid"].split()[:3]], [ruid, euid, suid], "status Uid vs getresuid")
    eq([int(x) for x in st["Gid"].split()[:3]], [rgid, egid, sgid], "status Gid vs getresgid")
    groups = os.getgroups()
    eq(sorted(int(g) for g in st.get("Groups", "").split()), sorted(groups), "status Groups vs getgroups")
    eq(libc.getgroups(0, None), len(groups), "getgroups(0) counts")
    if len(groups) > 1:
        expect_errno(errno.EINVAL, "getgroups with too small a buffer", _getgroups, len(groups) - 1)
    return f"uid {ruid}/{euid}/{suid} gid {rgid}/{egid}/{sgid} groups {groups}"


def _getgroups(n):
    arr = (ctypes.c_uint * max(n, 1))()
    r = libc.getgroups(n, arr)
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


@test(root=True)
def root_can_change_identity():
    """Root may setgroups/setresuid; a child that drops privilege keeps it dropped."""
    os.setgroups([0, 10, 998])
    eq(sorted(os.getgroups()), [0, 10, 998], "setgroups read back")
    pid = spawn(lambda: 0 if sorted(os.getgroups()) == [0, 10, 998] else 1)
    eq(reap(pid), 0, "fork inherits groups")

    def drop():
        os.setgroups([])
        os.setresgid(65534, 65534, 65534)
        os.setresuid(65534, 65534, 65534)
        if os.getresuid() != (65534, 65534, 65534) or os.getgroups():
            return 2
        try:
            os.setuid(0)
            return 3    # regained root: privilege drop didn't stick
        except PermissionError:
            return 0

    eq(reap(spawn(drop)), 0, "drop to nobody and stay there")
    return "setgroups, inherit, irreversible setresuid drop"


@test(host=True)
def capability_sets():
    """capget, /proc/self/status Cap* and root-ness agree."""
    class Hdr(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                    ("inheritable", ctypes.c_uint32)]

    h = Hdr(0x20080522, 0)
    d = (Data * 2)()
    syscall("capget", ctypes.addressof(h), ctypes.addressof(d))
    eff = d[0].effective | (d[1].effective << 32)
    st = proc_status()
    eq(eff, int(st["CapEff"], 16), "capget effective vs CapEff")
    if os.geteuid() == 0:
        check(eff & (1 << 21), "root lacks CAP_SYS_ADMIN")   # in the environment's own view
    else:
        eq(eff, 0, "an unprivileged user has effective caps")
    eq(int(st.get("NoNewPrivs", "0")), libc.prctl(39, 0, 0, 0, 0), "NoNewPrivs vs PR_GET_NO_NEW_PRIVS")
    return f"CapEff {eff:#x}"


@test
def no_new_privs():
    """PR_SET_NO_NEW_PRIVS sticks, is inherited, and can't be undone."""
    def child():
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            return 2
        if libc.prctl(39, 0, 0, 0, 0) != 1:
            return 3
        if libc.prctl(38, 0, 0, 0, 0) == 0 and libc.prctl(39, 0, 0, 0, 0) == 0:
            return 4   # undone
        pid = os.fork()
        if pid == 0:
            os._exit(0 if libc.prctl(39, 0, 0, 0, 0) == 1 else 1)
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])

    eq(reap(spawn(child)), 0, "no_new_privs")
    return "set, read back, inherited, irreversible"
