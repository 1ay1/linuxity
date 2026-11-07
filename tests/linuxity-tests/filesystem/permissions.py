"""Permissions: modes, umask, ownership, access checks and special bits."""
import errno
import os
import stat

from lxt import check, eq, expect_errno, reap, spawn, test


@test
def modes_and_umask():
    """umask applies at create, chmod round-trips every bit, and fchmodat agrees."""
    old = os.umask(0o027)
    fd = os.open("masked", os.O_CREAT | os.O_WRONLY, 0o777)
    os.mkdir("mdir", 0o777)
    os.umask(old)
    eq(stat.S_IMODE(os.fstat(fd).st_mode), 0o750, "file mode under umask 027")
    eq(stat.S_IMODE(os.stat("mdir").st_mode), 0o750, "dir mode under umask 027")
    for m in (0o000, 0o400, 0o644, 0o755, 0o4755, 0o2755, 0o1777, 0o7777):
        os.chmod("masked", m)
        eq(stat.S_IMODE(os.stat("masked").st_mode), m, f"chmod {oct(m)}")
    os.fchmod(fd, 0o600)
    eq(stat.S_IMODE(os.stat("masked").st_mode), 0o600, "fchmod")
    os.symlink("masked", "ln")
    os.chmod("ln", 0o640)          # follows the link
    eq(stat.S_IMODE(os.stat("masked").st_mode), 0o640, "chmod through a link")
    prev = os.umask(0o077)
    eq(os.umask(prev), 0o077, "umask returns the previous mask")
    return "umask 027, all mode bits, fchmod, chmod via link"


@test
def ownership():
    """Files are created with our ids; root can chown, others get EPERM."""
    open("mine", "w").close()
    st = os.stat("mine")
    eq((st.st_uid, st.st_gid), (os.geteuid(), os.getegid()), "owner of a new file")
    if os.geteuid() == 0:
        os.chown("mine", 1234, 5678)
        eq((os.stat("mine").st_uid, os.stat("mine").st_gid), (1234, 5678), "chown")
        os.symlink("mine", "ml")
        os.lchown("ml", 42, 43)
        eq((os.lstat("ml").st_uid, os.stat("mine").st_uid), (42, 1234), "lchown changes only the link")
        os.chown("mine", -1, 9)
        eq((os.stat("mine").st_uid, os.stat("mine").st_gid), (1234, 9), "chown with -1 keeps the uid")
    else:
        expect_errno(errno.EPERM, "chown to another user", os.chown, "mine", 0, 0)
    return f"owned by {st.st_uid}:{st.st_gid}"


@test
def access_checks():
    """access/faccessat and the real open() agree, including for root."""
    with open("ro", "w") as f:
        f.write("x")
    os.chmod("ro", 0o444)
    check(os.access("ro", os.R_OK), "R_OK")
    root = os.geteuid() == 0
    eq(os.access("ro", os.W_OK), root, "W_OK on a 0444 file")
    if root:
        with open("ro", "a") as f:     # root ignores the write bit
            f.write("y")
    else:
        expect_errno(errno.EACCES, "write-open 0444", os.open, "ro", os.O_WRONLY)
    os.chmod("ro", 0o000)
    eq(os.access("ro", os.R_OK), root, "R_OK on a 0000 file")
    open("noexec", "w").close()
    os.chmod("noexec", 0o644)
    check(not os.access("noexec", os.X_OK), "X_OK without any x bit (even root)")
    os.chmod("noexec", 0o744)
    check(os.access("noexec", os.X_OK), "X_OK with u+x")
    check(not os.access("missing", os.F_OK), "F_OK on a missing file")
    os.mkdir("locked", 0o000)
    if not root:
        expect_errno(errno.EACCES, "list a 0000 dir", os.listdir, "locked")
    else:
        eq(os.listdir("locked"), [], "root lists a 0000 dir")
    return "R/W/X/F, root bypass except X"


@test
def sticky_and_setgid_dirs():
    """A setgid dir passes its group down; mkdir under it inherits the bit."""
    os.mkdir("sg")
    if os.geteuid() == 0:
        os.chown("sg", 0, 777)
    os.chmod("sg", 0o2775)
    open("sg/f", "w").close()
    os.mkdir("sg/d")
    want = os.stat("sg").st_gid
    eq(os.stat("sg/f").st_gid, want, "file group under a setgid dir")
    check(os.stat("sg/d").st_mode & stat.S_ISGID, "subdir inherits S_ISGID")
    os.mkdir("sticky", 0o1777)
    os.chmod("sticky", 0o1777)
    check(os.stat("sticky").st_mode & stat.S_ISVTX, "sticky bit")
    if os.geteuid() == 0:
        open("sticky/rootfile", "w").close()

        def other_user():
            os.setgid(65534)
            os.setuid(65534)
            try:
                os.unlink("sticky/rootfile")
                return 1
            except PermissionError:
                return 0

        eq(reap(spawn(other_user)), 0, "another user deleting in a sticky dir")
    return "setgid group + bit inherit, sticky"
