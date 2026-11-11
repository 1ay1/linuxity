#!/usr/bin/env python3
"""fs_torture.py -- every corner of the Linux filesystem API, one script.

Runs anywhere Python 3.10+ runs on Linux: natively, in a container, or under
linuxity. Each check runs in its own forked process, in its own fresh
scratch directory, with its own deadline -- a hang or a crash fails that
check alone and the rest go on.

    python3 fs_torture.py                 # everything, scratch under /tmp
    python3 fs_torture.py --dir=/some/dir # scratch somewhere else
    python3 fs_torture.py -v              # with tracebacks
    python3 fs_torture.py rename link     # checks whose name contains any word
    python3 fs_torture.py --list

Checks that need root (chown to others, sticky dirs, mknod) skip as a user;
checks about permissions drop to an unprivileged uid when run as root.
Exit status: 0 if everything passed (skips are fine), 1 otherwise.
"""
import ctypes
import ctypes.util
import errno
import fcntl
import mmap
import os
import resource
import select
import shutil
import signal
import socket
import stat as S
import struct
import sys
import tempfile
import time
import traceback

libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
libc.syscall.restype = ctypes.c_long
CHECKS = []
ROOT = os.geteuid() == 0
ARCH = os.uname().machine
SYSNO = {"aarch64": {"renameat2": 276, "statx": 291, "openat2": 437},
         "x86_64":  {"renameat2": 316, "statx": 332, "openat2": 437}}.get(ARCH, {})
AT_FDCWD = -100


class Skip(Exception):
    pass


def check(fn):
    CHECKS.append(fn)
    return fn


def ok(cond, why):
    if not cond:
        raise AssertionError(why)


def eq(got, want, what):
    if got != want:
        raise AssertionError(f"{what}: got {got!r}, want {want!r}")


def errname(e):
    return errno.errorcode.get(e, str(e)) if e else "success"


def expect_errno(want, what, fn, *a, **k):
    wants = want if isinstance(want, tuple) else (want,)
    try:
        fn(*a, **k)
        got = 0
    except OSError as e:
        got = e.errno
    if got not in wants:
        raise AssertionError(f"{what}: got {errname(got)}, want {'/'.join(map(errname, wants))}")


def write(path, data=b"", mode=0o644, **k):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode, **k)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def slurp(path):
    with open(path, "rb") as f:
        return f.read()


def touch(path):
    os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o644))


def child(fn, *a):
    """fork; the child runs fn(*a) and exits with its int result (or 0)."""
    sys.stdout.flush(); sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            r = fn(*a)
            code = r if isinstance(r, int) else 0
        except BaseException:
            traceback.print_exc()
            code = 99
        os._exit(code)
    return pid


def status(pid):
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)


def unprivileged(fn, uid=65534):
    """Run fn in a child as an ordinary user: root drops to `uid` first."""
    def body():
        if os.geteuid() == 0:
            os.chmod(".", 0o777)
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)
        return fn()
    return status(child(body))


def need_root():
    if not ROOT:
        raise Skip("needs root")


def sys_call(name, *args):
    nr = SYSNO.get(name)
    if nr is None:
        raise Skip(f"no {name} number for {ARCH}")
    r = libc.syscall(ctypes.c_long(nr), *args)
    return r if r >= 0 else -ctypes.get_errno()


# ---------------------------------------------------------------- open / read / write

@check
def create_excl_trunc_append():
    write("f", b"hello")
    expect_errno(errno.EEXIST, "O_EXCL on an existing file",
                 os.open, "f", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    os.symlink("nowhere", "dangling")
    expect_errno(errno.EEXIST, "O_EXCL on a dangling symlink",
                 os.open, "dangling", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    ok(not os.path.lexists("nowhere"), "O_EXCL followed the symlink")
    os.close(os.open("f", os.O_WRONLY | os.O_TRUNC))
    eq(os.stat("f").st_size, 0, "O_TRUNC empties")
    fd = os.open("f", os.O_WRONLY | os.O_APPEND)
    os.write(fd, b"ab")
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, b"cd")
    os.pwrite(fd, b"ef", 0)          # Linux: pwrite on an O_APPEND fd appends
    os.close(fd)
    eq(slurp("f"), b"abcdef", "O_APPEND writes at the end (pwrite too)")


@check
def umask_shapes_new_modes():
    old = os.umask(0o027)
    try:
        write("f", mode=0o777)
        os.mkdir("d", 0o777)
        os.mkfifo("p", 0o666)
    finally:
        os.umask(old)
    eq(S.S_IMODE(os.stat("f").st_mode), 0o750, "file")
    eq(S.S_IMODE(os.stat("d").st_mode), 0o750, "dir")
    eq(S.S_IMODE(os.stat("p").st_mode), 0o640, "fifo")
    os.chmod("f", 0o777)
    eq(S.S_IMODE(os.stat("f").st_mode), 0o777, "chmod ignores the umask")


@check
def offsets_vectors_and_holes():
    fd = os.open("f", os.O_RDWR | os.O_CREAT, 0o644)
    eq(os.write(fd, b"0123456789"), 10, "write")
    eq(os.pread(fd, 4, 2), b"2345", "pread")
    eq(os.lseek(fd, 0, os.SEEK_CUR), 10, "pread leaves the offset alone")
    os.pwrite(fd, b"AB", 0)
    eq(os.lseek(fd, 0, os.SEEK_CUR), 10, "pwrite leaves the offset alone")
    os.lseek(fd, 0, os.SEEK_SET)
    a, b = bytearray(3), bytearray(4)
    eq(os.readv(fd, [a, b]), 7, "readv count")
    eq(bytes(a) + bytes(b), b"AB23456", "readv data")
    eq(os.writev(fd, [b"x", b"yz"]), 3, "writev count")
    eq(os.pread(fd, 10, 0), b"AB23456xyz", "writev data")
    eq(os.lseek(fd, 100, os.SEEK_END), 110, "seek past the end")
    os.write(fd, b"!")
    eq(os.fstat(fd).st_size, 111, "size after writing past the end")
    eq(os.pread(fd, 100, 10), b"\0" * 100, "the hole reads as zeros")
    expect_errno(errno.EINVAL, "seek before 0", os.lseek, fd, -1, os.SEEK_SET)
    eq(os.read(fd, 10), b"", "read at EOF")
    n = ctypes.c_int()
    os.lseek(fd, 100, os.SEEK_SET)
    eq(libc.ioctl(fd, 0x541B, ctypes.byref(n)), 0, "FIONREAD on a file")
    eq(n.value, 11, "FIONREAD: bytes left after the offset")
    os.close(fd)


@check
def seek_data_and_hole():
    fd = os.open("f", os.O_RDWR | os.O_CREAT, 0o644)
    os.pwrite(fd, b"x", 1 << 20)
    size = (1 << 20) + 1
    h = os.lseek(fd, 0, os.SEEK_HOLE)
    ok(0 <= h <= size, f"SEEK_HOLE from 0 gave {h}")
    d = os.lseek(fd, 0, os.SEEK_DATA)
    ok(0 <= d <= 1 << 20, f"SEEK_DATA from 0 gave {d}")
    eq(os.lseek(fd, 1 << 20, os.SEEK_DATA), 1 << 20, "SEEK_DATA on the data byte")
    expect_errno(errno.ENXIO, "SEEK_DATA at EOF", os.lseek, fd, size, os.SEEK_DATA)
    expect_errno(errno.ENXIO, "SEEK_HOLE at EOF", os.lseek, fd, size, os.SEEK_HOLE)
    os.close(fd)


@check
def truncate_grow_and_shrink():
    write("f", b"abcdef")
    os.truncate("f", 3)
    eq(slurp("f"), b"abc", "truncate shrinks")
    fd = os.open("f", os.O_RDWR)
    os.ftruncate(fd, 6)
    eq(slurp("f"), b"abc\0\0\0", "ftruncate grows with zeros")
    expect_errno(errno.EINVAL, "negative length", os.ftruncate, fd, -1)
    os.close(fd)
    fd = os.open("f", os.O_RDONLY)
    expect_errno((errno.EINVAL, errno.EBADF), "ftruncate a read-only fd", os.ftruncate, fd, 0)
    os.close(fd)
    os.mkdir("d")
    expect_errno(errno.EISDIR, "truncate a directory", os.truncate, "d", 0)


@check
def large_file_past_4g():
    fd = os.open("f", os.O_RDWR | os.O_CREAT, 0o644)
    off = 5 << 30
    os.pwrite(fd, b"end", off)
    eq(os.fstat(fd).st_size, off + 3, "size")
    eq(os.pread(fd, 3, off), b"end", "data at 5 GiB")
    eq(os.pread(fd, 4, 1 << 32), b"\0" * 4, "hole at 4 GiB")
    eq(os.lseek(fd, 0, os.SEEK_END), off + 3, "SEEK_END")
    os.close(fd)


@check
def fallocate_and_punch_hole():
    fd = os.open("f", os.O_RDWR | os.O_CREAT, 0o644)
    try:
        os.posix_fallocate(fd, 0, 1 << 20)
    except OSError as e:
        if e.errno in (errno.EOPNOTSUPP, errno.ENOSYS):
            raise Skip("no fallocate here")
        raise
    eq(os.fstat(fd).st_size, 1 << 20, "posix_fallocate extends")
    os.pwrite(fd, b"x" * 8192, 0)
    fa = libc.fallocate
    fa.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_long, ctypes.c_long]
    if fa(fd, 1, 1 << 20, 1 << 20) == 0:                     # FALLOC_FL_KEEP_SIZE
        eq(os.fstat(fd).st_size, 1 << 20, "KEEP_SIZE keeps the size")
    if fa(fd, 3, 0, 4096) == 0:                              # PUNCH_HOLE | KEEP_SIZE
        eq(os.pread(fd, 4096, 0), b"\0" * 4096, "a punched hole reads zeros")
        eq(os.pread(fd, 1, 4096), b"x", "data after the hole stays")
        eq(os.fstat(fd).st_size, 1 << 20, "punching keeps the size")
    else:
        ok(ctypes.get_errno() == errno.EOPNOTSUPP, f"punch hole: {errname(ctypes.get_errno())}")
    os.close(fd)


@check
def unlinked_but_open_file_lives_on():
    fd = os.open("f", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(fd, b"data")
    os.unlink("f")
    expect_errno(errno.ENOENT, "the name is gone", os.stat, "f")
    eq(os.fstat(fd).st_nlink, 0, "nlink of an unlinked file")
    os.pwrite(fd, b"more", 4)
    eq(os.pread(fd, 8, 0), b"datamore", "still readable and writable")
    link = os.readlink(f"/proc/self/fd/{fd}")
    ok(link.endswith(" (deleted)"), f"/proc/self/fd link: {link!r}")
    fd2 = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)
    eq(os.read(fd2, 8), b"datamore", "reopened through /proc/self/fd")
    os.close(fd2)
    os.close(fd)
    eq(os.listdir("."), [], "nothing left behind")


@check
def o_tmpfile_then_linkat():
    try:
        fd = os.open(".", os.O_TMPFILE | os.O_RDWR, 0o600)
    except (OSError, AttributeError) as e:
        raise Skip(f"no O_TMPFILE: {e}")
    os.write(fd, b"tmp")
    eq(os.listdir("."), [], "an O_TMPFILE file has no name")
    eq(os.fstat(fd).st_nlink, 0, "nlink")
    # linkat(AT_SYMLINK_FOLLOW), as open(2) documents; os.link would use
    # link(), which can't name a /proc/self/fd magic link (EXDEV)
    eq(libc.linkat(AT_FDCWD, f"/proc/self/fd/{fd}".encode(), AT_FDCWD, b"named", 0x400), 0,
       f"linkat names it ({errname(ctypes.get_errno())})")
    eq(slurp("named"), b"tmp", "linkat gave it a name")
    eq(os.stat("named").st_nlink, 1, "nlink after linkat")
    os.close(fd)


@check
def device_nodes():
    st = os.stat("/dev/null")
    ok(S.S_ISCHR(st.st_mode), "/dev/null is a char device")
    eq((os.major(st.st_rdev), os.minor(st.st_rdev)), (1, 3), "/dev/null is 1:3")
    fd = os.open("/dev/null", os.O_RDWR)
    eq(os.write(fd, b"x" * 100), 100, "/dev/null eats writes")
    eq(os.read(fd, 10), b"", "/dev/null reads EOF")
    os.close(fd)
    fd = os.open("/dev/zero", os.O_RDONLY)
    eq(os.read(fd, 4096), b"\0" * 4096, "/dev/zero")
    os.close(fd)
    fd = os.open("/dev/full", os.O_RDWR)
    expect_errno(errno.ENOSPC, "write to /dev/full", os.write, fd, b"x")
    eq(os.read(fd, 8), b"\0" * 8, "/dev/full reads zeros")
    os.close(fd)
    fd = os.open("/dev/urandom", os.O_RDONLY)
    a, b = os.read(fd, 32), os.read(fd, 32)
    os.close(fd)
    ok(len(a) == 32 and a != b and a != b"\0" * 32, "/dev/urandom")
    r, w = os.pipe()
    with open(f"/dev/fd/{w}", "wb", buffering=0) as f:
        f.write(b"via /dev/fd")
    eq(os.read(r, 20), b"via /dev/fd", "/dev/fd/N reopens the pipe")


@check
def concurrent_appends_stay_whole():
    touch("log")

    def appender(tag):
        fd = os.open("log", os.O_WRONLY | os.O_APPEND)
        line = tag.encode() * 63 + b"\n"
        for _ in range(300):
            os.write(fd, line)
        return 0
    pids = [child(appender, c) for c in "abcd"]
    for p in pids:
        eq(status(p), 0, "appender")
    data = slurp("log")
    eq(len(data), 4 * 300 * 64, "total size")
    lines = data.split(b"\n")[:-1]
    bad = [l for l in lines if len(l) != 63 or len(set(l)) != 1]
    eq(len(bad), 0, "interleaved lines")
    for c in "abcd":
        eq(sum(1 for l in lines if l[:1] == c.encode()), 300, f"lines from {c}")


@check
def fsync_family():
    fd = os.open("f", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(fd, b"x" * 10000)
    os.fsync(fd)
    os.fdatasync(fd)
    os.sync()
    eq(libc.syncfs(fd), 0, "syncfs")
    sfr = libc.sync_file_range
    sfr.argtypes = [ctypes.c_int, ctypes.c_long, ctypes.c_long, ctypes.c_uint]
    eq(sfr(fd, 0, 0, 7), 0, f"sync_file_range ({errname(ctypes.get_errno())})")
    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
    os.close(fd)
    r, w = os.pipe()
    expect_errno(errno.EINVAL, "fsync a pipe", os.fsync, r)
    expect_errno(errno.ESPIPE, "fadvise a pipe", os.posix_fadvise, r, 0, 0, os.POSIX_FADV_NORMAL)
    fd = os.open("g", os.O_WRONLY | os.O_CREAT | os.O_SYNC, 0o644)
    ok(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_SYNC == os.O_SYNC, "O_SYNC shows in F_GETFL")
    os.close(fd)


@check
def copy_file_range_sendfile_splice():
    src = bytes(range(256)) * 100
    write("src", src)
    s = os.open("src", os.O_RDONLY)
    d = os.open("dst", os.O_WRONLY | os.O_CREAT, 0o644)
    done = 0
    try:
        while done < len(src):
            n = os.copy_file_range(s, d, len(src) - done)
            ok(n > 0, "copy_file_range made progress")
            done += n
    except OSError as e:
        if e.errno not in (errno.ENOSYS, errno.EXDEV, errno.EOPNOTSUPP):
            raise
    else:
        eq(slurp("dst"), src, "copy_file_range copy")
    d2 = os.open("dst2", os.O_WRONLY | os.O_CREAT, 0o644)
    pos = os.lseek(s, 0, os.SEEK_CUR)
    done = 0
    while done < len(src):
        n = os.sendfile(d2, s, done, len(src) - done)
        ok(n > 0, "sendfile made progress")
        done += n
    eq(slurp("dst2"), src, "sendfile file to file")
    eq(os.lseek(s, 0, os.SEEK_CUR), pos, "sendfile with an offset leaves the fd's alone")
    r, w = os.pipe()
    eq(os.splice(s, w, 100, offset_src=0), 100, "splice file -> pipe")
    eq(os.read(r, 100), src[:100], "spliced bytes")
    for fd in (s, d, d2):
        os.close(fd)


@check
def rlimit_fsize():
    def capped():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_FSIZE, (1000, 1000))
        fd = os.open("f", os.O_WRONLY | os.O_CREAT, 0o644)
        if os.write(fd, b"x" * 1500) != 1000:
            return 1
        try:
            os.write(fd, b"y")
            return 2
        except OSError as e:
            if e.errno != errno.EFBIG:
                return 3
        try:
            os.ftruncate(fd, 5000)
            return 4
        except OSError as e:
            return 0 if e.errno == errno.EFBIG else 5
    eq(status(child(capped)), 0, "partial write, then EFBIG (write and ftruncate)")

    def killed():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        signal.signal(signal.SIGXFSZ, signal.SIG_DFL)      # Python starts with it ignored
        resource.setrlimit(resource.RLIMIT_FSIZE, (1000, 1000))
        fd = os.open("g", os.O_WRONLY | os.O_CREAT, 0o644)
        os.pwrite(fd, b"y", 1000)
        return 1
    eq(status(child(killed)), -signal.SIGXFSZ, "past the limit: SIGXFSZ")


# ---------------------------------------------------------------- directories

@check
def mkdir_rmdir_rules():
    os.mkdir("d")
    expect_errno(errno.EEXIST, "mkdir an existing dir", os.mkdir, "d")
    touch("d/f")
    expect_errno((errno.ENOTEMPTY, errno.EEXIST), "rmdir a non-empty dir", os.rmdir, "d")
    expect_errno(errno.EINVAL, "rmdir d/.", os.rmdir, "d/.")
    expect_errno((errno.ENOTEMPTY, errno.EEXIST, errno.EBUSY), "rmdir d/..", os.rmdir, "d/..")
    touch("f")
    expect_errno(errno.ENOTDIR, "rmdir a file", os.rmdir, "f")
    expect_errno(errno.EISDIR, "unlink a dir", os.unlink, "d")
    os.mkdir("e/")
    ok(os.path.isdir("e"), "mkdir with a trailing slash")
    expect_errno(errno.ENOENT, "mkdir under a missing dir", os.mkdir, "x/y")
    expect_errno(errno.ENOTDIR, "mkdir under a file", os.mkdir, "f/x")
    os.mkdir("d/s1")
    os.mkdir("d/s2")
    n = os.stat("d").st_nlink
    # 2 + subdirs on ext4/xfs/tmpfs; 1 on btrfs and some FUSE filesystems
    # ("unknown"), so only a value that is neither is wrong
    ok(n in (1, 4), f"nlink of a dir with 2 subdirs: {n}")
    os.rmdir("d/s1")
    ok(os.stat("d").st_nlink in (1, 3), "nlink after rmdir")


@check
def big_directory_listing():
    os.mkdir("big")
    want = {f"f{i:05}" for i in range(3000)}
    for n in want:
        touch(f"big/{n}")
    os.mkdir("big/sub")
    os.symlink("f00000", "big/ln")
    names = os.listdir("big")
    eq(len(names), len(want) + 2, "entry count")
    eq(set(names), want | {"sub", "ln"}, "entry names")
    kinds = {}
    with os.scandir("big") as it:
        for e in it:
            if e.name in ("sub", "ln", "f00000", "f02999"):
                kinds[e.name] = (e.is_dir(follow_symlinks=False), e.is_symlink(),
                                 e.is_file(follow_symlinks=False))
                eq(e.inode(), os.lstat(e.path).st_ino, f"d_ino of {e.name} matches st_ino")
    eq(kinds["sub"], (True, False, False), "a dir's d_type")
    eq(kinds["ln"], (False, True, False), "a symlink's d_type")
    eq(kinds["f02999"], (False, False, True), "a file's d_type")


@check
def unlink_while_listing():
    os.mkdir("d")
    names = [f"{i:04}_" + "x" * 100 for i in range(500)]   # several getdents batches
    for n in names:
        touch(f"d/{n}")
    seen = []
    with os.scandir("d") as it:
        for e in it:
            seen.append(e.name)
            os.unlink(e.path)
    eq(len(seen), len(set(seen)), "no entry returned twice")
    eq(sorted(seen), names, "every entry returned once")
    eq(os.listdir("d"), [], "all gone")


@check
def cwd_renamed_then_deleted():
    base = os.getcwd()
    os.mkdir("a")
    os.chdir("a")
    os.rename(os.path.join(base, "a"), os.path.join(base, "b"))
    eq(os.getcwd(), os.path.join(base, "b"), "getcwd follows a rename")
    eq(os.readlink("/proc/self/cwd"), os.path.join(base, "b"), "/proc/self/cwd too")
    write("x", b"1")
    eq(slurp(os.path.join(base, "b", "x")), b"1", "relative paths still land in it")
    os.unlink("x")
    os.rmdir(os.path.join(base, "b"))
    expect_errno(errno.ENOENT, "getcwd in a deleted dir", os.getcwd)
    expect_errno(errno.ENOENT, "create in a deleted dir",
                 os.open, "new", os.O_CREAT | os.O_WRONLY, 0o644)
    # Linux lists a deleted cwd as empty (it still holds the inode); an
    # emulator that tracks the cwd by path can only say ENOENT. Either way
    # nothing may be listed.
    try:
        eq(os.listdir("."), [], "a deleted dir lists empty")
    except FileNotFoundError:
        pass
    os.chdir(base)


@check
def at_calls_with_dirfds():
    os.mkdir("d")
    dfd = os.open("d", os.O_RDONLY | os.O_DIRECTORY)
    fd = os.open("f", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=dfd)
    os.write(fd, b"hi")
    os.close(fd)
    eq(slurp("d/f"), b"hi", "openat")
    os.mkdir("sub", dir_fd=dfd)
    ok(os.path.isdir("d/sub"), "mkdirat")
    os.rename("f", "g", src_dir_fd=dfd, dst_dir_fd=dfd)
    eq(os.stat("g", dir_fd=dfd).st_size, 2, "renameat + fstatat")
    os.symlink("g", "l", dir_fd=dfd)
    eq(os.readlink("l", dir_fd=dfd), "g", "symlinkat + readlinkat")
    os.unlink("l", dir_fd=dfd)
    os.rmdir("sub", dir_fd=dfd)
    eq(os.listdir(dfd), ["g"], "fdopendir")
    ffd = os.open("d/g", os.O_RDONLY)
    expect_errno(errno.ENOTDIR, "a relative path against a file fd", os.stat, "x", dir_fd=ffd)
    eq(os.stat(os.path.abspath("d/g"), dir_fd=ffd).st_size, 2, "an absolute path ignores dirfd")
    os.rename("d", "moved")
    eq(os.stat("g", dir_fd=dfd).st_size, 2, "a dirfd follows its dir through a rename")
    os.fchdir(dfd)
    eq(os.path.basename(os.getcwd()), "moved", "fchdir")
    os.chdir("..")
    os.close(ffd)
    os.close(dfd)


@check
def openat2_resolve_flags():
    class How(ctypes.Structure):
        _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]
    os.mkdir("d")
    write("d/f", b"inner")
    write("top", b"outer")
    os.symlink("../top", "d/up")
    os.symlink("f", "d/lf")
    dfd = os.open("d", os.O_RDONLY | os.O_DIRECTORY)

    def o2(path, resolve, size=24):
        how = How(os.O_RDONLY, 0, resolve)
        r = sys_call("openat2", ctypes.c_int(dfd), ctypes.c_char_p(path), ctypes.byref(how), ctypes.c_size_t(size))
        if r >= 0:
            data = os.read(r, 10)
            os.close(r)
            return data
        return r
    first = o2(b"f", 0)
    if first == -errno.ENOSYS:
        raise Skip("no openat2")
    eq(first, b"inner", "plain openat2")
    eq(o2(b"../top", 0x08), -errno.EXDEV, "RESOLVE_BENEATH stops ..")
    eq(o2(b"up", 0x08), -errno.EXDEV, "RESOLVE_BENEATH stops a symlink out")
    eq(o2(b"lf", 0x08), b"inner", "RESOLVE_BENEATH allows a symlink within")
    eq(o2(b"lf", 0x04), -errno.ELOOP, "RESOLVE_NO_SYMLINKS")
    eq(o2(b"/f", 0x10), b"inner", "RESOLVE_IN_ROOT: / is the dirfd")
    eq(o2(b"../../f", 0x10), b"inner", "RESOLVE_IN_ROOT: .. stops at the root")
    eq(o2(b"f", 1 << 40), -errno.EINVAL, "unknown resolve bit")
    eq(o2(b"f", 0, 8), -errno.EINVAL, "short open_how")
    os.close(dfd)


@check
def setgid_directory_inheritance():
    os.mkdir("d")
    try:
        os.chmod("d", 0o2775)
    except PermissionError:
        raise Skip("can't set setgid on a dir here")
    if not os.stat("d").st_mode & S.S_ISGID:
        raise Skip("setgid bit not kept")
    touch("d/f")
    os.mkdir("d/sub")
    gid = os.stat("d").st_gid
    eq(os.stat("d/f").st_gid, gid, "a new file takes the dir's group")
    ok(os.stat("d/sub").st_mode & S.S_ISGID, "a new subdir inherits setgid")


# ---------------------------------------------------------------- names and paths

@check
def rename_semantics():
    write("a", b"A")
    write("b", b"B")
    fd = os.open("b", os.O_RDONLY)
    os.rename("a", "b")
    eq(slurp("b"), b"A", "rename replaces")
    eq(os.read(fd, 1), b"B", "an open fd keeps the replaced file")
    os.close(fd)
    expect_errno(errno.ENOENT, "the old name is gone", os.stat, "a")
    os.mkdir("d")
    expect_errno(errno.EISDIR, "file over dir", os.rename, "b", "d")
    expect_errno(errno.ENOTDIR, "dir over file", os.rename, "d", "b")
    os.mkdir("e")
    os.rename("d", "e")
    ok(os.path.isdir("e") and not os.path.exists("d"), "dir over an empty dir")
    touch("e/x")
    os.mkdir("d")
    expect_errno((errno.ENOTEMPTY, errno.EEXIST), "dir over a non-empty dir", os.rename, "d", "e")
    expect_errno(errno.EINVAL, "dir into its own subdir", os.rename, "e", "e/sub")
    os.rename("b", "b")
    eq(slurp("b"), b"A", "rename to itself")
    os.link("b", "b2")
    os.rename("b", "b2")
    ok(os.path.exists("b") and os.path.exists("b2"), "rename between hard links does nothing")
    expect_errno((errno.EBUSY, errno.EINVAL), "rename .", os.rename, ".", "z")
    expect_errno(errno.ENOENT, "rename a missing file", os.rename, "nope", "z")
    os.mkdir("p")
    os.rename("e/x", "p/x")
    ok(os.path.exists("p/x") and not os.path.exists("e/x"), "across directories")
    os.rename("p", "q")
    ok(os.path.exists("q/x"), "a dir moves with its contents")


@check
def renameat2_noreplace_and_exchange():
    def ra2(a, b, flags):
        return sys_call("renameat2", ctypes.c_int(AT_FDCWD), ctypes.c_char_p(a),
                        ctypes.c_int(AT_FDCWD), ctypes.c_char_p(b), ctypes.c_uint(flags))
    write("a", b"A")
    write("b", b"B")
    r = ra2(b"a", b"b", 1)
    if r == -errno.EINVAL or r == -errno.ENOSYS:
        raise Skip("no RENAME_NOREPLACE here")
    eq(r, -errno.EEXIST, "NOREPLACE onto an existing name")
    eq(ra2(b"a", b"c", 1), 0, "NOREPLACE onto a free name")
    ok(os.path.exists("c") and not os.path.exists("a"), "NOREPLACE moved it")
    eq(ra2(b"b", b"c", 2), 0, "EXCHANGE")
    eq((slurp("b"), slurp("c")), (b"A", b"B"), "EXCHANGE swapped them")
    os.mkdir("d")
    eq(ra2(b"d", b"c", 2), 0, "EXCHANGE a dir with a file")
    ok(os.path.isdir("c") and os.path.isfile("d"), "dir and file swapped")
    eq(ra2(b"d", b"missing", 2), -errno.ENOENT, "EXCHANGE with a missing name")
    eq(ra2(b"d", b"c", 3), -errno.EINVAL, "NOREPLACE|EXCHANGE")


@check
def names_are_case_sensitive():
    write("foo", b"lower")
    write("Foo", b"upper")
    eq(sorted(os.listdir(".")), ["Foo", "foo"], "two files")
    eq((slurp("foo"), slurp("Foo")), (b"lower", b"upper"), "two contents")
    expect_errno(errno.ENOENT, "FOO is a third name", os.stat, "FOO")
    os.rename("foo", "FOO")
    eq(sorted(os.listdir(".")), ["FOO", "Foo"], "rename to another case")
    os.mkdir("Dir")
    expect_errno(errno.ENOENT, "dir is not Dir", os.stat, "dir")
    os.mkdir("dir")
    ok(os.path.isdir("dir") and os.path.isdir("Dir"), "dir and Dir")


@check
def names_are_bytes_not_normalized():
    nfc, nfd = "caf\u00e9", "cafe\u0301"
    write(nfc, b"composed")
    if os.path.exists(nfd):
        # The filesystem under the scratch dir folds Unicode normalization
        # (APFS, HFS+ -- e.g. linuxity on a Mac): no Linux kernel layer can
        # give it two names. Not a kernel-API failure; say so and move on.
        raise Skip("the filesystem folds Unicode normalization (APFS/HFS+); try --dir= on one that doesn't")
    write(nfd, b"decomposed")
    eq(sorted(os.listdir(".")), sorted([nfc, nfd]), "NFC and NFD are two names")
    eq((slurp(nfc), slurp(nfd)), (b"composed", b"decomposed"), "two contents")
    raw = b"\xff\xfe-not-utf8"
    write(raw, b"raw")
    ok(raw in os.listdir(b"."), "a non-UTF-8 name comes back byte for byte")
    eq(slurp(raw), b"raw", "and opens")


@check
def odd_names_and_name_max():
    names = ["with space", "new\nline", "back\\slash", "colon:x", "star*", "q?", "-dash",
             "trail.", "trail ", ".hidden", "._apple", "tab\tx", "quo\"te'", "<>|", "emoji\U0001F600",
             "a" * 255, "\u00e9" * 127]
    for n in names:
        write(n, n.encode())
    got = set(os.listdir("."))
    for n in names:
        ok(n in got, f"{n[:20]!r} listed")
        eq(slurp(n), n.encode(), f"{n[:20]!r} content")
    eq(len(got), len(names), "nothing extra (no ._ or .DS_Store)")
    expect_errno(errno.ENAMETOOLONG, "256-byte name", touch, "a" * 256)
    expect_errno(errno.ENAMETOOLONG, "128 two-byte chars = 256 bytes", touch, "\u00e9" * 128)


@check
def deep_and_long_paths():
    base = os.getcwd()
    comp = "d" * 200
    for _ in range(25):                                     # 25 * 201 bytes > PATH_MAX
        os.mkdir(comp)
        os.chdir(comp)
    write("leaf", b"deep")
    eq(slurp("leaf"), b"deep", "relative I/O at depth")
    full = base + ("/" + comp) * 25 + "/leaf"
    expect_errno(errno.ENAMETOOLONG, "an absolute path past PATH_MAX", os.stat, full)
    os.chdir(base)
    mid = "/".join([comp] * 12)                             # 2.4 KB: fine
    os.chdir(mid)
    eq(slurp("/".join([comp] * 13) + "/leaf"), b"deep", "a 2.6 KB relative path")
    os.chdir(base)


@check
def lexical_dotdot_is_wrong():
    touch("f")
    expect_errno(errno.ENOENT, "missing/.. needs missing to exist", os.stat, "missing/..")
    expect_errno(errno.ENOTDIR, "file/.. needs file to be a dir", os.stat, "f/..")
    expect_errno(errno.ENOTDIR, "file/ is not a dir", os.stat, "f/")
    expect_errno(errno.ENOTDIR, "file/. is not a dir", os.stat, "f/.")
    os.mkdir("d")
    ok(os.path.isfile("d/../f") and os.path.isdir("d//.//"), "real dirs resolve")
    os.makedirs("x/sub")
    write("x/marker", b"x")
    write("marker", b"top")
    os.symlink("x/sub", "ln")
    eq(slurp("ln/../marker"), b"x", "symlink/.. is the TARGET's parent")
    os.symlink("../marker", "x/sub/up")
    eq(slurp("ln/up"), b"x", "a relative link resolves from where it lives")
    os.symlink(os.path.abspath("marker"), "absl")
    eq(slurp("absl"), b"top", "an absolute symlink")


@check
def file_vs_dir_errors():
    touch("f")
    os.mkdir("d")
    expect_errno(errno.EISDIR, "open a dir for writing", os.open, "d", os.O_WRONLY)
    fd = os.open("d", os.O_RDONLY)
    expect_errno(errno.EISDIR, "read a dir", os.read, fd, 10)
    os.close(fd)
    expect_errno(errno.ENOTDIR, "O_DIRECTORY on a file", os.open, "f", os.O_RDONLY | os.O_DIRECTORY)
    expect_errno(errno.ENOTDIR, "open file/", os.open, "f/", os.O_RDONLY)
    expect_errno(errno.EISDIR, "O_CREAT of new/", os.open, "new/", os.O_CREAT | os.O_WRONLY, 0o644)
    expect_errno(errno.ENOENT, "open of an empty path", os.open, "", os.O_RDONLY)
    expect_errno(errno.ENOENT, "stat of an empty path", os.stat, "")
    fd = os.open("f", os.O_RDONLY)
    expect_errno(errno.EBADF, "write a read-only fd", os.write, fd, b"x")
    os.close(fd)
    fd = os.open("f", os.O_WRONLY)
    expect_errno(errno.EBADF, "read a write-only fd", os.read, fd, 1)
    os.close(fd)


# ---------------------------------------------------------------- links

@check
def hard_links():
    write("a", b"x")
    os.link("a", "b")
    sa, sb = os.stat("a"), os.stat("b")
    eq(sa.st_ino, sb.st_ino, "same inode")
    eq(sa.st_nlink, 2, "nlink 2")
    with open("b", "ab") as f:
        f.write(b"y")
    eq(slurp("a"), b"xy", "one file, two names")
    os.unlink("a")
    eq(os.stat("b").st_nlink, 1, "nlink after unlink")
    eq(slurp("b"), b"xy", "data survives")
    os.mkdir("d")
    expect_errno(errno.EPERM, "hard link to a dir", os.link, "d", "d2")
    expect_errno(errno.EEXIST, "link onto an existing name", os.link, "b", "b")
    expect_errno(errno.ENOENT, "link a missing file", os.link, "nope", "z")
    os.symlink("b", "s")
    os.link("s", "s2", follow_symlinks=False)
    ok(os.path.islink("s2"), "linkat without FOLLOW links the symlink itself")
    # CPython's os.link(follow_symlinks=True) calls plain link(), which on
    # Linux does NOT follow -- so ask linkat for AT_SYMLINK_FOLLOW directly
    eq(libc.linkat(AT_FDCWD, b"s", AT_FDCWD, b"s3", 0x400), 0, "linkat(AT_SYMLINK_FOLLOW)")
    ok(not os.path.islink("s3") and os.stat("s3").st_ino == os.stat("b").st_ino,
       "linkat with FOLLOW links the target")
    os.link("s", "s4")
    ok(os.path.islink("s4"), "link() links a symlink itself (Linux)")


@check
def symlinks():
    for target, name in (("target", "rel"), ("/abs/where", "abs"), ("dir/", "slash"),
                         ("a b/../c", "weird")):
        os.symlink(target, name)
        eq(os.readlink(name), target, f"readlink {name}")
    eq(os.lstat("rel").st_size, len("target"), "a symlink's size is its target's length")
    ok(S.S_ISLNK(os.lstat("rel").st_mode) and not os.path.exists("rel"), "dangling")
    touch("plain")
    expect_errno(errno.EINVAL, "readlink a regular file", os.readlink, "plain")
    os.close(os.open("rel", os.O_CREAT | os.O_WRONLY, 0o644))
    ok(os.path.isfile("target"), "O_CREAT through a dangling link creates the target")
    expect_errno(errno.ELOOP, "O_NOFOLLOW on a symlink", os.open, "rel", os.O_RDONLY | os.O_NOFOLLOW)
    fd = os.open("rel", os.O_PATH | os.O_NOFOLLOW)
    ok(S.S_ISLNK(os.fstat(fd).st_mode), "O_PATH|O_NOFOLLOW opens the link itself")
    os.close(fd)
    os.symlink("loop1", "loop2")
    os.symlink("loop2", "loop1")
    expect_errno(errno.ELOOP, "a symlink loop", os.stat, "loop1")
    os.symlink("target", "c0")
    for i in range(1, 41):
        os.symlink(f"c{i - 1}", f"c{i}")
    ok(os.path.isfile("c39"), "40 links deep resolves")
    expect_errno(errno.ELOOP, "41 links deep", os.stat, "c40")
    os.mkdir("realdir")
    write("realdir/f", b"in")
    os.symlink("realdir", "dl")
    eq(slurp("dl/f"), b"in", "through a dir symlink")
    eq(os.listdir("dl/"), ["f"], "list through it")
    expect_errno(errno.ENOTDIR, "rmdir a symlink", os.rmdir, "dl")
    os.unlink("dl")
    ok(os.path.isdir("realdir"), "unlink removed the link, not the dir")
    os.symlink("plain", "pl")
    os.utime("pl", ns=(5_000_000_000, 5_000_000_000), follow_symlinks=False)
    eq(os.lstat("pl").st_mtime_ns, 5_000_000_000, "lutimes sets the link's time")
    ok(os.stat("plain").st_mtime_ns != 5_000_000_000, "and not the target's")
    os.chmod("pl", 0o600)
    eq(S.S_IMODE(os.stat("plain").st_mode), 0o600, "chmod follows the link")


# ---------------------------------------------------------------- metadata

@check
def chmod_access_and_type_bits():
    touch("f")
    os.chmod("f", 0o4755)
    eq(S.S_IMODE(os.stat("f").st_mode), 0o4755, "setuid bit as owner")
    fd = os.open("f", os.O_RDONLY)
    os.fchmod(fd, 0o640)
    os.close(fd)
    eq(S.S_IMODE(os.stat("f").st_mode), 0o640, "fchmod")
    ok(S.S_ISREG(os.stat("f").st_mode), "type bits kept")
    os.chmod("f", 0o400)
    ok(os.access("f", os.R_OK), "R_OK")
    eq(os.access("f", os.W_OK), ROOT, "W_OK on a 0400 file")
    ok(not os.access("f", os.X_OK), "X_OK with no x bits (even root)")
    ok(not os.access("nope", os.F_OK), "F_OK on a missing file")


@check
def permissions_enforced():
    def body():
        write("f", b"x")
        os.chmod("f", 0)
        expect_errno(errno.EACCES, "read a 000 file", os.open, "f", os.O_RDONLY)
        expect_errno(errno.EACCES, "write a 000 file", os.open, "f", os.O_WRONLY)
        os.chmod("f", 0o200)
        expect_errno(errno.EACCES, "read a write-only file", os.open, "f", os.O_RDONLY)
        os.close(os.open("f", os.O_WRONLY))
        os.mkdir("d")
        touch("d/x")
        os.chmod("d", 0o600)
        expect_errno(errno.EACCES, "stat through a dir without x", os.stat, "d/x")
        os.chmod("d", 0o500)
        expect_errno(errno.EACCES, "create in a dir without w",
                     os.open, "d/new", os.O_CREAT | os.O_WRONLY, 0o644)
        expect_errno(errno.EACCES, "unlink in a dir without w", os.unlink, "d/x")
        os.chmod("d", 0o300)
        expect_errno(errno.EACCES, "list a dir without r", os.listdir, "d")
        os.stat("d/x")
        os.chmod("d", 0o700)
        write("s.sh", b"#!/bin/sh\nexit 3\n", 0o644)
        os.chmod("s.sh", 0o644)

        def run():
            try:
                os.execv("./s.sh", ["s.sh"])
            except OSError as e:
                return 100 + e.errno
        eq(status(child(run)), 100 + errno.EACCES, "exec without x")
        os.chmod("s.sh", 0o755)
        eq(status(child(run)), 3, "exec with x")
        expect_errno(errno.EPERM, "chown to another user", os.chown, "f", 0 if os.getuid() else 1, -1)
        expect_errno(errno.EACCES, "write /etc/passwd", os.open, "/etc/passwd", os.O_WRONLY)
        return 0
    eq(unprivileged(body), 0, "an ordinary user")


@check
def sticky_directory():
    need_root()
    os.chmod(".", 0o755)
    os.mkdir("t")
    os.chmod("t", 0o1777)

    def as_uid(uid, fn):
        def body():
            os.setgroups([]); os.setgid(uid); os.setuid(uid)
            return fn()
        return status(child(body))
    eq(as_uid(1001, lambda: touch("t/mine")), 0, "user A creates")

    def other():
        try:
            os.unlink("t/mine")
            return 1
        except PermissionError:
            pass
        try:
            os.rename("t/mine", "t/stolen")
            return 2
        except PermissionError:
            pass
        touch("t/theirs")
        return 0
    eq(as_uid(1002, other), 0, "user B can't remove or rename A's file, can create")
    os.chmod("t", 0o777)
    eq(as_uid(1002, lambda: os.unlink("t/mine")), 0, "without sticky, B can")


@check
def chown_and_setid_bits():
    touch("f")
    os.chmod("f", 0o4755)
    os.chown("f", os.getuid(), os.getgid())
    eq(os.stat("f").st_mode & S.S_ISUID, 0, "chown clears setuid")
    os.chown("f", -1, -1)
    os.chmod("f", 0o4755)
    with open("f", "ab") as w:
        w.write(b"x")
    kept = os.stat("f").st_mode & S.S_ISUID
    if ROOT:
        ok(kept, "root's write keeps setuid (CAP_FSETID)")
        os.chown("f", 1000, 1000)
        st = os.stat("f")
        eq((st.st_uid, st.st_gid), (1000, 1000), "root chowns")
        os.lchown("f", 0, 0)
        eq(os.stat("f").st_uid, 0, "and back")
    else:
        eq(kept, 0, "a user's write clears setuid")


@check
def timestamps():
    touch("f")
    ns = 1_234_567_890_123_456_789
    os.utime("f", ns=(ns, ns + 1))
    st = os.stat("f")
    eq((st.st_atime_ns, st.st_mtime_ns), (ns, ns + 1), "nanosecond utimensat round trip")

    class TS(ctypes.Structure):
        _fields_ = [("sec", ctypes.c_long), ("nsec", ctypes.c_long)]
    UTIME_NOW, UTIME_OMIT = (1 << 30) - 1, (1 << 30) - 2
    ts = (TS * 2)(TS(0, UTIME_OMIT), TS(0, UTIME_NOW))
    eq(libc.utimensat(AT_FDCWD, b"f", ts, 0), 0, "utimensat OMIT/NOW")
    st = os.stat("f")
    eq(st.st_atime_ns, ns, "UTIME_OMIT keeps atime")
    ok(abs(st.st_mtime - time.time()) < 5, "UTIME_NOW sets mtime to now")
    os.utime("f", (-86400, -86400))
    eq(os.stat("f").st_mtime, -86400, "before 1970")
    os.utime("f", (2**32 + 5, 2**32 + 5))
    eq(os.stat("f").st_mtime, 2**32 + 5, "after 2106")
    os.utime("f")                                          # back to now
    before = os.stat("f")
    time.sleep(0.05)
    with open("f", "ab") as w:
        w.write(b"x")
    st = os.stat("f")
    ok(st.st_mtime_ns > before.st_mtime_ns and st.st_ctime_ns > before.st_ctime_ns,
       "write moves mtime and ctime")
    before = st
    time.sleep(0.05)
    os.chmod("f", 0o600)
    st = os.stat("f")
    ok(st.st_ctime_ns > before.st_ctime_ns, "chmod moves ctime")
    eq(st.st_mtime_ns, before.st_mtime_ns, "chmod leaves mtime")
    d0 = os.stat(".").st_mtime_ns
    time.sleep(0.05)
    touch("g")
    ok(os.stat(".").st_mtime_ns > d0, "creating a file moves the dir's mtime")


@check
def stat_fields_and_statx():
    write("f", b"x" * (1 << 20))
    st = os.stat("f")
    ok(st.st_blocks > 0, "st_blocks")
    ok(st.st_blksize > 0 and st.st_blksize & (st.st_blksize - 1) == 0, f"st_blksize {st.st_blksize}")
    inos = set()
    for i in range(20):
        touch(f"n{i}")
        inos.add(os.stat(f"n{i}").st_ino)
    eq(len(inos), 20, "inode numbers are distinct")
    ok(len({os.stat(f"n{i}").st_dev for i in range(20)}) == 1, "one st_dev")
    ino = os.stat("f").st_ino
    os.rename("f", "g")
    eq(os.stat("g").st_ino, ino, "rename keeps the inode")
    fd = os.open("g", os.O_RDONLY)
    a, b = os.fstat(fd), os.stat("g")
    eq((a.st_ino, a.st_dev, a.st_size), (b.st_ino, b.st_dev, b.st_size), "fstat == stat")
    os.close(fd)
    buf = ctypes.create_string_buffer(256)
    r = sys_call("statx", ctypes.c_int(AT_FDCWD), ctypes.c_char_p(b"g"), ctypes.c_int(0),
                 ctypes.c_uint(0x7ff), buf)
    if r == -errno.ENOSYS:
        return
    eq(r, 0, "statx")
    mask, = struct.unpack_from("I", buf, 0)
    nlink, uid, gid, mode = struct.unpack_from("IIIH", buf, 16)
    sino, ssize = struct.unpack_from("QQ", buf, 32)
    ok(mask & 0x7ff == 0x7ff, f"statx basic mask {mask:#x}")
    eq((sino, ssize, mode, nlink, uid), (b.st_ino, b.st_size, b.st_mode, b.st_nlink, b.st_uid),
       "statx agrees with stat")


@check
def xattrs():
    touch("f")
    try:
        os.setxattr("f", "user.k", b"v")
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            raise Skip("no user xattrs here")
        raise
    eq(os.getxattr("f", "user.k"), b"v", "getxattr")
    names = os.listxattr("f")
    ok("user.k" in names, "listxattr")
    eq([n for n in names if n.startswith("user.")], ["user.k"], "no foreign user.* names")
    ok(not any("linuxity" in n or "apple" in n for n in names), f"implementation leaks: {names}")
    expect_errno(errno.EEXIST, "XATTR_CREATE on an existing name",
                 os.setxattr, "f", "user.k", b"w", os.XATTR_CREATE)
    expect_errno(errno.ENODATA, "XATTR_REPLACE on a missing name",
                 os.setxattr, "f", "user.none", b"w", os.XATTR_REPLACE)
    expect_errno(errno.ENODATA, "getxattr a missing name", os.getxattr, "f", "user.none")
    big = bytes(range(256)) * 15
    os.setxattr("f", "user.big", big)
    eq(os.getxattr("f", "user.big"), big, "a 3.8 KB value")
    os.removexattr("f", "user.k")
    ok("user.k" not in os.listxattr("f"), "removexattr")
    expect_errno(errno.EOPNOTSUPP, "an unknown namespace", os.setxattr, "f", "bogus.k", b"v")
    os.symlink("f", "s")
    expect_errno(errno.EPERM, "user xattr on a symlink",
                 os.setxattr, "s", "user.k", b"v", follow_symlinks=False)


@check
def statvfs_and_mounts():
    s = os.statvfs(".")
    ok(s.f_bsize > 0 and s.f_blocks > 0, "sizes")
    ok(s.f_bavail <= s.f_bfree <= s.f_blocks, "free <= total")
    eq(s.f_namemax, 255, "NAME_MAX")
    fd = os.open(".", os.O_RDONLY)
    eq(os.fstatvfs(fd).f_blocks, s.f_blocks, "fstatvfs")
    os.close(fd)
    with open("/proc/self/mounts") as f:
        mounts = [l.split() for l in f]
    ok(all(len(m) == 6 for m in mounts), "6 fields per line")
    ok(any(m[1] == "/" for m in mounts), "a / mount")


# ---------------------------------------------------------------- special files

@check
def fifos_sockets_and_mknod():
    os.mkfifo("p")
    ok(S.S_ISFIFO(os.lstat("p").st_mode), "mkfifo")
    s = socket.socket(socket.AF_UNIX)
    s.bind("sock")
    ok(S.S_ISSOCK(os.lstat("sock").st_mode), "bind makes a socket file")
    s.listen()
    c = socket.socket(socket.AF_UNIX)
    c.connect("sock")
    a, _ = s.accept()
    c.send(b"hi")
    eq(a.recv(2), b"hi", "connect by path")
    s2 = socket.socket(socket.AF_UNIX)
    expect_errno(errno.EADDRINUSE, "bind over an existing socket file", s2.bind, "sock")
    os.unlink("sock")
    c2 = socket.socket(socket.AF_UNIX)
    expect_errno(errno.ENOENT, "connect after unlink", c2.connect, "sock")
    touch("plain")
    c3 = socket.socket(socket.AF_UNIX)
    expect_errno(errno.ECONNREFUSED, "connect to a regular file", c3.connect, "plain")
    os.mknod("reg", 0o644 | S.S_IFREG)
    ok(os.path.isfile("reg"), "mknod S_IFREG")
    os.mknod("p2", 0o644 | S.S_IFIFO)
    ok(S.S_ISFIFO(os.stat("p2").st_mode), "mknod S_IFIFO")
    try:
        os.mknod("null", 0o666 | S.S_IFCHR, os.makedev(1, 3))
    except PermissionError:
        return                  # users can't; a container may forbid root too
    ok(ROOT, "a user made a device node")
    eq(os.stat("null").st_rdev, os.makedev(1, 3), "rdev")
    fd = os.open("null", os.O_RDWR)
    eq((os.write(fd, b"xyz"), os.read(fd, 5)), (3, b""), "it is /dev/null")
    os.close(fd)


# ---------------------------------------------------------------- file descriptors

@check
def fd_flags_and_dup():
    fd = os.open("f", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    ok(fl & os.O_APPEND and fl & os.O_ACCMODE == os.O_WRONLY, "F_GETFL")
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK | os.O_RDWR)
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    ok(fl & os.O_NONBLOCK and fl & os.O_APPEND, "F_SETFL adds O_NONBLOCK")
    eq(fl & os.O_ACCMODE, os.O_WRONLY, "F_SETFL can't change the access mode")
    eq(fcntl.fcntl(fd, fcntl.F_GETFD), fcntl.FD_CLOEXEC, "Python opens with O_CLOEXEC")
    fcntl.fcntl(fd, fcntl.F_SETFD, 0)
    eq(fcntl.fcntl(fd, fcntl.F_GETFD), 0, "F_SETFD clears it")
    d = os.dup(fd)
    os.write(fd, b"12345")
    eq(os.lseek(d, 0, os.SEEK_CUR), 5, "dup shares the offset")
    hi = fcntl.fcntl(fd, fcntl.F_DUPFD, 100)
    ok(hi >= 100, "F_DUPFD honours the minimum")
    eq(fcntl.fcntl(hi, fcntl.F_GETFD), 0, "F_DUPFD: no CLOEXEC")
    hc = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 100)
    eq(fcntl.fcntl(hc, fcntl.F_GETFD), fcntl.FD_CLOEXEC, "F_DUPFD_CLOEXEC")
    eq(os.dup2(fd, fd), fd, "dup2 onto itself")
    t = os.open("/dev/null", os.O_RDONLY)
    os.dup2(fd, t)
    ok(fcntl.fcntl(t, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY, "dup2 replaced the target")
    os.close(t)
    expect_errno(errno.EBADF, "a closed fd", os.fstat, t)
    a = os.open("f", os.O_RDONLY)
    os.open("f", os.O_RDONLY)
    os.close(a)
    eq(os.open("f", os.O_RDONLY), a, "the lowest free fd is reused")
    expect_errno(errno.EBADF, "close a bad fd", os.close, 9999)


@check
def cloexec_across_exec():
    touch("f")
    keep = os.open("f", os.O_RDONLY)
    os.set_inheritable(keep, True)
    drop = os.open("f", os.O_RDONLY)                        # O_CLOEXEC
    code = ("import os,sys\n"
            "def alive(n):\n"
            "    try: os.fstat(n); return True\n"
            "    except OSError: return False\n"
            f"sys.exit((0 if alive({keep}) else 1) | (2 if alive({drop}) else 0))")

    def run():
        os.execv(sys.executable, [sys.executable, "-S", "-c", code])
    eq(status(child(run)), 0, "inheritable kept, CLOEXEC closed")


@check
def open_file_description_sharing():
    write("f", b"0123456789")
    fd = os.open("f", os.O_RDONLY)
    eq(status(child(lambda: 0 if os.read(fd, 4) == b"0123" else 1)), 0, "child read")
    eq(os.read(fd, 2), b"45", "fork shares the file offset")
    fd2 = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)
    eq(os.read(fd2, 2), b"01", "reopening /proc/self/fd/N gives a fresh offset")
    eq(os.readlink(f"/proc/self/fd/{fd}"), os.path.abspath("f"), "/proc/self/fd/N names the file")
    with open(f"/proc/self/fdinfo/{fd}") as f:
        info = dict(l.split(":", 1) for l in f.read().splitlines() if ":" in l)
    eq(int(info["pos"]), 6, "fdinfo pos")
    eq(int(info["flags"], 8) & os.O_ACCMODE, os.O_RDONLY, "fdinfo flags")
    os.close(fd2)
    os.close(fd)


@check
def many_open_files():
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    n = min(1000, soft - 50)
    fds = [os.open(f"f{i}", os.O_RDWR | os.O_CREAT, 0o644) for i in range(n)]
    eq(len(set(fds)), n, "distinct fds")
    for i, fd in enumerate(fds):
        os.write(fd, str(i).encode())
    for i, fd in enumerate(fds):
        eq(os.pread(fd, 10, 0), str(i).encode(), f"file {i}")
        os.close(fd)


# ---------------------------------------------------------------- locks

LK = "hhqqi4x"


def lk(kind, start, length):
    return struct.pack(LK, kind, 0, start, length, 0)


@check
def flock_between_processes():
    touch("f")
    fd = os.open("f", os.O_RDWR)

    def try_ex():
        fd2 = os.open("f", os.O_RDWR)
        try:
            fcntl.flock(fd2, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return 0
        except BlockingIOError:
            return 1

    def try_sh():
        fd2 = os.open("f", os.O_RDWR)
        try:
            fcntl.flock(fd2, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return 0
        except BlockingIOError:
            return 1
    fcntl.flock(fd, fcntl.LOCK_EX)
    eq(status(child(try_ex)), 1, "EX blocks another EX")
    eq(status(child(try_sh)), 1, "EX blocks SH")
    fcntl.flock(fd, fcntl.LOCK_SH)
    eq(status(child(try_sh)), 0, "SH + SH")
    eq(status(child(try_ex)), 1, "SH blocks EX")
    fcntl.flock(fd, fcntl.LOCK_UN)
    eq(status(child(try_ex)), 0, "unlocked")
    fcntl.flock(fd, fcntl.LOCK_EX)
    d = os.dup(fd)
    os.close(fd)
    eq(status(child(try_ex)), 1, "a dup keeps the lock")
    os.close(d)
    eq(status(child(try_ex)), 0, "the last close drops it")
    fd = os.open("f", os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    r, w = os.pipe()

    def waiter():
        fd2 = os.open("f", os.O_RDWR)
        t = time.monotonic()
        fcntl.flock(fd2, fcntl.LOCK_EX)
        os.write(w, struct.pack("d", time.monotonic() - t))
        return 0
    pid = child(waiter)
    time.sleep(0.3)
    fcntl.flock(fd, fcntl.LOCK_UN)
    eq(status(pid), 0, "waiter")
    ok(struct.unpack("d", os.read(r, 8))[0] >= 0.2, "a blocking flock waited")


@check
def posix_record_locks():
    write("f", b"x" * 100)
    fd = os.open("f", os.O_RDWR)
    me = os.getpid()
    fcntl.fcntl(fd, fcntl.F_SETLK, lk(fcntl.F_WRLCK, 0, 10))

    def probe():
        fd2 = os.open("f", os.O_RDWR)
        try:
            fcntl.fcntl(fd2, fcntl.F_SETLK, lk(fcntl.F_WRLCK, 5, 10))
            return 1
        except OSError as e:
            if e.errno not in (errno.EAGAIN, errno.EACCES):
                return 2
        fcntl.fcntl(fd2, fcntl.F_SETLK, lk(fcntl.F_WRLCK, 20, 10))
        t, _, start, ln, pid = struct.unpack(LK, fcntl.fcntl(fd2, fcntl.F_GETLK, lk(fcntl.F_WRLCK, 0, 1)))
        if (t, start, ln) != (fcntl.F_WRLCK, 0, 10):
            return 3
        return 0 if pid == me else 4
    eq(status(child(probe)), 0, "conflict, disjoint range, F_GETLK names the holder's pid")

    def free_at(off):
        def f():
            fd2 = os.open("f", os.O_RDWR)
            try:
                fcntl.fcntl(fd2, fcntl.F_SETLK, lk(fcntl.F_WRLCK, off, 1))
                return 0
            except OSError:
                return 1
        return status(child(f))
    eq(free_at(0), 1, "still held after the child exits")
    fcntl.fcntl(fd, fcntl.F_SETLK, lk(fcntl.F_WRLCK, 0, 100))
    fcntl.fcntl(fd, fcntl.F_SETLK, lk(fcntl.F_UNLCK, 40, 20))
    eq((free_at(30), free_at(45), free_at(70)), (1, 0, 1), "unlocking the middle splits the lock")
    os.close(os.open("f", os.O_RDONLY))
    eq(free_at(0), 0, "closing ANY fd of the file drops the process's locks")
    fcntl.fcntl(fd, fcntl.F_SETLK, lk(fcntl.F_WRLCK, 0, 10))
    r, w = os.pipe()

    def waiter():
        fd2 = os.open("f", os.O_RDWR)
        t = time.monotonic()
        fcntl.fcntl(fd2, fcntl.F_SETLKW, lk(fcntl.F_WRLCK, 0, 10))
        os.write(w, struct.pack("d", time.monotonic() - t))
        return 0
    pid = child(waiter)
    time.sleep(0.3)
    fcntl.fcntl(fd, fcntl.F_SETLK, lk(fcntl.F_UNLCK, 0, 10))
    eq(status(pid), 0, "waiter")
    ok(struct.unpack("d", os.read(r, 8))[0] >= 0.2, "F_SETLKW waited for the unlock")


@check
def ofd_locks():
    GET, SET = getattr(fcntl, "F_OFD_GETLK", 36), getattr(fcntl, "F_OFD_SETLK", 37)
    write("f", b"x" * 100)
    a, b = os.open("f", os.O_RDWR), os.open("f", os.O_RDWR)
    try:
        fcntl.fcntl(a, SET, lk(fcntl.F_WRLCK, 0, 10))
    except OSError as e:
        if e.errno == errno.EINVAL:
            raise Skip("no OFD locks")
        raise
    expect_errno((errno.EAGAIN, errno.EACCES), "another open file in the SAME process conflicts",
                 fcntl.fcntl, b, SET, lk(fcntl.F_WRLCK, 5, 10))
    os.close(os.open("f", os.O_RDONLY))
    expect_errno((errno.EAGAIN, errno.EACCES), "closing another fd doesn't drop an OFD lock",
                 fcntl.fcntl, b, SET, lk(fcntl.F_WRLCK, 5, 10))
    t, _, _, _, pid = struct.unpack(LK, fcntl.fcntl(b, GET, lk(fcntl.F_WRLCK, 0, 1)))
    eq((t, pid), (fcntl.F_WRLCK, -1), "F_OFD_GETLK reports pid -1")
    os.close(a)
    fcntl.fcntl(b, SET, lk(fcntl.F_WRLCK, 0, 10))


# ---------------------------------------------------------------- mmap

@check
def mmap_shared_is_coherent():
    write("f", b"\0" * 8192)
    fd = os.open("f", os.O_RDWR)
    m = mmap.mmap(fd, 8192)
    m[0:5] = b"hello"
    eq(os.pread(fd, 5, 0), b"hello", "a store is visible to read()")
    os.pwrite(fd, b"world", 100)
    eq(m[100:105], b"world", "a write() is visible in the mapping")

    def kid():
        m[200:203] = b"kid"
        return 0
    eq(status(child(kid)), 0, "child")
    eq(m[200:203], b"kid", "a child's store through MAP_SHARED")
    eq(os.pread(fd, 3, 200), b"kid", "...and in the file")
    fd2 = os.open("f", os.O_RDWR)
    m2 = mmap.mmap(fd2, 8192)
    m2[300:303] = b"two"
    eq(m[300:303], b"two", "two mappings of one file share pages")
    m.flush()
    p = mmap.mmap(fd, 8192, flags=mmap.MAP_PRIVATE)
    p[0:3] = b"PRV"
    eq(os.pread(fd, 3, 0), b"hel", "MAP_PRIVATE stores stay private")
    p.close()
    os.close(fd)
    os.unlink("f")
    eq(m[0:5], b"hello", "a mapping outlives close and unlink")
    m.close()
    m2.close()


@check
def mmap_past_eof_is_sigbus():
    write("f", b"x")
    fd = os.open("f", os.O_RDWR)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                          ctypes.c_int, ctypes.c_long]
    pg = mmap.PAGESIZE
    addr = libc.mmap(None, 2 * pg, mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED, fd, 0)
    ok(addr not in (None, ctypes.c_void_p(-1).value), "mmap")
    eq(ctypes.string_at(addr, 1), b"x", "the file's byte")
    eq(ctypes.string_at(addr + 1, 16), b"\0" * 16, "the rest of the last page reads zero")

    def touch_page_2():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        ctypes.string_at(addr + pg, 1)
        return 0
    eq(status(child(touch_page_2)), -signal.SIGBUS, "a page wholly past EOF is SIGBUS")
    os.ftruncate(fd, 2 * pg)
    eq(ctypes.string_at(addr + pg, 4), b"\0" * 4, "after growing the file it reads zeros")
    os.close(fd)


# ---------------------------------------------------------------- inotify

IN = dict(MODIFY=0x2, ATTRIB=0x4, CLOSE_WRITE=0x8, MOVED_FROM=0x40, MOVED_TO=0x80,
          CREATE=0x100, DELETE=0x200, DELETE_SELF=0x400, IGNORED=0x8000, ISDIR=0x40000000)


def inotify_read(ifd, until, secs=3.0):
    evs = []
    end = time.monotonic() + secs
    while time.monotonic() < end and not until(evs):
        if not select.select([ifd], [], [], 0.05)[0]:
            continue
        data = os.read(ifd, 65536)
        off = 0
        while off + 16 <= len(data):
            wd, mask, cookie, ln = struct.unpack_from("iIII", data, off)
            evs.append((wd, mask, cookie, data[off + 16:off + 16 + ln].rstrip(b"\0").decode()))
            off += 16 + ln
    return evs


@check
def inotify_events():
    ifd = libc.inotify_init1(0)
    ok(ifd >= 0, "inotify_init1")
    mask = sum(v for k, v in IN.items() if k not in ("ISDIR", "IGNORED", "DELETE_SELF"))
    wd = libc.inotify_add_watch(ifd, b".", mask)
    ok(wd >= 0, "inotify_add_watch")
    write("a", b"1")
    os.chmod("a", 0o600)
    os.rename("a", "b")
    os.unlink("b")
    os.mkdir("d")
    want = [(IN["CREATE"], "a"), (IN["MODIFY"], "a"), (IN["CLOSE_WRITE"], "a"), (IN["ATTRIB"], "a"),
            (IN["MOVED_FROM"], "a"), (IN["MOVED_TO"], "b"), (IN["DELETE"], "b"),
            (IN["CREATE"] | IN["ISDIR"], "d")]

    def matched(evs):
        i = 0
        for _, m, _, n in evs:
            if i < len(want) and (m, n) == want[i]:
                i += 1
        return i
    evs = inotify_read(ifd, lambda e: matched(e) == len(want))
    got = [(m, n) for _, m, _, n in evs]
    eq(matched(evs), len(want), f"events in order; got {got}")
    cookies = [c for _, m, c, _ in evs if m in (IN["MOVED_FROM"], IN["MOVED_TO"])]
    ok(len(cookies) == 2 and cookies[0] == cookies[1] != 0, f"one rename cookie: {cookies}")
    eq(status(child(lambda: touch("from_child"))), 0, "child")
    evs = inotify_read(ifd, lambda e: any(n == "from_child" for _, _, _, n in e))
    ok(any(m == IN["CREATE"] and n == "from_child" for _, m, _, n in evs),
       "another process's create is seen")
    wd2 = libc.inotify_add_watch(ifd, b"d", IN["DELETE_SELF"])
    os.rmdir("d")
    evs = inotify_read(ifd, lambda e: any(w == wd2 and m & IN["IGNORED"] for w, m, _, _ in e))
    seen = [m for w, m, _, _ in evs if w == wd2]
    ok(IN["DELETE_SELF"] in seen and IN["IGNORED"] in seen, f"DELETE_SELF then IGNORED: {seen}")
    os.close(ifd)


# ---------------------------------------------------------------- runner

def run_one(fn, timeout, base):
    scratch = tempfile.mkdtemp(prefix=f"fst-{fn.__name__[:20]}-", dir=base)
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        os.setpgid(0, 0)
        os.dup2(w, 2)
        os.chdir(scratch)
        os.umask(0o022)
        try:
            fn()
            os._exit(0)
        except Skip as e:
            os.write(2, f"SKIP:{e}".encode()); os._exit(77)
        except BaseException:
            os.write(2, traceback.format_exc().encode()); os._exit(1)
    os.close(w)
    end = time.monotonic() + timeout
    out = b""
    res = None
    while True:
        done, st = os.waitpid(pid, os.WNOHANG)
        if select.select([r], [], [], 0.05)[0]:
            out += os.read(r, 65536)
        if done:
            while (b := os.read(r, 65536)):
                out += b
            break
        if time.monotonic() > end:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
            res = ("FAIL", f"timed out after {timeout}s")
            break
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    os.close(r)
    for root, dirs, _ in os.walk(scratch):
        for d in dirs:
            try:
                os.chmod(os.path.join(root, d), 0o700)
            except OSError:
                pass
    shutil.rmtree(scratch, ignore_errors=True)
    if res:
        return res
    code = os.waitstatus_to_exitcode(st)
    text = out.decode(errors="replace").strip()
    if code == 0:
        return "PASS", ""
    if code == 77:
        return "SKIP", text.replace("SKIP:", "")
    last = text.splitlines()[-1] if text else f"exit {code}"
    return "FAIL", (text if VERBOSE else last)


VERBOSE = False


def main(argv):
    global VERBOSE
    VERBOSE = "-v" in argv
    base = next((a.split("=", 1)[1] for a in argv if a.startswith("--dir=")), tempfile.gettempdir())
    words = [a for a in argv if not a.startswith("-")]
    chosen = [c for c in CHECKS if not words or any(w in c.__name__ for w in words)]
    if "--list" in argv:
        for c in chosen:
            print(c.__name__)
        return 0
    print(f"  {len(chosen)} checks, scratch in {base}, {'root' if ROOT else 'uid ' + str(os.getuid())}")
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    t0 = time.monotonic()
    for c in chosen:
        t = time.monotonic()
        res, why = run_one(c, 30, base)
        counts[res] += 1
        print(f"  {res}  {c.__name__:40} {time.monotonic() - t:6.2f}s  {why if res != 'PASS' else ''}"
              [:240 if not VERBOSE else None], flush=True)
    print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped "
          f"of {len(chosen)} in {time.monotonic() - t0:.1f}s")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
