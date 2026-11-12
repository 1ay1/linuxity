"""The VFS: names, paths, links, special files and data movement."""
import errno
import os
import random
import shutil
import stat
import threading

from lxt import check, eq, expect_errno, skip, test


@test
def names_and_paths():
    """255/256-byte names, unicode, an 80-deep tree, PATH_MAX, physical '..'."""
    os.close(os.open("n" * 255, os.O_CREAT | os.O_WRONLY, 0o644))
    expect_errno(errno.ENAMETOOLONG, "256-byte name", os.open, "n" * 256, os.O_CREAT | os.O_WRONLY, 0o644)
    weird = "ünïcødé 🚀 \t新\x01name"
    with open(weird, "w") as f:
        f.write("x")
    check(weird in os.listdir("."), "unicode name")
    part = "d" * 60
    fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    for _ in range(80):
        os.mkdir(part, dir_fd=fd)
        nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
        os.close(fd)
        fd = nfd
    leaf = os.open("leaf", os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=fd)
    os.write(leaf, b"deep")
    os.close(leaf)
    os.close(fd)
    expect_errno(errno.ENAMETOOLONG, "path over PATH_MAX", os.stat, "/".join([part] * 80 + ["leaf"]))
    base = os.getcwd()
    os.chdir("/".join([part] * 40))
    with open("/".join([part] * 40 + ["leaf"]), "rb") as f:
        eq(f.read(), b"deep", "deep leaf by relative path")
    os.chdir(base)
    shutil.rmtree(part)
    check(not os.path.exists(part), "rmtree of the 80-deep tree")
    os.makedirs("real/sub")
    os.symlink("real/sub", "lnk")
    eq(os.stat("lnk/..").st_ino, os.stat("real").st_ino, "'..' after a symlink")
    eq(os.path.realpath("lnk/../sub"), os.path.realpath("real/sub"), "realpath")
    return "255/256, unicode, 80 deep, PATH_MAX, physical '..'"


@test
def symlinks():
    """ELOOP at 40 links, O_NOFOLLOW, dangling links and lstat."""
    os.symlink("loop-b", "loop-a")
    os.symlink("loop-a", "loop-b")
    expect_errno(errno.ELOOP, "a symlink loop", os.open, "loop-a", os.O_RDONLY)
    with open("target", "w") as f:
        f.write("end")
    prev = "target"
    for i in range(50):
        os.symlink(prev, f"chain{i}")
        prev = f"chain{i}"
    with open("chain30") as f:
        eq(f.read(), "end", "31-link chain")
    expect_errno(errno.ELOOP, "50-link chain", os.open, "chain49", os.O_RDONLY)
    expect_errno(errno.ELOOP, "O_NOFOLLOW on a link", os.open, "chain0", os.O_RDONLY | os.O_NOFOLLOW)
    os.symlink("nowhere", "dangling")
    check(os.path.lexists("dangling") and not os.path.exists("dangling"), "dangling link")
    check(stat.S_ISLNK(os.lstat("chain0").st_mode), "lstat type")
    eq(os.lstat("dangling").st_size, len("nowhere"), "a link's size is its target length")
    eq(os.readlink("chain0"), "target", "readlink")
    fd = os.open("chain0", os.O_PATH | os.O_NOFOLLOW)
    eq(os.readlink("", dir_fd=fd), "target", "readlinkat on an O_PATH link fd")
    return "ELOOP, NOFOLLOW, dangling, lstat size, O_PATH"


@test
def links_and_unlinked_files():
    """Hard links share an inode; open files outlive unlink; O_TMPFILE + linkat."""
    with open("orig", "w") as f:
        f.write("same")
    for i in range(10):
        os.link("orig", f"hl{i}")
    st = os.stat("orig")
    eq(st.st_nlink, 11, "nlink")
    check(all(os.stat(f"hl{i}").st_ino == st.st_ino for i in range(10)), "shared inode")
    with open("hl3", "a") as f:
        f.write("!")
    with open("orig") as f:
        eq(f.read(), "same!", "write through one name shows in another")
    os.rename("hl0", "hl1")
    check(os.path.exists("hl0") and os.path.exists("hl1"), "rename between links of one inode is a no-op")
    os.unlink("hl1")
    eq(os.stat("orig").st_nlink, 10, "nlink after unlink")
    fd = os.open("ghost", os.O_RDWR | os.O_CREAT, 0o600)
    os.write(fd, b"boo")
    os.unlink("ghost")
    eq(os.pread(fd, 3, 0), b"boo", "unlinked file still readable")
    eq(os.fstat(fd).st_nlink, 0, "nlink 0")
    before = set(os.listdir("."))
    t = os.open(".", os.O_TMPFILE | os.O_RDWR, 0o600)
    os.write(t, b"born anonymous")
    eq(set(os.listdir(".")), before, "an O_TMPFILE file showed up in the directory")
    # The documented idiom (open(2)): linkat with AT_SYMLINK_FOLLOW. A plain
    # link(2) -- what os.link() issues by default -- does not follow the
    # /proc magic link on Linux either, and answers EXDEV.
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    rc = libc.linkat(-100, f"/proc/self/fd/{t}".encode(), -100, b"materialized", 0x400)
    eq((rc, ctypes.get_errno() if rc else 0), (0, 0), "linkat(AT_SYMLINK_FOLLOW) of an O_TMPFILE")
    with open("materialized", "rb") as f:
        eq(f.read(), b"born anonymous", "O_TMPFILE given a name")
    # linking never replaces a name, including one the image provides
    # (pacman's tmpfiles hook once replaced /etc/passwd this way)
    t2 = os.open(".", os.O_TMPFILE | os.O_RDWR, 0o600)
    rc = libc.linkat(-100, f"/proc/self/fd/{t2}".encode(), -100, b"materialized", 0x400)
    eq((rc, ctypes.get_errno() if rc else 0), (-1, errno.EEXIST), "linkat over an existing name")
    os.close(t2)
    # the name may be the image's alone, its directory not yet copied up
    image_file = next((os.path.join(d, n) for d in ("/usr/share/doc/bash", "/usr/share/doc/acl", "/etc")
                       if os.path.isdir(d) for n in sorted(os.listdir(d))
                       if os.path.isfile(os.path.join(d, n)) and not os.path.islink(os.path.join(d, n))), None)
    if os.getuid() == 0 and image_file:
        # a file created beside it copies the directory up, as pacman's does
        side = os.path.join(os.path.dirname(image_file), ".lxt-copyup")
        open(side, "w").close()
        t3 = os.open(os.path.dirname(image_file), os.O_TMPFILE | os.O_RDWR, 0o600)
        rc = libc.linkat(-100, f"/proc/self/fd/{t3}".encode(), -100, image_file.encode(), 0x400)
        os.unlink(side)
        eq((rc, ctypes.get_errno() if rc else 0), (-1, errno.EEXIST), f"linkat over {image_file}")
        os.close(t3)
    eq(os.stat("materialized").st_uid, os.getuid(), "a named O_TMPFILE is the caller's")
    return "nlink, shared writes, rename no-op, deleted-but-open, O_TMPFILE"


@test
def rename_rules():
    """rename and renameat2: overwrite rules, RENAME_NOREPLACE, RENAME_EXCHANGE."""
    os.makedirs("ra/inner")
    os.makedirs("rb/full")
    os.makedirs("empty")
    open("f1", "w").close()
    expect_errno((errno.ENOTEMPTY, errno.EEXIST), "onto a non-empty dir", os.rename, "ra", "rb")
    expect_errno(errno.EINVAL, "a dir into itself", os.rename, "ra", "ra/inner/x")
    expect_errno(errno.ENOTDIR, "a dir over a file", os.rename, "ra", "f1")
    expect_errno(errno.EISDIR, "a file over a dir", os.rename, "f1", "ra")
    os.rename("ra", "empty")          # a dir over an empty dir is fine
    check(os.path.isdir("empty/inner") and not os.path.exists("ra"), "dir over empty dir")
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    with open("a", "w") as f:
        f.write("A")
    with open("b", "w") as f:
        f.write("B")
    AT = -100
    # Through syscall(2): musl before 1.2.5 has no renameat2() wrapper.
    nr = {"aarch64": 276, "x86_64": 316}.get(os.uname().machine)
    if nr is None:
        return "overwrite rules (no renameat2 number for this arch)"
    libc.syscall.restype = ctypes.c_long
    renameat2 = lambda a, b, fl: libc.syscall(ctypes.c_long(nr), ctypes.c_int(AT), a,
                                              ctypes.c_int(AT), b, ctypes.c_uint(fl))
    rc = renameat2(b"a", b"b", 1)   # RENAME_NOREPLACE
    eq((rc, ctypes.get_errno()), (-1, errno.EEXIST), "RENAME_NOREPLACE onto an existing name")
    if renameat2(b"a", b"b", 2) == 0:   # RENAME_EXCHANGE
        with open("a") as f, open("b") as g:
            eq((f.read(), g.read()), ("B", "A"), "RENAME_EXCHANGE swapped")
    else:
        check(ctypes.get_errno() in (errno.EINVAL, errno.ENOSYS), "RENAME_EXCHANGE failed oddly")
    return "overwrite rules, NOREPLACE, EXCHANGE"


@test
def holes_and_copies():
    """Sparse files, SEEK_HOLE/DATA, truncate, fallocate, copy_file_range, sendfile, splice."""
    fd = os.open("sparse", os.O_RDWR | os.O_CREAT, 0o644)
    os.pwrite(fd, b"!", 1 << 30)
    st = os.fstat(fd)
    eq(st.st_size, (1 << 30) + 1, "sparse size")
    check(st.st_blocks * 512 < 1 << 20, f"a 1 GiB hole uses {st.st_blocks * 512} bytes")
    eq(os.pread(fd, 4096, 1 << 29), bytes(4096), "a hole reads zeros")
    eq(os.lseek(fd, 0, os.SEEK_HOLE), 0, "SEEK_HOLE")
    check((1 << 30) - (1 << 20) <= os.lseek(fd, 0, os.SEEK_DATA) <= 1 << 30, "SEEK_DATA")
    os.pwrite(fd, b"0123456789ABCDEF", 0)
    os.ftruncate(fd, 10)
    os.ftruncate(fd, 20)
    eq(os.pread(fd, 100, 0), b"0123456789" + bytes(10), "truncate zeroes the regrown tail")
    os.posix_fallocate(fd, 0, 1 << 20)
    eq(os.fstat(fd).st_size, 1 << 20, "fallocate size")
    data = random.Random(4).randbytes(3 << 20)
    src = os.open("src", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(src, data)
    for name, mover in (("copy_file_range", lambda d, n, off: os.copy_file_range(src, d, n, off, off)),
                        ("sendfile", lambda d, n, off: os.sendfile(d, src, off, n))):
        dst = os.open(name, os.O_RDWR | os.O_CREAT, 0o644)
        off = 0
        while off < len(data):
            k = mover(dst, len(data) - off, off)
            check(k > 0, f"{name} stalled")
            off += k
        eq(os.pread(dst, len(data) + 1, 0), data, name)
    dst = os.open("spl", os.O_RDWR | os.O_CREAT, 0o644)
    r, w = os.pipe()
    th = threading.Thread(target=lambda: (os.write(w, data), os.close(w)))
    th.start()
    while os.splice(r, dst, 1 << 16):
        pass
    th.join()
    eq(os.pread(dst, len(data) + 1, 0), data, "splice")
    return "holes, SEEK_HOLE/DATA, truncate, fallocate, 3 MiB x3 movers"


@test
def special_files():
    """FIFOs, /dev nodes and the type bits stat reports for each."""
    os.mkfifo("fifo", 0o600)
    check(stat.S_ISFIFO(os.stat("fifo").st_mode), "mkfifo type")
    expect_errno(errno.EEXIST, "mkfifo twice", os.mkfifo, "fifo")
    expect_errno(errno.ENXIO, "nonblocking write-open with no reader", os.open, "fifo", os.O_WRONLY | os.O_NONBLOCK)
    for dev, kind in (("/dev/null", stat.S_ISCHR), ("/dev/zero", stat.S_ISCHR), ("/dev/tty", stat.S_ISCHR),
                      ("/dev/urandom", stat.S_ISCHR), ("/dev/ptmx", stat.S_ISCHR)):
        check(kind(os.stat(dev).st_mode), f"{dev} type")
    eq(os.major(os.stat("/dev/null").st_rdev), 1, "/dev/null major")
    eq(os.minor(os.stat("/dev/null").st_rdev), 3, "/dev/null minor")
    check(os.path.isdir("/dev/pts") and os.path.isdir("/dev/shm"), "/dev/pts and /dev/shm")
    for link, tgt in (("/dev/stdin", "/proc/self/fd/0"), ("/dev/fd", "/proc/self/fd")):
        eq(os.readlink(link), tgt, link)
    with open("/dev/shm/lxt-shm", "w") as f:
        f.write("shm")
    os.unlink("/dev/shm/lxt-shm")
    import socket
    s = socket.socket(socket.AF_UNIX)
    s.bind("sock")
    check(stat.S_ISSOCK(os.stat("sock").st_mode), "socket node type")
    return "fifo, char devs, major/minor, /dev links, /dev/shm, socket node"


@test
def big_directory():
    """10000 entries listed, scanned, and deleted while iterating."""
    dfd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    for i in range(10000):
        os.close(os.open(f"f{i:05d}", os.O_CREAT | os.O_WRONLY, 0o644, dir_fd=dfd))
    names = os.listdir(".")
    eq((len(names), len(set(names))), (10000, 10000), "listdir")
    eq(sum(1 for _ in os.scandir(".")), 10000, "scandir")
    with os.scandir(".") as it:
        for e in it:
            os.unlink(e.name, dir_fd=dfd)
    eq(os.listdir("."), [], "left after delete-while-iterating")
    return "10000 entries"


@test
def xattrs():
    """user.* extended attributes set, list, get, replace and remove."""
    open("x", "w").close()
    try:
        os.setxattr("x", "user.lxt", b"v1")
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            skip("this filesystem has no user xattrs")
        raise
    check("user.lxt" in os.listxattr("x"), "listxattr")
    eq(os.getxattr("x", "user.lxt"), b"v1", "getxattr")
    expect_errno(errno.EEXIST, "XATTR_CREATE on an existing name", os.setxattr, "x", "user.lxt", b"v", os.XATTR_CREATE)
    expect_errno(errno.ENODATA, "XATTR_REPLACE on a missing name", os.setxattr, "x", "user.nope", b"v", os.XATTR_REPLACE)
    os.setxattr("x", "user.lxt", b"v2", os.XATTR_REPLACE)
    eq(os.getxattr("x", "user.lxt"), b"v2", "replace")
    os.removexattr("x", "user.lxt")
    expect_errno(errno.ENODATA, "getxattr after remove", os.getxattr, "x", "user.lxt")
    return "set/list/get/CREATE/REPLACE/remove"


@test
def openat2_resolve_rules():
    """openat2's RESOLVE_* flags judge the path as the guest named it:
    BENEATH refuses escapes by '..', absolute paths and symlinks, IN_ROOT
    re-roots them, NO_SYMLINKS and NO_MAGICLINKS refuse links."""
    import ctypes
    from lxt import syscall
    NO_MAGIC, NO_SYM, BENEATH, IN_ROOT = 0x02, 0x04, 0x08, 0x10
    os.makedirs("root/sub")
    with open("root/sub/f", "w") as f:
        f.write("in")
    with open("outside", "w") as f:
        f.write("out")
    os.symlink("sub/f", "root/inlink")
    os.symlink("../outside", "root/outlink")
    os.symlink("/sub/f", "root/abslink")
    rfd = os.open("root", os.O_PATH | os.O_DIRECTORY)

    def o2(path, resolve, dirfd=rfd, flags=os.O_RDONLY):
        how = (ctypes.c_uint64 * 3)(flags, 0, resolve)
        return syscall("openat2", dirfd, path.encode(), how, 24)

    def read(path, resolve):
        fd = o2(path, resolve)
        try:
            return os.read(fd, 16).decode()
        finally:
            os.close(fd)

    try:
        eq(read("sub/f", BENEATH), "in", "a plain path beneath")
    except OSError as e:
        if e.errno == errno.ENOSYS:
            skip("no openat2 here")
        raise
    eq(read("sub/../sub/f", BENEATH), "in", "'..' that stays beneath")
    eq(read("inlink", BENEATH), "in", "a symlink that stays beneath")
    expect_errno(errno.EXDEV, "'..' out of the root", o2, "../outside", BENEATH)
    expect_errno(errno.EXDEV, "an absolute path", o2, "/etc/hostname", BENEATH)
    expect_errno(errno.EXDEV, "a symlink out", o2, "outlink", BENEATH)
    expect_errno(errno.EXDEV, "an absolute symlink", o2, "abslink", BENEATH)
    eq(read("abslink", IN_ROOT), "in", "IN_ROOT re-roots an absolute symlink")
    eq(read("../../sub/f", IN_ROOT), "in", "IN_ROOT clamps '..' at the root")
    expect_errno(errno.ELOOP, "NO_SYMLINKS on a link", o2, "inlink", NO_SYM)
    expect_errno(errno.ELOOP, "NO_MAGICLINKS on /proc/self/cwd", o2,
                 "/proc/self/cwd", NO_MAGIC, -100, os.O_PATH)
    expect_errno(errno.EINVAL, "BENEATH with IN_ROOT", o2, "sub/f", BENEATH | IN_ROOT)
    fd = o2("sub/new", BENEATH, flags=os.O_CREAT | os.O_WRONLY)
    os.close(fd)
    check(os.path.exists("root/sub/new"), "O_CREAT beneath made the file")
    os.close(rfd)
    return "BENEATH, IN_ROOT, NO_SYMLINKS, NO_MAGICLINKS"
