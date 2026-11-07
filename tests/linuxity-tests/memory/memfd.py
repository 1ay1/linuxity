"""memfd: anonymous files, sealing, sharing by fd and by /proc path."""
import errno
import fcntl
import mmap
import os
import socket

from lxt import ENV, check, eq, expect_errno, must, reap, spawn, test


@test
def create_and_name():
    """memfd_create gives a sized, named, writable file with no path."""
    fd = os.memfd_create("lxt-mem")
    os.write(fd, b"x" * 10000)
    eq(os.fstat(fd).st_size, 10000, "size")
    link = os.readlink(f"/proc/self/fd/{fd}")
    check(link.startswith("/memfd:lxt-mem") and link.endswith("(deleted)"), f"link {link!r}")
    eq(os.fstat(fd).st_nlink, 0, "nlink")
    try:
        with open(f"/proc/self/fd/{fd}", "rb") as f:
            eq(f.read(), b"x" * 10000, "reopen through /proc")
    except PermissionError:
        # Android's SELinux refuses reopening a memfd; only on someone else's kernel
        if not ENV["host_kernel"]:
            raise
        link += ", reopen refused by the host [host]"
    expect_errno(errno.EINVAL, "a name over 249 bytes", os.memfd_create, "n" * 250)
    c = os.memfd_create("cloexec", os.MFD_CLOEXEC)
    check(fcntl.fcntl(c, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, "MFD_CLOEXEC")
    return link


@test
def seals():
    """Seals stop writes, shrinking, growing, and further sealing."""
    fd = os.memfd_create("sealed", os.MFD_ALLOW_SEALING)
    os.write(fd, b"sealed!")
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW)
    expect_errno(errno.EPERM, "shrink when sealed", os.ftruncate, fd, 1)
    expect_errno(errno.EPERM, "grow when sealed", os.ftruncate, fd, 100)
    os.pwrite(fd, b"S", 0)   # in-place write still allowed
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE)
    expect_errno(errno.EPERM, "write when sealed", os.pwrite, fd, b"x", 0)
    expect_errno(errno.EPERM, "writable shared map when sealed",
                 mmap.mmap, fd, 7, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL)
    expect_errno(errno.EPERM, "seal after F_SEAL_SEAL", fcntl.fcntl, fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW)
    s = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
    eq(s, fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SEAL, "F_GET_SEALS")
    nf = os.memfd_create("no-sealing")
    expect_errno(errno.EPERM, "seal without MFD_ALLOW_SEALING", fcntl.fcntl, nf, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE)
    eq(os.pread(fd, 7, 0), b"Sealed!", "content")
    return "SHRINK GROW WRITE SEAL, mmap refused, no-sealing memfd"


@test
def share_by_fork_and_socket():
    """A memfd mapping is shared with a forked child and with a process given the fd."""
    fd = os.memfd_create("shared")
    os.ftruncate(fd, 1 << 16)
    m = mmap.mmap(fd, 1 << 16)

    def poke():
        m[100:105] = b"memfd"

    must(spawn(poke))
    eq(os.pread(fd, 5, 100), b"memfd", "fork child's write")
    a, b = socket.socketpair()

    def receiver():
        _, fds, _, _ = socket.recv_fds(b, 16, 1)
        mm = mmap.mmap(fds[0], 1 << 16)
        mm[200:206] = b"passed"
        return 0

    pid = spawn(receiver)
    socket.send_fds(a, [b"fd"], [fd])
    eq(reap(pid), 0, "receiver")
    eq(m[200:206], b"passed", "write through an fd passed over a socket")
    return "fork and SCM_RIGHTS sharing"
