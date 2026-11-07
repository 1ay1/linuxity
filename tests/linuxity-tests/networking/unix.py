"""AF_UNIX: paths, the abstract namespace, credentials and fd passing."""
import os
import socket
import stat
import struct

from lxt import check, eq, expect_errno, must, reap, spawn, test
from networking._echo import swarm
import errno


@test
def path_sockets():
    """Bind by relative and absolute path, connect, unlink; EADDRINUSE; ENOENT."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind("rel.sock")
    srv.listen()
    check(stat.S_ISSOCK(os.stat("rel.sock").st_mode), "a bound path is a socket node")
    check("rel.sock" in os.listdir("."), "socket isn't in the cwd")
    c = socket.socket(socket.AF_UNIX)
    c.connect(os.path.abspath("rel.sock"))
    a, _ = srv.accept()
    c.send(b"hi")
    eq(a.recv(2), b"hi", "data")
    eq(srv.getsockname(), "rel.sock", "getsockname keeps the guest's spelling")
    dup = socket.socket(socket.AF_UNIX)
    expect_errno(errno.EADDRINUSE, "bind an existing path", dup.bind, "rel.sock")
    os.unlink("rel.sock")
    expect_errno((errno.ENOENT, errno.ECONNREFUSED), "connect after unlink",
                 socket.socket(socket.AF_UNIX).connect, "rel.sock")
    return "relative/absolute, node type, getsockname, EADDRINUSE, unlink"


@test
def path_swarm():
    """32 processes x 256 KiB through a path socket."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind("echo.sock")
    srv.listen(64)
    return swarm(socket.AF_UNIX, "echo.sock", srv)


@test
def abstract_swarm():
    """32 processes x 256 KiB through an abstract-namespace socket."""
    addr = b"\0lxt-%d" % os.getpid()
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(addr)
    srv.listen(64)
    eq(srv.getsockname(), addr, "abstract getsockname")
    return swarm(socket.AF_UNIX, addr, srv)


@test
def peer_credentials():
    """SO_PEERCRED names the connecting process; SCM_CREDENTIALS too."""
    srv = socket.socket(socket.AF_UNIX)
    srv.bind("cred.sock")
    srv.listen()

    def client():
        c = socket.socket(socket.AF_UNIX)
        c.connect("cred.sock")
        c.sendall(str(os.getpid()).encode())
        c.recv(1)

    pid = spawn(client)
    conn, _ = srv.accept()
    cpid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    said = int(conn.recv(32))
    conn.send(b"k")
    must(pid)
    eq((said, cpid), (pid, pid), "child's getpid vs SO_PEERCRED")
    eq((uid, gid), (os.getuid(), os.getgid()), "SO_PEERCRED ids")
    a, b = socket.socketpair()
    b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    a.sendmsg([b"c"], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("3i", os.getpid(), os.getuid(), os.getgid()))])
    _, anc, _, _ = b.recvmsg(1, 64)
    eq(struct.unpack("3i", anc[0][2]), (os.getpid(), os.getuid(), os.getgid()), "SCM_CREDENTIALS")
    return "SO_PEERCRED, SCM_CREDENTIALS"


@test
def fd_passing():
    """200 fds (files and memfds) over SCM_RIGHTS, and a pipe sent back."""
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    fds = []
    for i in range(200):
        fd = os.open(f"f{i}", os.O_RDWR | os.O_CREAT, 0o644) if i % 2 else os.memfd_create(f"m{i}")
        os.write(fd, f"payload-{i}".encode())
        os.lseek(fd, 0, 0)
        fds.append(fd)

    def child():
        a.close()
        _, got, _, _ = socket.recv_fds(b, 1024, 253)
        check(len(got) == 200, f"received {len(got)}/200")
        for i, fd in enumerate(got):
            check(os.read(fd, 100) == f"payload-{i}".encode(), f"fd {i}")
        pr, pw = os.pipe()
        socket.send_fds(b, [b"p"], [pr])
        os.write(pw, b"through-a-passed-pipe")

    pid = spawn(child)
    b.close()
    socket.send_fds(a, [b"files"], fds)
    _, back, _, _ = socket.recv_fds(a, 16, 1)
    eq(os.read(back[0], 100), b"through-a-passed-pipe", "pipe passed back")
    must(pid)
    return "200 out, 1 back"


@test
def message_boundaries():
    """DGRAM and SEQPACKET socketpairs keep message edges; MSG_PEEK doesn't consume."""
    for kind, name in ((socket.SOCK_DGRAM, "DGRAM"), (socket.SOCK_SEQPACKET, "SEQPACKET")):
        a, b = socket.socketpair(socket.AF_UNIX, kind)
        sizes = [1, 7, 4096, 30000, 1, 2]
        for n in sizes:
            a.send(bytes([n % 256]) * n)
        eq([len(b.recv(65536)) for _ in sizes], sizes, f"{name} boundaries")
        a.send(b"peekaboo")
        eq((b.recv(4, socket.MSG_PEEK), b.recv(100)), (b"peek", b"peekaboo"), f"{name} MSG_PEEK")
    a, b = socket.socketpair()
    a.close()
    eq(b.recv(1), b"", "EOF when the peer closes")
    expect_errno(errno.EPIPE, "send to a closed peer", b.send, b"x")
    return "DGRAM, SEQPACKET, PEEK, EOF, EPIPE"
