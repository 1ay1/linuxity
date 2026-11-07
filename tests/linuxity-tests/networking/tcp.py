"""TCP over loopback: streams, half-close, options, errors, IPv6."""
import errno
import socket
import time

from lxt import check, eq, expect_errno, skip, test
from networking._echo import swarm


def listener(family=socket.AF_INET, host="127.0.0.1", backlog=128):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.bind((host, 0))
    s.listen(backlog)
    return s


@test
def echo_swarm_v4():
    """32 processes stream 256 KiB each through one server."""
    srv = listener()
    return swarm(socket.AF_INET, srv.getsockname(), srv)


@test
def semantics():
    """Half-close, peer/sock names, refused connects, Nagle off, reuseaddr."""
    srv = listener()
    addr = srv.getsockname()
    c = socket.create_connection(addr)
    a, peer = srv.accept()
    eq(c.getpeername(), addr, "getpeername")
    eq(a.getpeername(), c.getsockname(), "accept's peer address")
    eq(peer, c.getsockname(), "accept's returned address")
    c.sendall(b"ping")
    c.shutdown(socket.SHUT_WR)
    eq(a.recv(10), b"ping", "data before FIN")
    eq(a.recv(10), b"", "EOF after half-close")
    a.sendall(b"still open")
    eq(c.recv(20), b"still open", "the other direction after SHUT_WR")
    a.close()
    c.close()
    t = socket.socket()
    t.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    eq(t.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), 1, "TCP_NODELAY")
    t.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
    check(t.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) >= 1 << 16, "SO_RCVBUF")
    port = addr[1]
    srv.close()
    expect_errno(errno.ECONNREFUSED, "connect to a closed port", socket.create_connection, ("127.0.0.1", port))
    r = socket.socket()
    r.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    r.bind(("127.0.0.1", port))      # reuse right after close
    busy = listener()
    dup = socket.socket()
    expect_errno(errno.EADDRINUSE, "bind a port in use", dup.bind, busy.getsockname())
    return "half-close, names, ECONNREFUSED, NODELAY, RCVBUF, REUSEADDR, EADDRINUSE"


@test
def nonblocking_connect():
    """Nonblocking connect finishes via poll; SO_ERROR reports the result."""
    import select
    srv = listener()
    c = socket.socket()
    c.setblocking(False)
    rc = c.connect_ex(srv.getsockname())
    check(rc in (0, errno.EINPROGRESS), f"connect_ex {errno.errorcode.get(rc, rc)}")
    _, w, _ = select.select([], [c], [], 5)
    check(w, "never became writable")
    eq(c.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), 0, "SO_ERROR")
    expect_errno((errno.EAGAIN, errno.EWOULDBLOCK), "recv with no data", c.recv, 1)
    srv.close()
    bad = socket.socket()
    bad.setblocking(False)
    bad.connect_ex(("127.0.0.1", 1))
    select.select([], [bad], [], 5)
    eq(bad.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), errno.ECONNREFUSED, "SO_ERROR for a refused connect")
    return "EINPROGRESS -> writable -> SO_ERROR"


@test
def ipv6_loopback():
    """::1 works if the host has IPv6 at all."""
    if not socket.has_ipv6:
        skip("python built without IPv6")
    try:
        srv = listener(socket.AF_INET6, "::1")
    except OSError as e:
        skip(f"no IPv6 loopback: {e.strerror}")
    c = socket.create_connection(srv.getsockname()[:2])
    a, _ = srv.accept()
    c.sendall(b"v6")
    eq(a.recv(2), b"v6", "data over ::1")
    return "::1"


@test
def many_connections():
    """500 simultaneous connections, each answered."""
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    want = min(hard if hard != resource.RLIM_INFINITY else 8192, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, want), hard))
    n = max(10, min(500, (resource.getrlimit(resource.RLIMIT_NOFILE)[0] - 100) // 2))
    srv = listener(backlog=n + 16)
    cs = [socket.create_connection(srv.getsockname()) for _ in range(n)]
    acc = [srv.accept()[0] for _ in range(n)]
    for i, c in enumerate(cs):
        c.send(b"%d" % i)
    got = sorted(int(a.recv(16)) for a in acc)
    eq(got, list(range(n)), "every connection's byte")
    t = time.monotonic()
    for c in cs:
        c.close()
    return f"{n} connections, closed in {time.monotonic() - t:.2f}s"
