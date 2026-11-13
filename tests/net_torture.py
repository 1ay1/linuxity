#!/usr/bin/env python3
"""net_torture.py -- Linux networking: TCP, UDP, AF_UNIX, readiness, names.

Loopback only, except one check that reaches the internet (and skips, saying
so, when there is none). See torture.py for how to run it.
"""
import sys
sys.dont_write_bytecode = True
import array
import hashlib
import os
import select
import signal
import socket
import struct
import threading
import time

from torture import *  # noqa: F401,F403
from torture import check, ok, eq, expect_errno, child, status, run_in_child, Skip, main
import errno


def listener(family=socket.AF_INET, host="127.0.0.1", kind=socket.SOCK_STREAM):
    s = socket.socket(family, kind)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, 0))
    if kind == socket.SOCK_STREAM:
        s.listen(128)
    return s


def recv_exact(s, n):
    buf = bytearray()
    while len(buf) < n:
        b = s.recv(min(1 << 20, n - len(buf)))
        if not b:
            break
        buf += b
    return bytes(buf)


# ---------------------------------------------------------------- TCP

@check
def tcp_loopback_echo_and_names():
    srv = listener()
    port = srv.getsockname()[1]
    ok(port > 0, "an ephemeral port was assigned")

    def echo():
        c, _ = srv.accept()
        while (b := c.recv(65536)):
            c.sendall(b)
        c.close()
        return 0
    pid = child(echo)
    srv.close()
    c = socket.create_connection(("127.0.0.1", port), timeout=10)
    eq(c.getpeername(), ("127.0.0.1", port), "getpeername")
    eq(c.getsockname()[0], "127.0.0.1", "getsockname address")
    data = os.urandom(1 << 20)
    t = threading.Thread(target=c.sendall, args=(data,))
    t.start()
    got = recv_exact(c, len(data))
    t.join()
    eq(hashlib.sha256(got).hexdigest(), hashlib.sha256(data).hexdigest(), "1 MiB echoed intact")
    c.shutdown(socket.SHUT_WR)
    eq(c.recv(10), b"", "EOF after the server closes")
    c.close()
    eq(status(pid), 0, "server")


@check
def tcp_ipv6_loopback():
    if not socket.has_ipv6:
        raise Skip("no IPv6 support compiled in")
    try:
        srv = listener(socket.AF_INET6, "::1")
    except OSError as e:
        raise Skip(f"no ::1 here: {e}")
    port = srv.getsockname()[1]
    c = socket.create_connection(("::1", port), timeout=5)
    a, peer = srv.accept()
    eq(peer[0], "::1", "peer address")
    c.sendall(b"six")
    eq(a.recv(3), b"six", "data over IPv6")


@check
def tcp_connect_refused_and_unreachable_port():
    s = listener()
    port = s.getsockname()[1]
    s.close()                                   # nobody listens there now
    c = socket.socket()
    expect_errno(errno.ECONNREFUSED, "connect to a closed port", c.connect, ("127.0.0.1", port))


@check
def tcp_nonblocking_connect_and_so_error():
    srv = listener()
    c = socket.socket()
    c.setblocking(False)
    rc = c.connect_ex(srv.getsockname())
    ok(rc in (0, errno.EINPROGRESS), f"non-blocking connect: {errname(rc)}")
    p = select.poll()
    p.register(c, select.POLLOUT)
    ok(p.poll(5000), "writable once connected")
    eq(c.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR), 0, "SO_ERROR after success")
    a, _ = srv.accept()
    expect_errno(errno.EAGAIN, "recv with nothing queued", c.recv, 10)
    a.send(b"x")
    ok(select.select([c], [], [], 5)[0], "readable after the peer sends")
    eq(c.recv(10), b"x", "the byte")


@check
def tcp_half_close_both_ways():
    srv = listener()
    c = socket.create_connection(srv.getsockname())
    a, _ = srv.accept()
    c.sendall(b"request")
    c.shutdown(socket.SHUT_WR)
    eq(recv_exact(a, 7), b"request", "request")
    eq(a.recv(10), b"", "server sees EOF after SHUT_WR")
    a.sendall(b"reply")                         # the other direction stays open
    a.close()
    eq(recv_exact(c, 5), b"reply", "client still reads after its own SHUT_WR")
    eq(c.recv(10), b"", "then EOF")


@check
def tcp_close_with_unread_data_resets():
    srv = listener()
    c = socket.create_connection(srv.getsockname())
    a, _ = srv.accept()
    c.sendall(b"unread")
    time.sleep(0.1)
    a.close()                                   # unread data -> RST (RFC 2525)
    time.sleep(0.1)
    try:
        c.sendall(b"x" * 10)
        time.sleep(0.1)
        c.recv(10)
        got = 0
    except OSError as e:
        got = e.errno
    ok(got in (errno.ECONNRESET, errno.EPIPE), f"peer reset: {errname(got)}")


@check
def tcp_options():
    s = socket.socket()
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ok(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY), "TCP_NODELAY")
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    ok(s.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), "SO_KEEPALIVE")
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 16)
    ok(s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) >= 1 << 16, "SO_RCVBUF (Linux doubles it)")
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    eq(struct.unpack("ii", s.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 8)), (1, 0), "SO_LINGER")
    eq(s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE), socket.SOCK_STREAM, "SO_TYPE")
    eq(s.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN), socket.AF_INET, "SO_DOMAIN")
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    eq(s.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE), 30, "TCP_KEEPIDLE")


@check
def tcp_bind_rules():
    a = listener()
    port = a.getsockname()[1]
    b = socket.socket()
    expect_errno(errno.EADDRINUSE, "a second bind of a listening port", b.bind, ("127.0.0.1", port))
    x = socket.socket(); x.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    x.bind(("127.0.0.1", 0)); x.listen()
    y = socket.socket(); y.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    y.bind(x.getsockname()); y.listen()         # SO_REUSEPORT: both may bind
    s = socket.socket()
    expect_errno(errno.EADDRNOTAVAIL, "bind to an address we don't have", s.bind, ("192.0.2.1", 0))


@check
def tcp_many_concurrent_clients():
    srv = listener()
    addr = srv.getsockname()

    def server():
        import selectors
        sel = selectors.DefaultSelector()
        sel.register(srv, selectors.EVENT_READ)
        served = 0
        while served < 100:
            for key, _ in sel.select(10):
                if key.fileobj is srv:
                    c, _ = srv.accept()
                    sel.register(c, selectors.EVENT_READ)
                else:
                    b = key.fileobj.recv(100)
                    if b:
                        key.fileobj.sendall(b[::-1])
                    else:
                        sel.unregister(key.fileobj); key.fileobj.close(); served += 1
        return 0
    pid = child(server)
    socks = [socket.create_connection(addr, timeout=10) for _ in range(100)]
    for i, s in enumerate(socks):
        s.sendall(f"msg{i:03}".encode())
    for i, s in enumerate(socks):
        eq(recv_exact(s, 6), f"msg{i:03}".encode()[::-1], f"client {i}")
        s.close()
    eq(status(pid), 0, "the server saw all 100")


@check
def tcp_peek_waitall_and_timeouts():
    srv = listener()
    c = socket.create_connection(srv.getsockname())
    a, _ = srv.accept()
    a.sendall(b"abcdef")
    time.sleep(0.05)
    eq(c.recv(3, socket.MSG_PEEK), b"abc", "MSG_PEEK")
    eq(c.recv(3), b"abc", "peek did not consume")

    def later():
        time.sleep(0.2); a.sendall(b"ghij")
    threading.Thread(target=later).start()
    eq(c.recv(7, socket.MSG_WAITALL), b"defghij", "MSG_WAITALL waits for all 7")
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, struct.pack("ll", 0, 200000))
    t = time.monotonic()
    expect_errno((errno.EAGAIN, errno.EWOULDBLOCK), "SO_RCVTIMEO expires", c.recv, 1)
    ok(0.15 < time.monotonic() - t < 2, f"after ~0.2s ({time.monotonic() - t:.2f})")


@check(timeout=60)
def tcp_16mib_full_duplex():
    srv = listener()
    c = socket.create_connection(srv.getsockname())
    a, _ = srv.accept()
    up, down = os.urandom(16 << 20), os.urandom(16 << 20)
    got = {}

    def side(sock, data, key):
        t = threading.Thread(target=sock.sendall, args=(data,))
        t.start()
        got[key] = recv_exact(sock, len(data))
        t.join()
    t1 = threading.Thread(target=side, args=(c, up, "c"))
    t2 = threading.Thread(target=side, args=(a, down, "a"))
    t1.start(); t2.start(); t1.join(); t2.join()
    eq(got["a"] == up and got["c"] == down, True, "both 16 MiB streams intact")


@check
def sendfile_and_splice_to_socket():
    data = os.urandom(300_000)
    with open("f", "wb") as f:
        f.write(data)
    srv = listener()
    c = socket.create_connection(srv.getsockname())
    a, _ = srv.accept()
    fd = os.open("f", os.O_RDONLY)
    sent = 0
    while sent < len(data):
        sent += os.sendfile(c.fileno(), fd, sent, len(data) - sent)
    c.shutdown(socket.SHUT_WR)
    eq(recv_exact(a, len(data) + 1), data, "sendfile file -> TCP")


# ---------------------------------------------------------------- UDP

@check
def udp_datagrams_keep_their_boundaries():
    r = listener(kind=socket.SOCK_DGRAM)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for m in (b"one", b"two two", b"", b"x" * 60000):
        s.sendto(m, r.getsockname())
    for m in (b"one", b"two two", b"", b"x" * 60000):
        got, src = r.recvfrom(65536)
        eq(got, m, f"datagram of {len(m)}")
    eq(src[0], "127.0.0.1", "sender address")
    s.sendto(b"truncate me", r.getsockname())
    data, _, flags, _ = r.recvmsg(4)
    eq(data, b"trun", "a short buffer truncates")
    ok(flags & socket.MSG_TRUNC, "and says MSG_TRUNC")
    expect_errno(errno.EMSGSIZE, "a datagram over 64 KiB", s.sendto, b"x" * 70000, r.getsockname())


@check
def udp_connected_gets_icmp_refusals():
    r = listener(kind=socket.SOCK_DGRAM)
    port = r.getsockname()[1]
    r.close()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("127.0.0.1", port))
    s.send(b"anyone?")
    s.settimeout(2)
    expect_errno(errno.ECONNREFUSED, "the port-unreachable comes back", s.recv, 10)


@check
def udp_broadcast_and_multicast_options():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    ok(s.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST), "SO_BROADCAST")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    eq(s.getsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL), 4, "IP_MULTICAST_TTL")
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 33)
    eq(s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL), 33, "IP_TTL")


# ---------------------------------------------------------------- AF_UNIX

@check
def unix_stream_by_path():
    srv = socket.socket(socket.AF_UNIX)
    srv.bind("s.sock")
    srv.listen()
    ok(os.path.exists("s.sock"), "bind made the socket file")

    def client():
        c = socket.socket(socket.AF_UNIX)
        c.connect("s.sock")
        c.sendall(b"hello")
        return 0 if c.recv(5) == b"olleh" else 1
    pid = child(client)
    a, _ = srv.accept()
    a.sendall(recv_exact(a, 5)[::-1])
    eq(status(pid), 0, "client")
    eq(srv.getsockname(), "s.sock", "getsockname gives the path as bound")


@check
def unix_abstract_names():
    name = f"\0torture-{os.getpid()}"
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(name)
    srv.listen()
    eq(os.listdir("."), [], "no file for an abstract name")
    c = socket.socket(socket.AF_UNIX)
    c.connect(name)
    a, _ = srv.accept()
    c.sendall(b"abs")
    eq(a.recv(3), b"abs", "data over an abstract socket")
    s2 = socket.socket(socket.AF_UNIX)
    expect_errno(errno.EADDRINUSE, "the name is taken", s2.bind, name)
    srv.close(); a.close(); c.close()
    s3 = socket.socket(socket.AF_UNIX)
    s3.bind(name)                               # freed with its last socket


@check
def unix_dgram_and_seqpacket_boundaries():
    for kind in (socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
        a, b = socket.socketpair(socket.AF_UNIX, kind)
        for m in (b"1", b"22", b"333"):
            a.send(m)
        eq([b.recv(100) for _ in range(3)], [b"1", b"22", b"333"], f"boundaries ({kind.name})")
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    a.close()
    eq(b.recv(10), b"", "SEQPACKET EOF")


@check
def unix_passes_fds_and_credentials():
    with open("f", "w") as f:
        f.write("through the socket")
    a, b = socket.socketpair()
    r, w = os.pipe()

    def sender():
        fd = os.open("f", os.O_RDONLY)
        socket.send_fds(b, [b"fds"], [fd, w])
        return 0
    pid = child(sender)
    msg, fds, _, _ = socket.recv_fds(a, 10, 4)
    eq(status(pid), 0, "sender")
    eq((msg, len(fds)), (b"fds", 2), "two fds arrive")
    eq(os.read(fds[0], 100), b"through the socket", "the passed file reads")
    os.write(fds[1], b"pipe")
    eq(os.read(r, 4), b"pipe", "the passed pipe end writes")
    a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    pid, uid, gid = struct.unpack("3i", a.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    eq((pid, uid, gid), (os.getpid(), os.getuid(), os.getgid()), "SO_PEERCRED of a socketpair")

    def peer():
        c = socket.socket(socket.AF_UNIX)
        c.connect("cred.sock")
        c.recv(1)
        return 0
    srv = socket.socket(socket.AF_UNIX)
    srv.bind("cred.sock"); srv.listen()
    kid = child(peer)
    conn, _ = srv.accept()
    p, _, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    eq(p, kid, "SO_PEERCRED names the connecting process")
    conn.send(b"k")
    eq(status(kid), 0, "peer")


@check
def a_passed_socket_keeps_its_data_in_flight():
    # Firefox's fork server gets each new content process's channel this
    # way: the browser sends one end of a fresh socketpair, closes its copy,
    # writes the launch info into the other end and closes that too -- all
    # before the fork server reads the message. Linux keeps the end and its
    # data alive inside the queued message. XNU's unix-socket garbage
    # collector, which any closing socket with fds in it sets off, flushed
    # it: the receiver read EOF, and every content process MOZ_CRASHed.
    conn_a, conn_b = socket.socketpair()

    def receiver():
        conn_a.close()
        time.sleep(0.3)                    # let the sender finish first
        _, fds, _, _ = socket.recv_fds(conn_b, 10, 2)
        got = b""
        while chunk := os.read(fds[0], 4096):
            got += chunk
        return 0 if got == b"E" * 724 else 3
    pid = child(receiver)
    conn_b.close()
    e0, e1 = socket.socketpair()
    socket.send_fds(conn_a, [b"x"], [e1.fileno()])
    e1.close()
    e0.send(b"E" * 724)
    x0, x1 = socket.socketpair()           # any closing socket with fds in flight
    socket.send_fds(x0, [b"y"], [x1.fileno()])
    for s in (x1, x0, e0):
        s.close()
    eq(status(pid), 0, "the receiver reads all 724 bytes, then EOF")


@check
def broken_connections_sigpipe_and_epipe():
    a, b = socket.socketpair()
    b.close()
    expect_errno(errno.EPIPE, "send with MSG_NOSIGNAL", a.send, b"x", socket.MSG_NOSIGNAL)

    def default_sigpipe():
        x, y = socket.socketpair()
        y.close()
        x.send(b"x")
        return 1
    eq(run_in_child(default_sigpipe), -signal.SIGPIPE, "a plain send dies of SIGPIPE")
    r, w = os.pipe()
    p = select.poll(); p.register(a, select.POLLIN)
    ev = p.poll(1000)
    ok(ev and ev[0][1] & (select.POLLHUP | select.POLLIN), f"poll sees the hangup: {ev}")


# ---------------------------------------------------------------- readiness

@check
def epoll_level_and_edge_on_sockets():
    a, b = socket.socketpair()
    a.setblocking(False); b.setblocking(False)
    lt, et = select.epoll(), select.epoll()
    lt.register(a, select.EPOLLIN)
    et.register(a, select.EPOLLIN | select.EPOLLET)
    b.send(b"xy")
    eq(len(lt.poll(1)), 1, "LT ready")
    eq(len(et.poll(1)), 1, "ET ready")
    eq(len(lt.poll(0.1)), 1, "LT stays ready while data is unread")
    eq(len(et.poll(0.1)), 0, "ET fires once per arrival")
    a.recv(10)
    eq(len(lt.poll(0.1)), 0, "LT quiet once drained")
    b.send(b"z")
    eq(len(et.poll(1)), 1, "ET fires again on new data")
    b.close()
    ev = lt.poll(1)
    ok(ev and ev[0][1] & (select.EPOLLHUP | select.EPOLLRDHUP | select.EPOLLIN), f"hangup: {ev}")
    o = select.epoll()
    s = socket.socket()
    o.register(s, select.EPOLLOUT | select.EPOLLONESHOT)
    o.poll(0.1)
    eq(o.poll(0.1), [], "EPOLLONESHOT disarms")
    expect_errno(errno.EEXIST, "registering twice", o.register, s, select.EPOLLIN)


@check
def poll_a_thousand_sockets():
    import resource
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    limit = min(hard, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (limit, hard))     # the 1024 default is too few
    npairs = min(600, (limit - 64) // 2)
    pairs = [socket.socketpair() for _ in range(npairs)]
    p = select.poll()
    for a, _ in pairs:
        p.register(a, select.POLLIN)
    for i in range(0, npairs, 7):
        pairs[i][1].send(b"!")
    ready = {fd for fd, ev in p.poll(2000)}
    eq(ready, {pairs[i][0].fileno() for i in range(0, npairs, 7)}, f"exactly the written ones of {npairs}")


# ---------------------------------------------------------------- names

@check
def local_names_resolve():
    infos = socket.getaddrinfo("localhost", 80, proto=socket.IPPROTO_TCP)
    addrs = {i[4][0] for i in infos}
    ok("127.0.0.1" in addrs or "::1" in addrs, f"localhost: {addrs}")
    eq(socket.getaddrinfo("10.1.2.3", None)[0][4][0], "10.1.2.3", "a numeric address")
    host = socket.gethostname()
    eq(host, os.uname().nodename, "gethostname == uname nodename")
    socket.getaddrinfo(host, None)              # our own name resolves
    ok(socket.getservbyname("ssh", "tcp") == 22, "/etc/services")
    names = [n for _, n in socket.if_nameindex()]
    ok("lo" in names, f"interfaces: {names}")
    with open("/proc/net/dev") as f:
        ok("lo:" in f.read(), "/proc/net/dev lists lo")


@check
def internet_dns_and_tcp():
    try:
        infos = socket.getaddrinfo("example.com", 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise Skip(f"no DNS from here ({e}); is the host offline?")
    last = None
    for fam, kind, proto, _, addr in infos:
        try:
            s = socket.socket(fam, kind, proto)
            s.settimeout(5)
            s.connect(addr)
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            reply = s.recv(100)
            ok(reply.startswith(b"HTTP/"), f"an HTTP reply: {reply[:30]!r}")
            return
        except OSError as e:
            last = e
    raise AssertionError(f"resolved {len(infos)} addresses but connected to none: {last}")


if __name__ == "__main__":
    sys.exit(main("networking"))
