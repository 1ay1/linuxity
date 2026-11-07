"""UDP over loopback: datagram boundaries, truncation, connected sockets."""
import errno
import random
import socket

from lxt import check, eq, expect_errno, must, spawn, test


@test
def echo_datagrams():
    """1000 datagrams up to 60 KB echoed by another process, intact."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))

    def echo():
        while True:
            d, a = srv.recvfrom(65536)
            if d == b"bye":
                return
            srv.sendto(d, a)

    pid = spawn(echo)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(5)
    c.connect(srv.getsockname())
    rnd = random.Random(11)
    for i in range(1000):
        d = rnd.randbytes(rnd.randint(1, 60000))
        c.send(d)
        eq(c.recv(65536), d, f"datagram {i}")
    c.send(b"bye")
    must(pid)
    return "1000 datagrams"


@test
def boundaries_and_truncation():
    """Datagrams keep their edges; a short buffer truncates; MSG_TRUNC tells the real size."""
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.bind(("127.0.0.1", 0))
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for n in (1, 7, 1400, 9000):
        b.sendto(bytes([n % 256]) * n, a.getsockname())
    eq([len(a.recv(65536)) for _ in range(4)], [1, 7, 1400, 9000], "boundaries")
    b.sendto(b"x" * 100, a.getsockname())
    data, _, flags, _ = a.recvmsg(10)
    eq((len(data), bool(flags & socket.MSG_TRUNC)), (10, True), "truncated recvmsg")
    b.sendto(b"y" * 300, a.getsockname())
    eq(len(a.recv(10, socket.MSG_PEEK)), 10, "peek into a short buffer")
    n = a.recv_into(bytearray(10), 0, socket.MSG_TRUNC)
    eq(n, 300, "MSG_TRUNC returns the datagram's real length")
    b.sendto(b"", a.getsockname())
    eq(a.recv(10), b"", "a zero-length datagram")
    return "edges, MSG_TRUNC, zero-length"


@test
def connected_udp():
    """A connected UDP socket filters senders and reports ICMP refusals."""
    a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.bind(("127.0.0.1", 0))
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    peer.bind(("127.0.0.1", 0))
    stranger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    a.connect(peer.getsockname())
    stranger.sendto(b"ignore me", a.getsockname())
    peer.sendto(b"from peer", a.getsockname())
    a.settimeout(2)
    eq(a.recv(100), b"from peer", "connected socket drops strangers")
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))
    port = dead.getsockname()[1]
    dead.close()
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.connect(("127.0.0.1", port))
    c.settimeout(2)
    c.send(b"anyone?")
    expect_errno(errno.ECONNREFUSED, "recv after sending to a closed port", c.recv, 10)
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    b.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    check(b.getsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST), "SO_BROADCAST")
    return "sender filter, ICMP refusal, SO_BROADCAST"
