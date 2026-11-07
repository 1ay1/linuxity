"""Shared echo-swarm helper for the socket tests."""
import random
import socket
import threading

from lxt import check, reap, spawn


def echo_server(srv):
    def handle(c):
        with c:
            while (d := c.recv(65536)):
                c.sendall(d)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def swarm(family, addr, srv, clients=32, size=256 << 10):
    """`clients` processes each echo `size` random bytes through srv."""
    echo_server(srv)

    def client(n):
        data = random.Random(n).randbytes(size)
        s = socket.socket(family, socket.SOCK_STREAM)
        s.connect(addr)

        def send():
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)

        t = threading.Thread(target=send)
        t.start()
        got = bytearray()
        while (d := s.recv(65536)):
            got += d
        t.join()
        check(got == data, f"client {n}: {len(got)}/{size} bytes back")

    bad = [p for p in [spawn(client, i) for i in range(clients)] if reap(p) != 0]
    check(not bad, f"{len(bad)}/{clients} clients failed")
    return f"{clients} procs x {size >> 10} KiB echoed"
