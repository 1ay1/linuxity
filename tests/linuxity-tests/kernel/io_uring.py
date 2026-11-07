"""io_uring: set up real rings and push work through them.

Sandboxes often refuse io_uring (Docker's default seccomp, Android's SELinux,
linuxity -- io_uring work never passes through a syscall a tracer can see,
so it would bypass path translation). Refusing is fine; what matters is
refusing with ENOSYS/EPERM so liburing users fall back to plain syscalls,
and never half-working.
"""
import ctypes
import errno
import mmap
import os

from lxt import check, eq, skip, syscall, test

u32, u64 = ctypes.c_uint32, ctypes.c_uint64


class SqOff(ctypes.Structure):
    _fields_ = [(n, u32) for n in ("head", "tail", "ring_mask", "ring_entries", "flags",
                                   "dropped", "array", "resv1")] + [("user_addr", u64)]


class CqOff(ctypes.Structure):
    _fields_ = [(n, u32) for n in ("head", "tail", "ring_mask", "ring_entries", "overflow",
                                   "cqes", "flags", "resv1")] + [("user_addr", u64)]


class Params(ctypes.Structure):
    _fields_ = [(n, u32) for n in ("sq_entries", "cq_entries", "flags", "sq_thread_cpu",
                                   "sq_thread_idle", "features", "wq_fd")] + [
        ("resv", u32 * 3), ("sq_off", SqOff), ("cq_off", CqOff)]


class Sqe(ctypes.Structure):
    _fields_ = [("opcode", ctypes.c_uint8), ("flags", ctypes.c_uint8), ("ioprio", ctypes.c_uint16),
                ("fd", ctypes.c_int32), ("off", u64), ("addr", u64), ("len", u32),
                ("rw_flags", u32), ("user_data", u64), ("pad", u64 * 3)]


class Cqe(ctypes.Structure):
    _fields_ = [("user_data", u64), ("res", ctypes.c_int32), ("flags", u32)]


OP_NOP, OP_READ, OP_WRITE = 0, 22, 23
OFF_SQ_RING, OFF_CQ_RING, OFF_SQES = 0, 0x8000000, 0x10000000


class Ring:
    def __init__(self, entries=8):
        self.p = Params()
        try:
            self.fd = syscall("io_uring_setup", entries, ctypes.addressof(self.p))
        except OSError as e:
            if e.errno in (errno.ENOSYS, errno.EPERM, errno.EACCES):
                skip(f"io_uring refused with {errno.errorcode[e.errno]} (programs fall back to syscalls)")
            raise
        p = self.p
        self.sq = mmap.mmap(self.fd, p.sq_off.array + p.sq_entries * 4,
                            mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=OFF_SQ_RING)
        self.cq = mmap.mmap(self.fd, p.cq_off.cqes + p.cq_entries * ctypes.sizeof(Cqe),
                            mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=OFF_CQ_RING)
        self.sqes = mmap.mmap(self.fd, p.sq_entries * ctypes.sizeof(Sqe),
                              mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE, offset=OFF_SQES)

    def _u32(self, m, off):
        return u32.from_buffer(m, off)

    def submit(self, sqe, wait=1):
        p = self.p
        tail = self._u32(self.sq, p.sq_off.tail)
        mask = self._u32(self.sq, p.sq_off.ring_mask).value
        idx = tail.value & mask
        ctypes.memmove(ctypes.addressof(Sqe.from_buffer(self.sqes, idx * ctypes.sizeof(Sqe))),
                       ctypes.addressof(sqe), ctypes.sizeof(Sqe))
        self._u32(self.sq, p.sq_off.array + idx * 4).value = idx
        tail.value += 1
        n = syscall("io_uring_enter", self.fd, 1, wait, 1, 0, 0)   # IORING_ENTER_GETEVENTS
        eq(n, 1, "io_uring_enter submitted")

    def reap(self):
        p = self.p
        head = self._u32(self.cq, p.cq_off.head)
        tail = self._u32(self.cq, p.cq_off.tail).value
        check(head.value != tail, "no completion")
        mask = self._u32(self.cq, p.cq_off.ring_mask).value
        c = Cqe.from_buffer_copy(self.cq, p.cq_off.cqes + (head.value & mask) * ctypes.sizeof(Cqe))
        head.value += 1
        return c.user_data, c.res

    def close(self):
        for m in (self.sq, self.cq, self.sqes):
            m.close()
        os.close(self.fd)


@test(host=True)
def nop_roundtrip():
    """A NOP goes in and its completion, with our user_data, comes out."""
    r = Ring()
    try:
        check(r.p.sq_entries >= 8 and r.p.cq_entries >= r.p.sq_entries, "ring sizes")
        for i in range(32):
            r.submit(Sqe(opcode=OP_NOP, user_data=0xC0FFEE00 + i))
            eq(r.reap(), (0xC0FFEE00 + i, 0), f"NOP {i} completion")
    finally:
        r.close()
    return f"32 NOPs, sq {r.p.sq_entries} cq {r.p.cq_entries}, features {r.p.features:#x}"


@test(host=True)
def read_and_write():
    """IORING_OP_WRITE then IORING_OP_READ move real bytes through a file."""
    r = Ring()
    try:
        fd = os.open("data", os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
        payload = os.urandom(65536)
        src = ctypes.create_string_buffer(payload, len(payload))
        r.submit(Sqe(opcode=OP_WRITE, fd=fd, off=0, addr=ctypes.addressof(src),
                     len=len(payload), user_data=1))
        ud, res = r.reap()
        if res == -errno.EINVAL:
            skip("kernel has no IORING_OP_WRITE (< 5.6)")
        eq((ud, res), (1, len(payload)), "write completion")
        eq(os.pread(fd, len(payload) + 1, 0), payload, "bytes on disk after OP_WRITE")
        dst = ctypes.create_string_buffer(len(payload))
        r.submit(Sqe(opcode=OP_READ, fd=fd, off=0, addr=ctypes.addressof(dst),
                     len=len(payload), user_data=2))
        eq(r.reap(), (2, len(payload)), "read completion")
        eq(dst.raw, payload, "bytes read through the ring")
        r.submit(Sqe(opcode=OP_READ, fd=999, addr=ctypes.addressof(dst), len=1, user_data=3))
        eq(r.reap(), (3, -errno.EBADF), "read from a bad fd")
    finally:
        r.close()
    return "64 KiB written and read back, EBADF in the cqe"
