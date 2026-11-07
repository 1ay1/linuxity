"""Memory protection: what faults, what doesn't, and executable memory."""
import ctypes
import mmap
import os
import signal

from lxt import check, eq, libc, no_core, reap, skip, spawn, test

PAGE = mmap.PAGESIZE
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
PROT_NONE, PROT_R, PROT_W, PROT_X = 0, 1, 2, 4


def anon(n, prot=PROT_R | PROT_W):
    p = libc.mmap(None, n, prot, 0x22, -1, 0)
    check(p and p != ctypes.c_void_p(-1).value, "mmap")
    return p


def faults(fn):
    def child():
        no_core()
        fn()
        return 0
    return reap(spawn(child))


@test
def protection_faults():
    """Writes to read-only pages and any touch of PROT_NONE pages fault."""
    p = anon(PAGE * 3)
    ctypes.memset(p, 1, PAGE * 3)
    check(libc.mprotect(p, PAGE, PROT_R) == 0, "mprotect R")
    check(libc.mprotect(p + PAGE, PAGE, PROT_NONE) == 0, "mprotect NONE")
    eq(ctypes.string_at(p, 1), b"\x01", "read of an R page")
    eq(faults(lambda: ctypes.memset(p, 2, 1)), -signal.SIGSEGV, "write to an R page")
    eq(faults(lambda: ctypes.string_at(p + PAGE, 1)), -signal.SIGSEGV, "read of a NONE page")
    ctypes.memset(p + 2 * PAGE, 3, 1)       # the RW neighbour still works
    check(libc.mprotect(p + PAGE, PAGE, PROT_R | PROT_W) == 0, "back to RW")
    ctypes.memset(p + PAGE, 4, 1)
    eq(ctypes.string_at(p + PAGE, 1), b"\x04", "RW again")
    return "R, NONE fault; neighbours untouched; restore"


@test
def residency():
    """mincore sees touched pages resident; mlock/munlock work within RLIMIT_MEMLOCK."""
    n = 16
    p = anon(PAGE * n)
    for i in range(0, n, 2):
        ctypes.memset(p + i * PAGE, 1, 1)
    vec = (ctypes.c_ubyte * n)()
    check(libc.mincore(ctypes.c_void_p(p), PAGE * n, vec) == 0, "mincore")
    res = [v & 1 for v in vec]
    check(all(res[i] for i in range(0, n, 2)), f"touched pages not resident: {res}")
    check(libc.mlock(ctypes.c_void_p(p), PAGE) == 0, f"mlock: {os.strerror(ctypes.get_errno())}")
    with open("/proc/self/status") as f:
        locked = next(int(l.split()[1]) for l in f if l.startswith("VmLck"))
    check(locked >= PAGE // 1024, f"VmLck {locked} kB after mlock")
    check(libc.munlock(ctypes.c_void_p(p), PAGE) == 0, "munlock")
    return f"{sum(res)}/{n} resident, mlock shows in VmLck"


@test
def executable_memory():
    """Code written to RW memory runs once flipped to RX (what every JIT does)."""
    m = os.uname().machine
    if m == "x86_64":
        code = bytes([0xB8, 0x2A, 0, 0, 0, 0xC3])               # mov eax, 42; ret
    elif m == "aarch64":
        code = (0xD2800540).to_bytes(4, "little") + (0xD65F03C0).to_bytes(4, "little")  # mov x0,#42; ret
    else:
        skip("no test code for " + m)
    p = anon(PAGE)
    ctypes.memmove(p, code, len(code))
    check(libc.mprotect(p, PAGE, PROT_R | PROT_X) == 0, "mprotect RX")
    f = ctypes.CFUNCTYPE(ctypes.c_int)(p)
    eq(f(), 42, "JIT'd function")
    eq(faults(lambda: ctypes.CFUNCTYPE(ctypes.c_int)(anon(PAGE))()), -signal.SIGSEGV, "jump into non-exec memory")
    # dual mapping through a memfd: one RW view, one RX view of the same page
    fd = os.memfd_create("jit")
    os.ftruncate(fd, PAGE)
    rw = libc.mmap(None, PAGE, PROT_R | PROT_W, 0x01, fd, 0)
    rx = libc.mmap(None, PAGE, PROT_R | PROT_X, 0x01, fd, 0)
    ctypes.memmove(rw, code, len(code))
    eq(ctypes.CFUNCTYPE(ctypes.c_int)(rx)(), 42, "RX alias of a memfd")
    return f"{m}: W^X flip and memfd dual map"
