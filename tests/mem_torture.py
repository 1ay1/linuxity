#!/usr/bin/env python3
"""mem_torture.py -- Linux memory management: mmap, protection, sharing,
remapping, memfd, JIT, limits, and what /proc says about it all.
See torture.py for how to run it."""
import sys
sys.dont_write_bytecode = True
import ctypes
import errno
import fcntl
import mmap
import os
import resource
import signal
import struct
import tempfile

from torture import *  # noqa: F401,F403
from torture import check, ok, eq, expect_errno, child, status, run_in_child, Skip, main, libc, ARCH, sh, have

PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC = 0, 1, 2, 4
MAP_SHARED, MAP_PRIVATE, MAP_FIXED, MAP_ANON = 1, 2, 0x10, 0x20
MAP_NORESERVE = 0x4000
MREMAP_MAYMOVE = 1
MADV_DONTNEED = 4
MAP_FAILED = ctypes.c_void_p(-1).value
PAGE = mmap.PAGESIZE

libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.mremap.restype = ctypes.c_void_p
libc.mremap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int]
libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.sbrk.restype = ctypes.c_void_p
libc.sbrk.argtypes = [ctypes.c_long]
libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p]


def anon(size, prot=PROT_READ | PROT_WRITE, flags=MAP_PRIVATE | MAP_ANON, addr=None):
    a = libc.mmap(addr, size, prot, flags, -1, 0)
    ok(a not in (None, MAP_FAILED), f"mmap({size}) failed: {errname(ctypes.get_errno())}")
    return a


def poke(a, data):
    ctypes.memmove(a, data, len(data))


def peek(a, n):
    return ctypes.string_at(a, n)


def dies_of(fn):
    """fn's fate in a child that can't dump core."""
    def body():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        fn()
        return 0
    return run_in_child(body)


def maps_line(addr):
    with open("/proc/self/maps") as f:
        for line in f:
            lo, hi = (int(x, 16) for x in line.split()[0].split("-"))
            if lo <= addr < hi:
                return line.split()
    return None


@check
def anonymous_memory_is_zeroed_and_unmapped_is_gone():
    a = anon(16 * PAGE)
    eq(peek(a, 16 * PAGE), b"\0" * (16 * PAGE), "new anonymous memory is zero")
    eq(a % PAGE, 0, "page aligned")
    poke(a + 5 * PAGE, b"hello")
    eq(peek(a + 5 * PAGE, 5), b"hello", "it stores")
    eq(libc.munmap(a + 4 * PAGE, 2 * PAGE), 0, "munmap a hole in the middle")
    eq(dies_of(lambda: peek(a + 5 * PAGE, 1)), -signal.SIGSEGV, "touching the hole is SIGSEGV")
    eq(peek(a, 1) + peek(a + 6 * PAGE, 1), b"\0\0", "both sides of the hole survive")
    eq(libc.munmap(a + 1, PAGE), -1, "munmap of an unaligned address")
    eq(ctypes.get_errno(), errno.EINVAL, "is EINVAL")


_MMAP_RACE_C = r"""
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
static void* run(void* a) {
    (void)a;
    for (int r = 0; r < 3000; r++) {
        volatile int* p = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        p[0] = r;
        munmap((void*)p, 4096);
    }
    return 0;
}
int main(void) {
    pthread_t t[4];
    for (int i = 0; i < 4; i++) pthread_create(&t[i], 0, run, 0);
    for (int i = 0; i < 4; i++) pthread_join(t[i], 0);
    puts("ok");
    return 0;
}
"""


@check(timeout=120)
def threads_mapping_and_unmapping_at_once():
    # mmap_lock: picking an address and setting its page tables is one step.
    # Without it a thread's munmap could fence the range another thread had
    # just been handed, and that thread's first store faulted -- every JIT
    # and threaded allocator (llvmpipe, so every OpenGL app) hit it. Native
    # threads: Python's take turns and never overlap in the syscalls.
    cc = next((c for c in ("cc", "gcc", "clang") if have(c)), None)
    if not cc:
        raise Skip("no C compiler")
    d = tempfile.mkdtemp()
    src, exe = os.path.join(d, "race.c"), os.path.join(d, "race")
    with open(src, "w") as f:
        f.write(_MMAP_RACE_C)
    eq(sh(f"{cc} -O2 -pthread -o {exe} {src}")[0], 0, "compiles")
    for _ in range(3):
        rc, out, _err = sh(exe)
        eq((rc, out.strip()), (0, "ok"), "four threads mapping, storing and unmapping")


@check
def a_second_shared_view_sees_the_first():
    # Fill a memfd through one MAP_SHARED mapping, then map it again:
    # the new view must see the bytes -- Firefox's shared string maps do
    # exactly this (odd sizes, not host-page aligned).
    fd = os.memfd_create("lx-view")
    size = 5 * PAGE + 123
    os.ftruncate(fd, size)
    a = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    a[0:8] = b"MAGIC123"
    a[size - 4:size] = b"TAIL"
    b = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ)
    eq((b[0:8], b[size - 4:size]), (b"MAGIC123", b"TAIL"), "the second view sees the first's stores")
    a.close(); b.close(); os.close(fd)
    # Firefox's shape: a /dev/shm file opened twice, written through the
    # read-write fd's mapping, mapped again through the read-only fd.
    path = "/dev/shm/lx-view-%d" % os.getpid()
    rw = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    ro = os.open(path, os.O_RDONLY)
    os.unlink(path)
    os.ftruncate(rw, size)
    w = mmap.mmap(rw, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    w[0:8] = b"SHMMAGIC"
    r = mmap.mmap(ro, size, mmap.MAP_SHARED, mmap.PROT_READ)
    eq(r[0:8], b"SHMMAGIC", "a read-only fd's mapping sees the read-write mapping's stores")
    w.close(); r.close(); os.close(rw); os.close(ro)
    # ...and Firefox's real one: fill a sealed memfd, fork, the child maps it
    fd = os.memfd_create("lx-fork-view", os.MFD_ALLOW_SEALING)
    os.ftruncate(fd, size)
    w = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    w[0:8] = b"FORKSEEN"
    fcntl.fcntl(fd, 1033, 0x10 | 0x4 | 0x2)   # F_ADD_SEALS: FUTURE_WRITE|GROW|SHRINK
    def child_reads():
        m = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ)
        return 0 if m[0:8] == b"FORKSEEN" else 7
    eq(run_in_child(child_reads), 0, "a fork child's mapping sees the parent's stores")
    w.close(); os.close(fd)
    # Firefox's actual handle: write a memfd, reopen it read-only through
    # /proc/self/fd/N, map that
    fd = os.memfd_create("lx-reopen", os.MFD_ALLOW_SEALING)
    os.ftruncate(fd, size)
    w = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    w[0:8] = b"REOPENED"
    w.close()
    ro = os.open("/proc/self/fd/%d" % fd, os.O_RDONLY)
    r = mmap.mmap(ro, size, mmap.MAP_SHARED, mmap.PROT_READ)
    eq(r[0:8], b"REOPENED", "a /proc/self/fd reopen of a memfd is the same file")
    w = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    w[0:8] = b"LATERONE"
    eq(r[0:8], b"LATERONE", "and sees later stores")
    r.close(); w.close(); os.close(ro); os.close(fd)


@check
def protections_are_enforced():
    a = anon(4 * PAGE)
    poke(a, b"data")
    eq(libc.mprotect(a, PAGE, PROT_READ), 0, "mprotect read-only")
    eq(peek(a, 4), b"data", "still readable")
    eq(dies_of(lambda: poke(a, b"X")), -signal.SIGSEGV, "a write to read-only memory")
    eq(libc.mprotect(a + PAGE, PAGE, PROT_NONE), 0, "mprotect PROT_NONE")
    eq(dies_of(lambda: peek(a + PAGE, 1)), -signal.SIGSEGV, "a read of PROT_NONE")
    eq(libc.mprotect(a, PAGE, PROT_READ | PROT_WRITE), 0, "back to read-write")
    poke(a, b"ok")
    line = maps_line(a + PAGE)
    ok(line and line[1].startswith("---p"), f"/proc/self/maps shows ---p: {line}")
    line = maps_line(a)
    ok(line and line[1].startswith("rw-p"), f"/proc/self/maps shows rw-p: {line}")


@check
def jit_write_then_execute():
    code = {"aarch64": struct.pack("<II", 0x52800540, 0xD65F03C0),   # mov w0,#42; ret
            "x86_64": bytes([0xB8, 42, 0, 0, 0, 0xC3])}.get(ARCH)    # mov eax,42; ret
    if code is None:
        raise Skip(f"no test code for {ARCH}")
    a = anon(PAGE)
    poke(a, code)
    fn = ctypes.CFUNCTYPE(ctypes.c_int)(a)
    eq(dies_of(fn), -signal.SIGSEGV, "executing non-executable memory")
    eq(libc.mprotect(a, PAGE, PROT_READ | PROT_EXEC), 0, "mprotect RX")
    eq(fn(), 42, "the JIT'ed function runs")
    # Rewriting live code needs an explicit I-cache flush on aarch64 (real
    # Linux runs the stale 42 without one), so write the variant to a FRESH
    # page, the way JITs emit new code.
    b = anon(PAGE)
    poke(b, code.replace(bytes([42]), bytes([7])) if ARCH == "x86_64"
         else struct.pack("<II", 0x528000E0, 0xD65F03C0))           # mov w0,#7; ret
    eq(libc.mprotect(b, PAGE, PROT_READ | PROT_EXEC), 0, "RX")
    eq(ctypes.CFUNCTYPE(ctypes.c_int)(b)(), 7, "a second JIT'ed function runs")
    eq(fn(), 42, "and the first is unchanged")


@check
def fork_shares_shared_and_copies_private():
    shared = anon(PAGE, flags=MAP_SHARED | MAP_ANON)
    private = anon(PAGE)
    poke(shared, b"S0"); poke(private, b"P0")

    def kid():
        poke(shared, b"S1"); poke(private, b"P1")
        return 0
    eq(run_in_child(kid), 0, "child")
    eq(peek(shared, 2), b"S1", "MAP_SHARED: the child's store is ours")
    eq(peek(private, 2), b"P0", "MAP_PRIVATE: copy-on-write")
    m = mmap.mmap(-1, 1 << 20)                  # Python's own shared anonymous map
    m[:4] = b"init"

    def kid2():
        m[:4] = b"kid!"
        return 0
    eq(run_in_child(kid2), 0, "child")
    eq(m[:4], b"kid!", "mmap.mmap(-1) is shared across fork")


@check
def mremap_grows_moves_and_shrinks():
    a = anon(2 * PAGE)
    poke(a, b"first"); poke(a + PAGE, b"second")
    b = libc.mremap(a, 2 * PAGE, 64 * PAGE, MREMAP_MAYMOVE)
    ok(b not in (None, MAP_FAILED), f"mremap grow: {errname(ctypes.get_errno())}")
    eq((peek(b, 5), peek(b + PAGE, 6)), (b"first", b"second"), "contents moved with it")
    eq(peek(b + 40 * PAGE, 4), b"\0" * 4, "the new part is zero")
    c = libc.mremap(b, 64 * PAGE, PAGE, 0)
    eq(c, b, "shrinking stays in place")
    eq(dies_of(lambda: peek(b + 10 * PAGE, 1)), -signal.SIGSEGV, "the shrunk-off part is gone")


@check
def madvise_dontneed_zeroes_private_pages():
    a = anon(4 * PAGE)
    poke(a, b"x" * (4 * PAGE))
    eq(libc.madvise(a, 2 * PAGE, MADV_DONTNEED), 0, "MADV_DONTNEED")
    eq(peek(a, 8), b"\0" * 8, "an anonymous private page reads zero after DONTNEED")
    eq(peek(a + 2 * PAGE, 1), b"x", "pages outside the range keep their data")
    vec = ctypes.create_string_buffer(4)
    eq(libc.mincore(a, 4 * PAGE, vec), 0, "mincore")


@check
def brk_heap_grows():
    start = libc.sbrk(0)
    got = libc.sbrk(1 << 20)
    eq(got, start, "sbrk returns the old break")
    end = libc.sbrk(0)
    eq(end - start, 1 << 20, "the break moved by 1 MiB")
    poke(start + (1 << 20) - 4, b"heap")
    eq(peek(start + (1 << 20) - 4, 4), b"heap", "the new heap is usable")
    big = bytearray(64 << 20)                   # malloc: brk or mmap, either way it works
    big[-1] = 1
    eq(big[-1], 1, "a 64 MiB bytearray")


@check
def large_sparse_reservation_costs_only_what_is_touched():
    def rss():
        with open("/proc/self/status") as f:
            return next(int(l.split()[1]) for l in f if l.startswith("VmRSS:"))
    before = rss()
    # A reservation far beyond what's touched: half of this machine's RAM
    # (8 GiB on a big host), and only 32 pages written.
    with open("/proc/meminfo") as f:
        total = next(int(l.split()[1]) for l in f if l.startswith("MemTotal:")) * 1024
    size = min(8 << 30, (total // 2) & ~((256 << 20) - 1))
    step = size // 32
    a = anon(size, flags=MAP_PRIVATE | MAP_ANON | MAP_NORESERVE)
    for i in range(0, size, step):
        poke(a + i, b"t")
    after = rss()
    # with transparent huge pages on "always" each touch can fault in 2 MiB
    try:
        thp = "[always]" in open("/sys/kernel/mm/transparent_hugepage/enabled").read()
    except OSError:
        thp = False
    per_touch = 2048 if thp else 4
    ok(after - before < 32 * per_touch + 32 * 1024,
       f"RSS grew {after - before} KiB for 32 touched pages of {size >> 20} MiB")
    eq(peek(a + step, 1), b"t", "a far page holds its byte")
    with open("/proc/self/status") as f:
        vm = next(int(l.split()[1]) for l in f if l.startswith("VmSize:"))
    ok(vm > size >> 10, f"VmSize counts the reservation ({vm} KiB)")


@check
def reservations_far_beyond_ram():
    # A 64-bit address space is not RAM: SpiderMonkey and WebAssembly
    # reserve eleven 16 GiB PROT_NONE regions at Firefox's startup and
    # commit pieces later. When guest memory was an identity map of a 2-4
    # GiB RAM block every one was ENOMEM, and Firefox came up as a blank
    # 122x38 window.
    G = 1 << 30
    regions = [anon(16 * G, prot=PROT_NONE, flags=MAP_PRIVATE | MAP_ANON | MAP_NORESERVE)
               for _ in range(11)]
    big = anon(64 * G, prot=PROT_NONE)
    for i, r in enumerate(regions + [big]):
        mid = r + (8 * G if r != big else 40 * G)
        eq(libc.mprotect(mid, 1 << 20, PROT_READ | PROT_WRITE), 0, f"commit 1 MiB inside region {i}")
        poke(mid + 4096, b"r%02d" % i)
    eq(dies_of(lambda: peek(regions[3], 1)), -signal.SIGSEGV, "the uncommitted rest stays PROT_NONE")

    def kid():
        ok_all = all(peek(r + (8 * G if r != big else 40 * G) + 4096, 3) == b"r%02d" % i
                     for i, r in enumerate(regions + [big]))
        poke(regions[0] + 8 * G + 4096, b"kid")
        return 0 if ok_all else 3
    eq(run_in_child(kid), 0, "a fork child sees every committed page")
    eq(peek(regions[0] + 8 * G + 4096, 3), b"r00", "and its stores are its own")
    for r in regions:
        eq(libc.munmap(r, 16 * G), 0, "munmap a 16 GiB region")
    eq(libc.munmap(big, 64 * G), 0, "munmap 64 GiB")


@check
def file_mapping_follows_the_file():
    with open("f", "wb") as f:
        f.write(b"A" * (3 * PAGE))
    fd = os.open("f", os.O_RDWR)
    a = libc.mmap(None, 3 * PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, PAGE)
    ok(a != MAP_FAILED, "a file mapping at an offset")
    poke(a, b"B")
    os.pwrite(fd, b"C", 2 * PAGE)
    eq(peek(a + PAGE, 1), b"C", "a write() shows in the mapping")
    eq(os.pread(fd, 1, PAGE), b"B", "a store shows in the file")
    eq(libc.mmap(None, PAGE, PROT_READ, MAP_SHARED, fd, 1), MAP_FAILED, "a mapping at an unaligned offset")
    eq(ctypes.get_errno(), errno.EINVAL, "is EINVAL")
    ro = os.open("f", os.O_RDONLY)
    eq(libc.mmap(None, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED, ro, 0), MAP_FAILED,
       "a writable shared map of a read-only fd fails")
    eq(ctypes.get_errno(), errno.EACCES, "with EACCES")
    line = maps_line(a)
    ok(line and line[-1].endswith("/f") and int(line[2], 16) == PAGE, f"maps names the file and offset: {line}")


@check
def memfd_and_seals():
    fd = os.memfd_create("torture", os.MFD_ALLOW_SEALING)
    os.ftruncate(fd, PAGE)
    m = mmap.mmap(fd, PAGE)
    m[:5] = b"memfd"
    eq(os.pread(fd, 5, 0), b"memfd", "memfd through mmap and pread")
    ok(os.readlink(f"/proc/self/fd/{fd}").startswith("/memfd:torture"), "its /proc/self/fd name")
    m.close()
    F_ADD_SEALS, F_GET_SEALS = 1033, 1034
    F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_WRITE = 2, 4, 8
    import fcntl
    fcntl.fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW)
    eq(fcntl.fcntl(fd, F_GET_SEALS) & 14, 14, "seals stick")
    expect_errno(errno.EPERM, "write after F_SEAL_WRITE", os.pwrite, fd, b"x", 0)
    expect_errno(errno.EPERM, "grow after F_SEAL_GROW", os.ftruncate, fd, 2 * PAGE)
    eq(os.pread(fd, 5, 0), b"memfd", "still readable")

    def kid():
        return 0 if os.pread(fd, 5, 0) == b"memfd" else 1
    eq(run_in_child(kid), 0, "a child reads the inherited memfd")


@check
def mlock_and_limits():
    a = anon(4 * PAGE)
    eq(libc.mlock(a, 4 * PAGE), 0, f"mlock 16 KiB ({errname(ctypes.get_errno())})")
    eq(libc.munlock(a, 4 * PAGE), 0, "munlock")

    def capped():
        resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
        r = libc.mmap(None, 1 << 30, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
        return 0 if r == MAP_FAILED and ctypes.get_errno() == errno.ENOMEM else 1
    eq(run_in_child(capped), 0, "RLIMIT_AS turns a 1 GiB mmap into ENOMEM")


@check
def proc_self_mem_reads_our_memory():
    buf = ctypes.create_string_buffer(b"find me in /proc/self/mem", 32)
    with open("/proc/self/mem", "rb", buffering=0) as f:
        f.seek(ctypes.addressof(buf))
        eq(f.read(25), b"find me in /proc/self/mem", "/proc/self/mem at a heap address")


@check
def process_vm_readv_reads_a_child():
    r, w = os.pipe()

    def kid():
        secret = ctypes.create_string_buffer(b"child secret", 16)
        os.write(w, struct.pack("Q", ctypes.addressof(secret)))
        __import__("time").sleep(5)              # the parent reads, then kills us
        return 0
    pid = child(kid)
    remote = struct.unpack("Q", os.read(r, 8))[0]

    class IoVec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
    out = ctypes.create_string_buffer(16)
    local = IoVec(ctypes.addressof(out), 12)
    rem = IoVec(remote, 12)
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    n = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(rem), 1, 0)
    os.kill(pid, signal.SIGKILL); status(pid)
    eq((n, out.raw[:12]), (12, b"child secret"), f"process_vm_readv ({errname(ctypes.get_errno())})")


@check
def page_size_agrees_everywhere():
    sc = os.sysconf("SC_PAGE_SIZE")
    eq(mmap.PAGESIZE, sc, "mmap.PAGESIZE vs sysconf")
    with open("/proc/self/auxv", "rb") as f:
        aux = f.read()
    vals = dict(struct.iter_unpack("QQ", aux[: len(aux) // 16 * 16]))
    eq(vals.get(6), sc, "AT_PAGESZ in /proc/self/auxv")
    with open("/proc/self/smaps") as f:
        ok("KernelPageSize:" in f.read(), "/proc/self/smaps has KernelPageSize")


@check
def meminfo_is_coherent():
    with open("/proc/meminfo") as f:
        mi = {l.split(":")[0]: int(l.split()[1]) for l in f if l.split()[1].isdigit()}
    for k in ("MemTotal", "MemFree", "MemAvailable", "Cached", "SwapTotal"):
        ok(k in mi, f"/proc/meminfo has {k}")
    ok(0 < mi["MemFree"] <= mi["MemTotal"], "MemFree <= MemTotal")
    ok(mi["MemAvailable"] <= mi["MemTotal"], "MemAvailable <= MemTotal")
    pages = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // 1024
    ok(abs(pages - mi["MemTotal"]) < mi["MemTotal"] // 20, f"sysconf vs MemTotal: {pages} vs {mi['MemTotal']}")


if __name__ == "__main__":
    sys.exit(main("memory"))
