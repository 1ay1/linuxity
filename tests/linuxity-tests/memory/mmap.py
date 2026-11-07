"""mmap: anonymous, shared, file-backed, private COW, and the edges."""
import ctypes
import hashlib
import mmap
import os

from lxt import check, eq, expect_errno, libc, must, reap, spawn, test, no_core
import errno
import signal

PAGE = mmap.PAGESIZE


def addr_of(m):
    return ctypes.addressof(ctypes.c_char.from_buffer(m))


@test
def shared_across_fork():
    """MAP_SHARED anonymous memory: 8 children write, the parent sees it."""
    nslot, slot = 8, 1 << 20
    m = mmap.mmap(-1, nslot * slot)

    def pattern(i):
        return hashlib.sha256(bytes([i])).digest() * (slot // 32)

    def fill(i):
        m[i * slot:(i + 1) * slot] = pattern(i)

    for p in [spawn(fill, i) for i in range(nslot)]:
        must(p)
    for i in range(nslot):
        check(m[i * slot:(i + 1) * slot] == pattern(i), f"slot {i}")
    return "8 MiB written by 8 children"


@test
def private_copy_on_write():
    """MAP_PRIVATE writes never leak across fork, in either direction."""
    pm = mmap.mmap(-1, PAGE * 4, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    pm[:5] = b"mine!"

    def clobber():
        if pm[:5] != b"mine!":
            return 2
        pm[:5] = b"yours"
        return 0 if pm[:5] == b"yours" else 1

    must(spawn(clobber))
    eq(pm[:5], b"mine!", "parent's page after the child wrote")
    fd = os.open("file", os.O_RDWR | os.O_CREAT, 0o644)
    os.write(fd, b"A" * PAGE)
    fm = mmap.mmap(fd, PAGE, flags=mmap.MAP_PRIVATE)
    fm[0:1] = b"B"
    eq(os.pread(fd, 1, 0), b"A", "MAP_PRIVATE write reached the file")
    return "anon and file COW"


@test
def file_backed():
    """A shared file mapping and read/write see each other; msync; truncate -> SIGBUS."""
    fd = os.open("mapped", os.O_RDWR | os.O_CREAT, 0o644)
    os.ftruncate(fd, 1 << 20)
    fm = mmap.mmap(fd, 1 << 20)

    def scribble():
        fm[123456:123462] = b"hello!"

    must(spawn(scribble))
    eq(os.pread(fd, 6, 123456), b"hello!", "child's mmap write through read()")
    os.pwrite(fd, b"BACK", 0)
    eq(fm[:4], b"BACK", "write() through the mapping")
    fm.flush()
    os.ftruncate(fd, PAGE)

    def touch_past_eof():
        no_core()
        _ = fm[PAGE * 4]

    eq(reap(spawn(touch_past_eof)), -signal.SIGBUS, "access past a truncated file")
    expect_errno(errno.EACCES, "PROT_WRITE shared map of an O_RDONLY fd",
                 mmap.mmap, os.open("mapped", os.O_RDONLY), PAGE, mmap.MAP_SHARED,
                 mmap.PROT_READ | mmap.PROT_WRITE)
    return "shared both ways, msync, SIGBUS past EOF, EACCES"


@test
def big_and_lazy():
    """1 GiB MAP_NORESERVE touched sparsely; madvise(DONTNEED) zeroes; mremap grows."""
    size = 1 << 30
    big = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS | getattr(mmap, "MAP_NORESERVE", 0))
    offs = range(0, size, 16 << 20)
    for o in offs:
        big[o] = 0x5A
    check(all(big[o] == 0x5A and big[o + 1] == 0 for o in offs), "sparse touches")
    with open("/proc/self/status") as f:
        rss = next(int(l.split()[1]) for l in f if l.startswith("VmRSS"))
    check(rss < 512 << 10, f"RSS {rss} kB after touching 64 pages of 1 GiB")
    big.madvise(mmap.MADV_DONTNEED, 0, PAGE)
    eq(big[0], 0, "MADV_DONTNEED page reads back zero")
    m = mmap.mmap(-1, PAGE, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    m[:4] = b"keep"
    m.resize(PAGE * 64)       # mremap(MREMAP_MAYMOVE)
    eq(m[:4], b"keep", "contents after mremap")
    m[PAGE * 63] = 1
    return f"1 GiB lazy, RSS {rss} kB, DONTNEED, mremap"


@test
def fixed_and_hints():
    """MAP_FIXED replaces a range; MAP_FIXED_NOREPLACE refuses to."""
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    base = libc.mmap(None, PAGE * 4, 3, 0x22, -1, 0)                 # rw, private|anon
    check(base not in (None, ctypes.c_void_p(-1).value), "mmap")
    ctypes.memset(base, 0x11, PAGE * 4)
    again = libc.mmap(base + PAGE, PAGE, 3, 0x22 | 0x10, -1, 0)       # MAP_FIXED
    eq(again, base + PAGE, "MAP_FIXED address")
    eq(ctypes.string_at(base + PAGE, 4), bytes(4), "MAP_FIXED replaced the old page")
    eq(ctypes.string_at(base, 4), b"\x11" * 4, "neighbour untouched")
    r = libc.mmap(base, PAGE, 3, 0x22 | 0x100000, -1, 0)             # MAP_FIXED_NOREPLACE
    eq((ctypes.c_long(r).value, ctypes.get_errno()), (-1, errno.EEXIST), "MAP_FIXED_NOREPLACE on a used range")
    check(libc.munmap(ctypes.c_void_p(base), PAGE * 4) == 0, "munmap")
    return "FIXED, FIXED_NOREPLACE -> EEXIST"
