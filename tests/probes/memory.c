// tests/probes/memory.c
//
// mmap/munmap/mprotect/mremap/brk and madvise.
//
// linuxity tracks the guest's address space itself (runtime/shared/
// address_space.hpp) alongside the host's real mappings, so this family has
// the same two-bookkeepings risk as the fd table: a drift shows up as a wrong
// errno, or worse, a mapping the guest thinks it has and doesn't.
//
// ADDRESSES ARE NOT COMPARED. Where a mapping lands is allocation-dependent
// and differs between any two runs (ASLR alone guarantees it). So every
// observation here is a success/errno or an INVARIANT -- the mapping is
// readable, the contents survive a remap, a PROT_NONE page faults. That is
// the same discipline procid needed for pids, and it is what makes the
// comparison meaningful rather than noisy.
#include "probe.h"

#include <fcntl.h>
#include <string.h>

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif
#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define MAP_SHARED  0x01
#define MAP_PRIVATE 0x02
#define MAP_FIXED   0x10
#define MAP_ANON    0x20
#define MREMAP_MAYMOVE 1

#define PAGE 4096

int main(void) {
    // -- anonymous mapping -------------------------------------------------
    const long p = LX_SYS5(SYS_mmap, 0, PAGE * 4, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON, -1);
    // The ADDRESS is not comparable; that it succeeded is.
    lx_emit("mmap", p < 0 && p >= -4095 ? p : 1, "anonymous 4 pages");
    if (p < 0 && p >= -4095) return 1;

    char* m = (char*)p;

    // It must be writable and read back what we wrote.
    memset(m, 0xAB, PAGE * 4);
    lx_emit("mmap", m[0] == (char)0xAB && m[PAGE * 4 - 1] == (char)0xAB ? 1 : 0,
            "the mapping is readable and writable");

    // A fresh anonymous mapping must be ZERO-filled before we touch it.
    {
        const long z = LX_SYS5(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANON, -1);
        lx_emit("mmap", z < 0 && z >= -4095 ? z : 1, "a second anonymous page");
        if (z > 0) {
            const char* zp = (const char*)z;
            int nonzero = 0;
            for (int i = 0; i < PAGE; ++i) if (zp[i]) { nonzero = 1; break; }
            lx_emit("mmap", nonzero ? 0 : 1, "anonymous memory is zero-filled");
            lx_emit("munmap", LX_SYS2(SYS_munmap, z, PAGE), "unmap it");
        }
    }

    // -- mprotect ----------------------------------------------------------
    lx_emit("mprotect", LX_SYS3(SYS_mprotect, p, PAGE, PROT_READ),
            "drop a page to read-only");
    lx_emit("mprotect", LX_SYS3(SYS_mprotect, p, PAGE, PROT_READ | PROT_WRITE),
            "restore read-write");
    // The data must have survived the protection changes.
    lx_emit("mprotect", m[0] == (char)0xAB ? 1 : 0,
            "contents survived the mprotect round-trip");

    // An unmapped range is ENOMEM, not EINVAL.
    lx_emit("mprotect", LX_SYS3(SYS_mprotect, 0x1000, PAGE, PROT_READ),
            "mprotect on an unmapped range is ENOMEM");
    // A bogus protection bit is EINVAL.
    lx_emit("mprotect", LX_SYS3(SYS_mprotect, p, PAGE, 0x1000000),
            "a bogus prot bit is EINVAL");

    // -- the mmap argument boundaries -------------------------------------
    // Length 0 is EINVAL.
    lx_emit("mmap", LX_SYS5(SYS_mmap, 0, 0, PROT_READ,
                            MAP_PRIVATE | MAP_ANON, -1),
            "a zero-length mmap is EINVAL");
    // An unaligned MAP_FIXED address is EINVAL.
    lx_emit("mmap", LX_SYS5(SYS_mmap, p + 1, PAGE, PROT_READ,
                            MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1),
            "an unaligned MAP_FIXED is EINVAL");
    // Neither MAP_PRIVATE nor MAP_SHARED is EINVAL.
    lx_emit("mmap", LX_SYS5(SYS_mmap, 0, PAGE, PROT_READ, MAP_ANON, -1),
            "mmap without PRIVATE or SHARED is EINVAL");
    // A file mapping with a bad fd is EBADF.
    lx_emit("mmap", LX_SYS5(SYS_mmap, 0, PAGE, PROT_READ, MAP_PRIVATE, 9999),
            "a file mmap with a bad fd is EBADF");

    // -- munmap boundaries -------------------------------------------------
    lx_emit("munmap", LX_SYS2(SYS_munmap, p + 1, PAGE),
            "an unaligned munmap is EINVAL");
    lx_emit("munmap", LX_SYS2(SYS_munmap, p, 0),
            "a zero-length munmap is EINVAL");
    // Unmapping a range that was never mapped SUCCEEDS on Linux.
    lx_emit("munmap", LX_SYS2(SYS_munmap, 0x70000000000, PAGE),
            "munmap of an unmapped range succeeds");

    // -- a FILE mapping, where contents are deterministic ------------------
    {
        const char* path = "/tmp/lx-mem-probe.dat";
        const long fd = LX_SYS4(SYS_openat, AT_FDCWD, path,
                                O_RDWR | O_CREAT | O_TRUNC, 0644);
        lx_emit("openat", fd < 0 ? fd : 1, "create a file to map");
        if (fd >= 0) {
            LX_SYS3(SYS_write, fd, "MAPPEDDATA", 10);

            const long fm = LX_SYS5(SYS_mmap, 0, PAGE, PROT_READ, MAP_PRIVATE, fd);
            lx_emit("mmap", fm < 0 && fm >= -4095 ? fm : 1, "map the file");
            if (fm > 0) {
                // The CONTENT is comparable -- we wrote it.
                lx_emit_buf("mmap", 1, 0, (const void*)fm, 10,
                            "the file's bytes through the mapping");
                lx_emit("munmap", LX_SYS2(SYS_munmap, fm, PAGE), "unmap the file");
            }

            // Mapping past EOF is allowed; touching it would SIGBUS, so we
            // only check that the mapping itself succeeds.
            const long past = LX_SYS5(SYS_mmap, 0, PAGE * 2, PROT_READ,
                                      MAP_PRIVATE, fd);
            lx_emit("mmap", past < 0 && past >= -4095 ? past : 1,
                    "mapping past EOF is allowed");
            if (past > 0) LX_SYS2(SYS_munmap, past, PAGE * 2);

            lx_emit("close", LX_SYS1(SYS_close, fd), "close the mapped file");
            lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, path, 0),
                    "unlink it");
        }
    }

    // -- mremap ------------------------------------------------------------
    {
        const long grow = LX_SYS4(SYS_mremap, p, PAGE * 4, PAGE * 8,
                                  MREMAP_MAYMOVE);
        lx_emit("mremap", grow < 0 && grow >= -4095 ? grow : 1,
                "grow the mapping to 8 pages");
        if (grow > 0) {
            m = (char*)grow;
            // THE invariant: a remap preserves contents.
            lx_emit("mremap", m[0] == (char)0xAB ? 1 : 0,
                    "contents survived the mremap");
            // And the new tail is usable.
            m[PAGE * 8 - 1] = 0x5A;
            lx_emit("mremap", m[PAGE * 8 - 1] == 0x5A ? 1 : 0,
                    "the grown tail is writable");
        }

        // mremap of an unmapped range is EINVAL.
        lx_emit("mremap", LX_SYS4(SYS_mremap, 0x1000, PAGE, PAGE * 2,
                                  MREMAP_MAYMOVE),
                "mremap of an unmapped range is EINVAL");
    }

    // -- madvise -----------------------------------------------------------
    lx_emit("madvise", LX_SYS3(SYS_madvise, m, PAGE, 0 /*MADV_NORMAL*/),
            "MADV_NORMAL succeeds");
    lx_emit("madvise", LX_SYS3(SYS_madvise, m, PAGE, 4 /*MADV_DONTNEED*/),
            "MADV_DONTNEED succeeds");
    // MADV_DONTNEED on anonymous memory ZEROES it -- a real invariant.
    lx_emit("madvise", m[0] == 0 ? 1 : 0,
            "MADV_DONTNEED zeroed the anonymous page");
    lx_emit("madvise", LX_SYS3(SYS_madvise, m, PAGE, 0x7fff),
            "a bogus advice value is EINVAL");

    lx_emit("munmap", LX_SYS2(SYS_munmap, m, PAGE * 8), "unmap everything");

    // -- brk ---------------------------------------------------------------
    {
        // brk(0) queries the current break; it must be non-zero and stable.
        const long b1 = LX_SYS1(SYS_brk, 0);
        lx_emit("brk", b1 > 0 ? 1 : 0, "brk(0) returns a break");
        const long b2 = LX_SYS1(SYS_brk, 0);
        lx_emit("brk", b1 == b2 ? 1 : 0, "brk(0) is stable across calls");

        // Growing the break returns the NEW break on success.
        const long up = LX_SYS1(SYS_brk, b1 + PAGE);
        lx_emit("brk", up >= b1 + PAGE ? 1 : 0, "brk can grow");

        // Shrinking back must work too.
        const long down = LX_SYS1(SYS_brk, b1);
        lx_emit("brk", down == b1 ? 1 : 0, "brk can shrink back");

        // An absurd break request fails by returning the UNCHANGED break,
        // not by returning an errno -- a classic emulator mistake.
        const long absurd = LX_SYS1(SYS_brk, 1);
        lx_emit("brk", absurd == b1 ? 1 : 0,
                "a too-low brk returns the old break, not an error");
    }

    return 0;
}
