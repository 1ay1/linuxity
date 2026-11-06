// tests/probes/jitwx.c
//
// The W^X JIT sequence, and the arm64 arch-private syscalls.
//
// WHY THIS IS NOT COVERED BY THE OTHER PROBES. `memory` exercises mmap/
// mprotect/mremap as memory management -- sizes, flags, error boundaries --
// but never EXECUTES from a mapping it made. That is a different contract,
// and it is the one every JIT depends on:
//
//     mmap W  ->  write code  ->  mprotect X  ->  flush i-cache  ->  call
//
// Java, V8, .NET, LuaJIT and every `node` process on the device do exactly
// that, and on arm64 it is more fragile than on x86-64: the architecture does
// not guarantee i-cache/d-cache coherence, so the flush is mandatory rather
// than advisory. linuxity forwards mmap/mprotect to the host, so what is
// really being tested is that its bookkeeping does not corrupt a mapping it
// handed back -- and that re-protecting a live mapping, which is how a JIT
// patches code in place, survives the round trip.
//
// arm64 also has arch-private syscalls in the 0xf0000 range that the generic
// decoder does not know (__ARM_NR_cacheflush). Whatever the host answers --
// modern kernels return ENOSYS, older ones 0 -- the guest must answer the
// SAME, because a JIT that treats an unexpected error as fatal will not
// start.
#include "probe.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

#define ARM_NR_cacheflush (0xf0000 + 2)

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

typedef int (*fn)(void);

int main(void) {
    // -- the arch-private syscall ------------------------------------------
    // Only meaningful on arm64; on x86-64 this number is not a syscall at
    // all and both sides must agree it is ENOSYS.
    lx_emit("mmap", LX_SYS3(ARM_NR_cacheflush, 0, 0, 0),
            "arm64 __ARM_NR_cacheflush answers the same as the host");

    // -- the JIT sequence --------------------------------------------------
    const long pg = 4096;
    const long m = LX_SYS6(SYS_mmap, 0, pg, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    lx_emit("mmap", m > 0 ? 1 : m, "mmap an anonymous RW page for code");
    if (m <= 0) {
        // Keep the step count identical on a host where this failed.
        for (int i = 0; i < 6; ++i)
            lx_emit("mprotect", LX_NA, "JIT step skipped: no mapping");
        return 0;
    }

    unsigned char* p = (unsigned char*)(unsigned long)m;

#if defined(__aarch64__)
    // mov w0, #42 ; ret
    const unsigned int c1[] = {0x52800540u, 0xd65f03c0u};
    // mov w0, #103 ; ret
    const unsigned int c2[] = {0x52800CE0u, 0xd65f03c0u};
#elif defined(__x86_64__)
    // mov eax, 42 ; ret
    const unsigned char c1[] = {0xb8, 42, 0, 0, 0, 0xc3};
    // mov eax, 103 ; ret
    const unsigned char c2[] = {0xb8, 103, 0, 0, 0, 0xc3};
#else
    const unsigned char c1[] = {0}, c2[] = {0};
#endif

    memcpy(p, c1, sizeof c1);

    const long x1 = LX_SYS3(SYS_mprotect, m, pg, PROT_READ | PROT_EXEC);
    lx_emit("mprotect", x1, "mprotect the code page W -> X");

    // The i-cache flush a compiler intrinsic emits. On arm64 this is real
    // work (IC IVAU / DSB ISH); on x86-64 it is a no-op.
    __builtin___clear_cache((char*)p, (char*)p + sizeof c1);

#if defined(__aarch64__) || defined(__x86_64__)
    const int got1 = (x1 == 0) ? ((fn)p)() : -1;
    lx_emit("mprotect", LX_CHECK(x1 == 0, got1 == 42),
            "code written to a fresh mapping executes");
#else
    lx_emit("mprotect", LX_NA, "code written to a fresh mapping executes");
#endif

    // -- in-place patching, which is what a real JIT does ------------------
    const long w2 = LX_SYS3(SYS_mprotect, m, pg, PROT_READ | PROT_WRITE);
    lx_emit("mprotect", w2, "mprotect back X -> W to patch");
    if (w2 == 0) memcpy(p, c2, sizeof c2);
    const long x2 = LX_SYS3(SYS_mprotect, m, pg, PROT_READ | PROT_EXEC);
    lx_emit("mprotect", x2, "mprotect W -> X again");
    __builtin___clear_cache((char*)p, (char*)p + sizeof c2);

#if defined(__aarch64__) || defined(__x86_64__)
    const int got2 = (x2 == 0 && w2 == 0) ? ((fn)p)() : -1;
    lx_emit("mprotect", LX_CHECK(x2 == 0 && w2 == 0, got2 == 103),
            "the repatched page executes the NEW code");
#else
    lx_emit("mprotect", LX_NA, "the repatched page executes the NEW code");
#endif

    lx_emit("munmap", LX_SYS2(SYS_munmap, m, pg), "unmap the code page");
    return 0;
}
