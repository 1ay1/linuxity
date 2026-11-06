// tests/probes/fuzz.c
//
// DIFFERENTIAL FUZZING: let the kernel write the test cases.
//
// THE LIMIT THIS BREAKS. Every other probe is a fixed script -- 674 steps,
// each one an argument somebody thought of. That bounds what the suite can
// find to what was anticipated, and the bugs found this way were all of the
// form "nobody tried THAT value": chown on a dangling symlink, getresuid
// through an unmapped pointer, umount2 of something never mounted. Each took
// a human noticing the case existed.
//
// linuxity has a property that makes the usual fuzzing problem disappear. A
// fuzzer normally needs an ORACLE -- some way to know the answer is wrong --
// and for a kernel ABI that oracle is the hard part. But linuxity's whole
// claim is "answers like the kernel", and the kernel is RIGHT THERE. So:
// generate a random syscall with random arguments, run it natively and under
// linuxity, and compare. No expected output has to be written down. The
// kernel is the expectation.
//
// DETERMINISM IS THE CONSTRAINT. The two runs must issue the SAME calls in
// the same order or the comparison is meaningless, so the generator is a
// seeded PRNG with no entropy from the environment -- same seed, same
// sequence, on both sides and on both arches. A failing seed is a complete,
// replayable bug report: LX_FUZZ_SEED=12345 reproduces it exactly.
//
// WHAT IT MAY NOT DO. It runs in the probe's own process against the live
// filesystem, so it must not destroy anything: paths stay under a scratch
// directory, destructive calls are restricted to files it created, and
// anything that could not be undone (execve, exit, mount, setuid) is simply
// not in the generator's vocabulary. The point is argument-space coverage of
// calls we already intercept, not a hostile fuzzer.
#define _GNU_SOURCE
#include "probe.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// xorshift64*: tiny, deterministic, and identical on every arch. rand(3)
// would not be -- its sequence is libc's business and musl and glibc differ,
// which would desynchronise the native and guest runs.
static unsigned long long g_state;
static unsigned long long rnd(void) {
    unsigned long long x = g_state;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    g_state = x;
    return x * 2685821657736338717ull;
}
static unsigned pick(unsigned n) { return (unsigned)(rnd() % n); }

#define SCRATCH "lx-fuzz-probe"
static char DIR[256];

// The argument pools. A fuzzer that only ever passes VALID arguments finds
// nothing: the interesting answers are at the boundaries, so each pool mixes
// legal values with the ones that break naive handlers -- empty strings,
// paths that escape, counts that overflow, fds that were never opened.
static const char* kPathTails[] = {
    "f1", "sub", "sub/f2", "nope", "", ".", "..", "sub/../f1",
    "f1/bad", "sub/", "./f1", "//f1",
};
static const long kFlags[] = {
    O_RDONLY, O_WRONLY, O_RDWR, O_RDONLY | O_DIRECTORY, O_WRONLY | O_CREAT,
    O_RDONLY | O_NOFOLLOW, O_WRONLY | O_CREAT | O_EXCL, O_PATH,
};
static const long kModes[] = {0644, 0755, 0777, 0700};
static const long kSizes[] = {0, 1, 7, 4095, 4096, -1};
static const long kWhence[] = {SEEK_SET, SEEK_CUR, SEEK_END, 99, -1};

// Build an absolute path inside the scratch dir from one of the tails.
static char* path_of(char* buf, size_t cap, const char* tail) {
    size_t i = 0;
    while (DIR[i] && i + 1 < cap) { buf[i] = DIR[i]; ++i; }
    if (i + 1 < cap) buf[i++] = '/';
    size_t j = 0;
    while (tail[j] && i + 1 < cap) buf[i++] = tail[j++];
    buf[i] = 0;
    return buf;
}
static const char* rnd_tail(void) {
    return kPathTails[pick(sizeof kPathTails / sizeof *kPathTails)];
}

// A pool of fds the generator can reach for: real ones it opened, plus the
// values that break naive handlers.
#define NFD 8
static long g_fds[NFD];
static long rnd_fd(void) {
    const unsigned k = pick(NFD + 3);
    if (k < NFD) return g_fds[k];
    if (k == NFD) return -1;
    if (k == NFD + 1) return 9999;        // never opened
    return 0;                              // stdin: real, but not ours
}

// Remove the scratch tree completely. The fuzzer CREATES things -- mkdir,
// symlink, link, rename -- and a leftover changes what the next run sees, so
// two native runs of the same seed would not agree with each other, let
// alone with the guest. Determinism is the whole basis of the comparison,
// so this runs before the seeding and again at the end.
//
// Depth-first and bounded: the generator can only make names from a fixed
// pool, so the tree is shallow by construction and a full walk is overkill.
static void wipe(void) {
    char p[512];
    static const char* const leaves[] = {
        "sub/f2", "sub/../f1", "./f1", "f1", "nope", "sub/",
    };
    // The generator sets modes from a pool that includes 0 and 07777, so a
    // directory can end up without write or search permission and its
    // contents become unremovable. chmod everything back first -- otherwise
    // the wipe half-fails, the next run sees leftovers, and the two native
    // runs disagree with each other before linuxity is even involved.
    for (unsigned k = 0; k < sizeof kPathTails / sizeof *kPathTails; ++k)
        LX_SYS4(SYS_fchmodat, AT_FDCWD,
                path_of(p, sizeof p, kPathTails[k]), 0755, 0);
    LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR, 0755, 0);

    // Files and symlinks first, then the directories they lived in.
    for (unsigned k = 0; k < sizeof leaves / sizeof *leaves; ++k)
        LX_SYS3(SYS_unlinkat, AT_FDCWD, path_of(p, sizeof p, leaves[k]), 0);
    for (unsigned k = 0; k < sizeof kPathTails / sizeof *kPathTails; ++k)
        LX_SYS3(SYS_unlinkat, AT_FDCWD, path_of(p, sizeof p, kPathTails[k]), 0);
    // Two passes: "sub/f2" must go before "sub", and a name the fuzzer
    // turned into a directory may hold another.
    for (unsigned pass = 0; pass < 2; ++pass)
        for (unsigned k = 0; k < sizeof kPathTails / sizeof *kPathTails; ++k)
            LX_SYS3(SYS_unlinkat, AT_FDCWD,
                    path_of(p, sizeof p, kPathTails[k]), 0x200);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, path_of(p, sizeof p, "sub"), 0x200);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, 0x200);
}

// A divergence is only useful if it says WHAT diverged. The note carries
// the operation index and the actual arguments, so a failing step reads
//
//     linkat = -EEXIST | #002 linkat(f1, .)
//
// and can be replayed by hand instead of bisected. The index also makes the
// two traces align visibly when they drift.
static char g_note[160];
static const char* note1(int i, const char* op, const char* a) {
    snprintf(g_note, sizeof g_note, "#%03d %s(%s)", i, op, a);
    return g_note;
}
static const char* note2(int i, const char* op, const char* a, const char* b) {
    snprintf(g_note, sizeof g_note, "#%03d %s(%s, %s)", i, op, a, b);
    return g_note;
}
static const char* note1n(int i, const char* op, const char* a, long n) {
    snprintf(g_note, sizeof g_note, "#%03d %s(%s, %ld)", i, op, a, n);
    return g_note;
}
static const char* note2n(int i, const char* op, long fd, long x, long y) {
    snprintf(g_note, sizeof g_note, "#%03d %s(fd=%ld, %ld, %ld)", i, op, fd, x, y);
    return g_note;
}

int main(void) {
    lx_path(DIR, sizeof DIR, SCRATCH);

    // The seed. Fixed by default so a run is reproducible and its golden is
    // stable; LX_FUZZ_SEED replays a specific failure.
    const char* s = getenv("LX_FUZZ_SEED");
    g_state = s && *s ? (unsigned long long)strtoull(s, 0, 0) : 0x9E3779B97F4A7C15ull;

    // A known starting shape, so the first operations have something real to
    // act on. Setup, not observations -- and a full wipe FIRST, because a
    // leftover from a previous run would change the answers.
    char p[512], q[512];
    wipe();
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR, 0755);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, path_of(p, sizeof p, "sub"), 0755);
    {
        static const char* const seed_files[] = {"f1", "sub/f2"};
        for (unsigned k = 0; k < 2; ++k) {
            const long fd = LX_SYS4(SYS_openat, AT_FDCWD,
                                    path_of(p, sizeof p, seed_files[k]),
                                    O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) { LX_SYS3(SYS_write, fd, "seed-data", 9); LX_SYS1(SYS_close, fd); }
        }
    }
    for (int i = 0; i < NFD; ++i) g_fds[i] = -1;

    // The campaign. 400 operations is enough to cover the argument pools
    // several times over while keeping the trace readable and the run under
    // a second.
    //
    // LX_FUZZ_OPS shortens it, which is what makes triage possible: a
    // divergence is mostly CASCADE (once one operation has a different
    // effect, every later one sees different state), so tools/fuzz-triage.sh
    // binary-searches the count for the smallest prefix that still diverges.
    // The last operation of that prefix is the actual cause.
    static char buf[4096];
    int kOps = 400;
    {
        const char* o = getenv("LX_FUZZ_OPS");
        if (o && *o) {
            const long v = strtol(o, 0, 0);
            if (v > 0 && v < 100000) kOps = (int)v;
        }
    }
    for (int i = 0; i < kOps; ++i) {
        switch (pick(14)) {
        case 0: {   // openat -- and keep the fd, so later ops have real ones
            const char* t = rnd_tail();
            const long fl = kFlags[pick(sizeof kFlags / sizeof *kFlags)];
            const long fd = LX_SYS4(SYS_openat, AT_FDCWD, path_of(p, sizeof p, t),
                                    fl, kModes[pick(sizeof kModes / sizeof *kModes)]);
            lx_emit("openat", fd < 0 ? fd : 1, note1n(i, "openat", t, fl));
            if (fd >= 0) {
                const unsigned slot = pick(NFD);
                if (g_fds[slot] >= 0) LX_SYS1(SYS_close, g_fds[slot]);
                g_fds[slot] = fd;
            }
            break;
        }
        case 1:
        {   const char* t = rnd_tail();
            const long fl = pick(2) ? 0x100 /*NOFOLLOW*/ : 0;
            lx_emit("newfstatat",
                    LX_SYS4(SYS_newfstatat, AT_FDCWD, path_of(p, sizeof p, t), buf, fl),
                    note1n(i, "newfstatat", t, fl));
        }   break;
        case 2:
        {   const long fd = rnd_fd();
            const long off = kSizes[pick(sizeof kSizes / sizeof *kSizes)];
            const long wh = kWhence[pick(sizeof kWhence / sizeof *kWhence)];
            lx_emit("lseek", LX_SYS3(SYS_lseek, fd, off, wh),
                    note2n(i, "lseek", fd, off, wh));
        }   break;
        case 3:
        {   const long fd = rnd_fd();
            const long n = kSizes[pick(sizeof kSizes / sizeof *kSizes)];
            lx_emit("read", LX_SYS3(SYS_read, fd, buf, n),
                    note2n(i, "read", fd, n, 0));
        }   break;
        case 4:
        {   const char* t = rnd_tail(); const long m = pick(8);
            lx_emit("faccessat",
                    LX_SYS3(SYS_faccessat, AT_FDCWD, path_of(p, sizeof p, t), m),
                    note1n(i, "faccessat", t, m));
        }   break;
        case 5:
        {   const char* t = rnd_tail();
            const long n = kSizes[pick(sizeof kSizes / sizeof *kSizes)];
            lx_emit("readlinkat",
                    LX_SYS4(SYS_readlinkat, AT_FDCWD, path_of(p, sizeof p, t), buf, n),
                    note1n(i, "readlinkat", t, n));
        }   break;
        case 6:
        {   const char* t = rnd_tail();
            const long m = kModes[pick(sizeof kModes / sizeof *kModes)];
            lx_emit("fchmodat",
                    LX_SYS4(SYS_fchmodat, AT_FDCWD, path_of(p, sizeof p, t), m, 0),
                    note1n(i, "fchmodat", t, m));
        }   break;
        case 7:
        {   const char* t = rnd_tail();
            const long m = kModes[pick(sizeof kModes / sizeof *kModes)];
            lx_emit("mkdirat",
                    LX_SYS3(SYS_mkdirat, AT_FDCWD, path_of(p, sizeof p, t), m),
                    note1n(i, "mkdirat", t, m));
        }   break;
        case 8:
            // Only ever inside the scratch dir, and AT_REMOVEDIR half the
            // time so both the file and directory paths are exercised.
        {   const char* t = rnd_tail();
            const long fl = pick(2) ? 0x200 /*AT_REMOVEDIR*/ : 0;
            lx_emit("unlinkat",
                    LX_SYS3(SYS_unlinkat, AT_FDCWD, path_of(p, sizeof p, t), fl),
                    note1n(i, "unlinkat", t, fl));
        }   break;
        case 9:
        {   const char* a = rnd_tail(); const char* b = rnd_tail();
            lx_emit("renameat",
                    LX_SYS4(SYS_renameat, AT_FDCWD, path_of(p, sizeof p, a),
                            AT_FDCWD, path_of(q, sizeof q, b)),
                    note2(i, "renameat", a, b));
        }   break;
        case 10:
        {   const char* a = rnd_tail(); const char* b = rnd_tail();
            lx_emit("symlinkat",
                    LX_SYS3(SYS_symlinkat, a, AT_FDCWD, path_of(p, sizeof p, b)),
                    note2(i, "symlinkat", a, b));
        }   break;
        case 11:
        {   const char* a = rnd_tail(); const char* b = rnd_tail();
            lx_emit("linkat",
                    LX_SYS5(SYS_linkat, AT_FDCWD, path_of(p, sizeof p, a),
                            AT_FDCWD, path_of(q, sizeof q, b), 0),
                    note2(i, "linkat", a, b));
        }   break;
        case 12:
        {   const long fd = rnd_fd();
            const long n = kSizes[pick(sizeof kSizes / sizeof *kSizes)];
            lx_emit("getdents64", LX_SYS3(SYS_getdents64, fd, buf, n),
                    note2n(i, "getdents64", fd, n, 0));
        }   break;
        default:
        {   const long fd = rnd_fd(); const long c = pick(6); const long a = pick(4);
            lx_emit("fcntl", LX_SYS3(SYS_fcntl, fd, c, a),
                    note2n(i, "fcntl", fd, c, a));
        }   break;
        }
    }

    // Leave nothing behind: the next run must see the same empty slate.
    for (int i = 0; i < NFD; ++i) if (g_fds[i] >= 0) LX_SYS1(SYS_close, g_fds[i]);
    wipe();
    return 0;
}
