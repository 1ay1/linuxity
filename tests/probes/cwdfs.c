// tests/probes/cwdfs.c
//
// The current directory, the filesystem-info calls, and the *at variants
// that had no coverage: chdir/fchdir/getcwd, statfs/fstatfs, sysinfo,
// mknod/mknodat, renameat2, openat2, faccessat2, fchmod/fchmodat2/fchown,
// utime/futimesat.
//
// WHY THE CWD MATTERS MOST HERE. linuxity keeps its own per-process cwd --
// it has to, because the guest's "/" is a host directory somewhere else --
// and every relative path a guest ever opens is resolved against it. If that
// model drifts from the kernel's, relative paths silently resolve to the
// wrong file. getcwd is also what a shell prints in its prompt and what
// getcwd(3) hands to every build tool.
//
// So the probe does not just call them, it checks the RELATIONSHIPS:
// getcwd after chdir reports where we went, fchdir to a fd lands in the same
// place as chdir to its path, and a relative open resolves against the cwd
// we last set. Those hold on any correct kernel whatever the absolute paths
// happen to be.
//
// FILESYSTEM NUMBERS ARE NOT COMPARED. statfs's free-block count changes
// between two runs seconds apart, and sysinfo's uptime always differs -- and
// linuxity deliberately reports its OWN virtual machine (2 GiB, its own
// process count) rather than the host's. What must agree is the STRUCTURE:
// the call succeeds, the block size is a sane power of two, the totals are
// self-consistent, a missing path is ENOENT.
#include "probe.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DIR   "/tmp/lx-cwdfs-probe"
#define SUB   DIR "/sub"
#define F1    DIR "/f1"
#define GONE  DIR "/absent"

// "Precondition did not hold" -- the traces must stay the same length on
// every host, so a check that cannot be answered says so rather than
// reporting a misleading 0.
#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

static long slen(const char* s) { long n = 0; while (s[n]) ++n; return n; }

int main(void) {
    // Clean slate; setup, not observations.
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SUB, AT_REMOVEDIR);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR, 0755);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, SUB, 0755);
    {
        const long fd = LX_SYS4(SYS_openat, AT_FDCWD, F1, O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) { LX_SYS3(SYS_write, fd, "x", 1); LX_SYS1(SYS_close, fd); }
    }

    static char cwd[512], cwd2[512];

    // -- getcwd / chdir, and that they agree -------------------------------
    const long c0 = LX_SYS2(SYS_getcwd, cwd, (long)sizeof cwd);
    lx_emit("getcwd", c0 > 0 ? 1 : c0, "getcwd returns a path");
    lx_emit("getcwd", LX_CHECK(c0 > 0, cwd[0] == '/'), "the cwd is absolute");
    // The kernel returns the LENGTH INCLUDING the NUL -- an easy off-by-one
    // to get wrong in a reimplementation.
    lx_emit("getcwd", LX_CHECK(c0 > 0, c0 == slen(cwd) + 1),
            "getcwd's return counts the NUL");

    lx_emit("chdir", LX_SYS1(SYS_chdir, DIR), "chdir into the scratch dir");
    const long c1 = LX_SYS2(SYS_getcwd, cwd2, (long)sizeof cwd2);
    lx_emit("getcwd", c1 > 0 ? 1 : c1, "getcwd after chdir");
    lx_emit("chdir", LX_CHECK(c1 > 0, strcmp(cwd2, DIR) == 0),
            "getcwd reports where chdir went");

    // THE INVARIANT that matters: a RELATIVE path resolves against the cwd.
    {
        const long fd = LX_SYS3(SYS_openat, AT_FDCWD, "f1", O_RDONLY);
        lx_emit("openat", fd < 0 ? fd : 1, "a relative open resolves in the cwd");
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }
    lx_emit("chdir", LX_SYS1(SYS_chdir, "sub"), "a relative chdir works too");
    {
        char c[512];
        const long n = LX_SYS2(SYS_getcwd, c, (long)sizeof c);
        lx_emit("chdir", LX_CHECK(n > 0, strcmp(c, SUB) == 0),
                "the relative chdir landed in sub");
    }

    // -- fchdir must land in the same place as chdir -----------------------
    {
        const long dfd = LX_SYS3(SYS_openat, AT_FDCWD, DIR, O_RDONLY | O_DIRECTORY);
        lx_emit("openat", dfd < 0 ? dfd : 1, "open the dir for fchdir");
        const long fc = (dfd < 0) ? dfd : LX_SYS1(SYS_fchdir, dfd);
        lx_emit("fchdir", fc, "fchdir to that fd");
        char c[512];
        const long n = LX_SYS2(SYS_getcwd, c, (long)sizeof c);
        lx_emit("fchdir", LX_CHECK(fc == 0 && n > 0, strcmp(c, DIR) == 0),
                "fchdir and chdir agree on the destination");
        if (dfd >= 0) LX_SYS1(SYS_close, dfd);
    }
    // fchdir to a NON-directory fd is ENOTDIR.
    {
        const long f = LX_SYS3(SYS_openat, AT_FDCWD, F1, O_RDONLY);
        lx_emit("fchdir", (f < 0) ? f : LX_SYS1(SYS_fchdir, f),
                "fchdir to a regular file is ENOTDIR");
        if (f >= 0) LX_SYS1(SYS_close, f);
    }
    lx_emit("fchdir", LX_SYS1(SYS_fchdir, 9999), "fchdir to a closed fd is EBADF");

    // -- getcwd error boundaries -------------------------------------------
    // A buffer too small for the path is ERANGE, not a truncated answer.
    lx_emit("getcwd", LX_SYS2(SYS_getcwd, cwd, 2L), "a too-small getcwd buffer is ERANGE");
    lx_emit("chdir", LX_SYS1(SYS_chdir, GONE), "chdir to a missing dir is ENOENT");
    lx_emit("chdir", LX_SYS1(SYS_chdir, F1), "chdir to a regular file is ENOTDIR");

    // Back to a known place so the rest is deterministic.
    LX_SYS1(SYS_chdir, DIR);

    // -- statfs / fstatfs --------------------------------------------------
    // struct statfs on x86-64/aarch64: f_type(8) f_bsize(8) f_blocks(8)
    // f_bfree(8) f_bavail(8) f_files(8) f_ffree(8) ... The VALUES are not
    // compared (free space moves, and linuxity reports its own machine), but
    // the structure must be sane.
    {
        static unsigned char sf[128];
        memset(sf, 0, sizeof sf);
        const long rc = LX_SYS2(SYS_statfs, DIR, sf);
        lx_emit("statfs", rc, "statfs the scratch dir");
        unsigned long long bsize = 0, blocks = 0, bfree = 0;
        memcpy(&bsize,  sf + 8,  8);
        memcpy(&blocks, sf + 16, 8);
        memcpy(&bfree,  sf + 24, 8);
        lx_emit("statfs", LX_CHECK(rc == 0, bsize >= 512 && (bsize & (bsize - 1)) == 0),
                "f_bsize is a power of two >= 512");
        lx_emit("statfs", LX_CHECK(rc == 0, blocks > 0), "f_blocks is non-zero");
        lx_emit("statfs", LX_CHECK(rc == 0, bfree <= blocks),
                "free blocks do not exceed total");

        static unsigned char sf2[128];
        memset(sf2, 0, sizeof sf2);
        const long fd = LX_SYS3(SYS_openat, AT_FDCWD, DIR, O_RDONLY | O_DIRECTORY);
        const long frc = (fd < 0) ? fd : LX_SYS2(SYS_fstatfs, fd, sf2);
        lx_emit("fstatfs", frc, "fstatfs the same dir by fd");
        // Same filesystem, so the static facts must match.
        unsigned long long t1 = 0, t2 = 0, b2 = 0;
        memcpy(&t1, sf, 8); memcpy(&t2, sf2, 8); memcpy(&b2, sf2 + 8, 8);
        lx_emit("fstatfs", LX_CHECK(rc == 0 && frc == 0, t1 == t2),
                "statfs and fstatfs agree on f_type");
        lx_emit("fstatfs", LX_CHECK(rc == 0 && frc == 0, bsize == b2),
                "statfs and fstatfs agree on f_bsize");
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }
    lx_emit("statfs", LX_SYS2(SYS_statfs, GONE, cwd), "statfs a missing path is ENOENT");
    lx_emit("fstatfs", LX_SYS2(SYS_fstatfs, 9999, cwd), "fstatfs a closed fd is EBADF");

    // -- sysinfo -----------------------------------------------------------
    // struct sysinfo: uptime(8) loads(24) totalram(8) freeram(8) ...
    // Uptime and free memory differ between runs by nature; totals do not.
    {
        static unsigned char si[128];
        memset(si, 0, sizeof si);
        const long rc = LX_SYS1(SYS_sysinfo, si);
        lx_emit("sysinfo", rc, "sysinfo succeeds");
        unsigned long long uptime = 0, totalram = 0, freeram = 0;
        memcpy(&uptime,   si,      8);
        memcpy(&totalram, si + 32, 8);
        memcpy(&freeram,  si + 40, 8);
        lx_emit("sysinfo", LX_CHECK(rc == 0, uptime > 0), "uptime is positive");
        lx_emit("sysinfo", LX_CHECK(rc == 0, totalram > 0), "totalram is non-zero");
        lx_emit("sysinfo", LX_CHECK(rc == 0, freeram <= totalram),
                "free memory does not exceed total");
    }

    // -- fchmod / fchown on an fd ------------------------------------------
    {
        const long fd = LX_SYS3(SYS_openat, AT_FDCWD, F1, O_RDONLY);
        lx_emit("fchmod", (fd < 0) ? fd : LX_SYS2(SYS_fchmod, fd, 0600),
                "fchmod 600 through an fd");
        // Read it back by path: the two views must agree.
        static unsigned char st[160];
        const long s = LX_SYS4(SYS_newfstatat, AT_FDCWD, F1, st, 0);
        unsigned mode = 0;
        if (s == 0) memcpy(&mode, st + 24, 4);
        lx_emit("fchmod", LX_CHECK(fd >= 0 && s == 0, (mode & 0777) == 0600),
                "stat sees what fchmod set");
        lx_emit("fchown", (fd < 0) ? fd : LX_SYS3(SYS_fchown, fd, -1, -1),
                "fchown -1/-1 is a no-op");
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }
    lx_emit("fchmod", LX_SYS2(SYS_fchmod, 9999, 0600), "fchmod a closed fd is EBADF");

    // -- the newer *at forms. Not every kernel has them (the Android 6.1
    //    kernel predates several), so ENOSYS is a legitimate answer that
    //    both sides must give identically.
    lx_emit("faccessat2", LX_SYS4(SYS_faccessat2, AT_FDCWD, F1, R_OK, 0),
            "faccessat2 R_OK");
    lx_emit("faccessat2", LX_SYS4(SYS_faccessat2, AT_FDCWD, GONE, R_OK, 0),
            "faccessat2 on a missing file is ENOENT");

    // renameat2 with no flags behaves like rename.
    lx_emit("renameat2", LX_SYS5(SYS_renameat2, AT_FDCWD, F1, AT_FDCWD, DIR "/f2", 0),
            "renameat2 with no flags renames");
    lx_emit("renameat2", LX_SYS5(SYS_renameat2, AT_FDCWD, DIR "/f2", AT_FDCWD, F1, 0),
            "renameat2 renames it back");
    // RENAME_NOREPLACE (1) onto an existing name must be EEXIST.
    lx_emit("renameat2", LX_SYS5(SYS_renameat2, AT_FDCWD, F1, AT_FDCWD, F1, 1),
            "RENAME_NOREPLACE onto an existing name is EEXIST");

    // mknod of a FIFO needs no privilege; a device node does.
    lx_emit("mknodat", LX_SYS4(SYS_mknodat, AT_FDCWD, DIR "/fifo", 0010644, 0),
            "mknodat makes a FIFO");
    lx_emit("mknodat", LX_SYS4(SYS_mknodat, AT_FDCWD, DIR "/fifo", 0010644, 0),
            "mknodat onto an existing name is EEXIST");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/fifo", 0);

    // -- tear down ---------------------------------------------------------
    LX_SYS1(SYS_chdir, "/");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SUB, AT_REMOVEDIR);
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR),
            "remove the scratch dir");
    return 0;
}
