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

    // -- statfs on a VIRTUAL mount -----------------------------------------
    // /proc and /sys are synthesized, so this is linuxity answering rather
    // than forwarding -- a branch nothing else reached. f_type is the field
    // that matters: a program decides whether a path IS procfs by comparing
    // it against PROC_SUPER_MAGIC (systemd, util-linux and container
    // runtimes all do this before trusting /proc), so reporting tmpfs for
    // everything was a real answer to a real question, and wrong.
    {
        static unsigned char sf[128];
        const long p = LX_SYS2(SYS_statfs, "/proc", sf);
        lx_emit("statfs", p, "statfs /proc");
        unsigned long long ty = 0;
        memcpy(&ty, sf, 8);
        lx_emit("statfs", LX_CHECK(p == 0, ty == 0x9fa0ull),
                "/proc reports PROC_SUPER_MAGIC");

        memset(sf, 0, sizeof sf);
        const long y = LX_SYS2(SYS_statfs, "/sys", sf);
        lx_emit("statfs", y, "statfs /sys");
        memcpy(&ty, sf, 8);
        lx_emit("statfs", LX_CHECK(y == 0, ty == 0x62656572ull),
                "/sys reports SYSFS_MAGIC");

        // The block counts must still be self-consistent on a synthesized
        // filesystem -- df divides by them.
        unsigned long long bsize = 0, blocks = 0, bfree = 0;
        memset(sf, 0, sizeof sf);
        if (LX_SYS2(SYS_statfs, "/proc", sf) == 0) {
            memcpy(&bsize,  sf + 8,  8);
            memcpy(&blocks, sf + 16, 8);
            memcpy(&bfree,  sf + 24, 8);
        }
        lx_emit("statfs", (bsize >= 512 && (bsize & (bsize - 1)) == 0) ? 1 : 0,
                "a virtual mount still has a sane block size");
        lx_emit("statfs", (bfree <= blocks) ? 1 : 0,
                "...and free does not exceed total");
    }

    // statx on a virtual FILE, which is a different path again from statfs
    // on its mount: procfs synthesizes the bytes, so the size and mode come
    // from linuxity rather than any inode.
    {
        static unsigned char stx[256];
        const long r = LX_SYS5(SYS_statx, AT_FDCWD, "/proc/version", 0, 0x7ff, stx);
        lx_emit("statx", r, "statx a synthesized /proc file");
        unsigned short mode = 0;
        memcpy(&mode, stx + 28, 2);            // stx_mode
        lx_emit("statx", LX_CHECK(r == 0, (mode & 0170000) == 0100000),
                "...and it is a regular file");
    }

    // -- EFAULT: writing through a pointer the guest cannot write ---------
    // Every virtualized handler that copies a struct OUT has this path, and
    // none of them were exercised -- the probes always passed good buffers.
    // 0x1 is unmapped on any sane process, so the kernel answers EFAULT and
    // the guest must too. getresuid returned 0 here: it checked for NULL,
    // which is the easy half, and the write itself discarded whether it
    // worked.
    {
        void* bad = (void*)0x1;
        lx_emit("uname",     LX_SYS1(SYS_uname, bad),     "uname to a bad pointer is EFAULT");
        lx_emit("getcwd",    LX_SYS2(SYS_getcwd, bad, 64), "getcwd to a bad pointer is EFAULT");
        lx_emit("sysinfo",   LX_SYS1(SYS_sysinfo, bad),   "sysinfo to a bad pointer is EFAULT");
        lx_emit("getresuid", LX_SYS3(SYS_getresuid, bad, bad, bad),
                "getresuid to bad pointers is EFAULT");
        lx_emit("getresgid", LX_SYS3(SYS_getresgid, bad, bad, bad),
                "getresgid to bad pointers is EFAULT");
        lx_emit("statfs",    LX_SYS2(SYS_statfs, "/proc", bad),
                "statfs to a bad pointer is EFAULT");
    }

    // -- /proc/self/maps ---------------------------------------------------
    // Was a stub serving an empty file. The guest is a real host process
    // with real mappings, and an empty map is not a plausible process --
    // pstack, a debugger, and any allocator that walks its own mappings
    // read this. The CONTENT cannot be compared (addresses are per-run), so
    // the probe checks the shape: non-empty, and every line starts with a
    // hex range.
    {
        const long fd = LX_SYS3(SYS_openat, AT_FDCWD, "/proc/self/maps", O_RDONLY);
        lx_emit("openat", fd < 0 ? fd : 1, "open /proc/self/maps");
        static char mb[4096];
        const long n = (fd < 0) ? fd : LX_SYS3(SYS_read, fd, mb, (long)sizeof mb - 1);
        if (fd >= 0) LX_SYS1(SYS_close, fd);
        lx_emit("read", LX_CHECK(fd >= 0, n > 0), "maps is not empty");
        // A map line is "<hex>-<hex> rwxp ...": check the first character is
        // a hex digit and a '-' appears before the first space.
        int shaped = 0;
        if (n > 0) {
            mb[n] = 0;
            const char c = mb[0];
            const int hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            const char* dash = strchr(mb, '-');
            const char* sp = strchr(mb, ' ');
            shaped = hex && dash && sp && dash < sp;
        }
        lx_emit("read", LX_CHECK(n > 0, shaped), "...and the first line is an address range");
    }
    // -- procfs SYMLINKS ---------------------------------------------------
    // /proc/self/{exe,cwd,root} are synthesized links, and stat through them
    // takes a different path from lstat on them -- one resolves to the
    // target, the other describes the link. Four separate blocks of that
    // code had no coverage.
    //
    // A procfs symlink reports st_size 0, unlike a real symlink whose size
    // is its target's length. linuxity reported the target length, which
    // `find -type l -size` and archivers that preallocate from st_size can
    // see. The MODE is the other half: lstat must say S_IFLNK where stat
    // says whatever the target is.
    {
        static unsigned char st[160];
        // st_mode is at offset 24 and st_size at 48 on x86-64; on aarch64
        // they are 16 and 48. Only the mode offset differs.
#if defined(__x86_64__)
        const int mode_off = 24;
#else
        const int mode_off = 16;
#endif
        const int size_off = 48;

        // lstat: the LINK itself.
        memset(st, 0, sizeof st);
        const long l = LX_SYS4(SYS_newfstatat, AT_FDCWD, "/proc/self/exe", st,
                               0x100 /*AT_SYMLINK_NOFOLLOW*/);
        unsigned mode = 0; unsigned long long size = 0;
        memcpy(&mode, st + mode_off, 4);
        memcpy(&size, st + size_off, 8);
        lx_emit("newfstatat", l, "lstat /proc/self/exe");
        lx_emit("newfstatat", LX_CHECK(l == 0, (mode & 0170000) == 0120000),
                "...reports S_IFLNK");
        lx_emit("newfstatat", LX_CHECK(l == 0, size == 0),
                "...and a procfs symlink has st_size 0");

        // stat: FOLLOWS to the executable, which is a regular file.
        memset(st, 0, sizeof st);
        const long s = LX_SYS4(SYS_newfstatat, AT_FDCWD, "/proc/self/exe", st, 0);
        memcpy(&mode, st + mode_off, 4);
        lx_emit("newfstatat", s, "stat /proc/self/exe follows the link");
        lx_emit("newfstatat", LX_CHECK(s == 0, (mode & 0170000) == 0100000),
                "...and lands on a regular file");

        // /proc/self/cwd follows to a DIRECTORY.
        memset(st, 0, sizeof st);
        const long c = LX_SYS4(SYS_newfstatat, AT_FDCWD, "/proc/self/cwd", st, 0);
        memcpy(&mode, st + mode_off, 4);
        lx_emit("newfstatat", LX_CHECK(c == 0, (mode & 0170000) == 0040000),
                "stat /proc/self/cwd lands on a directory");

        // readlink must give an absolute path for each of them.
        static char lb[256];
        for (int k = 0; k < 2; ++k) {
            const char* p = k ? "/proc/self/root" : "/proc/self/exe";
            memset(lb, 0, sizeof lb);
            const long n = LX_SYS4(SYS_readlinkat, AT_FDCWD, p, lb, 255);
            lx_emit("readlinkat", n > 0 ? 1 : n, k ? "readlink /proc/self/root"
                                                   : "readlink /proc/self/exe");
            lx_emit("readlinkat", LX_CHECK(n > 0, lb[0] == '/'),
                    "...and the target is absolute");
        }
    }

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
        // fchown acts on the fd, so it works on a path that has been
        // UNLINKED out from under it -- that is the difference from chown,
        // and the reason daemons hold an fd across a rename.
        if (fd >= 0) {
            LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
            lx_emit("fchown", LX_SYS3(SYS_fchown, fd, -1, -1),
                    "fchown still works on an unlinked fd");
            // Put it back for the rest of the probe.
            const long re = LX_SYS4(SYS_openat, AT_FDCWD, F1,
                                    O_WRONLY | O_CREAT, 0644);
            if (re >= 0) { LX_SYS3(SYS_write, re, "x", 1); LX_SYS1(SYS_close, re); }
        }
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }
    lx_emit("fchmod", LX_SYS2(SYS_fchmod, 9999, 0600), "fchmod a closed fd is EBADF");
    lx_emit("fchown", LX_SYS3(SYS_fchown, 9999, -1, -1), "fchown a closed fd is EBADF");

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
