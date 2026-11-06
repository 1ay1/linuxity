// tests/probes/fsmutate.c
//
// Filesystem MUTATION: mkdir/rmdir/rename/link/symlink/chmod/truncate, and
// the errno boundaries each one has.
//
// This is the highest-risk family after procid. linuxity routes every write
// through its overlay: a mutation has to land in the UPPER layer, copying the
// file up from the read-only lower first, so the pristine rootfs is never
// touched. That machinery (classify with for_write=true, WriteIntent,
// whiteouts) is linuxity's own code, not the host kernel's, and it is where a
// wrong errno or a write to the wrong layer would hide.
//
// Everything happens under one scratch directory this probe creates and
// removes, so the trace does not depend on the host's filesystem.
#include "probe.h"

#include <fcntl.h>
#include <sys/stat.h>

#define DIR  "/tmp/lx-fsmut-probe"
#define SUB  DIR "/sub"
#define F1   DIR "/f1"
#define F2   DIR "/f2"
#define LNK  DIR "/lnk"
#define SYM  DIR "/sym"

// Create a file with some content; emit nothing (setup, not an observation).
static long mkfile(const char* p, const char* content) {
    const long fd = LX_SYS4(SYS_openat, AT_FDCWD, p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return fd;
    if (content && *content) {
        long n = 0;
        while (content[n]) ++n;
        LX_SYS3(SYS_write, fd, content, n);
    }
    return LX_SYS1(SYS_close, fd);
}

int main(void) {
    // Clean slate, in case a previous run died mid-way. Not observations.
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SYM, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, LNK, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F2, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SUB, AT_REMOVEDIR);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR);

    // -- mkdir -------------------------------------------------------------
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR, 0755), "mkdir the scratch dir");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR, 0755),
            "mkdir an existing dir is EEXIST");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/a/b", 0755),
            "mkdir with a missing parent is ENOENT");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, SUB, 0755), "mkdir a subdir");

    // -- create files ------------------------------------------------------
    lx_emit("openat", mkfile(F1, "hello") < 0 ? -1 : 1, "create f1");
    lx_emit("openat",
            LX_SYS4(SYS_openat, AT_FDCWD, F1, O_WRONLY | O_CREAT | O_EXCL, 0644),
            "O_EXCL on an existing file is EEXIST");

    // -- rmdir -------------------------------------------------------------
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR),
            "rmdir a non-empty dir is ENOTEMPTY");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, AT_REMOVEDIR),
            "rmdir on a FILE is ENOTDIR");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/nope", AT_REMOVEDIR),
            "rmdir a missing dir is ENOENT");

    // unlink with AT_REMOVEDIR unset on a DIRECTORY is EISDIR.
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, SUB, 0),
            "unlink on a dir is EISDIR");

    // -- hard links --------------------------------------------------------
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, F1, AT_FDCWD, LNK, 0),
            "hardlink f1 -> lnk");
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, F1, AT_FDCWD, LNK, 0),
            "hardlink onto an existing name is EEXIST");
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, DIR "/nope", AT_FDCWD,
                              DIR "/x", 0),
            "hardlink a missing source is ENOENT");
    // A hardlink to a DIRECTORY is EPERM.
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, SUB, AT_FDCWD, DIR "/d2", 0),
            "hardlink a directory is EPERM");

    // The link count must now be 2 for both names.
    {
        char st[512];
        lx_emit("newfstatat", LX_SYS4(SYS_newfstatat, AT_FDCWD, F1, st, 0) < 0 ? -1 : 1,
                "stat f1 after linking");
        lx_emit("newfstatat", LX_SYS4(SYS_newfstatat, AT_FDCWD, LNK, st, 0) < 0 ? -1 : 1,
                "stat lnk");
    }

    // -- symlinks ----------------------------------------------------------
    lx_emit("symlinkat", LX_SYS3(SYS_symlinkat, "f1", AT_FDCWD, SYM),
            "symlink sym -> f1");
    lx_emit("symlinkat", LX_SYS3(SYS_symlinkat, "f1", AT_FDCWD, SYM),
            "symlink onto an existing name is EEXIST");

    {
        char buf[64];
        const long r = LX_SYS4(SYS_readlinkat, AT_FDCWD, SYM, buf, sizeof buf);
        lx_emit("readlinkat", r, "readlink the symlink returns its length");
        lx_emit_buf("readlinkat", r > 0 ? 1 : r, 2, buf, r > 0 ? (unsigned long)r : 0,
                    "the symlink target");
        // readlink on a NON-link is EINVAL.
        lx_emit("readlinkat", LX_SYS4(SYS_readlinkat, AT_FDCWD, F1, buf, sizeof buf),
                "readlink a regular file is EINVAL");
        // A zero-size buffer is EINVAL.
        lx_emit("readlinkat", LX_SYS4(SYS_readlinkat, AT_FDCWD, SYM, buf, 0),
                "readlink with a 0 buffer is EINVAL");
    }

    // A dangling symlink: stat follows (ENOENT), lstat does not (succeeds).
    {
        char st[512];
        lx_emit("symlinkat", LX_SYS3(SYS_symlinkat, "nowhere", AT_FDCWD, DIR "/dang"),
                "create a dangling symlink");
        lx_emit("newfstatat",
                LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/dang", st, 0),
                "stat a dangling symlink is ENOENT");
        lx_emit("newfstatat",
                LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/dang", st,
                        AT_SYMLINK_NOFOLLOW) < 0 ? -1 : 1,
                "lstat a dangling symlink succeeds");
        lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dang", 0),
                "unlink the dangling symlink");
    }

    // -- rename ------------------------------------------------------------
    lx_emit("renameat", LX_SYS4(SYS_renameat, AT_FDCWD, LNK, AT_FDCWD, F2),
            "rename lnk -> f2");
    lx_emit("renameat", LX_SYS4(SYS_renameat, AT_FDCWD, DIR "/nope", AT_FDCWD,
                                DIR "/x"),
            "rename a missing source is ENOENT");
    // Renaming a FILE onto a DIRECTORY is EISDIR.
    lx_emit("renameat", LX_SYS4(SYS_renameat, AT_FDCWD, F1, AT_FDCWD, SUB),
            "rename a file onto a dir is EISDIR");
    // Renaming a DIRECTORY onto a non-empty... use a file target: ENOTDIR.
    lx_emit("renameat", LX_SYS4(SYS_renameat, AT_FDCWD, SUB, AT_FDCWD, F1),
            "rename a dir onto a file is ENOTDIR");
    // Rename onto ITSELF is a no-op success.
    lx_emit("renameat", LX_SYS4(SYS_renameat, AT_FDCWD, F1, AT_FDCWD, F1),
            "rename onto itself succeeds");

    // -- chmod / chown -----------------------------------------------------
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, F1, 0600, 0),
            "chmod 600");
    {
        char st[512];
        lx_emit("newfstatat", LX_SYS4(SYS_newfstatat, AT_FDCWD, F1, st, 0) < 0 ? -1 : 1,
                "stat after chmod");
    }
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nope", 0600, 0),
            "chmod a missing file is ENOENT");

    // chown to our own ids is a no-op success; -1 means "don't change".
    lx_emit("fchownat", LX_SYS5(SYS_fchownat, AT_FDCWD, F1, -1, -1, 0),
            "chown with -1/-1 is a no-op success");
    lx_emit("fchownat", LX_SYS5(SYS_fchownat, AT_FDCWD, DIR "/nope", -1, -1, 0),
            "fchownat on a missing file is ENOENT");
    // AT_SYMLINK_NOFOLLOW is how a caller asks for lchown semantics through
    // the *at form -- cp -a and tar -x both set it. Without the flag the
    // call must FOLLOW, so a dangling link is ENOENT; with it, the link
    // itself is the target and the same path works. One call with flags=0
    // never exercises the distinction.
    LX_SYS3(SYS_symlinkat, DIR "/nope", AT_FDCWD, DIR "/dang");
    lx_emit("fchownat", LX_SYS5(SYS_fchownat, AT_FDCWD, DIR "/dang", -1, -1, 0),
            "fchownat follows by default, so a dangling link is ENOENT");
    lx_emit("fchownat",
            LX_SYS5(SYS_fchownat, AT_FDCWD, DIR "/dang", -1, -1, AT_SYMLINK_NOFOLLOW),
            "AT_SYMLINK_NOFOLLOW acts on the link itself");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dang", 0);
    // An fd-relative path, which is the whole reason the *at form exists.
    {
        const long d = LX_SYS3(SYS_openat, AT_FDCWD, DIR, O_RDONLY | O_DIRECTORY);
        lx_emit("fchownat", (d < 0) ? d : LX_SYS5(SYS_fchownat, d, "f1", -1, -1, 0),
                "fchownat resolves relative to a dirfd");
        if (d >= 0) LX_SYS1(SYS_close, d);
    }

    // -- truncate ----------------------------------------------------------
    lx_emit("truncate", LX_SYS2(SYS_truncate, F1, 2), "truncate f1 to 2");
    lx_emit("truncate", LX_SYS2(SYS_truncate, F1, -1),
            "a negative truncate is EINVAL");
    lx_emit("truncate", LX_SYS2(SYS_truncate, DIR "/nope", 0),
            "truncate a missing file is ENOENT");
    lx_emit("truncate", LX_SYS2(SYS_truncate, SUB, 0),
            "truncate a directory is EISDIR");

    // -- utimensat ---------------------------------------------------------
    lx_emit("utimensat", LX_SYS4(SYS_utimensat, AT_FDCWD, F1, 0, 0),
            "utimensat with NULL times sets now");
    // An EXPLICIT time must be readable back -- "sets now" is unverifiable
    // by construction, so on its own it proves only that the call returned.
    {
        // struct timespec times[2] = {{sec,nsec} atime, {sec,nsec} mtime}
        static long ts[4] = {1600000000L, 0, 1600000000L, 0};
        lx_emit("utimensat", LX_SYS4(SYS_utimensat, AT_FDCWD, F1, ts, 0),
                "utimensat sets an explicit time");
        static unsigned char st[160];
        const long s = LX_SYS4(SYS_newfstatat, AT_FDCWD, F1, st, 0);
        unsigned long long mtime = 0;
        if (s == 0) memcpy(&mtime, st + 88, 8);   // st_mtime on x86-64
        lx_emit("utimensat", (s == 0 && mtime == 1600000000ULL) ? 1 : 0,
                "stat reads back the time we set");
    }
    // UTIME_OMIT (0x3ffffffe) leaves one stamp alone -- how `touch -a` works.
    {
        static long ts[4] = {0, 0x3ffffffe, 1700000000L, 0};
        lx_emit("utimensat", LX_SYS4(SYS_utimensat, AT_FDCWD, F1, ts, 0),
                "UTIME_OMIT leaves atime alone");
    }
    lx_emit("utimensat", LX_SYS4(SYS_utimensat, AT_FDCWD, DIR "/nope", 0, 0),
            "utimensat on a missing file is ENOENT");

    // -- teardown, observing each removal ----------------------------------
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, SYM, 0), "unlink sym");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, F2, 0), "unlink f2");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0), "unlink f1");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, SUB, AT_REMOVEDIR),
            "rmdir the subdir");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR),
            "rmdir the scratch dir");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR, (char[512]){0}, 0),
            "the scratch dir is gone");

    return 0;
}
