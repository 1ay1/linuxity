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

    // -- mutating a SYNTHESIZED path ---------------------------------------
    // procfs is not a read-only mount, so none of these is EROFS. The errno
    // comes from the inode op the filesystem lacks, and which op is missing
    // depends on the operation -- so each class has to be asked separately.
    //
    // Creating a name: procfs dirs have no mkdir/symlink/mknod/create op, so
    // the VFS cannot make the name exist at all -> ENOENT, even when the
    // parent directory is right there.
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, "/proc/lxnew", 0755),
            "mkdir in /proc is ENOENT, not EROFS");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, "/proc/self/lxnew", 0755),
            "mkdir under an existing procfs dir is still ENOENT");
    lx_emit("symlinkat", LX_SYS3(SYS_symlinkat, "x", AT_FDCWD, "/proc/self/lxlink"),
            "symlink into procfs is ENOENT");
    lx_emit("mknodat", LX_SYS4(SYS_mknodat, AT_FDCWD, "/proc/self/lxnod", 0100644, 0),
            "mknod into procfs is ENOENT");

    // Creating over a name that DOES exist: the existence check runs first,
    // so EEXIST wins over the missing-create-op ENOENT above. These reach a
    // different branch than the cases above (the leaf resolves), which is
    // exactly where a blanket EROFS used to hide.
    lx_emit("symlinkat", LX_SYS3(SYS_symlinkat, "x", AT_FDCWD, "/proc/self/comm"),
            "symlink over an existing procfs file is EEXIST");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, "/proc/self/comm", 0755),
            "mkdir over an existing procfs file is EEXIST");
    lx_emit("mknodat", LX_SYS4(SYS_mknodat, AT_FDCWD, "/proc/version", 0100644, 0),
            "mknod over an existing procfs file is EEXIST");

    // Removing or truncating needs write permission on the containing
    // directory, checked BEFORE the missing inode op. The /proc root denies
    // it (EACCES); deeper dirs allow it so the inode refuses instead (EPERM).
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, "/proc/version", 0),
            "unlink directly under /proc is EACCES");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, "/proc/self/comm", 0),
            "unlink deeper in procfs is EPERM");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, "/proc/self/fd", AT_REMOVEDIR),
            "rmdir of a procfs dir is EPERM");
    lx_emit("truncate", LX_SYS2(SYS_truncate, "/proc/version", 0),
            "truncate under /proc is EACCES");

    // No setattr for the mode -> refused. WHICH refusal varies by host and
    // the guest cannot know which kernel it faces: mainline procfs has no
    // setattr for the mode and says EPERM, while Android's SELinux denies
    // the change at the permission layer first and says EACCES. Both are
    // correct for their kernel, so collapse them the way creds.c does and
    // assert the portable fact -- it is refused, and not with EROFS.
    {
        const long c1 = LX_SYS4(SYS_fchmodat, AT_FDCWD, "/proc/version", 0666, 0);
        lx_emit("fchmodat", (c1 == -EPERM || c1 == -EACCES) ? 1 : c1,
                "chmod on procfs is refused with EPERM or EACCES");
        const long c2 = LX_SYS4(SYS_fchmodat, AT_FDCWD, "/proc/self/comm", 0666, 0);
        lx_emit("fchmodat", (c2 == -EPERM || c2 == -EACCES) ? 1 : c2,
                "chmod is refused even on a writable procfs file");
    }

    // rename/link: inside procfs the destination name cannot be created, so
    // ENOENT; crossing between procfs and a real filesystem is a genuine
    // cross-mount move and reports EXDEV.
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, "/proc/self/comm", AT_FDCWD, "/proc/self/c2"),
            "rename within procfs is ENOENT");
    lx_emit("linkat",
            LX_SYS5(SYS_linkat, AT_FDCWD, "/proc/self/comm", AT_FDCWD, "/proc/self/c3", 0),
            "link within procfs is ENOENT");
    // With the destination ALSO existing, rename and link part ways: link
    // refuses the taken name (EEXIST), rename replaces and so hits the
    // missing rename inode op (EPERM).
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, "/proc/self/comm", AT_FDCWD, "/proc/version"),
            "rename onto an existing procfs name is EPERM");
    lx_emit("linkat",
            LX_SYS5(SYS_linkat, AT_FDCWD, "/proc/version", AT_FDCWD, "/proc/self/comm", 0),
            "link onto an existing procfs name is EEXIST");
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, "/proc/nope", AT_FDCWD, "/proc/nope2"),
            "rename of an absent procfs source is ENOENT");
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, "/proc/self/comm", AT_FDCWD, F2),
            "rename out of procfs is EXDEV");
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, F1, AT_FDCWD, "/proc/self/comm"),
            "rename into procfs is EXDEV");

    // -- the NULL path, and "."/".." as a final component ------------------
    // A NULL path pointer is NOT an empty string. utimensat spells "set the
    // times on this fd" that way, which is what touch(1) does on every file
    // it stamps -- reading it as "" made touch fail with ENOENT.
    {
        const long dfd = LX_SYS3(SYS_openat, AT_FDCWD, DIR, O_RDONLY | O_DIRECTORY);
        lx_emit("utimensat", LX_SYS4(SYS_utimensat, dfd, 0, 0, 0),
                "utimensat with a NULL path sets times on the dirfd");
        lx_emit("utimensat", LX_SYS4(SYS_utimensat, AT_FDCWD, 0, 0, 0),
                "a NULL path with no fd to fall back on is EFAULT");
        lx_emit("utimensat", LX_SYS4(SYS_utimensat, 999, 0, 0, 0),
                "a NULL path on a closed fd is EBADF");
        lx_emit("utimensat", LX_SYS4(SYS_utimensat, dfd, "", 0, 0),
                "an EMPTY path is still ENOENT, unlike NULL");
        lx_emit("utimensat", LX_SYS4(SYS_utimensat, dfd, "", 0, 0x1000),
                "...unless AT_EMPTY_PATH says the fd is the target");
        if (dfd >= 0) LX_SYS1(SYS_close, dfd);
    }

    // "." and ".." are the self and parent entries, not names you can remove.
    // Normalizing them away first turned `rmdir d/.` into a removal of d and
    // `rmdir d/..` into a removal of its PARENT -- the guest silently deleted
    // directories the kernel never touches.
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/dotdir", 0755);
    lx_emit("unlinkat",
            LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dotdir/.", 0x200),
            "rmdir of a path ending in . is EINVAL");
    lx_emit("unlinkat",
            LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dotdir/..", 0x200),
            "rmdir of a path ending in .. is ENOTEMPTY");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dotdir/.", 0),
            "unlink of a path ending in . is EISDIR");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/dotdir", (char[512]){0}, 0),
            "...and the directory is still there afterwards");
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, DIR "/dotdir/.", AT_FDCWD, DIR "/moved"),
            "rename of a . component is EBUSY");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dotdir", 0x200);

    // An empty symlink TARGET is ENOENT, and that is checked before anything
    // about the link name -- so it outranks the trailing-slash rule, which
    // would otherwise report EEXIST for a name that already exists.
    lx_emit("symlinkat", LX_SYS3(SYS_symlinkat, "", AT_FDCWD, DIR "/"),
            "an empty symlink target is ENOENT, not EEXIST");

    // A regular file used as a directory COMPONENT is ENOTDIR, and that
    // outranks the existence check -- testing existence first answered
    // ENOENT. Both metadata setters had the ordering wrong.
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, F1 "/bad", 0511, 0),
            "chmod through a FILE used as a directory is ENOTDIR");
    lx_emit("fchownat", LX_SYS5(SYS_fchownat, AT_FDCWD, F1 "/bad", -1, -1, 0),
            "chown through a FILE used as a directory is ENOTDIR");

    // chmod FOLLOWS a final symlink (there is no lchmod), so a dangling one
    // is ENOENT -- classifying the link instead of its target made this
    // report success. Found by the differential fuzzer.
    LX_SYS3(SYS_symlinkat, "gone-target", AT_FDCWD, DIR "/dangling");
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/dangling", 0600, 0),
            "chmod through a dangling symlink is ENOENT");
    lx_emit("fchownat", LX_SYS5(SYS_fchownat, AT_FDCWD, DIR "/dangling", -1, -1, 0),
            "chown through a dangling symlink is ENOENT too");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dangling", 0);

    // -- an unsearchable directory outranks every structural rule ----------
    // Without +x the kernel cannot traverse into a directory at all, so it
    // never discovers the "."/".." or the trailing slash it would otherwise
    // complain about -- EACCES comes first. The guest normalized those
    // components away and answered EEXIST/EINVAL/ENOTEMPTY instead.
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/nox", 0755);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/nox/in", 0755);
    LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nox", 0644, 0);   // readable, not searchable
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/nox/.", 0755),
            "mkdir through an unsearchable dir is EACCES, not EEXIST");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/nox/in/..", 0755),
            "...and so is mkdir on its .. ");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/nox/.", 0x200),
            "rmdir of . in an unsearchable dir is EACCES, not EINVAL");
    lx_emit("openat",
            LX_SYS4(SYS_openat, AT_FDCWD, DIR "/nox/.", O_WRONLY | O_CREAT | O_EXCL, 0644),
            "O_CREAT through an unsearchable dir is EACCES");
    lx_emit("symlinkat", LX_SYS3(SYS_symlinkat, "x", AT_FDCWD, DIR "/nox/in"),
            "symlink into an unsearchable dir is EACCES");
    lx_emit("linkat",
            LX_SYS5(SYS_linkat, AT_FDCWD, F1, AT_FDCWD, DIR "/nox/in/", 0),
            "hardlink into an unsearchable dir is EACCES, not ENOENT");
    LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nox", 0755, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/nox/in", 0x200);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/nox", 0x200);

    // A TRAILING SLASH asserts the name is a directory. rename checks it
    // against both operands (ENOTDIR when the source is not one); a hardlink
    // is never a directory, so for link the slash can only ever fail -- but
    // the source is resolved FIRST, so a missing source is ENOENT and an
    // existing destination is EEXIST, both ahead of the slash.
    lx_emit("renameat", LX_SYS4(SYS_renameat, AT_FDCWD, F1, AT_FDCWD, DIR "/newdir/"),
            "rename of a FILE to a trailing-slash name is ENOTDIR");
    lx_emit("renameat", LX_SYS4(SYS_renameat, AT_FDCWD, F1 "/", AT_FDCWD, DIR "/n2"),
            "rename FROM a trailing-slash file is ENOTDIR");
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, F1, AT_FDCWD, DIR "/newlnk/", 0),
            "hardlink to a trailing-slash name is ENOENT");
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, DIR "/nope", AT_FDCWD, SUB "/", 0),
            "...but a missing SOURCE is ENOENT first, not EEXIST");
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, F1, AT_FDCWD, SUB "/", 0),
            "...and an existing destination is EEXIST, slash or not");

    // -- a dot does not excuse the components before it --------------------
    // The kernel WALKS a path. "gone/.." fails at `gone`, even though the
    // lexically normalized form is a directory that plainly exists. The guest
    // rewrote the string first, so the missing component was never looked up:
    // stat("gone/../f1") SUCCEEDED and mkdir("gone/../x") actually created
    // the directory. A file before the dot is ENOTDIR, and a prefix hidden
    // behind an unsearchable directory is EACCES rather than ENOENT.
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/gone/..", 0700),
            "mkdir past a MISSING component is ENOENT, not EEXIST");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/gone/..", (char[512]){0}, 0),
            "stat past a missing component is ENOENT");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/gone/../x", 0700),
            "...and the directory is NOT created");
    lx_emit("openat", LX_SYS4(SYS_openat, AT_FDCWD, DIR "/gone/../f1", O_RDONLY, 0),
            "open past a missing component is ENOENT");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/gone/..", 0x200),
            "rmdir past a missing component is ENOENT");
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/gone/..", 0755, 0),
            "chmod past a missing component is ENOENT");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/gone/.", 0700),
            "a single dot past a missing component is ENOENT too");
    lx_emit("mkdirat", LX_SYS3(SYS_mkdirat, AT_FDCWD, F1 "/..", 0700),
            "a FILE before the dot is ENOTDIR");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, F1 "/..", (char[512]){0}, 0),
            "stat with a file before the dot is ENOTDIR");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/x/../f1", (char[512]){0}, 0),
            "the x/.. did not create anything either");

    // -- rename's error ORDER, which is not the obvious one ----------------
    // A dot component is EBUSY and outranks everything structural. Then a
    // destination that is an ANCESTOR of the source is ENOTEMPTY (the move
    // would absorb a directory containing itself) -- note that is about
    // containment, NOT about the destination merely being a non-empty
    // directory, which is only ENOTDIR. Each of these was wrong in a
    // different direction before.
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/anc", 0755);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/anc/kid", 0755);
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, DIR "/anc/", AT_FDCWD, DIR "/anc/.."),
            "a dot component is EBUSY, ahead of the ancestor rule");
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, DIR "/anc/kid", AT_FDCWD, DIR "/anc/"),
            "renaming into the source's own parent is ENOTEMPTY");
    lx_emit("renameat",
            LX_SYS4(SYS_renameat, AT_FDCWD, F1, AT_FDCWD, DIR "/anc/"),
            "...but an unrelated non-empty dir is only ENOTDIR");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/anc/kid", 0x200);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/anc", 0x200);

    // -- hardlink: the slash ENOENT is the LAST conclusion -----------------
    // Every structural fact about the destination is decided before the
    // "a hardlink is not a directory" verdict. Each of these answered ENOENT
    // before, because the slash rule short-circuited the lot.
    LX_SYS3(SYS_symlinkat, "nowhere", AT_FDCWD, DIR "/dang2");
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, DIR "/", AT_FDCWD, DIR "/dang2/x", 0),
            "a dangling link as the dst prefix is ENOENT");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/dang2", 0);
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, DIR "/", AT_FDCWD, F1 "/x", 0),
            "a FILE as the dst prefix is ENOTDIR");
    lx_emit("linkat", LX_SYS5(SYS_linkat, AT_FDCWD, DIR "/", AT_FDCWD, SUB "/x", 0),
            "linking a DIRECTORY is EPERM");
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/nox2", 0755);
    LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nox2", 0644, 0);
    lx_emit("linkat",
            LX_SYS5(SYS_linkat, AT_FDCWD, DIR "/", AT_FDCWD, DIR "/nox2/x", 0),
            "an unsearchable dst dir is EACCES, ahead of all of it");
    LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nox2", 0755, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/nox2", 0x200);

    // chmod/chown in an unsearchable directory is EACCES, not ENOENT: the
    // existence probe cannot see the file, which is not the same as it not
    // being there.
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR "/nox3", 0755);
    {
        const long t = LX_SYS4(SYS_openat, AT_FDCWD, DIR "/nox3/t",
                               O_WRONLY | O_CREAT, 0644);
        if (t >= 0) LX_SYS1(SYS_close, t);
    }
    LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nox3", 0644, 0);
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nox3/t", 0600, 0),
            "chmod in an unsearchable dir is EACCES, not ENOENT");
    lx_emit("fchownat", LX_SYS5(SYS_fchownat, AT_FDCWD, DIR "/nox3/t", -1, -1, 0),
            "chown in an unsearchable dir is EACCES, not ENOENT");
    LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/nox3", 0755, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/nox3/t", 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/nox3", 0x200);

    // -- a symlink LOOP is ELOOP, not a file and not absent ----------------
    // The symlink chase has a hop budget, but running out of it returned the
    // last link as a host-backed path -- so stat on a self-referential link
    // SUCCEEDED and chmod answered ENOENT, where the kernel says ELOOP.
    LX_SYS3(SYS_symlinkat, DIR "/loop", AT_FDCWD, DIR "/loop");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/loop", (char[512]){0}, 0),
            "stat of a symlink loop is ELOOP, not success");
    lx_emit("openat", LX_SYS4(SYS_openat, AT_FDCWD, DIR "/loop", O_RDONLY, 0),
            "open of a symlink loop is ELOOP");
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/loop", 0755, 0),
            "chmod of a symlink loop is ELOOP, not ENOENT");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/loop", (char[512]){0}, 0x100),
            "...but lstat sees the link itself");
    lx_emit("fchmodat", LX_SYS4(SYS_fchmodat, AT_FDCWD, DIR "/loop/under", 0755, 0),
            "a loop in the PREFIX is ELOOP too, not ENOENT");
    lx_emit("newfstatat",
            LX_SYS4(SYS_newfstatat, AT_FDCWD, DIR "/loop/under", (char[512]){0}, 0),
            "stat through a loop prefix is ELOOP");
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/loop", 0),
            "and the loop can still be unlinked");

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
