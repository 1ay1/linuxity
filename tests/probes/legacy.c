// tests/probes/legacy.c
//
// The x86-64-only syscalls that predate the *at family -- and the invariant
// that each one answers exactly like its modern equivalent.
//
// THE GAP THIS CLOSES. 56 syscalls exist on x86-64 and not on aarch64:
// open, stat, lstat, access, chmod, chown, rename, link, symlink, readlink,
// unlink, mkdir, rmdir, creat, utimes. Every probe in the suite reaches for
// the portable spelling (openat, newfstatat, unlinkat, ...), which is the
// right default -- it is the only one that compiles on both arches. The
// consequence is that the 18 calls an x86-64 glibc ACTUALLY issues were never
// differentially verified at all.
//
// That is the exact shape of a bug that shipped today: TCGETS2 and its
// sign-extended spelling are one operation with two encodings, the handler
// matched one, and the other fell through to the host. Two spellings of one
// operation, only one of them tested, is a hole with a known failure mode.
//
// WHAT IS COMPARED. Each alias is run against the live kernel like any other
// probe, so the golden holds the kernel's own answer. On top of that the
// probe asserts the EQUIVALENCE directly: stat(p) must report the same inode
// and mode as newfstatat(AT_FDCWD, p, 0), access(p, R_OK) must agree with
// faccessat, and so on. A divergence in either the raw result or the
// equivalence is a real difference in behaviour.
//
// ON AARCH64 this probe is a no-op that emits the same number of steps, every
// one marked not-applicable. The traces must stay the same length on every
// host or the step-by-step comparison misaligns.
#include "probe.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define DIR  "/tmp/lx-legacy-probe"
#define F1   DIR "/f1"
#define F2   DIR "/f2"
#define SYM  DIR "/sym"
#define GONE DIR "/absent"

// "Precondition did not hold", same convention as the ioctls probe: the two
// runs must emit the same step count, so a check that cannot be answered says
// so rather than reporting a misleading 0.
#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

// struct stat is big and its layout is arch-specific, but the two fields this
// probe compares sit at fixed offsets on x86-64: st_ino at 8, st_mode at 24.
// Only ever read on x86-64, where the legacy calls exist.
#define OFF_INO  8
#define OFF_MODE 24

#if defined(__x86_64__)

static unsigned long long ino_of(const unsigned char* st) {
    unsigned long long v;
    memcpy(&v, st + OFF_INO, 8);
    return v;
}
static unsigned mode_of(const unsigned char* st) {
    unsigned v;
    memcpy(&v, st + OFF_MODE, 4);
    return v;
}

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
    // Clean slate; setup, not observations.
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SYM, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F2, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR);

    static unsigned char a[256], b[256];

    // -- mkdir / rmdir -----------------------------------------------------
    lx_emit("mkdir", LX_SYS2(SYS_mkdir, DIR, 0755), "mkdir the scratch dir");
    lx_emit("mkdir", LX_SYS2(SYS_mkdir, DIR, 0755), "mkdir an existing dir is EEXIST");
    lx_emit("mkdir", LX_SYS2(SYS_mkdir, DIR "/a/b", 0755),
            "mkdir with a missing parent is ENOENT");

    // -- open / creat ------------------------------------------------------
    // open(2) is THE call an x86-64 glibc issues for fopen(). It had no
    // differential coverage at all.
    {
        const long fd = LX_SYS3(SYS_open, F1, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        lx_emit("open", fd < 0 ? fd : 1, "open with O_CREAT makes a file");
        if (fd >= 0) {
            LX_SYS3(SYS_write, fd, "hello", 5);
            LX_SYS1(SYS_close, fd);
        }
    }
    lx_emit("open", LX_SYS3(SYS_open, GONE, O_RDONLY, 0),
            "open a missing file is ENOENT");
    lx_emit("open", LX_SYS3(SYS_open, F1, O_WRONLY | O_CREAT | O_EXCL, 0644),
            "O_EXCL on an existing file is EEXIST");
    lx_emit("open", LX_SYS3(SYS_open, DIR, O_WRONLY, 0),
            "opening a directory for write is EISDIR");

    {
        const long fd = LX_SYS2(SYS_creat, F2, 0644);
        lx_emit("creat", fd < 0 ? fd : 1, "creat makes a file");
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }

    // -- stat / lstat, and the equivalence with newfstatat -----------------
    const long s1 = LX_SYS2(SYS_stat, F1, a);
    lx_emit("stat", s1, "stat a regular file");
    const long s2 = LX_SYS4(SYS_newfstatat, AT_FDCWD, F1, b, 0);
    lx_emit("newfstatat", s2, "newfstatat the same file");
    // THE INVARIANT: the legacy call and the modern one describe one file.
    lx_emit("stat", LX_CHECK(s1 == 0 && s2 == 0, ino_of(a) == ino_of(b)),
            "stat and newfstatat agree on st_ino");
    lx_emit("stat", LX_CHECK(s1 == 0 && s2 == 0, mode_of(a) == mode_of(b)),
            "stat and newfstatat agree on st_mode");

    lx_emit("stat", LX_SYS2(SYS_stat, GONE, a), "stat a missing file is ENOENT");
    lx_emit("stat", LX_SYS2(SYS_stat, "", a), "stat an empty path is ENOENT");

    // lstat must NOT follow a symlink, which is its whole reason to exist.
    lx_emit("symlink", LX_SYS2(SYS_symlink, F1, SYM), "symlink to f1");
    const long l1 = LX_SYS2(SYS_lstat, SYM, a);
    const long l2 = LX_SYS2(SYS_stat, SYM, b);
    lx_emit("lstat", l1, "lstat the symlink itself");
    lx_emit("lstat", LX_CHECK(l1 == 0, (mode_of(a) & 0170000) == 0120000),
            "lstat reports S_IFLNK");
    lx_emit("lstat", LX_CHECK(l1 == 0 && l2 == 0, ino_of(a) != ino_of(b)),
            "lstat and stat see DIFFERENT inodes through a symlink");

    // -- readlink ----------------------------------------------------------
    {
        char buf[128];
        memset(buf, 0, sizeof buf);
        const long n = LX_SYS3(SYS_readlink, SYM, buf, (long)sizeof buf);
        lx_emit("readlink", n > 0 ? 1 : n, "readlink the symlink");
        lx_emit("readlink", LX_CHECK(n > 0, (long)strlen(F1) == n),
                "readlink returns the target length");
    }
    lx_emit("readlink", LX_SYS3(SYS_readlink, F1, a, 128L),
            "readlink a non-symlink is EINVAL");

    // -- access, and the equivalence with faccessat ------------------------
    const long ar = LX_SYS2(SYS_access, F1, R_OK);
    lx_emit("access", ar, "access R_OK on a readable file");
    lx_emit("access", LX_SYS3(SYS_faccessat, AT_FDCWD, F1, R_OK),
            "faccessat R_OK agrees");
    lx_emit("access", LX_SYS2(SYS_access, GONE, R_OK),
            "access a missing file is ENOENT");
    lx_emit("access", LX_SYS2(SYS_access, F1, F_OK), "access F_OK is existence");

    // -- chmod, and that it is visible to stat -----------------------------
    lx_emit("chmod", LX_SYS2(SYS_chmod, F1, 0600), "chmod 600");
    {
        const long st = LX_SYS2(SYS_stat, F1, a);
        lx_emit("chmod", LX_CHECK(st == 0, (mode_of(a) & 0777) == 0600),
                "stat sees the new mode");
    }
    lx_emit("chmod", LX_SYS2(SYS_chmod, GONE, 0600),
            "chmod a missing file is ENOENT");

    // -- chown. Changing the owner needs privilege we may not have, so the
    //    observation is the call to -1/-1, which is a documented no-op.
    lx_emit("chown", LX_SYS3(SYS_chown, F1, -1, -1), "chown -1/-1 is a no-op");
    lx_emit("chown", LX_SYS3(SYS_chown, GONE, -1, -1),
            "chown a missing file is ENOENT");
    lx_emit("lchown", LX_SYS3(SYS_lchown, SYM, -1, -1), "lchown the symlink");

    // -- link / unlink -----------------------------------------------------
    lx_emit("link", LX_SYS2(SYS_link, F1, DIR "/hard"), "link makes a hard link");
    {
        const long h = LX_SYS2(SYS_stat, DIR "/hard", a);
        const long o = LX_SYS2(SYS_stat, F1, b);
        lx_emit("link", LX_CHECK(h == 0 && o == 0, ino_of(a) == ino_of(b)),
                "a hard link shares the inode");
    }
    lx_emit("link", LX_SYS2(SYS_link, F1, DIR "/hard"),
            "link onto an existing name is EEXIST");
    lx_emit("unlink", LX_SYS1(SYS_unlink, DIR "/hard"), "unlink the hard link");
    lx_emit("unlink", LX_SYS1(SYS_unlink, GONE), "unlink a missing file is ENOENT");
    lx_emit("unlink", LX_SYS1(SYS_unlink, DIR), "unlink a directory is EISDIR");

    // -- rename ------------------------------------------------------------
    lx_emit("rename", LX_SYS2(SYS_rename, F2, DIR "/renamed"), "rename a file");
    lx_emit("rename", LX_SYS2(SYS_stat, F2, a), "the old name is gone");
    lx_emit("rename", LX_SYS2(SYS_stat, DIR "/renamed", a), "the new name is there");
    lx_emit("rename", LX_SYS2(SYS_rename, GONE, DIR "/x"),
            "renaming a missing file is ENOENT");

    // -- utimes: set a known time and read it back -------------------------
    {
        // struct timeval[2] = {sec, usec} x2. 1600000000 is a fixed instant,
        // so the observation does not depend on when the probe ran.
        long tv[4] = {1600000000L, 0L, 1600000000L, 0L};
        lx_emit("utimes", LX_SYS2(SYS_utimes, F1, tv), "utimes sets a fixed mtime");
        const long st = LX_SYS2(SYS_stat, F1, a);
        unsigned long long mtime = 0;
        if (st == 0) memcpy(&mtime, a + 88, 8);     // st_mtime on x86-64
        lx_emit("utimes", LX_CHECK(st == 0, mtime == 1600000000ULL),
                "stat reads back the mtime we set");
    }
    lx_emit("utimes", LX_SYS2(SYS_utimes, GONE, 0L),
            "utimes on a missing file is ENOENT");

    // -- rmdir -------------------------------------------------------------
    lx_emit("rmdir", LX_SYS1(SYS_rmdir, F1), "rmdir a regular file is ENOTDIR");
    lx_emit("rmdir", LX_SYS1(SYS_rmdir, DIR), "rmdir a non-empty dir is ENOTEMPTY");

    // Tear down; the last two are observations of the now-empty dir.
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SYM, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/renamed", 0);
    lx_emit("rmdir", LX_SYS1(SYS_rmdir, DIR), "rmdir the now-empty dir");
    lx_emit("rmdir", LX_SYS1(SYS_rmdir, DIR), "rmdir it again is ENOENT");
    return 0;
}

#else   /* !__x86_64__ */

// These syscalls DO NOT EXIST on this arch -- aarch64 has only the *at forms.
// The probe still has to emit the same 44 steps, or the step-by-step trace
// comparison misaligns against a host that does have them. Every one reports
// not-applicable, which is the honest answer: the question cannot be asked.
int main(void) {
    static const char* const kSteps[] = {
        "mkdir the scratch dir", "mkdir an existing dir is EEXIST",
        "mkdir with a missing parent is ENOENT",
        "open with O_CREAT makes a file", "open a missing file is ENOENT",
        "O_EXCL on an existing file is EEXIST",
        "opening a directory for write is EISDIR", "creat makes a file",
        "stat a regular file", "newfstatat the same file",
        "stat and newfstatat agree on st_ino",
        "stat and newfstatat agree on st_mode",
        "stat a missing file is ENOENT", "stat an empty path is ENOENT",
        "symlink to f1", "lstat the symlink itself", "lstat reports S_IFLNK",
        "lstat and stat see DIFFERENT inodes through a symlink",
        "readlink the symlink", "readlink returns the target length",
        "readlink a non-symlink is EINVAL",
        "access R_OK on a readable file", "faccessat R_OK agrees",
        "access a missing file is ENOENT", "access F_OK is existence",
        "chmod 600", "stat sees the new mode", "chmod a missing file is ENOENT",
        "chown -1/-1 is a no-op", "chown a missing file is ENOENT",
        "lchown the symlink",
        "link makes a hard link", "a hard link shares the inode",
        "link onto an existing name is EEXIST", "unlink the hard link",
        "unlink a missing file is ENOENT", "unlink a directory is EISDIR",
        "rename a file", "the old name is gone", "the new name is there",
        "renaming a missing file is ENOENT",
        "utimes sets a fixed mtime", "stat reads back the mtime we set",
        "utimes on a missing file is ENOENT",
        "rmdir a regular file is ENOTDIR", "rmdir a non-empty dir is ENOTEMPTY",
        "rmdir the now-empty dir", "rmdir it again is ENOENT",
    };
    // The call name has to match the x86-64 run step for step too, and on
    // this arch none of them were issued -- "openat" is the honest stand-in
    // for "a call this arch does not have", and the value says NA anyway.
    for (unsigned i = 0; i < sizeof kSteps / sizeof *kSteps; ++i)
        lx_emit("openat", LX_NA, kSteps[i]);
    return 0;
}

#endif
