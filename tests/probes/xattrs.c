// tests/probes/xattrs.c
//
// Extended attributes: set, get, list, remove -- and the f*/l* variants.
//
// THE GAP THIS CLOSES. Sixteen xattr handlers were intercepted and NONE of
// them was differentially verified. They are not obscure: they carry file
// capabilities (security.capability), SELinux labels (security.selinux), and
// ACLs (system.posix_acl_access), and `tar --xattrs`, `cp -a`, `setcap` and
// `rsync -X` all depend on them. A wrong answer here is silent -- the file
// copies, the attribute quietly does not.
//
// They also sit on the confinement boundary. The path variants take a GUEST
// path that must be translated into the overlay before the host sees it; the
// *at forms were once decoded on aarch64 but not x86-64, so there they
// reached the host's real file from a guest tree that has no such file. That
// class of bug is exactly what a differential probe pins down.
//
// WHAT IS COMPARED. Everything here forwards to the host after translation,
// so the kernel is the oracle and the raw results are compared directly. On
// top of that the probe asserts round-trips: what set wrote, get must read
// back byte for byte, list must mention, and remove must make vanish.
//
// NOTE ON NAMESPACES. An unprivileged process may only write the "user.*"
// namespace, and only on a regular file or directory -- not a symlink. So
// the probe uses user.* throughout and checks the documented refusals rather
// than requiring privilege it will not have in CI.
#include "probe.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// The scratch paths are built at RUNTIME, not compiled in. /tmp is a tmpfs
// under linuxity and Android mounts tmpfs without user_xattr, so every
// setxattr came back EOPNOTSUPP there and eight checks went unverified for
// a reason that has nothing to do with linuxity. lx_scratch() picks a
// filesystem that supports what this probe tests.
static char DIR[256], F1[256], SYM[256], GONE[256];

#define A1   "user.lxtest"
#define A2   "user.second"
#define V1   "hello-xattr"
#define V2   "second-value"

// "Precondition did not hold" -- the traces must stay the same length on
// every host, so a check that cannot be answered says so rather than
// reporting a misleading 0. Same convention as the ioctls and legacy probes.
#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

static long slen(const char* s) {
    long n = 0;
    while (s[n]) ++n;
    return n;
}

// Is `name` one of the NUL-separated strings in a listxattr buffer?
static int in_list(const char* buf, long len, const char* name) {
    long i = 0;
    while (i < len) {
        if (strcmp(buf + i, name) == 0) return 1;
        i += slen(buf + i) + 1;
    }
    return 0;
}

int main(void) {
    lx_path(DIR,  sizeof DIR,  "lx-xattr-probe");
    {
        char rel[64];
        snprintf(rel, sizeof rel, "lx-xattr-probe/f1");  lx_path(F1,   sizeof F1,   rel);
        snprintf(rel, sizeof rel, "lx-xattr-probe/sym"); lx_path(SYM,  sizeof SYM,  rel);
        snprintf(rel, sizeof rel, "lx-xattr-probe/nope");lx_path(GONE, sizeof GONE, rel);
    }

    // Clean slate; setup, not observations.
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SYM, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR, 0755);

    const long fd = LX_SYS4(SYS_openat, AT_FDCWD, F1,
                            O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { LX_SYS3(SYS_write, fd, "body", 4); LX_SYS1(SYS_close, fd); }
    LX_SYS3(SYS_symlinkat, F1, AT_FDCWD, SYM);

    static char buf[512];

    // -- setxattr ----------------------------------------------------------
    // XATTR_CREATE is 1, XATTR_REPLACE is 2.
    const long s1 = LX_SYS5(SYS_setxattr, F1, A1, V1, slen(V1), 0);
    lx_emit("setxattr", s1, "setxattr user.lxtest");

    // Not every filesystem supports user xattrs (tmpfs historically did not,
    // and a golden recorded on such a host would be all ENOTSUP). Everything
    // below is conditioned on the first set having worked, so the trace is
    // honest either way.
    const int ok = (s1 == 0);

    lx_emit("setxattr", LX_SYS5(SYS_setxattr, F1, A2, V2, slen(V2), 0),
            "setxattr a second attribute");
    lx_emit("setxattr", LX_SYS5(SYS_setxattr, F1, A1, V1, slen(V1), 1),
            "XATTR_CREATE on an existing attr is EEXIST");
    lx_emit("setxattr", LX_SYS5(SYS_setxattr, F1, "user.absent", V1, slen(V1), 2),
            "XATTR_REPLACE on a missing attr is ENODATA");
    lx_emit("setxattr", LX_SYS5(SYS_setxattr, GONE, A1, V1, slen(V1), 0),
            "setxattr on a missing file is ENOENT");
    // Only user.*/trusted.*/security.* are valid namespaces.
    lx_emit("setxattr", LX_SYS5(SYS_setxattr, F1, "bogus.name", V1, slen(V1), 0),
            "an unknown xattr namespace is EOPNOTSUPP");

    // -- getxattr, and the round-trip --------------------------------------
    memset(buf, 0, sizeof buf);
    const long g1 = LX_SYS4(SYS_getxattr, F1, A1, buf, (long)sizeof buf);
    lx_emit("getxattr", g1, "getxattr reads the value back");
    lx_emit("getxattr", LX_CHECK(ok && g1 == slen(V1), memcmp(buf, V1, (unsigned long)g1) == 0),
            "the value round-trips byte for byte");

    // A zero-size buffer is the documented way to ASK the size.
    lx_emit("getxattr", LX_SYS4(SYS_getxattr, F1, A1, 0L, 0L),
            "size query returns the value length");
    // A buffer that is too small is ERANGE, not a truncated read.
    lx_emit("getxattr", LX_SYS4(SYS_getxattr, F1, A1, buf, 2L),
            "a too-small buffer is ERANGE");
    lx_emit("getxattr", LX_SYS4(SYS_getxattr, F1, "user.absent", buf, (long)sizeof buf),
            "getxattr of a missing attr is ENODATA");
    lx_emit("getxattr", LX_SYS4(SYS_getxattr, GONE, A1, buf, (long)sizeof buf),
            "getxattr on a missing file is ENOENT");

    // -- listxattr ---------------------------------------------------------
    memset(buf, 0, sizeof buf);
    const long ls = LX_SYS3(SYS_listxattr, F1, buf, (long)sizeof buf);
    lx_emit("listxattr", ls > 0 ? 1 : ls, "listxattr returns a name list");
    lx_emit("listxattr", LX_CHECK(ok && ls > 0, in_list(buf, ls, A1)),
            "the list contains user.lxtest");
    lx_emit("listxattr", LX_CHECK(ok && ls > 0, in_list(buf, ls, A2)),
            "the list contains user.second");
    lx_emit("listxattr", LX_SYS3(SYS_listxattr, F1, 0L, 0L) > 0 ? 1 : 0,
            "a size query returns a positive length");
    lx_emit("listxattr", LX_SYS3(SYS_listxattr, F1, buf, 1L),
            "a too-small list buffer is ERANGE");
    lx_emit("listxattr", LX_SYS3(SYS_listxattr, GONE, buf, (long)sizeof buf),
            "listxattr on a missing file is ENOENT");

    // -- the f* variants must agree with the path ones ---------------------
    {
        const long f = LX_SYS3(SYS_openat, AT_FDCWD, F1, O_RDONLY);
        memset(buf, 0, sizeof buf);
        const long fg = (f < 0) ? f : LX_SYS4(SYS_fgetxattr, f, A1, buf, (long)sizeof buf);
        lx_emit("fgetxattr", fg, "fgetxattr reads the same value");
        lx_emit("fgetxattr", LX_CHECK(ok && fg == slen(V1), memcmp(buf, V1, (unsigned long)fg) == 0),
                "fgetxattr agrees with getxattr");

        memset(buf, 0, sizeof buf);
        const long fl = (f < 0) ? f : LX_SYS3(SYS_flistxattr, f, buf, (long)sizeof buf);
        lx_emit("flistxattr", fl > 0 ? 1 : fl, "flistxattr lists the names");
        lx_emit("flistxattr", LX_CHECK(ok && fl > 0, in_list(buf, fl, A1)),
                "flistxattr contains user.lxtest");

        // fsetxattr writes through the fd; the path get must see it.
        const long fs = (f < 0) ? f
                                : LX_SYS5(SYS_fsetxattr, f, "user.viafd", "x", 1L, 0);
        lx_emit("fsetxattr", fs, "fsetxattr writes through the fd");
        memset(buf, 0, sizeof buf);
        const long back = LX_SYS4(SYS_getxattr, F1, "user.viafd", buf, (long)sizeof buf);
        lx_emit("fsetxattr", LX_CHECK(fs == 0, back == 1 && buf[0] == 'x'),
                "the path get sees what fsetxattr wrote");
        lx_emit("fremovexattr", (f < 0) ? f : LX_SYS2(SYS_fremovexattr, f, "user.viafd"),
                "fremovexattr drops it again");
        if (f >= 0) LX_SYS1(SYS_close, f);
    }

    lx_emit("fgetxattr", LX_SYS4(SYS_fgetxattr, 9999, A1, buf, (long)sizeof buf),
            "fgetxattr on a closed fd is EBADF");

    // -- the l* (no-follow) variants ---------------------------------------
    // A symlink cannot carry user.* attributes at all, which is the
    // documented refusal rather than a linuxity quirk. lgetxattr must look at
    // the LINK and so find nothing, where getxattr follows to the target.
    memset(buf, 0, sizeof buf);
    const long lg = LX_SYS4(SYS_lgetxattr, SYM, A1, buf, (long)sizeof buf);
    lx_emit("lgetxattr", lg, "lgetxattr on a symlink does NOT follow");
    memset(buf, 0, sizeof buf);
    const long sg = LX_SYS4(SYS_getxattr, SYM, A1, buf, (long)sizeof buf);
    lx_emit("getxattr", sg, "getxattr through the symlink DOES follow");
    lx_emit("lgetxattr", LX_CHECK(ok, lg != sg),
            "the follow and no-follow forms disagree, as they must");

    lx_emit("lsetxattr", LX_SYS5(SYS_lsetxattr, SYM, A1, V1, slen(V1), 0),
            "lsetxattr on a symlink is EPERM");
    memset(buf, 0, sizeof buf);
    lx_emit("llistxattr", LX_SYS3(SYS_llistxattr, SYM, buf, (long)sizeof buf),
            "llistxattr on a symlink lists nothing");

    // On a REGULAR FILE the l* forms have nothing to not-follow, so they
    // must behave exactly like their plain counterparts. Only ever testing
    // them on a symlink exercised the refusal and never the working path --
    // which is most of what they do, since `cp -a` and `tar` reach for the
    // l* spelling by default and meet regular files far more often.
    lx_emit("lsetxattr", LX_SYS5(SYS_lsetxattr, F1, "user.lform", V2, slen(V2), 0),
            "lsetxattr on a regular file works");
    memset(buf, 0, sizeof buf);
    {
        const long g = LX_SYS4(SYS_lgetxattr, F1, "user.lform", buf, (long)sizeof buf);
        lx_emit("lgetxattr", g, "lgetxattr reads it back");
        lx_emit("lgetxattr", LX_CHECK(g == slen(V2), memcmp(buf, V2, (unsigned long)g) == 0),
                "the l-form value round-trips");
    }
    memset(buf, 0, sizeof buf);
    {
        const long l = LX_SYS3(SYS_llistxattr, F1, buf, (long)sizeof buf);
        lx_emit("llistxattr", l > 0 ? 1 : l, "llistxattr on a regular file");
        lx_emit("llistxattr", LX_CHECK(l > 0, in_list(buf, l, "user.lform")),
                "...and it names the attribute we set");
    }
    lx_emit("lremovexattr", LX_SYS2(SYS_lremovexattr, F1, "user.lform"),
            "lremovexattr drops it");
    lx_emit("lgetxattr", LX_SYS4(SYS_lgetxattr, F1, "user.lform", buf, (long)sizeof buf),
            "it is ENODATA after lremovexattr");

    // -- removexattr -------------------------------------------------------
    lx_emit("removexattr", LX_SYS2(SYS_removexattr, F1, A2), "removexattr the second attr");
    lx_emit("removexattr", LX_SYS4(SYS_getxattr, F1, A2, buf, (long)sizeof buf),
            "it is ENODATA after removal");
    lx_emit("removexattr", LX_SYS2(SYS_removexattr, F1, A2),
            "removing it twice is ENODATA");
    lx_emit("removexattr", LX_SYS2(SYS_removexattr, GONE, A1),
            "removexattr on a missing file is ENOENT");
    lx_emit("lremovexattr", LX_SYS2(SYS_lremovexattr, SYM, A1),
            "lremovexattr on a symlink");

    // -- a directory carries xattrs too ------------------------------------
    lx_emit("setxattr", LX_SYS5(SYS_setxattr, DIR, A1, V1, slen(V1), 0),
            "setxattr on a directory");
    memset(buf, 0, sizeof buf);
    lx_emit("getxattr", LX_SYS4(SYS_getxattr, DIR, A1, buf, (long)sizeof buf),
            "getxattr on a directory");
    lx_emit("removexattr", LX_SYS2(SYS_removexattr, DIR, A1),
            "removexattr on a directory");

    // Tear down.
    LX_SYS2(SYS_removexattr, F1, A1);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SYM, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR);
    return 0;
}
