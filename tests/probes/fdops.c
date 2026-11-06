// tests/probes/fdops.c
//
// fd lifecycle: dup/dup2/dup3, fcntl, close, and the EBADF boundaries.
//
// This family is where the closed-fd bug lived, and fd bookkeeping is the
// part of linuxity most likely to drift from the kernel: it maintains its own
// table (fd->path, virtual dir streams) alongside the host's real fds, and
// any divergence between the two shows up as a wrong errno.
//
// fd NUMBERS are not compared -- linuxity reserves 3..8 on purpose so pacman's
// libcurl workers cannot race for fd 3 (commit ea99143), so the guest's first
// new fd is 4 where native gets 3. The law exempts the numeric value; what is
// compared is success-vs-errno and the RELATIONSHIPS between fds.
#include "probe.h"

#include <fcntl.h>
#include <sys/stat.h>

int main(void) {
    // -- open, dup, and the invariant that a dup shares the file -----------
    // /etc/hosts rather than /etc/hostname: both are ordinary readable files
    // on a desktop distro, but Android has no /etc/hostname, and the probe
    // has to run on every Linux host that might record a golden.
    const long fd = LX_SYS3(SYS_openat, AT_FDCWD, "/etc/hosts", O_RDONLY);
    lx_emit("openat", fd < 0 ? fd : 1, "open a regular file");
    if (fd < 0) return 1;

    const long d1 = LX_SYS1(SYS_dup, fd);
    lx_emit("dup", d1 < 0 ? d1 : 1, "dup succeeds");

    // A dup must be a DIFFERENT number than the original. Comparing the
    // relationship rather than the values keeps this stable under the fd
    // reservation.
    lx_emit("dup", (d1 != fd) ? 1 : 0, "dup returns a distinct fd");

    // Both must refer to the same file: reading from one advances the other.
    {
        char a[8], b[8];
        const long ra = LX_SYS3(SYS_read, fd, a, 4);
        const long rb = LX_SYS3(SYS_read, d1, b, 4);
        lx_emit("read", ra == 4 ? 1 : ra, "read 4 via the original");
        lx_emit("read", rb == 4 ? 1 : rb, "read 4 via the dup");
        // Shared offset: the dup's read must NOT return the same bytes.
        lx_emit("read", (a[0] != b[0] || a[1] != b[1]) ? 1 : 0,
                "dup shares the file offset");
    }

    // -- dup2 / dup3 -------------------------------------------------------
    // aarch64 (and every asm-generic arch) has NO dup2 syscall at all: glibc
    // implements dup2(o,n) as dup3(o,n,0), except that dup2 onto the SAME fd
    // is a no-op success while dup3 is EINVAL. Do the same here so the probe
    // builds and means the same thing on both arches -- the trace labels stay
    // "dup2", because what is being tested is the dup2 CONTRACT.
#ifdef SYS_dup2
#  define LX_DUP2(o, n) LX_SYS2(SYS_dup2, (o), (n))
#  define LX_DUP2_SELF(f) LX_SYS2(SYS_dup2, (f), (f))
#else
#  define LX_DUP2(o, n) LX_SYS3(SYS_dup3, (o), (n), 0)
   // dup2(fd, fd) returns fd without closing anything; dup3 rejects it.
#  define LX_DUP2_SELF(f) (f)
#endif

    // dup2 to an explicit target must land exactly there.
    const long t = LX_DUP2(fd, 400);
    lx_emit("dup2", t == 400 ? 1 : t, "dup2 lands on the requested fd");

    // dup2 onto ITSELF is a no-op success, not an error -- a classic miss.
    const long same = LX_DUP2_SELF(fd);
    lx_emit("dup2", same == fd ? 1 : same, "dup2(fd, fd) is a no-op success");

    // dup3 with the same fds must be EINVAL (unlike dup2).
    const long d3same = LX_SYS3(SYS_dup3, fd, fd, 0);
    lx_emit("dup3", d3same, "dup3(fd, fd, 0) must be EINVAL");

    // dup3 with a bad flag is EINVAL.
    const long d3bad = LX_SYS3(SYS_dup3, fd, 401, 0x12345);
    lx_emit("dup3", d3bad, "dup3 with a bogus flag must be EINVAL");

    // -- fcntl -------------------------------------------------------------
    lx_emit("fcntl", LX_SYS2(SYS_fcntl, fd, F_GETFD) >= 0 ? 1 : -1,
            "F_GETFD on a live fd");
    lx_emit("fcntl", LX_SYS3(SYS_fcntl, fd, F_SETFD, FD_CLOEXEC),
            "F_SETFD CLOEXEC");
    lx_emit("fcntl", LX_SYS2(SYS_fcntl, fd, F_GETFD) == FD_CLOEXEC ? 1 : 0,
            "F_GETFD reflects the CLOEXEC we set");
    lx_emit("fcntl", LX_SYS2(SYS_fcntl, 9999, F_GETFD), "F_GETFD bad fd is EBADF");
    lx_emit("fcntl", LX_SYS3(SYS_fcntl, fd, 0x7ffe, 0),
            "an unknown fcntl cmd must be EINVAL");

    // F_DUPFD must return the lowest free fd AT OR ABOVE the floor.
    {
        const long dupfd = LX_SYS3(SYS_fcntl, fd, F_DUPFD, 500);
        lx_emit("fcntl", dupfd >= 500 ? 1 : dupfd, "F_DUPFD respects its floor");
        if (dupfd >= 0) lx_emit("close", LX_SYS1(SYS_close, dupfd), "close the F_DUPFD");
    }

    // -- the EBADF boundaries ---------------------------------------------
    lx_emit("close", LX_SYS1(SYS_close, 9999), "close a bad fd is EBADF");
    lx_emit("close", LX_SYS1(SYS_close, -1), "close(-1) is EBADF");

    {
        char st[512];
        lx_emit("fstat", LX_SYS2(SYS_fstat, 9999, st), "fstat bad fd is EBADF");
        lx_emit("newfstatat", LX_SYS4(SYS_newfstatat, 9999, "x", st, 0),
                "newfstatat on a bad dirfd is EBADF");
    }

    // -- close then reuse --------------------------------------------------
    lx_emit("close", LX_SYS1(SYS_close, d1), "close the dup");
    lx_emit("close", LX_SYS1(SYS_close, d1), "double close is EBADF");
    lx_emit("read", LX_SYS3(SYS_read, d1, (char[8]){0}, 4),
            "read after close is EBADF");

    lx_emit("close", LX_SYS1(SYS_close, t), "close the dup2 target");
    lx_emit("close", LX_SYS1(SYS_close, fd), "close the original");
    lx_emit("read", LX_SYS3(SYS_read, fd, (char[8]){0}, 4),
            "read the closed original is EBADF");

    // -- O_DIRECTORY and friends on the wrong kind of file ----------------
    lx_emit("openat",
            LX_SYS3(SYS_openat, AT_FDCWD, "/etc/hostname", O_RDONLY | O_DIRECTORY),
            "O_DIRECTORY on a file must be ENOTDIR");
    lx_emit("openat",
            LX_SYS4(SYS_openat, AT_FDCWD, "/usr", O_WRONLY, 0),
            "O_WRONLY on a directory must be EISDIR");
    lx_emit("openat",
            LX_SYS3(SYS_openat, AT_FDCWD, "/nonexistent-xyzzy", O_RDONLY),
            "open a missing file is ENOENT");
    lx_emit("openat",
            LX_SYS4(SYS_openat, AT_FDCWD, "/etc/hostname/x", O_RDONLY, 0),
            "file-as-directory component is ENOTDIR");

    return 0;
}
