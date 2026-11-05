// tests/probes/statpaths.c
//
// stat/lstat/fstat/newfstatat/statx and access/faccessat across the realms
// linuxity distinguishes: host-backed, virtualised (procfs/sysfs), absent,
// and the awkward ones (root, symlinks, a file where a dir is expected).
//
// Error paths dominate on purpose. An emulator that returns the wrong errno
// breaks callers that branch on it, and errno is where divergence hides: the
// happy path is easy to get right, ENOTDIR-vs-ENOENT is not.
#include "probe.h"

#include <fcntl.h>
#include <sys/stat.h>

// Emit only whether the call succeeded and, on failure, the errno. The stat
// BUFFER is deliberately not compared: it holds inode numbers, timestamps and
// a device id, all of which legitimately differ between two runs.
static void stat_path(const char* what, const char* path) {
    char st[512];
    const long r = LX_SYS4(SYS_newfstatat, AT_FDCWD, path, st, 0);
    lx_emit("newfstatat", r < 0 ? r : 1, what);
}

static void lstat_path(const char* what, const char* path) {
    char st[512];
    const long r =
        LX_SYS4(SYS_newfstatat, AT_FDCWD, path, st, AT_SYMLINK_NOFOLLOW);
    lx_emit("newfstatat", r < 0 ? r : 1, what);
}

static void access_path(const char* what, const char* path, int mode) {
    const long r = LX_SYS3(SYS_faccessat, AT_FDCWD, path, mode);
    lx_emit("faccessat", r < 0 ? r : 1, what);
}

int main(void) {
    // -- host-backed, must exist ------------------------------------------
    stat_path("/ (the root itself)", "/");
    stat_path("/. (root, dot form)", "/.");
    stat_path("/usr", "/usr");
    stat_path("/usr/bin (a dir)", "/usr/bin");
    stat_path("/etc/hostname (a file)", "/etc/hostname");

    // -- virtualised -------------------------------------------------------
    stat_path("/proc", "/proc");
    stat_path("/proc/self", "/proc/self");
    stat_path("/proc/self/stat", "/proc/self/stat");
    stat_path("/proc/uptime", "/proc/uptime");
    stat_path("/sys", "/sys");
    stat_path("/dev", "/dev");
    stat_path("/dev/null", "/dev/null");

    // -- absent: ENOENT ----------------------------------------------------
    stat_path("missing top-level must be ENOENT", "/nonexistent-xyzzy");
    stat_path("missing under a real dir", "/usr/nonexistent-xyzzy");
    stat_path("missing under /proc", "/proc/nonexistent-xyzzy");

    // -- the error paths that matter --------------------------------------
    // A path component that is a FILE, not a dir, is ENOTDIR -- not ENOENT.
    stat_path("file-as-directory must be ENOTDIR", "/etc/hostname/x");
    // The empty path is ENOENT, a classic off-by-one in path handling.
    stat_path("empty path must be ENOENT", "");
    // A trailing slash on a FILE is ENOTDIR.
    stat_path("file with trailing slash must be ENOTDIR", "/etc/hostname/");

    // -- lstat vs stat on a symlink ---------------------------------------
    lstat_path("lstat /proc/self (a symlink)", "/proc/self");
    stat_path("stat /proc/self follows to a dir", "/proc/self");

    // -- access ------------------------------------------------------------
    access_path("F_OK on /usr", "/usr", F_OK);
    access_path("R_OK on /etc/hostname", "/etc/hostname", R_OK);
    access_path("F_OK on a missing path", "/nonexistent-xyzzy", F_OK);
    access_path("X_OK on a non-executable file", "/etc/hostname", X_OK);

    // -- fstat on fds we know ---------------------------------------------
    {
        char st[512];
        lx_emit("fstat", LX_SYS2(SYS_fstat, 1, st) < 0 ? -1 : 1, "fstat stdout");
        lx_emit("fstat", LX_SYS2(SYS_fstat, 9999, st), "fstat bad fd is EBADF");
    }

    // -- statx, the modern form -------------------------------------------
    {
        char sx[256];
        const long r = LX_SYS5(SYS_statx, AT_FDCWD, "/usr", 0, 0x7ff, sx);
        lx_emit("statx", r < 0 ? r : 1, "statx /usr");
        const long m = LX_SYS5(SYS_statx, AT_FDCWD, "/nonexistent-xyzzy", 0,
                               0x7ff, sx);
        lx_emit("statx", m, "statx missing is ENOENT");
    }

    // -- readlink ----------------------------------------------------------
    {
        char buf[256];
        const long r = LX_SYS4(SYS_readlinkat, AT_FDCWD, "/proc/self", buf,
                               sizeof buf);
        lx_emit("readlinkat", r > 0 ? 1 : r, "readlink /proc/self");
        const long d = LX_SYS4(SYS_readlinkat, AT_FDCWD, "/usr", buf,
                               sizeof buf);
        lx_emit("readlinkat", d, "readlink of a dir is EINVAL");
    }

    return 0;
}
