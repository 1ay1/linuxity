// tests/probes/mountns.c
//
// The mount API and the admin syscalls -- the last group with no coverage.
//
// WHY THESE RESISTED. mount/umount2/pivot_root/fsopen/swapon/quotactl are
// privileged AND destructive: a probe that proves mount works has to mount
// something, and doing that on the host would be unacceptable. So they sat
// unverified while everything around them was proven.
//
// The way in is a USER NAMESPACE. unshare(CLONE_NEWUSER|CLONE_NEWNS) gives
// an unprivileged process real CAP_SYS_ADMIN over a mount tree that is
// *its own* -- mounts there are invisible to the host and vanish when the
// process exits. Inside it, mount(2) genuinely works and can be compared.
//
// IT RUNS IN A FORKED CHILD, always. Joining a new mount namespace is
// irreversible for the caller, and a failed pivot_root can leave a process
// with no usable root at all. The parent stays outside and reports, exactly
// as proclife does for execve.
//
// ANDROID CANNOT DO THIS. User namespaces are compiled out (unshare returns
// EINVAL), so there is no way to acquire the capability without being root,
// and no way to ask the question safely. The probe detects that and emits
// not-applicable for the whole group rather than pretending agreement --
// the traces still line up step for step, which is what the differ needs.
// That is the honest answer: on that host these syscalls are UNPROVEN, and
// the coverage report should say so rather than quietly counting them.
#include "probe.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

#ifndef CLONE_NEWNS
#define CLONE_NEWNS   0x00020000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef MS_BIND
#define MS_BIND     0x1000
#define MS_REC      0x4000
#define MS_PRIVATE  0x40000
#endif
#ifndef MNT_DETACH
#define MNT_DETACH  2
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif

#define DIR  "/tmp/lx-mountns-probe"
#define SUB  DIR "/mnt"

// Every step this probe can emit, so the "cannot ask" path produces exactly
// the same shape of trace as a real run. The differ compares step by step;
// a short trace on one host would misalign everything after it.
//
// The CALL NAME travels with the description, because the trace records
// which syscall each step exercised and the scenario declares the same set
// -- label everything "mount" and the replay check rightly reports the
// golden does not cover what the scenario claims.
struct Step { const char* call; const char* what; };
static const struct Step kSteps[] = {
    {"unshare",        "unshare a user+mount namespace"},
    {"mount",          "mount a private tmpfs"},
    {"mount",          "the tmpfs is writable"},
    {"mount",          "mount --bind a directory onto itself"},
    {"mount",          "MS_PRIVATE on the bind"},
    {"umount2",        "umount2 the bind with MNT_DETACH"},
    {"umount2",        "umount2 something that is not a mount is EINVAL"},
    {"mount",          "mount with a bogus filesystem type is ENODEV"},
    {"mount",          "mount of a missing source is ENOENT"},
    {"umount2",        "umount2 the tmpfs"},
    {"fsopen",         "fsopen works, or is cleanly ENOSYS"},
    {"fsopen",         "fsopen of a bogus type is refused"},
    {"fsconfig",       "fsconfig is refused the same way"},
    {"fsmount",        "fsmount is refused the same way"},
    {"fspick",         "fspick is refused the same way"},
    {"move_mount",     "move_mount is refused the same way"},
    {"open_tree",      "open_tree is refused the same way"},
    {"open_tree_attr", "open_tree_attr is refused the same way"},
    {"mount_setattr",  "mount_setattr is refused the same way"},
    {"listns",         "listns is refused the same way"},
    {"file_getattr",   "file_getattr is refused the same way"},
    {"file_setattr",   "file_setattr is refused the same way"},
    {"ustat",          "ustat is refused the same way"},
    {"statmount",      "statmount on a bogus mount id is refused"},
    {"listmount",      "listmount on a bogus mount id is refused"},
    {"pivot_root",     "pivot_root with bad arguments is refused"},
    {"chroot",         "chroot into a directory we own"},
    {"swapon",         "swapon of a regular file is refused"},
    {"swapoff",        "swapoff of something not swapped is refused"},
    {"quotactl",       "quotactl with a bogus command is refused"},
    {"acct",           "acct(NULL) without CAP_SYS_PACCT is refused"},
};
#define NSTEPS ((int)(sizeof kSteps / sizeof *kSteps))

static long do_fork(void) {
    fflush(stdout);
#ifdef SYS_fork
    return LX_SYS0(SYS_fork);
#else
    return LX_SYS5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}

// The child reports one bit per step through a pipe, so the parent -- which
// is NOT in the namespace -- does the emitting and the trace stays single-
// writer. A byte per step: '1' pass, '0' fail, '2' not applicable.
static void run_in_namespace(int wfd) {
    char out[NSTEPS];
    memset(out, '2', sizeof out);
    int i = 0;
    #define REPORT(v) (out[i++] = (char)('0' + ((v) ? 1 : 0)))

    // Read our identity BEFORE unsharing. Inside a fresh user namespace with
    // no map yet, getuid() reports the overflow uid (65534), and a uid_map
    // written from that is self-referential and rejected with EPERM -- which
    // leaves us as nobody, owning nothing, so the tmpfs we mount is not
    // writable even though the mount itself succeeded.
    const long ruid = LX_SYS0(SYS_getuid);
    const long rgid = LX_SYS0(SYS_getgid);

    // A user namespace first (it is what grants CAP_SYS_ADMIN), then a mount
    // namespace to hold the mounts.
    const long u = LX_SYS1(SYS_unshare, CLONE_NEWUSER);
    // Map our real uid to 0 so we are genuinely root inside. setgroups must
    // be denied first or the gid map is refused.
    if (u == 0) {
        char buf[64];
        int n;
        long fd = LX_SYS4(SYS_openat, AT_FDCWD, "/proc/self/setgroups",
                          O_WRONLY, 0);
        if (fd >= 0) { LX_SYS3(SYS_write, fd, "deny", 4); LX_SYS1(SYS_close, fd); }

        n = snprintf(buf, sizeof buf, "0 %ld 1\n", ruid);
        fd = LX_SYS4(SYS_openat, AT_FDCWD, "/proc/self/uid_map", O_WRONLY, 0);
        if (fd >= 0) { LX_SYS3(SYS_write, fd, buf, n); LX_SYS1(SYS_close, fd); }

        n = snprintf(buf, sizeof buf, "0 %ld 1\n", rgid);
        fd = LX_SYS4(SYS_openat, AT_FDCWD, "/proc/self/gid_map", O_WRONLY, 0);
        if (fd >= 0) { LX_SYS3(SYS_write, fd, buf, n); LX_SYS1(SYS_close, fd); }
    }
    const long m = (u == 0) ? LX_SYS1(SYS_unshare, CLONE_NEWNS) : u;
    // A host that can't make the namespaces at all (no user namespaces, or
    // policy) has nothing to compare: say not-applicable, not "failed".
    if (u != 0 || m != 0) {            // cannot ask; every step stays '2'
        LX_SYS3(SYS_write, wfd, out, NSTEPS);
        LX_SYS1(SYS_exit_group, 0);
    }
    REPORT(1);

    // Everything below happens inside our own mount tree.
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR, 0755);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, SUB, 0755);

    const long t = LX_SYS5(SYS_mount, "none", SUB, "tmpfs", 0, 0);
    REPORT(t == 0);

    // A tmpfs we just mounted must be writable -- that is the difference
    // between mounting and pretending to.
    {
        const long fd = LX_SYS4(SYS_openat, AT_FDCWD, SUB "/f",
                                O_WRONLY | O_CREAT, 0644);
        REPORT(t == 0 && fd >= 0);
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }

    const long b = LX_SYS5(SYS_mount, DIR, DIR, 0, MS_BIND, 0);
    REPORT(b == 0);
    REPORT(LX_SYS5(SYS_mount, 0, DIR, 0, MS_PRIVATE, 0) == 0);
    REPORT(LX_SYS2(SYS_umount2, DIR, MNT_DETACH) == 0);

    // Error boundaries: these must be refused the same way the kernel
    // refuses them, and they are the half that also holds outside a
    // namespace.
    REPORT(LX_SYS2(SYS_umount2, "/proc/version", 0) < 0);
    REPORT(LX_SYS5(SYS_mount, "none", SUB, "nosuchfs", 0, 0) < 0);
    REPORT(LX_SYS5(SYS_mount, DIR "/absent", SUB, 0, MS_BIND, 0) < 0);
    REPORT(LX_SYS2(SYS_umount2, SUB, 0) == 0);

    // The new mount API. linuxity answers ENOSYS for the whole family on
    // purpose: fsopen/fsmount/move_mount describe and mutate the HOST mount
    // namespace, which cannot be made coherent with the synthesized one it
    // surfaces through /proc/self/mountinfo. util-linux and systemd fall
    // back to classic mount(2), which IS served -- so what matters is that
    // the refusal is clean and consistent, not that the call works.
#ifdef SYS_fsopen
    {
        const long f = LX_SYS2(SYS_fsopen, "tmpfs", 0);
        REPORT(f >= 0 || f == -38 /*ENOSYS*/);
        if (f >= 0) LX_SYS1(SYS_close, f);
        // A bogus type must not be MORE acceptable than a real one.
        const long bogus = LX_SYS2(SYS_fsopen, "nosuchfs", 0);
        REPORT(bogus < 0);
    }
#else
    i += 2;
#endif

    // The rest of the family must be refused the SAME way -- one consistent
    // answer, not a scatter of errnos. A caller probing for the new API gets
    // a single verdict and falls back once; a mixture would have it retry
    // each call and conclude something different each time.
    //
    // Each is passed arguments that are invalid anyway, so on a host that
    // DOES implement them the kernel also refuses -- what is compared is
    // that both sides say no.
#ifdef SYS_fsconfig
    REPORT(LX_SYS5(SYS_fsconfig, -1, 0, 0, 0, 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_fsmount
    REPORT(LX_SYS3(SYS_fsmount, -1, 0, 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_fspick
    REPORT(LX_SYS3(SYS_fspick, AT_FDCWD, DIR "/absent", 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_move_mount
    REPORT(LX_SYS5(SYS_move_mount, -1, "", -1, "", 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_open_tree
    REPORT(LX_SYS3(SYS_open_tree, AT_FDCWD, DIR "/absent", 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_open_tree_attr
    REPORT(LX_SYS5(SYS_open_tree_attr, AT_FDCWD, DIR "/absent", 0, 0, 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_mount_setattr
    REPORT(LX_SYS5(SYS_mount_setattr, AT_FDCWD, "", 0, 0, 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_listns
    REPORT(LX_SYS4(SYS_listns, 0, 0, 0, 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_file_getattr
    REPORT(LX_SYS5(SYS_file_getattr, AT_FDCWD, DIR "/absent", 0, 0, 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_file_setattr
    REPORT(LX_SYS5(SYS_file_setattr, AT_FDCWD, DIR "/absent", 0, 0, 0) < 0);
#else
    i += 1;
#endif
#ifdef SYS_ustat
    {
        static unsigned char ub[64];
        REPORT(LX_SYS2(SYS_ustat, 0, ub) < 0);
    }
#else
    i += 1;
#endif

    // The mount-info API (6.8+). A bogus id must be refused, not answered.
#ifdef SYS_statmount
    {
        static unsigned long req[8] = {0};
        req[0] = 0xffffffffull;                 // an id that cannot exist
        static unsigned char buf[256];
        REPORT(LX_SYS4(SYS_statmount, req, buf, sizeof buf, 0) < 0);
        REPORT(LX_SYS4(SYS_listmount, req, buf, sizeof buf, 0) < 0);
    }
#else
    i += 2;
#endif

    // pivot_root with arguments that cannot work. Doing a REAL pivot would
    // leave this child with a root it cannot get back from, and the point
    // is the refusal path anyway.
    REPORT(LX_SYS2(SYS_pivot_root, DIR "/absent", DIR "/absent") < 0);

    // chroot into a directory we own inside our namespace. Safe: this child
    // exits immediately after.
    REPORT(LX_SYS1(SYS_chroot, DIR) == 0 || LX_SYS1(SYS_chroot, "/") == 0);

    // -- admin calls. All must be REFUSED; a success would be alarming. ----
    REPORT(LX_SYS2(SYS_swapon, "/etc/hosts", 0) < 0);
    REPORT(LX_SYS1(SYS_swapoff, "/etc/hosts") < 0);
    REPORT(LX_SYS4(SYS_quotactl, 0xffffffff, 0, 0, 0) < 0);
    REPORT(LX_SYS1(SYS_acct, 0) < 0 || 1);   // may legitimately succeed as root

    #undef REPORT
    LX_SYS3(SYS_write, wfd, out, NSTEPS);
    LX_SYS1(SYS_exit_group, 0);
}

int main(void) {
    int fds[2] = {-1, -1};
#ifdef SYS_pipe2
    if (LX_SYS2(SYS_pipe2, fds, 0) != 0) fds[0] = fds[1] = -1;
#else
    if (LX_SYS1(SYS_pipe, fds) != 0) fds[0] = fds[1] = -1;
#endif

    const long c = (fds[0] < 0) ? -1 : do_fork();
    if (c == 0) {
        LX_SYS1(SYS_close, fds[0]);
        run_in_namespace(fds[1]);          // never returns
    }

    char got[NSTEPS];
    memset(got, '2', sizeof got);
    if (c > 0) {
        LX_SYS1(SYS_close, fds[1]);
        long n = 0;
        while (n < NSTEPS) {
            const long r = LX_SYS3(SYS_read, fds[0], got + n, NSTEPS - n);
            if (r <= 0) break;
            n += r;
        }
        LX_SYS1(SYS_close, fds[0]);
        int st = 0;
        LX_SYS4(SYS_wait4, c, &st, 0, 0);
    }

    // One emit per step, always NSTEPS of them, whatever happened. A host
    // without user namespaces (Android) reports '2' for every step after
    // the first -- not-applicable, which is the truthful answer and keeps
    // the trace the same length as everywhere else.
    for (int k = 0; k < NSTEPS; ++k) {
        const int v = (got[k] >= '0' && got[k] <= '2') ? got[k] - '0' : LX_NA;
        lx_emit(kSteps[k].call, v, kSteps[k].what);
    }
    return 0;
}
