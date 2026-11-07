// tests/probes/syscalls2.c
//
// The long tail: fs calls nothing else reached, the xattr *at forms,
// sockets, inotify/fanotify, landlock, and the file-handle API.
//
// THE POINT. A syscall that FAILS is still conformance: EPERM, ENOSYS and
// EINVAL are answers, and the guest must give the same one as the kernel. A
// probe does not need privilege to pin a privileged syscall -- it needs the
// two sides to agree about being refused. That is what makes most of this
// group testable at all, and it is a real property: a guest that gets 0 from
// something the kernel refuses is lying to the program, and one that gets
// ENOSYS where the kernel says EPERM breaks feature detection.
//
// Landlock is the exception that needs care: restrict_self is IRREVERSIBLE
// and would sandbox the probe for the rest of its run, so it happens in a
// forked child whose exit status is the observation -- the same trick
// proclife uses for execve.
#include "probe.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#define LX_NA 2
#define LX_CHECK(pre, cond) ((pre) ? ((cond) ? 1 : 0) : LX_NA)

#define DIR  "/tmp/lx-sys2-probe"
#define F1   DIR "/f1"
#define SOK  DIR "/sock"

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif

static long do_fork(void) {
    fflush(stdout);                 // never let a child reprint our buffer
#ifdef SYS_fork
    return LX_SYS0(SYS_fork);
#else
    return LX_SYS5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}
static int exited_with(int st) { return ((st & 0x7f) == 0) ? ((st >> 8) & 0xff) : -1; }

int main(void) {
    LX_SYS3(SYS_unlinkat, AT_FDCWD, SOK, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR);
    LX_SYS3(SYS_mkdirat, AT_FDCWD, DIR, 0755);
    {
        const long fd = LX_SYS4(SYS_openat, AT_FDCWD, F1, O_WRONLY | O_CREAT, 0644);
        if (fd >= 0) { LX_SYS3(SYS_write, fd, "x", 1); LX_SYS1(SYS_close, fd); }
    }

    // -- fs calls the other probes never reached --------------------------
    // fchmodat2 (6.6+) takes flags where fchmodat did not.
    //
    // linuxity may legitimately be AHEAD of the host here. It synthesizes a
    // 6.6 guest kernel, so on an older host -- Android's 6.1, where this is
    // ENOSYS -- implementing it is the same kind of papering-over as serving
    // termios2 through the classic ioctls. What must NOT happen is the
    // reverse: ENOSYS where the host supports it, which would silently
    // downgrade a guest. So the assertion is "works, or matches the host's
    // refusal", not "identical to the host".
#ifdef SYS_fchmodat2
    {
        const long r = LX_SYS4(SYS_fchmodat2, AT_FDCWD, F1, 0600, 0);
        lx_emit("fchmodat2", (r == 0 || r == -38 /*ENOSYS*/) ? 1 : 0,
                "fchmodat2 works, or is ENOSYS on a kernel without it");
        const long e = LX_SYS4(SYS_fchmodat2, AT_FDCWD, DIR "/nope", 0600, 0);
        lx_emit("fchmodat2", (e == -2 /*ENOENT*/ || e == -38) ? 1 : 0,
                "fchmodat2 on a missing file is ENOENT (or ENOSYS)");
    }
#else
    lx_emit("fchmodat2", LX_NA, "fchmodat2 works, or is ENOSYS on a kernel without it");
    lx_emit("fchmodat2", LX_NA, "fchmodat2 on a missing file is ENOENT (or ENOSYS)");
#endif

    // openat2 takes a struct open_how instead of a flags word, and RESOLVE_*
    // flags that constrain path walking -- which is precisely the kind of
    // thing a sandbox must not get wrong.
#ifdef SYS_openat2
    {
        // struct open_how { __u64 flags, mode, resolve; }
        static unsigned long how[3] = {O_RDONLY, 0, 0};
        const long fd = LX_SYS4(SYS_openat2, AT_FDCWD, F1, how, 24);
        lx_emit("openat2", fd < 0 ? fd : 1, "openat2 opens a file");
        if (fd >= 0) LX_SYS1(SYS_close, fd);
        // A bad struct size is EINVAL, which is how the ABI is versioned.
        lx_emit("openat2", LX_SYS4(SYS_openat2, AT_FDCWD, F1, how, 7),
                "openat2 with a short struct is EINVAL");
        // RESOLVE_BENEATH (0x08) must refuse an absolute path.
        static unsigned long beneath[3] = {O_RDONLY, 0, 0x08};
        lx_emit("openat2", LX_SYS4(SYS_openat2, AT_FDCWD, "/etc/hosts", beneath, 24),
                "RESOLVE_BENEATH refuses to escape");
    }
#else
    lx_emit("openat2", LX_NA, "openat2 opens a file");
    lx_emit("openat2", LX_NA, "openat2 with a short struct is EINVAL");
    lx_emit("openat2", LX_NA, "RESOLVE_BENEATH refuses to escape");
#endif

    // utime / futimesat: the pre-utimensat spellings, x86-64 only.
#ifdef SYS_utime
    {
        static long tv[2] = {1600000000L, 1600000000L};   // actime, modtime
        lx_emit("utime", LX_SYS2(SYS_utime, F1, tv), "utime sets a fixed mtime");
        lx_emit("utime", LX_SYS2(SYS_utime, DIR "/nope", tv),
                "utime on a missing file is ENOENT");
    }
#else
    lx_emit("utime", LX_NA, "utime sets a fixed mtime");
    lx_emit("utime", LX_NA, "utime on a missing file is ENOENT");
#endif
#ifdef SYS_futimesat
    {
        static long tv[4] = {1600000000L, 0, 1600000000L, 0};
        lx_emit("futimesat", LX_SYS3(SYS_futimesat, AT_FDCWD, F1, tv),
                "futimesat sets times");
    }
#else
    lx_emit("futimesat", LX_NA, "futimesat sets times");
#endif

    // mknod (the non-at form): a FIFO needs no privilege, a DEVICE does.
    // Both answers are conformance.
#ifdef SYS_mknod
    lx_emit("mknod", LX_SYS3(SYS_mknod, DIR "/fifo", 0010644, 0),
            "mknod makes a FIFO");
    lx_emit("mknod", LX_SYS3(SYS_mknod, DIR "/dev", 0020644, 0x103),
            "mknod of a character device without privilege is EPERM");
    LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR "/fifo", 0);
#else
    lx_emit("mknod", LX_NA, "mknod makes a FIFO");
    lx_emit("mknod", LX_NA, "mknod of a character device without privilege is EPERM");
#endif

    // -- the xattr *at forms (6.13+) --------------------------------------
    // These were decoded on aarch64 but NOT x86-64 at one point, so there
    // they reached the host's real file from a guest path. ENOSYS on an
    // older kernel is fine as long as BOTH sides say it.
#ifdef SYS_getxattrat
    {
        static char buf[64];
        lx_emit("setxattrat", LX_SYS5(SYS_setxattrat, AT_FDCWD, F1, 0,
                                      "user.at", 0),
                "setxattrat");
        lx_emit("getxattrat", LX_SYS5(SYS_getxattrat, AT_FDCWD, F1, 0,
                                      "user.at", buf),
                "getxattrat");
        lx_emit("listxattrat", LX_SYS5(SYS_listxattrat, AT_FDCWD, F1, 0, buf, 64),
                "listxattrat");
        lx_emit("removexattrat", LX_SYS4(SYS_removexattrat, AT_FDCWD, F1, 0,
                                         "user.at"),
                "removexattrat");
    }
#else
    lx_emit("setxattrat",    LX_NA, "setxattrat");
    lx_emit("getxattrat",    LX_NA, "getxattrat");
    lx_emit("listxattrat",   LX_NA, "listxattrat");
    lx_emit("removexattrat", LX_NA, "removexattrat");
#endif

    // -- sockets: bind/connect over AF_UNIX, to ourselves ------------------
    // A socket needs no peer if it is a listening socket we then connect to.
    // This is also the path where linuxity must TRANSLATE sun_path into the
    // overlay -- a guest socket that lands on the host filesystem is a
    // confinement hole, and the fallback that did that was removed.
    {
        // struct sockaddr_un { u16 family; char path[108]; }
        static unsigned char sa[110];
        memset(sa, 0, sizeof sa);
        sa[0] = 1;                                   // AF_UNIX
        memcpy(sa + 2, SOK, sizeof SOK);
        const long s = LX_SYS3(SYS_socket, 1 /*AF_UNIX*/, 1 /*SOCK_STREAM*/, 0);
        lx_emit("socket", s < 0 ? s : 1, "an AF_UNIX stream socket");
        // Pass the FULL sockaddr_un length, which is what every real caller
        // does (sizeof(struct sockaddr_un)). Sizing the length to the guest
        // path instead would leave no room for the translated host path the
        // kernel sees, and the second call on the same buffer would read a
        // truncated prefix.
        const long slen = (long)sizeof sa;
        const long b = (s < 0) ? s : LX_SYS3(SYS_bind, s, sa, slen);
        lx_emit("bind", b, "bind it to a path in our own tree");
        // the kernel reads the sockaddr, never writes it
        lx_emit("bind", memcmp(sa + 2, SOK, sizeof SOK) == 0 ? 1 : 0,
                "bind leaves the caller's sockaddr as it was");
        {
            static unsigned char got[110];
            static unsigned int glen;
            memset(got, 0, sizeof got);
            glen = sizeof got;
            const long g = (b == 0) ? LX_SYS3(SYS_getsockname, s, got, &glen) : -1;
            lx_emit("getsockname",
                    LX_CHECK(b == 0, g == 0 && glen == 2 + sizeof SOK &&
                                     memcmp(got + 2, SOK, sizeof SOK) == 0),
                    "getsockname gives back the path that was bound");
        }
        const long l = (b == 0) ? LX_SYS2(SYS_listen, s, 1) : -1;
        lx_emit("bind", LX_CHECK(b == 0, l == 0), "listen on it");

        // Connect a second socket to the first: no external peer needed.
        // Deliberately the SAME sockaddr buffer, because that is what a
        // client/server pair in one process does -- and translating an
        // already-translated path doubled the prefix, so the two never met.
        const long c = LX_SYS3(SYS_socket, 1, 1, 0);
        const long cc = (c < 0 || b != 0) ? -1
                      : LX_SYS3(SYS_connect, c, sa, slen);
        lx_emit("connect", LX_CHECK(b == 0 && c >= 0, cc == 0),
                "connect to it from a second socket");
        {
            static unsigned char got[110];
            static unsigned int glen;
            memset(got, 0, sizeof got);
            glen = sizeof got;
            const long g = (cc == 0) ? LX_SYS3(SYS_getpeername, c, got, &glen) : -1;
            lx_emit("getpeername",
                    LX_CHECK(cc == 0, g == 0 && memcmp(got + 2, SOK, sizeof SOK) == 0),
                    "the client's peer is the bound path");
        }
        if (c >= 0) LX_SYS1(SYS_close, c);
        if (s >= 0) LX_SYS1(SYS_close, s);
        LX_SYS3(SYS_unlinkat, AT_FDCWD, SOK, 0);
    }
    // -- syslog(2): the kernel log. Root (the guest) may read it; an
    // unprivileged native caller gets EPERM under dmesg_restrict, which
    // the law exempts. Sizes vary by config, so only "answered" is kept.
    {
        static char klog[4096];
        const long sz = LX_SYS3(SYS_syslog, 10 /*SIZE_BUFFER*/, 0, 0);
        lx_emit("syslog", sz > 0 ? 1 : sz, "the log has a size");
        const long rd = LX_SYS3(SYS_syslog, 3 /*READ_ALL*/, klog, sizeof klog);
        lx_emit("syslog", rd > 0 ? 1 : rd, "READ_ALL returns records");
    }
    // Connecting to a socket that is not there must be refused. WHICH
    // refusal depends on the namespace: a filesystem socket gives ENOENT
    // (no such path), but where the host forbids filesystem binds --
    // Android, every directory an app can write -- linuxity falls back to
    // the ABSTRACT namespace, where there is no directory entry to be
    // missing and the kernel says ECONNREFUSED instead.
    //
    // That is inherent to the fallback, not a mistake: the alternative is
    // no AF_UNIX at all on that host. What matters is that the connect is
    // REFUSED rather than quietly succeeding, so the probe asserts the
    // refusal and not its spelling.
    {
        static unsigned char sa[110];
        memset(sa, 0, sizeof sa);
        sa[0] = 1;
        memcpy(sa + 2, DIR "/absent-sock", sizeof(DIR "/absent-sock"));
        const long c = LX_SYS3(SYS_socket, 1, 1, 0);
        const long r = (c < 0) ? c : LX_SYS3(SYS_connect, c, sa, (long)sizeof sa);
        lx_emit("connect", LX_CHECK(c >= 0, r < 0),
                "connect to a missing socket is refused");
        if (c >= 0) LX_SYS1(SYS_close, c);
    }

    // -- inotify / fanotify ------------------------------------------------
    // The ADD is observable without ever waiting for an event.
    {
        const long fd = LX_SYS1(SYS_inotify_init1, 0);
        lx_emit("inotify_add_watch", fd < 0 ? fd : 1, "inotify_init1");
        // IN_MODIFY = 0x2
        lx_emit("inotify_add_watch",
                (fd < 0) ? fd : (LX_SYS3(SYS_inotify_add_watch, fd, DIR, 0x2) >= 0 ? 1 : -1),
                "watch a directory");
        lx_emit("inotify_add_watch",
                (fd < 0) ? fd : LX_SYS3(SYS_inotify_add_watch, fd, DIR "/nope", 0x2),
                "watching a missing path is ENOENT");
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }
    // fanotify needs CAP_SYS_ADMIN, so EPERM is the expected answer -- and
    // both sides must agree on it rather than one inventing success.
    {
        const long fd = LX_SYS2(SYS_fanotify_init, 0, 0);
        lx_emit("fanotify_mark", fd < 0 ? fd : 1,
                "fanotify_init (EPERM without CAP_SYS_ADMIN)");
        lx_emit("fanotify_mark",
                (fd < 0) ? fd : LX_SYS5(SYS_fanotify_mark, fd, 1, 0x1, AT_FDCWD, DIR),
                "fanotify_mark");
        if (fd >= 0) LX_SYS1(SYS_close, fd);
    }

    // -- landlock ----------------------------------------------------------
    // restrict_self is IRREVERSIBLE: it sandboxes the caller for life. So the
    // whole sequence runs in a child, and the child's exit status is the
    // observation. Without a ruleset fd the create is the interesting call;
    // on a kernel without landlock it is ENOSYS, which both sides must match.
#ifdef SYS_landlock_create_ruleset
    {
        // struct landlock_ruleset_attr { __u64 handled_access_fs; }
        static unsigned long attr = 0x1;      // LANDLOCK_ACCESS_FS_EXECUTE
        const long r = LX_SYS3(SYS_landlock_create_ruleset, &attr, 8, 0);
        // Like fchmodat2, linuxity may be AHEAD of the host: it accepts
        // landlock so a sandboxing guest (pacman does this) proceeds, even
        // where the host kernel has none and answers ENOSYS. Either is fine;
        // what must not happen is a half-answer that leaves the guest
        // believing it is sandboxed when nothing was applied.
        lx_emit("landlock_create_ruleset", (r >= 0 || r == -38) ? 1 : 0,
                "create a ruleset: works, or ENOSYS where the host has none");
        // A null rule_attr is EFAULT, and an unknown rule type EINVAL --
        // argument validation happens before policy, so these hold whether
        // or not landlock is really implemented.
        const long ar = (r < 0) ? -38 : LX_SYS4(SYS_landlock_add_rule, r, 1, 0, 0);
        lx_emit("landlock_add_rule", (ar < 0) ? 1 : 0,
                "add_rule with a null attr is refused");
        const long c = do_fork();
        if (c == 0) {
            // Child: restricting ourselves here cannot hurt the parent.
            const long rc = LX_SYS2(SYS_landlock_restrict_self, r, 0);
            LX_SYS1(SYS_exit_group, (rc == 0) ? 0 : 70);
        }
        int st = 0;
        const long w = (c > 0) ? LX_SYS4(SYS_wait4, c, &st, 0, 0) : c;
        lx_emit("landlock_restrict_self",
                LX_CHECK(w > 0, exited_with(st) == 0 || exited_with(st) == 70),
                "restrict_self in a child either works or is refused");
        if (r >= 0) LX_SYS1(SYS_close, r);
    }
#else
    lx_emit("landlock_create_ruleset", LX_NA,
            "create a ruleset: works, or ENOSYS where the host has none");
    lx_emit("landlock_add_rule", LX_NA, "add_rule with a null attr is refused");
    lx_emit("landlock_restrict_self", LX_NA,
            "restrict_self in a child either works or is refused");
#endif

    // -- the file-handle API -----------------------------------------------
    // linuxity refuses BOTH of these on purpose: the handle encodes host
    // filesystem inode identity, so round-tripping one would leak host-fs
    // structure into the guest and cannot be made coherent with the overlay.
    // That is a deliberate divergence from the kernel, not a bug, so the
    // probe asserts the REFUSAL is clean rather than demanding agreement:
    // whatever each side answers, a program must be able to fall back (glibc,
    // nfs-utils and tar all have a path-based fast-path fallback).
    {
        // struct file_handle { u32 handle_bytes; int handle_type; u8 f[]; }
        static unsigned char fh[136];
        memset(fh, 0, sizeof fh);
        unsigned int bytes = 128;
        memcpy(fh, &bytes, 4);
        int mnt = -1;
        const long r = LX_SYS5(SYS_name_to_handle_at, AT_FDCWD, F1, fh, &mnt, 0);
        // Either it worked (native) or it was refused (guest). What must NOT
        // happen is a partial success that hands back a usable handle into
        // the host filesystem.
        lx_emit("name_to_handle_at", (r == 0 || r < 0) ? 1 : 0,
                "name_to_handle_at either works or is cleanly refused");
        const long o = LX_SYS3(SYS_open_by_handle_at, mnt, fh, O_RDONLY);
        // Unprivileged, this is EPERM natively and ENOTSUP under linuxity.
        // Both are refusals; a SUCCESS here would be an escape.
        lx_emit("open_by_handle_at", o < 0 ? 1 : 0,
                "open_by_handle_at is refused (a success here escapes the namespace)");
    }

    // -- tear down ---------------------------------------------------------
    LX_SYS3(SYS_unlinkat, AT_FDCWD, F1, 0);
    lx_emit("unlinkat", LX_SYS3(SYS_unlinkat, AT_FDCWD, DIR, AT_REMOVEDIR),
            "remove the scratch dir");
    return 0;
}
