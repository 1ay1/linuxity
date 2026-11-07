// namespaces.c -- unshare/setns/sethostname/setdomainname.
//
// Natively an unprivileged probe can only make user namespaces (and on
// Android not even those); the guest is root, so linuxity serves them all.
// Every refusal is EPERM/EINVAL from host policy, which the law exempts; the
// shape of the trace is the same everywhere.
#define _GNU_SOURCE
#include "probe.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef SIGCHLD
#define SIGCHLD 17
#endif

int main(void) {
    // in a forked child: joining a namespace can't be undone
    fflush(stdout);
#ifdef SYS_fork
    long pid = LX_SYS0(SYS_fork);
#else
    long pid = LX_SYS5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
    if (pid == 0) {
        const long u = LX_SYS1(SYS_unshare, CLONE_NEWUTS);
        lx_emit("unshare", u, "unshare a UTS namespace");
        const long h = LX_SYS2(SYS_sethostname, "lx-ns-probe", 11);
        lx_emit("sethostname", h, "set its hostname");
        const long d = LX_SYS2(SYS_setdomainname, "lx-dom", 6);
        lx_emit("setdomainname", d, "set its domainname");
        static char uts[390];
        const long n = LX_SYS1(SYS_uname, uts);
        lx_emit("sethostname", (n == 0 && h == 0) ? (strcmp(uts + 65, "lx-ns-probe") == 0) : 2,
                "uname reports the new hostname");
        lx_emit("sethostname", LX_SYS2(SYS_sethostname, "x", 65), "a 65-byte name is EINVAL");
        // setns back into our parent's UTS namespace: open its ns link
        static char path[64];
        snprintf(path, sizeof path, "/proc/%ld/ns/uts", (long)LX_SYS0(SYS_getppid));
        const long fd = LX_SYS4(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
        const long s = fd >= 0 ? LX_SYS2(SYS_setns, fd, CLONE_NEWUTS) : fd;
        lx_emit("setns", s, "setns back into the parent's UTS namespace");
        lx_emit("setns", fd >= 0 ? LX_SYS2(SYS_setns, fd, CLONE_NEWUSER) : 2,
                "setns with the wrong type is EINVAL");
        lx_emit("setns", LX_SYS2(SYS_setns, 9999, 0), "setns on a bad fd is EBADF");
        fflush(stdout);
        LX_SYS1(SYS_exit_group, 0);
    }
    int st = 0;
    LX_SYS4(SYS_wait4, pid, &st, 0, 0);
    return 0;
}
