// tests/probes/procid.c
//
// Process identity and the /proc views of it: getpid/getppid/getuid/getgid,
// the resource limits, and the procfs files a guest actually reads.
//
// linuxity SYNTHESIZES most of this -- it runs the guest as a fake pid 1 in
// its own pid namespace with root-looking credentials, and builds /proc out of
// its own process table rather than the host's. So almost nothing here is
// forwarded, which makes it the opposite of rwio: high interception, high risk.
//
// WHAT CANNOT BE COMPARED. The pid itself legitimately differs (the guest is
// pid 1, the native run is whatever the shell gave it) and the law exempts
// getpid/gettid/getppid for exactly that reason. So this probe asserts
// INVARIANTS and RELATIONSHIPS instead of values: a pid is positive, getpid
// agrees with /proc/self, the uid matches what /proc/self/status says.
#include "probe.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

// Read a whole small file. Returns the byte count, or the negative errno.
static long slurp(const char* path, char* buf, long cap) {
    const long fd = LX_SYS3(SYS_openat, AT_FDCWD, path, O_RDONLY);
    if (fd < 0) return fd;
    long total = 0;
    for (;;) {
        const long n = LX_SYS3(SYS_read, fd, buf + total, cap - 1 - total);
        if (n <= 0) break;
        total += n;
        if (total >= cap - 1) break;
    }
    buf[total > 0 ? total : 0] = 0;
    LX_SYS1(SYS_close, fd);
    return total;
}

// Pull the first integer following `key` out of a procfs text file.
static long field(const char* text, const char* key) {
    const char* p = strstr(text, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p == ' ' || *p == '\t' || *p == ':') ++p;
    return atol(p);
}

int main(void) {
    static char buf[8192];

    // -- the ids, as invariants rather than values ------------------------
    const long pid = LX_SYS0(SYS_getpid);
    lx_emit("getpid", pid > 0 ? 1 : pid, "a pid is positive");

    const long tid = LX_SYS0(SYS_gettid);
    lx_emit("gettid", tid > 0 ? 1 : tid, "a tid is positive");

    // Single-threaded: the tid must equal the pid.
    lx_emit("gettid", tid == pid ? 1 : 0, "tid == pid in a single thread");

    const long ppid = LX_SYS0(SYS_getppid);
    lx_emit("getppid", ppid >= 0 ? 1 : ppid, "a ppid is non-negative");

    // A process is never its own parent.
    lx_emit("getppid", ppid != pid ? 1 : 0, "ppid differs from pid");

    // -- credentials -------------------------------------------------------
    // These ARE compared by value: linuxity presents root, and so does a
    // native run under this harness only if it happens to be root. Report
    // the RELATIONSHIPS so the probe is meaningful either way.
    const long uid  = LX_SYS0(SYS_getuid);
    const long euid = LX_SYS0(SYS_geteuid);
    const long gid  = LX_SYS0(SYS_getgid);
    const long egid = LX_SYS0(SYS_getegid);
    lx_emit("getuid",  uid  >= 0 ? 1 : uid,  "uid is valid");
    lx_emit("geteuid", euid == uid ? 1 : 0,  "euid == uid (no setuid here)");
    lx_emit("getgid",  gid  >= 0 ? 1 : gid,  "gid is valid");
    lx_emit("getegid", egid == gid ? 1 : 0,  "egid == gid");

    // -- /proc/self agrees with the syscalls -------------------------------
    // THE cross-check: procfs is synthesized, the syscalls are synthesized,
    // and the two must tell the same story. A guest that sees getpid()==1 but
    // /proc/self/status saying otherwise breaks every process manager.
    {
        const long n = slurp("/proc/self/status", buf, sizeof buf);
        lx_emit("openat", n > 0 ? 1 : n, "read /proc/self/status");
        if (n > 0) {
            lx_emit("read", field(buf, "Pid:") == pid ? 1 : 0,
                    "status Pid: matches getpid()");
            lx_emit("read", field(buf, "PPid:") == ppid ? 1 : 0,
                    "status PPid: matches getppid()");
            // Name: must be non-empty and must not contain a newline.
            lx_emit("read", strstr(buf, "Name:") != 0 ? 1 : 0,
                    "status has a Name: field");
            lx_emit("read", strstr(buf, "Uid:") != 0 ? 1 : 0,
                    "status has a Uid: field");
            lx_emit("read", strstr(buf, "Threads:") != 0 ? 1 : 0,
                    "status has a Threads: field");
        }
    }

    // /proc/self/stat is one space-separated line; field 1 is the pid and
    // field 2 is "(comm)". Parsers are strict about this layout.
    {
        const long n = slurp("/proc/self/stat", buf, sizeof buf);
        lx_emit("openat", n > 0 ? 1 : n, "read /proc/self/stat");
        if (n > 0) {
            lx_emit("read", atol(buf) == pid ? 1 : 0, "stat field 1 is the pid");
            lx_emit("read", strchr(buf, '(') && strchr(buf, ')') ? 1 : 0,
                    "stat field 2 is (comm)");
            // The line must end in a newline -- ps cares.
            lx_emit("read", buf[n - 1] == '\n' ? 1 : 0, "stat ends with a newline");
        }
    }

    // /proc/self/cmdline is NUL-separated and must name this probe.
    {
        const long n = slurp("/proc/self/cmdline", buf, sizeof buf);
        lx_emit("openat", n > 0 ? 1 : n, "read /proc/self/cmdline");
        if (n > 0)
            lx_emit("read", strstr(buf, "procid") != 0 ? 1 : 0,
                    "cmdline names this probe");
    }

    // -- the procfs files every tool reads --------------------------------
    {
        const long u = slurp("/proc/uptime", buf, sizeof buf);
        lx_emit("openat", u > 0 ? 1 : u, "read /proc/uptime");
        // Two space-separated numbers. The VALUES vary, the shape must not.
        if (u > 0) lx_emit("read", strchr(buf, ' ') != 0 ? 1 : 0,
                           "uptime has two fields");

        const long m = slurp("/proc/meminfo", buf, sizeof buf);
        lx_emit("openat", m > 0 ? 1 : m, "read /proc/meminfo");
        if (m > 0) lx_emit("read", strstr(buf, "MemTotal:") != 0 ? 1 : 0,
                           "meminfo has MemTotal:");

        const long s = slurp("/proc/stat", buf, sizeof buf);
        lx_emit("openat", s > 0 ? 1 : s, "read /proc/stat");
        if (s > 0) lx_emit("read", strstr(buf, "cpu") != 0 ? 1 : 0,
                           "stat has a cpu line");

        const long c = slurp("/proc/cpuinfo", buf, sizeof buf);
        lx_emit("openat", c > 0 ? 1 : c, "read /proc/cpuinfo");

        const long v = slurp("/proc/version", buf, sizeof buf);
        lx_emit("openat", v > 0 ? 1 : v, "read /proc/version");
        if (v > 0) lx_emit("read", strstr(buf, "Linux") != 0 ? 1 : 0,
                           "version says Linux");
    }

    // -- uname -------------------------------------------------------------
    {
        // struct utsname is 6 x 65 bytes on Linux.
        static char uts[390];
        const long r = LX_SYS1(SYS_uname, uts);
        lx_emit("uname", r, "uname succeeds");
        if (r == 0) {
            lx_emit("uname", strcmp(uts, "Linux") == 0 ? 1 : 0,
                    "sysname is exactly Linux");
            lx_emit("uname", uts[65] != 0 ? 1 : 0, "nodename is non-empty");
            lx_emit("uname", uts[130] != 0 ? 1 : 0, "release is non-empty");
        }
    }

    // -- resource limits ---------------------------------------------------
    {
        // struct rlimit { unsigned long cur, max; }
        unsigned long rl[2] = {0, 0};
        const long r = LX_SYS4(SYS_prlimit64, 0, 7 /*RLIMIT_NOFILE*/, 0, rl);
        lx_emit("prlimit64", r, "prlimit64 RLIMIT_NOFILE");
        if (r == 0) {
            lx_emit("prlimit64", rl[0] > 0 ? 1 : 0, "NOFILE soft limit is positive");
            lx_emit("prlimit64", rl[1] >= rl[0] ? 1 : 0, "hard >= soft");
        }
        // A bogus resource number is EINVAL.
        lx_emit("prlimit64", LX_SYS4(SYS_prlimit64, 0, 9999, 0, rl),
                "a bogus rlimit resource is EINVAL");
    }

    // -- sched_getaffinity -------------------------------------------------
    {
        unsigned long mask[16] = {0};
        const long r = LX_SYS3(SYS_sched_getaffinity, 0, sizeof mask, mask);
        lx_emit("sched_getaffinity", r > 0 ? 1 : r, "affinity returns a size");
        lx_emit("sched_getaffinity", mask[0] != 0 ? 1 : 0,
                "at least one cpu is in the mask");
        // A zero-sized mask is EINVAL.
        lx_emit("sched_getaffinity", LX_SYS3(SYS_sched_getaffinity, 0, 0, mask),
                "a zero-size affinity mask is EINVAL");
    }

    // -- the error boundaries ---------------------------------------------
    // Signal 0 to ourselves is the standard liveness probe, and must succeed.
    lx_emit("kill", LX_SYS2(SYS_kill, pid, 0), "kill(self, 0) succeeds");
    // A bogus signal number is EINVAL.
    lx_emit("kill", LX_SYS2(SYS_kill, pid, 9999), "a bogus signal is EINVAL");
    // A pid that cannot exist is ESRCH.
    lx_emit("kill", LX_SYS2(SYS_kill, 0x3fffffff, 0), "an absent pid is ESRCH");

    return 0;
}
