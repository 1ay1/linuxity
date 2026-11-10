// tests/bench_syscall.c
//
// What does linuxity's interception actually cost?
//
// The claim on the box is "native CPU speed": guest instructions run bare on
// the host, no VM, no interpreter. That is true and it is the important
// half. But a syscall linuxity INTERCEPTS does not run bare -- it stops the
// tracee, the supervisor decides, and it resumes. Two context switches that
// a native call does not pay.
//
// Nothing measured that. The conformance suite proves every answer is
// RIGHT; it says nothing about what the answer costs, so a change that made
// a hot path ten times slower would pass all 55 tests. This measures the
// three cases that matter and reports them separately, because they are
// wildly different numbers and an average across them is meaningless:
//
//   FORWARDED  -- the kernel runs it (read/write on a real fd). One stop or
//                 none, depending on the seccomp filter.
//   VIRTUAL    -- linuxity answers from its own state (getpid, uname). The
//                 syscall never reaches the kernel at all.
//   REDIRECTED -- a path is translated and the kernel runs the rewritten
//                 call (openat). The most expensive shape: read the guest's
//                 memory, resolve through the namespace, poke a new path
//                 back, then forward.
//
// Run it natively and under linuxity and compare. The ratio is the honest
// number, not the absolute, since it cancels the machine out.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/utsname.h>

static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

// Report ns/call rather than total: the iteration count is tuning, not
// something a reader should have to divide by.
static void report(const char* what, const char* kind, uint64_t ns, long n) {
    printf("  %-22s %-11s %8.0f ns/call  (%ld calls)\n",
           what, kind, (double)ns / (double)n, n);
}

int main(int argc, char** argv) {
    long n = (argc > 1) ? atol(argv[1]) : 200000;
    if (n < 1000) n = 1000;

    printf("bench_syscall: %ld iterations per case\n", n);

    // -- VIRTUAL: answered entirely by linuxity, never reaches the kernel --
    {
        uint64_t t0 = now_ns();
        for (long i = 0; i < n; ++i) (void)syscall(SYS_getpid);
        report("getpid", "VIRTUAL", now_ns() - t0, n);
    }
    {
        struct utsname u;
        uint64_t t0 = now_ns();
        for (long i = 0; i < n; ++i) (void)syscall(SYS_uname, &u);
        report("uname", "VIRTUAL", now_ns() - t0, n);
    }

    // -- FORWARDED: a real fd, the kernel does the work -------------------
    {
        int fd = open("/dev/null", O_WRONLY);
        if (fd < 0) { perror("open /dev/null"); return 1; }
        char b = 'x';
        uint64_t t0 = now_ns();
        for (long i = 0; i < n; ++i) (void)syscall(SYS_write, fd, &b, 1);
        report("write(/dev/null)", "FORWARDED", now_ns() - t0, n);
        close(fd);
    }
    {
        int fd = open("/dev/zero", O_RDONLY);
        if (fd < 0) { perror("open /dev/zero"); return 1; }
        char b[64];
        uint64_t t0 = now_ns();
        for (long i = 0; i < n; ++i) (void)syscall(SYS_read, fd, b, sizeof b);
        report("read(/dev/zero)", "FORWARDED", now_ns() - t0, n);
        close(fd);
    }
    {
        // lseek on a real fd: forwarded, but linuxity tracks dir streams, so
        // it is the cheap end of "has bookkeeping".
        int fd = open("/dev/zero", O_RDONLY);
        uint64_t t0 = now_ns();
        for (long i = 0; i < n; ++i) (void)syscall(SYS_lseek, fd, 0, SEEK_SET);
        report("lseek", "FORWARDED", now_ns() - t0, n);
        close(fd);
    }

    // -- REDIRECTED: path translation, the expensive shape ----------------
    {
        // openat of an absolute path: resolve through the namespace, poke
        // the host path into the guest, forward. Closing is part of the
        // cost of the loop but is itself cheap.
        uint64_t t0 = now_ns();
        for (long i = 0; i < n / 10; ++i) {
            long fd = syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDONLY, 0);
            if (fd >= 0) syscall(SYS_close, fd);
        }
        report("openat+close", "REDIRECTED", now_ns() - t0, n / 10);
    }
    {
        // stat: a path in, a struct out. linuxity answers it
        // in ONE stop rather than forwarding.
        struct stat st;
        uint64_t t0 = now_ns();
        for (long i = 0; i < n / 10; ++i)
            (void)syscall(SYS_newfstatat, AT_FDCWD, "/dev/null", &st, 0);
        report("newfstatat", "REDIRECTED", now_ns() - t0, n / 10);
    }

    // -- a NON-syscall baseline -------------------------------------------
    // Pure userspace work, to show that guest instructions really do run at
    // native speed: this number must be the SAME under linuxity, and if it
    // is not then something is wrong with the claim itself.
    {
        volatile uint64_t acc = 0;
        uint64_t t0 = now_ns();
        for (long i = 0; i < n * 20; ++i) acc += (uint64_t)i * 2654435761u;
        report("userspace loop", "NATIVE", now_ns() - t0, n * 20);
    }
    return 0;
}
