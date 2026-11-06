// tests/probes/probe.h
//
// The probe-side harness: emit one trace line per syscall, in the format
// conform/trace_text.hpp parses.
//
// A probe is a tiny FREESTANDING program. It is run twice -- natively and
// under linuxity -- and the two outputs are compared, so it must obey three
// rules or it reports differences that are not linuxity's fault:
//
//   1. Make raw syscalls, not libc calls. glibc caches (telldir), retries
//      (EINTR), and emulates (open -> openat on aarch64), so a libc call does
//      not observe the kernel, it observes glibc's opinion of the kernel.
//   2. Emit NOTHING that varies between two runs of the same program: no
//      pids, no timestamps, no addresses, no inode numbers. Those legitimately
//      differ and belong in the law's exemptions, not in a trace.
//   3. Never fail silently. A probe that dies mid-way must exit non-zero so
//      the oracle reports probe_failed instead of judging a truncated trace.
//
// Written in C against raw syscall() so it has no C++ runtime and no
// allocation -- a probe must behave identically under linuxity and natively,
// and the less machinery it carries the fewer things can differ.
#ifndef LX_PROBE_H
#define LX_PROBE_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// errno -> the name the trace format uses. Must agree with the renderer in
// conform/report.hpp; the round-trip test is what keeps them honest.
static const char* lx_errno_name(int e) {
    switch (e) {
        case EPERM:   return "EPERM";
        case ENOENT:  return "ENOENT";
        case EBADF:   return "EBADF";
        case EACCES:  return "EACCES";
        case EEXIST:  return "EEXIST";
        case ENOTDIR: return "ENOTDIR";
        case EISDIR:  return "EISDIR";
        case EINVAL:  return "EINVAL";
        case ENOSYS:  return "ENOSYS";
        case ERANGE:  return "ERANGE";
        case ESPIPE:  return "ESPIPE";
        case ELOOP:   return "ELOOP";
        case ENOTTY:  return "ENOTTY";
        case ESRCH:   return "ESRCH";
        case ENODATA: return "ENODATA";
        case EOPNOTSUPP: return "EOPNOTSUPP";
        case EFAULT:  return "EFAULT";
        case ECHILD:  return "ECHILD";
        case EXDEV:   return "EXDEV";
        default:      return 0;
    }
}

// Emit one observation. `ret` is the raw syscall return: negative small
// magnitude is -errno, exactly as the kernel encodes it, so the probe does no
// interpretation of its own.
static void lx_emit(const char* call, long ret, const char* note) {
    if (ret < 0 && ret >= -4095) {
        const char* n = lx_errno_name((int)-ret);
        if (n) printf("%s = -%s", call, n);
        else   printf("%s = -errno(%d)", call, (int)-ret);
    } else {
        printf("%s = %ld", call, ret);
    }
    if (note && *note) printf(" | %s", note);
    printf("\n");
}

// Emit an observation plus a buffer the call wrote. Hex, lossless, so a
// golden reproduces the bytes exactly.
static void lx_emit_buf(const char* call, long ret, int arg,
                        const void* buf, size_t len, const char* note) {
    if (ret < 0 && ret >= -4095) {
        const char* n = lx_errno_name((int)-ret);
        if (n) printf("%s = -%s", call, n);
        else   printf("%s = -errno(%d)", call, (int)-ret);
    } else {
        printf("%s = %ld", call, ret);
    }
    printf(" @%d:", arg);
    const unsigned char* p = (const unsigned char*)buf;
    for (size_t i = 0; i < len; ++i) printf("%02x", p[i]);
    if (note && *note) printf(" | %s", note);
    printf("\n");
}

// A raw syscall, returning the kernel's encoding rather than libc's -1/errno.
// This is the only way the probe talks to the kernel.
static long lx_sys(long nr, long a, long b, long c, long d, long e, long f) {
    errno = 0;
    const long r = syscall(nr, a, b, c, d, e, f);
    return r < 0 ? -errno : r;
}

#define LX_SYS0(nr)                lx_sys((nr), 0, 0, 0, 0, 0, 0)
#define LX_SYS1(nr, a)             lx_sys((nr), (long)(a), 0, 0, 0, 0, 0)
#define LX_SYS2(nr, a, b)          lx_sys((nr), (long)(a), (long)(b), 0, 0, 0, 0)
#define LX_SYS3(nr, a, b, c)       lx_sys((nr), (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define LX_SYS4(nr, a, b, c, d)    lx_sys((nr), (long)(a), (long)(b), (long)(c), (long)(d), 0, 0)
#define LX_SYS5(nr, a, b, c, d, e) lx_sys((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), 0)
// mmap is the one call that genuinely needs all six.
#define LX_SYS6(nr, a, b, c, d, e, f) lx_sys((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

#endif // LX_PROBE_H
