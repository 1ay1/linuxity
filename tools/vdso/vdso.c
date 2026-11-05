// tools/vdso/vdso.c -- the linuxity vDSO (aarch64).
//
// Linux maps a tiny shared object into every process (AT_SYSINFO_EHDR) so
// clock_gettime/gettimeofday never enter the kernel. Under linuxity a
// syscall is a VM EXIT (~1 us); the vDSO turns the hottest one into a few
// instructions (~20 ns): read the virtual counter CNTVCT_EL0 (EL0-readable,
// CNTKCTL_EL1.EL0VCTEN) and convert with a data page the host fills in.
//
// glibc looks these symbols up by NAME + VERSION (LINUX_2.6.39) at startup
// and calls them instead of svc whenever they are present. Clocks we can't
// compute here fall back to the real syscall, exactly like the kernel vDSO.
//
// Build: clang --target=aarch64-linux-gnu -O2 -fPIC -nostdlib -shared
//        -Wl,--version-script=vdso.lds -Wl,--hash-style=both -o vdso.so
// No libc, no relocations, no data writes: everything is position-
// independent and the data page is found PC-relatively (it sits one page
// BELOW the text, as on Linux's [vvar]).
#include <stdint.h>

struct timespec64 { int64_t tv_sec; int64_t tv_nsec; };
struct timeval64  { int64_t tv_sec; int64_t tv_usec; };

// Written by linuxity once at exec. CNTVCT is a single host-wide counter
// (it ticks through sleep on Apple Silicon), so the mapping is fixed.
struct vdso_data {
    uint64_t magic;           // "LXVDSO01"
    uint64_t cnt_freq;        // CNTFRQ_EL0, Hz
    // mono_ns = (cnt - cnt_base) * mult >> shift + mono_base_ns
    uint64_t cnt_base;
    uint64_t mult;
    uint32_t shift;
    uint32_t pad;
    int64_t  mono_base_ns;    // CLOCK_MONOTONIC at cnt_base
    int64_t  real_offset_ns;  // CLOCK_REALTIME - CLOCK_MONOTONIC
    int64_t  boot_offset_ns;  // CLOCK_BOOTTIME  - CLOCK_MONOTONIC
};

extern const struct vdso_data __lx_vdso_data __attribute__((visibility("hidden")));

static inline uint64_t cntvct(void) {
    uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
}

static inline long sys_clock_gettime(long clk, struct timespec64* ts) {
    register long x0 __asm__("x0") = clk;
    register long x1 __asm__("x1") = (long)ts;
    register long x8 __asm__("x8") = 113;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}
static inline long sys_gettimeofday(struct timeval64* tv, void* tz) {
    register long x0 __asm__("x0") = (long)tv;
    register long x1 __asm__("x1") = (long)tz;
    register long x8 __asm__("x8") = 169;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}
static inline long sys_clock_getres(long clk, struct timespec64* ts) {
    register long x0 __asm__("x0") = clk;
    register long x1 __asm__("x1") = (long)ts;
    register long x8 __asm__("x8") = 114;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x8) : "memory");
    return x0;
}

static inline int64_t mono_ns(const struct vdso_data* d) {
    const uint64_t delta = cntvct() - d->cnt_base;
    const unsigned __int128 p = (unsigned __int128)delta * d->mult;
    return d->mono_base_ns + (int64_t)(p >> d->shift);
}

// Linux clock ids.
enum { REALTIME = 0, MONOTONIC = 1, MONOTONIC_RAW = 4, REALTIME_COARSE = 5,
       MONOTONIC_COARSE = 6, BOOTTIME = 7 };

int __kernel_clock_gettime(long clk, struct timespec64* ts) {
    const struct vdso_data* d = &__lx_vdso_data;
    if (d->magic != 0x31304f5344564c58ull || !ts)   // "LXVDSO01"
        return (int)sys_clock_gettime(clk, ts);
    int64_t ns;
    switch (clk) {
        case MONOTONIC: case MONOTONIC_RAW: case MONOTONIC_COARSE:
            ns = mono_ns(d); break;
        case REALTIME: case REALTIME_COARSE:
            ns = mono_ns(d) + d->real_offset_ns; break;
        case BOOTTIME:
            ns = mono_ns(d) + d->boot_offset_ns; break;
        default:
            return (int)sys_clock_gettime(clk, ts);
    }
    ts->tv_sec  = ns / 1000000000;
    ts->tv_nsec = ns % 1000000000;
    return 0;
}

int __kernel_gettimeofday(struct timeval64* tv, void* tz) {
    const struct vdso_data* d = &__lx_vdso_data;
    if (d->magic != 0x31304f5344564c58ull || tz)
        return (int)sys_gettimeofday(tv, tz);
    if (tv) {
        const int64_t ns = mono_ns(d) + d->real_offset_ns;
        tv->tv_sec  = ns / 1000000000;
        tv->tv_usec = (ns % 1000000000) / 1000;
    }
    return 0;
}

int __kernel_clock_getres(long clk, struct timespec64* ts) {
    switch (clk) {
        case REALTIME: case MONOTONIC: case MONOTONIC_RAW: case BOOTTIME:
            if (ts) { ts->tv_sec = 0; ts->tv_nsec = 1; }
            return 0;
        default:
            return (int)sys_clock_getres(clk, ts);
    }
}

// rt_sigreturn trampoline the kernel vDSO also exports (glibc doesn't need
// it -- it brings its own restorer -- but unwinders look it up by name).
__asm__(".globl __kernel_rt_sigreturn\n"
        ".type __kernel_rt_sigreturn,%function\n"
        "__kernel_rt_sigreturn:\n"
        "  mov x8, #139\n"
        "  svc #0\n");
