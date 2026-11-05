// linuxity/runtime/hvf_vdso.hpp
//
// The vDSO: clock_gettime/gettimeofday without a VM exit.
//
// Every guest syscall under linuxity is a full VM exit (~1 us on M-series)
// -- 50x a native clock read. Programs read clocks constantly (Python's
// time.time, every log line's timestamp, event loops computing timeouts,
// glibc's own timer bookkeeping), so the Linux trick applies verbatim: map a
// tiny shared object (built from tools/vdso/vdso.c, embedded as
// hvf_vdso_blob.hpp) and announce it with AT_SYSINFO_EHDR. glibc resolves
// __kernel_clock_gettime from it at startup and never traps for the clock
// again.
//
// The vDSO reads CNTVCT_EL0 (made EL0-readable via CNTKCTL_EL1 when the
// vCPU is created) and converts ticks with a data page we fill once per
// exec: on Apple Silicon CNTVCT is the host's mach_absolute_time base,
// identical in every process and every vCPU, so the conversion never needs
// updating -- the realtime offset is sampled once, like a fresh boot.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/runtime/hvf_vdso_blob.hpp"
#include "linuxity/runtime/hvf_vm.hpp"

#include <mach/mach_time.h>

#include <cstdint>
#include <cstring>
#include <ctime>

namespace lx::runtime::vdso {

// Must match struct vdso_data in tools/vdso/vdso.c.
struct Data {
    std::uint64_t magic;
    std::uint64_t cnt_freq;
    std::uint64_t cnt_base;
    std::uint64_t mult;
    std::uint32_t shift;
    std::uint32_t pad;
    std::int64_t  mono_base_ns;
    std::int64_t  real_offset_ns;
    std::int64_t  boot_offset_ns;
};
inline constexpr std::uint64_t kMagic = 0x31304f5344564c58ull;   // "LXVDSO01"

// Where it lives: in the 1 MiB headroom between the mmap arena's top and the
// stack reservation (see ExecArena::mmap_top), so neither ever reaches it.
// Two pages: [data][image...].
[[nodiscard]] inline std::uint64_t base_for(std::uint64_t mem_size) noexcept {
    return ExecArena::mmap_top(mem_size) + 0x10000;
}
[[nodiscard]] inline std::uint64_t span() noexcept {
    return 0x1000 + ((kImageSize + 0xfff) & ~std::uint64_t{0xfff});
}

[[nodiscard]] inline std::uint64_t read_cntvct() noexcept {
    std::uint64_t v;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
}

inline void refresh(HvfMachine& vm);

// Write data page + image into guest RAM. Returns AT_SYSINFO_EHDR (the ELF
// header's guest address), or 0 if there is no room (the guest then simply
// uses syscalls, which is always correct).
[[nodiscard]] inline std::uint64_t install(HvfMachine& vm) {
    const std::uint64_t base = base_for(vm.mem_size());
    auto win = vm.ram().at(base, span());
    if (win.empty()) return 0;
    std::memset(win.data(), 0, win.size());
    std::memcpy(win.data() + 0x1000, kImage, kImageSize);
    vm.publish_code(base + 0x1000, kImageSize);
    refresh(vm);
    return base + 0x1000;
}
// (Re)compute the data page against THIS VM's counter. Called at exec and
// in every fork child (new VM, counter restarts). Harmless if the guest has
// no vDSO mapped: the page is ours.
inline void refresh(HvfMachine& vm) {
    const std::uint64_t base = base_for(vm.mem_size());
    auto win = vm.ram().at(base, 0x1000);
    if (win.empty()) return;
    Data d{};
    d.magic = kMagic;
    std::uint64_t frq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frq));
    d.cnt_freq = frq ? frq : 24000000;
    // ns = ticks * mult >> shift, with mult = 1e9 << shift / freq. shift=24
    // keeps mult < 2^32 for any freq >= 1 Hz... well above 24 MHz, and the
    // 128-bit product in the vDSO never overflows.
    d.shift = 24;
    d.mult  = (1000000000ull << d.shift) / d.cnt_freq;

    // Sample host clocks against the SAME counter (guest CNTVCT ==
    // mach_absolute_time, the vtimer offset is 0), so guest MONOTONIC agrees
    // with host CLOCK_MONOTONIC (what the trap path and timerfds use) and
    // REALTIME with the wall clock. mach_absolute_time stops during sleep
    // while Darwin MONOTONIC does not: re-sampling on every exec bounds that
    // drift to one process's lifetime across a sleep, the same contract
    // CLOCK_MONOTONIC_RAW-style counters give.
    timespec mono{}, real{};
    ::clock_gettime(CLOCK_MONOTONIC, &mono);
    const std::uint64_t c = ::mach_absolute_time();
    ::clock_gettime(CLOCK_REALTIME, &real);
    const std::int64_t mono_ns = mono.tv_sec * 1000000000ll + mono.tv_nsec;
    const std::int64_t real_ns = real.tv_sec * 1000000000ll + real.tv_nsec;
    d.cnt_base = c;
    d.mono_base_ns = mono_ns;
    d.real_offset_ns = real_ns - mono_ns;
    d.boot_offset_ns = 0;   // Darwin MONOTONIC already counts across sleep

    std::memcpy(win.data(), &d, sizeof d);
}

}  // namespace lx::runtime::vdso

#endif  // __APPLE__ && __aarch64__
