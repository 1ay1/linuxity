// linuxity/conform/arch.hpp
//
// The GUEST ABI axis, which is orthogonal to the host axis.
//
// Two different questions were easy to conflate, and conflating them is how a
// Linux arm64 CI job would silently corrupt the x86-64 goldens:
//
//   HOST  -- who services the syscall? (probe_runner.hpp / host.hpp)
//            Linux and macOS share one POSIX runner; Windows has its own.
//   ARCH  -- which Linux ABI is the guest speaking? (this file)
//            x86-64 and aarch64 are NOT interchangeable.
//
// They are independent: a macOS arm64 host replays an aarch64 golden, while a
// Linux x86-64 host records an x86-64 one. Four hosts, two ABIs, and the
// product is not a 2x2 of code -- it is one runner choice and one arch tag.
//
// WHY THE ABIs CANNOT SHARE A GOLDEN. 56 syscalls exist on x86-64 and not on
// aarch64: open, fork, vfork, stat, lstat, arch_prctl and more. aarch64 has
// only openat, clone, newfstatat. So a trace recorded on x86-64 contains calls
// that can never occur on aarch64, and judging one against the other reports
// divergences that are really just ABI differences -- or worse, masks a real
// one. The arch is therefore part of a golden's IDENTITY (its path), never
// metadata inside it.
#pragma once

#include <string_view>

#include "linuxity/abi/sysno.hpp"

namespace lx::conform {

// The ABI this build targets. One place, derived from the compiler's own
// target macros, so adding a Linux arm64 job needs no new code -- it compiles
// to aarch64 here and everything downstream follows.
[[nodiscard]] constexpr abi::Arch host_arch() noexcept {
#if defined(__aarch64__) || defined(_M_ARM64)
    return abi::Arch::aarch64;
#else
    return abi::Arch::x86_64;
#endif
}

// Stable, filesystem-safe names. Used in golden paths, so changing one
// invalidates every recording for that ABI -- which is the correct behaviour
// if the meaning ever changed, and a reason not to churn them casually.
[[nodiscard]] constexpr std::string_view arch_name(abi::Arch a) noexcept {
    switch (a) {
        case abi::Arch::x86_64:  return "x86_64";
        case abi::Arch::aarch64: return "aarch64";
    }
    return "unknown-arch";
}

// Does this ABI have the syscall at all? A golden for one arch naming a
// syscall the other lacks is an ABI difference, not a divergence, and this is
// how the oracles tell those apart.
[[nodiscard]] constexpr bool arch_has(abi::Arch a, abi::Sysno s) noexcept {
    if (s == abi::Sysno::unknown) return false;
    // decode() is the SSOT for the number<->Sysno mapping, so membership is
    // derived from it rather than from a second hand-written list.
    for (std::uint64_t nr = 0; nr < 600; ++nr)
        if (abi::decode(a, nr) == s) return true;
    return false;
}

static_assert(arch_name(host_arch()).size() > 0);

// The ABI differences that motivated all of this, asserted so a table edit
// that erased them would fail the build rather than silently make goldens
// interchangeable.
static_assert(arch_has(abi::Arch::x86_64, abi::Sysno::open),
              "x86-64 has open");
static_assert(!arch_has(abi::Arch::aarch64, abi::Sysno::open),
              "aarch64 has openat only -- goldens are not interchangeable");
static_assert(arch_has(abi::Arch::aarch64, abi::Sysno::openat),
              "aarch64 has openat");
static_assert(arch_has(abi::Arch::x86_64, abi::Sysno::fork) &&
                  !arch_has(abi::Arch::aarch64, abi::Sysno::fork),
              "fork is x86-64 only; aarch64 uses clone");

// lseek and getdents64 exist on BOTH, which is why the dirseek scenarios are
// valid on either ABI and the cookie regression is checkable everywhere.
static_assert(arch_has(abi::Arch::x86_64, abi::Sysno::lseek) &&
                  arch_has(abi::Arch::aarch64, abi::Sysno::lseek));
static_assert(arch_has(abi::Arch::x86_64, abi::Sysno::getdents64) &&
                  arch_has(abi::Arch::aarch64, abi::Sysno::getdents64));

} // namespace lx::conform
