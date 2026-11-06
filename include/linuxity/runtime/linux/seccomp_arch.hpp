// SPDX-License-Identifier: LGPL-2.0-or-later
//
// The per-arch facts the seccomp filter needs, in one place.
//
// The trapped SET is defined once, as x86-64 numbers, in seccomp_filter.hpp
// (kTrappedX86_64) -- that list is a security boundary and
// tools/check_syscall_coverage.sh reads it to prove every path-bearing
// syscall the dispatcher handles is actually trapped.
//
// A second hand-written list of aarch64 numbers would be a second source of
// truth for the same set, and the two would drift exactly the way the trap
// list and the dispatcher already drifted three times (lseek, fchmodat2,
// creat -- two of them sandbox escapes). So aarch64's numbers are DERIVED
// from the x86-64 list at compile time: map each number to its Sysno through
// abi::decode, then search the target arch's table for the number that
// decodes to the same Sysno. sysno.hpp stays the only syscall-numbering
// authority, and adding a syscall to the trap list covers both arches.
#ifndef LX_RUNTIME_LINUX_SECCOMP_ARCH_HPP
#define LX_RUNTIME_LINUX_SECCOMP_ARCH_HPP

#include <array>
#include <cstdint>

#include <linux/audit.h>

#include "linuxity/abi/sysno.hpp"
#include "linuxity/conform/arch.hpp"

namespace lx::runtime {

// The AUDIT_ARCH the filter must see. A mismatch here is invisible in
// testing and catastrophic in production: the arch check fails for EVERY
// syscall, the guest gets ENOSYS on all of them, and it spins forever
// instead of being traced.
[[nodiscard]] constexpr std::uint32_t seccomp_audit_arch(abi::Arch a) noexcept {
    return a == abi::Arch::aarch64 ? AUDIT_ARCH_AARCH64 : AUDIT_ARCH_X86_64;
}

// x32 shares AUDIT_ARCH_X86_64 and sets bit 30 of nr, so an x32 call would
// otherwise reach a handler expecting 64-bit layouts. aarch64 has no such
// personality (its 32-bit sibling is AUDIT_ARCH_ARM, a different arch token
// the check above already rejects), so the guard is x86-64-only.
[[nodiscard]] constexpr bool has_x32_personality(abi::Arch a) noexcept {
    return a == abi::Arch::x86_64;
}

// Highest syscall number we might have to encode. aarch64's table is dense
// up to ~465; x86-64's reaches ~460. 1024 covers both with room for the next
// decade of additions.
inline constexpr std::uint64_t kMaxSysno = 1024;

// One past the last Sysno enumerator. Sized generously and asserted below,
// so adding a syscall to sysno.hpp cannot silently overflow the table.
inline constexpr std::size_t kSysnoCount = 512;

// The number that means `s` on arch `a`, or kNoSysno when that arch has no
// such syscall (e.g. aarch64 has no open/stat/fork -- it only has openat,
// fstatat and clone).
inline constexpr std::uint64_t kNoSysno = ~std::uint64_t{0};

// decode() is Sysno-from-number; the filter needs number-from-Sysno. Invert
// the table ONCE per arch into a lookup indexed by Sysno, rather than
// linear-searching per entry: a per-entry search is O(entries x kMaxSysno)
// and blows the constexpr step limit at ~140 entries.
struct SysnoTable {
    std::array<std::uint64_t, kSysnoCount> nr{};
};

[[nodiscard]] constexpr SysnoTable invert(abi::Arch a) noexcept {
    SysnoTable t{};
    for (auto& n : t.nr) n = kNoSysno;
    // Ascending, and first write wins, so an alias pair maps to the lower
    // number -- the one the arch's own libc uses.
    for (std::uint64_t n = 0; n < kMaxSysno; ++n) {
        const auto s = static_cast<std::size_t>(abi::decode(a, n));
        if (s != 0 && s < kSysnoCount && t.nr[s] == kNoSysno) t.nr[s] = n;
    }
    return t;
}

[[nodiscard]] constexpr std::uint64_t encode(abi::Arch a, abi::Sysno s) noexcept {
    const auto i = static_cast<std::size_t>(s);
    if (i == 0 || i >= kSysnoCount) return kNoSysno;
    // One table per arch, built on first use in this translation unit.
    if (a == abi::Arch::aarch64) {
        constexpr SysnoTable t = invert(abi::Arch::aarch64);
        return t.nr[i];
    }
    constexpr SysnoTable t = invert(abi::Arch::x86_64);
    return t.nr[i];
}

// Translate a trapped-number list from x86-64 into `a`. Entries the target
// arch lacks collapse to kNoSysno and are dropped by the filter builder --
// correctly, since a syscall that doesn't exist can't be issued.
//
// N is the source list's length; the result is the same length with holes,
// so this stays a constant-expression (no vector, no allocation) and the
// whole translation happens at compile time. Both tables are built once
// here, not once per entry, which keeps the constexpr cost linear.
template <std::size_t N>
[[nodiscard]] constexpr std::array<std::uint64_t, N>
trapped_for(abi::Arch a, const int (&x86_64_numbers)[N]) noexcept {
    std::array<std::uint64_t, N> out{};
    if (a == abi::Arch::x86_64) {
        for (std::size_t i = 0; i < N; ++i)
            out[i] = static_cast<std::uint64_t>(x86_64_numbers[i]);
        return out;
    }
    const SysnoTable target = invert(a);
    for (std::size_t i = 0; i < N; ++i) {
        const auto src = static_cast<std::uint64_t>(x86_64_numbers[i]);
        const auto s = static_cast<std::size_t>(abi::decode(abi::Arch::x86_64, src));
        // Sysno::unknown (0) would match every unmapped number on the target,
        // so never translate through it.
        out[i] = (s == 0 || s >= kSysnoCount) ? kNoSysno : target.nr[s];
    }
    return out;
}

// If sysno.hpp ever grows past kSysnoCount, invert() would drop the tail
// silently and those syscalls would stop being trapped -- a confinement hole.
// invert() already walks every number, so have it report the highest Sysno
// index it saw rather than walking the table a second time just to assert.
[[nodiscard]] constexpr std::size_t max_sysno_index(abi::Arch a) noexcept {
    std::size_t hi = 0;
    for (std::uint64_t n = 0; n < kMaxSysno; ++n) {
        const auto s = static_cast<std::size_t>(abi::decode(a, n));
        if (s > hi) hi = s;
    }
    return hi;
}
static_assert(max_sysno_index(abi::Arch::x86_64) < kSysnoCount,
              "kSysnoCount is smaller than abi::Sysno; grow it or invert() "
              "will silently stop trapping the syscalls past the end");

// aarch64 really does lack these, so a translation returning kNoSysno for
// them is correct rather than a lookup bug. Pinned as a test of the seam
// itself: if encode() regressed to returning 0 or garbage, these fail.
// Checked on x86-64 builds only -- these are arch-independent facts about
// the tables, and evaluating both inversions on every target would cost more
// constexpr budget than it buys.
#if !defined(__aarch64__)
static_assert(encode(abi::Arch::aarch64, abi::Sysno::open) == kNoSysno);
static_assert(encode(abi::Arch::aarch64, abi::Sysno::openat) == 56);
static_assert(encode(abi::Arch::x86_64, abi::Sysno::openat) == 257);
static_assert(encode(abi::Arch::x86_64, abi::Sysno::read) == 0);
static_assert(encode(abi::Arch::aarch64, abi::Sysno::read) == 63);
#endif

}  // namespace lx::runtime

#endif  // LX_RUNTIME_LINUX_SECCOMP_ARCH_HPP
