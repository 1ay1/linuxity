// tests/test_seccomp_arch.cpp
//
// The seccomp arch seam.
//
// aarch64's trapped syscall numbers are DERIVED from the x86-64 list rather
// than hand-written a second time, because a second list is a second source
// of truth for the same set and the two drift. The trap list has already
// drifted from the dispatcher three times (lseek, fchmodat2, creat -- two of
// them sandbox escapes), so this one keeps its derivation pinned.
//
// The failure modes this catches, both silent at runtime:
//
//   * a wrong AUDIT_ARCH makes the filter's arch check fail for EVERY
//     syscall, so the guest gets ENOSYS on all of them and spins forever
//     instead of being traced. That is the exact bug that made linuxity hang
//     on Android before the seam existed.
//   * a bad translation names a DIFFERENT syscall on the target arch, so a
//     handler services a question the guest never asked.
#include "linuxity/runtime/linux/seccomp_arch.hpp"
#include "linuxity/runtime/linux/seccomp_filter.hpp"

#include <linux/audit.h>

#include <cstdio>
#include <set>

using namespace lx;
using namespace lx::runtime;

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

void check_eq(std::uint64_t got, std::uint64_t want, const char* what) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s = %llu, want %llu\n", what,
                     static_cast<unsigned long long>(got),
                     static_cast<unsigned long long>(want));
        ++failures;
    }
}

// A sample spanning the interesting shapes: same call different number,
// x86-64-only legacy calls, and the openat family aarch64 uses instead.
constexpr int kSample[] = {
    0,    // read    -> aarch64 63
    1,    // write   -> aarch64 64
    2,    // open    -> aarch64: ABSENT (openat only)
    257,  // openat  -> aarch64 56
    4,    // stat    -> aarch64: ABSENT (fstatat only)
    59,   // execve  -> aarch64 221
    39,   // getpid  -> aarch64 172
};

}  // namespace

int main() {
    // --- the audit token ---------------------------------------------------
    check_eq(seccomp_audit_arch(abi::Arch::x86_64), AUDIT_ARCH_X86_64,
             "audit arch x86_64");
    check_eq(seccomp_audit_arch(abi::Arch::aarch64), AUDIT_ARCH_AARCH64,
             "audit arch aarch64");

    // --- x32 is an x86-64-only personality ---------------------------------
    check(has_x32_personality(abi::Arch::x86_64), "x32 gate on x86_64");
    check(!has_x32_personality(abi::Arch::aarch64), "no x32 gate on aarch64");

    // --- encode is decode's inverse ----------------------------------------
    for (std::uint64_t nr = 0; nr < kMaxSysno; ++nr) {
        for (const abi::Arch a : {abi::Arch::x86_64, abi::Arch::aarch64}) {
            const abi::Sysno s = abi::decode(a, nr);
            if (s == abi::Sysno::unknown) continue;
            // Alias pairs (two numbers, one Sysno) resolve to the lower
            // number, so the round trip must name the same call -- not
            // necessarily the same number.
            if (abi::decode(a, encode(a, s)) != s) {
                std::fprintf(stderr,
                             "FAIL: encode/decode round trip broke for nr %llu\n",
                             static_cast<unsigned long long>(nr));
                ++failures;
            }
        }
    }

    // --- the sample translates as documented -------------------------------
    constexpr auto x86 = trapped_for(abi::Arch::x86_64, kSample);
    constexpr auto arm = trapped_for(abi::Arch::aarch64, kSample);

    for (std::size_t i = 0; i < x86.size(); ++i)
        check_eq(x86[i], static_cast<std::uint64_t>(kSample[i]),
                 "x86_64 translation is the identity");

    check_eq(arm[0], 63, "aarch64 read");
    check_eq(arm[1], 64, "aarch64 write");
    check_eq(arm[2], kNoSysno, "aarch64 has no open");
    check_eq(arm[3], 56, "aarch64 openat");
    check_eq(arm[4], kNoSysno, "aarch64 has no stat");
    check_eq(arm[5], 221, "aarch64 execve");
    check_eq(arm[6], 172, "aarch64 getpid");

    // --- the real trap list: every entry must mean the same call -----------
    constexpr auto all = trapped_for(abi::Arch::aarch64, kTrappedX86_64);
    std::size_t translated = 0, absent = 0;
    std::set<std::uint64_t> seen;

    for (std::size_t i = 0; i < all.size(); ++i) {
        const auto src = static_cast<std::uint64_t>(kTrappedX86_64[i]);
        const abi::Sysno want = abi::decode(abi::Arch::x86_64, src);
        if (all[i] == kNoSysno) {
            ++absent;
            continue;
        }
        ++translated;
        if (abi::decode(abi::Arch::aarch64, all[i]) != want) {
            std::fprintf(stderr,
                         "FAIL: x86 nr %llu translated to aarch64 %llu, which "
                         "is a different syscall\n",
                         static_cast<unsigned long long>(src),
                         static_cast<unsigned long long>(all[i]));
            ++failures;
        }
        check(all[i] < kMaxSysno, "translated number is in range");
        seen.insert(all[i]);
    }

    // Guard against a vacuous pass: if a refactor broke the lookup and every
    // entry collapsed to kNoSysno, the loop above would check nothing.
    std::printf("trap list: %zu translated, %zu absent on aarch64, %zu distinct\n",
                translated, absent, seen.size());
    check(translated > 100, "most of the trap list translates");
    check(absent < 40, "only the legacy x86-only calls are absent");

    if (failures != 0) {
        std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    std::printf("seccomp arch seam: ok\n");
    return 0;
}
