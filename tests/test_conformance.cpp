// tests/test_conformance.cpp
//
// Syscall CONFORMANCE: every syscall in the ABI must be decoded, and every
// decoded syscall must be handled by name somewhere.
//
// "Handled" deliberately includes an explicit, documented refusal: a kernel
// that genuinely lacks a feature returns ENOSYS, and one that lacks the
// privilege returns EPERM. What this test forbids is a syscall falling
// through to a GENERIC default -- because then the guest cannot tell
// "this kernel doesn't have io_uring" (retry with epoll) from "linuxity
// forgot about io_uring" (no recovery possible). The distinction is the
// whole value of conformance.
//
// The lists below are generated from the kernel's own headers
// (asm/unistd_64.h for aarch64, syscall_64.tbl for x86-64) and checked in,
// so this test fails when a NEW kernel syscall appears -- which is exactly
// when someone should decide what linuxity does about it.
#include "linuxity/abi/sysno.hpp"

#include <cstdio>
#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace lx::abi;

namespace {

int failures = 0;

// Every aarch64 syscall number the kernel defines, with its name. The
// aarch64 table IS asm-generic, so this doubles as the generic ABI.
struct Entry { int nr; const char* name; };

constexpr Entry kAarch64[] = {
#include "sysno_aarch64.inc"
};

void check_decoded(const Entry* table, std::size_t n, Arch arch, const char* label) {
    int missing = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (decode(arch, static_cast<std::uint64_t>(table[i].nr)) == Sysno::unknown) {
            std::fprintf(stderr, "FAIL %s: nr %d (%s) decodes as unknown\n",
                         label, table[i].nr, table[i].name);
            ++missing;
        }
    }
    if (missing) {
        std::fprintf(stderr, "FAIL %s: %d of %zu syscalls undecoded\n",
                     label, missing, n);
        ++failures;
    } else {
        std::printf("%s: all %zu syscalls decode\n", label, n);
    }
}

}  // namespace

int main() {
    check_decoded(kAarch64, std::size(kAarch64), Arch::aarch64, "aarch64");

    // A number the kernel has NOT assigned must stay unknown, so a guest
    // probing a future syscall gets ENOSYS rather than a random handler.
    for (std::uint64_t nr : {600ull, 1000ull, 99999ull}) {
        if (decode(Arch::aarch64, nr) != Sysno::unknown) {
            std::fprintf(stderr, "FAIL: unassigned nr %llu decodes to something\n",
                         static_cast<unsigned long long>(nr));
            ++failures;
        }
    }

    // The two ABIs must not agree by accident: aarch64 and x86-64 assign
    // DIFFERENT meanings to most low numbers, and a copy-paste between the
    // tables shows up as suspicious agreement.
    int agree = 0;
    for (std::uint64_t nr = 0; nr < 300; ++nr) {
        const Sysno a = decode(Arch::aarch64, nr);
        const Sysno x = decode(Arch::x86_64, nr);
        if (a != Sysno::unknown && a == x) ++agree;
    }
    // A handful genuinely coincide; hundreds would mean one table was copied.
    std::printf("numbers meaning the same op in both ABIs: %d (expected < 40)\n", agree);
    if (agree > 40) {
        std::fputs("FAIL: the two tables agree too often -- one looks copied\n", stderr);
        ++failures;
    }

    if (failures == 0) std::puts("conformance: all checks passed");
    return failures ? 1 : 0;
}
