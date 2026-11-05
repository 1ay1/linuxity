// tests/test_sysno.cpp
//
// Syscall-table conformance.
//
// abi/sysno.hpp claims to decode EVERY syscall in both 64-bit Linux ABIs.
// That claim is only worth something if it is checked, and the failure mode
// of a wrong entry is the nastiest kind: a mistyped number silently routes
// one syscall to another's handler, so the guest gets a plausible answer to
// a question it never asked.
//
// So this test hard-codes a sample of the ABI taken from the kernel's own
// headers and asserts the mapping both ways. The samples are chosen to cover
// the traps:
//
//   * numbers that differ between the two arches (openat, clone, futex)
//   * numbers that mean DIFFERENT syscalls on each arch -- the real hazard
//     (on aarch64 25 is fcntl, on x86-64 it is mremap)
//   * the legacy x86-only calls aarch64 deliberately lacks
//   * recent additions at the top of the table (futex_waitv, cachestat)
#include "linuxity/abi/sysno.hpp"

#include <cstdio>
#include <string_view>

using namespace lx::abi;

namespace {

int failures = 0;

void expect(Arch a, std::uint64_t nr, Sysno want, std::string_view what) {
    const Sysno got = decode(a, nr);
    if (got == want) return;
    std::fprintf(stderr, "FAIL %s: decode(%s, %llu) = %d, want %d\n",
                 what.data(), a == Arch::x86_64 ? "x86_64" : "aarch64",
                 static_cast<unsigned long long>(nr),
                 static_cast<int>(got), static_cast<int>(want));
    ++failures;
}

// The count of distinct numbers each arch decodes, so a table that loses
// entries fails loudly rather than quietly shrinking.
[[nodiscard]] int decoded_count(Arch a, std::uint64_t upto) {
    int n = 0;
    for (std::uint64_t nr = 0; nr <= upto; ++nr)
        if (decode(a, nr) != Sysno::unknown) ++n;
    return n;
}

}  // namespace

int main() {
    // -- aarch64 (asm-generic). Spot values across the whole range. --------
    expect(Arch::aarch64, 0,   Sysno::io_setup,      "arm io_setup");
    expect(Arch::aarch64, 17,  Sysno::getcwd,        "arm getcwd");
    expect(Arch::aarch64, 25,  Sysno::fcntl,         "arm 25 is fcntl");
    expect(Arch::aarch64, 29,  Sysno::ioctl,         "arm ioctl");
    expect(Arch::aarch64, 56,  Sysno::openat,        "arm openat");
    expect(Arch::aarch64, 57,  Sysno::close,         "arm close");
    expect(Arch::aarch64, 63,  Sysno::read,          "arm read");
    expect(Arch::aarch64, 64,  Sysno::write,         "arm write");
    expect(Arch::aarch64, 93,  Sysno::exit,          "arm exit");
    expect(Arch::aarch64, 94,  Sysno::exit_group,    "arm exit_group");
    expect(Arch::aarch64, 98,  Sysno::futex,         "arm futex");
    expect(Arch::aarch64, 129, Sysno::kill,          "arm kill");
    expect(Arch::aarch64, 134, Sysno::rt_sigaction,  "arm rt_sigaction");
    expect(Arch::aarch64, 135, Sysno::rt_sigprocmask,"arm rt_sigprocmask");
    expect(Arch::aarch64, 160, Sysno::uname,         "arm uname");
    expect(Arch::aarch64, 169, Sysno::gettimeofday,  "arm gettimeofday");
    expect(Arch::aarch64, 214, Sysno::brk,           "arm brk");
    expect(Arch::aarch64, 220, Sysno::clone,         "arm clone");
    expect(Arch::aarch64, 221, Sysno::execve,        "arm execve");
    expect(Arch::aarch64, 222, Sysno::mmap,          "arm mmap");
    expect(Arch::aarch64, 260, Sysno::wait4,         "arm wait4");
    expect(Arch::aarch64, 278, Sysno::getrandom,     "arm getrandom");
    expect(Arch::aarch64, 291, Sysno::statx,         "arm statx");
    expect(Arch::aarch64, 435, Sysno::clone3,        "arm clone3");
    expect(Arch::aarch64, 444, Sysno::landlock_create_ruleset, "arm landlock");
    expect(Arch::aarch64, 449, Sysno::futex_waitv,   "arm futex_waitv");
    expect(Arch::aarch64, 451, Sysno::cachestat,     "arm cachestat");
    expect(Arch::aarch64, 452, Sysno::fchmodat2,     "arm fchmodat2");

    // -- x86-64. The same operations, different numbers. -------------------
    expect(Arch::x86_64, 0,   Sysno::read,           "x86 read");
    expect(Arch::x86_64, 1,   Sysno::write,          "x86 write");
    expect(Arch::x86_64, 2,   Sysno::open,           "x86 open");
    expect(Arch::x86_64, 16,  Sysno::ioctl,          "x86 ioctl");
    expect(Arch::x86_64, 25,  Sysno::mremap,         "x86 25 is mremap");
    expect(Arch::x86_64, 56,  Sysno::clone,          "x86 56 is clone");
    expect(Arch::x86_64, 57,  Sysno::fork,           "x86 fork");
    expect(Arch::x86_64, 60,  Sysno::exit,           "x86 exit");
    expect(Arch::x86_64, 62,  Sysno::kill,           "x86 kill");
    expect(Arch::x86_64, 202, Sysno::futex,          "x86 futex");
    expect(Arch::x86_64, 231, Sysno::exit_group,     "x86 exit_group");
    expect(Arch::x86_64, 257, Sysno::openat,         "x86 openat");
    expect(Arch::x86_64, 262, Sysno::newfstatat,     "x86 newfstatat");
    expect(Arch::x86_64, 318, Sysno::getrandom,      "x86 getrandom");
    expect(Arch::x86_64, 332, Sysno::statx,          "x86 statx");
    expect(Arch::x86_64, 452, Sysno::fchmodat2,      "x86 fchmodat2");

    // -- The SAME number meaning DIFFERENT things is the core hazard. ------
    static_assert(static_cast<int>(Sysno::unknown) == 0);
    if (decode(Arch::aarch64, 25) == decode(Arch::x86_64, 25)) {
        std::fputs("FAIL: nr 25 must differ between the ABIs "
                   "(fcntl vs mremap)\n", stderr);
        ++failures;
    }
    if (decode(Arch::aarch64, 56) == decode(Arch::x86_64, 56)) {
        std::fputs("FAIL: nr 56 must differ between the ABIs "
                   "(openat vs clone)\n", stderr);
        ++failures;
    }

    // -- Legacy x86-only calls must NOT appear on aarch64, which genuinely
    //    lacks them (glibc implements open() as openat(), fork() as clone()).
    for (auto [nr, name] : {std::pair{2, "open"}, {57, "fork"}, {58, "vfork"},
                            {83, "mkdir"}, {87, "unlink"}, {88, "symlink"}}) {
        // On aarch64 these numbers are OTHER syscalls, never the x86 one.
        const Sysno arm_meaning = decode(Arch::aarch64, static_cast<std::uint64_t>(nr));
        const Sysno x86_meaning = decode(Arch::x86_64, static_cast<std::uint64_t>(nr));
        if (arm_meaning == x86_meaning && arm_meaning != Sysno::unknown) {
            std::fprintf(stderr, "FAIL: nr %d (%s on x86) collides on aarch64\n",
                         nr, name);
            ++failures;
        }
    }

    // -- Coverage. The ABIs have 327 (aarch64) and 374 (x86-64) syscalls;
    //    these floors catch a table that silently loses entries.
    const int arm_n = decoded_count(Arch::aarch64, 600);
    const int x86_n = decoded_count(Arch::x86_64, 600);
    std::printf("decoded: aarch64 %d, x86_64 %d\n", arm_n, x86_n);
    if (arm_n < 327) {
        std::fprintf(stderr, "FAIL: aarch64 decodes %d, expected >= 327\n", arm_n);
        ++failures;
    }
    if (x86_n < 374) {
        std::fprintf(stderr, "FAIL: x86_64 decodes %d, expected >= 374\n", x86_n);
        ++failures;
    }

    // An unassigned number must stay unknown, so a guest probing the future
    // gets ENOSYS rather than a random handler.
    expect(Arch::aarch64, 9999, Sysno::unknown, "unassigned stays unknown");
    expect(Arch::x86_64, 9999, Sysno::unknown, "unassigned stays unknown");

    if (failures == 0) std::puts("sysno: all checks passed");
    return failures ? 1 : 0;
}
