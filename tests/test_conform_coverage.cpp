// tests/test_conform_coverage.cpp
//
// The RATCHET: how many intercepted syscalls are differentially verified?
//
// WHY THIS TEST EXISTS. The old conformance test checked that every syscall
// decodes and is handled by name. That is COVERAGE, it is necessarily true,
// and it stayed green through three real bugs the differential harness found
// in an afternoon:
//
//   * lseek on a virtual dir returned an entry index where Linux returns a
//     byte offset (fish printed "lseek: Invalid argument" at every startup)
//   * getdents64 on a CLOSED virtual dir fd returned 0 (clean EOF) where
//     Linux returns EBADF, because close was untrapped and the DirStream
//     outlived the fd
//   * classify("/") produced an empty host path, so stat("/") was ENOENT and
//     `rm -r` failed walking up
//
// So "handled" is not "correct", and this test refuses to conflate them. It
// prints the gap and FAILS if the verified set shrinks -- a ratchet, not a
// target. Nobody can claim 100% while the number says otherwise.
//
// A forwarded syscall needs no proof: on Linux a real kernel runs it, so it
// is native by construction. Only INTERCEPTED handlers can diverge, and those
// are what the denominator counts.
#include "linuxity/conform/observation.hpp"
#include "linuxity/conform/report.hpp"
#include "linuxity/conform/scenario.hpp"
#include "linuxity/conform/sysno_names.hpp"

#include <cstdio>
#include <set>
#include <string>
#include <string_view>
#include <vector>

using namespace lx;
using namespace lx::conform;

namespace {

// Every syscall some scenario actually exercises. Derived from the registry,
// so adding a scenario moves this number with no edit here.
[[nodiscard]] std::set<std::string_view> verified_calls() {
    std::set<std::string_view> v;
    for (const Scenario& s : all_scenarios())
        for (const abi::Sysno c : s.expects) v.insert(name_of(c));
    return v;
}

// The syscalls linuxity INTERCEPTS rather than forwards. Hand-listed here
// against a documented floor rather than parsed out of syscall.hpp: a regex
// over a 2000-line dispatcher is its own source of bugs, and the point of
// this test is a number nobody can fudge.
//
// This is the FLOOR, not the ceiling: the real count is ~139. Raising the
// floor as scenarios land is the ratchet.
constexpr int kInterceptedHandlers = 139;

// The verified floor. RAISE this as scenarios are added; never lower it.
// A drop means a scenario was deleted or a syscall silently stopped being
// exercised, which is exactly the regression this test exists to catch.
//
// 48 -> 52: the ioctls scenario (tty/termios, which had no probe at all).
// 52 -> 68: the legacy scenario (the x86-64-only aliases that predate the
//           *at family -- open/stat/access/chmod/rename/unlink/...).
// 68 -> 80: the xattrs scenario (16 handlers that had zero coverage).
// 80 -> 97: the creds scenario (credentials, sessions, process groups).
// 97 -> 108: the cwdfs scenario (cwd model, statfs/sysinfo, newer *at forms).
constexpr std::size_t kVerifiedFloor = 108;

} // namespace

int main() {
    const auto verified = verified_calls();

    std::puts("conform_coverage: differential verification of intercepted "
              "syscalls");
    std::printf("  intercepted handlers   : %d\n", kInterceptedHandlers);
    std::printf("  differentially verified: %zu\n", verified.size());
    std::printf("  unverified             : %d\n",
                kInterceptedHandlers - static_cast<int>(verified.size()));
    std::printf("  coverage               : %.1f%%\n",
                100.0 * static_cast<double>(verified.size()) /
                    static_cast<double>(kInterceptedHandlers));

    std::fputs("  verified:", stdout);
    for (const std::string_view c : verified) std::printf(" %s", std::string{c}.c_str());
    std::puts("");

    int failures = 0;

    // THE RATCHET. Coverage may only go up.
    if (verified.size() < kVerifiedFloor) {
        std::fprintf(stderr,
                     "FAIL: differential coverage DROPPED to %zu (floor %zu). "
                     "A scenario was removed or stopped exercising a syscall; "
                     "restore it rather than lowering the floor.\n",
                     verified.size(), kVerifiedFloor);
        ++failures;
    }

    // Every scenario must exercise at least one syscall, or it is decoration
    // that inflates the scenario count without verifying anything.
    for (const Scenario& s : all_scenarios()) {
        if (s.expects.empty()) {
            std::fprintf(stderr, "FAIL: scenario '%s' exercises nothing\n",
                         std::string{s.name}.c_str());
            ++failures;
        }
    }

    // At least one scenario must hit a VIRTUALISED directory. Host-backed
    // paths forward to the real kernel and so cannot catch a bug in
    // linuxity's own code -- which is how the lseek bug survived a test that
    // only looked at /usr/bin.
    bool virtualised = false;
    for (const Scenario& s : all_scenarios())
        if (s.flavour == DirFlavour::virtualised) virtualised = true;
    if (!virtualised) {
        std::fputs("FAIL: no scenario exercises a virtualised path; "
                   "host-backed ones forward to the kernel and verify "
                   "nothing about linuxity\n", stderr);
        ++failures;
    }

    // State the gap plainly. This is not a failure -- it is the honest status,
    // and printing it is what keeps "100% conformant" from being asserted.
    if (failures == 0) {
        std::printf("conform_coverage: ratchet holds at %zu verified. "
                    "%d intercepted handlers remain unverified -- linuxity is "
                    "NOT yet differentially proven on those.\n",
                    verified.size(),
                    kInterceptedHandlers - static_cast<int>(verified.size()));
    }
    return failures ? 1 : 0;
}
