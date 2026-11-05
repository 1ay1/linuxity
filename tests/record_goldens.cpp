// tests/record_goldens.cpp
//
// Record this host's syscall behaviour as checked-in golden traces.
//
// WHY THIS EXISTS. The differential law needs a REFERENCE trace. On a Linux
// host that reference is the live kernel (LiveOracle). On macOS arm64 and
// Windows x86-64 there is no Linux kernel to ask, so the reference has to come
// from a recording made on Linux -- that is what RecordedOracle replays, and
// until now there were no recordings for it to replay, so those hosts reported
// no_recording and verified nothing.
//
// WHAT GETS RECORDED. The NATIVE trace, not linuxity's. The golden is the
// kernel's answer, captured once, so a host with no kernel can still be held
// to it. Recording linuxity's own output would make the test tautological: it
// would prove only that linuxity still does what it did when we recorded.
//
// This is a TOOL, not a test: it writes files and is run deliberately, from
// Linux CI or by hand. `ctest` never invokes it.
#include "linuxity/conform/host.hpp"
#include "linuxity/conform/oracles.hpp"
#include "linuxity/conform/report.hpp"
#include "linuxity/conform/trace_text.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;
using namespace lx::conform;

namespace {

std::string env_or(const char* k, const char* fallback) {
    const char* v = std::getenv(k);
    return v != nullptr ? std::string{v} : std::string{fallback};
}

} // namespace

int main() {
#if !defined(__linux__)
    std::fputs("record_goldens: refusing to run -- a golden must be recorded\n"
               "against a REAL Linux kernel, and this host has none. Run this\n"
               "on Linux (both arches) and commit the output.\n", stderr);
    return 1;
#else
    const OraclePaths paths{env_or("LX_PROBE_DIR", "build/probes"),
                            env_or("LX_GOLDEN_DIR", "tests/goldens")};
    const PosixProbeRunner             host;
    const LiveOracle<PosixProbeRunner> oracle{host, paths};

    if (!oracle.usable()) {
        std::fputs("record_goldens: no live oracle on this host\n", stderr);
        return 1;
    }

    std::printf("record_goldens: arch %s, kernel %s\n",
                std::string{arch_name(host_arch())}.c_str(),
                std::string{oracle.kernel_release()}.c_str());

    int wrote = 0;
    int failed = 0;
    for (const Scenario& s : all_scenarios()) {
        const std::string path = paths.golden(s);
        oracle.record(s.name)
            .match(
                [&](const Trace& t) {
                    std::printf("  %-14s -> %s (%zu steps)\n",
                                std::string{s.name}.c_str(), path.c_str(),
                                t.steps.size());
                    ++wrote;
                },
                [&](const Unavailable& u) {
                    std::printf("  %-14s FAILED: %s\n",
                                std::string{s.name}.c_str(),
                                u.describe().c_str());
                    ++failed;
                });
    }

    std::printf("record_goldens: %d written, %d failed\n", wrote, failed);
    if (failed != 0)
        std::fputs("record_goldens: some scenarios did not record; the goldens\n"
                   "are INCOMPLETE and a non-Linux host will report\n"
                   "no_recording for the missing ones (which is correct -- it\n"
                   "must not claim a pass it cannot justify).\n", stderr);
    return failed ? 1 : 0;
#endif
}
