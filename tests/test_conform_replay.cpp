// tests/test_conform_replay.cpp
//
// THE PORTABILITY PROOF: verify linuxity against RECORDED goldens, with no
// live kernel involved.
//
// WHY THIS IS THE IMPORTANT TEST. conform_diff compares linuxity against the
// kernel running underneath it -- which only exists on a Linux host. This test
// compares linuxity against a trace recorded on Linux and committed to the
// repo, so it runs on ALL FOUR targets and means the same thing on each:
//
//     Linux arm64 / x86-64   runs it (and can also run conform_diff)
//     macOS arm64            runs it -- this is the only conformance it gets
//     Windows x86-64         runs it -- likewise
//
// If this passes on a fresh host, that host's linuxity answers these syscalls
// exactly as a real Linux kernel did. That is the "if it passes it works"
// property: the golden is the kernel's answer, captured once, and replaying it
// needs no kernel at all.
//
// It is deliberately NOT tautological. The golden holds the NATIVE trace, so
// agreeing with it means agreeing with Linux. Had we recorded linuxity's own
// output, the test would only prove linuxity still does what it did on
// recording day -- a change detector, not a conformance check.
#include "linuxity/conform/host.hpp"
#include "linuxity/conform/oracles.hpp"
#include "linuxity/conform/report.hpp"
#include "linuxity/conform/trace_text.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace lx;
using namespace lx::conform;

namespace {

std::string env_or(const char* k, const char* fallback) {
    const char* v = std::getenv(k);
    return v != nullptr ? std::string{v} : std::string{fallback};
}

// Runs a probe UNDER LINUXITY. Same ProbeRunner contract the oracles use, so
// the guest side is produced by exactly the machinery that produces the
// reference side -- only the program launched differs.
class GuestRunner {
public:
    GuestRunner(std::string linuxity, PosixProbeRunner host)
        : linuxity_{std::move(linuxity)}, host_{host} {}

    [[nodiscard]] ProbeOutput run(std::string_view probe,
                                  std::span<const std::string> args,
                                  std::uint32_t deadline_ms) const {
        std::vector<std::string> argv;
        argv.emplace_back(probe);
        for (const std::string& a : args) argv.push_back(a);
        return host_.run(linuxity_, argv, deadline_ms);
    }
    [[nodiscard]] std::optional<std::string> read_file(std::string_view p) const {
        return host_.read_file(p);
    }
    [[nodiscard]] bool write_file(std::string_view p, std::string_view t) const {
        return host_.write_file(p, t);
    }
    [[nodiscard]] bool linux_native() const { return false; }

private:
    std::string      linuxity_;
    PosixProbeRunner host_;
};

static_assert(ProbeRunner<GuestRunner>);

} // namespace

int main() {
    const OraclePaths paths{env_or("LX_PROBE_DIR", "build/probes"),
                            env_or("LX_GOLDEN_DIR", "tests/goldens")};
    const std::string linuxity = env_or("LX_BINARY", "build/linuxity");

    const PosixProbeRunner host;
    const GuestRunner      guest{linuxity, host};

    // The oracle is the RECORDING. Note this needs only ProbeRunner, not
    // HasLinuxKernel -- which is precisely why it instantiates on every host.
    const RecordedOracle<PosixProbeRunner> oracle{host, paths};

    std::printf("conform_replay: arch %s, reference = %s\n",
                std::string{arch_name(host_arch())}.c_str(),
                std::string{oracle.provenance()}.c_str());

    const auto guest_trace = [&](const Scenario& s) -> Reference {
        const ProbeOutput out =
            guest.run(paths.probe(s.probe), s.args, kProbeDeadlineMs);
        if (out.timed_out)
            return Unavailable{Unavailable::Cause::probe_failed,
                               "guest probe timed out"};
        if (!out.completed())
            return Unavailable{Unavailable::Cause::probe_failed,
                               "guest probe exited " +
                                   std::to_string(out.exit_code)};
        return parse_trace(out.stdout_text, std::string{s.name})
            .match([](const Trace& t) { return Reference{t}; },
                   [](const ParseError& e) {
                       return Reference{Unavailable{
                           Unavailable::Cause::probe_failed,
                           "unparsable guest output, " + e.describe()}};
                   });
    };

    int checked = 0;
    int failures = 0;
    int missing = 0;

    for (const Scenario& s : all_scenarios()) {
        const Reference golden = oracle.reference_for(s.name);

        // A MISSING golden is not a pass and not a failure: it means this
        // arch has not been recorded yet. Counted and reported separately so
        // "we did not check" can never read as "we checked and agreed".
        Trace gref{""};
        bool have_golden = false;
        golden.match([&](const Trace& t) { gref = t; have_golden = true; },
                     [&](const Unavailable& u) {
                         std::printf("  %-14s NO REFERENCE: %s\n",
                                     std::string{s.name}.c_str(),
                                     u.describe().c_str());
                         ++missing;
                     });
        if (!have_golden) continue;

        Trace gt{""};
        bool have_guest = false;
        guest_trace(s).match([&](const Trace& t) { gt = t; have_guest = true; },
                             [&](const Unavailable& u) {
                                 std::printf("  %-14s GUEST FAILED: %s\n",
                                             std::string{s.name}.c_str(),
                                             u.describe().c_str());
                                 ++failures;
                             });
        if (!have_guest) continue;

        ++checked;
        judge(gref, gt, default_law())
            .match(
                [&](Match m) {
                    std::printf("  %-14s MATCHES GOLDEN (%zu steps)\n",
                                std::string{s.name}.c_str(), m.steps_compared);
                },
                [&](const Divergence& d) {
                    std::printf("  %-14s DIVERGES FROM GOLDEN\n    %s\n",
                                std::string{s.name}.c_str(),
                                d.describe().c_str());
                    ++failures;
                });
    }

    std::printf("conform_replay: %d scenarios matched the recorded kernel, "
                "%d failing, %d unrecorded\n", checked, failures, missing);

    // An unrecorded scenario is a HOLE, not a pass. Failing on it is what
    // stops the suite from going quietly green as scenarios are added faster
    // than goldens are recorded -- the exact way a conformance suite rots
    // into a formality.
    if (missing != 0) {
        std::fprintf(stderr,
                     "conform_replay: %d scenario(s) have NO golden for arch "
                     "%s, so they were not verified at all. Record them on a "
                     "Linux host of this arch and commit the result:\n"
                     "  cmake --build build --target record_goldens\n"
                     "  LX_PROBE_DIR=$PWD/build/probes "
                     "./build/tests/record_goldens\n",
                     missing, std::string{arch_name(host_arch())}.c_str());
        return 1;
    }
    return failures ? 1 : 0;
}
