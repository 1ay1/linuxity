// tests/test_conform_diff.cpp
//
// The LIVE differential test: run each scenario's probe natively and under
// linuxity, and judge the two traces with the same law every host uses.
//
// This is the test that actually verifies handlers. The portable tests prove
// the law is sound; this one points it at the real kernel. Linux-only, because
// it needs a live oracle -- on macOS/Windows the same comparison runs against
// recorded goldens instead.
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

int failures = 0;

// Where the build put things. Passed in by ctest so the test does not guess.
std::string env_or(const char* k, const char* fallback) {
    const char* v = std::getenv(k);
    return v != nullptr ? std::string{v} : std::string{fallback};
}

// A runner that executes the probe UNDER LINUXITY, so its trace is the guest
// side. The oracle machinery is reused verbatim: same ProbeRunner concept,
// same parser, same law -- only the program being launched differs.
class GuestRunner {
public:
    GuestRunner(std::string linuxity, PosixProbeRunner host)
        : linuxity_{std::move(linuxity)}, host_{host} {}

    [[nodiscard]] ProbeOutput run(std::string_view probe,
                                  std::span<const std::string> args,
                                  std::uint32_t deadline_ms) const {
        // linuxity <probe> <args...>  -- the guest needs an absolute path,
        // since it resolves the program through its own namespace.
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
    [[nodiscard]] bool linux_native() const { return false; }  // it's the guest

private:
    std::string      linuxity_;
    PosixProbeRunner host_;
};

static_assert(ProbeRunner<GuestRunner>);

} // namespace

int main() {
#if !defined(__linux__)
    std::puts("conform_diff: skipped, no live Linux kernel on this host");
    return 0;
#else
    const std::string probe_dir = env_or("LX_PROBE_DIR", "build/probes");
    const std::string linuxity  = env_or("LX_BINARY", "build/linuxity");
    const OraclePaths paths{probe_dir, env_or("LX_GOLDEN_DIR", "tests/goldens")};

    const PosixProbeRunner host;
    const GuestRunner      guest{linuxity, host};

    // Only the NATIVE side is an oracle: it is the reference. The guest side
    // is the thing under test, so it is run directly rather than wrapped in
    // LiveOracle -- and the type system enforces that, since GuestRunner
    // reports linux_native() == false and so cannot satisfy HasLinuxKernel.
    const LiveOracle<PosixProbeRunner> oracle{host, paths};

    std::printf("conform_diff: %s, arch %s\n",
                std::string{HostConformance::describe()}.c_str(),
                std::string{arch_name(host_arch())}.c_str());

    // Run a scenario's probe under linuxity and parse its trace. Mirrors
    // LiveOracle::run_and_parse, including refusing to parse a crashed probe.
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
    for (const Scenario& s : all_scenarios()) {
        const Reference native = oracle.reference_for(s.name);
        const Reference ours   = guest_trace(s);

        // An unavailable reference is NOT a pass -- report it and fail, or a
        // broken probe would look like perfect conformance.
        const Trace* nt = nullptr;
        const Trace* gt = nullptr;
        Trace nbuf{""}, gbuf{""};

        native.match([&](const Trace& t) { nbuf = t; nt = &nbuf; },
                     [&](const Unavailable& u) {
                         std::printf("  %-14s NATIVE UNAVAILABLE: %s\n",
                                     std::string{s.name}.c_str(),
                                     u.describe().c_str());
                         ++failures;
                     });
        ours.match([&](const Trace& t) { gbuf = t; gt = &gbuf; },
                   [&](const Unavailable& u) {
                       std::printf("  %-14s GUEST UNAVAILABLE: %s\n",
                                   std::string{s.name}.c_str(),
                                   u.describe().c_str());
                       ++failures;
                   });
        if (nt == nullptr || gt == nullptr) continue;

        ++checked;
        judge(*nt, *gt, default_law())
            .match(
                [&](Match m) {
                    std::printf("  %-14s AGREE  (%zu steps, %s)\n",
                                std::string{s.name}.c_str(), m.steps_compared,
                                std::string{flavour_name(s.flavour)}.c_str());
                },
                [&](const Divergence& d) {
                    std::printf("  %-14s DIVERGE (%s)\n    %s\n",
                                std::string{s.name}.c_str(),
                                std::string{flavour_name(s.flavour)}.c_str(),
                                d.describe().c_str());
                    ++failures;
                });
    }

    std::printf("conform_diff: %d scenarios checked, %d failing\n", checked,
                failures);
    return failures ? 1 : 0;
#endif
}
