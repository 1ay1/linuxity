// linuxity/conform/oracles.hpp
//
// The two oracles, each written ONCE for all four hosts.
//
// Neither of these is host-specific. They are generic over a ProbeRunner and
// contain only policy -- which scenario to run, where a golden lives, whether
// it is stale, how to turn output into a Trace. A host supplies a ProbeRunner
// (three members) and gets both oracles for free.
//
//     LiveOracle<R>      requires HasLinuxKernel<R>: runs the probe natively
//                        and parses its output. Available on Linux arm64 and
//                        Linux x86-64.
//
//     RecordedOracle<R>  needs only ProbeRunner<R>: reads a checked-in golden.
//                        Available everywhere, which is what gives macOS arm64
//                        and Windows x86-64 real conformance coverage instead
//                        of a vacuous pass.
//
// WHY LiveOracle IS CONSTRAINED. `requires HasLinuxKernel<R>` is not
// decoration: it makes "this oracle needs a Linux kernel" a type error on a
// host that hasn't got one, caught at the instantiation site with a named
// concept. The alternative -- an #ifdef inside the oracle, or a runtime check
// that returns an empty Trace -- is the vacuous pass this design exists to
// make impossible.
#pragma once

#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "linuxity/conform/observation.hpp"
#include "linuxity/conform/oracle.hpp"
#include "linuxity/conform/probe_runner.hpp"
#include "linuxity/conform/scenario.hpp"
#include "linuxity/conform/trace_text.hpp"

namespace lx::conform {

// Where probe binaries and goldens live. Paths are POLICY -- the same layout
// on every host -- so they are computed here, once, rather than in each
// runner.
struct OraclePaths {
    std::string probe_dir;   // built probe binaries
    std::string golden_dir;  // checked-in reference traces

    [[nodiscard]] std::string probe(std::string_view name) const {
        return probe_dir + "/" + std::string{name};
    }
    // Derived from the scenario KEY, never stored, so a renamed scenario
    // cannot keep matching an old recording.
    [[nodiscard]] std::string golden(const Scenario& s) const {
        return golden_dir + "/" + s.key() + ".trace";
    }
};

// How long a probe may run. A hung probe is the common failure -- an
// interactive guest never exits -- so the deadline is explicit policy rather
// than each runner's guess.
inline constexpr std::uint32_t kProbeDeadlineMs = 15'000;

// -- the live oracle -------------------------------------------------------

// Runs the scenario's probe on a real Linux kernel. The reference is the
// kernel's own behaviour, so nothing here encodes an opinion about what a
// syscall should do.
template <ProbeRunner R>
    requires HasLinuxKernel<R>
class LiveOracle {
public:
    LiveOracle(const R& runner, OraclePaths paths)
        : runner_{&runner}, paths_{std::move(paths)} {}

    [[nodiscard]] Reference reference_for(std::string_view scenario) const {
        const auto found = find_scenario(scenario);
        if (!found)
            return Unavailable{Unavailable::Cause::probe_failed,
                               "no scenario named " + std::string{scenario}};
        return run_and_parse(*found);
    }

    [[nodiscard]] std::string_view provenance() const {
        return "live Linux kernel on this host";
    }

    [[nodiscard]] bool usable() const { return runner_->linux_native(); }

    [[nodiscard]] std::string_view kernel_release() const
        requires KnowsKernelRelease<R>
    {
        return runner_->kernel_release();
    }

    // The Records capability: capture this host's behaviour as a golden, for
    // replay on hosts with no Linux kernel. Only a live oracle can do this,
    // which is exactly why it is a capability and not a core member.
    [[nodiscard]] Reference record(std::string_view scenario) const {
        const auto found = find_scenario(scenario);
        if (!found)
            return Unavailable{Unavailable::Cause::probe_failed,
                               "no scenario named " + std::string{scenario}};

        Reference ref = run_and_parse(*found);
        const std::string path = paths_.golden(*found);
        return ref.match(
            [&](const Trace& t) -> Reference {
                std::string kernel;
                if constexpr (KnowsKernelRelease<R>)
                    kernel = std::string{runner_->kernel_release()};
                // A golden that failed to write must not be reported as a
                // successful recording: the next host would find no
                // reference and we would have lost the reason why.
                if (!runner_->write_file(path,
                                         render_trace(t, provenance(), kernel)))
                    return Unavailable{Unavailable::Cause::probe_failed,
                                       "could not write golden " + path};
                return t;
            },
            [](const Unavailable& u) -> Reference { return u; });
    }

private:
    [[nodiscard]] static std::optional<Scenario>
    find_scenario(std::string_view name) {
        for (const Scenario& s : all_scenarios())
            if (s.name == name) return s;
        return std::nullopt;
    }

    [[nodiscard]] Reference run_and_parse(const Scenario& s) const {
        const ProbeOutput out =
            runner_->run(paths_.probe(s.probe), s.args, kProbeDeadlineMs);

        // A crashed or hung probe must NOT be parsed: partial output would
        // read as a short trace and then report a bogus step_count
        // divergence instead of the real problem.
        if (out.timed_out)
            return Unavailable{Unavailable::Cause::probe_failed,
                               "probe timed out: " + std::string{s.probe}};
        if (!out.completed())
            return Unavailable{Unavailable::Cause::probe_failed,
                               "probe exited " + std::to_string(out.exit_code)};

        return parse_trace(out.stdout_text, std::string{s.name})
            .match([](const Trace& t) { return Reference{t}; },
                   [&](const ParseError& e) {
                       return Reference{Unavailable{
                           Unavailable::Cause::probe_failed,
                           "unparsable probe output, " + e.describe()}};
                   });
    }

    const R*    runner_;
    OraclePaths paths_;
};

// -- the recorded oracle ---------------------------------------------------

// Replays a golden captured on Linux CI. Needs no Linux kernel, so this is
// what macOS arm64 and Windows x86-64 run -- and it is the SAME comparison,
// under the same law, as a live Linux run.
//
// THE STALENESS PROBLEM. A golden is only a valid reference while the scenario
// still means what it meant when recorded. Rename a scenario and the key
// changes, so the golden simply isn't found (reported as no_recording, not a
// pass). Change what a probe DOES without renaming it, and the recording is
// silently wrong -- so the trace is checked against the scenario's declared
// `expects` list, and a mismatch is stale_recording rather than a divergence
// blamed on linuxity.
template <ProbeRunner R>
class RecordedOracle {
public:
    RecordedOracle(const R& runner, OraclePaths paths)
        : runner_{&runner}, paths_{std::move(paths)} {}

    [[nodiscard]] Reference reference_for(std::string_view scenario) const {
        const auto found = find_scenario(scenario);
        if (!found)
            return Unavailable{Unavailable::Cause::no_recording,
                               "no scenario named " + std::string{scenario}};

        const std::string path = paths_.golden(*found);
        const auto text = runner_->read_file(path);
        if (!text)
            return Unavailable{Unavailable::Cause::no_recording,
                               "no golden at " + path +
                                   " (record one on a Linux host)"};

        return parse_trace(*text, std::string{found->name})
            .match(
                [&](const Trace& t) -> Reference {
                    if (const char* why = stale_reason(*found, t))
                        return Unavailable{Unavailable::Cause::stale_recording,
                                           std::string{why} + " in " + path};
                    return t;
                },
                [&](const ParseError& e) -> Reference {
                    return Unavailable{Unavailable::Cause::stale_recording,
                                       "malformed golden " + path + ", " +
                                           e.describe()};
                });
    }

    [[nodiscard]] std::string_view provenance() const {
        return "recorded golden trace from a Linux host";
    }

    // Usable wherever a golden can be read, which is every host. Note this is
    // NOT `linux_native()`: the point of this oracle is working without one.
    [[nodiscard]] bool usable() const { return true; }

private:
    [[nodiscard]] static std::optional<Scenario>
    find_scenario(std::string_view name) {
        for (const Scenario& s : all_scenarios())
            if (s.name == name) return s;
        return std::nullopt;
    }

    // A recording whose syscalls no longer match what the scenario claims to
    // exercise is stale, not a divergence. Reporting those apart is the
    // difference between "regenerate the golden" and "linuxity has a bug".
    [[nodiscard]] static const char* stale_reason(const Scenario& s,
                                                  const Trace& t) {
        if (t.steps.empty()) return "golden has no steps";
        for (const abi::Sysno want : s.expects) {
            bool seen = false;
            for (const Observation& o : t.steps)
                if (o.call == want) seen = true;
            if (!seen) return "golden lacks a syscall the scenario exercises";
        }
        return nullptr;
    }

    const R*    runner_;
    OraclePaths paths_;
};

} // namespace lx::conform
