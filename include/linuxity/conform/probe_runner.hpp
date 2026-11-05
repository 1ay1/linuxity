// linuxity/conform/probe_runner.hpp
//
// The HOST-FACILITY contract for conformance: the three operations an oracle
// genuinely cannot do portably.
//
// WHY THIS IS SO SMALL. runtime/hostcalls.hpp settled the axis this file
// obeys: the question is never "which host am I on", it is "does this need a
// host facility, or is it policy over state we already own?" Splitting by host
// is what grew a second dispatcher on Windows and left every Windows process
// seeing pid 1 -- 46 syscalls of policy duplicated because the seam was cut in
// the wrong place.
//
// Applying that axis to oracles, almost everything turns out to be policy:
//
//   POLICY -- written ONCE in conform/, identical on all four hosts:
//     parsing probe output into a Trace      (trace_text.hpp)
//     rendering a Trace back to text         (trace_text.hpp)
//     choosing the golden path for a key     (oracle_recorded.hpp)
//     deciding stale vs fresh                (oracle_recorded.hpp)
//     comparing and reporting                (observation.hpp -- done)
//
//   HOST FACILITY -- this file. Three members, nothing else:
//     run a program and collect its output
//     read a file / write a file
//     ask the host kernel its release
//
// So LiveOracle and RecordedOracle are each written exactly once, against this
// concept, and work on every host that can satisfy it. A host does not get its
// own oracle; it gets its own ProbeRunner, which is the only part that differs.
//
// WHAT BELONGS HERE. Only operations whose IMPLEMENTATION is host-specific,
// never policy. `run()` belongs: posix_spawn vs CreateProcess is
// irreplaceable. Parsing the output does NOT -- that is the same parser
// everywhere. The test for a new member is the one hostcalls.hpp uses: "would
// two correct hosts write different code here?" If no, it is policy and
// belongs beside judge().
#pragma once

#include <concepts>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace lx::conform {

// What a finished child process produced. Exit status and output travel
// together because a probe that died mid-way yields partial output, and
// judging that as a short trace would report a bogus step_count divergence
// instead of "the probe crashed".
struct ProbeOutput {
    int         exit_code{0};
    bool        timed_out{false};
    std::string stdout_text{};

    // A probe is only usable if it ran to completion. Checked by callers
    // before parsing, so a crash is never silently read as a trace.
    [[nodiscard]] bool completed() const noexcept {
        return !timed_out && exit_code == 0;
    }
};

// -- the contract ----------------------------------------------------------
//
// Every member is REQUIRED, as in hostcalls.hpp: there is no capability tier,
// because a host that cannot spawn a process or read a file cannot act as an
// oracle at all. A missing or misspelled member is a build error naming it,
// never a silent degradation.
template <class R>
concept ProbeRunner = requires(const R& r, std::string_view path,
                               std::span<const std::string> args,
                               std::string_view text) {
    // Run a program to completion with a deadline, capturing stdout. The
    // deadline is mandatory rather than optional because a hung probe is the
    // common failure (an interactive guest never exits) and an oracle that can
    // block forever is not usable in CI.
    { r.run(path, args, std::uint32_t{}) } -> std::same_as<ProbeOutput>;

    // Golden-trace storage. Text, not bytes: a recording is reviewed in diffs
    // and must be legible, which is a property of the FORMAT (policy) that
    // this facility merely persists.
    { r.read_file(path) }        -> std::same_as<std::optional<std::string>>;
    { r.write_file(path, text) } -> std::same_as<bool>;
};

// Reporting the host kernel's release is a CAPABILITY, not a core member:
// only a host running Linux has one to report. A recording carries it so a
// later divergence can be attributed to a kernel change rather than to
// linuxity -- the single most useful field when a golden goes stale.
template <class R>
concept KnowsKernelRelease = ProbeRunner<R> && requires(const R& r) {
    { r.kernel_release() } -> std::convertible_to<std::string>;
};

// Only a host with a real Linux kernel can produce a reference trace live.
// This is THE capability that divides the four targets, and naming it here --
// rather than testing for an OS macro at each use -- is what keeps the two
// oracles host-agnostic.
template <class R>
concept HasLinuxKernel = ProbeRunner<R> && requires(const R& r) {
    { r.linux_native() } -> std::convertible_to<bool>;
};

} // namespace lx::conform
