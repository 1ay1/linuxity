// linuxity/conform/host.hpp
//
// THE one place the conformance layer names a host.
//
// Every other file in conform/ is host-agnostic: the law, the trace format,
// both oracles, the scenarios. This header picks the ProbeRunner for the
// target and states, as types, what that host can verify. Nothing else may
// contain a platform #ifdef -- check_layout.sh enforces that -- so there is a
// single answer to "what does this host do", not one per use site.
//
//     host              runner              live oracle?   what runs
//     ----------------  ------------------  -------------  ----------------
//     Linux arm64       PosixProbeRunner    yes            Live + record
//     Linux x86-64      PosixProbeRunner    yes            Live + record
//     macOS arm64       PosixProbeRunner    no             Recorded
//     Windows x86-64    WindowsProbeRunner  no             Recorded
//
// Three of four share one runner, and all four share one comparison.
#pragma once

#include <string_view>

#include "linuxity/conform/oracles.hpp"
#include "linuxity/conform/probe_runner.hpp"

#if defined(_WIN32)
#include "linuxity/conform/runner_windows.hpp"
#else
#include "linuxity/conform/runner_posix.hpp"
#endif

namespace lx::conform {

#if defined(_WIN32)
using HostProbeRunner = WindowsProbeRunner;
#else
using HostProbeRunner = PosixProbeRunner;
#endif

static_assert(ProbeRunner<HostProbeRunner>,
              "this host's runner must satisfy the core contract");

// Whether a live Linux kernel can act as the oracle here. A compile-time
// constant, so a consumer selects an oracle with `if constexpr` and the
// unusable branch is never instantiated.
inline constexpr bool kHasLiveOracle =
#if defined(__linux__)
    true;
#else
    false;
#endif

// The oracle this host uses. LiveOracle is constrained on HasLinuxKernel, so
// naming it on macOS or Windows would be a compile error -- hence the
// conditional type rather than a runtime choice.
#if defined(__linux__)
using HostOracle = LiveOracle<HostProbeRunner>;
#else
using HostOracle = RecordedOracle<HostProbeRunner>;
#endif

static_assert(Oracle<HostOracle>, "this host's oracle must satisfy the contract");

// The honest summary of what this host verifies, as data. A runner prints it
// so "what did this host actually check" is answerable from the output rather
// than inferred from which CI job ran.
struct HostConformance {
    static constexpr bool live_oracle     = kHasLiveOracle;
    static constexpr bool can_record      = Records<HostOracle>;
    static constexpr bool replays_goldens = !kHasLiveOracle;

    [[nodiscard]] static constexpr std::string_view describe() noexcept {
        if constexpr (live_oracle)
            return "live Linux kernel oracle; can record goldens for other hosts";
        else
            return "no Linux kernel here; replaying goldens recorded on Linux";
    }
};

} // namespace lx::conform
