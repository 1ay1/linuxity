// linuxity/conform/scenario.hpp
//
// WHAT to test, written ONCE for all four hosts.
//
// A Scenario is a named syscall sequence plus the law it is judged under. It
// is pure data and pure description: it performs no syscalls itself and names
// no platform API, so the same scenario list compiles on Linux arm64, Linux
// x86-64, macOS arm64 and Windows x86-64.
//
// THE DRY CLAIM, CONCRETELY. A scenario is authored once and is then:
//   * executed under linuxity, on every host, to produce the guest Trace;
//   * executed natively on Linux hosts, to produce the reference Trace;
//   * recorded on Linux CI into a golden, replayed on macOS/Windows;
//   * judged by the SAME judge() with the SAME law, everywhere.
// Nothing about the scenario changes between those uses, which is why there is
// exactly one place to add a test and one place that defines agreement.
//
// WHY SCENARIOS ARE DATA, NOT FUNCTIONS. The obvious encoding is a C++ lambda
// that makes the calls. But the reference run has to happen in a *separate
// native process*, and on macOS/Windows it happened months ago on another
// machine -- neither can call back into a lambda in this address space. So a
// scenario names a PROBE (a tiny self-contained program) and the steps it is
// expected to perform. The probe is the only thing that crosses the process
// boundary, and its output is parsed back into a Trace.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "linuxity/abi/sysno.hpp"
#include "linuxity/conform/observation.hpp"

namespace lx::conform {

// Which directory flavour a scenario exercises. The lseek bug lived entirely
// in the gap between these: /usr/bin forwards to the host kernel and was
// always correct, while /proc and /sys go through linuxity's own virtual
// directory streams and were not. A scenario states which it means, so
// "we tested directories" can never again mean "we tested the forwarded one".
enum class DirFlavour : std::uint8_t {
    host_backed,  // a real host directory, forwarded
    virtualised,  // procfs/sysfs, synthesized by linuxity
    overlaid,     // a merged lower+upper union
};

[[nodiscard]] constexpr std::string_view
flavour_name(DirFlavour f) noexcept {
    switch (f) {
        case DirFlavour::host_backed: return "host-backed";
        case DirFlavour::virtualised: return "virtualised";
        case DirFlavour::overlaid:    return "overlaid";
    }
    return "<unknown flavour>";
}

// A scenario: a name, the probe that performs it, and the arguments that
// select the case. `expects` names the syscalls the probe is supposed to
// exercise -- not an assertion about results (that would be the opinion about
// Linux we refuse to encode) but a guard that the probe still does what its
// name claims after someone edits it.
struct Scenario {
    std::string_view              name;
    std::string_view              probe;     // probe program, e.g. "dirseek"
    std::vector<std::string>      args{};
    std::vector<abi::Sysno>       expects{};
    DirFlavour                    flavour{DirFlavour::host_backed};

    Scenario(std::string_view n, std::string_view p) : name{n}, probe{p} {}

    [[nodiscard]] Scenario&& with(std::string a) && {
        args.push_back(std::move(a));
        return std::move(*this);
    }
    [[nodiscard]] Scenario&& exercising(abi::Sysno s) && {
        expects.push_back(s);
        return std::move(*this);
    }
    [[nodiscard]] Scenario&& on(DirFlavour f) && {
        flavour = f;
        return std::move(*this);
    }

    // A stable identity for the golden-trace filename. Derived, never stored,
    // so a renamed scenario cannot keep silently matching an old recording.
    [[nodiscard]] std::string key() const;
};

// -- the registry ----------------------------------------------------------
//
// Declared in report.hpp (header-only, so the portable test set needs no
// compiled library). THE one place scenarios are listed: every host, oracle
// and runner reads it, none of them keeps its own.

} // namespace lx::conform
