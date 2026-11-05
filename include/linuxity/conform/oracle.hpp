// linuxity/conform/oracle.hpp
//
// WHERE the reference trace comes from. The host-dependent half of
// differential conformance; observation.hpp holds the host-independent law.
//
// THE PROBLEM THIS FILE SOLVES. linuxity targets four hosts:
//
//     Linux arm64      Linux kernel present -> it can BE the oracle
//     Linux x86-64     Linux kernel present -> it can BE the oracle
//     macOS arm64      no Linux kernel      -> nothing to compare against
//     Windows x86-64   no Linux kernel      -> nothing to compare against
//
// "Run it natively and diff" is therefore a CAPABILITY, not a universal. Bake
// fork+execve into the core contract and the harness builds on Linux only,
// while macOS and Windows either fail to compile or -- far worse -- pass
// vacuously, reporting conformance they never checked. That is exactly the
// `else { forward(); }` failure mode runtime/backend.hpp exists to prevent, so
// this file borrows its two-tier shape:
//
//   * Oracle        -- the CORE every oracle must satisfy. No fallback; a
//                      missing or mistyped member is a build error naming it.
//   * Capabilities  -- named concepts for what only SOME oracles can do
//                      (regenerating goldens needs a live kernel). A consumer
//                      asks by name, so a typo breaks the check instead of
//                      silently taking a wrong branch.
//
// DRY/SSOT. Scenarios are written ONCE against the Oracle concept (see
// scenario.hpp) and the comparison is written once in judge(). A host swaps
// only the oracle: a live kernel on Linux, a checked-in recording elsewhere.
// Neither the scenarios nor the law know which they got.
#pragma once

#include <concepts>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "linuxity/conform/observation.hpp"

namespace lx::conform {

// Why a scenario could not be judged on this host. Distinct from a Divergence:
// "we could not check" must never render as "we checked and it agreed", which
// is the vacuous pass this whole file is arranged to make impossible.
struct Unavailable {
    enum class Cause : std::uint8_t {
        no_live_kernel,  // host is not Linux; nothing native to run
        no_recording,    // no golden trace checked in for this scenario
        stale_recording, // the golden predates the scenario's current shape
        probe_failed,    // the probe binary could not be built or run
    };

    Cause       cause;
    std::string detail;

    Unavailable(Cause c, std::string d) : cause{c}, detail{std::move(d)} {}

    [[nodiscard]] static constexpr std::string_view
    cause_name(Cause c) noexcept {
        switch (c) {
            case Cause::no_live_kernel:  return "no live Linux kernel on this host";
            case Cause::no_recording:    return "no recorded golden trace";
            case Cause::stale_recording: return "recorded trace is stale";
            case Cause::probe_failed:    return "probe could not be run";
        }
        return "<unknown cause>";
    }

    [[nodiscard]] std::string describe() const;
};

// An oracle yields a reference trace, or says why it cannot. A SUM again:
// Trace | Unavailable, so "no oracle here" is a value the caller must handle
// rather than an empty trace that silently compares equal to everything.
class Reference {
public:
    Reference(Trace t) : v_{std::move(t)} {}
    Reference(Unavailable u) : v_{std::move(u)} {}

    template <class OnTrace, class OnUnavailable>
    [[nodiscard]] decltype(auto) match(OnTrace&& t, OnUnavailable&& u) const {
        if (const auto* tr = std::get_if<Trace>(&v_))
            return std::forward<OnTrace>(t)(*tr);
        return std::forward<OnUnavailable>(u)(std::get<Unavailable>(v_));
    }

    [[nodiscard]] bool available() const noexcept {
        return std::holds_alternative<Trace>(v_);
    }

private:
    std::variant<Trace, Unavailable> v_;
};

// -- the core contract -----------------------------------------------------

// Every oracle must provide ALL of this, on every host. No fallback, so a
// backend that misspells `reference_for` fails to build rather than quietly
// producing nothing to compare against.
template <class O>
concept Oracle = requires(const O& o, std::string_view scenario) {
    // The reference trace for a named scenario, or why there isn't one.
    { o.reference_for(scenario) } -> std::same_as<Reference>;
    // How this oracle got its answer, for the report header. Mandatory: a
    // conformance result is not interpretable without knowing whether the
    // reference came from a live kernel or a six-month-old recording.
    { o.provenance() }            -> std::convertible_to<std::string_view>;
    // Whether this oracle can judge at all on this host. Lets a runner print
    // "skipped: no live kernel" instead of a misleading pass.
    { o.usable() }                -> std::convertible_to<bool>;
};

// -- the capabilities ------------------------------------------------------

// Only an oracle backed by a real Linux kernel can CREATE a golden trace.
// This is the capability that makes the cross-host story work: Linux CI
// records, macOS and Windows replay.
template <class O>
concept Records = Oracle<O> && requires(O& o, std::string_view scenario) {
    { o.record(scenario) } -> std::same_as<Reference>;
};

// An oracle that can report the kernel it spoke to, so a recording carries the
// version that produced it and a divergence can be attributed to a kernel
// change rather than to linuxity.
template <class O>
concept KnowsKernel = Oracle<O> && requires(const O& o) {
    { o.kernel_release() } -> std::convertible_to<std::string_view>;
};

// The honest summary, as data -- mirroring runtime::Capabilities. A runner
// prints this so "what did this host actually verify" is answerable.
template <class O>
struct OracleCapabilities {
    static constexpr bool records       = Records<O>;
    static constexpr bool knows_kernel  = KnowsKernel<O>;
};

} // namespace lx::conform
