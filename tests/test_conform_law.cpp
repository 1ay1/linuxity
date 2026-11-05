// tests/test_conform_law.cpp
//
// The conformance LAW, tested on its own. Host-independent by construction:
// this file makes no syscalls and names no platform API, so it is one of the
// portable tests and runs identically on all four targets.
//
// Two things are checked here:
//   1. The law behaves -- agreement, divergence, exemptions, ordering.
//   2. The TYPES forbid the mistakes the design claims to forbid, via
//      static_asserts that would fail to compile if a guarantee regressed.
#include "linuxity/conform/observation.hpp"
#include "linuxity/conform/oracle.hpp"
#include "linuxity/conform/report.hpp"
#include "linuxity/conform/scenario.hpp"

#include <cerrno>
#include <cstdio>
#include <string>
#include <type_traits>

using namespace lx;
using namespace lx::conform;

namespace {

int failures = 0;

void check(bool cond, const char* what) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

// -- the type-level guarantees --------------------------------------------
//
// These are the design's actual claims. Each would become a compile error if
// someone "simplified" the types back into the shapes that hid bugs before.

// A Verdict must not be usable as a bool: the whole point is that a consumer
// is handed the explanation in the failing branch.
static_assert(!std::is_convertible_v<Verdict, bool>,
              "Verdict must not be convertible to bool -- consumers must "
              "match() so a divergence carries its explanation");

// A Divergence must not be default-constructible: a failure with no stated
// cause is the thing this design exists to prevent.
static_assert(!std::is_default_constructible_v<Divergence>,
              "Divergence must require index/field/both sides");

// Returned must not be constructible from a bare int: that is precisely the
// packed-register conflation (negative means -errno) the type unpacks once.
static_assert(!std::is_constructible_v<Returned, std::int64_t>,
              "Returned must be built via from_raw/ok/failed, never implicitly "
              "from an integer");

// Reference must not silently become an empty Trace on a host with no oracle.
static_assert(!std::is_default_constructible_v<Reference>,
              "Reference must be either a Trace or an Unavailable");

// Strict and the composed policy must satisfy Law. If a law forgets reason(),
// this is where it fails -- not at the call site, anonymously.
static_assert(Law<Strict>);
static_assert(Law<Exempt>);
static_assert(Law<decltype(universal_exemptions())>);

// The law's DECISION must be constexpr-evaluable: Exempt compares only a
// Sysno, so a policy can be folded at compile time. (Observation itself holds
// vectors and so is not a literal type -- the decision, not the observation,
// is what must be free.)
static_assert(Exempt{abi::Sysno::getpid, "pids differ"}.call() ==
              abi::Sysno::getpid);
static_assert(!Exempt{abi::Sysno::getpid, "pids differ"}.reason().empty());

// -- Returned: the unpacking is exact -------------------------------------

void returned_unpacks_the_kernel_convention() {
    // A plain success.
    check(Returned::from_raw(368) == Returned::ok(368), "raw 368 is ok(368)");

    // -EINVAL as the kernel encodes it.
    check(Returned::from_raw(-22) == Returned::failed(22), "raw -22 is EINVAL");

    // The boundary: -4095 is the most negative errno, -4096 is a value.
    check(!Returned::from_raw(-4095).is_ok(), "-4095 is still an errno");
    check(Returned::from_raw(-4096).is_ok(), "-4096 is a value, not an errno");

    // The bug class this prevents: an ok value and an errno that share a
    // bit pattern must never compare equal.
    check(!(Returned::ok(-22) == Returned::failed(22)),
          "ok(-22) and failed(22) are different observations");

    // mmap returning a high address must not look like a failure.
    check(Returned::from_raw(static_cast<std::int64_t>(0x7fff'0000'0000)).is_ok(),
          "a high mmap address is a success");
}

// -- judge(): agreement and divergence ------------------------------------

Trace trace_of(std::string name, std::initializer_list<Observation> steps) {
    Trace t{std::move(name)};
    for (const Observation& o : steps) t.steps.push_back(o);
    return t;
}

void identical_traces_agree() {
    const auto a = trace_of("x", {Observation{abi::Sysno::lseek, Returned::ok(368)}});
    const auto b = trace_of("x", {Observation{abi::Sysno::lseek, Returned::ok(368)}});

    const Verdict v = judge(a, b);
    check(v.agreed(), "identical traces agree");
    v.match([](Match m) { check(m.steps_compared == 1, "compared one step"); },
            [](const Divergence&) { check(false, "unexpected divergence"); });
}

// THE REGRESSION. This is the real lseek bug, as a law-level test: the guest
// returned an entry index where the kernel returns a byte offset.
void the_lseek_cookie_bug_is_a_divergence() {
    const auto native = trace_of(
        "dirseek-proc",
        {Observation{abi::Sysno::lseek, Returned::ok(368)}.labelled("lseek(SEEK_CUR,0)")});
    const auto guest = trace_of(
        "dirseek-proc",
        {Observation{abi::Sysno::lseek, Returned::ok(13)}.labelled("lseek(SEEK_CUR,0)")});

    const Verdict v = judge(native, guest);
    check(!v.agreed(), "368 vs 13 is a divergence");

    v.match([](Match) { check(false, "the cookie bug must not agree"); },
            [](const Divergence& d) {
                check(d.field == Divergence::Field::returned, "field is returned");
                check(d.native == "368" && d.guest == "13",
                      "both sides are reported");
                check(d.note == "lseek(SEEK_CUR,0)", "the label is carried");
            });
}

// The OTHER half of the same bug: EINVAL where the kernel succeeded. An
// errno-vs-value difference must be caught, not coerced.
void einval_versus_success_diverges() {
    const auto native = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(266)}});
    const auto guest  = trace_of("s", {Observation{abi::Sysno::lseek, Returned::failed(EINVAL)}});

    const Verdict v = judge(native, guest);
    check(!v.agreed(), "ok vs EINVAL is a divergence");
    v.match([](Match) { check(false, "must diverge"); },
            [](const Divergence& d) {
                check(d.guest == "-EINVAL", "errno renders by name");
            });
}

void written_buffers_are_compared() {
    auto mk = [](std::byte last) {
        return Observation{abi::Sysno::getdents64, Returned::ok(3)}.writing(
            Written{1, {std::byte{'a'}, std::byte{'b'}, last}});
    };
    const auto native = trace_of("s", {mk(std::byte{'c'})});
    const auto guest  = trace_of("s", {mk(std::byte{'X'})});

    const Verdict v = judge(native, guest);
    check(!v.agreed(), "differing buffer contents diverge");
    v.match([](Match) { check(false, "must diverge"); },
            [](const Divergence& d) {
                check(d.field == Divergence::Field::written, "field is written");
            });
}

void call_identity_is_checked_before_results() {
    // Same return, different syscall: must report the identity, not the value.
    const auto native = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(0)}});
    const auto guest  = trace_of("s", {Observation{abi::Sysno::close, Returned::ok(0)}});

    judge(native, guest).match(
        [](Match) { check(false, "different syscalls must diverge"); },
        [](const Divergence& d) {
            check(d.field == Divergence::Field::call_identity, "identity first");
            check(d.native == "lseek" && d.guest == "close",
                  "syscalls render by name");
        });
}

void extra_steps_diverge() {
    const auto native = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(0)},
                                       Observation{abi::Sysno::close, Returned::ok(0)}});
    const auto guest  = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(0)}});

    judge(native, guest).match(
        [](Match) { check(false, "a missing call must diverge"); },
        [](const Divergence& d) {
            check(d.field == Divergence::Field::step_count, "step count differs");
            check(d.native == "2" && d.guest == "1", "both counts reported");
        });
}

// A divergence must point at the FIRST difference, since later steps are
// downstream of it.
void the_first_divergence_wins() {
    const auto native = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(1)},
                                       Observation{abi::Sysno::lseek, Returned::ok(2)}});
    const auto guest  = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(9)},
                                       Observation{abi::Sysno::lseek, Returned::ok(8)}});

    judge(native, guest).match(
        [](Match) { check(false, "must diverge"); },
        [](const Divergence& d) { check(d.index == 0, "reports the first"); });
}

// -- exemptions ------------------------------------------------------------

void exempt_calls_may_differ() {
    const auto native = trace_of("s", {Observation{abi::Sysno::getpid, Returned::ok(1000)}});
    const auto guest  = trace_of("s", {Observation{abi::Sysno::getpid, Returned::ok(2000)}});

    check(!judge(native, guest).agreed(), "strict law rejects differing pids");
    check(judge(native, guest, universal_exemptions()).agreed(),
          "the universal law exempts getpid");
}

// An exemption must be narrow: exempting getpid must not excuse lseek.
void exemptions_do_not_leak() {
    const auto native = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(368)}});
    const auto guest  = trace_of("s", {Observation{abi::Sysno::lseek, Returned::ok(13)}});

    check(!judge(native, guest, universal_exemptions()).agreed(),
          "exempting getpid must not excuse lseek");
}

// Every exemption must state a reason -- enforced by the Law concept, checked
// here as a value so an empty reason cannot slip through.
void every_exemption_states_a_reason() {
    constexpr Exempt e{abi::Sysno::getpid, "two processes have different pids"};
    check(!e.reason().empty(), "an exemption has a non-empty reason");
}

// -- scenarios -------------------------------------------------------------

void scenarios_are_declared_once_and_distinctly() {
    const auto all = all_scenarios();
    check(!all.empty(), "the registry is non-empty");

    for (const Scenario& s : all) {
        check(!s.name.empty(), "every scenario is named");
        check(!s.probe.empty(), "every scenario names a probe");
        check(!s.expects.empty(), "every scenario says what it exercises");
    }

    // Keys must be unique, or two scenarios would share one golden trace.
    for (std::size_t i = 0; i < all.size(); ++i)
        for (std::size_t j = i + 1; j < all.size(); ++j)
            check(all[i].key() != all[j].key(),
                  "scenario keys are unique (goldens would collide)");
}

// The flavour distinction is load-bearing: the lseek bug was invisible on
// host-backed directories. If the registry ever covers only those, the suite
// is back to testing the forwarded path and nothing else.
void the_registry_covers_virtualised_directories() {
    bool saw_virtual = false;
    for (const Scenario& s : all_scenarios())
        if (s.flavour == DirFlavour::virtualised) saw_virtual = true;

    check(saw_virtual,
          "at least one scenario must exercise a VIRTUALISED directory -- "
          "host-backed ones forward to the kernel and cannot catch a "
          "virtual-dir bug");
}

// -- the oracle contract ---------------------------------------------------

// A stub oracle, to prove the concept is satisfiable without a Linux kernel --
// which is the macOS/Windows case.
struct StubOracle {
    [[nodiscard]] Reference reference_for(std::string_view) const {
        return Unavailable{Unavailable::Cause::no_live_kernel, "stub"};
    }
    [[nodiscard]] std::string_view provenance() const { return "stub"; }
    [[nodiscard]] bool usable() const { return false; }
};
static_assert(Oracle<StubOracle>, "the stub must satisfy the core contract");
static_assert(!Records<StubOracle>, "a stub cannot record goldens");

// An oracle that MISSPELLS a core member must fail the concept, rather than
// silently providing no reference. This is the backend.hpp lesson applied.
struct TypoOracle {
    [[nodiscard]] Reference reference_fro(std::string_view) const;  // typo
    [[nodiscard]] std::string_view provenance() const;
    [[nodiscard]] bool usable() const;
};
static_assert(!Oracle<TypoOracle>,
              "a misspelled core member must fail the Oracle concept");

void unavailable_is_not_a_pass() {
    const StubOracle o;
    const Reference r = o.reference_for("anything");
    check(!r.available(), "a stub oracle reports unavailable");

    // The guarantee: an unavailable reference cannot be mistaken for a pass.
    bool treated_as_pass = false;
    r.match([&](const Trace&) { treated_as_pass = true; },
            [&](const Unavailable& u) {
                check(u.cause == Unavailable::Cause::no_live_kernel,
                      "the cause is reported");
            });
    check(!treated_as_pass, "unavailable must never render as agreement");
}

} // namespace

int main() {
    returned_unpacks_the_kernel_convention();
    identical_traces_agree();
    the_lseek_cookie_bug_is_a_divergence();
    einval_versus_success_diverges();
    written_buffers_are_compared();
    call_identity_is_checked_before_results();
    extra_steps_diverge();
    the_first_divergence_wins();
    exempt_calls_may_differ();
    exemptions_do_not_leak();
    every_exemption_states_a_reason();
    scenarios_are_declared_once_and_distinctly();
    the_registry_covers_virtualised_directories();
    unavailable_is_not_a_pass();

    if (failures == 0)
        std::puts("conform_law: the law agrees, diverges, exempts narrowly, "
                  "and refuses to call an unavailable oracle a pass");
    return failures ? 1 : 0;
}
