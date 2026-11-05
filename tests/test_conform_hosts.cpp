// tests/test_conform_hosts.cpp
//
// The HOST layer: the trace format, both oracles, and the per-host selection.
//
// The oracles are generic over ProbeRunner, so they are tested here against a
// FAKE runner -- no process spawning, no filesystem. That is the point of the
// seam: the policy (which is all of them) is testable without a host.
#include "linuxity/conform/host.hpp"
#include "linuxity/conform/oracles.hpp"
#include "linuxity/conform/report.hpp"
#include "linuxity/conform/trace_text.hpp"

#include <cerrno>
#include <cstdio>
#include <map>
#include <string>

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

// -- a fake runner ---------------------------------------------------------
//
// Satisfies the whole contract in memory. Because every oracle is generic over
// ProbeRunner, this exercises all the real policy -- staleness, parse-failure
// handling, golden paths -- with no host involvement at all.
class FakeRunner {
public:
    std::string                        probe_stdout{};
    int                                probe_exit{0};
    bool                               probe_timeout{false};
    bool                               is_linux{true};
    mutable std::map<std::string, std::string> files{};
    mutable int                        runs{0};

    [[nodiscard]] ProbeOutput run(std::string_view, std::span<const std::string>,
                                  std::uint32_t) const {
        ++runs;
        ProbeOutput o;
        o.stdout_text = probe_stdout;
        o.exit_code = probe_exit;
        o.timed_out = probe_timeout;
        return o;
    }
    [[nodiscard]] std::optional<std::string> read_file(std::string_view p) const {
        const auto it = files.find(std::string{p});
        if (it == files.end()) return std::nullopt;
        return it->second;
    }
    [[nodiscard]] bool write_file(std::string_view p, std::string_view t) const {
        files[std::string{p}] = std::string{t};
        return true;
    }
    [[nodiscard]] bool linux_native() const { return is_linux; }
    [[nodiscard]] std::string kernel_release() const { return "Linux 6.6.0-test"; }
};

static_assert(ProbeRunner<FakeRunner>);
static_assert(HasLinuxKernel<FakeRunner>);
static_assert(KnowsKernelRelease<FakeRunner>);

// A runner missing a core member must FAIL the concept -- the backend.hpp
// lesson: a typo cannot silently degrade into "no reference".
struct TypoRunner {
    [[nodiscard]] ProbeOutput ruu(std::string_view, std::span<const std::string>,
                                  std::uint32_t) const;  // typo
    [[nodiscard]] std::optional<std::string> read_file(std::string_view) const;
    [[nodiscard]] bool write_file(std::string_view, std::string_view) const;
};
static_assert(!ProbeRunner<TypoRunner>,
              "a misspelled run() must fail the ProbeRunner concept");

OraclePaths paths() { return OraclePaths{"/probes", "/goldens"}; }

// The scenario a test means, by name.
[[nodiscard]] std::optional<Scenario> find(std::string_view name) {
    for (const Scenario& s : all_scenarios())
        if (s.name == name) return s;
    return std::nullopt;
}

// -- the trace format ------------------------------------------------------

void a_trace_round_trips() {
    Trace t{"dirseek-proc"};
    t.steps.push_back(
        Observation{abi::Sysno::getdents64, Returned::ok(384)}.labelled("first"));
    t.steps.push_back(Observation{abi::Sysno::lseek, Returned::ok(368)});
    t.steps.push_back(Observation{abi::Sysno::lseek, Returned::failed(EINVAL)});
    t.steps.push_back(
        Observation{abi::Sysno::read, Returned::ok(3)}.writing(
            Written{1, {std::byte{0xde}, std::byte{0xad}, std::byte{0x00}}}));

    const std::string text = render_trace(t, "unit test", "Linux 6.6");

    // THE property that makes one format safe for both directions: what the
    // renderer writes, the parser reads back identically. If this holds, a
    // golden is indistinguishable from a live run.
    parse_trace(text, "dirseek-proc")
        .match(
            [&](const Trace& back) {
                check(back.steps.size() == t.steps.size(), "round-trip keeps steps");
                const Verdict v = judge(t, back);
                check(v.agreed(), "a rendered trace parses back identically");
            },
            [](const ParseError& e) {
                std::fprintf(stderr, "  parse error: %s\n", e.describe().c_str());
                check(false, "a rendered trace must parse");
            });
}

void errno_names_survive_the_round_trip() {
    // The renderer spells errnos by name; the parser must map them back to the
    // same number, or a golden would compare unequal to the run that made it.
    for (const std::int32_t e : {EPERM, ENOENT, EBADF, EINVAL, ENOSYS, ESPIPE}) {
        Trace t{"s"};
        t.steps.push_back(Observation{abi::Sysno::lseek, Returned::failed(e)});
        parse_trace(render_trace(t), "s")
            .match([&](const Trace& back) {
                       check(judge(t, back).agreed(), "errno round-trips by name");
                   },
                   [](const ParseError&) { check(false, "errno must parse"); });
    }
}

void a_negative_return_is_not_an_errno() {
    // -4096 and beyond are legitimate values. If the parser treated every
    // negative as an errno, this would silently become a failure.
    Trace t{"s"};
    t.steps.push_back(Observation{abi::Sysno::lseek, Returned::ok(-4096)});
    parse_trace(render_trace(t), "s")
        .match([&](const Trace& back) {
                   check(judge(t, back).agreed(), "a large negative stays a value");
               },
               [](const ParseError&) { check(false, "must parse"); });
}

void a_malformed_golden_is_an_error_not_an_empty_trace() {
    parse_trace("lseek 368\n", "s")   // missing '='
        .match([](const Trace&) { check(false, "malformed input must not parse"); },
               [](const ParseError& e) {
                   check(e.line == 1, "the failing line is reported");
               });

    parse_trace("notasyscall = 1\n", "s")
        .match([](const Trace&) { check(false, "unknown syscall must not parse"); },
               [](const ParseError& e) {
                   check(e.reason.find("unknown syscall") != std::string::npos,
                         "the reason names the problem");
               });
}

// -- the live oracle -------------------------------------------------------

void the_live_oracle_parses_probe_output() {
    FakeRunner r;
    r.probe_stdout = "getdents64 = 384\nlseek = 368\n";
    const LiveOracle<FakeRunner> o{r, paths()};

    check(o.usable(), "a Linux runner yields a usable live oracle");
    o.reference_for("dirseek-proc")
        .match([](const Trace& t) { check(t.steps.size() == 2, "both steps parsed"); },
               [](const Unavailable& u) {
                   std::fprintf(stderr, "  unavailable: %s\n", u.describe().c_str());
                   check(false, "the live oracle should have produced a trace");
               });
}

// A crashed or hung probe must NOT become a short trace -- that would report a
// bogus step_count divergence instead of "the probe failed".
void a_failed_probe_is_unavailable_not_a_short_trace() {
    FakeRunner r;
    r.probe_stdout = "getdents64 = 384\n";
    r.probe_exit = 1;
    const LiveOracle<FakeRunner> crashed{r, paths()};
    crashed.reference_for("dirseek-proc")
        .match([](const Trace&) { check(false, "a crashed probe must not parse"); },
               [](const Unavailable& u) {
                   check(u.cause == Unavailable::Cause::probe_failed,
                         "a crash reports probe_failed");
               });

    FakeRunner h;
    h.probe_stdout = "getdents64 = 384\n";
    h.probe_timeout = true;
    const LiveOracle<FakeRunner> hung{h, paths()};
    hung.reference_for("dirseek-proc")
        .match([](const Trace&) { check(false, "a hung probe must not parse"); },
               [](const Unavailable& u) {
                   check(u.cause == Unavailable::Cause::probe_failed,
                         "a timeout reports probe_failed");
               });
}

void unparsable_output_is_unavailable() {
    FakeRunner r;
    r.probe_stdout = "this is not a trace\n";
    const LiveOracle<FakeRunner> o{r, paths()};
    o.reference_for("dirseek-proc")
        .match([](const Trace&) { check(false, "garbage must not parse"); },
               [](const Unavailable& u) {
                   check(u.cause == Unavailable::Cause::probe_failed,
                         "unparsable output is reported, not ignored");
               });
}

// -- recording, then replaying: the cross-host path ------------------------

void linux_records_and_another_host_replays() {
    // Linux CI records.
    FakeRunner linux;
    linux.probe_stdout = "getdents64 = 384\nlseek = 368\n";
    const LiveOracle<FakeRunner> live{linux, paths()};
    check(live.record("dirseek-proc").available(), "recording succeeded");
    check(!linux.files.empty(), "recording wrote a golden");

    // A host with no Linux kernel replays the same bytes.
    FakeRunner mac;
    mac.is_linux = false;
    mac.files = linux.files;        // the checked-in golden
    const RecordedOracle<FakeRunner> recorded{mac, paths()};

    check(recorded.usable(), "the recorded oracle is usable without a kernel");
    recorded.reference_for("dirseek-proc")
        .match(
            [&](const Trace& replayed) {
                check(replayed.steps.size() == 2, "the golden replays");
                check(recorded.provenance().find("recorded") != std::string_view::npos,
                      "provenance says the reference was recorded");

                // THE cross-host guarantee: the replayed reference judges a
                // guest trace exactly as the live kernel would have.
                Trace guest{"dirseek-proc"};
                guest.steps.push_back(
                    Observation{abi::Sysno::getdents64, Returned::ok(384)});
                guest.steps.push_back(
                    Observation{abi::Sysno::lseek, Returned::ok(13)});  // the bug
                check(!judge(replayed, guest).agreed(),
                      "a replayed golden still catches the lseek cookie bug");
            },
            [](const Unavailable& u) {
                std::fprintf(stderr, "  unavailable: %s\n", u.describe().c_str());
                check(false, "the golden should have replayed");
            });
}

void a_missing_golden_is_not_a_pass() {
    FakeRunner mac;
    mac.is_linux = false;          // no goldens at all
    const RecordedOracle<FakeRunner> o{mac, paths()};

    o.reference_for("dirseek-proc")
        .match([](const Trace&) { check(false, "there is no golden to return"); },
               [](const Unavailable& u) {
                   check(u.cause == Unavailable::Cause::no_recording,
                         "a missing golden reports no_recording");
                   check(u.detail.find("record one") != std::string::npos,
                         "the message says how to fix it");
               });
}

// A golden that no longer exercises what its scenario claims is STALE, which
// is a different problem from linuxity having a bug.
void a_stale_golden_is_distinguished_from_a_divergence() {
    FakeRunner r;
    const Scenario target = [] {
        for (const Scenario& s : all_scenarios())
            if (s.name == "dirseek-proc") return s;
        return Scenario{"missing", "none"};
    }();

    // A golden with only getdents64, though the scenario also exercises lseek.
    r.files[paths().golden(target)] = "getdents64 = 384\n";
    const RecordedOracle<FakeRunner> o{r, paths()};

    o.reference_for("dirseek-proc")
        .match([](const Trace&) { check(false, "a stale golden must be rejected"); },
               [](const Unavailable& u) {
                   check(u.cause == Unavailable::Cause::stale_recording,
                         "a golden missing an exercised syscall is stale");
               });
}

// -- the guest-ABI axis ----------------------------------------------------
//
// Orthogonal to the host axis: a macOS arm64 host replays an aarch64 golden
// while Linux x86-64 records an x86-64 one. These tests cover the failure
// that adding a Linux arm64 job would otherwise cause.

void goldens_are_per_arch() {
    const Scenario s = *find("dirseek-proc");

    const OraclePaths x{"/probes", "/goldens", abi::Arch::x86_64};
    const OraclePaths a{"/probes", "/goldens", abi::Arch::aarch64};

    // THE bug this prevents: without the arch in the path, a Linux arm64 CI
    // job overwrites the x86-64 goldens and macOS replays whichever ran last.
    check(x.golden(s) != a.golden(s),
          "an x86-64 and an aarch64 golden must not share a path");
    check(x.golden(s).find("x86_64") != std::string::npos,
          "the x86-64 golden path names its arch");
    check(a.golden(s).find("aarch64") != std::string::npos,
          "the aarch64 golden path names its arch");
}

// Adding Linux arm64 must need NO new conformance code: it is the same POSIX
// runner and the same live oracle, with only the arch tag differing.
void adding_linux_arm64_needs_no_new_code() {
    FakeRunner arm;           // a Linux host, as arm64 would be
    arm.probe_stdout = "getdents64 = 384\nlseek = 368\n";

    const OraclePaths p{"/probes", "/goldens", abi::Arch::aarch64};
    const LiveOracle<FakeRunner> live{arm, p};   // same template, no new type

    check(live.usable(), "a Linux arm64 host has a live oracle");
    check(live.record("dirseek-proc").available(), "and can record goldens");

    // The recording lands under its own arch, so both Linux jobs coexist.
    bool under_aarch64 = false;
    for (const auto& [path, _] : arm.files)
        if (path.find("aarch64") != std::string::npos) under_aarch64 = true;
    check(under_aarch64, "an arm64 recording is stored under aarch64/");

    // And the stamped header records the ABI, so a reader can tell.
    for (const auto& [_, body] : arm.files)
        check(body.find("# arch: aarch64") != std::string::npos,
              "the golden header states the ABI it was recorded for");
}

// A golden from the wrong ABI must be rejected, not judged. 56 syscalls exist
// on x86-64 and not on aarch64, so judging one against the other would report
// ABI differences as linuxity bugs.
void a_cross_arch_golden_is_rejected() {
    const Scenario s = *find("dirseek-proc");
    FakeRunner r;

    // An x86-64 trace (it uses `open`, which aarch64 does not have) placed
    // where the aarch64 oracle will look.
    const OraclePaths a{"/probes", "/goldens", abi::Arch::aarch64};
    r.files[a.golden(s)] = "open = 3\ngetdents64 = 384\nlseek = 368\n";

    const RecordedOracle<FakeRunner> o{r, a};
    o.reference_for("dirseek-proc")
        .match([](const Trace&) {
                   check(false, "a golden using x86-64-only syscalls must not "
                                "be judged on aarch64");
               },
               [](const Unavailable& u) {
                   check(u.cause == Unavailable::Cause::stale_recording,
                         "a cross-arch golden is reported as stale");
               });
}

// The ABI difference is real, not hypothetical -- asserted here as a value so
// the motivation for all of the above stays visible.
void the_two_linux_abis_genuinely_differ() {
    check(arch_has(abi::Arch::x86_64, abi::Sysno::open),
          "x86-64 has open");
    check(!arch_has(abi::Arch::aarch64, abi::Sysno::open),
          "aarch64 has openat only");
    check(arch_has(abi::Arch::x86_64, abi::Sysno::lseek) &&
              arch_has(abi::Arch::aarch64, abi::Sysno::lseek),
          "lseek exists on both, so dirseek is valid on either");
}

// -- the host selection ----------------------------------------------------

void this_host_states_what_it_verifies() {
    static_assert(ProbeRunner<HostProbeRunner>);
    static_assert(Oracle<HostOracle>);

    check(!HostConformance::describe().empty(), "the host describes itself");

    // Exactly one of the two paths must be in force -- never both, never
    // neither, which is how a host would end up verifying nothing.
    check(HostConformance::live_oracle != HostConformance::replays_goldens,
          "a host either has a live oracle or replays goldens, never both");

    // Only a live-oracle host can record. If this ever became true on
    // macOS/Windows it would mean goldens were being written from a
    // non-Linux reference, which is worse than having none.
    check(HostConformance::can_record == HostConformance::live_oracle,
          "only a host with a live Linux kernel may record goldens");
}

} // namespace

int main() {
    a_trace_round_trips();
    errno_names_survive_the_round_trip();
    a_negative_return_is_not_an_errno();
    a_malformed_golden_is_an_error_not_an_empty_trace();
    the_live_oracle_parses_probe_output();
    a_failed_probe_is_unavailable_not_a_short_trace();
    unparsable_output_is_unavailable();
    linux_records_and_another_host_replays();
    a_missing_golden_is_not_a_pass();
    a_stale_golden_is_distinguished_from_a_divergence();
    goldens_are_per_arch();
    adding_linux_arm64_needs_no_new_code();
    a_cross_arch_golden_is_rejected();
    the_two_linux_abis_genuinely_differ();
    this_host_states_what_it_verifies();

    if (failures == 0)
        std::printf("conform_hosts: one trace format round-trips, both oracles "
                    "work over a fake runner, goldens replay across hosts; "
                    "this host: %s\n",
                    std::string{HostConformance::describe()}.c_str());
    return failures ? 1 : 0;
}
