// linuxity/conform/observation.hpp
//
// The algebra of DIFFERENTIAL syscall conformance: what it means for two runs
// of the same scenario to AGREE.
//
// WHY DIFFERENTIAL. A conformance test cannot assert what Linux "should" do:
// there is no formal spec, and a hand-written belief about the kernel is
// routinely false. We shipped one -- a test asserted telldir() returns to its
// saved cookie after a relative lseek; POSIX implies it, the real kernel
// returns 18 where the test wanted 1. Worse, the old coverage-style
// conformance test (every syscall decodes, every syscall is handled by name)
// stayed green through a real bug where lseek on a virtual directory returned
// an entry index (13) where Linux returns a byte offset (368). Coverage is
// necessarily true and says nothing about correctness.
//
// So the reference is a REAL Linux kernel, and no file in conform/ encodes an
// opinion about what a syscall does.
//
// THE CENTRAL SPLIT. linuxity targets Linux arm64/x86-64, macOS arm64 and
// Windows x86-64. On the two Linux hosts a Linux kernel is available to be the
// oracle; on macOS and Windows one does not exist. If "compare against the
// live kernel" were part of the core contract, the harness would build only on
// Linux and the other hosts would get a vacuous pass -- the same silent
// wrong-answer failure runtime/backend.hpp was written to eliminate.
//
// So two things that were conflated are separated:
//
//   * The LAW -- what agreement MEANS. Host-independent, pure, constexpr.
//     Compiles and behaves identically on all four targets. Lives here.
//   * The ORACLE -- where the reference trace COMES FROM. Host-dependent, and
//     therefore a named capability, not a universal. Lives in oracle.hpp.
//
// That is the SSOT: the comparison engine is written once, and every host
// reuses it whether its reference trace came from a live kernel or a recording.
//
// Three types carry the law:
//
//     Observation  - a PRODUCT: everything one syscall produced.
//     Verdict      = Match | Divergence        (a SUM, never a bool)
//     Law          - a concept: which fields two Observations may differ in.
//
// WHY VERDICT IS A SUM. `bool equal(a, b)` discards the only interesting
// information: WHAT differed. A false says a test failed; a Divergence says
// "step 1 lseek: native 368, guest 13". The sum makes the explanation
// mandatory -- Divergence has no default constructor, so a failing verdict
// cannot be built without naming both sides.
//
// WHY LAW IS A CONCEPT. Some results legitimately differ between two runs:
// pids, timestamps, random bytes, address-space layout. The naive fix is an
// `if` in the comparator, which buries policy in control flow and makes "why
// is this field exempt" unanswerable. A Law is a value with a stated reason,
// so every exemption is declared, greppable and attributable.
#pragma once

#include <algorithm>
#include <cerrno>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "linuxity/abi/sysno.hpp"
#include "linuxity/conform/sysno_names.hpp"

namespace lx::conform {

// -- what a syscall returned ----------------------------------------------

// The kernel's return convention is a SUM, not an int: a syscall either
// yielded a value or failed with an errno. Linux packs both into one register
// (negative small magnitude means -errno), and the bug classes that follow --
// treating -EINVAL as a huge positive, negating twice, comparing a packed
// value against an unpacked one -- all come from leaving them packed. So we
// unpack once, at the boundary, and the type forbids re-conflating them.
class Returned {
public:
    // Decode the raw register exactly as the kernel encodes it. Linux reserves
    // only the last page of the range for errors, so a legitimate return (an
    // mmap address, a large offset) is not mistaken for one.
    [[nodiscard]] static constexpr Returned from_raw(std::int64_t raw) noexcept {
        if (raw < 0 && raw >= -4095)
            return Returned{Err{static_cast<std::int32_t>(-raw)}};
        return Returned{Ok{raw}};
    }

    [[nodiscard]] static constexpr Returned ok(std::int64_t v) noexcept {
        return Returned{Ok{v}};
    }
    [[nodiscard]] static constexpr Returned failed(std::int32_t e) noexcept {
        return Returned{Err{e}};
    }

    [[nodiscard]] constexpr bool is_ok() const noexcept {
        return std::holds_alternative<Ok>(v_);
    }

    // Exhaustive consumption, mirroring abi::Outcome::match.
    template <class OnOk, class OnErr>
    [[nodiscard]] constexpr decltype(auto) match(OnOk&& ok_fn,
                                                 OnErr&& err_fn) const {
        if (const auto* o = std::get_if<Ok>(&v_))
            return std::forward<OnOk>(ok_fn)(o->value);
        return std::forward<OnErr>(err_fn)(std::get<Err>(v_).number);
    }

    friend constexpr bool operator==(const Returned&, const Returned&) = default;

    [[nodiscard]] std::string describe() const;

private:
    struct Ok {
        std::int64_t value;
        friend constexpr bool operator==(Ok, Ok) = default;
    };
    struct Err {
        std::int32_t number;
        friend constexpr bool operator==(Err, Err) = default;
    };

    constexpr explicit Returned(std::variant<Ok, Err> v) noexcept
        : v_{std::move(v)} {}

    std::variant<Ok, Err> v_;
};

// A buffer the syscall wrote into guest memory, tagged with the argument whose
// pointer it came from. Content and provenance travel together, because
// "buffers differ" is useless without knowing WHICH buffer.
struct Written {
    int                    arg;
    std::vector<std::byte> bytes;

    Written(int a, std::vector<std::byte> b) : arg{a}, bytes{std::move(b)} {}

    friend bool operator==(const Written&, const Written&) = default;
};

// Everything one syscall produced. A PRODUCT, because these are genuinely
// independent: a call can succeed writing nothing, fail writing nothing, or
// succeed writing several buffers. No combination is illegal, so unlike
// Returned a struct is the honest encoding -- the shape follows the domain.
struct Observation {
    abi::Sysno           call;
    Returned             returned;
    std::vector<Written> wrote{};
    // A label for the step, so a report reads "lseek(-102, SEEK_CUR)" rather
    // than bare "lseek". Carried into the Divergence.
    std::string          note{};

    Observation(abi::Sysno c, Returned r) : call{c}, returned{r} {}

    // Builder tail-calls, rvalue-qualified so a half-built Observation cannot
    // be left lying around as an lvalue.
    [[nodiscard]] Observation&& writing(Written w) && {
        wrote.push_back(std::move(w));
        return std::move(*this);
    }
    [[nodiscard]] Observation&& labelled(std::string n) && {
        note = std::move(n);
        return std::move(*this);
    }
};

// One execution of a scenario. ORDER is part of the observation: two runs
// making the same calls in a different sequence have not agreed.
struct Trace {
    std::string              scenario;
    std::vector<Observation> steps{};

    explicit Trace(std::string s) : scenario{std::move(s)} {}
};

// -- the verdict -----------------------------------------------------------

// What specifically differed. Step index, field, and both sides are
// constructor parameters, so an unexplained failure is unrepresentable.
struct Divergence {
    enum class Field : std::uint8_t {
        returned,      // retval or errno differed
        written,       // a written buffer's contents differed
        step_count,    // one side made more calls than the other
        call_identity, // the same index was a different syscall
    };

    std::size_t index;
    Field       field;
    std::string native;  // the oracle's value, rendered
    std::string guest;   // linuxity's value, rendered
    std::string note{};

    Divergence(std::size_t i, Field f, std::string n, std::string g)
        : index{i}, field{f}, native{std::move(n)}, guest{std::move(g)} {}

    [[nodiscard]] static constexpr std::string_view
    field_name(Field f) noexcept {
        switch (f) {
            case Field::returned:      return "return value / errno";
            case Field::written:       return "written buffer";
            case Field::step_count:    return "number of syscalls";
            case Field::call_identity: return "syscall identity";
        }
        return "<unknown field>";
    }

    [[nodiscard]] std::string describe() const;
};

// Agreement carries no payload on purpose: it has no interesting content, and
// giving it one would invite code that branches on it.
struct Match {
    std::size_t steps_compared{0};
};

// A SUM. There is deliberately no `operator bool` and no `.ok()`: consumers
// must match, which hands them the explanation in the failing branch.
class Verdict {
public:
    constexpr Verdict(Match m) noexcept : v_{m} {}
    Verdict(Divergence d) : v_{std::move(d)} {}

    template <class OnMatch, class OnDiverge>
    [[nodiscard]] decltype(auto) match(OnMatch&& m, OnDiverge&& d) const {
        if (const auto* ok = std::get_if<Match>(&v_))
            return std::forward<OnMatch>(m)(*ok);
        return std::forward<OnDiverge>(d)(std::get<Divergence>(v_));
    }

    [[nodiscard]] bool agreed() const noexcept {
        return std::holds_alternative<Match>(v_);
    }

private:
    std::variant<Match, Divergence> v_;
};

// -- comparison laws -------------------------------------------------------

// A Law decides whether a pair of Observations is exempt from comparison. It
// is a concept rather than a virtual interface so laws compose at compile time
// and cost nothing at runtime, and -- the point -- so a law that forgets
// reason() fails to build instead of exempting things anonymously.
template <class L>
concept Law = requires(const L& law, const Observation& n, const Observation& g) {
    { law.exempt(n, g) } -> std::convertible_to<bool>;
    { law.reason() }     -> std::convertible_to<std::string_view>;
};

// Strict agreement: nothing is exempt. The default, because an exemption
// should be an explicit act.
struct Strict {
    [[nodiscard]] static constexpr bool exempt(const Observation&,
                                               const Observation&) noexcept {
        return false;
    }
    [[nodiscard]] static constexpr std::string_view reason() noexcept {
        return "strict: every observed field must agree exactly";
    }
};

// Exempt one syscall, with a mandatory stated reason. For the handful that
// cannot agree between two processes by construction: getpid returns different
// pids, clock_gettime different times, getrandom different bytes.
class Exempt {
public:
    constexpr Exempt(abi::Sysno call, std::string_view why) noexcept
        : call_{call}, why_{why} {}

    [[nodiscard]] constexpr bool exempt(const Observation& n,
                                        const Observation& g) const noexcept {
        return n.call == call_ && g.call == call_;
    }
    [[nodiscard]] constexpr std::string_view reason() const noexcept {
        return why_;
    }
    [[nodiscard]] constexpr abi::Sysno call() const noexcept { return call_; }

private:
    abi::Sysno       call_;
    std::string_view why_;
};

// Disjunction: exempt if ANY component exempts, so a policy reads as a list of
// declared exemptions. Variadic and constexpr-friendly.
template <Law... Ls>
class AnyOf {
public:
    constexpr explicit AnyOf(Ls... ls) noexcept : laws_{std::move(ls)...} {}

    [[nodiscard]] constexpr bool exempt(const Observation& n,
                                        const Observation& g) const {
        return std::apply([&](const Ls&... l) { return (l.exempt(n, g) || ...); },
                          laws_);
    }
    [[nodiscard]] static constexpr std::string_view reason() noexcept {
        return "any-of: an exemption applied; see the component laws";
    }

private:
    std::tuple<Ls...> laws_;
};

// Compare an fd-returning call by WHETHER it succeeded, not by which number
// it got. Allocation-dependent values are not comparable between two
// processes -- and linuxity deliberately differs here: src/main.cpp holds
// /dev/null on fds 3..8 (commit ea99143) so pacman's parallel libcurl workers
// cannot race for fd 3, which corrupted core.db. So the guest's first new fd
// is 4 where native gets 3, by design.
//
// This is NOT a blanket exemption: success-vs-failure and the errno still
// have to agree, so `openat` returning EACCES where native succeeded is still
// a divergence. Only the fd's NUMERIC value is excused.
class FdNumbersDiffer {
public:
    [[nodiscard]] bool exempt(const Observation& n,
                              const Observation& g) const noexcept {
        if (!returns_fd(n.call) || n.call != g.call) return false;
        // Both succeeded: the numbers may differ. Either failing, or one
        // failing and the other not, must still be compared.
        return n.returned.is_ok() && g.returned.is_ok();
    }
    [[nodiscard]] static constexpr std::string_view reason() noexcept {
        return "fd numbers are allocation-dependent; linuxity reserves 3..8 "
               "so guests start allocating at 4 (see src/main.cpp)";
    }

private:
    [[nodiscard]] static constexpr bool returns_fd(abi::Sysno s) noexcept {
        switch (s) {
            case abi::Sysno::open:
            case abi::Sysno::openat:
            case abi::Sysno::openat2:
            case abi::Sysno::creat:
            case abi::Sysno::dup:
            case abi::Sysno::dup2:
            case abi::Sysno::dup3:
            case abi::Sysno::socket:
            case abi::Sysno::accept:
            case abi::Sysno::accept4:
            case abi::Sysno::epoll_create1:
            case abi::Sysno::eventfd2:
            case abi::Sysno::memfd_create:
            case abi::Sysno::inotify_init1:
            case abi::Sysno::timerfd_create:
            case abi::Sysno::signalfd4:
            case abi::Sysno::pidfd_open:
                return true;
            default:
                return false;
        }
    }
};

// linuxity may SUCCEED where the host refused by POLICY -- never the reverse.
//
// A guest kernel exists partly to paper over a host that forbids something
// Linux allows. Android is the live case: the shell domain's SELinux ioctl
// whitelist for devpts predates termios2, so TCGETS2/TCSETS2 on a pty slave
// return EACCES, while glibc >= 2.42 uses only those requests. `tty` reported
// "not a tty" on a working pty until linuxity served them with the classic
// ioctl and converted the struct.
//
// So on Android the kernel says EACCES and linuxity says 0, and that
// divergence is the FIX, not a bug. Exempting ioctl outright would throw away
// the other 25 checks in the probe, so this law is deliberately narrow in
// three ways:
//
//   * only EACCES/EPERM -- the errnos a policy layer produces. A real ENOTTY
//     or EBADF from the kernel must still be matched exactly.
//   * only in the direction native-failed / guest-succeeded, or native-denied
//     / guest-failed-differently. If the guest fails where the host SUCCEEDED,
//     that is a regression and is reported.
//   * only for the syscalls a host security policy actually filters: ioctl
//     (SELinux's per-command whitelist), bind (Android forbids a filesystem
//     AF_UNIX bind in every directory an app can write, so linuxity falls
//     back to the abstract namespace -- which is the whole reason the
//     guest's sockets work there at all), and link/linkat (Android denies
//     the `link` permission on /data for EVERY process, and no filesystem an
//     adb shell can reach allows a hardlink at all -- so linuxity emulates
//     it by copying and tracking the link set, which is the only reason a
//     package that ships hardlinked aliases installs. gcc ships /usr/bin/gcc,
//     g++, cc and five more that way, so without it there is no compiler),
//     and mknod/mknodat (Android's SELinux refuses mkfifo for the shell in
//     every directory it can write, so linuxity emulates named FIFOs; make's
//     jobserver is one of them).
//
// The effect: the aarch64 golden still RECORDS the denial as the kernel's
// truth, and the guest is still held to every other observation.
class HostPolicyMayDeny {
public:
    [[nodiscard]] static constexpr bool filtered(abi::Sysno c) noexcept {
        // connect, getsockname and getpeername ride along with bind, and
        // newfstatat with link: if the host refused the bind there is nothing
        // to connect TO or name, and if it
        // refused the link there is nothing to stat -- so the probe marks
        // the follow-up not applicable while the guest, whose call
        // succeeded, answers it. Clause (b) below pairs the two up.
        return c == abi::Sysno::ioctl || c == abi::Sysno::bind ||
               c == abi::Sysno::connect || c == abi::Sysno::getsockname ||
               c == abi::Sysno::getpeername || c == abi::Sysno::link ||
               c == abi::Sysno::linkat || c == abi::Sysno::newfstatat ||
               c == abi::Sysno::mknod || c == abi::Sysno::mknodat ||
               // dmesg_restrict: the guest is root, the native probe isn't
               c == abi::Sysno::syslog ||
               // CAP_SYS_ADMIN: likewise
               c == abi::Sysno::unshare || c == abi::Sysno::setns ||
               c == abi::Sysno::sethostname || c == abi::Sysno::setdomainname ||
               // and every mount step that needed the namespace first
               c == abi::Sysno::mount || c == abi::Sysno::umount2 ||
               c == abi::Sysno::fsopen || c == abi::Sysno::fsconfig ||
               c == abi::Sysno::fsmount || c == abi::Sysno::fspick ||
               c == abi::Sysno::move_mount || c == abi::Sysno::open_tree ||
               c == abi::Sysno::open_tree_attr || c == abi::Sysno::mount_setattr ||
               c == abi::Sysno::listns || c == abi::Sysno::file_getattr ||
               c == abi::Sysno::file_setattr || c == abi::Sysno::ustat ||
               c == abi::Sysno::statmount || c == abi::Sysno::listmount ||
               c == abi::Sysno::pivot_root || c == abi::Sysno::chroot ||
               c == abi::Sysno::swapon || c == abi::Sysno::swapoff ||
               c == abi::Sysno::quotactl || c == abi::Sysno::acct ||
               // SysV IPC: the get calls can be ENOSYS on the host; every
               // later step then reads "not applicable" there
               c == abi::Sysno::msgget || c == abi::Sysno::msgsnd ||
               c == abi::Sysno::msgrcv || c == abi::Sysno::msgctl ||
               c == abi::Sysno::semget || c == abi::Sysno::semop ||
               c == abi::Sysno::semtimedop || c == abi::Sysno::semctl ||
               c == abi::Sysno::shmget || c == abi::Sysno::shmat ||
               c == abi::Sysno::shmdt || c == abi::Sysno::shmctl;
    }
    [[nodiscard]] bool exempt(const Observation& n,
                              const Observation& g) const noexcept {
        if (!filtered(n.call) || n.call != g.call) return false;
        // (a) the call itself: host denied by policy, linuxity served it.
        //     For unshare a kernel built without that namespace type says
        //     EINVAL (Android has no user namespaces): also the host's limit.
        const bool ns_call = n.call == abi::Sysno::unshare;
        // a kernel built without SysV IPC answers ENOSYS (Android)
        const bool sysv = n.call == abi::Sysno::msgget || n.call == abi::Sysno::semget ||
                          n.call == abi::Sysno::shmget;
        if (g.returned.is_ok() &&
            n.returned.match([](std::int64_t) { return false; },
                             [&](std::int32_t e) {
                                 return e == EACCES || e == EPERM || (ns_call && e == EINVAL) ||
                                        (sysv && e == ENOSYS);
                             }))
            return true;
        // (b) an invariant DERIVED from such a call. The probe reports 2 for
        //     "not applicable" when the call it depends on failed, so one
        //     side saying 2 and the other 0/1 is the same denial showing up
        //     downstream, not a disagreement about behaviour. Two answered
        //     results are always compared.
        constexpr std::int64_t kNotApplicable = 2;
        const auto na = [](const Observation& o) {
            return o.returned.match(
                [](std::int64_t v) { return v == kNotApplicable; },
                [](std::int32_t) { return false; });
        };
        if (na(n) != na(g)) return true;
        // (c) a policy denial that MASKS the real error. When the host
        //     refuses a call outright, every answer it gives for that call
        //     is its own EACCES rather than what Linux would say -- so the
        //     guest reporting a DIFFERENT failure is the guest being right,
        //     not a disagreement. Android's link(2) is the case: Linux
        //     answers EEXIST for a link onto a taken name, and the host says
        //     EACCES because it never got as far as looking.
        //
        //     Still narrow: only when the NATIVE side carries the policy
        //     errno. If the host answered properly and the guest invented
        //     some other failure, that is a real divergence and is reported.
        return n.returned.match(
            [](std::int64_t) { return false; },
            [&](std::int32_t e) {
                return (e == EACCES || e == EPERM) && !g.returned.is_ok();
            });
    }
    [[nodiscard]] static constexpr std::string_view reason() noexcept {
        return "the host denied a policy-filtered syscall (EACCES/EPERM) and "
               "linuxity served it anyway -- Android's SELinux whitelist "
               "rejects TCGETS2 on a pty slave, forbids a filesystem "
               "AF_UNIX bind, and denies link(2) on /data outright, all of "
               "which the guest kernel is there to paper over. Covers the "
               "denied call and any invariant the probe marked "
               "not-applicable because of it; the reverse direction, and any "
               "two answered results, are never exempt";
    }
};

// The exemptions that hold on EVERY host, each with its reason. This is the
// SSOT for "results that cannot agree between two processes" -- scenarios
// extend it rather than restating it.
[[nodiscard]] constexpr auto universal_exemptions() noexcept {
    return AnyOf{
        Exempt{abi::Sysno::getpid,        "two processes have different pids"},
        Exempt{abi::Sysno::gettid,        "two threads have different tids"},
        Exempt{abi::Sysno::getppid,       "parents differ between runs"},
        Exempt{abi::Sysno::getrandom,     "randomness is the point"},
        Exempt{abi::Sysno::clock_gettime, "time advances between runs"},
        Exempt{abi::Sysno::gettimeofday,  "time advances between runs"},
        Exempt{abi::Sysno::time,          "time advances between runs"},
    };
}

// The universal exemptions plus fd-number tolerance. This is what the live
// differential test uses: fd numbers differ by design, so comparing them
// would report a divergence on every single open.
[[nodiscard]] constexpr auto default_law() noexcept {
    return AnyOf{universal_exemptions(), FdNumbersDiffer{}, HostPolicyMayDeny{}};
}

// -- rendering (defined in observation.cpp) --------------------------------

[[nodiscard]] std::string render_buffers(std::span<const Written> bufs);

// -- the comparison --------------------------------------------------------

// Judge a guest trace against a reference trace under a law. Returns the FIRST
// divergence: later steps are causally downstream of an earlier mismatch, so
// reporting them all is noise.
//
// Host-independent by construction -- it makes no syscalls and touches no
// platform API, so it is the same code on all four targets.
template <Law L = Strict>
[[nodiscard]] Verdict judge(const Trace& reference, const Trace& guest,
                            const L& law = L{}) {
    const std::size_t n = std::min(reference.steps.size(), guest.steps.size());

    for (std::size_t i = 0; i < n; ++i) {
        const Observation& a = reference.steps[i];
        const Observation& b = guest.steps[i];

        if (a.call != b.call) {
            Divergence d{i, Divergence::Field::call_identity,
                         std::string{name_of(a.call)},
                         std::string{name_of(b.call)}};
            d.note = a.note;
            return d;
        }

        if (law.exempt(a, b)) continue;

        if (!(a.returned == b.returned)) {
            Divergence d{i, Divergence::Field::returned, a.returned.describe(),
                         b.returned.describe()};
            d.note = a.note;
            return d;
        }

        if (a.wrote != b.wrote) {
            Divergence d{i, Divergence::Field::written, render_buffers(a.wrote),
                         render_buffers(b.wrote)};
            d.note = a.note;
            return d;
        }
    }

    // Checked after the common prefix, so a report points at the first
    // behavioural difference rather than at the length.
    if (reference.steps.size() != guest.steps.size())
        return Divergence{n, Divergence::Field::step_count,
                          std::to_string(reference.steps.size()),
                          std::to_string(guest.steps.size())};

    return Match{n};
}

} // namespace lx::conform
