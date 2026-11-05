// linuxity/abi/outcome.hpp
//
// The algebra of syscall FATES.
//
// Servicing one guest syscall ends in exactly ONE of eight fates. That
// "exactly one" is the point of this file: the fate is a SUM, so it is
// spelled as a sum, not as a struct of independent bools.
//
//     Outcome = Virtualize | Forward | Redirect | Inject
//             | Signal | ExecInterp | SockRewrite | Exited
//
// The old encoding was a PRODUCT: seven `bool` flags and ~20 payload fields in
// one flat struct. It could spell `redirect && inject` (meaningless), or
// `signal` with no signal number (silently delivers 0), or a redirect with an
// empty host path. Of 2^7 flag combinations only 8 were legal; the consumer
// chose between them with an if/else chain whose ORDER was the real
// specification; and adding a fate left every backend compiling while silently
// ignoring it.
//
// Here each fate is its own type carrying ONLY its own data, mandatory data is
// a constructor parameter, and consumers use `match`, which is EXHAUSTIVE: a
// new fate fails to compile at every site that must handle it.
//
// MODIFIERS vs FATES. Three things are deliberately not fates, because they
// qualify one rather than stand beside it:
//
//   * Scrub        - a post-redirect id fixup. Only Redirect has one.
//   * make_parents - a pre-forward `mkdir -p`. Only Redirect has one.
//   * DupMirror    - an fd-binding mirror. Only Forward has one.
//
// Each lives inside the fate it qualifies, so it is unrepresentable elsewhere.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"

namespace lx::abi {

// -- modifiers -------------------------------------------------------------

// Post-redirect id scrub. Host-backed stat/lstat/newfstatat/statx are
// REDIRECTED, so the host kernel fills the guest buffer with the HOST file's
// uid/gid (whoever unpacked the rootfs). linuxity presents a root-owned world,
// so once the redirect returns 0 we read the buffer back and overlay the
// guest-intended mode/uid/gid. The layout, the buffer and the lookup key
// travel together: a kind without a buffer cannot be built.
struct Scrub {
    enum class Layout : std::uint8_t { stat, statx };

    Layout      layout;
    UAddr       buf;
    std::string guest_path;  // normalized guest path; key into shadow metadata

    Scrub(Layout l, UAddr b, std::string gp)
        : layout{l}, buf{b}, guest_path{std::move(gp)} {}
};

// A path argument to rewrite: which arg register holds the `char*`, and the
// translated real host path to splice in. Required together, by construction.
struct PathArg {
    int         arg;
    std::string host_path;

    PathArg(int a, std::string hp) : arg{a}, host_path{std::move(hp)} {}
};

// dup/dup2/dup3/fcntl(F_DUPFD*) make a NEW fd aliasing an existing one, so the
// new fd must inherit the source's path and virtual-dir bindings or an *at call
// relative to it resolves against the wrong directory (this is what breaks
// `rm -rf` via coreutils fts, which dups a dir fd then unlinkat's through it).
// The host does the real dup, so these FORWARD and then mirror.
struct DupMirror {
    int from;              // source fd whose bindings to copy
    int close_first{-1};   // dup2/dup3 target whose stale binding must be dropped

    explicit DupMirror(int f, int c = -1) noexcept : from{f}, close_first{c} {}
};

// -- the fates -------------------------------------------------------------

// VIRTUALIZE - answered from our own subsystems. Hand the guest a value; no
// real syscall runs.
struct Virtualize {
    std::int64_t ret;

    constexpr explicit Virtualize(std::int64_t v) noexcept : ret{v} {}

    // An errno return, negated into the kernel's -errno convention exactly
    // once, here, so no call site open-codes the sign.
    [[nodiscard]] static constexpr Virtualize fail(Errno e) noexcept {
        return Virtualize{-static_cast<std::int64_t>(e)};
    }
};

// FORWARD - let the real host kernel run this syscall in the guest, for
// memory and host-resource calls (mmap/brk/mprotect, host-backed I/O).
struct Forward {
    std::optional<DupMirror> mirror{};  // fd bindings to carry onto the result

    constexpr Forward() noexcept = default;
    explicit Forward(DupMirror m) noexcept : mirror{m} {}
};

// REDIRECT - the guest named a host-backed path. Rewrite the path argument(s)
// to the translated real host path, then forward. This is how a native ld.so
// mmaps real library files while the guest sees only linuxity's namespace.
struct Redirect {
    PathArg                first;
    std::optional<PathArg> second{};      // rename/link: both operands are paths
    bool                   make_parents{false};
    std::optional<Scrub>   scrub{};

    explicit Redirect(PathArg p) : first{std::move(p)} {}

    // `symlink`'s first operand is the link's literal TEXT (guest data, not a
    // host path), so only the target is translated. Naming that case keeps the
    // old `path_arg = -1` sentinel from existing at all.
    [[nodiscard]] static Redirect target_only(PathArg p) {
        Redirect r{PathArg{-1, std::string{}}};
        r.second = std::move(p);
        return r;
    }

    Redirect&& with(Scrub s) && { scrub = std::move(s); return std::move(*this); }
    Redirect&& with(PathArg p) && { second = std::move(p); return std::move(*this); }
    Redirect&& parents() && { make_parents = true; return std::move(*this); }
};

// INJECT - the guest opened a purely virtual node (procfs/tmpfs). Materialize
// its bytes into a host memfd and splice that fd in; reads and mmaps then hit
// real memory at native speed.
struct Inject {
    std::vector<std::byte> content;
    bool                   is_dir{false};

    explicit Inject(std::vector<std::byte> c, bool dir = false)
        : content{std::move(c)}, is_dir{dir} {}
};

// RAISE - the guest issued kill/tgkill/tkill against a GUEST pid. Guest pids
// are linuxity's own namespace, unrelated to host pids, so forwarding the raw
// number would hit an unrelated host task. The loop maps the guest pid to its
// real host tid and delivers there.
//
// (Named Raise, not Signal: lx::Signal is already the strong signal-number id.)
struct Raise {
    std::int32_t guest_pid;  // 0 => the current task
    std::int32_t signum;

    constexpr Raise(std::int32_t pid, std::int32_t sig) noexcept
        : guest_pid{pid}, signum{sig} {}
};

// EXEC_INTERP - the guest execve'd a DYNAMIC binary. The host kernel would
// resolve its PT_INTERP against the host root and fail, so the exec becomes
// `interp_host <prog_guest> <argv...>`: the child execs the real loader, which
// then opens the program and its libraries through redirected syscalls.
struct ExecInterp {
    int         path_arg;     // register holding the execve path
    std::string interp_host;  // real host path of the dynamic linker
    std::string prog_guest;   // guest path of the program

    // argv tokens spliced BETWEEN the interpreter and the program: a shebang's
    // optional argument, and for a `#!` script whose interpreter is itself
    // dynamic, that interpreter's host path.
    std::vector<std::string> prefix{};
    // argv tokens APPENDED after the program's own arguments.
    std::vector<std::string> extra_args{};

    ExecInterp(int pa, std::string ih, std::string pg)
        : path_arg{pa}, interp_host{std::move(ih)}, prog_guest{std::move(pg)} {}
};

// SOCK_REWRITE - AF_UNIX bind/connect path translation. Unprivileged linuxity
// cannot chroot (that needs CAP_SYS_CHROOT), so a raw absolute sun_path would
// land on the HOST filesystem, leaking sockets onto the host and colliding with
// stale ones. Poke the translated path into the sockaddr and fix the socklen so
// both peers resolve to the same in-overlay node.
struct SockRewrite {
    UAddr         path_addr;    // guest address of sockaddr_un.sun_path
    std::string   host_path;    // translated host path to write there
    int           len_arg{2};   // register holding socklen
    std::uint64_t new_len{0};   // family + path + NUL

    SockRewrite(UAddr pa, std::string hp, int la, std::uint64_t nl)
        : path_addr{pa}, host_path{std::move(hp)}, len_arg{la}, new_len{nl} {}
};

// EXITED - the guest asked to terminate. Carries the status, nothing else.
struct Exited {
    int code;

    constexpr explicit Exited(int c) noexcept : code{c} {}
};

// -- the sum ---------------------------------------------------------------

// Exactly one fate. No flags, no combinations, no precedence to remember.
using Fate = std::variant<Virtualize, Forward, Redirect, Inject,
                          Raise, ExecInterp, SockRewrite, Exited>;

class Outcome {
public:
    // Implicit so a handler can `return Virtualize{...};` and read naturally.
    template <class F>
        requires std::is_constructible_v<Fate, F>
    constexpr Outcome(F f) : fate_{std::move(f)} {}

    // -- the named constructors every handler uses -------------------------
    [[nodiscard]] static constexpr Outcome value(std::int64_t v) {
        return Outcome{Virtualize{v}};
    }
    [[nodiscard]] static constexpr Outcome error(Errno e) {
        return Outcome{Virtualize::fail(e)};
    }
    [[nodiscard]] static constexpr Outcome forward() { return Outcome{Forward{}}; }
    [[nodiscard]] static constexpr Outcome exited(int code) {
        return Outcome{Exited{code}};
    }
    [[nodiscard]] static constexpr Outcome raise_at(std::int32_t pid,
                                                     std::int32_t sig) {
        return Outcome{Raise{pid, sig}};
    }

    // -- the ONLY way to consume one --------------------------------------
    // Exhaustive by construction. The static_assert fires FIRST and names the
    // fate you forgot; without it a missing arm surfaces as a page of
    // std::variant instantiation noise.
    template <class... Fs>
    [[nodiscard]] decltype(auto) match(Fs&&... fs) const& {
        static_assert(handles_every_fate<overload<std::decay_t<Fs>...>>,
                      "match() is missing an arm: every fate must be handled. "
                      "The fate_is_handled<Visitor, Fate> assertion above names "
                      "the one you forgot.");
        return std::visit(overload{std::forward<Fs>(fs)...}, fate_);
    }
    template <class... Fs>
    [[nodiscard]] decltype(auto) match(Fs&&... fs) && {
        static_assert(handles_every_fate<overload<std::decay_t<Fs>...>>,
                      "match() is missing an arm: every fate must be handled. "
                      "The fate_is_handled<Visitor, Fate> assertion above names "
                      "the one you forgot.");
        return std::visit(overload{std::forward<Fs>(fs)...}, std::move(fate_));
    }

    // Narrow accessor for the few places that genuinely need to ask about one
    // fate (tracing, tests). Prefer match().
    template <class F>
    [[nodiscard]] const F* get_if() const noexcept {
        return std::get_if<F>(&fate_);
    }

    [[nodiscard]] const Fate& fate() const& noexcept { return fate_; }
    [[nodiscard]] Fate&& fate() && noexcept { return std::move(fate_); }

private:
    template <class... Fs>
    struct overload : Fs... { using Fs::operator()...; };

    // One check per fate. The assert lives INSIDE a struct keyed on the fate
    // type, so the failing instantiation is `fate_is_handled<V, Exited>` and
    // the compiler names the fate you forgot rather than printing `T`.
    template <class V, class T>
    struct fate_is_handled {
        static constexpr bool value = std::is_invocable_v<V, const T&>;
        static_assert(value,
                      "this fate has no arm in match(); the enclosing "
                      "fate_is_handled<Visitor, Fate> names which one");
    };

    template <class V, class... Ts>
    static constexpr bool handles_all(std::variant<Ts...>*) {
        return (fate_is_handled<V, Ts>::value && ...);
    }

    template <class V>
    static constexpr bool handles_every_fate =
        handles_all<V>(static_cast<Fate*>(nullptr));

    Fate fate_;
};

} // namespace lx::abi
