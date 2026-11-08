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

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/sysno.hpp"
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
//
// `rewrites` records whether the splice would actually CHANGE anything. With
// no --root the guest tree IS the host tree, so classify() hands back the path
// it was given and the rewrite is an identity -- 132K of them in one
// `ls -lR /usr/include`, each paying a ptrace stop to write a path back over
// itself. The comparison is free here (both strings are in hand) and
// impossible later: a Redirect carries only the translated path, so by the
// time the trap loop sees it the original is gone. Computed once, in the
// constructor, so no call site can forget.
struct PathArg {
    int         arg;
    std::string host_path;
    bool        rewrites{true};

    PathArg(int a, std::string hp) : arg{a}, host_path{std::move(hp)} {}

    // The form that knows the guest path it came from, and so can tell.
    PathArg(int a, std::string hp, std::string_view guest_path)
        : arg{a}, host_path{std::move(hp)}, rewrites{host_path != guest_path} {}
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

// Bytes the host call reads through pointer arg `arg`, in place of the
// guest's own. openat2 gets its open_how with `resolve` cleared, once we've
// done the RESOLVE_* walk in our namespace.
struct ArgBlob {
    int                    arg;
    std::vector<std::byte> bytes;
};

// -- the fates -------------------------------------------------------------

// VIRTUALIZE - answered from our own subsystems. Hand the guest a value; no
// real syscall runs.
struct Virtualize {
    std::int64_t ret;
    // Also run the real call on the host and ignore its result. For calls
    // like setsid whose guest answer is ours but whose host effect matters
    // (a pty's ^C goes to the HOST's foreground group).
    bool mirror_host{false};
    // A host mirror that needs guest ids made host ids first.
    enum class Mirror : std::uint8_t { none, setpgid, tcsetpgrp } host_mirror{Mirror::none};
    std::int32_t m_a{0}, m_b{0};      // setpgid: pid, pgid. tcsetpgrp: pgid
    std::uint64_t m_ptr{0};           // tcsetpgrp: the pid_t* argument
    // Nonzero: don't answer yet. Wait this long in the guest's kernel and run
    // the call again (an open that has to block on another guest task).
    std::int64_t retry_ns{0};

    constexpr explicit Virtualize(std::int64_t v) noexcept : ret{v} {}
    [[nodiscard]] static constexpr Virtualize retry_after(std::int64_t ns) noexcept {
        Virtualize x{0};
        x.retry_ns = ns;
        return x;
    }
    [[nodiscard]] static constexpr Virtualize mirrored(std::int64_t v) noexcept {
        Virtualize x{v};
        x.mirror_host = true;
        return x;
    }

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
    // may wait on another guest task (a FIFO open), so the backend must not
    // block the whole tree waiting for it
    bool                   may_block{false};
    // run for the host effect only; the guest gets this instead
    std::optional<std::int64_t> force_ret{};
    // on success this call created `created` (a dir if created_dir)
    std::optional<std::string> created{};
    bool                   created_dir{false};
    std::optional<Scrub>   scrub{};
    std::optional<ArgBlob> blob{};

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

    // Is this redirect a pure no-op -- nothing to rewrite, no second path, no
    // directories to create, no buffer to scrub? Then the guest's own
    // registers are already correct and the call can simply be forwarded,
    // which costs one stop instead of two and no guest-memory writes.
    //
    // Asked by the trap loop (the single Redirect consumer), so the 14 sites
    // that BUILD a Redirect do not each need to know about the optimisation.
    [[nodiscard]] bool is_noop() const noexcept {
        return !second && !make_parents && !scrub && !blob && !force_ret && !created && first.arg >= 0 &&
               !first.rewrites;
    }
};

// INJECT - the guest opened a purely virtual node (procfs/tmpfs). Materialize
// its bytes into a host temp and splice that path into `path_arg`, so the real
// open returns a real fd; reads and mmaps then hit real memory at native
// speed. A virtual DIRECTORY is backed by an empty temp dir so O_DIRECTORY
// opens succeed and getdents64 can enumerate the synthesized entries.
struct Inject {
    int                    path_arg;  // register holding the char* path
    std::vector<std::byte> content;   // empty for a directory
    bool                   is_dir{false};
    // The temp is read back by path later (a write to comm, uid_map, ...),
    // so it must outlive the open.
    bool                   keep_name{false};
    // The open follows links and isn't O_PATH, so it can reopen an fd of
    // ours through /proc/<pid>/fd/N (a memfd: no temp file at all).
    bool                   reopen_ok{false};
    // A virtual directory's backing: the host's /proc, /sys or /dev, whose
    // real entries never show (getdents is ours). Empty = a temp dir.
    std::string            dir_host{};
    std::optional<ArgBlob> blob{};

    Inject(int pa, std::vector<std::byte> c, bool dir = false, bool keep = false,
           bool reopen = false)
        : path_arg{pa}, content{std::move(c)}, is_dir{dir}, keep_name{keep}, reopen_ok{reopen} {}
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
    // For a GROUP target (kill(0) / kill(-pgid)): the guest pids that are in
    // that group, resolved by the ABI layer, which is the one place that
    // knows the groups. Empty = let the backend decide (single pid, or a
    // backend that models groups itself). `grouped` says the list is
    // authoritative even when empty: an empty group is ESRCH.
    std::vector<std::int32_t> members{};
    bool grouped{false};

    Raise(std::int32_t pid, std::int32_t sig) noexcept
        : guest_pid{pid}, signum{sig} {}
    Raise(std::int32_t pid, std::int32_t sig, std::vector<std::int32_t> m)
        : guest_pid{pid}, signum{sig}, members{std::move(m)}, grouped{true} {}
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
    // The bytes to write there. Usually a NUL-terminated host path; for an
    // ABSTRACT address (hosts that forbid a filesystem bind) it is a leading
    // NUL followed by the name, where new_len -- not a terminator -- is what
    // delimits it. Written byte-wise, so an embedded NUL survives.
    std::string   host_path;
    int           len_arg{2};   // register holding socklen
    std::uint64_t new_len{0};   // family + path (+ NUL for the filesystem form)
    std::string   guest_path{}; // what the guest named, for getsockname later
    bool          binds{false}; // bind (names this socket) vs connect (names the peer)

    SockRewrite(UAddr pa, std::string hp, int la, std::uint64_t nl)
        : path_addr{pa}, host_path{std::move(hp)}, len_arg{la}, new_len{nl} {}
};

// ARG_REWRITE - run the guest's syscall, but with one NON-PATH argument
// register changed, and convert the buffer it filled on the way back.
//
// This exists for a host that refuses a syscall variant the guest's libc
// insists on. Android's SELinux ioctl whitelist allows TCGETS/TCSETS on a pty
// slave but not TCGETS2/TCSETS2, and glibc >= 2.42 implements tcgetattr/
// tcsetattr/isatty/ttyname with the 2-variants -- so every termios call on a
// pty fails EACCES and `tty` reports "not a tty" on a perfectly good pty.
// struct termios2 is struct termios plus c_ispeed/c_ospeed, so the classic
// ioctl can serve the new one if someone fixes the struct up. That someone is
// here: swap the request register, forward, then translate the layout.
//
// Not a Redirect: nothing about this is a path, there is no namespace
// translation, and the fixup rewrites a DIFFERENT buffer shape than Scrub's.
struct ArgRewrite {
    // How to convert the buffer once the host syscall has returned.
    enum class Convert : std::uint8_t {
        none,
        termios_to_termios2,   // widen: host filled termios, guest wants termios2
        unix_name,             // an AF_UNIX address came back: report the guest's spelling
    };

    int           arg;              // which argument register to replace
    std::uint64_t to;               // what to put in it
    Convert       convert{Convert::none};
    UAddr         buf{};            // the guest buffer `convert` operates on
    UAddr         len{};            // unix_name: the socklen_t* beside it
    std::string   name{};           // unix_name: the guest's spelling

    ArgRewrite(int a, std::uint64_t v) noexcept : arg{a}, to{v} {}
    ArgRewrite(int a, std::uint64_t v, Convert c, UAddr b) noexcept
        : arg{a}, to{v}, convert{c}, buf{b} {}
};

// GUEST CALLS - run a short chain of syscalls inside the trapped task in
// place of its own call, and return the last one's result. For what only the
// guest can make: a MAP_SHARED mapping of a SysV segment in its own memory.
// `prev` in an arg slot means "the previous step's return"; `str0 + i`
// means "the i-th string, poked onto the task's stack".
struct GuestCalls {
    static constexpr std::uint64_t prev = 0xfeedfacecafe0001ull;
    static constexpr std::uint64_t str0 = 0xfeedfacecafe0100ull;
    // the return value of step i (prev is the one just before)
    static constexpr std::uint64_t prev_of(std::size_t i) { return 0xfeedfacecafe0200ull + i; }
    struct Step { Sysno nr; std::array<std::uint64_t, 6> a; };
    std::vector<Step> steps;
    std::vector<std::string> strings;
    // which step's result the guest gets (-1 = the last one)
    int result_of{-1};
    // if the result is 0, wait this long and run the guest's own call again
    // (a blocking wait made of non-blocking ones); 0 = never
    std::int64_t retry_if_zero_ns{0};
    // ...and treat -ECHILD from the last step like 0 (a tracer waiting for a
    // tracee that isn't its real child)
    bool echild_is_zero{false};
    // called with the final result before the guest sees it
    std::function<void(std::int64_t)> done{};
    // called while the task is still stopped, before it runs on
    std::function<void(std::int64_t)> before_resume{};
};

// EXITED - the guest asked to terminate. Carries the status, nothing else.
struct Exited {
    int code;

    constexpr explicit Exited(int c) noexcept : code{c} {}
};

// -- the sum ---------------------------------------------------------------

// Exactly one fate. No flags, no combinations, no precedence to remember.
using Fate = std::variant<Virtualize, Forward, Redirect, Inject,
                          Raise, ExecInterp, SockRewrite, ArgRewrite, GuestCalls, Exited>;

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
    [[nodiscard]] static Outcome raise_at(std::int32_t pid, std::int32_t sig) {
        return Outcome{Raise{pid, sig}};
    }
    [[nodiscard]] static Outcome raise_group(std::int32_t pid, std::int32_t sig,
                                             std::vector<std::int32_t> members) {
        return Outcome{Raise{pid, sig, std::move(members)}};
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
