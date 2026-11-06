// linuxity/runtime/backend.hpp
//
// The trap-backend contract, written down once.
//
// A backend's job is narrow: make guest syscalls trap, run the guest until one
// does, and then let the loop either answer it (resume with a value) or let the
// real host kernel run it (forward). Three exist -- ptrace+seccomp on Linux,
// Hypervisor.framework on macOS, WHP on Windows -- and the native-execution
// loop is written ONCE against this file.
//
// WHY THIS FILE EXISTS. The loop used to call 11 methods on its backend while
// the concept required 7. The other four were reached through
//
//     if constexpr (requires { trap_.rewrite_sockaddr(...); }) { ... }
//     else { forward(); }                       // <-- the silent path
//
// which is not a contract, it's duck-typing with a wrong-answer fallback. Three
// things went wrong with it:
//
//   1. A backend that MISSPELLED a method still compiled, and silently took
//      the else branch -- forwarding an untranslated guest path to the host.
//      For rewrite_sockaddr that means a guest's AF_UNIX socket escaping onto
//      the host filesystem. A typo could not fail the build.
//   2. Nobody could tell which backend supported what without grepping every
//      `requires` in the loop.
//   3. The signatures silently diverged: rewrite_sockaddr returned Status in
//      ptrace and Result<int64_t> in hvf; its socklen was uint64_t in one and
//      unsigned long long in the other. Nothing checked, because nothing was
//      ever instantiated against a written-down shape.
//
// The fix is two tiers, both checked by the compiler:
//
//   * SyscallTrap   -- the CORE every backend must have. No fallback: a
//                      missing or mistyped method is a build error naming it.
//   * The capability concepts (TranslatesSockets, ExecsThroughInterp, ...) --
//      genuinely optional abilities, each a NAMED concept a backend opts into
//      by implementing it. The loop still can't use one silently: it asks
//      `requires Capability<T>` and the backend declares support explicitly,
//      so a typo breaks the capability check instead of being papered over.
#pragma once

#include <concepts>
#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"

namespace lx::runtime {

struct TrapFrame;   // defined in trap.hpp

// -- the core contract -----------------------------------------------------

// Every backend must provide ALL of this. There is no fallback for any of it,
// so a missing or wrongly-typed member is a compile error that names the
// member rather than a silent behavioural change.
template <class T>
concept SyscallTrap = requires(T t, TrapFrame& f, std::int64_t ret) {
    // Begin executing the loaded guest at (entry, sp). Returns when the guest
    // first traps or exits.
    { t.start(UAddr{}, UAddr{}) }    -> std::same_as<Status>;
    // Block until the next syscall trap; fills `f`. false => guest exited.
    { t.next(f) }                    -> std::same_as<Result<bool>>;
    // VIRTUALIZE: set the syscall return value and resume (no real syscall).
    { t.resume(ret) }                -> std::same_as<Status>;
    // FORWARD: let the real host kernel run this syscall in the guest and
    // return its result. For mmap/brk/mprotect and host-backed I/O.
    { t.forward() }                  -> std::same_as<Result<std::int64_t>>;
    // REDIRECT: rewrite a char* path argument to a translated host path, then
    // forward. This is what carries the guest's namespace onto real files.
    { t.redirect(0, std::string{}) } -> std::same_as<Result<std::int64_t>>;
    // Whether the guest exited during the last resume()/forward().
    { t.exited() }                   -> std::same_as<bool>;
    // The guest's exit status once it has exited.
    { t.exit_code() }                -> std::same_as<int>;
};

// -- the capabilities ------------------------------------------------------
//
// These are REAL options, not accidents: a backend without a process table has
// no guest pid to deliver a signal to, and one that cannot rewrite argv cannot
// exec through an interpreter. Each is a named concept, so "which backend can
// do what" is answered by reading this file, and a misspelled method fails its
// capability check instead of vanishing into an `else`.

// REDIRECT with a scrub hook and an optional SECOND path (rename/link, whose
// two operands are both guest paths). The observer runs inside the stopped
// window, before the guest can read the buffer the host just filled.
template <class T>
concept RedirectsTwoPaths = SyscallTrap<T> && requires(T t) {
    { t.redirect(0, std::string{}, [](std::int64_t) {}, 0, std::string{}) }
        -> std::same_as<Result<std::int64_t>>;
};

// FORWARD synchronously, observing the result before the guest resumes. Needed
// to mirror fd bindings across dup/dup2/dup3/fcntl(F_DUPFD*).
template <class T>
concept ForwardsSynchronously = SyscallTrap<T> && requires(T t) {
    { t.forward_sync([](std::int64_t) {}) } -> std::same_as<Result<std::int64_t>>;
};

// AF_UNIX path translation: poke a translated host path into the guest's
// sun_path and fix the socklen register. Without this a guest's absolute
// sun_path lands on the HOST filesystem.
//
// The two backends legitimately finish differently, so the concept accepts
// either and the loop handles both:
//   * ptrace resumes the task ASYNCHRONOUSLY (PTRACE_SYSCALL) and has no
//     result yet, so it returns Status.
//   * hvf COMPLETES the syscall inline, so it returns the value, like
//     forward()/redirect().
// This divergence existed all along; the old inline `requires` probe just
// never looked at the return type, so nothing had to agree on it.
template <class T>
concept TranslatesSockets = SyscallTrap<T> && requires(T t) {
    { t.rewrite_sockaddr(UAddr{}, std::string{}, 0, std::uint64_t{}) };
};

// Which of the two it is, so the loop can branch on a named question.
template <class T>
concept SocketRewriteYieldsValue =
    TranslatesSockets<T> && requires(T t) {
        { t.rewrite_sockaddr(UAddr{}, std::string{}, 0, std::uint64_t{}) }
            -> std::same_as<Result<std::int64_t>>;
    };

// Rewrite a dynamic execve to run through the real interpreter:
// `interp_host <prog_guest> <argv...>`.
template <class T>
concept ExecsThroughInterp = SyscallTrap<T> && requires(T t) {
    { t.exec_through_interp(0, std::string{}, std::string{},
                            std::vector<std::string>{},
                            std::vector<std::string>{}) }
        -> std::same_as<Result<std::int64_t>>;
};

// Map a GUEST pid to its host tid and deliver a real signal there. Returns the
// value the guest's kill() should see.
template <class T>
concept DeliversSignals = SyscallTrap<T> && requires(T t) {
    { t.deliver_signal(std::int32_t{}, std::int32_t{}) }
        -> std::same_as<std::int64_t>;
};

// Replace one NON-PATH argument register, run the syscall, and hand its result
// to a callback before the guest sees it. Used to serve a syscall variant the
// host refuses (Android's SELinux ioctl whitelist rejects TCGETS2 on a pty) by
// downgrading it to one the host allows and fixing up the buffer.
template <class T>
concept RewritesArgs = SyscallTrap<T> && requires(T t) {
    { t.rewrite_arg(0, std::uint64_t{}, std::function<void(std::int64_t)>{}) }
        -> std::same_as<Result<std::int64_t>>;
};

// Report guest process lifecycle events (clone/exec/exit) the loop folds into
// the pid namespace. Each backend declares its OWN event type (ptrace nests a
// ProcEvent), so the requirement is on the SHAPE: a range of records carrying
// a kind, a pid and a ppid. A backend whose events don't carry those fields
// fails the check here rather than deep inside apply_proc_events.
template <class T>
concept ReportsProcEvents = SyscallTrap<T> && requires(T t) {
    { t.drain_proc_events() };
    requires requires(decltype(*std::begin(t.drain_proc_events())) e) {
        e.kind; e.pid; e.ppid;
    };
};

// -- the honest summary ----------------------------------------------------
//
// What a backend can do, as data. The loop branches on these instead of on an
// ad-hoc `requires` expression inline, so every capability decision in the
// run loop reads as a named question with an answer you can print.
template <class T>
struct Capabilities {
    static constexpr bool two_path_redirect = RedirectsTwoPaths<T>;
    static constexpr bool forward_sync      = ForwardsSynchronously<T>;
    static constexpr bool sockets           = TranslatesSockets<T>;
    static constexpr bool exec_interp       = ExecsThroughInterp<T>;
    static constexpr bool signals           = DeliversSignals<T>;
    static constexpr bool arg_rewrite       = RewritesArgs<T>;
    static constexpr bool proc_events       = ReportsProcEvents<T>;
};

// A backend that claims full fidelity must actually have everything. Assert
// this in a backend's own header to get a build error listing what's missing,
// instead of discovering it as a wrong answer at runtime.
template <class T>
concept CompleteTrap = SyscallTrap<T> && RedirectsTwoPaths<T> &&
                       ForwardsSynchronously<T> && TranslatesSockets<T> &&
                       ExecsThroughInterp<T> && DeliversSignals<T>;

} // namespace lx::runtime
