// linuxity/runtime/trap.hpp
//
// The syscall trap: how natively-executing guest code re-enters the runtime.
//
// This is the mechanism that makes "native speed" and "we service the
// syscalls" coexist. Guest code runs DIRECTLY on the CPU — every arithmetic,
// branch, and memory instruction executes bare, at full speed. The ONLY
// thing that must come back to us is the `syscall` instruction (x86-64) /
// `svc #0` (aarch64), because that's the guest asking the kernel — and we
// are the kernel.
//
// On Linux the production mechanism is SECCOMP_RET_TRAP: install a seccomp
// filter that returns SECCOMP_RET_TRAP for the guest thread, so every
// syscall instruction raises SIGSYS instead of entering the host kernel. The
// SIGSYS handler receives a siginfo + ucontext holding the guest register
// file; we decode it into abi::Regs, dispatch through the subsystems, write
// the return value back into the saved RAX/x0, and return from the handler —
// the CPU resumes the guest at the instruction after `syscall`. No emulation,
// no per-instruction cost; only syscalls pay a signal round-trip.
//
// (ptrace(PTRACE_SYSEMU) is the portable fallback; a KVM-less "process as
// address space" model. Both reduce to the same abstraction below: produce a
// guest register file, ask the runtime to service it, resume.)
//
// This header defines the ARCHITECTURE-NEUTRAL seam. The actual signal
// wiring is host-specific and lives behind the SyscallTrap concept, so the
// dispatcher and the process model never mention SIGSYS or ucontext.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/syscall.hpp"
#include "linuxity/host/tmpdir.hpp"
#include "linuxity/host/win_posix.hpp"
#include "linuxity/runtime/backend.hpp"

#include <array>
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <ctime>
#include <algorithm>
#include <unordered_map>
#include <vector>
#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#include <io.h>
#endif

namespace lx::runtime {

// The guest register snapshot at a trapped syscall, plus the machinery to
// resume. Arch-neutral: `regs` already carries the 6 args + nr in the
// canonical order abi::Syscalls expects (the host trap backend maps
// RAX/RDI/... or x8/x0/... into this).
struct TrapFrame {
    abi::Regs regs;         // decoded syscall number + arguments
    std::uint64_t pc{};     // guest program counter at the trap (for logging)
};

// A host trap backend models SyscallTrap. The contract -- the core every
// backend must implement, plus the named optional capabilities -- lives in
// backend.hpp, so "what must a backend provide" is one file to read rather
// than a scatter of inline `requires` probes through this loop.

// The native execution loop, written ONCE against the concept: run the guest
// at native speed; each time it traps, dispatch through the kernel and
// resume. This is the beating heart of "run the distro natively".
template <SyscallTrap T, kernel::IsKernel K, abi::GuestMem M>
class Cpu {
public:
    Cpu(T& trap, K& kernel, M& mem, abi::Arch arch)
        : trap_{trap}, kernel_{kernel}, mem_{mem}, arch_{arch} {}

    // Run a loaded process to completion; returns its exit code.
    [[nodiscard]] Result<int> run(UAddr entry, UAddr sp) {
        abi::Syscalls sys{kernel_, mem_, arch_};
        int exit_status = 0;
        // Kernel state is shared by every guest thread's loop; lock it for
        // BOOKKEEPING only. The host syscall itself (forward/redirect, which
        // may block in read/wait4/open-a-FIFO) runs unlocked, or one blocked
        // thread would freeze every other thread's dispatch.
        auto locked = [this](auto&& fn) -> decltype(auto) {
            if constexpr (requires { kernel_.mutex(); }) {
                std::lock_guard g{kernel_.mutex()};
                return fn();
            } else {
                return fn();
            }
        };
        static const char* const trace_env = [] {
            const char* t = std::getenv("LINUXITY_TRACE");
            return (t && *t) ? t : nullptr;
        }();
        // before the first child exists, so its waitpid can't take a guest's
        (void)memfd_reopen_ok();
        LX_TRY(trap_.start(entry, sp));
        // with host pids, init is the root task's real pid, known only now
        if constexpr (requires { trap_.init_gpid(); }) {
            const std::int32_t init = trap_.init_gpid();
            if (init != kernel_.procs().init_pid()) {
                kernel_.files().rekey_pid(kernel_.procs().init_pid(), init);
                kernel_.procs().rekey_init(init);
            }
        }
        // an instance can sit idle for minutes; apply exits as they happen
        if constexpr (requires { trap_.set_flush_events(std::function<void()>{}); })
            trap_.set_flush_events([&] { locked([&] { apply_proc_events(); }); });
        if constexpr (requires { trap_.ig_setup(kernel_, sys); })
            locked([&] { trap_.ig_setup(kernel_, sys); });
        // A backend that answers inotify itself (kernel/fsnotify.hpp) hears
        // every call's final result, so the dispatcher's planned events are
        // emitted exactly when the call succeeded.
        if constexpr (requires { trap_.set_result_observer(std::function<void(std::int64_t)>{}); })
            trap_.set_result_observer([&](std::int64_t rc) { locked([&] { sys.fsnotify_commit(rc); }); });
        if constexpr (requires { trap_.set_fsnotify_hub(nullptr); })
            trap_.set_fsnotify_hub(&kernel_.files().fsnotify());
        for (;;) {
            TrapFrame f;
            const auto t_wait = prof_.on ? prof_clock() : 0;
            bool still_running = LX_TRY(trap_.next(f));
            const auto t_got = prof_.on ? prof_clock() : 0;
            if (prof_.on) prof_.wait_ns += t_got - t_wait;
            locked([&] { apply_proc_events(); });
            if (!still_running) {
                cleanup_temps();
                if constexpr (requires { trap_.ig_report(); }) if (prof_.on) trap_.ig_report();
                prof_.report();
                return ok(trap_.exit_code());
            }

            // A hot read-only path query: maybe patch its site so the guest
            // answers the next ones itself (runtime/linux/inguest.hpp).
            // First, apply any fd changes the guest made on its own.
            if constexpr (requires { trap_.ig_before_dispatch(kernel_); })
                locked([&] { trap_.ig_before_dispatch(kernel_); });
            if constexpr (requires { trap_.ig_before_call(f.regs, kernel_); })
                locked([&] { trap_.ig_before_call(f.regs, kernel_); });
            if constexpr (requires { trap_.ig_maybe_patch(f.regs, f.pc, kernel_, sys); }) {
                if (locked([&] { return trap_.ig_maybe_patch(f.regs, f.pc, kernel_, sys); })) continue;
            }

            // The dispatcher classifies the trapped syscall: service it from
            // our subsystems, forward it to the host kernel, or exit.
            abi::Outcome o = locked([&] { return sys.dispatch(f.regs); });
            // An open's pending state, taken with the dispatch: the open runs
            // unlocked and a sibling thread's dispatch would clobber it. Only
            // the outcomes that open something carry it.
            using OpenState = typename std::remove_cvref_t<decltype(sys)>::OpenState;
            std::optional<OpenState> open_state;
            if (o.template get_if<abi::Inject>() || o.template get_if<abi::Redirect>())
                open_state = locked([&] { return sys.save_open_state(); });
            auto note_opened = [&](std::int64_t fd) {
                locked([&] {
                    if (open_state) sys.restore_open_state(std::move(*open_state));
                    sys.note_opened_fd(fd);
                });
            };
            // publish what the call changed to the in-guest handler
            if constexpr (runtime::AnswersInGuest<T, K, decltype(sys)>)
                locked([&] { trap_.ig_after_dispatch(f.regs, kernel_, sys); });
            // the host already refused this call, so it can't be forwarded or
            // redirected; anything but a virtualized answer is ENOSYS
            if constexpr (requires { trap_.refused_call(); })
                if (trap_.refused_call() && !o.template get_if<abi::Virtualize>())
                    o = abi::Outcome::error(Errno::enosys);
            if (const char* t = trace_env) trace_fate(t, f.regs, o);
            const int o_kind = prof_.on ? static_cast<int>(o.fate().index()) : 0;
            const auto t_disp = prof_.on ? prof_clock() : 0;

            // Act on the fate. Exactly one arm runs, chosen by the type, and
            // the compiler rejects this match if a fate is left unhandled --
            // no flag precedence to remember, no silent fallthrough.
            //
            // Each arm returns a Step: `done` to finish the whole run,
            // `again` to retry the loop (a trap primitive raced the guest and
            // the syscall was already completed with -errno), or `next` to
            // carry on. A fate CANNOT forget to say what happens next.
            const Step step = std::move(o).match(

                [&](abi::Exited e) { exit_status = e.code; return Step::done; },

                [&](const abi::GuestCalls& gc) {
                    // Run the chain inside the task, where only it can make the
                    // thing (a shared mapping in its own memory).
                    if constexpr (requires { trap_.run_in_guest({}, {}, -1, 0, false); }) {
                        using GC = typename T::GuestCall;
                        std::vector<GC> calls;
                        for (const auto& s : gc.steps) calls.push_back(GC{s.nr, s.a});
                        if constexpr (requires { trap_.set_before_resume({}); })
                            if (gc.before_resume)
                                trap_.set_before_resume([&](std::int64_t v) {
                                    locked([&] { gc.before_resume(v); });
                                });
                        auto rr = trap_.run_in_guest(calls, gc.strings, gc.result_of, gc.retry_if_zero_ns,
                                                     gc.echild_is_zero);
                        if (!rr) return recover(rr.error());
                        if (gc.done) locked([&] { gc.done(*rr); });
                        return Step::next;
                    } else {
                        auto st = trap_.resume(-static_cast<std::int64_t>(Errno::enosys));
                        if (!st) return recover(st.error());
                        return Step::next;
                    }
                },

                [&](const abi::Inject& in) {
                    // openat2's open_how, resolve cleared: our reopen path is
                    // ours, not the guest's, so RESOLVE_* must not judge it
                    auto arm_blob = [&] {
                        if constexpr (requires { trap_.set_arg_blob(0, std::string{}); })
                            if (in.blob)
                                trap_.set_arg_blob(in.blob->arg, std::string(
                                    reinterpret_cast<const char*>(in.blob->bytes.data()), in.blob->bytes.size()));
                    };
#if defined(__linux__)
                    // A file: a memfd of ours that the guest's open reopens
                    // through /proc/<us>/fd/N, with exactly the flags it asked
                    // for. No temp file, nothing under /tmp for a sandbox to
                    // hide, and the same inode refresh_virtual_fd rewrites.
                    if (!in.is_dir && !in.keep_name && in.reopen_ok && memfd_reopen_ok())
                        if (const int m = memfd_of(in.content); m >= 0) {
                            const std::string via = "/proc/" + std::to_string(::getpid()) +
                                                    "/fd/" + std::to_string(m);
                            arm_blob();
                            auto fdr = trap_.redirect(in.path_arg, via);
                            ::close(m);   // the guest's open holds it now
                            if (!fdr) return recover(fdr.error());
                            note_opened(*fdr);
                            return Step::next;
                        }
#endif
                    // A purely virtual node: back it with a real host temp -- a
                    // temp FILE (with the synthesized bytes) for a file, or an
                    // empty temp DIRECTORY for a virtual dir so O_DIRECTORY
                    // opens succeed and getdents64 (virtualized) can enumerate
                    // it. The open runs ASYNCHRONOUSLY in the child, so we must
                    // NOT unlink here -- the child hasn't opened it yet; temps
                    // are cleaned up at the end of the run.
                    // A virtual directory opens the host's twin (/proc, /sys, ...)
                    // when we may: it exists and is nothing of ours to clean.
                    // Android refuses apps most of /sys, so there it gets an
                    // empty temp dir; its entries come from getdents either way.
                    const bool twin = in.is_dir && !in.dir_host.empty() && dir_openable(in.dir_host);
                    std::string tmp = in.is_dir ? (twin ? std::string{} : materialize_dir())
                                                : materialize(in.content);
                    const std::string& backing = tmp.empty() && in.is_dir ? in.dir_host : tmp;
                    arm_blob();
                    auto fdr = trap_.redirect(in.path_arg, backing);
#if defined(__linux__)
                    // ptrace's redirect has run the open by now, so the fd
                    // holds the inode and the name can go. Keeping it leaked
                    // one temp per /proc read until exit, and forever on a kill.
                    if (!tmp.empty() && !in.keep_name) {
                        if (in.is_dir) ::rmdir(tmp.c_str()); else ::unlink(tmp.c_str());
                        tmp.clear();
                    }
#endif
                    if (!fdr) return recover(fdr.error());
                    if (!tmp.empty()) temps_.push_back(std::move(tmp));
                    note_opened(*fdr);
                    return Step::next;
                },

                [&](const abi::Redirect& rd) {
                    // Host-backed path: rewrite the arg to the real host path
                    // and let the kernel run it in the child (real fd for
                    // mmap). A host-backed stat leaves the HOST file's owner in
                    // the guest buffer; scrub it to root in the SAME stopped
                    // window, before the task resumes and could read it.
                    //
                    // A mutation may need its destination's parent host dirs to
                    // exist first (the overlay upper starts empty), and may
                    // carry a SECOND path to translate (rename/link/symlink).

                    // When the translation is an identity and there
                    // is nothing else to do, the guest's registers already say
                    // what we would write. Forwarding costs one stop and no
                    // guest-memory traffic; redirecting costs two stops plus a
                    // path poke. That is the common case without --root, where
                    // the guest tree IS the host tree.
                    if (rd.is_noop()) {
                        auto fr = trap_.forward();
                        if (!fr) return recover(fr.error());
                        return Step::next;
                    }

                    const int   arg2 = rd.second ? rd.second->arg : -1;
                    const auto& hp2  = rd.second ? rd.second->host_path
                                                 : empty_path();
                    if constexpr (requires { trap_.set_arg_blob(0, std::string{}); })
                        if (rd.blob)
                            trap_.set_arg_blob(rd.blob->arg, std::string(
                                reinterpret_cast<const char*>(rd.blob->bytes.data()), rd.blob->bytes.size()));
                    if constexpr (requires { trap_.redirect_deferred(0, std::string{}, nullptr); }) {
                        if (rd.may_block && !rd.second && !rd.scrub) {
                            if (rd.make_parents) make_host_parents(rd.first.host_path);
                            auto po = locked([&] { return sys.take_pending_open(); });
                            auto st = trap_.redirect_deferred(
                                rd.first.arg, rd.first.host_path,
                                [&locked, &sys, po = std::move(po)](std::int64_t ret) mutable {
                                    locked([&] { sys.finish_pending_open(std::move(po), ret); });
                                });
                            if (!st) return recover(st.error());
                            return Step::next;
                        }
                    }
                    if (rd.make_parents) {
                        make_host_parents(rd.first.host_path);
                        if (rd.second) make_host_parents(hp2);
                    }
                    // PATH_MAX applies to the string, not the depth: rebase an
                    // over-long host path onto the call's own dirfd -- unless
                    // the backend walks long paths itself (WalksLongPaths).
                    std::string hp1_fit = rd.first.host_path, hp2_fit = hp2;
                    if constexpr (!runtime::WalksLongPaths<T>) locked([&] {
                        if (auto s = sys.rebase_on_dirfd(f.regs, rd.first.arg, hp1_fit)) hp1_fit = *s;
                        if (rd.second)
                            if (auto s = sys.rebase_on_dirfd(f.regs, arg2, hp2_fit)) hp2_fit = *s;
                    });
                    auto retr = trap_.redirect(
                        rd.first.arg, hp1_fit,
                        [&](std::int64_t rc) {
                            // Only a successful stat has a buffer worth fixing,
                            // and only a Redirect can even carry a scrub.
                            if (rc == 0 && rd.scrub)
                                locked([&] { sys.scrub_ids(*rd.scrub); });
                            if (rc == 0 && rd.created)
                                locked([&] { sys.note_created(*rd.created, rd.created_dir); });
                            if (rc == 0 && rd.moved)
                                locked([&] { sys.note_moved(rd.moved->first, rd.moved->second); });
                            if (rc == 0 && rd.removed)
                                locked([&] { sys.note_removed(*rd.removed); });
                            if (rc == 0 && rd.linked)
                                locked([&] { sys.note_linked(rd.linked->first, rd.linked->second); });
                            if constexpr (requires { trap_.set_ret_now(std::int64_t{0}); })
                                if (rd.force_ret) trap_.set_ret_now(*rd.force_ret);
                            // a new fd: tell the in-guest handler what it is
                            // now, before the task runs on and uses it
                            if constexpr (requires { trap_.ig_note_fd(kernel_, 0, std::string{}); })
                                if (rc >= 0 && !rd.force_ret)
                                    locked([&] {
                                        if (!sys.pending_open_path().empty())
                                            trap_.ig_note_fd(kernel_, static_cast<int>(rc), sys.pending_open_path());
                                    });
                        },
                        arg2, hp2_fit);
                    if (!retr) return recover(retr.error());
                    if (rd.force_ret) return Step::next;   // nothing was opened
                    note_opened(*retr);
                    return Step::next;
                },

                [&](const abi::SockRewrite& sr) {
                    // AF_UNIX bind/connect: create the socket's parent chain in
                    // the overlay upper, then poke the translated host path into
                    // the guest's sun_path and forward.
                    //
                    // The two backends finish differently (see backend.hpp):
                    // ptrace resumes asynchronously and yields a Status, hvf
                    // completes the syscall and yields its value.
                    make_host_parents(sr.host_path);
                    if constexpr (runtime::TranslatesSockets<T>) {
                        const int sock_fd = static_cast<int>(f.regs.arg[0]);
                        int sock_tid = -1;
                        if constexpr (requires { trap_.host_tid(); }) sock_tid = trap_.host_tid();
                        auto rr = [&] {
                            if constexpr (requires { trap_.rewrite_sockaddr(sr.path_addr, sr.host_path, 0, 0, nullptr); })
                                return trap_.rewrite_sockaddr(
                                    sr.path_addr, sr.host_path, sr.len_arg, sr.new_len,
                                    [&locked, &sys, sock_tid, sock_fd, name = sr.guest_path, binds = sr.binds](std::int64_t ret) {
                                        if (ret == 0)
                                            locked([&] { sys.note_socket_name(sock_tid, sock_fd, name, binds); });
                                    });
                            else
                                return trap_.rewrite_sockaddr(sr.path_addr, sr.host_path, sr.len_arg, sr.new_len);
                        }();
                        if (!rr) return recover(rr.error());
                        return Step::next;
                    } else {
                        // The backend cannot translate sun_path. Fail the call
                        // rather than forwarding the UNTRANSLATED guest path,
                        // which is what the old silent fallback did -- that put
                        // the guest's socket on the HOST filesystem. ENOTSUP is
                        // a truthful answer; a leaked host socket is not.
                        auto st = trap_.resume(
                            -static_cast<std::int64_t>(Errno::enotsup));
                        if (!st) return Step::fail;
                        return Step::next;
                    }
                },

                [&](abi::Raise k) {
                    // The guest signalled a GUEST pid. Deliver the real signal
                    // to that task's host tid, then hand the caller the result.
                    // The target's death, if fatal, is observed as a normal reap
                    // by next() on a later iteration.
                    std::int64_t ret =
                        -static_cast<std::int64_t>(Errno::eperm);
                    if constexpr (runtime::DeliversSignals<T>) {
                        if (k.grouped) {
                            // A group, already resolved to its members by the
                            // ABI layer. Success if ANY member got it, like
                            // kill(2); the first error otherwise.
                            int delivered = 0;
                            std::int64_t first = 0;
                            for (const std::int32_t m : k.members) {
                                const std::int64_t rc =
                                    trap_.deliver_signal(m, k.signum);
                                if (rc == 0) ++delivered;
                                else if (first == 0) first = rc;
                            }
                            ret = delivered ? 0
                                : (first ? first
                                         : -static_cast<std::int64_t>(Errno::esrch));
                        } else {
                            ret = trap_.deliver_signal(k.guest_pid, k.signum);
                        }
                    }
                    auto st = trap_.resume(ret);
                    if (!st) return Step::fail;
                    return Step::next;
                },

                [&](const abi::ExecInterp& ei) {
                    // A dynamic guest execve: rewrite it to run through the
                    // real interpreter. The image is replaced on success and
                    // observed as an EXEC event.
                    if constexpr (runtime::ExecsThroughInterp<T>) {
                        auto er = trap_.exec_through_interp(
                            ei.path_arg, ei.interp_host, ei.prog_guest,
                            ei.prefix, ei.extra_args);
                        if (!er) return recover(er.error());
                        return Step::next;
                    } else {
                        // Without argv rewriting a dynamic exec cannot work:
                        // the host would resolve PT_INTERP against the HOST
                        // root. ENOEXEC says exactly that.
                        auto st = trap_.resume(
                            -static_cast<std::int64_t>(Errno::enoexec));
                        if (!st) return Step::fail;
                        return Step::next;
                    }
                },

                [&](const abi::Forward& fo) {
                    // A dup/dup2/dup3/fcntl(F_DUPFD*) must step SYNCHRONOUSLY
                    // so we can read the real new fd and mirror the source fd's
                    // path / virtual-dir binding onto it (an *at call or
                    // getdents on the dup must resolve the same path and
                    // entries). dup2/dup3 first close their explicit target, so
                    // drop its stale binding.
                    if constexpr (runtime::ForwardsSynchronously<T>) {
                        if (fo.mirror) {
                            const int from   = fo.mirror->from;
                            const int closed = fo.mirror->close_first;
                            auto fr = trap_.forward_sync([&](std::int64_t ret) {
                                if (ret < 0) return;
                                locked([&] {
                                    if (closed >= 0 && closed != from)
                                        sys.on_fd_closed(closed);
                                    sys.on_fd_dup(from, static_cast<int>(ret));
                                });
                                if constexpr (requires { trap_.ig_note_fd(kernel_, 0, std::string{}); })
                                    locked([&] {
                                        trap_.ig_note_fd(kernel_, static_cast<int>(ret),
                                                         std::string{kernel_.files().path_of_fd(static_cast<int>(ret))});
                                    });
                            });
                            if (!fr) return recover(fr.error());
                            return Step::next;
                        }
                    }
                    // Let the host kernel run it IN the guest (mmap/brk/...).
                    // A backend without forward_sync still dups correctly; it
                    // just can't mirror the binding, so *at calls through the
                    // new fd fall back to plain path resolution.
                    auto fr = trap_.forward();
                    if (!fr) return recover(fr.error());
                    return Step::next;
                },

                [&](const abi::ArgRewrite& ar) {
                    // Swap one argument register, run the real syscall, then
                    // convert the buffer it filled. Needs a backend that can
                    // both write a register and step to the exit stop; without
                    // that the guest's own request stands and we just forward
                    // (the host may well allow it -- this is a workaround for
                    // hosts that don't, not a correctness requirement).
                    if constexpr (runtime::RewritesArgs<T>) {
                        const auto conv  = ar.convert;
                        const auto buf   = ar.buf;
                        const auto len   = ar.len;
                        const std::string name = ar.name;
                        auto fr = trap_.rewrite_arg(
                            ar.arg, ar.to, [&](std::int64_t ret) {
                                if (ret < 0) return;
                                using C = abi::ArgRewrite::Convert;
                                switch (conv) {
                                    case C::termios_to_termios2:
                                        widen_termios(buf); break;
                                    case C::unix_name:
                                        put_unix_name(buf, len, name); break;
                                    case C::none: break;
                                }
                            });
                        if (!fr) return recover(fr.error());
                        return Step::next;
                    } else {
                        auto fr = trap_.forward();
                        if (!fr) return recover(fr.error());
                        return Step::next;
                    }
                },

                [&](abi::Virtualize v) {
                    if constexpr (requires { trap_.mirror_setpgid(0, 0, std::int64_t{0}); }) {
                        using Mir = abi::Virtualize::Mirror;
                        if (v.host_mirror != Mir::none) {
                            auto fr = v.host_mirror == Mir::setpgid
                                          ? trap_.mirror_setpgid(v.m_a, v.m_b, v.ret)
                                          : trap_.mirror_tcsetpgrp(v.m_ptr, v.m_a, v.ret);
                            if (v.host_mirror == Mir::tcsetpgrp) locked([&] { sys.note_foreground(); });
                            if (!fr) return recover(fr.error());
                            return Step::next;
                        }
                    }
                    if constexpr (requires { trap_.wait_then_retry(std::int64_t{0}); }) {
                        if (v.retry_ns > 0) {
                            auto st = trap_.wait_then_retry(v.retry_ns);
                            if (!st) return recover(st.error());
                            return Step::next;
                        }
                    }
                    if constexpr (requires { trap_.forward_sync_then_set(std::int64_t{0}); }) {
                        if (v.mirror_host) {
                            // run the real call for its host effect, then
                            // hand the guest our answer instead of its result
                            auto fr = trap_.forward_sync_then_set(v.ret);
                            if (!fr) return recover(fr.error());
                            return Step::next;
                        }
                    }
                    // Hand the guest our answer; no real syscall runs.
                    locked([&] { sys.note_foreground(); });
                    auto st = trap_.resume(v.ret);
                    if (!st) return Step::fail;
                    return Step::next;
                });

            switch (step) {
                case Step::done:  cleanup_temps(); prof_.report(); return ok(exit_status);
                case Step::fail:  cleanup_temps();
                                  return std::unexpected(Errno::eio);
                case Step::again: continue;
                case Step::next:  break;
            }
            if (prof_.on) prof_.add(f.regs.nr, o_kind, prof_clock() - t_got, t_disp - t_got);
            // The trap continues the task asynchronously; whole-tree exit is
            // reported by next() returning false, so we just loop.
        }
    }

private:
    // A trap primitive (redirect/inject/forward/exec_interp) failed while
    // servicing ONE guest syscall. Crucially this is NOT a reason to tear
    // down the whole runtime — it usually means the guest task raced us
    // (a short-lived helper forked by gpg/dirmngr dying mid-poke yields
    // EFAULT/ESRCH from process_vm_* or PTRACE_POKEDATA). The correct guest
    // semantics is to complete THAT syscall with -errno and keep running the
    // rest of the tree. So we resume the still-stopped task with the errno as
    // its return value. Only a failure to even resume the task (the tracer
    // itself is desynced) is genuinely fatal and propagates out of run().
    //
    // ESRCH specifically means the task is already gone; there is nothing to
    // resume and next() will observe its reap on the following iteration, so
    // we simply swallow it and loop.
    // What the loop does after acting on one fate. Every match arm must
    // return one of these, so an arm cannot forget to say what happens next.
    enum class Step {
        next,   // fate handled; the task continues, loop again
        again,  // the syscall was already completed with -errno; just loop
        done,   // the guest exited; finish the run
        fail,   // a trap primitive failed unrecoverably
    };

    // A trap primitive failed. ESRCH means the task died under us, which is
    // normal; anything else is pushed back to the guest as -errno. Either way
    // the loop just goes round again.
    [[nodiscard]] Step recover(Errno e) {
        if (const char* t = std::getenv("LINUXITY_TRACE"); t && *t)
            std::fprintf(trace_out(t),
                "[lx] trap op failed errno=%d -> recovered (inject to guest)\n",
                int(e));
        if (e == Errno::esrch) return Step::again;
        if (!trap_.resume(-static_cast<std::int64_t>(e))) return Step::fail;
        return Step::again;
    }

    // A stable empty string to bind the "no second path" reference to.
    [[nodiscard]] static const std::string& empty_path() {
        static const std::string kEmpty;
        return kEmpty;
    }

    // getsockname/getpeername/accept filled a sockaddr_un with the host path
    // the kernel holds; put back the name the guest bound, within the
    // caller's buffer, and report the full length as the kernel does.
    void put_unix_name(UAddr buf, UAddr len, const std::string& name) {
        std::array<std::byte, 4> lb{};
        if (!trap_.copy_in(len, lb)) return;
        std::uint32_t cap = 0;
        std::memcpy(&cap, lb.data(), 4);
        std::array<std::byte, 110> sa{};
        const std::uint16_t fam = 1;   // AF_UNIX (the guest's ABI, not the host's headers)
        std::memcpy(sa.data(), &fam, 2);
        const bool abstract = !name.empty() && name.front() == '\0';
        const std::size_t n = std::min<std::size_t>(name.size(), 107);
        std::memcpy(sa.data() + 2, name.data(), n);
        const std::uint32_t full = static_cast<std::uint32_t>(2 + n + (abstract ? 0 : 1));
        const std::size_t wrote = std::min<std::size_t>(cap, full);
        if (wrote) (void)trap_.copy_out(buf, std::span<const std::byte>{sa.data(), wrote});
        std::memcpy(lb.data(), &full, 4);
        (void)trap_.copy_out(len, lb);
    }

    // Turn the struct termios the host's TCGETS wrote into the struct
    // termios2 the guest's TCGETS2 asked for. Same first 36 bytes, then two
    // speed fields the classic ioctl never writes -- so fill them from the
    // CBAUD code already in c_cflag. Verified on a pty: the kernel reports a
    // real Bxxx code there (not BOTHER), so nothing is lost in the downgrade.
    void widen_termios(UAddr buf) {
        constexpr std::size_t kTermios  = 36;   // 4 flags + c_line + 19 c_cc
        constexpr std::uint32_t kCbaud  = 0x0000100f;
        constexpr std::uint32_t kBother = 0x00001000;
        std::array<std::byte, kTermios> t{};
        if (!trap_.copy_in(buf, t)) return;
        std::uint32_t cflag = 0;
        std::memcpy(&cflag, t.data() + 8, 4);          // c_cflag is field 3
        const std::uint32_t speed = baud_of(cflag & kCbaud);
        // BOTHER means the speed lives ONLY in the speed fields, which the
        // classic ioctl didn't give us. Leave them zero rather than invent a
        // rate -- a pty never reports BOTHER, so this is a safety net.
        const std::uint32_t v = (cflag & kCbaud) == kBother ? 0 : speed;
        std::array<std::byte, 8> tail{};
        std::memcpy(tail.data(),     &v, 4);           // c_ispeed
        std::memcpy(tail.data() + 4, &v, 4);           // c_ospeed
        (void)trap_.copy_out(uaddr(value(buf) + kTermios), tail);
    }

    // The CBAUD code -> its baud rate. Only the codes a terminal actually
    // reports; anything else gives 0, which is what B0 means anyway.
    static std::uint32_t baud_of(std::uint32_t code) {
        switch (code) {
            case 0x1:  return 50;      case 0x2:  return 75;
            case 0x3:  return 110;     case 0x4:  return 134;
            case 0x5:  return 150;     case 0x6:  return 200;
            case 0x7:  return 300;     case 0x8:  return 600;
            case 0x9:  return 1200;    case 0xa:  return 1800;
            case 0xb:  return 2400;    case 0xc:  return 4800;
            case 0xd:  return 9600;    case 0xe:  return 19200;
            case 0xf:  return 38400;
            case 0x1001: return 57600;   case 0x1002: return 115200;
            case 0x1003: return 230400;  case 0x1004: return 460800;
            case 0x1005: return 500000;  case 0x1006: return 576000;
            case 0x1007: return 921600;  case 0x1008: return 1000000;
            case 0x1009: return 1152000; case 0x100a: return 1500000;
            case 0x100b: return 2000000; case 0x100c: return 2500000;
            case 0x100d: return 3000000; case 0x100e: return 3500000;
            case 0x100f: return 4000000;
            default: return 0;
        }
    }

    // One line per serviced syscall under LINUXITY_TRACE. The fate names
    // itself, so this is a match too rather than a row of flag tests.
    //
    // The first two arguments are printed too. Without them an ioctl is just
    // "nr=29 -> VIRT", and finding WHICH request a tty bug turned on took a
    // round of guessing; a0/a1 is the fd and the request for ioctl, and the
    // dirfd and path pointer for the *at calls.
    void trace_fate(const char* t, const abi::Regs& rg, const abi::Outcome& o) {
        const auto nr = static_cast<unsigned long long>(rg.nr);   // %llu below
        std::FILE* out = trace_out(t);
        std::fprintf(out, "[lx] a0=%#llx a1=%#llx ",
                     static_cast<unsigned long long>(rg.arg[0]),
                     static_cast<unsigned long long>(rg.arg[1]));
        o.match(
            [&](const abi::Virtualize& v) {
                std::fprintf(out, "[lx] nr=%llu -> VIRT ret=%lld\n",
                    nr, static_cast<long long>(v.ret));
            },
            [&](const abi::Forward& f) {
                if (f.mirror)
                    std::fprintf(out, "[lx] nr=%llu -> FORWARD dup_from=%d\n",
                        nr, f.mirror->from);
                else
                    std::fprintf(out, "[lx] nr=%llu -> FORWARD\n",
                        nr);
            },
            [&](const abi::Redirect& rd) {
                // Say when the rewrite is an identity and the loop will just
                // forward: otherwise the trace reports INTENT and hides the
                // plain forward, which made a profile look unchanged after it
                // landed.
                if (rd.is_noop()) {
                    std::fprintf(out, "[lx] nr=%llu -> FORWARD (identity %s)\n",
                        nr, rd.first.host_path.c_str());
                    return;
                }
                std::fprintf(out, "[lx] nr=%llu -> REDIRECT %s%s%s%s\n",
                    nr, rd.first.host_path.c_str(),
                    rd.second ? " -> " : "",
                    rd.second ? rd.second->host_path.c_str() : "",
                    rd.scrub ? " +scrub" : "");
            },
            [&](const abi::Inject& in) {
                std::fprintf(out, "[lx] nr=%llu -> INJECT %zu bytes%s\n",
                    nr, in.content.size(),
                    in.is_dir ? " (dir)" : "");
            },
            [&](const abi::Raise& k) {
                std::fprintf(out, "[lx] nr=%llu -> SIGNAL pid=%d sig=%d\n",
                    nr, k.guest_pid, k.signum);
            },
            [&](const abi::ExecInterp& ei) {
                std::fprintf(out, "[lx] nr=%llu -> EXECINT %s %s\n",
                    nr, ei.interp_host.c_str(),
                    ei.prog_guest.c_str());
            },
            [&](const abi::SockRewrite& sr) {
                std::fprintf(out, "[lx] nr=%llu -> SOCKREWRITE %s\n",
                    nr, sr.host_path.c_str());
            },
            [&](const abi::ArgRewrite& ar) {
                std::fprintf(out, "[lx] nr=%llu -> ARGREWRITE a%d=%#llx%s\n",
                    nr, ar.arg,
                    static_cast<unsigned long long>(ar.to),
                    ar.convert == abi::ArgRewrite::Convert::termios_to_termios2
                        ? " +widen_termios" : "");
            },
            [&](const abi::GuestCalls& gc) {
                std::fprintf(out, "[lx] nr=%llu -> GUESTCALLS steps=%zu\n",
                    nr, gc.steps.size());
            },
            [&](const abi::Exited& e) {
                std::fprintf(out, "[lx] nr=%llu -> EXIT code=%d\n",
                    nr, e.code);
            });
    }

    [[nodiscard]] Status recover_syscall(Errno e) {
        if (const char* t = std::getenv("LINUXITY_TRACE"); t && *t)
            std::fprintf(trace_out(t),
                "[lx] trap op failed errno=%d -> recovered (inject to guest)\n",
                int(e));
        if (e == Errno::esrch) return ok();
        LX_TRY(trap_.resume(-static_cast<std::int64_t>(e)));
        return ok();
    }

    // Fold the trap's observed fork/exec/exit events into the kernel's
    // ProcessTable, so a process monitor (top/htop/ps) reading synthesized
    // /proc sees linuxity's real, live process tree. Gated on the NAMED
    // capability (backend.hpp), not an inline probe: a backend that misspells
    // drain_proc_events now fails ReportsProcEvents where it declares itself,
    // instead of silently reporting no process events forever.
    void apply_proc_events() {
        // the CLONE_NEW* a spawn carries, on backends that report them
        auto ns_flags_of = [](const auto& e) -> std::uint64_t {
            if constexpr (requires { e.ns_flags; }) return e.ns_flags;
            else return 0;
        };
        if constexpr (runtime::ReportsProcEvents<T>) {
            for (auto& e : trap_.drain_proc_events()) {
                using EV = std::decay_t<decltype(e)>;
                switch (e.kind) {
                    case EV::spawn: {
                        kernel::ProcInfo pi;
                        pi.pid  = static_cast<std::int32_t>(e.pid);
                        pi.ppid = static_cast<std::int32_t>(e.ppid);
                        pi.comm = "(spawning)";
                        pi.cmdline = "(spawning)";
                        pi.vsize_bytes = 4u << 20;   // plausible until first exec
                        pi.rss_pages = 256;
                        // fork copies the parent's image, so it has the same
                        // exe, comm and argv until it execs
                        if (const auto* pp = kernel_.procs().find(pi.ppid)) {
                            pi.comm = pp->comm;
                            pi.cmdline = pp->cmdline;
                            pi.vsize_bytes = pp->vsize_bytes;
                            pi.rss_pages = pp->rss_pages;
                            pi.creds() = pp->creds();       // fork: one value, every field
                            pi.creds_given = true;
                            kernel_.procs().inherit_ns(pi, *pp, kernel_.procs().take_clone_ns(pi.ppid) | ns_flags_of(e));
                        }
                        pi.state = 'R';
                        // The child may have run (and setsid/setpgid/setuid'd)
                        // before this event is applied; then it already has a
                        // record and only the gaps get filled from here.
                        if (auto* existing = kernel_.procs().find_mut(pi.pid); existing && existing->live_seen) {
                            if (existing->ppid == 0) existing->ppid = pi.ppid;
                            if (existing->comm == "linuxity" || existing->comm.empty()) {
                                existing->comm = pi.comm;
                                existing->cmdline = pi.cmdline;
                            }
                            // It took its namespaces from its parent at its
                            // first call and may have unshared since: add only
                            // what the clone itself asked for (CLONE_NEW*),
                            // once, and keep the rest.
                            if (!existing->clone_ns_applied) {
                                const std::uint64_t cf = kernel_.procs().take_clone_ns(pi.ppid) | ns_flags_of(e);
                                if (cf) kernel_.procs().unshare_ns(*existing, cf);
                                existing->clone_ns_applied = true;
                            }
                            kernel_.procs().assign_ns_pid(existing->pid);
                            // its cwd and fds are its own by now
                            if (!kernel_.files().cwd_known(static_cast<std::int32_t>(e.pid)))
                                kernel_.files().inherit_cwd(
                                    static_cast<std::int32_t>(e.pid),
                                    static_cast<std::int32_t>(e.ppid));
                            break;
                        }
                        kernel_.procs().upsert(pi);
                        kernel_.procs().assign_ns_pid(pi.pid);
                        // a forked child shares its parent's SysV attaches
                        kernel_.procs().ipc().inherit(pi.pid, pi.ppid);
                        // A freshly forked child inherits a COPY of its
                        // parent's cwd AT FORK TIME. Seeding it here (rather
                        // than lazily on the child's first syscall) means the
                        // record is correct even if the parent chdir's away
                        // before the child runs, and a later pid reuse can't
                        // pick up a stale parent cwd.
                        kernel_.files().inherit_cwd(
                            static_cast<std::int32_t>(e.pid),
                            static_cast<std::int32_t>(e.ppid));
                        break;
                    }
                    case EV::exec:
                        if (auto* pi = kernel_.procs().find(
                                static_cast<std::int32_t>(e.pid))) {
                            kernel::ProcInfo np = *pi;
                            if (!e.comm.empty()) {
                                np.comm = e.comm;
                                // Prefer the real argv captured at exec; fall
                                // back to comm so there's always a name.
                                np.cmdline = e.cmdline.empty() ? e.comm
                                                               : e.cmdline;
                            }
                            np.state = 'R';
                            np.creds_given = false;      // exec keeps them (upsert)
                            kernel_.procs().upsert(np);
                            // execve's credential transform (set-ID bits
                            // path_exec resolved) and SysV detach, shared
                            abi::creds::exec_happened(kernel_.procs(), np.pid);
                        }
                        break;
                    case EV::thread:
                        kernel_.procs().add_thread(static_cast<std::int32_t>(e.ppid),
                                                   static_cast<std::int32_t>(e.pid));
                        break;
                    case EV::stop:
                    case EV::cont:
                        if (auto* p = kernel_.procs().find_mut(static_cast<std::int32_t>(e.pid)))
                            p->state = e.kind == EV::stop ? 'T' : 'R';
                        break;
                    case EV::reparent:
                        if (auto* p = kernel_.procs().find_mut(static_cast<std::int32_t>(e.pid)))
                            p->ppid = static_cast<std::int32_t>(e.ppid);
                        break;
                    case EV::reap:
                        kernel_.procs().drop_thread(static_cast<std::int32_t>(e.pid));
                        // its SysV attaches go and its SEM_UNDO adjustments apply
                        kernel_.procs().ipc().process_gone(static_cast<std::int32_t>(e.pid));
                        // pid 1 (our init) is never removed: /proc must always
                        // have a root even as the last guest thread winds down.
                        if (e.pid != kernel_.procs().init_pid()) {
                            // NOT drop_ns_pid here: like the kernel, a zombie
                            // keeps its pid until its parent waits for it, and
                            // the parent waits by the namespace's number. It
                            // goes when a new process would take that number
                            // (assign_ns_pid skips numbers still held).
                            kernel_.procs().retire_ns_pid(static_cast<std::int32_t>(e.pid));
                            kernel_.procs().remove(static_cast<std::int32_t>(e.pid));
                            // Drop the exited pid's cwd record so a later pid
                            // REUSE starts from its real parent's cwd instead
                            // of resurrecting the dead process's directory
                            // (this is the git pack-helper tmp_pack_* leak:
                            // the helper chdir'd into a temp dir, exited, and
                            // the reused pid inherited that stale cwd).
                            kernel_.files().forget_pid(
                                static_cast<std::int32_t>(e.pid));
                        }
                        break;
                }
            }
        }
    }

    // Where the LINUXITY_TRACE log goes. If the value looks like a path
    // (contains '/'), append to that file (opened once); otherwise stderr.
    // Routing to a file keeps the trace out of a guest TUI's pty stream.
    static std::FILE* trace_out(const char* val) {
        static std::FILE* f = [val] {
            if (std::strchr(val, '/')) {
                if (std::FILE* fp = std::fopen(val, "w")) return fp;
            }
            return stderr;
        }();
        return f;
    }

    // A memfd holding `bytes`, or -1. The guest reopens it by path.
    static int memfd_of(const std::vector<std::byte>& bytes) {
#if defined(__linux__)
        const int fd = static_cast<int>(::syscall(SYS_memfd_create, "linuxity-vfile", 1u /*MFD_CLOEXEC*/));
        if (fd < 0) return -1;
        std::size_t off = 0;
        while (off < bytes.size()) {
            const auto n = ::write(fd, bytes.data() + off, bytes.size() - off);
            if (n <= 0) { ::close(fd); return -1; }
            off += static_cast<std::size_t>(n);
        }
        return fd;
#else
        (void)bytes;
        return -1;
#endif
    }

    // Write bytes to a fresh host temp file, return its path ("" on failure).
    // Used to back an INJECT (virtual file) with a real, mmappable fd.
    static std::string materialize(const std::vector<std::byte>& bytes) {
        std::string tmpl = host::tmp_path("linuxity-vfile-XXXXXX");
        int fd = ::mkstemp(tmpl.data());
        if (fd < 0) return {};
        std::size_t off = 0;
        while (off < bytes.size()) {
            auto n = ::write(fd, bytes.data() + off, bytes.size() - off);
            if (n <= 0) break;
            off += static_cast<std::size_t>(n);
        }
        ::close(fd);
        return tmpl;
    }

    // Create a fresh empty host temp DIRECTORY, return its path. Backs a
    // virtual directory so the child's O_DIRECTORY open succeeds; the actual
    // entries are served by the virtualized getdents64.
    static std::string materialize_dir() {
        std::string tmpl = host::tmp_path("linuxity-vdir-XXXXXX");
        return ::mkdtemp(tmpl.data()) ? tmpl : std::string{};
    }

    // Can a guest open this host directory? Same domain as us, so ask once
    // per path and remember.
    static bool dir_openable(const std::string& p) {
        static std::mutex mu;
        static std::unordered_map<std::string, bool> seen;
        std::lock_guard g{mu};
        if (auto it = seen.find(p); it != seen.end()) return it->second;
        const int fd = ::open(p.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) ::close(fd);
        return seen[p] = fd >= 0;
    }

    // LINUXITY_PROFILE=1: where the time goes. Per syscall and fate, how
    // often it was trapped and how long linuxity spent on it (dispatch plus
    // acting on it, which includes the extra stops a redirect needs), and how
    // long the loop waited for the next trap. Printed at exit.
    static std::uint64_t prof_clock() {
        ::timespec ts{};
        ::clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull + static_cast<std::uint64_t>(ts.tv_nsec);
    }
    struct Profile {
        bool on = [] { const char* p = std::getenv("LINUXITY_PROFILE"); return p && *p && *p != '0'; }();
        struct Cell { std::uint64_t n{0}, ns{0}, disp{0}; };
        std::unordered_map<std::uint64_t, Cell> cells;   // (nr << 8) | fate
        std::uint64_t wait_ns{0};
        void add(std::uint64_t nr, int fate, std::uint64_t ns, std::uint64_t disp) {
            auto& c = cells[(nr << 8) | static_cast<std::uint64_t>(fate)];
            ++c.n;
            c.ns += ns;
            c.disp += disp;
        }
        void report() {
            if (!on || cells.empty()) return;
            static constexpr const char* kFate[] = {"virt", "forward", "redirect", "inject", "raise",
                                                    "exec", "sock", "argrw", "guestcall", "exit"};
            std::vector<std::pair<std::uint64_t, Cell>> v(cells.begin(), cells.end());
            std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second.ns > b.second.ns; });
            std::uint64_t total = 0, calls = 0;
            for (auto& [k, c] : v) { total += c.ns; calls += c.n; }
            std::fprintf(stderr, "\nlinuxity profile: %llu trapped calls, %.1f ms handling them, %.1f ms waiting for the next\n"
                                 "  %-6s %-9s %9s %10s %9s %9s\n",
                         static_cast<unsigned long long>(calls), static_cast<double>(total) / 1e6,
                         static_cast<double>(wait_ns) / 1e6, "nr", "fate", "calls", "total ms", "us/call", "decide us");
            for (std::size_t i = 0; i < v.size() && i < 20; ++i) {
                const auto& [k, c] = v[i];
                const auto fate = static_cast<std::size_t>(k & 0xff);
                std::fprintf(stderr, "  %-6llu %-9s %9llu %10.2f %9.2f %9.2f\n", static_cast<unsigned long long>(k >> 8),
                             fate < std::size(kFate) ? kFate[fate] : "?", static_cast<unsigned long long>(c.n),
                             static_cast<double>(c.ns) / 1e6, static_cast<double>(c.ns) / 1e3 / static_cast<double>(c.n),
                             static_cast<double>(c.disp) / 1e3 / static_cast<double>(c.n));
            }
            on = false;
        }
    };
    Profile prof_;

    // Unlink every INJECT temp created during the run (files and dirs).
    void cleanup_temps() {
        for (const auto& t : temps_) { std::remove(t.c_str()); ::rmdir(t.c_str()); }
        temps_.clear();
    }

    // Ensure every parent directory of a host path exists (mkdir -p of the
    // dirname). The overlay upper layer starts empty, so a create into a
    // deep guest path (e.g. mkdir /var/lib/pacman/local/pkg) would ENOENT on
    // the missing intermediate upper dirs; build them 0755 first. Idempotent;
    // failures are ignored (the forwarded syscall reports the real error).
    static void make_host_parents(const std::string& host_path) {
        if (host_path.empty()) return;
        auto slash = host_path.find_last_of('/');
        if (slash == std::string::npos || slash == 0) return;
        std::string dir = host_path.substr(0, slash);
        // Walk the components, creating each level.
        for (std::size_t p = 1; p <= dir.size(); ++p) {
            if (p == dir.size() || dir[p] == '/') {
                std::string seg = dir.substr(0, p);
                if (!seg.empty()) (void)::mkdir(seg.c_str(), 0755);
            }
        }
    }

    T& trap_;
    K& kernel_;
    M& mem_;
    abi::Arch arch_;
    std::vector<std::string> temps_;

    // Can a child of ours reopen one of our memfds through /proc/<us>/fd/N?
    // Android's SELinux says no (the fd's label isn't the opener's). Asked
    // once, by a forked child: it runs as the guest will.
    static bool memfd_reopen_ok() {
#if defined(__linux__)
        static const bool ok = [] {
            const int m = memfd_of({std::byte{'x'}});
            if (m < 0) return false;
            const std::string via = "/proc/" + std::to_string(::getpid()) + "/fd/" + std::to_string(m);
            const ::pid_t c = ::fork();
            if (c == 0) {
                const int f = ::open(via.c_str(), O_RDONLY | O_CLOEXEC);
                char b = 0;
                ::_exit(f >= 0 && ::read(f, &b, 1) == 1 && b == 'x' ? 0 : 1);
            }
            int st = 0;
            const bool good = c > 0 && ::waitpid(c, &st, 0) == c && WIFEXITED(st) && WEXITSTATUS(st) == 0;
            ::close(m);
            return good;
        }();
        return ok;
#else
        return false;
#endif
    }
};

} // namespace lx::runtime
