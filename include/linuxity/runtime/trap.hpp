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
#include "linuxity/host/win_posix.hpp"
#include "linuxity/runtime/backend.hpp"

#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>
#if !defined(_WIN32)
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
        LX_TRY(trap_.start(entry, sp));
        for (;;) {
            TrapFrame f;
            bool still_running = LX_TRY(trap_.next(f));
            locked([&] { apply_proc_events(); });
            if (!still_running) { cleanup_temps(); return ok(trap_.exit_code()); }

            // The dispatcher classifies the trapped syscall: service it from
            // our subsystems, forward it to the host kernel, or exit.
            abi::Outcome o = locked([&] { return sys.dispatch(f.regs); });
            if (const char* t = trace_env) trace_fate(t, f.regs.nr, o);

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

                [&](const abi::Inject& in) {
                    // A purely virtual node: back it with a real host temp -- a
                    // temp FILE (with the synthesized bytes) for a file, or an
                    // empty temp DIRECTORY for a virtual dir so O_DIRECTORY
                    // opens succeed and getdents64 (virtualized) can enumerate
                    // it. The open runs ASYNCHRONOUSLY in the child, so we must
                    // NOT unlink here -- the child hasn't opened it yet; temps
                    // are cleaned up at the end of the run.
                    std::string tmp = in.is_dir ? materialize_dir()
                                                : materialize(in.content);
                    auto fdr = trap_.redirect(in.path_arg, tmp);
                    if (!fdr) return recover(fdr.error());
                    if (!tmp.empty()) temps_.push_back(std::move(tmp));
                    locked([&] { sys.note_opened_fd(*fdr); });
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
                    const int   arg2 = rd.second ? rd.second->arg : -1;
                    const auto& hp2  = rd.second ? rd.second->host_path
                                                 : empty_path();
                    if (rd.make_parents) {
                        make_host_parents(rd.first.host_path);
                        if (rd.second) make_host_parents(hp2);
                    }
                    auto retr = trap_.redirect(
                        rd.first.arg, rd.first.host_path,
                        [&](std::int64_t rc) {
                            // Only a successful stat has a buffer worth fixing,
                            // and only a Redirect can even carry a scrub.
                            if (rc == 0 && rd.scrub)
                                locked([&] { sys.scrub_ids(*rd.scrub); });
                        },
                        arg2, hp2);
                    if (!retr) return recover(retr.error());
                    locked([&] { sys.note_opened_fd(*retr); });
                    return Step::next;
                },

                [&](const abi::SockRewrite& sr) {
                    // AF_UNIX bind/connect: create the socket's parent chain in
                    // the overlay upper, then poke the translated host path into
                    // the guest's sun_path and forward.
                    //
                    // The two backends finish differently (see backend.hpp):
                    // ptrace resumes asynchronously and yields a Status, hvf
                    // completes the syscall and yields its value. Both are
                    // named capabilities, so neither can be reached by accident.
                    make_host_parents(sr.host_path);
                    auto rr = trap_.rewrite_sockaddr(sr.path_addr, sr.host_path,
                                                     sr.len_arg, sr.new_len);
                    if (!rr) return recover(rr.error());
                    return Step::next;
                },

                [&](abi::Raise k) {
                    // The guest signalled a GUEST pid. Deliver the real signal
                    // to that task's host tid, then hand the caller the result.
                    // The target's death, if fatal, is observed as a normal reap
                    // by next() on a later iteration.
                    auto st = trap_.resume(trap_.deliver_signal(k.guest_pid,
                                                               k.signum));
                    if (!st) return Step::fail;
                    return Step::next;
                },

                [&](const abi::ExecInterp& ei) {
                    // A dynamic guest execve: rewrite it to run through the
                    // real interpreter. The image is replaced on success and
                    // observed as an EXEC event.
                    auto er = trap_.exec_through_interp(
                        ei.path_arg, ei.interp_host, ei.prog_guest,
                        ei.prefix, ei.extra_args);
                    if (!er) return recover(er.error());
                    return Step::next;
                },

                [&](const abi::Forward& fo) {
                    // A dup/dup2/dup3/fcntl(F_DUPFD*) must step SYNCHRONOUSLY
                    // so we can read the real new fd and mirror the source fd's
                    // path / virtual-dir binding onto it (an *at call or
                    // getdents on the dup must resolve the same path and
                    // entries). dup2/dup3 first close their explicit target, so
                    // drop its stale binding.
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
                        });
                        if (!fr) return recover(fr.error());
                        return Step::next;
                    }
                    // Let the host kernel run it IN the guest (mmap/brk/...).
                    auto fr = trap_.forward();
                    if (!fr) return recover(fr.error());
                    return Step::next;
                },

                [&](abi::Virtualize v) {
                    // Hand the guest our answer; no real syscall runs.
                    auto st = trap_.resume(v.ret);
                    if (!st) return Step::fail;
                    return Step::next;
                });

            switch (step) {
                case Step::done:  cleanup_temps(); return ok(exit_status);
                case Step::fail:  cleanup_temps();
                                  return std::unexpected(Errno::eio);
                case Step::again: continue;
                case Step::next:  break;
            }
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

    // One line per serviced syscall under LINUXITY_TRACE. The fate names
    // itself, so this is a match too rather than a row of flag tests.
    void trace_fate(const char* t, std::uint64_t nr, const abi::Outcome& o) {
        std::FILE* out = trace_out(t);
        o.match(
            [&](const abi::Virtualize& v) {
                std::fprintf(out, "[lx] nr=%llu -> VIRT ret=%lld\n",
                    (unsigned long long)nr, (long long)v.ret);
            },
            [&](const abi::Forward& f) {
                if (f.mirror)
                    std::fprintf(out, "[lx] nr=%llu -> FORWARD dup_from=%d\n",
                        (unsigned long long)nr, f.mirror->from);
                else
                    std::fprintf(out, "[lx] nr=%llu -> FORWARD\n",
                        (unsigned long long)nr);
            },
            [&](const abi::Redirect& rd) {
                std::fprintf(out, "[lx] nr=%llu -> REDIRECT %s%s%s%s\n",
                    (unsigned long long)nr, rd.first.host_path.c_str(),
                    rd.second ? " -> " : "",
                    rd.second ? rd.second->host_path.c_str() : "",
                    rd.scrub ? " +scrub" : "");
            },
            [&](const abi::Inject& in) {
                std::fprintf(out, "[lx] nr=%llu -> INJECT %zu bytes%s\n",
                    (unsigned long long)nr, in.content.size(),
                    in.is_dir ? " (dir)" : "");
            },
            [&](const abi::Raise& k) {
                std::fprintf(out, "[lx] nr=%llu -> SIGNAL pid=%d sig=%d\n",
                    (unsigned long long)nr, k.guest_pid, k.signum);
            },
            [&](const abi::ExecInterp& ei) {
                std::fprintf(out, "[lx] nr=%llu -> EXECINT %s %s\n",
                    (unsigned long long)nr, ei.interp_host.c_str(),
                    ei.prog_guest.c_str());
            },
            [&](const abi::SockRewrite& sr) {
                std::fprintf(out, "[lx] nr=%llu -> SOCKREWRITE %s\n",
                    (unsigned long long)nr, sr.host_path.c_str());
            },
            [&](const abi::Exited& e) {
                std::fprintf(out, "[lx] nr=%llu -> EXIT code=%d\n",
                    (unsigned long long)nr, e.code);
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
                        pi.state = 'R';
                        pi.vsize_bytes = 4u << 20;   // plausible until first exec
                        pi.rss_pages = 256;
                        kernel_.procs().upsert(pi);
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
                            kernel_.procs().upsert(np);
                        }
                        break;
                    case EV::reap:
                        // pid 1 (our init) is never removed: /proc must always
                        // have a root even as the last guest thread winds down.
                        if (e.pid != 1) {
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

    // Write bytes to a fresh host temp file, return its path ("" on failure).
    // Used to back an INJECT (virtual file) with a real, mmappable fd.
    static std::string materialize(const std::vector<std::byte>& bytes) {
        char tmpl[] = "/tmp/linuxity-vfile-XXXXXX";
        int fd = ::mkstemp(tmpl);
        if (fd < 0) return {};
        std::size_t off = 0;
        while (off < bytes.size()) {
            auto n = ::write(fd, bytes.data() + off, bytes.size() - off);
            if (n <= 0) break;
            off += static_cast<std::size_t>(n);
        }
        ::close(fd);
        return std::string{tmpl};
    }

    // Create a fresh empty host temp DIRECTORY, return its path. Backs a
    // virtual directory so the child's O_DIRECTORY open succeeds; the actual
    // entries are served by the virtualized getdents64.
    static std::string materialize_dir() {
        char tmpl[] = "/tmp/linuxity-vdir-XXXXXX";
        return ::mkdtemp(tmpl) ? std::string{tmpl} : std::string{};
    }

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
};

} // namespace lx::runtime
