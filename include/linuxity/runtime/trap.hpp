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

#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

namespace lx::runtime {

// The guest register snapshot at a trapped syscall, plus the machinery to
// resume. Arch-neutral: `regs` already carries the 6 args + nr in the
// canonical order abi::Syscalls expects (the host trap backend maps
// RAX/RDI/... or x8/x0/... into this).
struct TrapFrame {
    abi::Regs regs;         // decoded syscall number + arguments
    std::uint64_t pc{};     // guest program counter at the trap (for logging)
};

// A host trap backend models this: it arranges for guest syscalls to trap,
// runs the guest until one occurs (or it exits), and lets us either service
// the call ourselves (resume with a value) OR forward it to the real host
// kernel acting on the guest (for memory/host-resource syscalls). The whole
// native-execution loop is expressed against this concept, so it is identical
// whether the backend is ptrace, seccomp+SIGSYS, or an in-process trampoline.
template <class T>
concept SyscallTrap = requires(T t, TrapFrame& f, std::int64_t ret) {
    // Begin executing the loaded guest at (entry, sp). Returns when the
    // guest first traps or exits.
    { t.start(UAddr{}, UAddr{}) } -> std::same_as<Status>;
    // Block until the next syscall trap; fills `f`. false => guest exited.
    { t.next(f) }                 -> std::same_as<Result<bool>>;
    // VIRTUALIZE: set the syscall return value and resume (no real syscall).
    { t.resume(ret) }             -> std::same_as<Status>;
    // FORWARD: let the real host kernel run this syscall in the guest and
    // return its result. For mmap/brk/mprotect and host-backed I/O.
    { t.forward() }               -> std::same_as<Result<std::int64_t>>;
    // REDIRECT: rewrite a char* path argument to a translated host path, then
    // forward. Carries the guest's virtual namespace onto real host files.
    { t.redirect(0, std::string{}) } -> std::same_as<Result<std::int64_t>>;
    // Whether the guest exited during the last resume()/forward().
    { t.exited() }                -> std::same_as<bool>;
    // The guest's exit status once it has exited.
    { t.exit_code() }             -> std::same_as<int>;
};

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
        LX_TRY(trap_.start(entry, sp));
        for (;;) {
            TrapFrame f;
            bool still_running = LX_TRY(trap_.next(f));
            apply_proc_events();
            if (!still_running) { cleanup_temps(); return ok(trap_.exit_code()); }

            // The dispatcher classifies the trapped syscall: service it from
            // our subsystems, forward it to the host kernel, or exit.
            abi::Outcome o = sys.dispatch(f.regs);
            if (const char* t = std::getenv("LINUXITY_TRACE"); t && *t) {
                std::fprintf(trace_out(t), "[lx] nr=%llu -> %s%s%s%s%s%s%s ret=%lld %s%s%s\n",
                    static_cast<unsigned long long>(f.regs.nr),
                    o.inject?"INJECT ":"", o.redirect?"REDIRECT ":"",
                    o.sock_rewrite?"SOCKREWRITE ":"",
                    o.signal?"SIGNAL ":"",
                    o.exec_interp?"EXECINT ":"",
                    o.forward?"FORWARD ":"", o.exited?"EXIT ":"VIRT ",
                    static_cast<long long>(o.ret),
                    o.redirect?o.host_path.c_str():(o.sock_rewrite?o.host_path.c_str():""),
                    (o.redirect && o.path_arg2>=0)?" -> ":"",
                    (o.redirect && o.path_arg2>=0)?o.host_path2.c_str():"");
            }
            if (o.exited) return ok(o.exit_code);

            if (o.inject) {
                // A purely virtual node: back it with a real host temp — a
                // temp FILE (with the synthesized bytes) for a file, or an
                // empty temp DIRECTORY for a virtual dir so O_DIRECTORY opens
                // succeed and getdents64 (virtualized) can enumerate it. The
                // open runs ASYNCHRONOUSLY in the child (event-driven trap),
                // so we must NOT unlink here — the child hasn't opened it yet;
                // temps are cleaned up at the end of the run.
                std::string tmp = o.inject_dir ? materialize_dir()
                                               : materialize(o.content);
                auto fdr = trap_.redirect(o.path_arg, tmp);
                if (!fdr) { LX_TRY(recover_syscall(fdr.error())); continue; }
                if (!tmp.empty()) temps_.push_back(std::move(tmp));
                sys.note_opened_fd(*fdr);
            } else if (o.redirect) {
                // Host-backed path: rewrite the arg to the real host path and
                // let the kernel run it in the child (real fd for mmap). A
                // host-backed stat leaves the HOST file's owner in the guest
                // buffer; scrub it to root in the SAME stopped window, before
                // the task resumes and could read the buffer (racing us).
                //
                // A MUTATION (mkdir/rename/...) may need its destination's
                // parent host dirs to exist first (the overlay upper layer
                // starts empty), and may carry a SECOND path to translate
                // (rename/link/symlink). Build the parents and pass the
                // second rewrite through to the trap.
                if (o.make_parents) {
                    make_host_parents(o.host_path);
                    if (o.path_arg2 >= 0) make_host_parents(o.host_path2);
                }
                auto retr = trap_.redirect(
                    o.path_arg, o.host_path,
                    [&](std::int64_t rc) { if (rc == 0) sys.scrub_ids(o); },
                    o.path_arg2, o.host_path2);
                if (!retr) { LX_TRY(recover_syscall(retr.error())); continue; }
                sys.note_opened_fd(*retr);
            } else if (o.sock_rewrite) {
                // AF_UNIX bind/connect: create the socket's parent chain in
                // the overlay upper, then poke the translated host path into
                // the guest's sun_path and forward. Guarded so backends
                // without the primitive fall back to a plain forward (which
                // uses the untranslated path — correct only under a real
                // chroot, but at least well-formed).
                make_host_parents(o.host_path);
                if constexpr (requires {
                        trap_.rewrite_sockaddr(UAddr{}, std::string{}, 0, 0ULL); }) {
                    auto sr = trap_.rewrite_sockaddr(
                        o.sock_path_addr, o.host_path,
                        o.sock_len_arg, o.sock_new_len);
                    if (!sr) { LX_TRY(recover_syscall(sr.error())); continue; }
                } else {
                    auto fr = trap_.forward();
                    if (!fr) { LX_TRY(recover_syscall(fr.error())); continue; }
                }
            } else if (o.signal) {
                // The guest signalled a GUEST pid. Deliver the real signal to
                // that task's host tid (guarded so backends without the
                // bridge just report failure), then hand the caller the
                // result. The target's death, if fatal, is observed as a
                // normal reap by next() on a later iteration.
                std::int64_t ret = -static_cast<std::int64_t>(Errno::eperm);
                if constexpr (requires { trap_.deliver_signal(0, 0); })
                    ret = trap_.deliver_signal(o.sig_pid, o.sig_num);
                LX_TRY(trap_.resume(ret));
            } else if (o.exec_interp) {
                // A dynamic guest execve: rewrite it to run through the real
                // interpreter (guarded so backends without the bridge just
                // forward the original, which fails cleanly). The image is
                // replaced on success and observed as an EXEC event.
                if constexpr (requires {
                        trap_.exec_through_interp(0, std::string{}, std::string{}); }) {
                    auto er = trap_.exec_through_interp(
                        o.path_arg, o.interp_host, o.prog_guest, o.interp_prefix,
                        o.exec_extra_args);
                    if (!er) { LX_TRY(recover_syscall(er.error())); continue; }
                } else {
                    auto fr = trap_.forward();
                    if (!fr) { LX_TRY(recover_syscall(fr.error())); continue; }
                }
            } else if (o.forward) {
                // A dup/dup2/dup3/fcntl(F_DUPFD*): step SYNCHRONOUSLY so we can
                // read the real new fd and mirror the source fd's path /
                // virtual-dir binding onto it (an *at call or getdents on the
                // dup must resolve the same path/entries). dup2/dup3 first
                // close their explicit target, so drop its stale binding.
                if (o.dup_from >= 0) {
                    int from = o.dup_from, closed = o.dup_close;
                    auto fr = trap_.forward_sync([&](std::int64_t ret) {
                        if (ret < 0) return;
                        if (closed >= 0 && closed != from) sys.on_fd_closed(closed);
                        sys.on_fd_dup(from, static_cast<int>(ret));
                    });
                    if (!fr) { LX_TRY(recover_syscall(fr.error())); continue; }
                } else {
                    // Let the host kernel run it IN the guest (mmap/brk/...).
                    auto fr = trap_.forward();
                    if (!fr) { LX_TRY(recover_syscall(fr.error())); continue; }
                }
            } else {
                // Virtualize: hand the guest our answer, no real syscall.
                LX_TRY(trap_.resume(o.ret));
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
    // /proc sees linuxity's real, live process tree. Guarded on the trap
    // actually exposing the bridge, so the loop stays generic over backends
    // that don't (the concept only requires start/next/resume/forward/...).
    void apply_proc_events() {
        if constexpr (requires { trap_.drain_proc_events(); }) {
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
