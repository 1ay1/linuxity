// linuxity/runtime/ptrace_trap.hpp
//
// A real, native-execution SyscallTrap backend using ptrace.
//
// The traced child executes its own instructions DIRECTLY on the host CPU at
// native speed. Its syscalls stop back into us at syscall-entry; for each we
// choose one of four fates (virtualize / forward / redirect / inject — see
// abi/syscall.hpp).
//
// MULTI-PROCESS + EVENT-DRIVEN. A real shell forks and execs children and
// blocks in wait4()/read() on them, so we (a) trace the WHOLE tree via
// PTRACE_O_TRACEFORK|VFORK|CLONE|EXEC, and (b) NEVER block on one task while
// another could make progress. The loop waits on -1 (any task); when a task
// stops at a syscall we service it and CONTINUE it, then go straight back to
// the wait. A parent's blocking wait4() therefore doesn't deadlock its
// still-scheduled child. Each task carries a tiny state machine: at a syscall
// -ENTRY stop we record the chosen action and let it run to its EXIT stop,
// where we finalize (write the virtualized return value / read the forwarded
// result). Every forked coreutils binary lives in the SAME virtual namespace
// as its parent shell — it never escapes to the host filesystem.
#pragma once

#include "linuxity/abi/syscall.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/runtime/seccomp_filter.hpp"

#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cerrno>

#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <fcntl.h>

namespace lx::runtime {

class PtraceTrap {
public:
    PtraceTrap(std::string path, std::vector<std::string> argv,
               std::vector<std::string> envp = {}, std::string root = {},
               std::function<void()> pre_exec = {})
        : path_{std::move(path)}, argv_{std::move(argv)},
          envp_{std::move(envp)}, root_{std::move(root)},
          pre_exec_{std::move(pre_exec)} {}

    // Per-task state machine. Declared here (before the methods that take a
    // Task&) so the public entry/exit helpers can name it.
    enum class Action { none, set_ret };
    struct Task {
        bool in_call{false};   // currently between an ENTRY and its EXIT stop
        Action action{Action::none};
        std::int64_t ret{0};
        int pending_sig{0};    // a signal held during a redirect, to re-inject
        struct user_regs_struct regs{};
    };

    [[nodiscard]] Status start(UAddr, UAddr) {
        // A tiny pipe lets the child report whether the seccomp trap filter
        // installed, so the parent knows to drive tasks with PTRACE_CONT (only
        // filtered syscalls stop) versus PTRACE_SYSCALL (every syscall stops).
        int seccomp_pipe[2] = {-1, -1};
        (void)::pipe(seccomp_pipe);
        ::pid_t pid = ::fork();
        if (pid < 0) return err(Errno::eagain);
        if (pid == 0) {
            if (seccomp_pipe[0] >= 0) ::close(seccomp_pipe[0]);
            if (!root_.empty()) {
                if (::chroot(root_.c_str()) == 0) (void)::chdir("/");
            }
            // Bound this task (and, by inheritance, every descendant) BEFORE
            // it starts running: the child writes its own pid into the
            // resource cgroup and installs rlimit fallbacks. Runs pre-TRACEME
            // so enforcement is in effect the instant the guest's _start runs.
            if (pre_exec_) pre_exec_();
            // Install the seccomp trap filter so ONLY the syscalls linuxity
            // intercepts stop into the tracer; everything else runs natively.
            // Report the outcome to the parent, then let the filter be
            // inherited across the coming execve and every future fork. If
            // seccomp is unavailable the parent falls back to PTRACE_SYSCALL,
            // which is always correct (just slower). LINUXITY_NO_SECCOMP=1
            // forces that fallback (for benchmarking / debugging the slow path).
            char ok_byte = (!std::getenv("LINUXITY_NO_SECCOMP") &&
                            install_trap_filter()) ? 1 : 0;
            if (seccomp_pipe[1] >= 0) {
                (void)!::write(seccomp_pipe[1], &ok_byte, 1);
                ::close(seccomp_pipe[1]);
            }
            ::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            std::vector<char*> cargv;
            for (auto& a : argv_) cargv.push_back(a.data());
            cargv.push_back(nullptr);
            std::vector<char*> cenvp;
            for (auto& e : envp_) cenvp.push_back(e.data());
            cenvp.push_back(nullptr);
            ::execve(path_.c_str(), cargv.data(), cenvp.data());
            ::_exit(127);
        }
        int st = 0;
        ::waitpid(pid, &st, 0);
        // Learn whether the child installed the seccomp filter.
        if (seccomp_pipe[1] >= 0) ::close(seccomp_pipe[1]);
        char ok_byte = 0;
        if (seccomp_pipe[0] >= 0) {
            (void)!::read(seccomp_pipe[0], &ok_byte, 1);
            ::close(seccomp_pipe[0]);
        }
        seccomp_ = (ok_byte == 1);
        int opts = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD |
                   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
        // With a filter, ask for PTRACE_EVENT_SECCOMP stops on the traced
        // syscalls; without one, we rely on ordinary syscall-entry stops.
        if (seccomp_) opts |= PTRACE_O_TRACESECCOMP;
        ::ptrace(PTRACE_SETOPTIONS, pid, 0, opts);
        root_pid_ = pid;
        tasks_[pid];                       // create, at-entry state
        // Filtered: run free until a seccomp/event stop. Unfiltered: stop at
        // the next syscall entry.
        resume_run(pid, 0);
        ++live_;
        return ok();
    }

    // Block until some task reaches a syscall-ENTRY stop, and fill `f` with
    // its registers. EXIT stops are finalized here (applying the action the
    // dispatcher chose at entry) and the task is continued. Returns false once
    // the whole tree has exited.
    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        for (;;) {
            int st = 0;
            ::pid_t w = ::waitpid(-1, &st, __WALL);
            if (w < 0) return ok(false);

            if (WIFEXITED(st) || WIFSIGNALED(st)) {
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                if (w == root_pid_) exit_code_ = code;
                if (auto it = gpid_.find(w); it != gpid_.end())
                    proc_events_.push_back({ProcEvent::reap, it->second, 0, {}, {}});
                // NB: do NOT erase gpid_[w] here. The parent's wait4() has not
                // run its exit stop yet; when it does, finalize_exit translates
                // the reaped HOST pid to its GUEST pid via this very map. If we
                // dropped the entry now, gpid_of() would mint a FRESH number
                // and $!/`wait N` would never match the pid the parent saw at
                // fork. A dead child's identity must outlive it until reaped;
                // guest pids are tiny ints, so retaining them is cheap.
                tasks_.erase(w);
                if (--live_ <= 0) { exited_ = true; return ok(false); }
                continue;
            }
            if (!WIFSTOPPED(st)) continue;

            int sig = WSTOPSIG(st);
            int event = st >> 16;

            // A new tracee appeared: register it and keep the parent moving.
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
                unsigned long np = 0;
                ::ptrace(PTRACE_GETEVENTMSG, w, 0, &np);
                auto child = static_cast<::pid_t>(np);
                if (np && tasks_.emplace(child, Task{}).second)
                    ++live_;   // may already be counted if it stopped first
                // A fork/vfork is a new PROCESS in the guest's world; a
                // CLONE (thread) shares the tgid and is NOT a distinct pid to
                // a process monitor. Record only real processes, and map the
                // host tid to a small guest pid so /proc is a coherent, tiny
                // pid space (root == pid 1) rather than leaking host pids.
                if (np && event != PTRACE_EVENT_CLONE) {
                    std::int32_t gpid = gpid_of(child);
                    std::int32_t gppid = gpid_of(w);
                    gppid_[gpid] = gppid;
                    proc_events_.push_back({ProcEvent::spawn, gpid, gppid, {}, {}});
                }
                // If we're mid-servicing this task's clone/fork (in_call), it
                // still owes us its EXIT stop so finalize_exit can translate
                // the returned host pid to a guest pid. Step to that exit with
                // PTRACE_SYSCALL rather than letting CONT run past it — else $!
                // and jobs would show a host pid. Otherwise run free.
                resume_after_event(w);
                continue;
            }
            if (event == PTRACE_EVENT_EXEC) {
                // The image was replaced: the pid keeps its number but becomes
                // a new program. Recover its new comm from /proc/<tid>/comm on
                // the HOST (the child is mid-exec; this is the real name).
                proc_events_.push_back({ProcEvent::exec, gpid_of(w), 0,
                                        comm_of(w), cmdline_of(w)});
                tasks_[w] = Task{};        // fresh image, back at-entry
                resume_run(w, 0);
                continue;
            }
            // A seccomp-filter trap: the guest hit one of the syscalls we
            // intercept. This IS the syscall-ENTRY stop under the fast path;
            // service it exactly like an ordinary entry (the seccomp event
            // fires BEFORE the syscall runs). Non-filtered syscalls never get
            // here — they ran natively without stopping.
            if (event == PTRACE_EVENT_SECCOMP) {
                Task& t = tasks_[w];
                struct user_regs_struct rr{};
                ::ptrace(PTRACE_GETREGS, w, 0, &rr);
                cur_ = w;
                t.regs = rr;
                t.in_call = true;
                translate_entry_args(w, rr, t);
                fill_frame(f, rr);
                return ok(true);
            }
            // The initial SIGSTOP/ SIGTRAP of a freshly-attached child.
            if (sig == SIGSTOP || sig == SIGTRAP) {
                tasks_.try_emplace(w);
                resume_run(w, 0);
                continue;
            }
            // A real syscall stop (TRACESYSGOOD => SIGTRAP|0x80). Under the
            // seccomp fast path this is ONLY an EXIT stop (from the one-shot
            // PTRACE_SYSCALL a serviced entry issued); entries arrive as
            // PTRACE_EVENT_SECCOMP above. Without seccomp it is BOTH the entry
            // and the exit, distinguished by the -ENOSYS-primed RAX.
            if (sig == (SIGTRAP | 0x80)) {
                Task& t = tasks_[w];
                struct user_regs_struct rr{};
                ::ptrace(PTRACE_GETREGS, w, 0, &rr);
                bool is_entry = !seccomp_
                    && (static_cast<long long>(rr.rax) == -38 /*ENOSYS*/)
                    && !t.in_call;
                if (is_entry) {
                    cur_ = w;
                    t.regs = rr;
                    t.in_call = true;
                    translate_entry_args(w, rr, t);
                    fill_frame(f, rr);
                    return ok(true);
                }
                // EXIT stop: finalize the action recorded at entry, then let
                // the task run FREE again (CONT) until its next filtered call.
                finalize_exit(w, t);
                resume_run(w, 0);
                continue;
            }
            // Any other signal: deliver it to the task.
            resume_run(w, sig);
        }
    }

    // Fill the arch-neutral TrapFrame from x86-64 registers at a syscall stop.
    static void fill_frame(TrapFrame& f, const struct user_regs_struct& rr) {
        f.regs.nr     = rr.orig_rax;
        f.regs.arg[0] = rr.rdi; f.regs.arg[1] = rr.rsi;
        f.regs.arg[2] = rr.rdx; f.regs.arg[3] = rr.r10;
        f.regs.arg[4] = rr.r8;  f.regs.arg[5] = rr.r9;
        f.pc          = rr.rip;
    }

    // At a syscall-ENTRY stop, translate any GUEST pid arguments to host tids
    // before the kernel runs the (forwarded) call. Currently: wait4(pid,...).
    // A forwarded wait4 carries a GUEST pid in arg0 (we hand the guest small
    // pids from fork); the host kernel only knows the real host tid, so a raw
    // guest pid would wait on nothing and return -1/ECHILD. Rewrite a positive
    // pid to its host tid; the reaped pid is translated back at the exit stop
    // (returns_pid). pid<=0 (any child / process group) passes through.
    void translate_entry_args(::pid_t w, struct user_regs_struct& rr, Task& t) {
        if (rr.orig_rax == 61 /*wait4*/) {
            auto gpid = static_cast<std::int32_t>(static_cast<long long>(rr.rdi));
            if (gpid > 0) {
                ::pid_t host = host_tid_of(gpid);
                if (host > 0) {
                    struct user_regs_struct wr = rr;
                    wr.rdi = static_cast<unsigned long long>(host);
                    ::ptrace(PTRACE_SETREGS, w, 0, &wr);
                    t.regs = wr;
                    rr = wr;
                }
            }
        }
    }

    // Resume a task to run FREE until its next stop of interest: CONT when a
    // seccomp filter is active (only filtered syscalls stop), PTRACE_SYSCALL
    // otherwise (every syscall entry/exit stops). `sig` is delivered on resume.
    void resume_run(::pid_t w, int sig) {
        ::ptrace(seccomp_ ? PTRACE_CONT : PTRACE_SYSCALL, w, 0, sig);
    }

    // Resume after a fork/exec EVENT stop. If the task is still inside a
    // syscall WE are servicing (clone/fork/execve), it owes us its EXIT stop,
    // so step to it with PTRACE_SYSCALL even under seccomp; otherwise run free.
    void resume_after_event(::pid_t w) {
        bool in_call = false;
        if (auto it = tasks_.find(w); it != tasks_.end()) in_call = it->second.in_call;
        if (seccomp_ && in_call) ::ptrace(PTRACE_SYSCALL, w, 0, 0);
        else                     resume_run(w, 0);
    }

    // VIRTUALIZE: neutralize the syscall now; write `ret` into RAX at exit.
    [[nodiscard]] Status resume(std::int64_t ret) {
        Task& t = tasks_[cur_];
        struct user_regs_struct r = t.regs;
        r.orig_rax = static_cast<unsigned long long>(-1);
        ::ptrace(PTRACE_SETREGS, cur_, 0, &r);
        t.action = Action::set_ret;
        t.ret = ret;
        // A one-shot PTRACE_SYSCALL runs the (neutralized) call to its EXIT
        // stop, where finalize_exit writes `ret` into RAX. This is correct
        // under BOTH drive modes: from a seccomp-event entry stop or an
        // ordinary syscall-entry stop, PTRACE_SYSCALL always halts at the
        // matching exit. After finalize we return to the free-running CONT.
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);
        return ok();
    }

    // FORWARD: let the host kernel run this syscall in the task. We report the
    // result asynchronously as 0 (the loop doesn't need it for a plain
    // forward); the real value lands in the guest's RAX by the kernel itself.
    // A one-shot PTRACE_SYSCALL steps to the EXIT stop so finalize_exit can
    // translate a returned host pid (fork/wait) to a guest pid before the
    // guest reads it; for non-pid forwards the exit stop is a cheap no-op.
    [[nodiscard]] Result<std::int64_t> forward() {
        Task& t = tasks_[cur_];
        t.action = Action::none;
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);   // run the real syscall to exit
        return ok(std::int64_t{0});
    }

    // REDIRECT: rewrite the char* path arg to the translated host path (in the
    // task's stack scratch), then run the syscall to its EXIT stop and return
    // the kernel's real result (e.g. the fd for openat). This is SYNCHRONOUS:
    // path syscalls (open/stat/exec) never block on a sibling task, so
    // stepping to their exit can't deadlock the tree — and we need the real fd
    // to bind virtual-directory streams and readlinkat paths.
    [[nodiscard]] Result<std::int64_t> redirect(int path_arg,
                                                const std::string& host_path,
                                                std::function<void(std::int64_t)>
                                                    post_exit = {},
                                                int path_arg2 = -1,
                                                const std::string& host_path2 = {}) {
        Task& t = tasks_[cur_];
        struct user_regs_struct r = t.regs;
        // Park the translated path in the child's own stack, below the red
        // zone. The child is stopped at its syscall-ENTRY; on resume the
        // kernel copies this pathname from userspace via copy_from_user.
        //
        // The path MUST be written with PTRACE_POKEDATA, not process_vm_writev:
        // a cross-process vm write to a STOPPED tracee is not guaranteed
        // coherent with the very next in-kernel copy_from_user of the same
        // pages — empirically the syscall then reads a stale/partial path and
        // fails with a scattered ENOTDIR/EINVAL/EACCES/EPERM (flaky, masked by
        // any added latency). PTRACE_POKEDATA goes through the ptrace access
        // path, which IS ordered against the tracee's own memory accesses.
        std::size_t need = host_path.size() + 1;
        std::uint64_t scratch =
            (t.regs.rsp - 256 - need) & ~std::uint64_t{15};
        if (!poke_path(scratch, host_path)) {
            // The path could not be written into this task's memory at all
            // (PTRACE_POKEDATA -> EIO and process_vm_writev -> EPERM). This
            // happens for a DAEMONIZED guest task: gpg spawns gpg-agent, which
            // double-forks + setsid()s; the resulting task sits in a ptrace
            // stop we cannot poke. Failing the syscall with -EFAULT breaks the
            // guest (gpg-agent's stat() returns "Bad address" and it refuses
            // to start). The correct degradation is to run the syscall
            // UNMODIFIED on the guest's own path: the guest is chroot'd into
            // the rootfs, so an in-rootfs path resolves correctly as-is, and
            // even an overlay/bind path fails no worse than before. Restore the
            // entry registers and forward.
            ::ptrace(PTRACE_SETREGS, cur_, 0, &t.regs);
            if (!step_to_exit(cur_)) return ok(std::int64_t{-1});
            struct user_regs_struct rr0{};
            ::ptrace(PTRACE_GETREGS, cur_, 0, &rr0);
            std::int64_t ret0 = static_cast<std::int64_t>(rr0.rax);
            tasks_[cur_].in_call = false;
            if (post_exit) post_exit(ret0);
            resume_task(cur_);
            return ok(ret0);
        }
        set_arg(r, path_arg, scratch);
        // A two-path mutation (rename/link/symlink): park the SECOND host path
        // in a distinct, non-overlapping scratch slot below the first and
        // rewrite its register too. Both operands are then translated before
        // the kernel runs the single syscall.
        if (path_arg2 >= 0 && !host_path2.empty()) {
            std::size_t need2 = host_path2.size() + 1;
            std::uint64_t scratch2 =
                (scratch - 256 - need2) & ~std::uint64_t{15};
            if (!poke_path(scratch2, host_path2))
                return err<std::int64_t>(Errno::efault);
            set_arg(r, path_arg2, scratch2);
        }
        ::ptrace(PTRACE_SETREGS, cur_, 0, &r);
        if (!step_to_exit(cur_)) return ok(std::int64_t{-1});   // task exited
        struct user_regs_struct rr{};
        ::ptrace(PTRACE_GETREGS, cur_, 0, &rr);
        std::int64_t ret = static_cast<std::int64_t>(rr.rax);
        tasks_[cur_].in_call = false;
        // Run the caller's post-exit patch WHILE the task is still stopped at
        // its syscall-exit (e.g. scrub a stat buffer the kernel just filled).
        // This must precede the resume below: once the task runs it may read
        // the buffer, so writing after resuming would race the child.
        if (post_exit) post_exit(ret);
        // Resume the task toward its next syscall (we consumed its exit stop),
        // delivering any signal held during the step.
        resume_task(cur_);
        return ok(ret);
    }

    // EXEC_INTERP: the guest execve'd a dynamic binary. Rewrite the call in
    // place into `interp_host <prog_guest> <orig argv[1..]>` so the child
    // execs the real dynamic linker (which then opens the program and its
    // libraries through redirected syscalls), then FORWARD it to the kernel.
    //
    // We build the new argument vector in the child's own stack, below rsp:
    //   [ interp_host\0 ][ prog_guest\0 ][ ptr array: &interp,&prog,
    //     orig_argv[1], orig_argv[2], ..., NULL ]
    // The original argv[1..] pointers still address valid guest strings, so we
    // reuse them; only argv[0] is replaced by prog_guest. path_arg is the
    // execve path register (0 for execve, 1 for execveat); argv follows it.
    [[nodiscard]] Result<std::int64_t> exec_through_interp(
            int path_arg, const std::string& interp_host,
            const std::string& prog_guest,
            const std::vector<std::string>& prefix = {}) {
        Task& t = tasks_[cur_];
        struct user_regs_struct r = t.regs;
        int argv_reg = path_arg + 1;
        std::uint64_t argv_ptr = reg_arg(r, argv_reg);

        // Read the original argv pointer array (stop at NULL, bounded).
        std::vector<std::uint64_t> orig;
        for (std::size_t i = 0; i < 1024; ++i) {
            std::uint64_t p = 0;
            std::array<std::byte, 8> b{};
            if (!copy_in(uaddr(argv_ptr + i * 8), b)) break;
            std::memcpy(&p, b.data(), 8);
            if (p == 0) break;
            orig.push_back(p);
        }

        // Lay strings then the pointer array into a scratch block below rsp.
        // Layout: interp_host, each prefix token, prog_guest, then the array
        // [ &interp, &prefix..., &prog, orig_argv[1..], NULL ].
        std::size_t nprefix = prefix.size();
        std::size_t narg = 2 + nprefix + (orig.empty() ? 0 : orig.size() - 1);
        std::size_t arr_bytes = (narg + 1) * 8;
        std::size_t strbytes = interp_host.size() + 1 + prog_guest.size() + 1;
        for (const auto& s : prefix) strbytes += s.size() + 1;
        std::size_t block = strbytes + arr_bytes + 64;
        std::uint64_t base = (t.regs.rsp - 512 - block) & ~std::uint64_t{15};

        std::uint64_t cursor = base;
        auto put = [&](const std::string& s) -> std::uint64_t {
            std::uint64_t at = cursor;
            cursor += s.size() + 1;
            return at;
        };
        std::uint64_t p_interp = put(interp_host);
        std::vector<std::uint64_t> p_prefix;
        for (const auto& s : prefix) p_prefix.push_back(put(s));
        std::uint64_t p_prog = put(prog_guest);

        if (!write_cstr(p_interp, interp_host)) return err<std::int64_t>(Errno::efault);
        for (std::size_t i = 0; i < nprefix; ++i)
            if (!write_cstr(p_prefix[i], prefix[i])) return err<std::int64_t>(Errno::efault);
        if (!write_cstr(p_prog, prog_guest)) return err<std::int64_t>(Errno::efault);

        std::uint64_t arr = (cursor + 15) & ~std::uint64_t{15};
        std::vector<std::uint64_t> ptrs;
        ptrs.push_back(p_interp);          // argv[0] = interpreter
        for (auto p : p_prefix) ptrs.push_back(p);  // shebang arg / sh host path
        ptrs.push_back(p_prog);            // the program (guest path)
        for (std::size_t i = 1; i < orig.size(); ++i)
            ptrs.push_back(orig[i]);       // original argv[1..]
        ptrs.push_back(0);                 // NULL terminator
        std::vector<std::byte> arrbytes(ptrs.size() * 8);
        std::memcpy(arrbytes.data(), ptrs.data(), arrbytes.size());
        if (!copy_out(uaddr(arr), arrbytes)) return err<std::int64_t>(Errno::efault);

        set_arg(r, path_arg, p_interp);   // exec the interpreter
        set_arg(r, argv_reg, arr);        // with the rebuilt argv
        ::ptrace(PTRACE_SETREGS, cur_, 0, &r);
        // Forward: the kernel runs the (rewritten) execve; on success it
        // replaces the image and we get a PTRACE_EVENT_EXEC. Don't step here.
        t.action = Action::none;
        resume_run(cur_, 0);
        return ok(std::int64_t{0});
    }

    static std::uint64_t reg_arg(const struct user_regs_struct& r, int n) {
        switch (n) {
            case 0: return r.rdi; case 1: return r.rsi; case 2: return r.rdx;
            case 3: return r.r10; case 4: return r.r8;  case 5: return r.r9;
            default: return 0;
        }
    }

    [[nodiscard]] bool write_cstr(std::uint64_t at, const std::string& s) {
        std::vector<std::byte> b(s.size() + 1);
        std::memcpy(b.data(), s.c_str(), s.size() + 1);
        return static_cast<bool>(copy_out(uaddr(at), b));
    }

    static void set_arg(struct user_regs_struct& r, int n, std::uint64_t v) {
        switch (n) {
            case 0: r.rdi = v; break;  case 1: r.rsi = v; break;
            case 2: r.rdx = v; break;  case 3: r.r10 = v; break;
            case 4: r.r8  = v; break;  case 5: r.r9  = v; break;
            default: break;
        }
    }

    // Read a task's current program name from the host's /proc/<tid>/comm.
    // Used at PTRACE_EVENT_EXEC to learn the new image's name.
    static std::string comm_of(::pid_t tid) {
        std::string path = "/proc/" + std::to_string(tid) + "/comm";
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return {};
        char buf[256]; auto n = ::read(fd, buf, sizeof buf - 1); ::close(fd);
        if (n <= 0) return {};
        std::string s(buf, static_cast<std::size_t>(n));
        if (!s.empty() && s.back() == '\n') s.pop_back();
        return s;
    }

    // Read a task's full NUL-joined argv from the host's /proc/<tid>/cmdline
    // at exec, so the process monitor shows the real command line.
    static std::string cmdline_of(::pid_t tid) {
        std::string path = "/proc/" + std::to_string(tid) + "/cmdline";
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return {};
        std::string s; char buf[512]; ssize_t n;
        while ((n = ::read(fd, buf, sizeof buf)) > 0)
            s.append(buf, static_cast<std::size_t>(n));
        ::close(fd);
        // Present argv as space-separated for the guest's cmdline field; the
        // procfs synthesizer re-appends the trailing NUL it needs.
        for (char& c : s) if (c == '\0') c = ' ';
        while (!s.empty() && s.back() == ' ') s.pop_back();
        return s;
    }

    // Map a host tid to a small, stable GUEST pid: the root task is pid 1,
    // and each newly-seen process gets the next number. This keeps /proc in
    // linuxity's own tiny pid space instead of exposing host pids.
    std::int32_t gpid_of(::pid_t tid) {
        if (tid == root_pid_) return 1;
        auto [it, fresh] = gpid_.try_emplace(tid, 0);
        if (fresh) it->second = next_gpid_++;
        return it->second;
    }

    [[nodiscard]] bool exited() const noexcept { return exited_; }
    [[nodiscard]] int exit_code() const noexcept { return exit_code_; }

    // -- Live process tree -> ProcessTable bridge --------------------------
    // The trap observes every fork/exec/exit in the guest tree. It records
    // them as neutral events; the Cpu loop drains them each iteration and
    // applies them to the kernel's ProcessTable, so a process monitor sees
    // linuxity's real, live process list. The trap stays decoupled from the
    // kernel: it only emits events, it never touches ProcessTable itself.
    struct ProcEvent {
        enum Kind { spawn, exec, reap } kind;
        ::pid_t pid;          // the affected task's tid (== pid for a process)
        ::pid_t ppid;         // parent (spawn only)
        std::string comm;     // program name (exec only)
        std::string cmdline;  // full argv, space-joined (exec only)
    };
    [[nodiscard]] std::vector<ProcEvent> drain_proc_events() {
        return std::exchange(proc_events_, {});
    }

    // The current guest tid, so the loop can attribute a syscall to a pid.
    [[nodiscard]] ::pid_t current_tid() const noexcept { return cur_; }

    // The GUEST-namespace identity of the task that trapped: its pid, its
    // thread id (== pid for the main thread; a distinct host tid otherwise),
    // and its parent's guest pid. The dispatcher answers getpid/gettid/
    // getppid from THIS, so every task sees its own coherent pid rather than
    // a fixed "pid 1". The root task is pid 1 with ppid 0 (init has no
    // parent in linuxity's world).
    struct TaskIds { std::int32_t pid, tid, ppid; };
    [[nodiscard]] TaskIds current_ids() {
        std::int32_t pid = gpid_of(cur_);
        std::int32_t ppid = 0;
        if (auto it = gppid_.find(pid); it != gppid_.end()) ppid = it->second;
        // A thread (CLONE) shares its thread-group leader's pid but keeps its
        // own tid. We map threads to their own small id space lazily via the
        // same allocator, and the tgid is the process the monitor tracks.
        return TaskIds{pid, pid, ppid};
    }

    // -- Signal delivery ---------------------------------------------------
    // The guest issued kill/tgkill/tkill against a GUEST pid. Translate that
    // pid to the real host tid of the traced task and deliver the signal
    // THERE (never to the raw host pid, which is an unrelated task). Returns
    // the guest-visible result: 0 on delivery, -ESRCH if the target guest pid
    // is unknown, or -errno if the host kill(2) itself fails.
    [[nodiscard]] std::int64_t deliver_signal(std::int32_t gpid,
                                              std::int32_t signum) {
        // gpid 0 in kill(2) means the caller's process group; we don't model
        // groups, so target the current task. A negative pid (process group)
        // likewise collapses to the current task in our tiny namespace.
        ::pid_t tid = (gpid <= 0) ? cur_ : host_tid_of(gpid);
        if (tid < 0) return -static_cast<std::int64_t>(Errno::esrch);
        // Deliver to the specific THREAD so it lands on the traced task even
        // when signal-0 probes or fatal signals race the group.
        long rc = ::syscall(SYS_tgkill, tid, tid, signum);
        if (rc != 0) rc = ::kill(tid, signum);   // fall back to process kill
        return (rc == 0) ? 0 : -static_cast<std::int64_t>(Errno{errno});
    }

    // Reverse of gpid_of: a guest pid -> its host tid. pid 1 is the root task.
    // Because fork/clone are FORWARDED, the guest actually learns the real
    // HOST pid of its children (that's what $! / clone's return value carry),
    // so a kill target may already BE a host tid we trace. Accept either: a
    // known guest pid (our tiny namespace) or a raw traced host tid.
    [[nodiscard]] ::pid_t host_tid_of(std::int32_t pid) const {
        if (pid == 1) return root_pid_;
        if (pid == root_pid_) return root_pid_;
        auto host = static_cast<::pid_t>(pid);
        if (tasks_.find(host) != tasks_.end()) return host;  // a traced host tid
        for (const auto& [tid, g] : gpid_)
            if (g == pid) return tid;                         // a guest pid
        return -1;
    }

    // -- GuestMem: the CURRENT task's pages ARE the guest memory. -----------
    [[nodiscard]] Status copy_in(UAddr src, std::span<std::byte> dst) const {
        ::iovec local{dst.data(), dst.size()};
        ::iovec remote{reinterpret_cast<void*>(value(src)), dst.size()};
        auto n = ::process_vm_readv(cur_, &local, 1, &remote, 1, 0);
        return (n >= 0 && std::size_t(n) == dst.size()) ? ok() : err(Errno::efault);
    }
    [[nodiscard]] Status copy_out(UAddr dst, std::span<const std::byte> src) const {
        ::iovec local{const_cast<std::byte*>(src.data()), src.size()};
        ::iovec remote{reinterpret_cast<void*>(value(dst)), src.size()};
        auto n = ::process_vm_writev(cur_, &local, 1, &remote, 1, 0);
        return (n >= 0 && std::size_t(n) == src.size()) ? ok() : err(Errno::efault);
    }

    // Write a path string into the current task, preferring PTRACE_POKEDATA
    // (ordered against the tracee's own copy_from_user — see redirect()) and
    // falling back to process_vm_writev when the poke is refused. The poke can
    // fail with EIO on a task we can observe but not ptrace-poke (a daemonized
    // child whose stop we reached indirectly); the vm write uses a different
    // kernel access path and often still succeeds. Returns false only if BOTH
    // paths fail, which the caller degrades to a forward-unmodified.
    [[nodiscard]] bool poke_path(std::uint64_t at, const std::string& s) const {
        if (poke_bytes(at, s)) return true;
        std::vector<std::byte> b(s.size() + 1);
        std::memcpy(b.data(), s.c_str(), s.size() + 1);
        return static_cast<bool>(copy_out(uaddr(at), std::span<const std::byte>{b}));
    }

    // Write a NUL-terminated string into the CURRENT task at `at` using
    // PTRACE_POKEDATA (word-granular). Unlike process_vm_writev, ptrace pokes
    // are ordered against the tracee's own subsequent copy_from_user, so a
    // path spliced here is reliably seen by the syscall we then step. Reads
    // the existing word first to preserve bytes past the string's NUL within
    // the final partial word. Returns false on any poke failure.
    [[nodiscard]] bool poke_bytes(std::uint64_t at, const std::string& s) const {
        const std::size_t n = s.size() + 1;             // include the NUL
        std::size_t off = 0;
        while (off < n) {
            errno = 0;
            long word = ::ptrace(PTRACE_PEEKDATA, cur_,
                                 reinterpret_cast<void*>(at + off), nullptr);
            if (word == -1 && errno != 0) return false;
            auto* wb = reinterpret_cast<unsigned char*>(&word);
            for (std::size_t i = 0; i < sizeof(long) && off + i < n; ++i)
                wb[i] = (off + i < s.size())
                            ? static_cast<unsigned char>(s[off + i])
                            : 0;                        // the terminating NUL
            if (::ptrace(PTRACE_POKEDATA, cur_,
                         reinterpret_cast<void*>(at + off),
                         reinterpret_cast<void*>(word)) != 0)
                return false;
            off += sizeof(long);
        }
        return true;
    }

private:
    // Resume `w` toward its next syscall stop, delivering any signal we held
    // back during a redirect step (so a deferred SIGALRM/SIGCHLD/... is not
    // lost, just sequenced AFTER the rewritten syscall completed).
    void resume_task(::pid_t w) {
        int sig = 0;
        if (auto it = tasks_.find(w); it != tasks_.end()) {
            sig = it->second.pending_sig;
            it->second.pending_sig = 0;
        }
        // We've consumed this task's exit stop; let it run FREE to its next
        // filtered call (CONT under seccomp) rather than stopping at every
        // subsequent syscall (PTRACE_SYSCALL), delivering any held signal.
        resume_run(w, sig);
    }

    // At a task's syscall-EXIT stop, apply the action recorded at entry.
    void finalize_exit(::pid_t w, Task& t) {
        if (t.action == Action::set_ret) {
            struct user_regs_struct r{};
            ::ptrace(PTRACE_GETREGS, w, 0, &r);
            r.rax = static_cast<unsigned long long>(t.ret);
            ::ptrace(PTRACE_SETREGS, w, 0, &r);
        } else {
            // A FORWARDED syscall ran natively. The process-management calls
            // (fork/vfork/clone, wait4/waitid, getpgid/getsid/tcgetpgrp done
            // via forwarded ioctl) return a real HOST pid in RAX. Left raw it
            // would leak the host pid space into the guest — $! and jobs would
            // print six-digit host pids, and `wait N` on a small guest pid
            // would never match. Rewrite the returned pid to its small GUEST
            // pid so the whole tree lives in one coherent tiny namespace, the
            // way a PID-namespace container does. Only positive returns are
            // pids; negative (errno) and 0 (the child side of fork) pass
            // through untouched.
            struct user_regs_struct r{};
            ::ptrace(PTRACE_GETREGS, w, 0, &r);
            if (returns_pid(r.orig_rax)) {
                auto host = static_cast<::pid_t>(static_cast<long long>(r.rax));
                if (host > 0) {
                    r.rax = static_cast<unsigned long long>(gpid_of(host));
                    ::ptrace(PTRACE_SETREGS, w, 0, &r);
                }
            }
        }
        t.action = Action::none;
        t.in_call = false;
    }

    // The forwarded syscalls whose successful return value IS a pid (x86-64
    // numbers). We translate these host pids to guest pids at their exit stop
    // so the guest never sees a host pid. fork=57, vfork=58, clone=56,
    // clone3=435, wait4=61, waitid=247.
    static bool returns_pid(unsigned long long nr) {
        switch (nr) {
            case 56: case 57: case 58: case 435:   // clone/fork/vfork/clone3
            case 61:                               // wait4
                return true;
            default:
                return false;
        }
    }

    // Step ONE task from its syscall-ENTRY stop to its syscall-EXIT stop,
    // transparently passing any PTRACE_EVENT (fork/exec) stops. Used by the
    // SYNCHRONOUS redirect(); safe because path syscalls never block on a
    // sibling. Returns false if the task exited during the syscall.
    bool step_to_exit(::pid_t w) {
        ::ptrace(PTRACE_SYSCALL, w, 0, 0);
        int held_sig = 0;   // a signal that arrived mid-syscall, re-injected after
        for (;;) {
            int st = 0;
            if (::waitpid(w, &st, __WALL) < 0) return false;
            if (WIFEXITED(st) || WIFSIGNALED(st)) {
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                if (w == root_pid_) exit_code_ = code;
                if (auto it = gpid_.find(w); it != gpid_.end())
                    proc_events_.push_back({ProcEvent::reap, it->second, 0, {}, {}});
                // Retained past exit — see the note in next(): the parent's
                // wait4 still needs to translate this reaped pid.
                tasks_.erase(w);
                if (--live_ <= 0) exited_ = true;
                return false;
            }
            if (!WIFSTOPPED(st)) return false;
            int event = st >> 16;
            if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {
                unsigned long np = 0;
                ::ptrace(PTRACE_GETEVENTMSG, w, 0, &np);
                auto child = static_cast<::pid_t>(np);
                if (np && tasks_.emplace(child, Task{}).second)
                    ++live_;
                if (np && event != PTRACE_EVENT_CLONE) {
                    gppid_[gpid_of(child)] = gpid_of(w);
                    proc_events_.push_back({ProcEvent::spawn, gpid_of(child),
                                            gpid_of(w), {}, {}});
                }
                ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
            if (event == PTRACE_EVENT_EXEC) {
                // exec replaced the image; there is no ordinary syscall-exit.
                // This is the exec we were redirecting: record the new image
                // so the process monitor sees the program it became.
                proc_events_.push_back({ProcEvent::exec, gpid_of(w), 0,
                                        comm_of(w), cmdline_of(w)});
                tasks_[w] = Task{};
                return true;
            }
            if (WSTOPSIG(st) == (SIGTRAP | 0x80)) {
                // The syscall-exit stop we were after. If a real signal was
                // held back during the syscall, re-inject it now so the task
                // still receives it — but on the NEXT resume, after we've read
                // the result and (for a redirect) any post_exit patch has run.
                if (held_sig) tasks_[w].pending_sig = held_sig;
                return true;
            }
            // A real signal arrived while we were stepping the rewritten path
            // syscall to its exit. Delivering it HERE runs the guest's handler
            // mid-redirect, which reorders the handler's own syscalls ahead of
            // the result we're about to read. So HOLD the signal: resume with
            // 0 and re-inject it once the syscall has exited (via pending_sig).
            // SIGTRAP (a trap, not a real signal) is swallowed as before.
            int sig = WSTOPSIG(st);
            if (sig != SIGTRAP && sig != (SIGTRAP | 0x80)) held_sig = sig;
            ::ptrace(PTRACE_SYSCALL, w, 0, 0);
        }
    }

    std::string path_;
    std::vector<std::string> argv_;
    std::vector<std::string> envp_;
    std::string root_;
    std::function<void()> pre_exec_;   // child hook (post-fork, pre-execve)
    std::vector<ProcEvent> proc_events_;
    std::unordered_map<::pid_t, std::int32_t> gpid_;   // host tid -> guest pid
    std::unordered_map<std::int32_t, std::int32_t> gppid_; // guest pid -> ppid
    std::int32_t next_gpid_{2};                        // pid 1 = root/init
    ::pid_t cur_{-1};
    ::pid_t root_pid_{-1};
    int exit_code_{0};
    int live_{0};
    bool exited_{false};
    bool seccomp_{false};          // trap filter active -> drive with PTRACE_CONT
    std::unordered_map<::pid_t, Task> tasks_;
};

static_assert(SyscallTrap<PtraceTrap>, "PtraceTrap must model SyscallTrap");

} // namespace lx::runtime
