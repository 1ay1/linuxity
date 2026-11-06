// linuxity/runtime/linux/ptrace_trap.hpp
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
#include "linuxity/conform/arch.hpp"
#include "linuxity/runtime/linux/ptrace_regs.hpp"
#include "linuxity/abi/wire/errno_map.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/runtime/linux/seccomp_filter.hpp"

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
#include <unordered_set>
#include <utility>
#include <vector>
#include <fcntl.h>

namespace lx::runtime {

// The per-arch register view (ptrace_regs.hpp). Named locally so the state
// machine below reads the same on x86-64 and aarch64.
using Regs = linux_regs::Regs;

// The arch whose syscall numbering the tracee uses. Same reason as Regs:
// every decode below reads this instead of naming a machine, so there is one
// place to change and none to forget. A wrong arch here does not fail to
// compile -- it silently names OTHER syscalls, so it must not be spelled
// twice.
inline constexpr abi::Arch kTraceeArch = conform::host_arch();

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
        Regs regs{};
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
            // Our own ids, read BEFORE the filter goes up: getpid and gettid
            // are both trapped, so calling them after the filter is installed
            // but before the tracer is armed would ENOSYS-fail.
            const int pre_pid = static_cast<int>(::syscall(SYS_getpid));
            const int pre_tid = static_cast<int>(::syscall(SYS_gettid));
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
            // Stop here so the parent can arm PTRACE_O_TRACESECCOMP before the
            // first (now TRACE-filtered) execve runs; otherwise that exec
            // traps with no tracer listening and ENOSYS-aborts (_exit 127).
            //
            // The self-stop must use a syscall this filter does NOT trap:
            // with the filter up but no tracer armed, a trapped syscall
            // ENOSYS-fails, the child never stops, and the parent waits
            // forever (observed: guests ran to completion printing nothing).
            // kill, getpid, gettid, tkill and tgkill are all trapped now, so
            // the stop goes through rt_tgsigqueueinfo(297), which linuxity has
            // no handler for and never needs to intercept. Reserving one
            // obscure syscall is cheaper than leaving the whole kill family
            // native -- untrapped tkill/tgkill returned EPERM to guests,
            // because the guest passes a GUEST pid the host cannot signal.
            //
            // siginfo for a queued signal: si_code SI_TKILL (-6) makes the
            // kernel treat it exactly like tkill.
            struct {
                int si_signo, si_errno, si_code;
                int pad[29];
            } info{};
            info.si_signo = SIGSTOP;
            info.si_code = -6;                 // SI_TKILL
            if (::syscall(SYS_rt_tgsigqueueinfo, pre_pid, pre_tid, SIGSTOP,
                          &info) != 0) {
                // Pre-5.x kernels or a seccomp policy we did not expect.
                // If the stop never happens the parent's waitpid reports the
                // exec instead, which the loop handles -- a degradation, not
                // a hang.
                ::syscall(SYS_tkill, pre_tid, SIGSTOP);
            }
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
        // The child is stopped at the tkill-SIGSTOP it raised after TRACEME.
        // Arm options now (so the coming execve traps as PTRACE_EVENT_SECCOMP),
        // then resume it past the stop into its bootstrap execve.
        int opts = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD |
                   PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
        if (seccomp_) opts |= PTRACE_O_TRACESECCOMP;
        ::ptrace(PTRACE_SETOPTIONS, pid, 0, opts);
        root_pid_ = pid;
        tasks_[pid];                       // create, at-entry state
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
                if (WIFSIGNALED(st)) trace_killed(w, WTERMSIG(st));
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
                --live_;
                // The ROOT task is the guest's init/session leader. When it
                // exits the foreground session is over and control returns to
                // whoever launched linuxity -- exactly as a controlling
                // terminal returns to the parent shell when the session leader
                // dies. A DAEMON the guest detached (gpg-agent/dirmngr: double
                // fork + setsid) is still alive and, worse, typically inherited
                // our stdout/stderr, so it neither exits on its own nor lets
                // its pipe EOF: waiting for live_==0 would hang the runtime
                // forever. On a real host such a daemon survives reparented to
                // init; here linuxity OWNS the tree, so the faithful behaviour
                // is to reap the session and let PTRACE_O_EXITKILL take the
                // orphans down with us. Tear the tree down and return.
                if (w == root_pid_) { reap_tree(); exited_ = true; return ok(false); }
                if (live_ <= 0) { exited_ = true; return ok(false); }
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
                // The parent link is recorded for EVERY new task, thread or
                // process. A PROCESS also gets a process-table entry (below);
                // a thread must not, since it is not a separate process in
                // the guest's view -- but it still needs gppid_, because
                // set_current_pid() seeds a task's cwd from its parent and a
                // missing link means seeding from pid 0, which has no record.
                // That resolved relative paths against "/": gcc under
                // `make -j` hit "can't create s4.o: Permission denied" because
                // it was trying to create /s4.o.
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
                // a new program. The ROOT's FIRST exec is the bootstrap of
                // path_ (a host path) -- mark it done so later guest execs are
                // dispatched through path_exec.
                if (w == root_pid_) booted_root_ = true;
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
                Regs rr{};
                (void)Regs::fetch(w, rr);
                // The ROOT's bootstrap execve targets path_, already a resolved
                // HOST path; path_exec expects a GUEST path and would
                // mis-resolve it. Run that one exec natively; every guest exec
                // after the image is live goes through the dispatcher.
                std::uint64_t sysno = rr.nr();
                const abi::Sysno boot_sc = abi::decode(kTraceeArch, sysno);
                if (!booted_root_ && w == root_pid_ &&
                    (boot_sc == abi::Sysno::execve ||
                     boot_sc == abi::Sysno::execveat)) {
                    // Let this bootstrap execve run NATIVELY. At a
                    // PTRACE_EVENT_SECCOMP stop the kernel has parked rax at
                    // -ENOSYS as the "skip unless the tracer re-arms it"
                    // sentinel; a bare PTRACE_CONT would return that ENOSYS and
                    // the exec would _exit(127). Re-write the entry registers
                    // (orig_rax = the exec nr) so the syscall is re-armed, then
                    // resume -- the exec proceeds and its PTRACE_EVENT_EXEC
                    // sets booted_root_.
                    (void)rr.store(w);
                    resume_run(w, 0);
                    continue;
                }
                Task& t = tasks_[w];
                cur_ = w;
                t.regs = rr;
                t.in_call = true;
                translate_entry_args(w, rr, t);
                fill_frame(f, rr);
                return ok(true);
            }
            // The initial SIGSTOP/ SIGTRAP of a freshly-attached child. This
            // may arrive BEFORE the parent's PTRACE_EVENT_FORK stop (the kernel
            // does not order the two), so this can be the FIRST time we see the
            // task. If so it must be counted in live_ here -- otherwise the
            // fork-event's `emplace(...).second` guard finds the task already
            // present, skips its ++live_, and the child is tracked but NEVER
            // counted. When it later exits, --live_ then undercounts the tree
            // and can drive live_ to 0 while real tasks remain, tearing the
            // whole runtime down mid-run (observed: gpg-agent's fast-exiting
            // double-fork intermediary killing the parent shell prematurely).
            if (sig == SIGSTOP || sig == SIGTRAP) {
                // ...but only when it IS that attach stop. A SIGTRAP from a
                // real trap instruction (a breakpoint, an assert that
                // compiles to brk/int3) must be delivered: swallowing one is
                // an infinite loop, because resumed with signal 0 the guest
                // re-executes the same instruction at the same pc forever,
                // never dying and never progressing.
                //
                // si_code tells them apart, but not uniformly: arm64's brk
                // reports TRAP_BRKPT, while x86-64's int3 reports SI_KERNEL
                // (measured, both on this kernel). The attach stop instead
                // reports SI_USER/0, which is neither. So accept anything
                // that is positively a trap rather than listing one arch's
                // spelling.
                siginfo_t si{};
                const bool real_trap =
                    sig == SIGTRAP &&
                    ::ptrace(PTRACE_GETSIGINFO, w, 0, &si) == 0 &&
                    (si.si_code == TRAP_BRKPT || si.si_code == TRAP_TRACE ||
                     si.si_code == SI_KERNEL);
                if (!real_trap) {
                    if (tasks_.try_emplace(w).second) ++live_;
                    resume_run(w, 0);
                    continue;
                }
                trace_fault(w, sig);
                resume_run(w, sig);
                continue;
            }
            // A real syscall stop (TRACESYSGOOD => SIGTRAP|0x80). Under the
            // seccomp fast path this is ONLY an EXIT stop (from the one-shot
            // PTRACE_SYSCALL a serviced entry issued); entries arrive as
            // PTRACE_EVENT_SECCOMP above. Without seccomp it is BOTH the entry
            // and the exit, distinguished by the -ENOSYS-primed RAX.
            if (sig == (SIGTRAP | 0x80)) {
                Task& t = tasks_[w];
                Regs rr{};
                (void)Regs::fetch(w, rr);
                bool is_entry = !seccomp_
                    && (static_cast<long long>(rr.ret()) == -38 /*ENOSYS*/)
                    && !t.in_call;
                if (is_entry) {
                    // Same bootstrap exemption as the seccomp path, for the
                    // PTRACE_SYSCALL fallback (LINUXITY_NO_SECCOMP): the ROOT's
                    // first execve targets path_ (a resolved HOST path), which
                    // path_exec would mis-resolve as a guest path. Forward it
                    // natively; its PTRACE_EVENT_EXEC sets booted_root_ and
                    // every later guest exec is dispatched normally.
                    std::uint64_t sysno = rr.nr();
                    const abi::Sysno bsc = abi::decode(kTraceeArch, sysno);
                    if (!booted_root_ && w == root_pid_ &&
                        (bsc == abi::Sysno::execve ||
                         bsc == abi::Sysno::execveat)) {
                        t.in_call = true;
                        ::ptrace(PTRACE_SYSCALL, w, 0, 0);   // run exec to exit
                        continue;
                    }
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
            // Any other signal: deliver it to the task. Rewrite si_pid first,
            // so a SA_SIGINFO handler sees the SENDER's guest pid rather than
            // a host pid that does not exist in its namespace.
            rewrite_siginfo_pid(w);
            trace_fault(w, sig);
            resume_run(w, sig);
        }
    }

    // A guest died on a signal. Under LINUXITY_TRACE say so, because the
    // trace otherwise just stops mid-stream and a fatal SIGILL/SIGSEGV looks
    // identical to a clean exit.
    void trace_killed(::pid_t w, int sig) const {
        const char* path = std::getenv("LINUXITY_TRACE");
        if (!path || !*path) return;
        std::FILE* out = std::fopen(path, "ae");
        if (!out) return;
        std::fprintf(out, "[lx] KILLED host_tid=%d sig=%d\n", (int)w, sig);
        std::fclose(out);
    }

    // Under LINUXITY_TRACE, say WHERE a hardware fault happened. A guest that
    // dies with "Illegal instruction" otherwise leaves nothing to go on: the
    // trace just stops, because no syscall was involved. Reporting the faulting
    // pc and the mapping it lands in turns that into a one-line answer.
    void trace_fault(::pid_t w, int sig) const {
        if (sig != SIGILL && sig != SIGSEGV && sig != SIGBUS && sig != SIGFPE)
            return;
        const char* path = std::getenv("LINUXITY_TRACE");
        if (!path || !*path) return;

        siginfo_t si{};
        (void)::ptrace(PTRACE_GETSIGINFO, w, 0, &si);
        Regs rr{};
        (void)Regs::fetch(w, rr);
        const std::uint64_t pc = rr.pc();

        // Which mapping holds the pc, so the address means something without
        // a debugger attached.
        std::string where;
        if (std::FILE* m = std::fopen(("/proc/" + std::to_string(w) + "/maps").c_str(), "re")) {
            char line[512];
            while (std::fgets(line, sizeof line, m)) {
                unsigned long long lo = 0, hi = 0;
                if (std::sscanf(line, "%llx-%llx", &lo, &hi) != 2) continue;
                if (pc < lo || pc >= hi) continue;
                std::string s{line};
                while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back();
                const auto sp = s.find('/');
                where = sp == std::string::npos ? s : s.substr(sp);
                // Offset within the mapping is what an addr2line wants.
                where += " +" + hex_of(pc - lo);
                break;
            }
            std::fclose(m);
        }

        std::FILE* out = std::fopen(path, "ae");
        if (!out) return;
        std::fprintf(out, "[lx] FAULT sig=%d code=%d pc=%#llx addr=%p %s\n",
                     sig, si.si_code, (unsigned long long)pc, si.si_addr,
                     where.c_str());
        std::fclose(out);
    }

    static std::string hex_of(std::uint64_t v) {
        char b[32];
        std::snprintf(b, sizeof b, "%#llx", (unsigned long long)v);
        return b;
    }

    // Fill the arch-neutral TrapFrame from x86-64 registers at a syscall stop.
    static void fill_frame(TrapFrame& f, const Regs& rr) {
        f.regs.nr     = rr.nr();
        f.regs.arg[0] = rr.arg(0); f.regs.arg[1] = rr.arg(1);
        f.regs.arg[2] = rr.arg(2); f.regs.arg[3] = rr.arg(3);
        f.regs.arg[4] = rr.arg(4);  f.regs.arg[5] = rr.arg(5);
        f.pc          = rr.pc();
    }

    // At a syscall-ENTRY stop, translate any GUEST pid arguments to host tids
    // before the kernel runs the (forwarded) call. Currently: wait4(pid,...).
    // A forwarded wait4 carries a GUEST pid in arg0 (we hand the guest small
    // pids from fork); the host kernel only knows the real host tid, so a raw
    // guest pid would wait on nothing and return -1/ECHILD. Rewrite a positive
    // pid to its host tid; the reaped pid is translated back at the exit stop
    // (returns_pid). pid<=0 (any child / process group) passes through.
    void translate_entry_args(::pid_t w, Regs& rr, Task& t) {
        const abi::Sysno sc = abi::decode(kTraceeArch, rr.nr());
        if (sc == abi::Sysno::wait4) {
            auto gpid = static_cast<std::int32_t>(static_cast<long long>(rr.arg(0)));
            if (gpid > 0) {
                ::pid_t host = host_tid_of(gpid);
                if (host > 0) {
                    Regs wr = rr;
                    wr.set_arg(0, static_cast<std::uint64_t>(host));
                    (void)wr.store(w);
                    t.regs = wr;
                    rr = wr;
                }
            }
        } else if (sc == abi::Sysno::waitid) {
            // waitid(idtype /*rdi*/, id /*rsi*/, siginfo* /*rdx*/, opts /*r10*/).
            // Kernel idtype enum: P_ALL=0, P_PID=1, P_PGID=2, P_PIDFD=3. For
            // P_PID/P_PGID the `id` is a GUEST pid/pgid we map to a host tid;
            // P_ALL and P_PIDFD carry no guest pid.
            auto idtype = static_cast<unsigned>(rr.arg(0));
            auto gid = static_cast<std::int32_t>(static_cast<long long>(rr.arg(1)));
            if ((idtype == 1 /*P_PID*/ || idtype == 2 /*P_PGID*/) && gid > 0) {
                ::pid_t host = host_tid_of(gid);
                if (host > 0) {
                    Regs wr = rr;
                    wr.set_arg(1, static_cast<std::uint64_t>(host));
                    (void)wr.store(w);
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
        Regs r = t.regs;
        r.skip_call();
        if (seccomp_) {
            // Fast path: one stop, not two. At a PTRACE_EVENT_SECCOMP stop,
            // orig_rax = -1 skips the call and the kernel returns whatever we
            // leave in rax (seccomp(2), SECCOMP_RET_TRACE). The old path
            // stepped to the syscall EXIT just to write rax there: 7 ptrace
            // calls and 2 waits per answered syscall, measured. Now 3 and 1.
            r.set_ret(static_cast<std::int64_t>(ret));
            if (!store_and_skip(r)) return err(Errno::eio);
            t.action = Action::none;
            t.in_call = false;
            const int sig = t.pending_sig;
            t.pending_sig = 0;
            resume_run(cur_, sig);
            return ok();
        }
        // PTRACE_SYSCALL fallback (no seccomp): at an ordinary entry stop the
        // kernel still owes us the exit stop, so write rax there.
        if (!store_and_skip(r)) return err(Errno::eio);
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

    // Writing the general registers is only HALF of neutralizing a syscall.
    // On aarch64 the kernel latches the syscall number before the tracer
    // stop, so x8 is advisory by then and the original call still runs --
    // NT_ARM_SYSTEM_CALL is the register set that actually selects it. Both
    // steps, in order, in one place, because doing the store without the
    // commit silently runs the syscall we meant to answer ourselves (seen as
    // a virtualized uname returning EFAULT: the handler's reply was
    // overwritten by the real one).
    [[nodiscard]] bool store_and_skip(const Regs& r) const {
        return r.store(cur_) && r.commit_skip(cur_);
    }

    // FORWARD: let the host kernel run this syscall in the task. We report the
    // result asynchronously as 0 (the loop doesn't need it for a plain
    // forward); the real value lands in the guest's RAX by the kernel itself.
    // A one-shot PTRACE_SYSCALL steps to the EXIT stop so finalize_exit can
    // translate a returned host pid (fork/wait) to a guest pid before the
    // guest reads it -- but only for the calls that need it, see below.
    // Does a FORWARDED syscall still owe us its EXIT stop? True exactly when
    // finalize_exit has something to do there -- translating a returned host
    // pid, or rewriting waitid's si_pid. Derived from returns_pid, the SSOT
    // for the pid-returning set, so adding a syscall there cannot forget this.
    //
    // Everything else (read, close, lgetxattr, getdents64, ...) gets nothing
    // from the exit stop, and that stop is not free: it is a wait4 and a pair
    // of context switches. A plain forward is the most common fate there is --
    // lgetxattr, close and getdents64 alone are 77K of the 150K traps in one
    // `ls -lR /usr/include`.
    [[nodiscard]] static bool owes_exit_stop(unsigned long long nr) {
        return returns_pid(nr) || abi::decode(kTraceeArch, nr) ==
                                      abi::Sysno::waitid;
    }

    [[nodiscard]] Result<std::int64_t> forward() {
        Task& t = tasks_[cur_];
        t.action = Action::none;
        // Under seccomp a call with no exit work can run FREE to its next
        // filtered syscall instead of stopping again at this one's exit.
        //
        // Only when nothing is owed. A blanket CONT here broke two things at
        // once: fork handed the guest a raw HOST pid (run_pid_namespace caught
        // it as fork-ret != child-getpid) and the two drive modes diverged
        // (run_seccomp, 15 vs 0). The exit stop is where that translation
        // happens, so skipping it is only safe per-syscall.
        if (seccomp_ && !owes_exit_stop(t.regs.nr())) {
            t.in_call = false;
            resume_run(cur_, 0);
            return ok(std::int64_t{0});
        }
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);   // run the real syscall to exit
        return ok(std::int64_t{0});
    }

    // Like forward(), but SYNCHRONOUS: step the syscall to its EXIT stop and
    // return the kernel's real result (rax). Used for dup/dup2/dup3/fcntl,
    // whose returned fd we must observe to mirror the source fd's path/dir
    // binding onto the new fd. Safe because these calls never block on a
    // sibling. `post_exit` runs while the task is still stopped at exit.
    [[nodiscard]] Result<std::int64_t> forward_sync(
            std::function<void(std::int64_t)> post_exit = {}) {
        Task& t = tasks_[cur_];
        t.action = Action::none;
        if (!step_to_exit(cur_)) return ok(std::int64_t{-1});   // task exited
        Regs rr{};
        (void)Regs::fetch(cur_, rr);
        std::int64_t ret = static_cast<std::int64_t>(rr.ret());
        tasks_[cur_].in_call = false;
        if (post_exit) post_exit(ret);
        resume_task(cur_);
        return ok(ret);
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
        Regs r = t.regs;
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
            (t.regs.sp() - 256 - need) & ~std::uint64_t{15};
        if (!poke_path(scratch, host_path, /*dead_scratch=*/true)) {
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
            (void)t.regs.store(cur_);
            if (!step_to_exit(cur_)) return ok(std::int64_t{-1});
            Regs rr0{};
            (void)Regs::fetch(cur_, rr0);
            std::int64_t ret0 = static_cast<std::int64_t>(rr0.ret());
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
            if (!poke_path(scratch2, host_path2, /*dead_scratch=*/true))
                return err<std::int64_t>(Errno::efault);
            set_arg(r, path_arg2, scratch2);
        }
        (void)r.store(cur_);
        if (!step_to_exit(cur_)) return ok(std::int64_t{-1});   // task exited
        Regs rr{};
        (void)Regs::fetch(cur_, rr);
        std::int64_t ret = static_cast<std::int64_t>(rr.ret());
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

    // REWRITE_ARG: run the guest's syscall with one argument register replaced,
    // step to its exit, and let the caller patch the result buffer before the
    // guest can read it. Synchronous for the same reason redirect() is: the
    // fixup has to land while the task is still stopped at the exit.
    //
    // No path is involved, so nothing is poked into guest memory on entry --
    // just the one register.
    [[nodiscard]] Result<std::int64_t> rewrite_arg(
        int arg, std::uint64_t value_in,
        std::function<void(std::int64_t)> post_exit = {}) {
        Task& t = tasks_[cur_];
        Regs r = t.regs;
        set_arg(r, arg, value_in);
        (void)r.store(cur_);
        if (!step_to_exit(cur_)) return ok(std::int64_t{-1});   // task exited
        Regs rr{};
        (void)Regs::fetch(cur_, rr);
        const std::int64_t ret = static_cast<std::int64_t>(rr.ret());
        tasks_[cur_].in_call = false;
        if (post_exit) post_exit(ret);
        resume_task(cur_);
        return ok(ret);
    }

    // REWRITE_SOCKADDR: for an AF_UNIX bind/connect, poke the translated host
    // path into the guest's sun_path and set the socklen register, then
    // forward the call to the kernel. Like redirect(), the path bytes MUST go
    // in via PTRACE_POKEDATA (ordered against the kernel's copy_from_user on
    // resume) rather than process_vm_writev. The socket path lives in the
    // guest's OWN memory (the sockaddr the caller passed), so we overwrite it
    // in place; the new path is guaranteed by the dispatcher to fit in the
    // 108-byte sun_path. Asynchronous like forward(): the kernel runs the
    // bind/connect and lands the result in the guest's RAX itself.
    [[nodiscard]] Status rewrite_sockaddr(UAddr path_addr,
                                          const std::string& host_path,
                                          int len_arg,
                                          std::uint64_t new_len) {
        Task& t = tasks_[cur_];
        Regs r = t.regs;
        if (!poke_path(value(path_addr), host_path))
            return err(Errno::efault);
        set_arg(r, len_arg, new_len);
        (void)r.store(cur_);
        t.action = Action::none;
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);   // run the real bind/connect
        return ok();
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
            const std::vector<std::string>& prefix = {},
            const std::vector<std::string>& extra_args = {}) {
        Task& t = tasks_[cur_];
        Regs r = t.regs;
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
        std::size_t narg = 2 + nprefix +
                           (orig.empty() ? 0 : orig.size() - 1) + extra_args.size();
        std::size_t arr_bytes = (narg + 1) * 8;
        std::size_t strbytes = interp_host.size() + 1 + prog_guest.size() + 1;
        for (const auto& s : prefix) strbytes += s.size() + 1;
        for (const auto& s : extra_args) strbytes += s.size() + 1;
        std::size_t block = strbytes + arr_bytes + 64;
        std::uint64_t base = (t.regs.sp() - 512 - block) & ~std::uint64_t{15};

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
        std::vector<std::uint64_t> p_extra;
        for (const auto& s : extra_args) p_extra.push_back(put(s));

        if (!write_cstr(p_interp, interp_host)) return err<std::int64_t>(Errno::efault);
        for (std::size_t i = 0; i < nprefix; ++i)
            if (!write_cstr(p_prefix[i], prefix[i])) return err<std::int64_t>(Errno::efault);
        if (!write_cstr(p_prog, prog_guest)) return err<std::int64_t>(Errno::efault);
        for (std::size_t i = 0; i < extra_args.size(); ++i)
            if (!write_cstr(p_extra[i], extra_args[i])) return err<std::int64_t>(Errno::efault);

        std::uint64_t arr = (cursor + 15) & ~std::uint64_t{15};
        std::vector<std::uint64_t> ptrs;
        ptrs.push_back(p_interp);          // argv[0] = interpreter
        for (auto p : p_prefix) ptrs.push_back(p);  // shebang arg / sh host path
        ptrs.push_back(p_prog);            // the program (guest path)
        for (std::size_t i = 1; i < orig.size(); ++i)
            ptrs.push_back(orig[i]);       // original argv[1..]
        for (auto p : p_extra) ptrs.push_back(p);  // appended --overwrite "*"
        ptrs.push_back(0);                 // NULL terminator
        std::vector<std::byte> arrbytes(ptrs.size() * 8);
        std::memcpy(arrbytes.data(), ptrs.data(), arrbytes.size());
        if (!copy_out(uaddr(arr), arrbytes)) return err<std::int64_t>(Errno::efault);

        set_arg(r, path_arg, p_interp);   // exec the interpreter
        set_arg(r, argv_reg, arr);        // with the rebuilt argv
        (void)r.store(cur_);
        // Forward: the kernel runs the (rewritten) execve; on success it
        // replaces the image and we get a PTRACE_EVENT_EXEC. Don't step here.
        t.action = Action::none;
        resume_run(cur_, 0);
        return ok(std::int64_t{0});
    }

    // Thin wrappers kept so existing call sites read unchanged; the arch
    // detail now lives in ptrace_regs.hpp.
    static std::uint64_t reg_arg(const Regs& r, int n) { return r.arg(n); }

    [[nodiscard]] bool write_cstr(std::uint64_t at, const std::string& s) {
        std::vector<std::byte> b(s.size() + 1);
        std::memcpy(b.data(), s.c_str(), s.size() + 1);
        return static_cast<bool>(copy_out(uaddr(at), b));
    }

    static void set_arg(Regs& r, int n, std::uint64_t v) { r.set_arg(n, v); }

    // A task's program name for /proc/<pid>/comm, the (comm) field of stat,
    // and Name: in status.
    //
    // NOT the host's /proc/<tid>/comm. linuxity launches every dynamic guest
    // as `ld-linux-x86-64.so.2 /bin/prog ...`, so the host kernel's comm for
    // that task is the LOADER -- "ld-linux-x86-64" -- for every single dynamic
    // process. That made /proc report the same name for bash, ps and ls, so
    // `pgrep bash` found nothing while bash was running, `pstree` showed a
    // tree of identical loaders, and `top`'s COMMAND column was useless.
    //
    // cmdline_of() already strips that launch artifact for /proc/PID/cmdline.
    // comm is the same fact -- "what program is this" -- so it is derived from
    // the same cleaned argv instead of re-reading a second, wrong source. The
    // kernel truncates comm to TASK_COMM_LEN-1 (15) bytes; matching that keeps
    // `ps -o comm` columns and pgrep's exact-match semantics identical to a
    // real kernel.
    std::string comm_of(::pid_t tid) const {
        const std::string cmd = cmdline_of(tid);
        if (!cmd.empty()) {
            // argv[0] of the de-translated command line, basename only.
            const std::string argv0 = cmd.substr(0, cmd.find('\0'));
            const auto slash = argv0.find_last_of('/');
            std::string base = slash == std::string::npos ? argv0
                                                          : argv0.substr(slash + 1);
            if (base.size() > 15) base.resize(15);   // TASK_COMM_LEN - 1
            if (!base.empty()) return base;
        }
        // No usable argv (a task that cleared its own): fall back to the
        // host's comm, which is right for a static guest with no loader.
        return host_comm_of(tid);
    }

    static std::string host_comm_of(::pid_t tid) {
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
    // at exec, so the process monitor shows the real command line. The raw
    // host argv is in HOST terms: linuxity launches a dynamic guest as
    // `<root>/lib64/ld-linux-x86-64.so.2 <root>/bin/prog ...`, so we (1) drop a
    // leading ELF interpreter (ld-linux/ld-musl) token — it's a linuxity
    // launch artifact, not part of the guest's command — and (2) de-translate
    // the overlay/root prefix off every remaining token so /proc shows the
    // GUEST path (/bin/htop) instead of /tmp/arch/root.x86_64/bin/htop.
    std::string cmdline_of(::pid_t tid) const {
        std::string path = "/proc/" + std::to_string(tid) + "/cmdline";
        int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return {};
        std::string s; char buf[512]; ssize_t n;
        while ((n = ::read(fd, buf, sizeof buf)) > 0)
            s.append(buf, static_cast<std::size_t>(n));
        ::close(fd);
        // Split on the NUL argv separators into individual tokens.
        std::vector<std::string> args;
        std::string cur;
        for (char c : s) {
            if (c == '\0') { if (!cur.empty() || !args.empty()) args.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        if (!cur.empty()) args.push_back(cur);
        if (args.empty()) return {};
        // De-translate a host path back to the guest view: strip the overlay
        // upper prefix or the --root prefix so the guest sees its own path.
        auto detranslate = [this](std::string a) -> std::string {
            if (!root_.empty() && a.size() > root_.size() &&
                a.compare(0, root_.size(), root_) == 0 && a[root_.size()] == '/')
                a.erase(0, root_.size());
            return a;
        };
        // Drop a leading ELF interpreter token (ld-linux*.so* / ld-musl*.so*):
        // it's how linuxity launches a dynamic binary, not the guest command.
        auto is_interp = [](const std::string& a) {
            auto slash = a.find_last_of('/');
            std::string base = slash == std::string::npos ? a : a.substr(slash + 1);
            return base.rfind("ld-linux", 0) == 0 || base.rfind("ld-musl", 0) == 0 ||
                   base.rfind("ld.so", 0) == 0;
        };
        std::size_t start = (args.size() > 1 && is_interp(args[0])) ? 1 : 0;
        // NUL-joined, which is ProcInfo::cmdline's documented contract and
        // the exact /proc/<pid>/cmdline wire format. This used to join with
        // SPACES, contradicting the field's own comment -- so a guest got
        // "/tmp/argv C two three" where the kernel gives
        // "/tmp/argv\0C\0two\0three", and an argument containing a space
        // became indistinguishable from two arguments.
        std::string out;
        for (std::size_t i = start; i < args.size(); ++i) {
            if (i > start) out.push_back('\0');
            out += detranslate(args[i]);
        }
        return out;
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

    // Stat a REAL host path, so the dispatcher can answer a host-backed guest
    // stat in the SAME trap stop instead of redirecting the call and stepping
    // the guest to its syscall exit. Optional by design: the dispatcher asks
    // with `requires`, so a backend without it keeps the two-stop path and the
    // worst case of not having it is slower, never wrong.
    //
    // The supervisor's own stat is safe here because the path has ALREADY been
    // translated through FileNamespace -- it is a host path we chose, not
    // guest-controlled text, so this cannot be used to escape the namespace.
    [[nodiscard]] std::optional<abi::wire::StatFields>
    stat_host_path(const std::string& path) const {
        struct ::stat st{};
        if (::lstat(path.c_str(), &st) != 0) return std::nullopt;
        abi::wire::StatFields h;
        h.mode     = static_cast<std::uint32_t>(st.st_mode);
        h.dev      = static_cast<std::uint64_t>(st.st_dev);
        h.ino      = static_cast<std::uint64_t>(st.st_ino);
        h.nlink    = static_cast<std::uint64_t>(st.st_nlink);
        h.rdev     = static_cast<std::uint64_t>(st.st_rdev);
        h.size     = static_cast<std::uint64_t>(st.st_size);
        h.blksize  = static_cast<std::int64_t>(st.st_blksize);
        h.blocks   = static_cast<std::int64_t>(st.st_blocks);
        h.mtime_ns = static_cast<std::uint64_t>(st.st_mtim.tv_sec) * 1'000'000'000ull +
                     static_cast<std::uint64_t>(st.st_mtim.tv_nsec);
        h.atime_ns = static_cast<std::uint64_t>(st.st_atim.tv_sec) * 1'000'000'000ull +
                     static_cast<std::uint64_t>(st.st_atim.tv_nsec);
        h.ctime_ns = static_cast<std::uint64_t>(st.st_ctim.tv_sec) * 1'000'000'000ull +
                     static_cast<std::uint64_t>(st.st_ctim.tv_nsec);
        return h;
    }

    struct TaskIds { std::int32_t pid, tid, ppid; };
    // The GUEST-namespace identity of the task that trapped: its pid, its
    // thread id (== pid for the main thread; a distinct host tid otherwise),
    // and its parent's guest pid. The dispatcher answers getpid/gettid/getppid
    // from THIS, so every task sees its own coherent pid rather than a fixed
    // "pid 1". The root task is pid 1 with ppid 0 (init has no parent in
    // linuxity's world).
    [[nodiscard]] TaskIds current_ids() {
        // A THREAD shares its thread-group leader's pid and keeps its own tid.
        // gpid_of is keyed by host TID, so asking it directly gave a thread a
        // fresh guest pid -- a pthread reported getpid()==2 where native
        // reports the same pid as main. Two things broke on that:
        //
        //   * getpid() lied, which any threaded runtime notices.
        //   * the dispatcher keys each task's CWD by guest pid, so a thread
        //     looked up a pid with no cwd record and got "/". Relative paths
        //     then resolved against the root: gcc under `make -j` failed with
        //     "can't create s7.o: Permission denied" because the trace shows
        //     it trying to create /s7.o. One root cause, two symptoms.
        //
        // Resolve the host tgid first and map THAT, so every thread of a
        // process answers with the process's guest pid.
        //
        // CACHED: tgid_of reads /proc/<tid>/status, and doing that on every
        // syscall cost 18.79us against 4.86us before -- a 4x regression on
        // the hot path. A task's tgid never changes, so one lookup per task
        // is enough.
        ::pid_t host_tgid = cur_;
        if (auto it = tgid_cache_.find(cur_); it != tgid_cache_.end()) {
            host_tgid = it->second;
        } else {
            const ::pid_t t = tgid_of(cur_);
            host_tgid = t > 0 ? t : cur_;
            tgid_cache_[cur_] = host_tgid;
        }
        const std::int32_t pid = gpid_of(host_tgid);
        const std::int32_t tid = gpid_of(cur_);
        std::int32_t ppid = 0;
        if (auto it = gppid_.find(pid); it != gppid_.end()) ppid = it->second;
        return TaskIds{pid, tid, ppid};
    }

    // -- Signal delivery ---------------------------------------------------
    // The guest issued kill/tgkill/tkill against a GUEST pid. Translate that
    // pid to the real host tid of the traced task and deliver the signal
    // THERE (never to the raw host pid, which is an unrelated task). Returns
    // the guest-visible result: 0 on delivery, -ESRCH if the target guest pid
    // is unknown, or -errno if the host kill(2) itself fails.
    [[nodiscard]] std::int64_t deliver_signal(std::int32_t gpid,
                                              std::int32_t signum) {
        // kill(2)'s pid argument is a SUM, not a number:
        //   pid  > 0  -> that process
        //   pid == 0  -> every process in the CALLER's group
        //   pid == -1 -> every process we may signal
        //   pid  < -1 -> every process in group (-pid)
        //
        // All three non-positive forms used to collapse to the caller, so
        // kill(-childpgid, sig) signalled US instead of the child -- the
        // caller's handler ran and the target never saw it. LTP's kill10
        // caught this; it drives process groups with kill(-pid, SIGUSR1).
        //
        // We do not model process GROUPS on Linux: setpgid is accepted and
        // discarded (abi/syscall.hpp's flat model, since only the Darwin
        // backend declares models_process_groups), so the host pgid of every
        // traced task is the same and cannot distinguish one group from
        // another. Filtering on it signalled EVERY task, which leaked across
        // groups -- kill10 saw "unexpected signal 10".
        //
        // What we DO track is the guest process TREE (gppid_). A group leader
        // plus its descendants is a sound approximation: it is exactly right
        // for the shape programs actually use (fork children, setpgid the
        // leader, signal the group), and it is bounded -- unlike signalling
        // everything. Reaching only the leader was the other extreme, and
        // kill10's handshake hung waiting for acks that never came.
        if (gpid < -1 || gpid == 0 || gpid == -1) {
            const std::int32_t leader =
                (gpid < -1) ? -gpid : gpid_of(cur_);

            std::vector<::pid_t> targets;
            // Collect FIRST: deliver_to_tid calls gpid_of, which can insert
            // into gpid_ and invalidate an iterator we were holding.
            for (const auto& [tid, gp] : gpid_)
                if (gp == leader || descends_from(gp, leader))
                    targets.push_back(tid);

            // The implicit forms (0 and -1) always include the caller, which
            // may not be in gpid_ (the root task is tracked separately). An
            // explicit -pgid must NOT add the caller unless it is in that
            // tree -- doing so unconditionally made the sender signal itself,
            // which native does not.
            const bool implicit = (gpid == 0 || gpid == -1);
            if (implicit &&
                std::find(targets.begin(), targets.end(), cur_) == targets.end())
                targets.push_back(cur_);

            int delivered = 0;
            std::int64_t first_err = 0;
            for (const ::pid_t tid : targets) {
                const std::int64_t rc = deliver_to_tid(tid, signum);
                if (rc == 0) ++delivered;
                else if (first_err == 0) first_err = rc;
            }
            if (delivered == 0)
                return first_err != 0 ? first_err
                                      : -static_cast<std::int64_t>(Errno::esrch);
            return 0;
        }

        const ::pid_t tid = host_tid_of(gpid);
        if (tid < 0) return -static_cast<std::int64_t>(Errno::esrch);
        return deliver_to_tid(tid, signum);
    }

    // Is guest pid `p` a descendant of `root`? Walks gppid_ with a bounded
    // depth so a cycle (which should not happen, but a stale entry could
    // create one) cannot spin.
    [[nodiscard]] bool descends_from(std::int32_t p, std::int32_t root) const {
        for (int hops = 0; hops < 64 && p > 1; ++hops) {
            const auto it = gppid_.find(p);
            if (it == gppid_.end()) return false;
            p = it->second;
            if (p == root) return true;
        }
        return false;
    }

    // Deliver one signal to one host tid, with the guest sender in si_pid.
    [[nodiscard]] std::int64_t deliver_to_tid(::pid_t tid, std::int32_t signum) {

        // WHO the signal came from. The supervisor is the one issuing the
        // delivery, so a plain tgkill puts the SUPERVISOR's host pid in
        // si_pid -- a six-digit number that does not exist in the guest's
        // namespace. LTP's kill10 reported "received unexpected signal 10
        // from 1690548" for every process-group signal because of it, and any
        // program that checks its sender (a supervisor, an init, a test
        // harness) gets a pid it cannot match.
        //
        // rt_tgsigqueueinfo lets the sender state si_pid explicitly, and we
        // know the right answer: the guest pid of the task that made the call.
        //
        // si_code has to be SI_QUEUE, not SI_USER. The kernel REFUSES a
        // foreign sender's SI_USER with EPERM (measured) -- that rule exists
        // so nobody can forge a sender identity, and we are a foreign sender
        // from its point of view. SI_QUEUE is permitted and carries si_pid
        // faithfully.
        //
        // The tradeoff is honest: a handler that inspects si_code sees
        // SI_QUEUE where native would say SI_USER. That is the lesser error --
        // si_pid is what programs actually branch on (LTP's kill10 replies to
        // si_pid and never looks at si_code), and the alternative was a host
        // pid the guest cannot resolve at all.
        siginfo_t si{};
        si.si_signo = signum;
        si.si_code  = SI_QUEUE;
        si.si_pid   = gpid_of(cur_);
        si.si_uid   = 0;                 // the guest runs as root

        // signal 0 queues nothing -- it is a pure permission/liveness probe --
        // so it must go through the plain form.
        long rc = signum == 0
                      ? ::syscall(SYS_tgkill, tid, tid, signum)
                      : ::syscall(SYS_rt_tgsigqueueinfo, tid, tid, signum, &si);
        if (rc != 0) {
            // A kernel that refuses the queued form still has to deliver;
            // fall back to the direct ones, which are right apart from si_pid.
            rc = ::syscall(SYS_tgkill, tid, tid, signum);
            if (rc != 0) rc = ::kill(tid, signum);
        }
        // Translate through the ONE table (abi/wire/errno_map.hpp) rather than
        // casting: `Errno{errno}` asserts the host's errno numbering equals
        // the guest's. It happens to on Linux/x86-64, which is exactly why
        // the bug would survive here and surface on an ABI where it doesn't.
        if (rc == 0) return 0;
        return -static_cast<std::int64_t>(abi::wire::errno_from_host(errno));
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
        if (n >= 0 && std::size_t(n) == dst.size()) return ok();
        // process_vm_readv is denied (EPERM) for a task that dropped its
        // dumpable flag or changed credentials — e.g. gpg-agent/dirmngr call
        // prctl(PR_SET_DUMPABLE,0) and setuid for security, which makes their
        // memory unreadable via the /proc-mem path EVEN for the tracer. The
        // ptrace peek path goes through the ptrace access check (we ARE the
        // tracer) and still works, so fall back to it. Without this, reading a
        // bind()'s sockaddr fails, the AF_UNIX path can't be translated, and
        // the socket leaks onto the HOST filesystem.
        return peek_in(value(src), dst);
    }
    // Word-granular read via PTRACE_PEEKDATA. Ordered against the tracee and
    // permitted for any task we trace regardless of its dumpable/cred state.
    [[nodiscard]] Status peek_in(std::uint64_t at, std::span<std::byte> dst) const {
        std::size_t off = 0;
        while (off < dst.size()) {
            errno = 0;
            long word = ::ptrace(PTRACE_PEEKDATA, cur_,
                                 reinterpret_cast<void*>(at + off), nullptr);
            if (word == -1 && errno != 0) return err(Errno::efault);
            auto* wb = reinterpret_cast<const unsigned char*>(&word);
            for (std::size_t i = 0; i < sizeof(long) && off + i < dst.size(); ++i)
                dst[off + i] = static_cast<std::byte>(wb[i]);
            off += sizeof(long);
        }
        return ok();
    }
    [[nodiscard]] Status copy_out(UAddr dst, std::span<const std::byte> src) const {
        ::iovec local{const_cast<std::byte*>(src.data()), src.size()};
        ::iovec remote{reinterpret_cast<void*>(value(dst)), src.size()};
        auto n = ::process_vm_writev(cur_, &local, 1, &remote, 1, 0);
        if (n >= 0 && std::size_t(n) == src.size()) return ok();
        // Same rationale as copy_in: fall back to the ptrace poke path for a
        // task whose /proc-mem write access is denied. Word-granular, reading
        // each final partial word first to preserve bytes past src.
        std::size_t off = 0;
        const std::uint64_t at = value(dst);
        while (off < src.size()) {
            errno = 0;
            long word = ::ptrace(PTRACE_PEEKDATA, cur_,
                                 reinterpret_cast<void*>(at + off), nullptr);
            if (word == -1 && errno != 0) return err(Errno::efault);
            auto* wb = reinterpret_cast<unsigned char*>(&word);
            for (std::size_t i = 0; i < sizeof(long) && off + i < src.size(); ++i)
                wb[i] = static_cast<unsigned char>(src[off + i]);
            if (::ptrace(PTRACE_POKEDATA, cur_, reinterpret_cast<void*>(at + off),
                         reinterpret_cast<void*>(word)) != 0)
                return err(Errno::efault);
            off += sizeof(long);
        }
        return ok();
    }

    // Write a path string into the current task, preferring PTRACE_POKEDATA
    // (ordered against the tracee's own copy_from_user — see redirect()) and
    // falling back to process_vm_writev when the poke is refused. The poke can
    // fail with EIO on a task we can observe but not ptrace-poke (a daemonized
    // child whose stop we reached indirectly); the vm write uses a different
    // kernel access path and often still succeeds. Returns false only if BOTH
    // paths fail, which the caller degrades to a forward-unmodified.
    [[nodiscard]] bool poke_path(std::uint64_t at, const std::string& s,
                                 bool dead_scratch = false) const {
        if (dead_scratch ? poke_scratch(at, s) : poke_bytes(at, s)) return true;
        std::vector<std::byte> b(s.size() + 1);
        std::memcpy(b.data(), s.c_str(), s.size() + 1);
        return static_cast<bool>(copy_out(uaddr(at), std::span<const std::byte>{b}));
    }

    // Write a NUL-terminated string into DEAD stack scratch below rsp. Nothing
    // live sits in the tail of the last word there, so there is nothing to
    // preserve and no PEEK first: one POKE per word instead of PEEK+POKE.
    // Still PTRACE_POKEDATA, for the ordering reason in redirect().
    [[nodiscard]] bool poke_scratch(std::uint64_t at, const std::string& s) const {
        const std::size_t n = s.size() + 1;
        for (std::size_t off = 0; off < n; off += sizeof(long)) {
            long word = 0;
            std::memcpy(&word, s.c_str() + off, std::min(sizeof(long), n - off));
            if (::ptrace(PTRACE_POKEDATA, cur_, reinterpret_cast<void*>(at + off),
                         reinterpret_cast<void*>(word)) != 0)
                return false;
        }
        return true;
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
    // Bring the whole traced tree down after the root/session leader exited.
    // Any surviving task is a detached daemon (gpg-agent/dirmngr etc.) that the
    // guest orphaned, OR a foreground child (e.g. pacman mid-transaction) that
    // was still running when the session leader exited. We must take the whole
    // tree down, but NOT with an immediate SIGKILL: a package manager killed
    // uncatchably leaves a stale db.lck and a half-written local-DB entry
    // (dir + mtree but no desc), which then poisons every later transaction.
    // So we do what a real machine's shutdown does -- deliver a CATCHABLE
    // SIGTERM first (via PTRACE_CONT, since a ptrace-stopped task only receives
    // an injected signal on resume), give the tree a bounded grace window to
    // run its own cleanup handlers (pacman removes the lock and rolls back the
    // partial transaction), then ESCALATE to SIGKILL for anything that ignores
    // SIGTERM (detached gpg-agent/dirmngr). PTRACE_O_EXITKILL still backstops
    // us if we exit before the drain completes. Best-effort throughout: a task
    // may already be gone (ESRCH) between the snapshot and each step.
    void reap_tree() {
        std::vector<::pid_t> victims;
        victims.reserve(tasks_.size());
        for (const auto& [tid, _] : tasks_) victims.push_back(tid);

        // Phase 1: graceful. Resume each stopped task delivering SIGTERM, so
        // its handler runs (SIGCONT first in case it was group-stopped). This
        // lets pacman's signal handler unlink db.lck and undo the in-progress
        // transaction, exactly as on native Linux.
        std::unordered_set<::pid_t> alive;
        for (::pid_t tid : victims) {
            ::kill(tid, SIGCONT);
            // Inject SIGTERM through the ptrace resume so a stopped tracee
            // actually receives it; also kill(2) it in case it is running.
            if (::ptrace(PTRACE_CONT, tid, 0, SIGTERM) != 0)
                ::kill(tid, SIGTERM);
            alive.insert(tid);
        }

        // Phase 2: bounded drain. Reap any task that exits on its own within
        // the grace window. Poll waitpid(WNOHANG) across all victims for up to
        // ~2s (pacman's rollback is sub-second); resume any that re-stop under
        // ptrace so the pending SIGTERM keeps propagating. As soon as the tree
        // is empty we stop early.
        constexpr int kGraceMs = 2000;
        constexpr int kStepMs = 20;
        for (int waited = 0; waited < kGraceMs && !alive.empty(); waited += kStepMs) {
            bool progressed = false;
            for (auto it = alive.begin(); it != alive.end();) {
                ::pid_t tid = *it;
                int st = 0;
                ::pid_t r = ::waitpid(tid, &st, __WALL | WNOHANG);
                if (r == tid && (WIFEXITED(st) || WIFSIGNALED(st))) {
                    it = alive.erase(it); progressed = true; continue;
                }
                if (r == tid && WIFSTOPPED(st)) {
                    // Re-stopped (e.g. group-stop or trap): resume, keep the
                    // SIGTERM heading its way.
                    ::ptrace(PTRACE_CONT, tid, 0, SIGTERM);
                    progressed = true;
                }
                if (r < 0) { it = alive.erase(it); progressed = true; continue; }
                ++it;
            }
            if (!progressed)
                ::usleep(static_cast<useconds_t>(kStepMs) * 1000);
        }

        // Phase 3: escalate. Anything still alive ignored SIGTERM (detached
        // daemons); force it down and drain its exit so no zombie is left.
        for (::pid_t tid : alive) {
            ::ptrace(PTRACE_KILL, tid, 0, 0);
            ::kill(tid, SIGKILL);
            for (;;) {
                int st = 0;
                ::pid_t r = ::waitpid(tid, &st, __WALL);
                if (r <= 0) break;
                if (WIFEXITED(st) || WIFSIGNALED(st)) break;
                ::ptrace(PTRACE_CONT, tid, 0, SIGKILL);
            }
        }
        tasks_.clear();
        live_ = 0;
    }

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
            Regs r{};
            (void)Regs::fetch(w, r);
            r.set_ret(static_cast<std::int64_t>(t.ret));
            (void)r.store(w);
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
            Regs r{};
            (void)Regs::fetch(w, r);
            if (abi::decode(kTraceeArch, r.nr()) == abi::Sysno::waitid) {
                // waitid returns 0 in RAX (not a pid) and instead fills a
                // siginfo_t (guest ptr in rdx at entry, preserved at exit)
                // whose si_pid holds the reaped child — as a HOST tid. Rust's
                // std/nix reads si_pid and compares it to the guest pid it got
                // from fork; an untranslated host pid there makes fish's job
                // control panic ("Unexpected waitpid() return"). Rewrite
                // si_pid (offset 16 in the x86-64 siginfo_t) to the guest pid.
                auto ret = static_cast<long long>(r.ret());
                std::uint64_t infop = r.arg(2);
                if (ret == 0 && infop != 0) {
                    errno = 0;
                    long word = ::ptrace(PTRACE_PEEKDATA, w,
                                         reinterpret_cast<void*>(infop + 16), 0);
                    if (errno == 0) {
                        auto host = static_cast<std::int32_t>(
                            static_cast<std::uint32_t>(word & 0xffffffffu));
                        if (host > 0) {
                            std::int32_t g = gpid_of(host);
                            std::uint64_t uw = static_cast<std::uint64_t>(word);
                            uw = (uw & ~0xffffffffull) |
                                 static_cast<std::uint32_t>(g);
                            ::ptrace(PTRACE_POKEDATA, w,
                                     reinterpret_cast<void*>(infop + 16),
                                     reinterpret_cast<void*>(uw));
                        }
                    }
                }
            } else if (returns_pid(r.nr())) {
                auto host = static_cast<::pid_t>(static_cast<long long>(r.ret()));
                if (host > 0) {
                    r.set_ret(static_cast<std::int64_t>(gpid_of(host)));
                    (void)r.store(w);
                }
            }
        }
        t.action = Action::none;
        t.in_call = false;
    }

    // The forwarded syscalls whose successful return value IS a pid. We
    // translate these host pids to guest pids at their exit stop so the guest
    // never sees a host pid.
    //
    // Decoded through the generated Sysno table rather than matched against
    // literal numbers: the same syscall has different numbers per arch, so a
    // literal would silently name a DIFFERENT syscall elsewhere and translate
    // the return value of something that isn't a pid. sysno.hpp is the single
    // source of truth for this mapping, and kTraceeArch picks the column.
    static bool returns_pid(unsigned long long nr) {
        switch (abi::decode(kTraceeArch, nr)) {
            case abi::Sysno::clone:
            case abi::Sysno::fork:
            case abi::Sysno::vfork:
            case abi::Sysno::clone3:
            case abi::Sysno::wait4:
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
            if (sig != SIGTRAP && sig != (SIGTRAP | 0x80)) {
                rewrite_siginfo_pid(w);
                trace_fault(w, sig);
                held_sig = sig;
            }
            ::ptrace(PTRACE_SYSCALL, w, 0, 0);
        }
    }

    // A signal's siginfo carries si_pid: WHO sent it. The kernel fills that
    // with the sender's real host pid, so a guest handler using SA_SIGINFO saw
    // a six-digit pid that does not exist in its namespace -- LTP's kill10
    // printed "received unexpected signal 10 from 1690548" for every one of
    // its process-group signals, and any program that checks the sender (an
    // init, a supervisor, a test harness) gets a pid it cannot match.
    //
    // Same translation waitid already does for the reaped child, applied to
    // the delivery path. Only SI_USER/SI_QUEUE/SI_TKILL carry a meaningful
    // sender; kernel-generated codes (SI_TIMER, SIGSEGV's fault address) use
    // the union differently and must not be touched.
    void rewrite_siginfo_pid(::pid_t w) {
        siginfo_t si{};
        if (::ptrace(PTRACE_GETSIGINFO, w, 0, &si) != 0) return;
        // SI_USER=0, SI_QUEUE=-1, SI_TKILL=-6: the three the sender fills.
        if (si.si_code != SI_USER && si.si_code != SI_QUEUE &&
            si.si_code != -6)
            return;
        if (si.si_pid <= 0) return;

        // LOOK UP ONLY -- never allocate. gpid_of() mints a fresh guest pid
        // for an unknown tid, so calling it here invented pid 3 for a sender
        // whose real guest pid was 2. si_pid also holds a thread-group id
        // while our map is keyed by tid, so a direct hit can miss; fall back
        // to scanning for a task whose tgid matches.
        const std::int32_t g = known_gpid_of(si.si_pid);
        if (g <= 0 || g == si.si_pid) return;
        si.si_pid = g;
        ::ptrace(PTRACE_SETSIGINFO, w, 0, &si);
    }

    // The guest pid for a host id we have ALREADY seen, or 0. Pure lookup, so
    // it cannot perturb the pid allocator the way gpid_of does.
    [[nodiscard]] std::int32_t known_gpid_of(::pid_t host) const {
        if (host == root_pid_) return 1;
        if (auto it = gpid_.find(host); it != gpid_.end()) return it->second;
        // si_pid carries the sender's THREAD-GROUP id; our map is keyed by
        // the tid we attached to. For a single-threaded task those are equal,
        // but check the task table too rather than guessing.
        for (const auto& [tid, gp] : gpid_)
            if (tgid_of(tid) == host) return gp;
        return 0;
    }

    // A host task's thread-group id, from /proc. Returns 0 when unknown.
    [[nodiscard]] static ::pid_t tgid_of(::pid_t tid) {
        char path[64];
        std::snprintf(path, sizeof path, "/proc/%d/status", static_cast<int>(tid));
        std::FILE* f = std::fopen(path, "r");
        if (f == nullptr) return 0;
        char line[256];
        ::pid_t out = 0;
        while (std::fgets(line, sizeof line, f) != nullptr) {
            if (std::strncmp(line, "Tgid:", 5) == 0) {
                out = static_cast<::pid_t>(std::atoi(line + 5));
                break;
            }
        }
        std::fclose(f);
        return out;
    }

    std::string path_;
    std::vector<std::string> argv_;
    std::vector<std::string> envp_;
    std::string root_;
    std::function<void()> pre_exec_;   // child hook (post-fork, pre-execve)
    std::vector<ProcEvent> proc_events_;
    std::unordered_map<::pid_t, std::int32_t> gpid_;   // host tid -> guest pid
    std::unordered_map<std::int32_t, std::int32_t> gppid_; // guest pid -> ppid
    // host tid -> host tgid. A task's tgid is fixed for its lifetime, and
    // tgid_of() reads /proc, so this is looked up once per task rather than
    // once per syscall.
    std::unordered_map<::pid_t, ::pid_t> tgid_cache_;
    std::int32_t next_gpid_{2};                        // pid 1 = root/init
    ::pid_t cur_{-1};
    ::pid_t root_pid_{-1};
    bool booted_root_{false};      // root's bootstrap execve(path_) has completed
    int exit_code_{0};
    int live_{0};
    bool exited_{false};
    bool seccomp_{false};          // trap filter active -> drive with PTRACE_CONT
    std::unordered_map<::pid_t, Task> tasks_;
};

// The Linux backend is the reference implementation: it has every capability,
// so assert the whole contract. If a method here is renamed or its signature
// drifts, THIS is the build error -- rather than the run loop quietly taking a
// fallback path and forwarding an untranslated path to the host.
static_assert(SyscallTrap<PtraceTrap>, "PtraceTrap must model SyscallTrap");
static_assert(CompleteTrap<PtraceTrap>,
              "PtraceTrap is the reference backend: it must have every "
              "capability (two-path redirect, forward_sync, sockets, "
              "exec-through-interp, signals)");
static_assert(ReportsProcEvents<PtraceTrap>,
              "PtraceTrap tracks the guest process tree, so it must report "
              "clone/exec/exit events");

} // namespace lx::runtime
