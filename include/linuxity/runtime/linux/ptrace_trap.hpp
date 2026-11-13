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
#include "linuxity/runtime/linux/inguest.hpp"

#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cerrno>

#include <optional>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <fcntl.h>
#include <set>
#include "linuxity/host/real_netns.hpp"
#include "linuxity/host/stat_fields.hpp"

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
        // the registers as the GUEST issued the call, before the entry
        // translation rewrote its pids; a retried call starts from these
        Regs guest_regs{};
        // run at the exit stop of a redirect that didn't wait for it
        std::function<void(std::int64_t)> on_exit{};
        // the call is being forwarded as the guest issued it (so the normal
        // exit translations apply even with an on_exit hook)
        bool forwarded{false};
        // this call was refused by a host seccomp filter and is being
        // answered by the dispatcher (see next())
        bool refused{false};
    };

    [[nodiscard]] Status start(UAddr, UAddr) {
        // No program: an instance. Sessions arrive later through spawn().
        if (path_.empty()) { instance_ = true; return ok(); }
        const ::pid_t pid = launch(path_, argv_, envp_, pre_exec_, {});
        if (pid < 0) return err(Errno::eagain);
        root_pid_ = pid;
        tasks_[pid];                       // create, at-entry state
        resume_run(pid, 0);
        ++live_;
        return ok();
    }

    // Instance mode: start a new session leader inside the running tree, a
    // child of guest init. `setup` runs in the child before anything else
    // (setsid, its fds); `pre` is the resource hook. Returns {host pid,
    // guest pid}, or {-1, 0} if the fork failed.
    std::pair<::pid_t, std::int32_t> spawn(const std::string& path,
                                           const std::vector<std::string>& argv,
                                           const std::vector<std::string>& envp,
                                           const std::function<void()>& pre,
                                           const std::function<void()>& setup) {
        const ::pid_t pid = launch(path, argv, envp, pre, setup);
        if (pid < 0) return {-1, 0};
        tasks_[pid];
        ++live_;
        bootstrapping_.insert(pid);
        tgid_cache_[pid] = pid;
        const std::int32_t g = gpid_of(pid);
        gppid_[g] = init_gpid();
        resume_run(pid, 0);
        return {pid, g};
    }

    // Fork a traced child that will execve(path), a HOST path. It comes back
    // stopped and armed; the caller registers and resumes it. -1 on failure.
    ::pid_t launch(const std::string& path, const std::vector<std::string>& argv,
                   const std::vector<std::string>& envp,
                   const std::function<void()>& pre,
                   const std::function<void()>& setup) {
        // the in-guest handler's key must be in the filter the child installs
        if (inguest::wanted()) inguest::arm();
        // A tiny pipe lets the child report whether the seccomp trap filter
        // installed, so the parent knows to drive tasks with PTRACE_CONT (only
        // filtered syscalls stop) versus PTRACE_SYSCALL (every syscall stops).
        int seccomp_pipe[2] = {-1, -1};
        (void)::pipe2(seccomp_pipe, O_CLOEXEC);
        ::pid_t pid = ::fork();
        if (pid < 0) {
            if (seccomp_pipe[0] >= 0) { ::close(seccomp_pipe[0]); ::close(seccomp_pipe[1]); }
            return -1;
        }
        if (pid == 0) {
            if (seccomp_pipe[0] >= 0) ::close(seccomp_pipe[0]);
            // A fresh process starts with NOTHING blocked. The mask is
            // inherited across fork and survives execve, so whatever the
            // launching shell had set would otherwise become the guest's --
            // and Android's adb shell blocks signal 32 (SigBlk 0x80000000).
            // glibc reserves 32 as SIGCANCEL, so python then rejected its
            // own mask ("invalid signal number 32") the moment
            // multiprocessing called pthread_sigmask. No real Linux hands a
            // new process that mask.
            //
            // The RAW syscall, not sigprocmask(3): libc's wrapper only
            // covers signals 1-31, and 32 is above that -- it would have
            // left the one bit that matters untouched.
            {
                std::uint64_t none = 0;
                (void)::syscall(SYS_rt_sigprocmask, SIG_SETMASK, &none,
                                nullptr, sizeof none);
            }
            if (!root_.empty()) {
                if (::chroot(root_.c_str()) == 0) (void)::chdir("/");
            }
            // The session and its fds first, so the resource hook below sees
            // 0/1/2 already in place when it fills the low slots.
            if (setup) setup();
            // Bound this task (and, by inheritance, every descendant) BEFORE
            // it starts running: the child writes its own pid into the
            // resource cgroup and installs rlimit fallbacks. Runs pre-TRACEME
            // so enforcement is in effect the instant the guest's _start runs.
            if (pre) pre();
            // Our own ids, read BEFORE the filter goes up: getpid and gettid
            // are both trapped, so calling them after the filter is installed
            // but before the tracer is armed would ENOSYS-fail.
            const int pre_pid = static_cast<int>(::syscall(SYS_getpid));
            const int pre_tid = static_cast<int>(::syscall(SYS_gettid));
            // TRACEME before the filter: ptrace itself is trapped (guests
            // tracing guests), so after it TRACEME would ENOSYS-fail
            ::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            // Install the seccomp trap filter so ONLY the syscalls linuxity
            // intercepts stop into the tracer; everything else runs natively.
            // Report the outcome to the parent, then let the filter be
            // inherited across the coming execve and every future fork. If
            // seccomp is unavailable the parent falls back to PTRACE_SYSCALL,
            // which is always correct (just slower). LINUXITY_TEST_NO_SECCOMP=1
            // forces that fallback (tests only).
            char ok_byte = (!std::getenv("LINUXITY_TEST_NO_SECCOMP") &&
                            install_trap_filter()) ? 1 : 0;
            if (seccomp_pipe[1] >= 0) {
                (void)!::write(seccomp_pipe[1], &ok_byte, 1);
                ::close(seccomp_pipe[1]);
            }
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
            for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
            cargv.push_back(nullptr);
            std::vector<char*> cenvp;
            for (const auto& e : envp) cenvp.push_back(const_cast<char*>(e.c_str()));
            cenvp.push_back(nullptr);
            ::execve(path.c_str(), cargv.data(), cenvp.data());
            ::_exit(127);
        }
        int st = 0;
        ::waitpid(pid, &st, 0);
        // A host seccomp policy (Android's app filter) can refuse a call the
        // child makes before its self-stop. Say which, instead of a bare
        // "killed by SIGSYS" later.
        if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGSYS) {
            siginfo_t si{};
            if (::ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0)
                std::fprintf(stderr, "linuxity: the host refused syscall %d while starting a task\n",
                             si.si_syscall);
        } else if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) {
            std::fprintf(stderr, "linuxity: the host killed a starting task with SIGSYS (seccomp)\n");
        }
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
        base_opts_ = opts;
        ::ptrace(PTRACE_SETOPTIONS, pid, 0, opts);
        return pid;
    }

    // Block until some task reaches a syscall-ENTRY stop, and fill `f` with
    // its registers. EXIT stops are finalized here (applying the action the
    // dispatcher chose at entry) and the task is continued. Returns false once
    // the whole tree has exited.
    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        for (;;) {
            // a syscall entry the guest tracer just let go (no seccomp: every
            // entry stop is ours to dispatch, after the tracer saw it)
            while (!redispatch_.empty()) {
                const ::pid_t w = redispatch_.front();
                redispatch_.pop_front();
                if (!tasks_.count(w)) continue;
                Regs rr{};
                if (!Regs::fetch(w, rr)) continue;
                Task& t = tasks_[w];
                cur_ = w;
                t.regs = rr;
                t.guest_regs = rr;
                t.in_call = true;
                translate_entry_args(w, rr, t);
                fill_frame(f, rr);
                return ok(true);
            }
            int st = 0;
            ::pid_t w;
            if (draining_) {
                // After pid 1 exits: keep serving the survivors, but never
                // block past the grace deadline -- a daemon that ignores
                // SIGTERM and sleeps in the kernel would otherwise hold the
                // runtime open forever. Wait on the actual event (SIGCHLD,
                // blocked in begin_drain so it pends instead of being lost
                // between the waitpid and the wait) rather than polling.
                w = ::waitpid(-1, &st, __WALL | WNOHANG);
                if (w == 0) {
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= drain_deadline_) {
                        kill_remaining();
                        exited_ = true;
                        return ok(false);
                    }
                    const auto ns = std::chrono::duration_cast<
                        std::chrono::nanoseconds>(drain_deadline_ - now).count();
                    ::timespec ts{static_cast<::time_t>(ns / 1000000000),
                                  static_cast<long>(ns % 1000000000)};
                    ::sigset_t chld;
                    ::sigemptyset(&chld);
                    ::sigaddset(&chld, SIGCHLD);
                    (void)::sigtimedwait(&chld, nullptr, &ts);
                    continue;
                }
            } else if (instance_) {
                // An instance never runs out of work: with nothing to reap it
                // waits on SIGCHLD and the supervisor's own fds together.
                // Drain first, then reap: a SIGCHLD after the drain is either
                // seen by this waitpid or leaves the fd readable for poll.
                (void)chld_fd();
                drain_chld_fd();
                w = ::waitpid(-1, &st, __WALL | WNOHANG);
                if (w == 0 || (w < 0 && errno == ECHILD)) {
                    if (flush_events_ && !proc_events_.empty()) flush_events_();
                    if (stop_requested_ || !idle_ || !idle_(chld_fd(), true)) {
                        kill_remaining();
                        exited_ = true;
                        return ok(false);
                    }
                    last_poll_ = std::chrono::steady_clock::now();
                    continue;
                }
                if (w < 0) continue;   // EINTR
                // a busy guest must not starve the control socket
                if (const auto now = std::chrono::steady_clock::now();
                    now - last_poll_ > std::chrono::milliseconds(10)) {
                    last_poll_ = now;
                    if (idle_ && !idle_(chld_fd(), false)) stop_requested_ = true;
                }
                // a host helper the supervisor ran itself (not a tracee)
                if (!tasks_.count(w) && (WIFEXITED(st) || WIFSIGNALED(st)) &&
                    !gpid_.count(w)) {
                    if (on_exit_) on_exit_(w, 0, WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
                    continue;
                }
            } else {
                w = ::waitpid(-1, &st, __WALL);
            }
            if (w < 0) return ok(false);

            if (WIFEXITED(st) || WIFSIGNALED(st)) {
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                if (WIFSIGNALED(st)) trace_killed(w, WTERMSIG(st));
                if (w == root_pid_) exit_code_ = code;
                if (!strict_tgids_.empty()) strict_tgids_.erase(w);
                gt_on_exit(w, st);
                const std::int32_t exited_g = exited_gpid(w);
                // A child can exit before its parent's fork event is seen.
                // Remember it, so that event doesn't bring it back to life.
                if (w != root_pid_ && !announced_.erase(w)) {
                    if (exited_early_.size() > 4096) exited_early_.clear();
                    exited_early_.insert(w);
                }
                if (const std::int32_t g = exited_g) {
                    // A process stays a zombie until its parent waits for it;
                    // a thread just goes.
                    const auto tc = tgid_cache_.find(w);
                    const bool leader = tc == tgid_cache_.end() || tc->second == w;
                    if (leader && w != root_pid_) {
                        proc_events_.push_back({ProcEvent::zombie, g, 0, {}, {}});
                        zombies_[g] = w;
                    } else {
                        proc_events_.push_back({ProcEvent::reap, g, 0, {}, {}});
                    }
                    reparent_orphans_of(g);
                }
                // NB: do NOT erase gpid_[w] here. The parent's wait4() has not
                // run its exit stop yet; when it does, finalize_exit translates
                // the reaped HOST pid to its GUEST pid via this very map. If we
                // dropped the entry now, gpid_of() would mint a FRESH number
                // and $!/`wait N` would never match the pid the parent saw at
                // fork. A dead child's identity must outlive it until reaped;
                // guest pids are tiny ints, so retaining them is cheap.
                tasks_.erase(w);
                stopped_.erase(w);
                stop_owed_.erase(w);
                // a thread group's leader gone: its region (and pid) go too
                if (tgid_cache_.count(w) && tgid_cache_[w] == w) ig_reaped(w);
                // the host may hand this tid to an unrelated new process
                tgid_cache_.erase(w);
                bootstrapping_.erase(w);
                --live_;
                if (on_exit_) on_exit_(w, exited_g, code);
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
                // is to shut the session down -- but through begin_drain(),
                // which keeps translating the survivors' syscalls until they
                // exit or the grace deadline passes. Releasing them
                // untraced was a sandbox escape.
                if (w == root_pid_) begin_drain();
                if (live_ <= 0 && !instance_) { exited_ = true; return ok(false); }
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
                // Already exited: its reap event went out, so announcing it now
                // would leave a dead row in ps and /proc. The pid can't have
                // been reused: its parent is stopped right here, unable to reap.
                const bool gone = np && exited_early_.erase(child);
                if (np && !gone) {
                    announced_.insert(child);
                    if (tasks_.emplace(child, Task{}).second) ++live_;   // may already be counted if it stopped first
                }
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
                // A CLONE event is a thread only if the child shares the
                // creator's thread group; clone3() for a plain fork (what
                // glibc's posix_spawn and subprocess use) reports CLONE too.
                const bool is_thread = np && event == PTRACE_EVENT_CLONE &&
                                       !gone && tgid_of(child) == host_tgid_of(w);
                if (gone) {
                } else if (np && !is_thread) {
                    std::int32_t gpid = gpid_of(child);
                    std::int32_t gppid = gpid_of(host_tgid_of(w));   // a thread's child belongs to its process
                    gppid_[gpid] = gppid;
                    tgid_cache_[child] = child;
                    std::uint64_t nsf = 0;
                    if (auto it = pending_clone_ns_.find(w); it != pending_clone_ns_.end()) {
                        nsf = it->second;
                        pending_clone_ns_.erase(it);
                    }
                    // its user namespace needs maps before it runs a step
                    if (pending_real_netns_.erase(w))
                        (void)host::write_identity_maps(static_cast<int>(child));
                    proc_events_.push_back({ProcEvent::spawn, gpid, gppid, {}, {}, nsf});
                    ig_inherit(host_tgid_of(w), child);
                } else if (np) {
                    note_thread(w, child);
                }
                // If we're mid-servicing this task's clone/fork (in_call), it
                // still owes us its EXIT stop so finalize_exit can translate
                // the returned host pid to a guest pid. Step to that exit with
                // PTRACE_SYSCALL rather than letting CONT run past it — else $!
                // and jobs would show a host pid. Otherwise run free.
                gt_on_fork_event(w, event, child);
                if (auto gt = gtr_.find(w); gt != gtr_.end() && !gt->second.q.empty()) {
                    gt_park(w);   // the tracer sees the event first
                    continue;
                }
                resume_after_event(w);
                continue;
            }
            if (event == PTRACE_EVENT_EXIT) {
                // a traced task about to exit: its tracer sees it first
                if (gt_on_exit_event(w)) continue;
                resume_run(w, 0);
                continue;
            }
            if (event == PTRACE_EVENT_EXEC) {
                // The image was replaced: the pid keeps its number but becomes
                // a new program. The ROOT's FIRST exec is the bootstrap of
                // path_ (a host path) -- mark it done so later guest execs are
                // dispatched through path_exec.
                if (w == root_pid_) booted_root_ = true;
                bootstrapping_.erase(w);
                proc_events_.push_back({ProcEvent::exec, gpid_of(w), 0,
                                        comm_of(w), cmdline_of(w)});
                tasks_[w] = Task{};        // fresh image, back at-entry
                ig_forget(host_tgid_of(w));
                gt_on_exec(w);
                resume_run(w, 0);
                continue;
            }
            // A seccomp-filter trap: the guest hit one of the syscalls we
            // intercept. This IS the syscall-ENTRY stop under the filter;
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
                if (booting(w) &&
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
                t.guest_regs = rr;
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
            if (sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTOU) {
                siginfo_t si{};
                const bool have_si = ::ptrace(PTRACE_GETSIGINFO, w, 0, &si) == 0;
                // GETSIGINFO fails with EINVAL only at a group-stop: the
                // signal was delivered and the task is now job-stopped.
                // Leave it stopped until a SIGCONT; resuming here undid
                // every kill -STOP and ^Z.
                if (!have_si && errno == EINVAL && tasks_.count(w)) {
                    if (stopped_.insert(w).second)
                        proc_events_.push_back({ProcEvent::stop, gpid_of(host_tgid_of(w)), 0, {}, {}});
                    continue;
                }
                // A fresh tracee's attach stop: a SIGSTOP the kernel added
                // with no siginfo (SI_USER from pid 0). A real one has a
                // sender and has to be delivered.
                const bool attach = sig == SIGSTOP && (!have_si ||
                    (si.si_code == SI_USER && si.si_pid == 0));
                if (attach) {
                    if (tasks_.try_emplace(w).second) ++live_;
                    if (gt_on_new_task(w)) continue;
                    // A guest SIGSTOP sent before the attach stop was taken
                    // merged into it (one pending SIGSTOP max). Deliver it.
                    resume_run(w, stop_owed_.erase(w) ? SIGSTOP : 0);
                    continue;
                }
                if (sig == SIGSTOP) stop_owed_.erase(w);
                if (gt_on_signal_stop(w, sig)) continue;
            }
            if (sig == SIGTRAP) {
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
                     si.si_code == TRAP_HWBKPT || si.si_code == SI_KERNEL);
                if (!real_trap) {
                    if (tasks_.try_emplace(w).second) ++live_;
                    if (gt_on_new_task(w)) continue;
                    resume_run(w, 0);
                    continue;
                }
                trace_fault(w, sig);
                if (gt_on_signal_stop(w, sig)) continue;   // a breakpoint or a step
                resume_run(w, sig);
                continue;
            }
            // A real syscall stop (TRACESYSGOOD => SIGTRAP|0x80). Under the
            // seccomp filter this is ONLY an EXIT stop (from the one-shot
            // PTRACE_SYSCALL a serviced entry issued); entries arrive as
            // PTRACE_EVENT_SECCOMP above. Without seccomp it is BOTH the entry
            // and the exit, distinguished by the -ENOSYS-primed RAX.
            if (sig == (SIGTRAP | 0x80)) {
                Task& t = tasks_[w];
                // a stop the guest tracer asked for (PTRACE_SYSCALL)
                if (gt_on_sys_stop(w, t)) continue;
                Regs rr{};
                (void)Regs::fetch(w, rr);
                // Entry or exit? The kernel says, since 5.3. The old test
                // (rax primed to -ENOSYS at entry) is x86-64 only: aarch64's
                // x0 is the first argument at entry, so on the phone every
                // entry read as an exit and nothing was ever dispatched.
                const int op = syscall_stop_op(w);
                // a strict-seccomp task (see set_strict) stops on every call
                if (seccomp_ && op == 1 && is_strict(w)) {
                    const abi::Sysno s = abi::decode(kTraceeArch, rr.nr());
                    using S = abi::Sysno;
                    if (s != S::read && s != S::write && s != S::exit &&
                        s != S::rt_sigreturn) {
                        ::kill(host_tgid_of(w), SIGKILL);
                        ::ptrace(PTRACE_CONT, w, 0, 0);
                        continue;
                    }
                    ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                    continue;
                }
                if (seccomp_ && op == 2 && is_strict(w)) { ::ptrace(PTRACE_SYSCALL, w, 0, 0); continue; }
                bool is_entry = !seccomp_ &&
                    (op > 0 ? op == 1 /*ENTRY*/
                            : static_cast<long long>(rr.ret()) == -38 /*ENOSYS*/ && !t.in_call);
                if (is_entry) {
                    // Same bootstrap exemption as the seccomp path, for the
                    // PTRACE_SYSCALL fallback (LINUXITY_TEST_NO_SECCOMP): the ROOT's
                    // first execve targets path_ (a resolved HOST path), which
                    // path_exec would mis-resolve as a guest path. Forward it
                    // natively; its PTRACE_EVENT_EXEC sets booted_root_ and
                    // every later guest exec is dispatched normally.
                    std::uint64_t sysno = rr.nr();
                    const abi::Sysno bsc = abi::decode(kTraceeArch, sysno);
                    if (booting(w) &&
                        (bsc == abi::Sysno::execve ||
                         bsc == abi::Sysno::execveat)) {
                        t.in_call = true;
                        ::ptrace(PTRACE_SYSCALL, w, 0, 0);   // run exec to exit
                        continue;
                    }
                    cur_ = w;
                    t.regs = rr;
                    t.guest_regs = rr;
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
            if (gt_on_signal_stop(w, sig)) continue;   // its tracer decides
            if (sig == SIGCHLD) {
                siginfo_t csi{};
                if (::ptrace(PTRACE_GETSIGINFO, w, 0, &csi) == 0) {
                    if (gt_fix_chld(w, csi)) {
                        ::ptrace(PTRACE_SETSIGINFO, w, 0, &csi);
                        resume_run(w, sig);
                        continue;
                    }
                    // the kernel's own SIGCHLD (exited, killed, stopped...)
                    // names the child by its host pid
                    if (csi.si_code >= CLD_EXITED && csi.si_code <= CLD_CONTINUED && csi.si_pid > 0) {
                        const std::int32_t g = chld_gpid(w, csi.si_pid);
                        if (g > 0 && g != csi.si_pid) {
                            csi.si_pid = g;
                            ::ptrace(PTRACE_SETSIGINFO, w, 0, &csi);
                        }
                        resume_run(w, sig);
                        continue;
                    }
                }
            }
            if (sig == SIGSYS) {
                siginfo_t si{};
                if (::ptrace(PTRACE_GETSIGINFO, w, 0, &si) == 0 && si.si_code == 1 /*SYS_SECCOMP*/) {
                    // A refused call with an allowed equivalent runs again as
                    // that: Android's app filter has accept4 but not accept,
                    // which glibc's accept() uses (gpg-agent spun on ENOSYS).
                    if (rerun_as_allowed(w, si.si_syscall)) continue;
                    // A filter the HOST installed refused this call (Android's
                    // app policy: setfsuid, set_robust_list, rseq, ...). Its
                    // SIGSYS outranks our trace rule, so the dispatcher never
                    // saw it. Hand it over now; the kernel already skipped
                    // the call, so resume() only has to write the answer.
                    Regs rr{};
                    if (Regs::fetch(w, rr)) {
                        if (refused_.insert(si.si_syscall).second)
                            std::fprintf(stderr, "linuxity: the host refuses syscall %d; linuxity answers it\n",
                                         si.si_syscall);
                        Task& t = tasks_[w];
                        cur_ = w;
                        t.regs = rr;
                        t.guest_regs = rr;
                        t.in_call = true;
                        t.refused = true;
                        translate_entry_args(w, rr, t);
                        fill_frame(f, rr);
                        f.regs.nr = static_cast<std::uint64_t>(si.si_syscall);
                        return ok(true);
                    }
                }
            }
            rewrite_siginfo_pid(w);
            // a fault in the in-guest handler's guarded copy: make the call fall back
            if ((sig == SIGSEGV || sig == SIGBUS) && ig_fixup_fault(w)) { resume_run(w, 0); continue; }
            trace_fault(w, sig);
            resume_run(w, sig);
        }
    }

    // PTRACE_GET_SYSCALL_INFO's op for a syscall stop: 1 entry, 2 exit,
    // 3 seccomp; 0 when the kernel predates it (< 5.3).
    [[nodiscard]] static int syscall_stop_op(::pid_t w) {
        struct { std::uint8_t op; std::uint8_t pad[7]; std::uint64_t rest[10]; } info{};
        constexpr long kGetSyscallInfo = 0x420e;
#if defined(__GLIBC__)
        const auto req = static_cast<__ptrace_request>(kGetSyscallInfo);
#else
        const auto req = static_cast<int>(kGetSyscallInfo);
#endif
        const long n = ::ptrace(req, w, reinterpret_cast<void*>(sizeof info), &info);
        return n > 0 ? info.op : 0;
    }

    // Syscalls a host seccomp policy refused, reported once each.
    std::set<int> refused_;

    // The kernel skipped the call and left pc just past the syscall
    // instruction with the original arguments, so rewrite the number and
    // step back: the guest reissues it as the allowed form.
    bool rerun_as_allowed(::pid_t w, int nr) {
        const abi::Sysno sc = abi::decode(kTraceeArch, static_cast<std::uint64_t>(nr));
        Regs rr{};
        if (sc != abi::Sysno::accept || !Regs::fetch(w, rr)) return false;
        rr.set_nr(encode(kTraceeArch, abi::Sysno::accept4));
        rr.set_arg(3, 0);   // accept4 flags: none, i.e. plain accept
        rr.rewind_to_syscall();
        if (!rr.store(w)) return false;
        resume_run(w, 0);
        return true;
    }

    // A guest died on a signal. Under LINUXITY_TRACE say so, because the
    // trace otherwise just stops mid-stream and a fatal SIGILL/SIGSEGV looks
    // identical to a clean exit.
    void trace_killed(::pid_t w, int sig) const {
        const char* path = std::getenv("LINUXITY_TRACE");
        if (!path || !*path) return;
        std::FILE* out = std::fopen(path, "ae");
        if (!out) return;
        std::fprintf(out, "[lx] KILLED host_tid=%d sig=%d\n", static_cast<int>(w), sig);
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
                     sig, si.si_code, static_cast<unsigned long long>(pc), si.si_addr,
                     where.c_str());
        std::fclose(out);
    }

    static std::string hex_of(std::uint64_t v) {
        char b[32];
        std::snprintf(b, sizeof b, "%#llx", static_cast<unsigned long long>(v));
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
        // CLONE_NEW*: linuxity keeps the guest's namespaces itself, so the
        // host never sees them (Android refuses them). The flags are noted
        // for the child; the clone itself is an ordinary one. Except a
        // network namespace, which only the host can make real: that one
        // goes through, with a user namespace to allow it.
        if (sc == abi::Sysno::clone || sc == abi::Sysno::clone3) {
            constexpr std::uint64_t kNew = 0x7e020080;
            std::uint64_t flags = 0;
            if (sc == abi::Sysno::clone) flags = rr.arg(0);
            else {
                errno = 0;
                const long f = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(rr.arg(0)), 0);
                if (errno) return;
                flags = static_cast<std::uint64_t>(f);
            }
            if (!(flags & kNew)) return;
            pending_clone_ns_[w] = flags & kNew;
            std::uint64_t keep = 0;
            if ((flags & host::kCloneNewnet) && host::host_can_netns()) {
                keep = host::real_netns_flags();
                pending_real_netns_.insert(w);
            }
            const std::uint64_t out = (flags & ~kNew) | keep;
            if (sc == abi::Sysno::clone) {
                Regs wr = rr;
                wr.set_arg(0, out);
                (void)wr.store(w);
                t.regs = wr;
                rr = wr;
            } else {
                ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(rr.arg(0)),
                         reinterpret_cast<void*>(out));
            }
            return;
        }
        if (sc == abi::Sysno::pidfd_open) {
            // A guest pid; one outside the tree must be ESRCH, not some
            // unrelated host process. No host pid is ever INT_MAX.
            auto gpid = static_cast<std::int32_t>(static_cast<long long>(rr.arg(0)));
            if (gpid > 0) {
                const ::pid_t host = host_tid_of(gpid);
                Regs wr = rr;
                wr.set_arg(0, static_cast<std::uint64_t>(host > 0 ? host : 0x7fffffff));
                (void)wr.store(w);
                t.regs = wr;
                rr = wr;
            }
            return;
        }
        // sendmsg with SCM_CREDENTIALS names the sender in guest terms; the
        // host kernel checks it against host ids, so restate it in those.
        if (sc == abi::Sysno::sendmsg) {
            rewrite_scm_creds(w, rr.arg(1), t);
            return;
        }
        // Calls whose pid (0 = self) names a task: map a guest pid to its host
        // task, so sched_setaffinity(pid) pins OUR child, not a host stranger.
        if (const int at = pid_arg_of(sc); at >= 0) {
            auto gpid = static_cast<std::int32_t>(static_cast<long long>(rr.arg(at)));
            // ioprio's `who` is only a pid for IOPRIO_WHO_PROCESS (1)
            const bool is_pid = (sc != abi::Sysno::ioprio_get && sc != abi::Sysno::ioprio_set) ||
                                rr.arg(0) == 1;
            if (gpid > 0 && is_pid) {
                const ::pid_t host = host_tid_of(gpid);
                Regs wr = rr;
                wr.set_arg(at, static_cast<std::uint64_t>(host > 0 ? host : 0x7fffffff));
                if (sc == abi::Sysno::kcmp) {
                    const auto g2 = static_cast<std::int32_t>(static_cast<long long>(rr.arg(1)));
                    const ::pid_t h2 = g2 > 0 ? host_tid_of(g2) : -1;
                    if (g2 > 0) wr.set_arg(1, static_cast<std::uint64_t>(h2 > 0 ? h2 : 0x7fffffff));
                }
                // the siginfo the guest built names the sender by guest ids
                if (sc == abi::Sysno::rt_sigqueueinfo) fix_queued_siginfo(w, rr.arg(2), t);
                (void)wr.store(w);
                t.regs = wr;
                rr = wr;
            }
            return;
        }
        if (sc == abi::Sysno::wait4) {
            auto gpid = static_cast<std::int32_t>(static_cast<long long>(rr.arg(0)));
            // the pid as the caller's pid namespace numbers it, like every
            // other pid argument; fork already returned it that way, so
            // waiting by it inside `unshare -p` named another process
            const std::int32_t viewer = known_gpid_of(host_tgid_of(w));
            if (gpid > 0) gpid = global_pid(viewer, gpid);
            else if (gpid < -1) gpid = -global_pid(viewer, -gpid);
            if (gpid > 0) {
                ::pid_t host = host_tid_of(gpid);
                if (host > 0) {
                    Regs wr = rr;
                    wr.set_arg(0, static_cast<std::uint64_t>(host));
                    (void)wr.store(w);
                    t.regs = wr;
                    rr = wr;
                }
            } else if (gpid < -1) {
                // wait4(-pgid): any member of that group. When setpgid was
                // mirrored onto the host, the group's host id is its
                // leader's host pid and this is a real group wait. Where the
                // host refused the mirror, waiting on the leader is the best
                // a shell gets (fish's `help` pager hung on ECHILD before).
                const ::pid_t host = host_tid_of(-gpid);
                if (host > 0) {
                    const bool real = host_groups_.count(-gpid) != 0;
                    Regs wr = rr;
                    wr.set_arg(0, real ? static_cast<std::uint64_t>(-static_cast<std::int64_t>(host))
                                       : static_cast<std::uint64_t>(host));
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
            if (idtype == 1 /*P_PID*/ && gid > 0) gid = global_pid(known_gpid_of(host_tgid_of(w)), gid);
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
        // a guest-traced task with a stop queued waits for its tracer
        if (auto it = gtr_.find(w); it != gtr_.end()) {
            if (!it->second.q.empty()) { if (sig) it->second.carry_sig = sig; gt_park(w); return; }
            gt_plain_resume(w, sig);
            return;
        }
        ::ptrace(seccomp_ && !strict_tgids_.count(host_tgid_of(w)) ? PTRACE_CONT : PTRACE_SYSCALL, w, 0, sig);
    }
    // SECCOMP_MODE_STRICT can't stack on our filter in the kernel, so we
    // enforce it: the task stops on every call and anything not allowed dies.
    [[nodiscard]] bool is_strict(::pid_t w) { return !strict_tgids_.empty() && strict_tgids_.count(host_tgid_of(w)); }
    std::unordered_set<::pid_t> strict_tgids_;

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
        if (t.refused) {
            // the host refused it: nothing ran, nothing to skip, no exit stop
            Regs r = t.regs;
            r.set_ret(ret);
            if (!r.store(cur_)) return err(Errno::eio);
            t.refused = false;
            t.in_call = false;
            t.action = Action::none;
            resume_run(cur_, 0);
            return ok();
        }
        Regs r = t.regs;
        r.skip_call();
        if (seccomp_) {
            // One stop, not two. At a PTRACE_EVENT_SECCOMP stop,
            // orig_rax = -1 skips the call and the kernel returns whatever we
            // leave in rax (seccomp(2), SECCOMP_RET_TRACE). The old path
            // stepped to the syscall EXIT just to write rax there: 7 ptrace
            // calls and 2 waits per answered syscall, measured. Now 3 and 1.
            r.set_ret(static_cast<std::int64_t>(ret));
            if (!store_and_skip(r)) return err(Errno::eio);
            t.action = Action::none;
            sys_done(cur_, /*kernel_owes_exit=*/true);
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

    // Write the answer back and neutralize the call.
    //
    // Writing the general registers is only HALF of neutralizing a syscall.
    // On aarch64 the kernel latches the syscall number before the tracer
    // stop, so x8 is advisory by then and the original call still runs --
    // NT_ARM_SYSTEM_CALL is the register set that actually selects it. Both
    // steps, in order, in one place, because doing the store without the
    // commit silently runs the syscall we meant to answer ourselves (seen as
    // a virtualized uname returning EFAULT: the handler's reply was
    // overwritten by the real one).
    //
    // Returns false only on a REAL failure: a tracee that has already died is
    // not one. A guest that signals itself fatally -- kill(getpid(), SIGKILL),
    // which is what a crashing child or an OOM kill looks like -- is gone by
    // the time we resume it, so ptrace answers ESRCH. Treating that as a
    // failure aborted the whole runtime with "runtime error 5": one guest
    // process dying took linuxity and every sibling with it. The death is
    // observed as an ordinary reap by next() on a later iteration, exactly
    // like any other fatal signal.
    [[nodiscard]] bool store_and_skip(const Regs& r) const {
        if (r.store(cur_) && r.commit_skip(cur_)) return true;
        return errno == ESRCH;        // already gone: nothing to write to
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
        const auto s = abi::decode(kTraceeArch, nr);
        return returns_pid(nr) || s == abi::Sysno::waitid || s == abi::Sysno::rt_sigtimedwait ||
               (s == abi::Sysno::recvfrom && kernel::dns_proxy_port() != 0);
    }

    // fcntl(F_GETLK) fills struct flock's l_pid with the HOST pid of the
    // lock holder, and SO_PEERCRED's ucred holds a host pid/uid/gid. Both
    // need their exit stop to be put in the guest's terms.
    static constexpr std::uint64_t kFGetLk = 5;
    [[nodiscard]] static bool is_getlk(const Regs& r) {
        return abi::decode(kTraceeArch, r.nr()) == abi::Sysno::fcntl &&
               r.arg(1) == kFGetLk && r.arg(2) != 0;
    }
    [[nodiscard]] static bool is_peercred(const Regs& r) {
        return abi::decode(kTraceeArch, r.nr()) == abi::Sysno::getsockopt &&
               r.arg(1) == 1 /*SOL_SOCKET*/ && r.arg(2) == 17 /*SO_PEERCRED*/ &&
               r.arg(3) != 0;
    }
    [[nodiscard]] bool needs_out_fixup(const Regs& r, ::pid_t w = -1) const {
        return is_getlk(r) || is_peercred(r) || is_recv_creds(r, w) || ipc_pid_field(r) != 0;
    }
    // SysV IPC answers that carry host pids: the *ctl stat structs (msg
    // lspid/lrpid at 96/100, shm cpid/lpid at 80/84) and semctl(GETPID)'s
    // return. Returns 1 msg, 2 shm, 3 GETPID, 0 none. Only seen when the
    // host has SysV IPC (otherwise linuxity answers these itself).
    [[nodiscard]] static int ipc_pid_field(const Regs& r) {
        const auto sc = abi::decode(kTraceeArch, r.nr());
        const auto cmd = r.arg(sc == abi::Sysno::semctl ? 2 : 1) & ~0x100ull;
        if (sc == abi::Sysno::msgctl && (cmd == 2 || cmd == 11 || cmd == 13) && r.arg(2)) return 1;
        if (sc == abi::Sysno::shmctl && (cmd == 2 || cmd == 13 || cmd == 15) && r.arg(2)) return 2;
        if (sc == abi::Sysno::semctl && cmd == 11) return 3;
        return 0;
    }
    // A host pid as the calling guest names it; 0 when it isn't a guest's.
    // A child the parent hears about in SIGCHLD, by the parent's numbering.
    [[nodiscard]] std::int32_t chld_gpid(::pid_t parent, std::int32_t host) {
        if (host_pids_) return host;
        return guest_view_of_host(parent, host);
    }
    // A host pid as the calling guest names it; 0 when it isn't a guest's.
    [[nodiscard]] std::int32_t guest_view_of_host(::pid_t w, std::int32_t host) {
        if (host <= 0) return 0;
        const std::int32_t g = known_gpid_of(host);
        if (g <= 0) return 0;
        const std::int32_t l = local_pid(known_gpid_of(host_tgid_of(w)), g);
        return l > 0 ? l : 0;
    }
    void translate_ipc_pids(::pid_t w, Regs& r) {
        const int kind = ipc_pid_field(r);
        const auto ret = static_cast<long long>(r.ret());
        if (ret < 0) return;
        if (kind == 3) {
            r.set_ret(guest_view_of_host(w, static_cast<std::int32_t>(ret)));
            (void)r.store(w);
            return;
        }
        const std::uint64_t at = r.arg(2) + (kind == 1 ? 96 : 80);
        errno = 0;
        const long word = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(at), 0);
        if (errno) return;
        const auto a = static_cast<std::int32_t>(static_cast<std::uint32_t>(word));
        const auto b = static_cast<std::int32_t>(static_cast<std::uint64_t>(word) >> 32);
        const auto na = static_cast<std::uint32_t>(guest_view_of_host(w, a));
        const auto nb = static_cast<std::uint32_t>(guest_view_of_host(w, b));
        const auto nw = static_cast<std::uint64_t>(na) | (static_cast<std::uint64_t>(nb) << 32);
        ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at), reinterpret_cast<void*>(nw));
    }
    // `w` is the task the registers belong to; at an exit stop that is not
    // necessarily cur_ any more.
    [[nodiscard]] bool is_recv_creds(const Regs& r, ::pid_t w = -1) const {
        if (abi::decode(kTraceeArch, r.nr()) != abi::Sysno::recvmsg || r.arg(1) == 0) return false;
        errno = 0;
        const long ctllen = ::ptrace(PTRACE_PEEKDATA, w > 0 ? w : cur_,
                                     reinterpret_cast<void*>(r.arg(1) + 40), 0);
        return errno == 0 && ctllen >= 28;
    }

    // recvmsg: SCM_CREDENTIALS from a peer in the tree comes back as the
    // host's {pid, uid, gid}; restate it as the guest sees that process.
    void translate_recv_creds(::pid_t w, const Regs& r) {
        if (static_cast<long long>(r.ret()) < 0) return;
        auto peek = [&](std::uint64_t a, std::uint64_t& out) {
            errno = 0;
            const long v = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(a), 0);
            if (errno) return false;
            out = static_cast<std::uint64_t>(v);
            return true;
        };
        const std::uint64_t msg = r.arg(1);
        std::uint64_t ctl = 0, ctllen = 0;
        if (!peek(msg + 32, ctl) || !peek(msg + 40, ctllen) || !ctl) return;
        std::uint64_t off = 0;
        while (off + 16 <= ctllen) {
            std::uint64_t len = 0, lt = 0;
            if (!peek(ctl + off, len) || !peek(ctl + off + 8, lt) || len < 16) return;
            const auto level = static_cast<std::uint32_t>(lt), type = static_cast<std::uint32_t>(lt >> 32);
            if (level == 1 && type == 2 && len >= 28) {
                const std::uint64_t at = ctl + off + 16;
                std::uint64_t w0 = 0, w1 = 0;
                if (!peek(at, w0) || !peek(at + 8, w1)) return;
                const auto hp = static_cast<::pid_t>(static_cast<std::uint32_t>(w0));
                const std::int32_t g = known_gpid_of(hp);
                if (g <= 0) return;
                const auto ids = guest_ids_of_ ? guest_ids_of_(g) : std::pair<std::uint32_t, std::uint32_t>{0, 0};
                const std::uint64_t n0 = static_cast<std::uint32_t>(g) | (static_cast<std::uint64_t>(ids.first) << 32);
                const std::uint64_t n1 = (w1 & ~0xffffffffull) | ids.second;
                ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at), reinterpret_cast<void*>(n0));
                ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at + 8), reinterpret_cast<void*>(n1));
            }
            off += (len + 7) & ~std::uint64_t{7};
        }
    }

    // The guest {uid, gid} of a guest pid, for restating credentials the
    // host passes along (SCM_CREDENTIALS, SO_PEERCRED).
    void set_guest_ids(std::function<std::pair<std::uint32_t, std::uint32_t>(std::int32_t)> f) {
        guest_ids_of_ = std::move(f);
    }
    // How guest process `viewer` numbers global guest pid `pid` (its pid
    // namespace), and the reverse. Unset means one flat namespace.
    void set_pid_view(std::function<std::int32_t(std::int32_t, std::int32_t)> to_local,
                      std::function<std::int32_t(std::int32_t, std::int32_t)> to_global) {
        pid_to_local_ = std::move(to_local);
        pid_to_global_ = std::move(to_global);
    }
    [[nodiscard]] std::int32_t local_pid(std::int32_t viewer, std::int32_t pid) const {
        return pid_to_local_ && pid > 0 ? pid_to_local_(viewer, pid) : pid;
    }
    [[nodiscard]] std::int32_t global_pid(std::int32_t viewer, std::int32_t pid) const {
        return pid_to_global_ && pid > 0 ? pid_to_global_(viewer, pid) : pid;
    }
    // the guest pid a host pid had, even once it has exited; 0 if never ours
    [[nodiscard]] std::int32_t guest_pid_of_host(::pid_t host) const { return known_gpid_of(host); }

    // struct ucred {pid, uid, gid}. A peer in the guest tree is a guest
    // process, so it's root like every guest; one outside shows pid 0.
    void translate_peercred(::pid_t w, const Regs& r) {
        if (static_cast<long long>(r.ret()) != 0) return;
        const std::uint64_t at = r.arg(3);
        errno = 0;
        const long w0 = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(at), 0);
        const long w1 = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(at + 8), 0);
        if (errno != 0) return;
        const auto host = static_cast<std::int32_t>(static_cast<std::uint32_t>(w0));
        std::int32_t g = host > 0 ? known_gpid_of(host) : 0;
        // a child that connected before its fork event was processed (the
        // no-seccomp test mode makes this race easy to hit) is still one
        // we trace: give it its pid now, as the fork event would
        if (g <= 0 && host > 0 && tasks_.count(host)) g = gpid_of(host);
        if (g <= 0) return;   // not ours: leave the host's answer alone
        const auto ids = guest_ids_of_ ? guest_ids_of_(g) : std::pair<std::uint32_t, std::uint32_t>{0, 0};
        const auto n0 = static_cast<std::uint64_t>(static_cast<std::uint32_t>(g)) |
                        (static_cast<std::uint64_t>(ids.first) << 32);
        const auto n1 = (static_cast<std::uint64_t>(w1) & ~0xffffffffull) | ids.second;
        ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at), reinterpret_cast<void*>(n0));
        ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at + 8), reinterpret_cast<void*>(n1));
    }

    // l_pid sits at offset 24 of struct flock on x86-64 and aarch64. A
    // holder outside the guest tree shows as 0, like a pid namespace.
    void translate_getlk(::pid_t w, const Regs& r) {
        if (static_cast<long long>(r.ret()) != 0) return;
        const std::uint64_t at = r.arg(2) + 24;
        errno = 0;
        const long word = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(at), 0);
        if (errno != 0) return;
        const auto host = static_cast<std::int32_t>(static_cast<std::uint32_t>(word));
        if (host <= 0) return;
        auto uw = static_cast<std::uint64_t>(word);
        uw = (uw & ~0xffffffffull) | static_cast<std::uint32_t>(known_gpid_of(host));
        ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at), reinterpret_cast<void*>(uw));
    }

    // Forward, and run `then` at the call's exit stop. Unlike forward_sync
    // the tracer keeps serving other tasks while the call runs, so it suits
    // calls that may block (a socket waiting for its peer).
    [[nodiscard]] Result<std::int64_t> forward_then(std::function<void(std::int64_t)> then) {
        tasks_[cur_].on_exit = std::move(then);
        return forward();
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
        if (seccomp_ && !owes_exit_stop(t.regs.nr()) && !needs_out_fixup(t.regs) && !t.on_exit &&
            !gt_wants_exit(cur_)) {
            sys_done(cur_);
            resume_run(cur_, 0);
            return ok(std::int64_t{0});
        }
        t.forwarded = true;
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
        sys_done(cur_);
        if (post_exit) post_exit(ret);
        resume_task(cur_);
        return ok(ret);
    }

    // Run the real call for its host side effect (setsid, TIOCSCTTY), then
    // overwrite its result with `ret`, the guest's answer. These never block.
    [[nodiscard]] Result<std::int64_t> forward_sync_then_set(std::int64_t ret) {
        return forward_sync([this, ret](std::int64_t) { set_ret_now(ret); });
    }

    // Make the current task wait `ns` in the kernel (ppoll on no fds), then
    // run the syscall it trapped on again from scratch, so the dispatcher
    // sees it afresh. For an open that has to block on another guest task.
    // A signal ends the wait early and is handled on the way out; the call
    // then runs again, as with SA_RESTART. Ctrl-C still kills.
    // Run a few syscalls INSIDE the current task, in place of the one it
    // trapped on, and return the last one's result as that call's. Used
    // where only the guest itself can make the thing (a shared mapping in
    // its address space): each step is (sysno, 6 args); an arg of
    // kPrevRet is replaced by the previous step's return value. A step
    // failing stops the chain and its error is returned. `strings` are
    // poked onto the task's stack first; kStr0 + i in an arg names the i-th.
    static constexpr std::uint64_t kPrevRet = 0xfeedfacecafe0001ull;
    static constexpr std::uint64_t kStr0    = 0xfeedfacecafe0100ull;
    static constexpr std::uint64_t kStepRet = 0xfeedfacecafe0200ull;   // + step index
    struct GuestCall { abi::Sysno nr; std::array<std::uint64_t, 6> a; };

    // Run setup calls inside the current task, then put it back exactly as
    // it trapped and run the trapped call again from its instruction. Its
    // results come back in order (a negative one stops the chain), and
    // `between` runs after the chain with the task still stopped (to write
    // into what the chain made). Used by the in-guest handler to map its region
    // and patch a site: the guest's own call then takes the patched route.
    // False only if the task died.
    [[nodiscard]] bool inject_then_retry(const std::vector<GuestCall>& calls,
                                         std::vector<std::int64_t>& rets,
                                         const std::function<void(const std::vector<std::int64_t>&)>& between = {}) {
        Task& t = tasks_[cur_];
        const Regs entry = t.regs;          // the guest's own registers
        rets.clear();
        bool alive = true;
        for (std::size_t i = 0; i < calls.size(); ++i) {
            Regs r = entry;
            for (int k = 0; k < 6; ++k) {
                std::uint64_t v = calls[i].a[static_cast<std::size_t>(k)];
                if (v >= kStepRet && v < kStepRet + rets.size()) v = static_cast<std::uint64_t>(rets[v - kStepRet]);
                r.set_arg(k, v);
            }
            r.set_nr(encode(kTraceeArch, calls[i].nr));
            if (!r.store(cur_) || !r.commit_nr(cur_)) { alive = Regs::fetch(cur_, r); break; }
            if (!step_to_exit(cur_)) return false;
            Regs after{};
            (void)Regs::fetch(cur_, after);
            const auto ret = static_cast<std::int64_t>(after.ret());
            rets.push_back(ret);
            const bool stop = ret < 0 && ret >= -4095;
            if (i + 1 < calls.size() && !stop) {
                Regs again = after;
                again.rewind_to_syscall();
                (void)again.store(cur_);
                if (!step_to_entry(cur_)) return false;
            }
            if (stop) break;
        }
        if (!alive) return true;
        if (between) between(rets);
        // Back to the guest's own syscall instruction with its own registers,
        // so it runs again (now down the patched route, or trapping again).
        Regs back = entry;
        if (!calls.empty()) {
            // at an exit stop the pc is past the instruction
            back.rewind_to_syscall();
        } else {
            // still at the entry stop: skip this run, then rewind at its exit
            back.skip_call();
            back.set_ret(-static_cast<std::int64_t>(EINTR));
            if (!store_and_skip(back)) return true;
            if (!step_to_exit(cur_)) return false;
            back = entry;
            back.rewind_to_syscall();
        }
        (void)back.store(cur_);
        t.regs = entry;
        sys_done(cur_);
        t.action = Action::none;
        resume_task(cur_);
        return true;
    }
    [[nodiscard]] Result<std::int64_t> run_in_guest(const std::vector<GuestCall>& calls,
                                                    const std::vector<std::string>& strings = {},
                                                    int result_of = -1, std::int64_t retry_if_zero_ns = 0,
                                                    bool echild_is_zero = false) {
        Task& t = tasks_[cur_];
        const Regs entry = t.regs;
        // scratch for the strings, well below the red zone
        std::vector<std::uint64_t> saddr;
        std::uint64_t at = (entry.sp() - 512) & ~std::uint64_t{15};
        for (const auto& s : strings) {
            std::string z = s;
            z.push_back('\0');
            at = (at - z.size()) & ~std::uint64_t{15};
            if (!poke_scratch(at, z)) return err<std::int64_t>(Errno::efault);
            saddr.push_back(at);
        }
        std::int64_t prev = 0;
        std::vector<std::int64_t> rets;
        for (std::size_t i = 0; i < calls.size(); ++i) {
            Regs r = entry;
            for (int k = 0; k < 6; ++k) {
                std::uint64_t v = calls[i].a[static_cast<std::size_t>(k)];
                if (v == kPrevRet) v = static_cast<std::uint64_t>(prev);
                else if (v >= kStr0 && v < kStr0 + saddr.size()) v = saddr[v - kStr0];
                else if (v >= kStepRet && v < kStepRet + rets.size()) v = static_cast<std::uint64_t>(rets[v - kStepRet]);
                r.set_arg(k, v);
            }
            r.set_nr(encode(kTraceeArch, calls[i].nr));
            if (!r.store(cur_) || !r.commit_nr(cur_)) return err<std::int64_t>(Errno::eio);
            if (!step_to_exit(cur_)) return ok(std::int64_t{-1});   // task died
            Regs after{};
            (void)Regs::fetch(cur_, after);
            prev = static_cast<std::int64_t>(after.ret());
            // a real wait4 here reports a host pid; the guest gets its own
            if (calls[i].nr == abi::Sysno::wait4 && prev > 0) {
                const std::int32_t g = known_gpid_of(static_cast<::pid_t>(prev));
                const std::int32_t l = local_pid(known_gpid_of(host_tgid_of(cur_)), g);
                prev = l > 0 ? l : g;
            }
            rets.push_back(prev);
            if (i + 1 < calls.size()) {
                if (prev < 0 && prev >= -4095) break;   // a step failed
                // back to the syscall instruction to run the next step; the
                // pc is the kernel's (past the svc), the args are set below
                Regs again = after;
                again.rewind_to_syscall();
                (void)again.store(cur_);
                if (!step_to_entry(cur_)) return ok(std::int64_t{-1});
            }
        }
        // the original call's registers, with the chain's answer: the chosen
        // step's result, or a failing step's error
        const bool failed = prev < 0 && prev >= -4095;
        if (!failed && result_of >= 0 && static_cast<std::size_t>(result_of) < rets.size())
            prev = rets[static_cast<std::size_t>(result_of)];
        if (echild_is_zero && prev == -ECHILD) prev = 0;
        if (prev == 0 && retry_if_zero_ns > 0) {
            // nothing yet: back to the guest's own call, wait, run it again
            Regs again{};
            (void)Regs::fetch(cur_, again);
            again.rewind_to_syscall();
            (void)again.store(cur_);
            if (!step_to_entry(cur_)) return ok(std::int64_t{-1});
            Regs orig = entry;
            (void)orig.store(cur_);
            t.regs = entry;
            if (auto st = wait_then_retry(retry_if_zero_ns); !st) return err<std::int64_t>(st.error());
            return ok(std::int64_t{0});
        }
        Regs out{};
        (void)Regs::fetch(cur_, out);
        Regs keep = entry;
        for (int k = 0; k < 6; ++k) out.set_arg(k, keep.arg(k));
        out.set_ret(prev);
        (void)out.store(cur_);
        // still stopped: fill what the chain made before the guest uses it
        if (before_resume_) std::exchange(before_resume_, {})(prev);
        sys_done(cur_);
        t.action = Action::none;
        resume_task(cur_);
        return ok(prev);
    }
    // Run once by the next run_in_guest, with its result, before the task
    // resumes.
    void set_before_resume(std::function<void(std::int64_t)> f) { before_resume_ = std::move(f); }
    // Bytes the NEXT redirect hands the host through pointer arg `arg`
    // (openat2's open_how with resolve cleared). One-shot.
    void set_arg_blob(int arg, std::string bytes) { blob_arg_ = arg; blob_ = std::move(bytes); }

    // Poke the pending blob below `floor` and point its arg at it. Returns
    // the guest's own pointer for that arg, or nothing if there was no blob.
    [[nodiscard]] std::optional<std::pair<int, std::uint64_t>> place_blob(Regs& r, std::uint64_t floor) {
        if (blob_arg_ < 0) return std::nullopt;
        const int arg = std::exchange(blob_arg_, -1);
        const std::string bytes = std::exchange(blob_, {});
        const std::uint64_t at = (floor - 256 - bytes.size() - 1) & ~std::uint64_t{15};
        if (!poke_path(at, bytes, /*dead_scratch=*/true)) return std::nullopt;
        const std::uint64_t old = r.arg(arg);
        set_arg(r, arg, at);
        return std::pair{arg, old};
    }
    void drop_blob() noexcept { blob_arg_ = -1; blob_.clear(); }

    [[nodiscard]] Status wait_then_retry(std::int64_t ns) {
        Task& t = tasks_[cur_];
        const Regs entry = t.regs;
        Regs r = entry;
        const std::uint64_t ts = (entry.sp() - 256 - 32) & ~std::uint64_t{15};
        std::string spec(16, '\0');
        const std::int64_t sec = ns / 1'000'000'000, nsec = ns % 1'000'000'000;
        std::memcpy(spec.data(), &sec, 8);
        std::memcpy(spec.data() + 8, &nsec, 8);
        if (!poke_scratch(ts, spec)) return err(Errno::efault);
        r.set_arg(0, 0);    // no fds
        r.set_arg(1, 0);
        r.set_arg(2, ts);
        r.set_arg(3, 0);    // keep the signal mask
        r.set_arg(4, 8);
        r.set_nr(encode(kTraceeArch, abi::Sysno::ppoll));
        if (!r.store(cur_) || !r.commit_nr(cur_)) return err(Errno::eio);
        t.action = Action::none;
        // Rewind to the guest's OWN call: the rerun traps and is translated
        // again, so re-issuing the pid-translated args translated them twice.
        // Harmless while guest pids are small and host pids large; inside a
        // pid namespace (claybin, unshare -p) the ranges overlap and guest 4
        // = host 6 became host 8, so wait4 returned another child or ECHILD.
        t.on_exit = [w = cur_, again = t.guest_regs](std::int64_t) {
            Regs back = again;
            back.rewind_to_syscall();
            (void)back.store(w);
        };
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);
        return ok();
    }

    // Overwrite the return of the task stopped at its syscall exit. Only
    // valid inside a post_exit callback.
    void set_ret_now(std::int64_t ret) {
        Regs rr{};
        if (!Regs::fetch(cur_, rr)) return;
        rr.set_ret(ret);
        (void)rr.store(cur_);
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
            drop_blob();
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
            sys_done(cur_);
            if (post_exit) post_exit(ret0);
            resume_task(cur_);
            return ok(ret0);
        }
        set_arg(r, path_arg, scratch);
        // A two-path mutation (rename/link/symlink): park the SECOND host path
        // in a distinct, non-overlapping scratch slot below the first and
        // rewrite its register too. Both operands are then translated before
        // the kernel runs the single syscall.
        std::uint64_t lowest = scratch;
        if (path_arg2 >= 0 && !host_path2.empty()) {
            std::size_t need2 = host_path2.size() + 1;
            std::uint64_t scratch2 =
                (scratch - 256 - need2) & ~std::uint64_t{15};
            if (!poke_path(scratch2, host_path2, /*dead_scratch=*/true)) {
                drop_blob();
                return err<std::int64_t>(Errno::efault);
            }
            set_arg(r, path_arg2, scratch2);
            lowest = scratch2;
        }
        (void)place_blob(r, lowest);
        (void)r.store(cur_);
        if (!step_to_exit(cur_)) return ok(std::int64_t{-1});   // task exited
        Regs rr{};
        (void)Regs::fetch(cur_, rr);
        std::int64_t ret = static_cast<std::int64_t>(rr.ret());
        sys_done(cur_);
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

    // REDIRECT for a call that may block on ANOTHER guest task (opening a
    // FIFO waits for its other end). Rewrite the path and let it run;
    // `on_exit` gets the result at its exit stop, so the tracer keeps
    // serving the rest of the tree meanwhile.
    [[nodiscard]] Status redirect_deferred(int path_arg, const std::string& host_path,
                                           std::function<void(std::int64_t)> on_exit) {
        Task& t = tasks_[cur_];
        Regs r = t.regs;
        const std::size_t need = host_path.size() + 1;
        const std::uint64_t scratch = (t.regs.sp() - 256 - need) & ~std::uint64_t{15};
        std::optional<std::pair<int, std::uint64_t>> blob;
        if (poke_path(scratch, host_path, /*dead_scratch=*/true)) {
            set_arg(r, path_arg, scratch);
            blob = place_blob(r, scratch);
            (void)r.store(cur_);
        } else {
            drop_blob();
            (void)t.regs.store(cur_);   // same fallback as redirect()
        }
        t.action = Action::none;
        const std::uint64_t guest_ptr = t.regs.arg(path_arg);
        t.on_exit = [w = cur_, path_arg, guest_ptr, blob,
                     fn = std::move(on_exit)](std::int64_t ret) {
            // -ERESTART*: the kernel re-runs the call with these registers,
            // and a signal handler may overwrite the scratch path on the
            // stack, so point the arg back at the guest's own string.
            if (ret <= -512 && ret >= -516) {
                Regs now{};
                if (Regs::fetch(w, now)) {
                    set_arg(now, path_arg, guest_ptr);
                    if (blob) set_arg(now, blob->first, blob->second);
                    (void)now.store(w);
                }
            }
            fn(ret);
        };
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);
        return ok();
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
        sys_done(cur_);
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
                                          std::uint64_t new_len,
                                          std::function<void(std::int64_t)> on_done = {}) {
        Task& t = tasks_[cur_];
        Regs r = t.regs;
        // Save the guest's own sockaddr bytes: the kernel reads ours but
        // never writes the buffer back, so without a restore the guest's
        // struct would hold the translated host path afterwards.
        const std::size_t span = std::max<std::size_t>(host_path.size() + 1, 108);
        std::vector<std::byte> saved(span);
        const bool have_saved = static_cast<bool>(copy_in(path_addr, saved));
        const std::uint64_t old_len = reg_arg(r, len_arg);
        if (!poke_path(value(path_addr), host_path))
            return err(Errno::efault);
        set_arg(r, len_arg, new_len);
        (void)r.store(cur_);
        t.action = Action::none;
        t.on_exit = [this, w = cur_, path_addr, saved = std::move(saved), have_saved, len_arg,
                     old_len, fn = std::move(on_done)](std::int64_t ret) {
            if (have_saved) {
                const pid_t keep = cur_;
                cur_ = w;
                (void)poke_bytes(value(path_addr),
                                 std::string(reinterpret_cast<const char*>(saved.data()), saved.size() - 1));
                cur_ = keep;
            }
            // a restarted call has to see the guest's socklen again
            if (ret <= -512 && ret >= -516) {
                Regs now{};
                if (Regs::fetch(w, now)) { now.set_arg(len_arg, old_len); (void)now.store(w); }
            }
            if (fn) fn(ret);
        };
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

        // Read the original argv pointer array up to its NULL, in chunks.
        // The kernel's own limit is the stack rlimit, not an entry count.
        std::vector<std::uint64_t> orig;
        constexpr std::size_t kChunk = 512, kMaxArgs = std::size_t{1} << 21;
        for (bool done = false; !done && orig.size() < kMaxArgs;) {
            std::array<std::uint64_t, kChunk> buf{};
            const std::uint64_t at = argv_ptr + orig.size() * 8;
            // don't run a chunk across a page we may not own
            const std::size_t to_page = (4096 - (at & 4095)) / 8;
            const std::size_t n = std::min(kChunk, to_page == 0 ? kChunk : to_page);
            if (!copy_in(uaddr(at), std::as_writable_bytes(std::span{buf.data(), n}))) break;
            for (std::size_t i = 0; i < n; ++i) {
                if (buf[i] == 0) { done = true; break; }
                orig.push_back(buf[i]);
            }
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
        // --overwrite "*" goes before the guest's own arguments: yay ends its
        // with "--", and anything after that is a package name to pacman
        for (auto p : p_extra) ptrs.push_back(p);
        for (std::size_t i = 1; i < orig.size(); ++i)
            ptrs.push_back(orig[i]);       // original argv[1..]
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
        // the exec is still to happen: run to it (a traced task too)
        if (gtr_.count(cur_)) ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);
        else resume_run(cur_, 0);
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
        // Drop a leading ELF interpreter token: it's how linuxity launches a
        // dynamic binary, not the guest command.
        //
        // The name is NOT the same everywhere. glibc ships ld-linux*.so*,
        // musl ships ld-musl*.so*, and BIONIC -- Android -- ships plain
        // `linker64` (or `linker` on 32-bit) with no .so suffix at all,
        // usually under /apex/com.android.runtime/bin/. Missing that last
        // one meant every guest on Android read its own /proc/self/cmdline
        // as "/apex/com.android.runtime/bin/linker64\0<program>" and its
        // comm as "linker64": anything that introspects its own argv --
        // argv[0]-based re-exec, a daemon logging its name, ps -- saw the
        // loader instead of itself. Caught by the procid conformance probe,
        // which was the one scenario still diverging on the device.
        auto is_interp = [](const std::string& a) {
            auto slash = a.find_last_of('/');
            std::string base = slash == std::string::npos ? a : a.substr(slash + 1);
            return base.rfind("ld-linux", 0) == 0 || base.rfind("ld-musl", 0) == 0 ||
                   base.rfind("ld.so", 0) == 0 ||
                   base == "linker64" || base == "linker";
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
        if (host_pids_) return static_cast<std::int32_t>(tid);
        if (tid == root_pid_) return 1;
        auto [it, fresh] = gpid_.try_emplace(tid, 0);
        if (fresh) {
            it->second = next_gpid_++;
            host_of_gpid_[it->second] = tid;
        }
        return it->second;
    }
    // The guest pid of a task that just exited, or 0 if it was never ours
    // (the root is reported by its own path).
    [[nodiscard]] std::int32_t exited_gpid(::pid_t w) const {
        if (host_pids_)
            return w != root_pid_ && (gppid_.count(static_cast<std::int32_t>(w)))
                ? static_cast<std::int32_t>(w) : 0;
        auto it = gpid_.find(w);
        return it != gpid_.end() ? it->second : 0;
    }

    // Guest pids are host pids (--host-pids). Set before start().
    void set_host_pids(bool on) noexcept { host_pids_ = on; }
    // The guest's init: the root task's pid as the guest names it.
    [[nodiscard]] std::int32_t init_gpid() const noexcept {
        // an instance has no root task; with host pids its init is us
        if (host_pids_) return instance_ ? static_cast<std::int32_t>(::getpid())
                                         : static_cast<std::int32_t>(root_pid_);
        return 1;
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
        enum Kind { spawn, exec, reap, thread, stop, cont, reparent, zombie } kind;
        ::pid_t pid;          // the affected task's tid (== pid for a process)
        ::pid_t ppid;         // parent (spawn), owning process (thread)
        std::string comm;     // program name (exec only)
        std::string cmdline;  // full argv, space-joined (exec only)
        std::uint64_t ns_flags{0};   // spawn: the CLONE_NEW* the clone asked for
    };
    [[nodiscard]] std::vector<ProcEvent> drain_proc_events() {
        // A zombie lives as long as the host keeps it: once its parent's wait
        // (or an auto-reap: SIGCHLD ignored, parent gone) frees it, the host
        // drops /proc/<pid>, and so do we. Every wait form works the same.
        if (!zombies_.empty()) {
            for (auto it = zombies_.begin(); it != zombies_.end();) {
                char p[32];
                std::snprintf(p, sizeof p, "/proc/%d", static_cast<int>(it->second));
                if (::access(p, F_OK) != 0) {
                    proc_events_.push_back({ProcEvent::reap, it->first, 0, {}, {}});
                    it = zombies_.erase(it);
                } else ++it;
            }
        }
        return std::exchange(proc_events_, {});
    }
    // Zombies keyed by guest pid -> host pid, until the host reaps them.
    std::unordered_map<std::int32_t, ::pid_t> zombies_;
    // CLONE_NEW* flags of a clone a task is in, by host tid
    std::unordered_map<::pid_t, std::uint64_t> pending_clone_ns_;

    // The current guest tid, so the loop can attribute a syscall to a pid.
    [[nodiscard]] ::pid_t current_tid() const noexcept { return cur_; }
    [[nodiscard]] ::pid_t current_tgid() { return host_tgid_of(cur_); }
    void set_strict(::pid_t host_tgid) { strict_tgids_.insert(host_tgid); }

    // Stat a REAL host path, so the dispatcher can answer a host-backed guest
    // stat in the SAME trap stop instead of redirecting the call and stepping
    // the guest to its syscall exit. Optional by design: the dispatcher asks
    // with `requires`, so a backend without it keeps the two-stop path and the
    // worst case of not having it is slower, never wrong.
    //
    // The supervisor's own stat is safe here because the path has ALREADY been
    // translated through FileNamespace -- it is a host path we chose, not
    // guest-controlled text, so this cannot be used to escape the namespace.
    // The TRACEE's real memory map, as /proc/<pid>/maps text.
    //
    // The guest is a real host process, so its mappings are real and the
    // honest answer is to report them. procfs served an EMPTY file, which is
    // worse than it sounds: `pstack`, a debugger attaching to a guest, and
    // any allocator or sanitizer that walks its own mappings all read this,
    // and an empty map is not a plausible process.
    //
    // Host paths in the right-hand column are the caller's problem to
    // translate -- they are rootfs paths like /tmp/linuxity-tmp-N/usr/bin/sh
    // and must be mapped back into the guest's namespace before the guest
    // sees them, or the file leaks where its rootfs really lives.
    [[nodiscard]] std::optional<std::string> host_maps() const {
        const std::string p = "/proc/" + std::to_string(cur_) + "/maps";
        std::FILE* f = std::fopen(p.c_str(), "re");
        if (!f) return std::nullopt;
        std::string out;
        char buf[4096];
        while (std::size_t n = std::fread(buf, 1, sizeof buf, f))
            out.append(buf, n);
        std::fclose(f);
        return out;
    }

    // The supervisor's own stat is safe here because the path has ALREADY
    // been translated through FileNamespace -- it is a host path we chose,
    // not guest-controlled text, so this cannot be used to escape.
    [[nodiscard]] std::optional<abi::wire::StatFields>
    stat_host_path(const std::string& path) const {
        struct ::stat st{};
        if (::lstat(path.c_str(), &st) != 0) return std::nullopt;
        return host::stat_fields(st);
    }

    struct TaskIds { std::int32_t pid, tid, ppid; };

    // The HOST tid of the task whose syscall is being served. The dispatcher
    // needs it to read the tracee's own /proc (e.g. /proc/<tid>/fd/<n> to
    // identify an fd it never saw opened); guest pids do not exist there.
    [[nodiscard]] int host_tid() const noexcept { return cur_; }

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
        ::pid_t host_tgid = host_tgid_of(cur_);
        const std::int32_t pid = gpid_of(host_tgid);
        const std::int32_t tid = gpid_of(cur_);
        std::int32_t ppid = 0;
        if (auto it = gppid_.find(pid); it != gppid_.end()) {
            ppid = it->second;
        } else if (pid != init_gpid()) {
            // The child's attach stop can win the race with the parent's
            // fork event, so its first syscall arrives with no parent link.
            // The host knows the parent; take it from there.
            const ::pid_t hp = status_field(host_tgid, "PPid:");
            if (const std::int32_t gp = hp > 0 ? known_gpid_of(hp) : 0; gp > 0) {
                gppid_[pid] = gp;
                ppid = gp;
            }
        } else if (host_pids_) {
            // init's parent is linuxity itself, which the guest can see
            ppid = static_cast<std::int32_t>(::getpid());
            gppid_[pid] = ppid;
        }
        return TaskIds{pid, tid, ppid};
    }

    // Cached host tgid of a host tid.
    ::pid_t host_tgid_of(::pid_t tid) {
        if (auto it = tgid_cache_.find(tid); it != tgid_cache_.end()) return it->second;
        const ::pid_t t = tgid_of(tid);
        const ::pid_t out = t > 0 ? t : tid;
        tgid_cache_[tid] = out;
        return out;
    }

    // Every traced guest process (host tgids, one per process).
    [[nodiscard]] std::vector<::pid_t> host_tgids() {
        std::unordered_set<::pid_t> seen;
        std::vector<::pid_t> out;
        for (const auto& [tid, _] : tasks_)
            if (const ::pid_t tg = host_tgid_of(tid); seen.insert(tg).second) out.push_back(tg);
        return out;
    }

    // A new thread `child` in the same process as `creator`. A clone that
    // made a separate process (no CLONE_THREAD) isn't one.
    void note_thread(::pid_t creator, ::pid_t child) {
        const ::pid_t tg = host_tgid_of(creator);
        const ::pid_t ctg = tgid_of(child);
        if (ctg > 0 && ctg != tg) return;
        tgid_cache_[child] = tg;
        proc_events_.push_back({ProcEvent::thread, gpid_of(child), gpid_of(tg), {}, {}});
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
            // host pids keep no gpid_ map; the tree is gppid_ itself
            if (host_pids_)
                for (const auto& [gp, _] : gppid_)
                    if ((gp == leader || descends_from(gp, leader)) && tasks_.count(gp))
                        targets.push_back(static_cast<::pid_t>(gp));

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
        // a host process outside the guest: the host kernel decides
        if (host_pids_ && !known_gpid_of(tid))
            return ::kill(tid, signum) == 0 ? 0 : -static_cast<std::int64_t>(errno);
        return deliver_to_tid(tid, signum);
    }

    // Is guest pid `p` a descendant of `root`? Walks gppid_ with a bounded
    // depth so a cycle (which should not happen, but a stale entry could
    // create one) cannot spin.
    [[nodiscard]] bool descends_from(std::int32_t p, std::int32_t root) const {
        for (int hops = 0; hops < 64 && p > 1 && p != init_gpid(); ++hops) {
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
        si.si_uid   = sender_uid_;       // the sender's real uid in the guest
        // marks it as a kill(2), turned back into SI_USER at delivery
        si.si_value.sival_int = kKillMark;

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
        if (rc == 0) {
            if (signum == SIGCONT) continue_group(tid);
            if (signum == SIGSTOP) stop_owed_.insert(tid);
            return 0;
        }
        return -static_cast<std::int64_t>(abi::wire::errno_from_host(errno));
    }

    // A traced task in group-stop sits in a ptrace stop, which SIGCONT can't
    // wake; only the tracer can. Resume every stopped thread of tid's process
    // so it picks up the SIGCONT and its parent sees WCONTINUED.
    void continue_group(::pid_t tid) {
        const ::pid_t tg = host_tgid_of(tid);
        std::vector<::pid_t> wake;
        for (::pid_t s : stopped_)
            if (host_tgid_of(s) == tg) wake.push_back(s);
        if (wake.empty()) return;
        for (::pid_t s : wake) {
            stopped_.erase(s);
            resume_run(s, 0);
        }
        proc_events_.push_back({ProcEvent::cont, gpid_of(tg), 0, {}, {}});
    }

    // Run the trapped setpgid(pid, pgid) on the host with both ids made
    // host ids, then give the guest `ret`. Records whether the group now
    // exists for real, which decides how wait4(-pgid) is served.
    [[nodiscard]] Result<std::int64_t> mirror_setpgid(std::int32_t gpid, std::int32_t gpgid,
                                                      std::int64_t ret) {
        const ::pid_t hp = gpid == 0 ? 0 : host_tid_of(gpid);
        const ::pid_t hg = gpgid == 0 ? 0 : host_tid_of(gpgid);
        if (hp < 0 || hg < 0) return forward_sync_then_set(ret);
        Task& t = tasks_[cur_];
        Regs r = t.regs;
        r.set_arg(0, static_cast<std::uint64_t>(hp));
        r.set_arg(1, static_cast<std::uint64_t>(hg));
        (void)r.store(cur_);
        t.regs = r;
        const std::int32_t group = gpgid ? gpgid : (gpid ? gpid : gpid_of(host_tgid_of(cur_)));
        return forward_sync([this, ret, group](std::int64_t host) {
            if (host == 0) host_groups_.insert(group);
            set_ret_now(ret);
        });
    }

    // Run the trapped TIOCSPGRP on the host with the group as a host id, so
    // the real tty sends ^C/^Z/SIGTTIN to the right job. The guest's pid_t
    // is put back afterwards.
    [[nodiscard]] Result<std::int64_t> mirror_tcsetpgrp(std::uint64_t argp, std::int32_t gpgid,
                                                        std::int64_t ret) {
        const ::pid_t hg = host_tid_of(gpgid);
        if (hg <= 0 || !argp) return forward_sync_then_set(ret);
        std::array<std::byte, 4> saved{};
        if (!copy_in(uaddr(argp), saved)) return forward_sync_then_set(ret);
        std::array<std::byte, 4> hb{};
        std::memcpy(hb.data(), &hg, 4);
        if (!copy_out(uaddr(argp), hb)) return forward_sync_then_set(ret);
        return forward_sync([this, ret, argp, saved](std::int64_t) {
            (void)copy_out(uaddr(argp), saved);
            set_ret_now(ret);
        });
    }

    // Walk sendmsg's control buffer for SCM_CREDENTIALS and replace the
    // guest's {pid, uid, gid} with the host task's, remembering the guest
    // bytes so they can be put back after the call. Root in the guest may
    // name any of its own processes; anything else is left for the kernel
    // to refuse.
    void rewrite_scm_creds(::pid_t w, std::uint64_t msg, Task& t) {
        auto peek = [&](std::uint64_t a, std::uint64_t& out) {
            errno = 0;
            const long v = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(a), 0);
            if (errno) return false;
            out = static_cast<std::uint64_t>(v);
            return true;
        };
        std::uint64_t ctl = 0, ctllen = 0;
        if (!msg || !peek(msg + 32, ctl) || !peek(msg + 40, ctllen) || !ctl) return;
        std::uint64_t off = 0;
        while (off + 16 <= ctllen) {
            std::uint64_t len = 0, lt = 0;
            if (!peek(ctl + off, len) || !peek(ctl + off + 8, lt) || len < 16) return;
            const auto level = static_cast<std::uint32_t>(lt), type = static_cast<std::uint32_t>(lt >> 32);
            if (level == 1 /*SOL_SOCKET*/ && type == 2 /*SCM_CREDENTIALS*/ && len >= 28) {
                std::uint64_t w0 = 0, w1 = 0;
                const std::uint64_t at = ctl + off + 16;
                if (!peek(at, w0) || !peek(at + 8, w1)) return;
                const auto gp = static_cast<std::int32_t>(static_cast<std::uint32_t>(w0));
                const ::pid_t hp = host_tgid_of(host_tid_of(gp) > 0 ? host_tid_of(gp) : w);
                const auto hu = static_cast<std::uint64_t>(::getuid());
                const auto hg = static_cast<std::uint64_t>(::getgid());
                const std::uint64_t n0 = static_cast<std::uint32_t>(hp) | (hu << 32);
                const std::uint64_t n1 = (w1 & ~0xffffffffull) | hg;
                ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at), reinterpret_cast<void*>(n0));
                ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at + 8), reinterpret_cast<void*>(n1));
                t.on_exit = [w, at, w0, w1](std::int64_t) {
                    ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at), reinterpret_cast<void*>(w0));
                    ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(at + 8), reinterpret_cast<void*>(w1));
                };
                return;
            }
            off += (len + 7) & ~std::uint64_t{7};
        }
    }

    // The siginfo a guest queues names its sender as the guest sees it, and
    // the kernel passes si_pid/si_uid through untouched for SI_QUEUE, to
    // itself or another process (measured on x86-64 and Android). It used
    // to be rewritten to the host pid and uid, so sigtimedwait saw a pid
    // that doesn't exist in the guest. Nothing to fix.
    void fix_queued_siginfo(::pid_t, std::uint64_t, Task&) {}

    // clone/clone3 with CLONE_PARENT_SETTID store the child's tid in the
    // parent's memory, and that's what glibc keeps as the thread's tid
    // (pthread_kill, pthread_getattr_np use it). It is the host tid; make it
    // the guest's. CLONE_CHILD_SETTID's copy lives in the child, which reads
    // gettid() (already translated) for the same field, so it's left.
    void translate_clone_tids(::pid_t w, const Regs& r, ::pid_t host, std::int32_t g) {
        constexpr std::uint64_t kParentSettid = 0x00100000;
        std::uint64_t flags = 0, ptid = 0;
        const abi::Sysno sc = abi::decode(kTraceeArch, r.nr());
        if (sc == abi::Sysno::clone3) {
            // struct clone_args { u64 flags, pidfd, child_tid, parent_tid, ... }
            errno = 0;
            const long f = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(r.arg(0)), 0);
            const long p = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(r.arg(0) + 24), 0);
            if (errno) return;
            flags = static_cast<std::uint64_t>(f);
            ptid = static_cast<std::uint64_t>(p);
        } else if (sc == abi::Sysno::clone) {
            flags = r.arg(0);
            ptid = r.arg(2);   // same slot on x86-64 and aarch64
        } else {
            return;
        }
        if (!(flags & kParentSettid) || ptid == 0) return;
        errno = 0;
        const long word = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(ptid), 0);
        if (errno || static_cast<::pid_t>(static_cast<std::uint32_t>(word)) != host) return;
        const auto uw = (static_cast<std::uint64_t>(word) & ~0xffffffffull) | static_cast<std::uint32_t>(g);
        ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(ptid), reinterpret_cast<void*>(uw));
    }

    // Which argument of `sc` is a pid/tid the host would resolve, or -1.
    [[nodiscard]] static int pid_arg_of(abi::Sysno sc) noexcept {
        using S = abi::Sysno;
        switch (sc) {
            case S::sched_setaffinity: case S::sched_setscheduler:
            case S::sched_getscheduler: case S::sched_setparam:
            case S::sched_getparam: case S::sched_rr_get_interval:
            case S::sched_setattr: case S::sched_getattr:
            case S::prlimit64: case S::process_vm_readv:
            case S::process_vm_writev: case S::kcmp:
            case S::rt_sigqueueinfo:
                return 0;
            case S::ioprio_get: case S::ioprio_set:
            case S::perf_event_open:   // (attr, pid, cpu, group_fd, flags)
                return 1;
            default:
                return -1;
        }
    }

    // Reverse of gpid_of: a guest pid -> its host tid, or -1. pid 1 is the
    // root task.
    //
    // Only guest pids. This used to also accept a raw traced host tid, from
    // when fork returned host pids to the guest; it doesn't any more, and on
    // a host with a small pid_max (Android's is 32768) host pids wrap into
    // the same range guest pids reach, so waitpid(child) sometimes landed on
    // an unrelated tracee and got ECHILD.
    [[nodiscard]] ::pid_t host_tid_of(std::int32_t pid) const {
        if (host_pids_) return pid > 0 ? static_cast<::pid_t>(pid) : -1;
        if (pid == 1) return root_pid_;
        if (auto it = host_of_gpid_.find(pid); it != host_of_gpid_.end()) return it->second;
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

    // Write a path string into the current task. One process_vm_writev (it
    // has landed before it returns, and the task is stopped) instead of a
    // ptrace call per 8 bytes. copy_out falls back to pokes when the vm
    // write is refused (non-dumpable task, read-only page).
    [[nodiscard]] bool poke_path(std::uint64_t at, const std::string& s,
                                 bool dead_scratch = false) const {
        if (copy_out(uaddr(at), std::span<const std::byte>{
                reinterpret_cast<const std::byte*>(s.c_str()), s.size() + 1}))
            return true;
        return dead_scratch ? poke_scratch(at, s) : poke_bytes(at, s);
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
    // pid 1 exited: shut the rest of the tree down WITHOUT leaving the
    // dispatch loop.
    //
    // The survivors are detached daemons (gpg-agent, dirmngr) or foreground
    // children still running when the session leader exited -- pacman
    // mid-transaction, say. They get a CATCHABLE SIGTERM first, so pacman can
    // unlink db.lck and roll back instead of leaving a half-written local DB,
    // then SIGKILL after a 2s grace window for anything that ignores it.
    //
    // That grace window used to resume every task with PTRACE_CONT. Under
    // seccomp a syscall stop resumed that way runs the call NATIVELY,
    // untranslated, against the host filesystem -- so for two seconds after
    // init died every guest process was outside its root. python's
    // forkserver child, mid-import, opened /usr/lib/python3.14/threading.py
    // on the HOST and died with "No module named 'threading'", and pacman's
    // own cleanup was unlinking a host path instead of its lock. Now next()
    // keeps serving the survivors normally until they exit or the deadline
    // passes, and kill_remaining() ends it.
    void begin_drain() {
        draining_ = true;
        drain_deadline_ = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(2000);
        // Block SIGCHLD so next() can sigtimedwait for it: a blocked signal
        // pends even under the default (ignore) disposition, so a state
        // change can never slip in unnoticed between waitpid and the wait.
        ::sigset_t chld;
        ::sigemptyset(&chld);
        ::sigaddset(&chld, SIGCHLD);
        (void)::pthread_sigmask(SIG_BLOCK, &chld, nullptr);
        for (const auto& [tid, _] : tasks_) {
            ::kill(tid, SIGCONT);
            ::kill(tid, SIGTERM);
        }
    }

    // Grace window over: force down whatever ignored SIGTERM (a detached
    // daemon) and drain its exit so no zombie is left behind.
    void kill_remaining() {
        for (const auto& [tid, _] : tasks_) {
            ::ptrace(PTRACE_KILL, tid, 0, 0);
            ::kill(tid, SIGKILL);
            for (;;) {
                int st = 0;
                const ::pid_t r = ::waitpid(tid, &st, __WALL);
                if (r <= 0 || WIFEXITED(st) || WIFSIGNALED(st)) break;
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
        if (t.on_exit) {
            Regs r{};
            (void)Regs::fetch(w, r);
            auto fn = std::exchange(t.on_exit, {});
            fn(static_cast<std::int64_t>(r.ret()));
            // a deferred redirect owns its result; a forwarded call that only
            // borrowed a buffer still gets the usual translations below
            if (t.action != Action::none || !t.forwarded) {
                t.forwarded = false;
                // the call is over. Without seccomp in_call is what tells the
                // next stop's entry from an exit; left set, the guest's next
                // syscall (a getpid after connect) was taken for this one's
                // exit and ran unanswered, returning a host pid. on_exit may
                // already have restarted it (wait_then_retry), which is fine:
                // the rerun is a fresh entry either way.
                if (t.in_call) sys_done(w);
                return;
            }
        }
        t.forwarded = false;
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
            // -ERESTART*: the call will run again, re-entering as a fresh
            // syscall that we translate once more. With the args we already
            // translated still in place a pid was mapped twice; inside a pid
            // namespace, where guest and host numbers overlap, wait4(guest 2)
            // = wait4(host 4) became wait4(host 6) and the parent got ECHILD.
            if (const auto rv = static_cast<long long>(r.ret()); rv <= -512 && rv >= -516) {
                // x86-64 restarts from the registers as they are now, so put
                // the guest's own back. aarch64 restarts arg 0 from orig_x0,
                // which the kernel saved before we rewrote x0 (and x0 holds
                // the return here), so only x1-x5 need it.
                bool moved = false;
                for (int k = 0; k < 6; ++k)
                    if (r.arg(k) != t.guest_regs.arg(k) &&
                        (kTraceeArch != abi::Arch::aarch64 || k != 0)) {
                        r.set_arg(k, t.guest_regs.arg(k));
                        moved = true;
                    }
                if (moved) (void)r.store(w);
                t.action = Action::none;
                sys_done(w);
                return;
            }
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
            } else if (abi::decode(kTraceeArch, r.nr()) == abi::Sysno::rt_sigtimedwait) {
                // the returned siginfo (arg 1) of a SIGCHLD names the child by
                // its host pid; other senders already carry a guest pid
                const auto ret = static_cast<long long>(r.ret());
                const std::uint64_t infop = r.arg(1);
                if (ret == SIGCHLD && infop != 0) {
                    errno = 0;
                    const long word = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(infop + 16), 0);
                    const long code = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(infop + 8), 0);
                    const auto c = static_cast<std::int32_t>(code & 0xffffffff);
                    if (errno == 0 && c >= CLD_EXITED && c <= CLD_CONTINUED) {
                        const auto host = static_cast<std::int32_t>(static_cast<std::uint32_t>(word & 0xffffffffu));
                        if (const std::int32_t g = host > 0 ? chld_gpid(w, host) : 0; g > 0 && g != host) {
                            auto uw = static_cast<std::uint64_t>(word);
                            uw = (uw & ~0xffffffffull) | static_cast<std::uint32_t>(g);
                            ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(infop + 16), reinterpret_cast<void*>(uw));
                        }
                    }
                }
            } else if (abi::decode(kTraceeArch, r.nr()) == abi::Sysno::recvfrom) {
                // an answer from the DNS forwarder reads back as from port 53
                const std::uint16_t port = kernel::dns_proxy_port();
                const std::uint64_t sa = r.arg(4);
                if (port && sa && static_cast<long long>(r.ret()) >= 0) {
                    errno = 0;
                    const long word = ::ptrace(PTRACE_PEEKDATA, w, reinterpret_cast<void*>(sa), 0);
                    if (errno == 0) {
                        const auto u = static_cast<std::uint64_t>(word);
                        const std::uint16_t fam = static_cast<std::uint16_t>(u & 0xffff);
                        const std::uint16_t p_be = static_cast<std::uint16_t>((u >> 16) & 0xffff);
                        const std::uint16_t p = static_cast<std::uint16_t>((p_be >> 8) | (p_be << 8));
                        const std::uint32_t a = static_cast<std::uint32_t>(u >> 32);
                        std::uint32_t want = 0;
                        std::memcpy(&want, kernel::kDnsGuestAddr.data(), 4);
                        if (fam == AF_INET && p == port && a == want) {
                            const std::uint64_t nw = (u & ~0xffff0000ull) | (std::uint64_t{0x3500} << 16);
                            ::ptrace(PTRACE_POKEDATA, w, reinterpret_cast<void*>(sa), reinterpret_cast<void*>(nw));
                        }
                    }
                }
            } else if (is_getlk(r)) {
                translate_getlk(w, r);
            } else if (is_peercred(r)) {
                translate_peercred(w, r);
            } else if (is_recv_creds(r, w)) {
                translate_recv_creds(w, r);
            } else if (ipc_pid_field(r)) {
                translate_ipc_pids(w, r);
            } else if (returns_pid(r.nr())) {
                auto host = static_cast<::pid_t>(static_cast<long long>(r.ret()));
                if (host > 0) {
                    const std::int32_t g = gpid_of(host);
                    // as the caller's pid namespace numbers it
                    const std::int32_t me = gpid_of(host_tgid_of(w));
                    const std::int32_t l = local_pid(me, g);
                    r.set_ret(static_cast<std::int64_t>(l > 0 ? l : g));
                    (void)r.store(w);
                    // entry regs: on aarch64 x0 is already the return value
                    translate_clone_tids(w, t.regs, host, l > 0 ? l : g);
                }
            }
        }
        t.action = Action::none;
        sys_done(w);
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

    // From an exit stop rewound onto the syscall instruction, run to the
    // next syscall-ENTRY stop (that same instruction). False if it died.
    bool step_to_entry(::pid_t w) {
        for (;;) {
            ::ptrace(PTRACE_SYSCALL, w, 0, 0);
            int st = 0;
            if (::waitpid(w, &st, __WALL) != w) return false;
            if (WIFEXITED(st) || WIFSIGNALED(st)) return false;
            if (!WIFSTOPPED(st)) return false;
            if (WSTOPSIG(st) == (SIGTRAP | 0x80)) return true;   // the entry stop
            if (WSTOPSIG(st) == SIGTRAP && (st >> 16) == PTRACE_EVENT_SECCOMP) return true;
            // a signal arrived first: hold it for after the chain
            if (WSTOPSIG(st) != SIGTRAP && (st >> 16) == 0)
                if (auto it = tasks_.find(w); it != tasks_.end()) it->second.pending_sig = WSTOPSIG(st);
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
                if (!strict_tgids_.empty()) strict_tgids_.erase(w);
                gt_on_exit(w, st);
                if (const std::int32_t g = exited_gpid(w)) {
                    const auto tc = tgid_cache_.find(w);
                    const bool leader = tc == tgid_cache_.end() || tc->second == w;
                    if (leader && w != root_pid_) {
                        proc_events_.push_back({ProcEvent::zombie, g, 0, {}, {}});
                        zombies_[g] = w;
                    } else {
                        proc_events_.push_back({ProcEvent::reap, g, 0, {}, {}});
                    }
                    reparent_orphans_of(g);
                }
                // Retained past exit — see the note in next(): the parent's
                // wait4 still needs to translate this reaped pid.
                tasks_.erase(w);
                stopped_.erase(w);
                stop_owed_.erase(w);
                tgid_cache_.erase(w);
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
                const bool is_thread = np && event == PTRACE_EVENT_CLONE &&
                                       tgid_of(child) == host_tgid_of(w);
                if (np && !is_thread) {
                    const std::int32_t gppid = gpid_of(host_tgid_of(w));
                    gppid_[gpid_of(child)] = gppid;
                    tgid_cache_[child] = child;
                    proc_events_.push_back({ProcEvent::spawn, gpid_of(child),
                                            gppid, {}, {}});
                    ig_inherit(host_tgid_of(w), child);
                } else if (np) {
                    note_thread(w, child);
                }
                // traced with fork/clone options: the child becomes a tracee;
                // the parent's event stop is shown once this call returns
                gt_on_fork_event(w, event, child);
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
                ig_forget(host_tgid_of(w));
                gt_on_exec(w);
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
            if ((sig == SIGSEGV || sig == SIGBUS) && ig_fixup_fault(w)) {
                ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
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
        // a kill(2) we had to queue: the tracer may set SI_USER, so it does
        if (si.si_code == SI_QUEUE && si.si_value.sival_int == kKillMark) {
            si.si_code = SI_USER;
            si.si_value.sival_int = 0;
            ::ptrace(PTRACE_SETSIGINFO, w, 0, &si);
            return;
        }

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

    // A known guest pid for a host id we have ALREADY seen, or 0.
    static constexpr int kKillMark = 0x4c58eb1d;
public:
    // The guest uid of the task about to send a signal (set per kill).
    void set_sender_uid(std::uint32_t u) noexcept { sender_uid_ = u; }
private:
    std::uint32_t sender_uid_{0};

    // The guest pid for a host id we have ALREADY seen, or 0. Pure lookup, so
    // it cannot perturb the pid allocator the way gpid_of does.
    [[nodiscard]] std::int32_t known_gpid_of(::pid_t host) const {
        if (host == root_pid_) return init_gpid();
        if (host_pids_) {
            // ours only if we trace it (or did): a host stranger is not
            if (tasks_.count(host) || gppid_.count(static_cast<std::int32_t>(host)))
                return static_cast<std::int32_t>(host);
            for (const auto& [tid, _] : tasks_) {
                auto c = tgid_cache_.find(tid);
                if ((c != tgid_cache_.end() ? c->second : tgid_of(tid)) == host)
                    return static_cast<std::int32_t>(host);
            }
            return 0;
        }
        if (auto it = gpid_.find(host); it != gpid_.end()) return it->second;
        // si_pid carries the sender's THREAD-GROUP id; our map is keyed by
        // the tid we attached to. They differ only once the group's leader
        // thread is gone, so look among the live tasks for one in that group.
        for (const auto& [tid, _] : tasks_) {
            auto c = tgid_cache_.find(tid);
            const ::pid_t tg = c != tgid_cache_.end() ? c->second : tgid_of(tid);
            if (tg == host)
                if (auto it = gpid_.find(tid); it != gpid_.end()) return it->second;
        }
        return 0;
    }

    // A host task's thread-group id, from /proc. Returns 0 when unknown.
    [[nodiscard]] static ::pid_t tgid_of(::pid_t tid) { return status_field(tid, "Tgid:"); }

    // When a process dies the kernel hands its children to the nearest
    // subreaper, or init. The host already did that (prctl is forwarded),
    // so read where each child went and say the same in guest pids. Only
    // a parent outside the tree means init, which is pid 1 here.
    void reparent_orphans_of(std::int32_t dead) {
        for (auto& [child, parent] : gppid_) {
            if (parent != dead || child == dead) continue;
            const ::pid_t host = host_tid_of(child);
            if (host <= 0) continue;
            const ::pid_t hp = status_field(host, "PPid:");
            if (hp <= 0) continue;   // gone already
            std::int32_t np = known_gpid_of(hp);
            // with host pids the new parent is the host's answer as is
            if (host_pids_) np = static_cast<std::int32_t>(hp);
            else if (np <= 0 || np == dead) np = 1;
            parent = np;
            proc_events_.push_back({ProcEvent::reparent, child, np, {}, {}});
        }
    }

    // One numeric field ("Tgid:", "PPid:") of /proc/<tid>/status, or 0.
    [[nodiscard]] static ::pid_t status_field(::pid_t tid, const char* key) {
        char path[64];
        std::snprintf(path, sizeof path, "/proc/%d/status", static_cast<int>(tid));
        std::FILE* f = std::fopen(path, "r");
        if (f == nullptr) return 0;
        char line[256];
        const std::size_t kl = std::strlen(key);
        ::pid_t out = 0;
        while (std::fgets(line, sizeof line, f) != nullptr) {
            if (std::strncmp(line, key, kl) == 0) {
                out = static_cast<::pid_t>(std::atoi(line + kl));
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
    std::function<std::pair<std::uint32_t, std::uint32_t>(std::int32_t)> guest_ids_of_;
    std::function<std::int32_t(std::int32_t, std::int32_t)> pid_to_local_, pid_to_global_;
    // guest process groups that also exist on the host (setpgid mirrored)
    std::unordered_set<std::int32_t> host_groups_;
    // tasks parked in a group-stop (kill -STOP, ^Z) until a SIGCONT
    std::unordered_set<::pid_t> stopped_;
    // SIGSTOPs we sent that the task hasn't taken yet (see the attach stop)
    std::unordered_set<::pid_t> stop_owed_;
    // children whose fork event has been handled, and ones that exited first
    std::unordered_set<::pid_t> announced_, exited_early_;
    std::unordered_map<::pid_t, std::int32_t> gpid_;   // host tid -> guest pid
    std::unordered_map<std::int32_t, ::pid_t> host_of_gpid_; // guest pid -> host tid
    std::unordered_map<std::int32_t, std::int32_t> gppid_; // guest pid -> ppid
    // host tid -> host tgid. A task's tgid is fixed for its lifetime, and
    // tgid_of() reads /proc, so this is looked up once per task rather than
    // once per syscall.
    std::unordered_map<::pid_t, ::pid_t> tgid_cache_;
    std::int32_t next_gpid_{2};                        // pid 1 = root/init
    ::pid_t cur_{-1};
    ::pid_t root_pid_{-1};
    bool booted_root_{false};      // root's bootstrap execve(path_) has completed
    // Instance mode: no root program; sessions come from spawn().
    bool instance_{false};
    bool stop_requested_{false};
    std::set<::pid_t> bootstrapping_;   // spawned, first execve not done yet
    std::function<bool(int, bool)> idle_;
    std::chrono::steady_clock::time_point last_poll_{};
    std::function<void(::pid_t, std::int32_t, int)> on_exit_;
    std::function<void()> flush_events_;
    int chld_fd_{-1};
    [[nodiscard]] bool booting(::pid_t w) const {
        return (w == root_pid_ && !booted_root_) || bootstrapping_.count(w) != 0;
    }
    int chld_fd() {
        if (chld_fd_ < 0) {
            ::sigset_t s;
            ::sigemptyset(&s);
            ::sigaddset(&s, SIGCHLD);
            (void)::pthread_sigmask(SIG_BLOCK, &s, nullptr);
            chld_fd_ = ::signalfd(-1, &s, SFD_NONBLOCK | SFD_CLOEXEC);
        }
        return chld_fd_;
    }
    void drain_chld_fd() {
        if (chld_fd_ < 0) return;
        ::signalfd_siginfo si[8];
        while (::read(chld_fd_, si, sizeof si) > 0) {}
    }
public:
    // Instance mode. `idle(chld_fd, may_block)` serves the supervisor's own
    // fds: with may_block it should wait on them plus chld_fd (readable when
    // a task changed state), without it just take what is ready. Return
    // false to shut the instance down.
    void set_idle(std::function<bool(int, bool)> f) { idle_ = std::move(f); }
    // Called for every process that exits: (host pid, guest pid, status).
    void set_on_exit(std::function<void(::pid_t, std::int32_t, int)> f) { on_exit_ = std::move(f); }
    void set_flush_events(std::function<void()> f) { flush_events_ = std::move(f); }
    void request_stop() { stop_requested_ = true; }
    // The current call was refused by the host: only a virtualized answer
    // can complete it.
    [[nodiscard]] bool refused_call() const {
        auto it = tasks_.find(cur_);
        return it != tasks_.end() && it->second.refused;
    }
    // Graceful stop: SIGTERM everything, SIGKILL what's left after the grace.
    void shutdown() { if (!draining_) begin_drain(); }
    [[nodiscard]] bool instance() const noexcept { return instance_; }
    [[nodiscard]] int live_count() const noexcept { return live_; }
private:
    int exit_code_{0};
    int live_{0};
    bool exited_{false};
    // Set once pid 1 exits: the survivors are being shut down but are still
    // served through the normal dispatch path until drain_deadline_.
    bool draining_{false};
    std::chrono::steady_clock::time_point drain_deadline_{};
    bool host_pids_{false};        // --host-pids: guest pids are host pids
    std::function<void(std::int64_t)> before_resume_{};
    int blob_arg_{-1};             // set_arg_blob: pending for the next redirect
    std::string blob_{};
    std::set<::pid_t> pending_real_netns_;   // clones making a real netns
    bool seccomp_{false};          // trap filter active -> drive with PTRACE_CONT
    int base_opts_{0};             // linuxity's own ptrace options on every task
    std::unordered_map<::pid_t, Task> tasks_;
#include "linuxity/runtime/linux/guest_ptrace.inc"
#include "linuxity/runtime/linux/inguest.inc"

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
