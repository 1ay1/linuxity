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

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cerrno>

#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <fcntl.h>

namespace lx::runtime {

class PtraceTrap {
public:
    PtraceTrap(std::string path, std::vector<std::string> argv,
               std::vector<std::string> envp = {}, std::string root = {})
        : path_{std::move(path)}, argv_{std::move(argv)},
          envp_{std::move(envp)}, root_{std::move(root)} {}

    [[nodiscard]] Status start(UAddr, UAddr) {
        ::pid_t pid = ::fork();
        if (pid < 0) return err(Errno::eagain);
        if (pid == 0) {
            if (!root_.empty()) {
                if (::chroot(root_.c_str()) == 0) (void)::chdir("/");
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
        ::ptrace(PTRACE_SETOPTIONS, pid, 0,
                 PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD |
                 PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                 PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
        root_pid_ = pid;
        tasks_[pid];                       // create, at-entry state
        ::ptrace(PTRACE_SYSCALL, pid, 0, 0);
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
                if (auto it = gpid_.find(w); it != gpid_.end()) {
                    proc_events_.push_back({ProcEvent::reap, it->second, 0, {}, {}});
                    gpid_.erase(it);
                }
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
                ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
            if (event == PTRACE_EVENT_EXEC) {
                // The image was replaced: the pid keeps its number but becomes
                // a new program. Recover its new comm from /proc/<tid>/comm on
                // the HOST (the child is mid-exec; this is the real name).
                proc_events_.push_back({ProcEvent::exec, gpid_of(w), 0,
                                        comm_of(w), cmdline_of(w)});
                tasks_[w] = Task{};        // fresh image, back at-entry
                ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
            // The initial SIGSTOP/ SIGTRAP of a freshly-attached child.
            if (sig == SIGSTOP || sig == SIGTRAP) {
                tasks_.try_emplace(w);
                ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
            // A real syscall stop (TRACESYSGOOD => SIGTRAP|0x80).
            if (sig == (SIGTRAP | 0x80)) {
                Task& t = tasks_[w];
                struct user_regs_struct rr{};
                ::ptrace(PTRACE_GETREGS, w, 0, &rr);
                // The kernel primes RAX to -ENOSYS at syscall-ENTRY and
                // overwrites it with the result at EXIT. This is the robust,
                // state-free way to tell the two stops apart (surviving
                // fork/exec/attach without a fragile per-task toggle).
                bool is_entry = (static_cast<long long>(rr.rax) == -38 /*ENOSYS*/)
                                && !t.in_call;
                if (is_entry) {
                    cur_ = w;
                    t.regs = rr;
                    t.in_call = true;
                    f.regs.nr     = rr.orig_rax;
                    f.regs.arg[0] = rr.rdi; f.regs.arg[1] = rr.rsi;
                    f.regs.arg[2] = rr.rdx; f.regs.arg[3] = rr.r10;
                    f.regs.arg[4] = rr.r8;  f.regs.arg[5] = rr.r9;
                    f.pc          = rr.rip;
                    return ok(true);
                }
                // EXIT stop: finalize the action recorded at entry.
                finalize_exit(w, t);
                ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
            // Any other signal: deliver it to the task.
            ::ptrace(PTRACE_SYSCALL, w, 0, sig);
        }
    }

    // VIRTUALIZE: neutralize the syscall now; write `ret` into RAX at exit.
    [[nodiscard]] Status resume(std::int64_t ret) {
        Task& t = tasks_[cur_];
        struct user_regs_struct r = t.regs;
        r.orig_rax = static_cast<unsigned long long>(-1);
        ::ptrace(PTRACE_SETREGS, cur_, 0, &r);
        t.action = Action::set_ret;
        t.ret = ret;
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);   // run to exit; don't block here
        return ok();
    }

    // FORWARD: let the host kernel run this syscall in the task. We report the
    // result asynchronously as 0 (the loop doesn't need it for a plain
    // forward); the real value lands in the guest's RAX by the kernel itself.
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
                                                const std::string& host_path) {
        Task& t = tasks_[cur_];
        struct user_regs_struct r = t.regs;
        // Park the translated path in the child's own stack, just below the
        // current stack pointer. The SysV red zone (128B) plus a small margin
        // keeps us clear of live frames, and staying within a few hundred
        // bytes of rsp guarantees the target lies in an already-mapped stack
        // page (rsp-8KB could fall past the mapped stack of a freshly-exec'd
        // task, where process_vm_writev faults with EFAULT). Path arguments
        // are short, so a modest scratch window is ample.
        std::size_t need = host_path.size() + 1;
        std::uint64_t scratch =
            (t.regs.rsp - 256 - need) & ~std::uint64_t{15};
        std::vector<std::byte> bytes(need);
        std::memcpy(bytes.data(), host_path.c_str(), need);
        if (!copy_out(uaddr(scratch), bytes))
            return err<std::int64_t>(Errno::efault);
        set_arg(r, path_arg, scratch);
        ::ptrace(PTRACE_SETREGS, cur_, 0, &r);
        if (!step_to_exit(cur_)) return ok(std::int64_t{-1});   // task exited
        struct user_regs_struct rr{};
        ::ptrace(PTRACE_GETREGS, cur_, 0, &rr);
        std::int64_t ret = static_cast<std::int64_t>(rr.rax);
        tasks_[cur_].in_call = false;
        // Resume the task toward its next syscall (we consumed its exit stop).
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);
        return ok(ret);
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

private:
    enum class Action { none, set_ret };
    struct Task {
        bool in_call{false};   // currently between an ENTRY and its EXIT stop
        Action action{Action::none};
        std::int64_t ret{0};
        struct user_regs_struct regs{};
    };

    // At a task's syscall-EXIT stop, apply the action recorded at entry.
    void finalize_exit(::pid_t w, Task& t) {
        if (t.action == Action::set_ret) {
            struct user_regs_struct r{};
            ::ptrace(PTRACE_GETREGS, w, 0, &r);
            r.rax = static_cast<unsigned long long>(t.ret);
            ::ptrace(PTRACE_SETREGS, w, 0, &r);
        }
        t.action = Action::none;
        t.in_call = false;
    }

    // Step ONE task from its syscall-ENTRY stop to its syscall-EXIT stop,
    // transparently passing any PTRACE_EVENT (fork/exec) stops. Used by the
    // SYNCHRONOUS redirect(); safe because path syscalls never block on a
    // sibling. Returns false if the task exited during the syscall.
    bool step_to_exit(::pid_t w) {
        ::ptrace(PTRACE_SYSCALL, w, 0, 0);
        for (;;) {
            int st = 0;
            if (::waitpid(w, &st, __WALL) < 0) return false;
            if (WIFEXITED(st) || WIFSIGNALED(st)) {
                int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
                if (w == root_pid_) exit_code_ = code;
                if (auto it = gpid_.find(w); it != gpid_.end()) {
                    proc_events_.push_back({ProcEvent::reap, it->second, 0, {}, {}});
                    gpid_.erase(it);
                }
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
            if (WSTOPSIG(st) == (SIGTRAP | 0x80)) return true;   // the exit stop
            ::ptrace(PTRACE_SYSCALL, w, 0,
                     WSTOPSIG(st) == SIGTRAP ? 0 : WSTOPSIG(st));
        }
    }

    std::string path_;
    std::vector<std::string> argv_;
    std::vector<std::string> envp_;
    std::string root_;
    std::vector<ProcEvent> proc_events_;
    std::unordered_map<::pid_t, std::int32_t> gpid_;   // host tid -> guest pid
    std::unordered_map<std::int32_t, std::int32_t> gppid_; // guest pid -> ppid
    std::int32_t next_gpid_{2};                        // pid 1 = root/init
    ::pid_t cur_{-1};
    ::pid_t root_pid_{-1};
    int exit_code_{0};
    int live_{0};
    bool exited_{false};
    std::unordered_map<::pid_t, Task> tasks_;
};

static_assert(SyscallTrap<PtraceTrap>, "PtraceTrap must model SyscallTrap");

} // namespace lx::runtime
