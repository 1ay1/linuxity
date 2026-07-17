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
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

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
                if (np && tasks_.emplace(static_cast<::pid_t>(np), Task{}).second)
                    ++live_;   // may already be counted if it stopped first
                ::ptrace(PTRACE_SYSCALL, w, 0, 0);
                continue;
            }
            if (event == PTRACE_EVENT_EXEC) {
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
    // task's stack scratch), then forward. The kernel's result (e.g. a real
    // fd) lands in RAX by itself. We can't observe it synchronously, so we
    // best-effort return 0; fd->path binding for redirects that need it is
    // handled by re-reading RAX would require an exit hook — for the common
    // case (ld.so mmaping libs) the fd is used immediately and doesn't need
    // our path table, so 0 is fine.
    [[nodiscard]] Result<std::int64_t> redirect(int path_arg,
                                                const std::string& host_path) {
        Task& t = tasks_[cur_];
        struct user_regs_struct r = t.regs;
        std::uint64_t scratch = (t.regs.rsp - 8192) & ~std::uint64_t{15};
        std::vector<std::byte> bytes(host_path.size() + 1);
        std::memcpy(bytes.data(), host_path.c_str(), host_path.size() + 1);
        if (!copy_out(uaddr(scratch), bytes)) return err<std::int64_t>(Errno::efault);
        set_arg(r, path_arg, scratch);
        ::ptrace(PTRACE_SETREGS, cur_, 0, &r);
        t.action = Action::none;
        ::ptrace(PTRACE_SYSCALL, cur_, 0, 0);
        return ok(std::int64_t{0});
    }

    static void set_arg(struct user_regs_struct& r, int n, std::uint64_t v) {
        switch (n) {
            case 0: r.rdi = v; break;  case 1: r.rsi = v; break;
            case 2: r.rdx = v; break;  case 3: r.r10 = v; break;
            case 4: r.r8  = v; break;  case 5: r.r9  = v; break;
            default: break;
        }
    }

    [[nodiscard]] bool exited() const noexcept { return exited_; }
    [[nodiscard]] int exit_code() const noexcept { return exit_code_; }

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

    std::string path_;
    std::vector<std::string> argv_;
    std::vector<std::string> envp_;
    std::string root_;
    ::pid_t cur_{-1};
    ::pid_t root_pid_{-1};
    int exit_code_{0};
    int live_{0};
    bool exited_{false};
    std::unordered_map<::pid_t, Task> tasks_;
};

static_assert(SyscallTrap<PtraceTrap>, "PtraceTrap must model SyscallTrap");

} // namespace lx::runtime
