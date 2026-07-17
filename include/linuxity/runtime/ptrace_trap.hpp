// linuxity/runtime/ptrace_trap.hpp
//
// A real, native-execution SyscallTrap backend using ptrace.
//
// The traced child executes its own instructions DIRECTLY on the host CPU at
// native speed. Its syscalls stop back into us at syscall-entry; for each we
// choose one of two fates:
//
//   * VIRTUALIZE — we service it from linuxity's subsystems and skip the real
//     syscall (getpid, uname, our identity/credential world). Implemented by
//     rewriting the syscall number to -1 (invalid) so the host kernel runs a
//     no-op, then overwriting the return register with our value.
//
//   * FORWARD — we let the real host kernel run it IN THE CHILD (mmap, brk,
//     mprotect, and — for now — file I/O against a mounted rootfs). This is
//     how the child gets real pages in its own address space and how native
//     libc reaches main(). We observe the result on syscall-exit.
//
// Ordinary instructions never trap; only syscalls pay a stop/continue. This
// models runtime::SyscallTrap (+ abi::GuestMem via process_vm_*).
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
#include <vector>

namespace lx::runtime {

class PtraceTrap {
public:
    PtraceTrap(std::string path, std::vector<std::string> argv,
               std::vector<std::string> envp = {}, std::string root = {})
        : path_{std::move(path)}, argv_{std::move(argv)},
          envp_{std::move(envp)}, root_{std::move(root)} {}

    [[nodiscard]] Status start(UAddr /*entry*/, UAddr /*sp*/) {
        pid_ = ::fork();
        if (pid_ < 0) return err(Errno::eagain);
        if (pid_ == 0) {
            // Optionally enter the guest rootfs (needs privilege; if it
            // fails we run against the host fs, still useful for bring-up).
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
        ::waitpid(pid_, &st, 0);
        ::ptrace(PTRACE_SETOPTIONS, pid_, 0, PTRACE_O_EXITKILL);
        return ok();
    }

    // Advance to the next syscall-ENTRY stop and fill `f`. Returns false on
    // guest exit. We stop at every syscall so the dispatcher can decide its
    // fate; the actual execution is controlled by resume()/forward().
    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        if (!at_entry_) {
            if (::ptrace(PTRACE_SYSCALL, pid_, 0, 0) < 0) return err<bool>(Errno::esrch);
            int st = 0;
            ::waitpid(pid_, &st, 0);
            if (WIFEXITED(st)) { exit_code_ = WEXITSTATUS(st); return ok(false); }
            if (WIFSIGNALED(st)) { exit_code_ = 128 + WTERMSIG(st); return ok(false); }
        }
        at_entry_ = false;

        ::ptrace(PTRACE_GETREGS, pid_, 0, &last_);
        f.regs.nr     = last_.orig_rax;
        f.regs.arg[0] = last_.rdi;
        f.regs.arg[1] = last_.rsi;
        f.regs.arg[2] = last_.rdx;
        f.regs.arg[3] = last_.r10;
        f.regs.arg[4] = last_.r8;
        f.regs.arg[5] = last_.r9;
        f.pc          = last_.rip;
        return ok(true);
    }

    // VIRTUALIZE: neutralize the real syscall (set nr = -1 so the kernel
    // rejects it as ENOSYS harmlessly), then write our return value at exit.
    [[nodiscard]] Status resume(std::int64_t ret) {
        struct user_regs_struct r = last_;
        r.orig_rax = static_cast<unsigned long long>(-1); // no real syscall
        ::ptrace(PTRACE_SETREGS, pid_, 0, &r);
        // Step over the (neutralized) syscall to its exit stop.
        int st = 0;
        ::ptrace(PTRACE_SYSCALL, pid_, 0, 0);
        ::waitpid(pid_, &st, 0);
        if (WIFEXITED(st)) { exit_code_ = WEXITSTATUS(st); exited_ = true; return ok(); }
        // Overwrite the return register with linuxity's answer.
        ::ptrace(PTRACE_GETREGS, pid_, 0, &r);
        r.rax = static_cast<unsigned long long>(ret);
        ::ptrace(PTRACE_SETREGS, pid_, 0, &r);
        return ok();
    }

    // FORWARD: let the real host kernel execute this syscall in the child,
    // then return the kernel's own result. Used for mmap/brk/mprotect (and,
    // during bring-up, file I/O against the real rootfs).
    [[nodiscard]] Result<std::int64_t> forward() {
        int st = 0;
        // Run the real syscall (regs already hold the original orig_rax).
        ::ptrace(PTRACE_SYSCALL, pid_, 0, 0);
        ::waitpid(pid_, &st, 0);
        if (WIFEXITED(st)) { exit_code_ = WEXITSTATUS(st); exited_ = true;
                             return ok(std::int64_t{0}); }
        struct user_regs_struct r{};
        ::ptrace(PTRACE_GETREGS, pid_, 0, &r);
        return ok(static_cast<std::int64_t>(r.rax));
    }

    // REDIRECT: rewrite the char* path argument in register `path_arg` to
    // point at `host_path` (written into the child's stack red-zone scratch),
    // then let the host kernel run the now-redirected syscall in the child.
    // Returns the kernel's result (e.g. the real fd for openat). This is how
    // the guest's virtual path resolves to a real host file it can mmap.
    [[nodiscard]] Result<std::int64_t> redirect(int path_arg,
                                                const std::string& host_path) {
        struct user_regs_struct r = last_;
        // Scratch lives well below the current stack pointer, in a page we
        // ensure is writable by poking it (the red-zone + a fresh page).
        std::uint64_t scratch = (last_.rsp - 8192) & ~std::uint64_t{15};
        std::vector<std::byte> bytes(host_path.size() + 1);
        std::memcpy(bytes.data(), host_path.c_str(), host_path.size() + 1);
        if (!copy_out(uaddr(scratch), bytes)) return err<std::int64_t>(Errno::efault);
        set_arg(r, path_arg, scratch);
        ::ptrace(PTRACE_SETREGS, pid_, 0, &r);
        return forward();
    }

    // Set the Nth syscall-argument register in a saved regfile.
    static void set_arg(struct user_regs_struct& r, int n, std::uint64_t v) {
        switch (n) {
            case 0: r.rdi = v; break;
            case 1: r.rsi = v; break;
            case 2: r.rdx = v; break;
            case 3: r.r10 = v; break;
            case 4: r.r8  = v; break;
            case 5: r.r9  = v; break;
            default: break;
        }
    }

    [[nodiscard]] bool exited() const noexcept { return exited_; }
    [[nodiscard]] int exit_code() const noexcept { return exit_code_; }

    // -- GuestMem: the child's pages ARE the guest memory. -----------------
    [[nodiscard]] Status copy_in(UAddr src, std::span<std::byte> dst) const {
        ::iovec local{dst.data(), dst.size()};
        ::iovec remote{reinterpret_cast<void*>(value(src)), dst.size()};
        auto n = ::process_vm_readv(pid_, &local, 1, &remote, 1, 0);
        return (n >= 0 && std::size_t(n) == dst.size()) ? ok() : err(Errno::efault);
    }
    [[nodiscard]] Status copy_out(UAddr dst, std::span<const std::byte> src) const {
        ::iovec local{const_cast<std::byte*>(src.data()), src.size()};
        ::iovec remote{reinterpret_cast<void*>(value(dst)), src.size()};
        auto n = ::process_vm_writev(pid_, &local, 1, &remote, 1, 0);
        return (n >= 0 && std::size_t(n) == src.size()) ? ok() : err(Errno::efault);
    }

private:
    std::string path_;
    std::vector<std::string> argv_;
    std::vector<std::string> envp_;
    std::string root_;
    ::pid_t pid_{-1};
    int exit_code_{0};
    bool exited_{false};
    bool at_entry_{false};
    struct user_regs_struct last_{};
};

static_assert(SyscallTrap<PtraceTrap>, "PtraceTrap must model SyscallTrap");

} // namespace lx::runtime
