// linuxity/runtime/ptrace_trap.hpp
//
// A real, native-execution SyscallTrap backend using ptrace(PTRACE_SYSEMU).
//
// This is the proof that the model works: the traced child executes its own
// instructions DIRECTLY on the host CPU at native speed. PTRACE_SYSEMU makes
// the kernel stop the child at every syscall entry WITHOUT executing it, hand
// us the register file, and wait — so *we* become the kernel for that child.
// We decode the registers into abi::Regs, and the runtime's subsystems
// service the call; we write the result into RAX and continue. Ordinary
// instructions never trap: only syscalls pay the stop/continue cost.
//
// This backend runs on Linux/x86-64 hosts. It models runtime::SyscallTrap,
// so runtime::Cpu drives it unchanged — the same loop that would drive a
// seccomp+SIGSYS or in-process backend.
#pragma once

#include "linuxity/abi/syscall.hpp"
#include "linuxity/runtime/trap.hpp"

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace lx::runtime {

// Executes a real host binary as the guest, trapping its syscalls. (For the
// bring-up demo we exec a real static ELF so libc/_start run natively; the
// in-tree Loader path replaces exec once the in-process trampoline lands.)
class PtraceTrap {
public:
    // `path` + `argv` name the guest program; it is exec'd under the tracer.
    PtraceTrap(std::string path, std::vector<std::string> argv)
        : path_{std::move(path)}, argv_{std::move(argv)} {}

    [[nodiscard]] Status start(UAddr /*entry*/, UAddr /*sp*/) {
        pid_ = ::fork();
        if (pid_ < 0) return err(Errno::eagain);
        if (pid_ == 0) {
            // -- child: become traceable, then exec the guest natively. ---
            ::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            std::vector<char*> cargv;
            for (auto& a : argv_) cargv.push_back(a.data());
            cargv.push_back(nullptr);
            char* envp[] = {nullptr};
            ::execve(path_.c_str(), cargv.data(), envp);
            ::_exit(127); // exec failed
        }
        // -- parent: wait for the initial exec-stop. ----------------------
        int st = 0;
        ::waitpid(pid_, &st, 0);
        // Use SYSEMU so syscalls are trapped and NOT run by the host kernel.
        ::ptrace(PTRACE_SETOPTIONS, pid_, 0, PTRACE_O_EXITKILL);
        armed_ = true;
        return ok();
    }

    // Advance to the next syscall-entry stop. Fills `f` with the guest regs.
    // Returns false when the guest exits.
    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        // Ask the kernel to stop the child at the next syscall entry, but
        // NOT execute the syscall (SYSEMU) — we will service it ourselves.
        if (::ptrace(PTRACE_SYSEMU, pid_, 0, 0) < 0) return err<bool>(Errno::esrch);
        int st = 0;
        ::waitpid(pid_, &st, 0);
        if (WIFEXITED(st)) { exit_code_ = WEXITSTATUS(st); return ok(false); }
        if (WIFSIGNALED(st)) { exit_code_ = 128 + WTERMSIG(st); return ok(false); }

        struct user_regs_struct r{};
        ::ptrace(PTRACE_GETREGS, pid_, 0, &r);
        // x86-64 Linux syscall ABI: nr=rax, args=rdi,rsi,rdx,r10,r8,r9.
        f.regs.nr     = r.orig_rax;
        f.regs.arg[0] = r.rdi;
        f.regs.arg[1] = r.rsi;
        f.regs.arg[2] = r.rdx;
        f.regs.arg[3] = r.r10;
        f.regs.arg[4] = r.r8;
        f.regs.arg[5] = r.r9;
        f.pc          = r.rip;
        last_ = r;
        return ok(true);
    }

    // Write the syscall's return value into RAX and let the guest resume.
    [[nodiscard]] Status resume(std::int64_t ret) {
        last_.rax = static_cast<unsigned long long>(ret);
        ::ptrace(PTRACE_SETREGS, pid_, 0, &last_);
        return ok();
    }

    [[nodiscard]] int exit_code() const noexcept { return exit_code_; }

    // -- GuestMem: share the child's real address space via process_vm_*. --
    // The child's pages ARE the guest memory; we read/write them directly,
    // no translation table needed (ptrace model). This models abi::GuestMem.
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
    ::pid_t pid_{-1};
    bool armed_{false};
    int exit_code_{0};
    struct user_regs_struct last_{};
};

static_assert(SyscallTrap<PtraceTrap>, "PtraceTrap must model SyscallTrap");

} // namespace lx::runtime
