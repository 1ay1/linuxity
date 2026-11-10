// linuxity/runtime/linux/ptrace_regs.hpp
//
// The per-ARCH half of the Linux ptrace backend: how to read and write a
// stopped task's registers.
//
// WHY THIS FILE EXISTS. runtime/backend.hpp split the Linux/macOS/Windows
// HOSTS cleanly, and abi::Regs (nr + 6 args) already keeps the dispatcher
// arch-neutral -- nothing above runtime/linux/ knows what a register is. But
// ptrace_trap.hpp itself reached into `struct user_regs_struct` directly in 36
// places, so the backend was x86-64-only by accident rather than by design:
//
//     error: no member named 'orig_rax' in 'struct user_regs_struct'
//
// is what compiling it for aarch64 says, and that is the whole obstacle to
// running on an arm64 Linux box (or Android).
//
// THE SEAM IS SIX OPERATIONS. That is all the backend actually does to
// registers, enumerated from the call sites:
//
//     nr()        which syscall is this
//     arg(i)      read argument i (dispatch, and reading path strings)
//     set_arg     splice a translated host path in (REDIRECT)
//     skip_call   neutralize the syscall so it does not run (VIRT)
//     set_ret     the value the guest sees
//     sp()        stack pointer, for the scratch a REDIRECT writes into
//
// Everything else -- the state machine, pid translation, the fd and cwd
// bookkeeping, the fast paths -- is arch-independent and stays in one place.
//
// WHY A STRUCT AND NOT A CONCEPT. backend.hpp uses concepts because a BACKEND
// is chosen at a seam where several could plausibly exist. Here exactly one
// implementation is correct per target and the compiler already knows which,
// so a concept would add a name to check without adding a choice. The arch is
// selected by #if in ONE place (below), the way host.hpp selects a host.
//
// AARCH64 IS NOT JUST DIFFERENT NAMES. Two things genuinely differ and are the
// reason this cannot be a set of #defines:
//
//   * there is no PTRACE_GETREGS. You use PTRACE_GETREGSET with NT_PRSTATUS
//     and an iovec, which also tells the kernel how many bytes you expect.
//   * writing regs[8] does NOT change which syscall runs. The syscall number
//     is latched before the stop; changing it needs a second GETREGSET/SETREGSET
//     on NT_ARM_SYSTEM_CALL. Skipping a call means writing -1 THERE, not to
//     the general-purpose set.
//
// Getting that wrong would not fail to compile -- it would silently run the
// syscall we meant to skip, which is why it is spelled out here rather than
// left to whoever ports it.
#pragma once

#include <cstdint>

#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#if defined(__aarch64__)
// aarch64's register struct is user_pt_regs, and glibc's <sys/user.h> does
// NOT declare it -- only the kernel header does. (Bionic does, which is why
// an NDK build compiled and a cross-glibc build did not.)
#include <asm/ptrace.h>
#endif

#include "linuxity/abi/syscall.hpp"

namespace lx::runtime::linux_regs {

#if defined(__x86_64__)

// The x86-64 view. `orig_rax` holds the syscall number as it was at entry
// (rax is clobbered by the return value), which is why the two are distinct.
struct Regs {
    using Raw = struct user_regs_struct;
    Raw r{};

    [[nodiscard]] static bool fetch(::pid_t t, Regs& out) {
        return ::ptrace(PTRACE_GETREGS, t, 0, &out.r) == 0;
    }
    [[nodiscard]] bool store(::pid_t t) const {
        return ::ptrace(PTRACE_SETREGS, t, 0, const_cast<Raw*>(&r)) == 0;
    }

    [[nodiscard]] std::uint64_t nr()  const noexcept { return r.orig_rax; }
    [[nodiscard]] std::uint64_t sp()  const noexcept { return r.rsp; }
    [[nodiscard]] std::uint64_t pc()  const noexcept { return r.rip; }
    void set_pc(std::uint64_t v) noexcept { r.rip = v; }
    [[nodiscard]] std::uint64_t ret() const noexcept { return r.rax; }

    [[nodiscard]] std::uint64_t arg(int i) const noexcept {
        switch (i) {
            case 0: return r.rdi; case 1: return r.rsi; case 2: return r.rdx;
            case 3: return r.r10; case 4: return r.r8;  case 5: return r.r9;
            default: return 0;
        }
    }
    void set_arg(int i, std::uint64_t v) noexcept {
        switch (i) {
            case 0: r.rdi = v; break; case 1: r.rsi = v; break;
            case 2: r.rdx = v; break; case 3: r.r10 = v; break;
            case 4: r.r8  = v; break; case 5: r.r9  = v; break;
            default: break;
        }
    }
    void set_ret(std::int64_t v) noexcept {
        r.rax = static_cast<unsigned long long>(v);
    }
    // Neutralize the call: an invalid number makes the kernel skip it and
    // return whatever we leave in rax.
    void skip_call() noexcept {
        r.orig_rax = static_cast<unsigned long long>(-1);
    }
    // On x86-64 skip_call() is part of the general register set, so storing
    // the registers is enough. aarch64 needs a second poke -- see below.
    [[nodiscard]] bool commit_skip(::pid_t) const noexcept { return true; }

    // Run a different syscall from this entry stop. orig_rax is the number.
    void set_nr(std::uint64_t n) noexcept { r.orig_rax = n; }
    [[nodiscard]] bool commit_nr(::pid_t) const noexcept { return true; }
    // At an exit stop: point back at the `syscall` instruction so it runs
    // again with these registers.
    void rewind_to_syscall() noexcept {
        r.rip -= 2;
        r.rax = r.orig_rax;
    }
};

#elif defined(__aarch64__)

// The aarch64 view. Registers come as `user_pt_regs`: x0-x30 in regs[],
// plus sp/pc/pstate. The syscall number is x8 (regs[8]).
struct Regs {
    using Raw = struct user_pt_regs;
    Raw r{};

    [[nodiscard]] static bool fetch(::pid_t t, Regs& out) {
        ::iovec io{&out.r, sizeof out.r};
        return ::ptrace(PTRACE_GETREGSET, t, NT_PRSTATUS, &io) == 0;
    }
    [[nodiscard]] bool store(::pid_t t) const {
        ::iovec io{const_cast<Raw*>(&r), sizeof r};
        return ::ptrace(PTRACE_SETREGSET, t, NT_PRSTATUS, &io) == 0;
    }

    [[nodiscard]] std::uint64_t nr()  const noexcept { return r.regs[8]; }
    [[nodiscard]] std::uint64_t sp()  const noexcept { return r.sp; }
    [[nodiscard]] std::uint64_t pc()  const noexcept { return r.pc; }
    void set_pc(std::uint64_t v) noexcept { r.pc = v; }
    [[nodiscard]] std::uint64_t ret() const noexcept { return r.regs[0]; }

    [[nodiscard]] std::uint64_t arg(int i) const noexcept {
        return (i >= 0 && i < 6) ? r.regs[i] : 0;
    }
    void set_arg(int i, std::uint64_t v) noexcept {
        if (i >= 0 && i < 6) r.regs[i] = v;
    }
    void set_ret(std::int64_t v) noexcept {
        r.regs[0] = static_cast<std::uint64_t>(v);
    }
    // Record the intent; the actual poke happens in commit_skip, because the
    // syscall number is NOT taken from the general register set at this point.
    void skip_call() noexcept { skip_ = true; }

    // THE aarch64-only step. The kernel latches the syscall number before the
    // tracer stop, so writing regs[8] changes x8 for the callee and nothing
    // else -- the original call still runs. NT_ARM_SYSTEM_CALL is the register
    // set that actually selects it, and -1 there means "no syscall".
    //
    // Must be called after store(). Silently skipping it would run the syscall
    // we meant to virtualize, so it returns a status the caller checks.
    [[nodiscard]] bool commit_skip(::pid_t t) const {
        if (!skip_) return true;
        int none = -1;
        ::iovec io{&none, sizeof none};
        return ::ptrace(PTRACE_SETREGSET, t, NT_ARM_SYSTEM_CALL, &io) == 0;
    }

    // Run a different syscall from this entry stop. As with skip, the number
    // is latched, so it goes through NT_ARM_SYSTEM_CALL after store().
    void set_nr(std::uint64_t n) noexcept {
        r.regs[8] = n;
        nr_ = static_cast<int>(n);
    }
    [[nodiscard]] bool commit_nr(::pid_t t) const {
        if (nr_ < 0) return true;
        int n = nr_;
        ::iovec io{&n, sizeof n};
        return ::ptrace(PTRACE_SETREGSET, t, NT_ARM_SYSTEM_CALL, &io) == 0;
    }
    // At an exit stop: back to the `svc`, which reads x8 afresh.
    void rewind_to_syscall() noexcept { r.pc -= 4; }

private:
    bool skip_{false};
    int  nr_{-1};
};

#else
#error "linuxity's ptrace backend supports x86-64 and aarch64"
#endif

// Fill the arch-neutral frame the dispatcher sees. One definition for both
// arches, because Regs already hides the difference -- this is the payoff.
inline void fill_frame(abi::Regs& out, std::uint64_t& pc, const Regs& r) {
    out.nr = r.nr();
    for (int i = 0; i < 6; ++i) out.arg[static_cast<std::size_t>(i)] = r.arg(i);
    pc = r.pc();
}

} // namespace lx::runtime::linux_regs
