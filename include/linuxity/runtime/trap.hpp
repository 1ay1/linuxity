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
            if (!still_running) return ok(trap_.exit_code());

            // The dispatcher classifies the trapped syscall: service it from
            // our subsystems, forward it to the host kernel, or exit.
            abi::Outcome o = sys.dispatch(f.regs);
            if (o.exited) return ok(o.exit_code);

            if (o.forward) {
                // Let the host kernel run it IN the guest (mmap/brk/...).
                (void)LX_TRY(trap_.forward());
            } else {
                // Virtualize: hand the guest our answer, no real syscall.
                LX_TRY(trap_.resume(o.ret));
            }
            if (trap_.exited()) return ok(trap_.exit_code());
        }
    }

private:
    T& trap_;
    K& kernel_;
    M& mem_;
    abi::Arch arch_;
};

} // namespace lx::runtime
