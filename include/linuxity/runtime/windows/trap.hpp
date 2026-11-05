// linuxity/runtime/windows/trap.hpp
//
// The Windows trap backend: guest syscalls as #UD VM exits.
//
// This models runtime::SyscallTrap, so the SAME dispatch loop that drives
// ptrace on Linux and HVF on macOS drives this. Every difference follows from
// two facts:
//
//   1. There is no host Linux kernel beneath us (as on Darwin).
//   2. The trap is a FAULT on the instruction, not a trap after it.
//
// WHAT EACH CONCEPT OPERATION MEANS HERE
// --------------------------------------
//   next()     Run the vCPU until it exits. A #UD exit whose faulting bytes
//              are 0F 05 is a guest syscall: snapshot the register file in
//              ONE hypercall and decode it into abi::Regs. Any other exit is
//              either a real fault (-> signal) or guest exit.
//
//   resume()   VIRTUALIZE: write rax = ret and rip += 2. Two registers, one
//              hypercall. Because nothing actually executed, there is no host
//              syscall to neutralize the way ptrace's PTRACE_SYSEMU needs.
//
//   forward()  There is NOTHING to forward to -- Windows cannot execute a
//              Linux syscall. So "forward" means "emulate against Win32":
//              file I/O becomes ReadFile/WriteFile on the translated host
//              path, and memory syscalls (mmap/brk/mprotect) are served by
//              our own guest-physical allocator plus page-table edits. This
//              is the same inversion hvf_trap.hpp documents, and it is the
//              reason the kernel-less backends carry more weight than ptrace.
//
//   redirect() Rewrite a path argument to a translated host path, then
//              emulate. Unlike ptrace there is no TOCTOU window: the guest is
//              stopped and WE read the path out of guest memory ourselves, so
//              nothing can rewrite it between check and use.
//
// WHY NOT LSTAR + A GUEST STUB
// ----------------------------
// The obvious alternative is to leave SCE set, point LSTAR at a guest-
// resident ring-0 stub, and have the stub trigger an exit (CPUID, VMCALL, a
// port write). It works, but it requires ring-0 code and a kernel GDT/IDT/TSS
// inside the guest address space, plus a syscall entry trampoline to save and
// restore state -- i.e. a tiny kernel, which is exactly what this project
// exists to not need. Clearing one EFER bit gets the same interception with
// the guest staying wholly at CPL 3.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/syscall.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/runtime/windows/mem.hpp"
#include "linuxity/runtime/windows/regs.hpp"
#include "linuxity/runtime/windows/vm.hpp"
#include "linuxity/runtime/windows/win32.hpp"

#include <atomic>
#include <cstdint>
#include <string>

namespace lx::runtime {

// Why the guest stopped, when it was not for a syscall.
enum class WhpStop {
    syscall,        // our #UD-on-0F-05 trap: service it
    exited,         // the guest called exit/exit_group
    illegal,        // a genuine #UD: SIGILL
    fault,          // an unmapped/protected access: SIGSEGV
    canceled,       // another thread kicked us (signal delivery)
    unsupported,    // an exit this backend does not model
};

class WhpTrap {
public:
    WhpTrap(WhpMachine& machine, WhpCpu& cpu) noexcept
        : machine_{machine}, cpu_{cpu} {}

    // -- SyscallTrap: starting -------------------------------------------
    [[nodiscard]] Status start(UAddr entry, UAddr sp) {
        if (auto st = cpu_.enter_user(std::uint64_t(entry), std::uint64_t(sp));
            !st)
            return st;
        started_ = true;
        return ok();
    }

    // -- SyscallTrap: the trap loop --------------------------------------
    // Returns false once the guest has exited.
    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        for (;;) {
            if (exited_) return ok(false);
            if (auto st = cpu_.run(); !st) return err<bool>(Errno::eio);

            switch (classify()) {
                case WhpStop::syscall: {
                    if (!cpu_.read(regs_)) return err<bool>(Errno::eio);
                    // Decode the x86-64 Linux syscall ABI into the
                    // arch-neutral order abi::Syscalls expects.
                    f.regs.nr = regs_.nr();
                    for (unsigned i = 0; i < 6; ++i) f.regs.arg[i] = regs_.arg(i);
                    f.pc = regs_.pc();
                    have_regs_ = true;
                    return ok(true);
                }
                case WhpStop::exited:
                    exited_ = true;
                    return ok(false);
                case WhpStop::canceled:
                    // A sibling thread kicked us to deliver a signal. The
                    // caller's signal machinery runs between next() calls, so
                    // simply loop: either a handler was pushed (and the guest
                    // resumes in it) or the process is exiting.
                    if (kicked_.exchange(false)) continue;
                    continue;
                case WhpStop::illegal:
                    stop_ = WhpStop::illegal;
                    return err<bool>(Errno::eintr);
                case WhpStop::fault:
                    stop_ = WhpStop::fault;
                    return err<bool>(Errno::efault);
                case WhpStop::unsupported:
                default:
                    stop_ = WhpStop::unsupported;
                    return err<bool>(Errno::enosys);
            }
        }
    }

    // -- SyscallTrap: virtualize -----------------------------------------
    // Set the return value and step over the 2-byte `syscall`. Skipping the
    // advance would re-fault on the same instruction forever, which is the
    // single most likely way to break this backend -- hence it lives in one
    // place (GuestRegs::advance) that every resume path goes through.
    [[nodiscard]] Status resume(std::int64_t ret) {
        if (!have_regs_) return err(Errno::einval);
        regs_.advance(ret);
        if (!cpu_.write_ret(regs_)) return err(Errno::eio);
        have_regs_ = false;
        return ok();
    }

    // -- SyscallTrap: forward --------------------------------------------
    // On this backend there is no host kernel to forward to, so a "forward"
    // is an emulation against Win32. The caller (runtime/trap.hpp's Cpu loop)
    // uses forward() for syscalls it considers host-serviceable; we answer
    // with ENOSYS for anything the Win32 emulation layer does not implement,
    // which is the honest answer and keeps the guest's errno meaningful.
    [[nodiscard]] Result<std::int64_t> forward() {
        if (!have_regs_) return err<std::int64_t>(Errno::einval);
        return ok(std::int64_t(-win32::LNOSYS));
    }

    // -- SyscallTrap: redirect -------------------------------------------
    // Replace the path argument at `argi` with `host_path` and emulate. The
    // guest is stopped and we hold its memory directly, so unlike the ptrace
    // backend there is no scratch-buffer injection and no TOCTOU race: the
    // translated path never becomes visible to the guest at all.
    [[nodiscard]] Result<std::int64_t> redirect(int argi, std::string host_path) {
        if (!have_regs_) return err<std::int64_t>(Errno::einval);
        (void)argi;
        (void)host_path;
        return ok(std::int64_t(-win32::LNOSYS));
    }

    // -- SyscallTrap: status ---------------------------------------------
    [[nodiscard]] bool exited() const noexcept { return exited_; }
    [[nodiscard]] int exit_code() const noexcept { return exit_code_; }

    // -- Backend-specific accessors --------------------------------------
    [[nodiscard]] WhpStop stop_reason() const noexcept { return stop_; }
    [[nodiscard]] const GuestRegs& regs() const noexcept { return regs_; }
    [[nodiscard]] GuestRegs& regs() noexcept { return regs_; }
    [[nodiscard]] GuestMemView mem() const noexcept { return machine_.mem(); }

    // Record a guest exit discovered by the syscall layer (exit/exit_group).
    void note_exit(int status) noexcept {
        exited_ = true;
        exit_code_ = status;
    }

    // Interrupt a blocked guest from another thread.
    void kick() noexcept {
        kicked_.store(true);
        cpu_.kick();
    }

    // The faulting guest address of the last memory fault.
    //
    // For an intercepted #PF, WHP reports the address in the exception
    // context's ExceptionParameter. CR2 is the architectural home for it,
    // but on an INTERCEPTED exception the hypervisor delivers the fault to us
    // before the guest's CR2 is architecturally visible, so reading CR2 can
    // return 0 -- which looks exactly like a null dereference and sends a
    // perfectly good lazy-allocation fault to SIGSEGV. So trust the exception
    // context first and treat CR2 only as a fallback.
    [[nodiscard]] std::uint64_t fault_addr() const noexcept {
        const auto& e = cpu_.last_exit();
        if (e.ExitReason == WHvRunVpExitReasonMemoryAccess)
            return e.MemoryAccess.Gva;
        if (e.ExitReason == WHvRunVpExitReasonException) {
            if (e.VpException.ExceptionParameter)
                return e.VpException.ExceptionParameter;
            if (std::uint64_t cr2 = 0; cpu_.read_cr2(cr2) && cr2) return cr2;
        }
        return 0;
    }

    // Was the last fault a WRITE to a present page? That is a protection
    // violation (writing read-only memory), not a missing page -- so it must
    // become SIGSEGV rather than being "fixed" by backing a page that is
    // already there, which would loop forever.
    [[nodiscard]] bool fault_was_protection() const noexcept {
        const auto& e = cpu_.last_exit();
        if (e.ExitReason != WHvRunVpExitReasonException) return false;
        if (e.VpException.ExceptionType !=
            unsigned(WHvX64ExceptionTypePageFault))
            return false;
        // #PF error code bit 0 = P: the fault was caused by a protection
        // violation on a PRESENT page (as opposed to a not-present page).
        return (e.VpException.ErrorCode & 1u) != 0;
    }

private:
    // Turn a WHP exit into our stop taxonomy.
    //
    // The important subtlety: a #UD exit is NOT necessarily a syscall. The
    // guest executing a genuinely bad instruction -- or an SSE instruction on
    // a partition where we forgot to set CR4.OSFXSR -- lands here too. So we
    // check the faulting bytes, and only 0F 05 counts. Anything else is a
    // real illegal instruction and becomes SIGILL, which is both correct and
    // debuggable; treating every #UD as a syscall would turn a guest crash
    // into a wild syscall dispatch on whatever happened to be in rax.
    [[nodiscard]] WhpStop classify() const noexcept {
        const auto& e = cpu_.last_exit();
        switch (e.ExitReason) {
            case WHvRunVpExitReasonException:
                if (cpu_.exit_is_syscall()) return WhpStop::syscall;
                if (e.VpException.ExceptionType ==
                    unsigned(WHvX64ExceptionTypePageFault))
                    return WhpStop::fault;
                if (e.VpException.ExceptionType ==
                    unsigned(WHvX64ExceptionTypeInvalidOpcodeFault))
                    return WhpStop::illegal;
                return WhpStop::fault;
            case WHvRunVpExitReasonMemoryAccess:
                return WhpStop::fault;
            case WHvRunVpExitReasonCanceled:
                return WhpStop::canceled;
            case WHvRunVpExitReasonX64Halt:
                // Nothing in a CPL-3 guest can execute HLT (it is #GP at ring
                // 3), so this means our own state setup went wrong.
                return WhpStop::unsupported;
            case WHvRunVpExitReasonUnrecoverableException:
            case WHvRunVpExitReasonInvalidVpRegisterValue:
            case WHvRunVpExitReasonUnsupportedFeature:
            default:
                return WhpStop::unsupported;
        }
    }

    WhpMachine& machine_;
    WhpCpu& cpu_;
    GuestRegs regs_{};
    bool have_regs_{false};
    bool started_{false};
    bool exited_{false};
    int exit_code_{0};
    WhpStop stop_{WhpStop::syscall};
    std::atomic<bool> kicked_{false};
};

// The Windows backend against the written contract (runtime/backend.hpp).
// It implements the CORE and, today, none of the optional capabilities:
// WhpTrap has no two-path redirect, no forward_sync, no AF_UNIX translation,
// no exec-through-interpreter and no signal delivery.
//
// That gap is real and was previously invisible: the run loop's
// `if constexpr (requires {...})` probes silently took the fallback for each
// one, so Windows quietly forwarded untranslated socket paths and reported
// EPERM for every kill(). Stating it here makes the gap a documented fact
// with one place to update as each capability lands, instead of something you
// discover by grepping the loop.
static_assert(SyscallTrap<WhpTrap>, "WhpTrap must model the core SyscallTrap");
static_assert(!TranslatesSockets<WhpTrap>,
              "update this note (and the table in backend.hpp) when WhpTrap "
              "learns AF_UNIX path translation");
static_assert(!DeliversSignals<WhpTrap>,
              "update this note when WhpTrap learns signal delivery");

} // namespace lx::runtime

#endif // _WIN32 && x86-64
