// linuxity/runtime/hvf_signal.hpp
//
// Linux signal delivery into a kernel-less guest.
//
// On Linux the KERNEL delivers a signal: it saves the interrupted registers
// in a frame on the user stack, points PC at the handler with x0 = signo,
// and sets x30 to a trampoline that calls rt_sigreturn, which restores the
// frame. Here there is no kernel in the guest, so linuxity does exactly that
// itself, at the next point the guest is stopped in our hands.
//
// Host signals (Ctrl-C on the terminal, kill from another process, a child
// exiting) arrive at LINUXITY. A tiny async-signal-safe handler only records
// them in a pending bitmask and kicks the vCPU out of hv_vcpu_run
// (hv_vcpus_exit); the trap loop then delivers them to the guest between
// syscalls -- the same "deliver on return to user space" rule Linux uses.
//
// The frame layout is aarch64 Linux's rt_sigframe:
//
//     struct rt_sigframe { siginfo_t info; ucontext_t uc; }
//     ucontext: flags, link, stack_t, sigset_t mask, pad to 128B,
//               mcontext { fault_address, regs[31], sp, pc, pstate,
//                          __reserved[4096] (FP state as fpsimd_context) }
//
// The FP/SIMD state is saved in the frame's fpsimd_context record so a
// handler that uses floating point (printf of a double does) can't corrupt
// the interrupted code's vector registers.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/runtime/hvf_proc.hpp"
#include "linuxity/runtime/hvf_vm.hpp"

#include <Hypervisor/Hypervisor.h>
#include <signal.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>

namespace lx::runtime {

inline constexpr int kLinuxNsig = 64;

// The guest's view of one signal's disposition (struct k_sigaction as the
// aarch64 kernel ABI defines it: handler, flags, restorer, mask).
struct LinuxSigaction {
    std::uint64_t handler{};     // 0 = SIG_DFL, 1 = SIG_IGN, else address
    std::uint64_t flags{};
    std::uint64_t restorer{};
    std::uint64_t mask{};
};
static_assert(sizeof(LinuxSigaction) == 32);

namespace sigflag {
inline constexpr std::uint64_t kSiginfo  = 0x00000004;
inline constexpr std::uint64_t kOnstack  = 0x08000000;
inline constexpr std::uint64_t kRestart  = 0x10000000;
inline constexpr std::uint64_t kNodefer  = 0x40000000;
inline constexpr std::uint64_t kResethand= 0x80000000;
inline constexpr std::uint64_t kRestorer = 0x04000000;
}

[[nodiscard]] constexpr std::uint64_t sigbit(int linux_sig) noexcept {
    return 1ull << (linux_sig - 1);
}

// What Linux does by default with each signal when no handler is installed.
enum class Default { term, core, ignore, stop, cont };
[[nodiscard]] constexpr Default default_action(int s) noexcept {
    switch (s) {
        case 17: case 23: case 28: return Default::ignore;     // CHLD URG WINCH
        case 18:                   return Default::cont;       // CONT
        case 19: case 20: case 21: case 22: return Default::stop;  // STOP TSTP TTIN TTOU
        case 3: case 4: case 5: case 6: case 7: case 8: case 11:
        case 24: case 25: case 31: return Default::core;
        default:                   return Default::term;
    }
}

// -- Host-side pending set ----------------------------------------------------
// One process == one guest process == one vCPU, so a single global is the
// honest representation. The handler touches nothing but this and the
// framework's documented async-safe exit call.
struct PendingSignals {
    std::atomic<std::uint64_t> bits{0};
    std::atomic<hv_vcpu_t> vcpu{0};
    std::atomic<bool> vcpu_valid{false};
};
inline PendingSignals g_pending;

extern "C" inline void hvf_host_signal(int host_sig) {
    const int ls = signal_to_linux(host_sig);
    if (ls > 0 && ls <= kLinuxNsig)
        g_pending.bits.fetch_or(sigbit(ls), std::memory_order_relaxed);
    // Kick the guest out of hv_vcpu_run so the loop notices promptly. The
    // call is async-signal-safe by design (it only sets a flag the vCPU
    // thread polls on its way out).
    if (g_pending.vcpu_valid.load(std::memory_order_relaxed)) {
        hv_vcpu_t v = g_pending.vcpu.load(std::memory_order_relaxed);
        ::hv_vcpus_exit(&v, 1);
    }
}

// Route host signal `ls` (Linux number) to the guest: catch it on the host,
// or restore the host default so e.g. SIGKILL semantics stay exact.
inline void route_host_signal(int linux_sig, bool catch_it) {
    const int hs = signal_from_linux(linux_sig);
    if (hs <= 0 || hs == SIGKILL || hs == SIGSTOP) return;
    struct ::sigaction sa{};
    sa.sa_handler = catch_it ? hvf_host_signal : SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    ::sigaction(hs, &sa, nullptr);
}

// -- The aarch64 rt_sigframe ----------------------------------------------------
struct LinuxSiginfo {               // 128 bytes; we fill the common prefix
    std::int32_t si_signo, si_errno, si_code, pad_;
    std::int32_t si_pid, si_uid;    // kill(): sender
    std::uint8_t rest[104];
};
static_assert(sizeof(LinuxSiginfo) == 128);

struct LinuxStack { std::uint64_t ss_sp; std::int32_t ss_flags, pad_; std::uint64_t ss_size; };

struct FpsimdContext {             // the first record in __reserved
    std::uint32_t magic{0x46508001}, size{528};
    std::uint32_t fpsr{}, fpcr{};
    hv_simd_fp_uchar16_t vregs[32]{};
};
static_assert(sizeof(FpsimdContext) == 528);

struct LinuxMcontext {
    std::uint64_t fault_address;
    std::uint64_t regs[31];
    std::uint64_t sp, pc, pstate;
    alignas(16) std::uint8_t reserved[4096];
};

struct LinuxUcontext {
    std::uint64_t uc_flags;
    std::uint64_t uc_link;
    LinuxStack uc_stack;
    std::uint64_t uc_sigmask;
    std::uint8_t pad_[128 - 8];      // sigset_t is padded to 1024 bits
    alignas(16) LinuxMcontext uc_mcontext;
};

struct RtSigframe {
    LinuxSiginfo info;
    LinuxUcontext uc;
};

// The return trampoline: `mov x8, #139 (rt_sigreturn); svc #0`. glibc always
// passes SA_RESTORER with its own __default_rt_sa_restorer, but a handler
// installed via the raw syscall may not; then we place this on the stack.
inline constexpr std::uint32_t kSigreturnTrampoline[2] = {0xD2801168, 0xD4000001};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
