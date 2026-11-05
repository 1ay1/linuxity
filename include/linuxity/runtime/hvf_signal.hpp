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
#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>

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

// The per-PROCESS signal disposition table. Shared by every thread (Linux
// has no per-thread handlers -- only the blocked mask is per-thread), so it
// lives in ProcessState under its lock.
class SignalDispositions {
public:
    [[nodiscard]] LinuxSigaction get(int s) const noexcept {
        return valid(s) ? act_[s - 1] : LinuxSigaction{};
    }
    // Returns false for SIGKILL/SIGSTOP, whose disposition cannot change.
    bool set(int s, const LinuxSigaction& a) noexcept {
        if (!valid(s) || s == 9 || s == 19) return false;
        act_[s - 1] = a;
        return true;
    }
    // execve(2): handlers point at code that no longer exists, so caught
    // signals revert to SIG_DFL; ignored stay ignored.
    void on_exec() noexcept {
        for (auto& a : act_) if (a.handler > 1) a = {};
    }
    [[nodiscard]] static constexpr bool valid(int s) noexcept {
        return s >= 1 && s <= kLinuxNsig;
    }

private:
    std::array<LinuxSigaction, kLinuxNsig> act_{};
};

// -- Host-side pending set ----------------------------------------------------
// A host signal arrives at LINUXITY, on whichever thread the kernel picks.
// The handler must be async-signal-safe, so it does the minimum: set a bit
// and kick the vCPUs so every thread leaves the guest promptly and checks.
//
// Delivery itself happens at a trap boundary, where the guest is stopped and
// we own its registers -- the same "on return to user space" rule Linux uses.
struct PendingSignals {
    std::atomic<std::uint64_t> bits{0};
    // Up to 64 live vCPUs to kick. Written under ProcessState's lock when
    // threads start/stop; read from a signal handler, hence atomic.
    static constexpr int kMaxCpus = 64;
    std::atomic<hv_vcpu_t> cpus[kMaxCpus]{};
    std::atomic<int> cpu_count{0};
    std::mutex wait_mu_;
    std::condition_variable wait_cv_;

    void register_cpu(hv_vcpu_t v) noexcept {
        const int n = cpu_count.load(std::memory_order_relaxed);
        for (int i = 0; i < n; ++i)
            if (cpus[i].load(std::memory_order_relaxed) == v) return;
        if (n < kMaxCpus) {
            cpus[n].store(v, std::memory_order_relaxed);
            cpu_count.store(n + 1, std::memory_order_release);
        }
    }
    void unregister_cpu(hv_vcpu_t v) noexcept {
        const int n = cpu_count.load(std::memory_order_acquire);
        for (int i = 0; i < n; ++i)
            if (cpus[i].load(std::memory_order_relaxed) == v)
                cpus[i].store(0, std::memory_order_relaxed);
    }
    void kick_all() noexcept {
        const int n = cpu_count.load(std::memory_order_acquire);
        for (int i = 0; i < n; ++i) {
            hv_vcpu_t v = cpus[i].load(std::memory_order_relaxed);
            if (v) ::hv_vcpus_exit(&v, 1);
        }
    }

    // Block until one of `interesting` is pending, then return. Used by
    // sigsuspend/pause, which must be genuinely idle rather than spinning.
    //
    // The handler cannot take a mutex (not async-signal-safe), so it only
    // sets the bit and bumps a sequence counter; the waiter polls that
    // counter under its own lock with a bounded wait. That keeps the handler
    // safe AND the waiter asleep.
    void wait_for_signal(std::uint64_t interesting) {
        std::unique_lock lk{wait_mu_};
        wait_cv_.wait_for(lk, std::chrono::milliseconds{50}, [&] {
            return (bits.load(std::memory_order_relaxed) & interesting) != 0;
        });
        while (!(bits.load(std::memory_order_relaxed) & interesting))
            if (wait_cv_.wait_for(lk, std::chrono::milliseconds{50}, [&] {
                    return (bits.load(std::memory_order_relaxed) & interesting) != 0;
                }))
                break;
    }
    void notify_waiters() noexcept { wait_cv_.notify_all(); }

    // A forked child inherits the PARENT's vCPU handles -- this table is a
    // process global, and fork copies it. Those handles name vCPUs in a
    // DIFFERENT process; kicking them is meaningless and can wedge this one.
    // Start empty: the child's own threads register themselves.
    void reset_for_fork_child() noexcept {
        cpu_count.store(0, std::memory_order_release);
        for (auto& c : cpus) c.store(0, std::memory_order_relaxed);
        bits.store(0, std::memory_order_relaxed);
    }
};
inline PendingSignals g_pending;

extern "C" inline void hvf_host_signal(int host_sig) {
    const int ls = signal_to_linux(host_sig);
    if (ls > 0 && ls <= kLinuxNsig)
        g_pending.bits.fetch_or(sigbit(ls), std::memory_order_relaxed);
    g_pending.kick_all();
    // notify_all() on a condvar is not formally async-signal-safe, but the
    // waiter also re-checks on a 50 ms timeout, so a missed wake costs
    // latency rather than correctness.
    g_pending.notify_waiters();
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

// The SAME 128 bytes as seen by a FAULT handler. For the synchronous
// signals (SIGSEGV/SIGBUS/SIGILL/SIGFPE) the kernel's _sigfault union puts
// the offending address where kill()'s sender pid/uid would be, so a
// handler reads si_addr at offset 16 -- not si_pid. gpg's secmem probe and
// every JIT/GC that recovers from a guarded access reads exactly this.
struct LinuxSigfault {
    std::int32_t  si_signo, si_errno, si_code, pad_;
    std::uint64_t si_addr;          // SIGSEGV/SIGBUS: the faulting address
    std::uint8_t  rest[104];
};
static_assert(sizeof(LinuxSigfault) == 128);
static_assert(offsetof(LinuxSigfault, si_addr) == 16);

// si_code values for the fault signals (asm-generic/siginfo.h).
namespace sicode {
inline constexpr std::int32_t kSegvMaperr = 1;   // address not mapped
inline constexpr std::int32_t kSegvAccerr = 2;   // no permission for access
inline constexpr std::int32_t kBusAdraln  = 1;   // invalid alignment
inline constexpr std::int32_t kIllIllopc  = 1;   // illegal opcode
}

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
