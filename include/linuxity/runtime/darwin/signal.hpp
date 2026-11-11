// linuxity/runtime/darwin/signal.hpp
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

#include "linuxity/runtime/darwin/proc.hpp"
#include "linuxity/runtime/darwin/vm.hpp"

#include <Hypervisor/Hypervisor.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <bit>
#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <vector>

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
    // The whole table, for a fork's handoff: a child inherits every
    // disposition verbatim (SIGKILL/SIGSTOP are SIG_DFL in both).
    using Table = std::array<LinuxSigaction, kLinuxNsig>;
    [[nodiscard]] const Table& table() const noexcept { return act_; }
    void set_table(const Table& t) noexcept { act_ = t; }

    [[nodiscard]] LinuxSigaction get(int s) const noexcept {
        return valid(s) ? act_[slot(s)] : LinuxSigaction{};
    }
    // Returns false for SIGKILL/SIGSTOP, whose disposition cannot change.
    bool set(int s, const LinuxSigaction& a) noexcept {
        if (!valid(s) || s == 9 || s == 19) return false;
        act_[slot(s)] = a;
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
    // Signal s lives in act_[s - 1]; callers checked valid(s).
    [[nodiscard]] static constexpr std::size_t slot(int s) noexcept {
        return static_cast<std::size_t>(s - 1);
    }

private:
    Table act_{};
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
    // What Linux's siginfo says about each pending signal. Classic signals
    // merge (one record, the latest sender); real-time ones QUEUE, one record
    // per send, delivered in order. Touched only at trap boundaries and in
    // the drain of the cross-process mailbox -- never from a host signal
    // handler, which only sets `bits` -- so a plain mutex guards it.
    struct Info { int signo; std::int32_t pid, code, value; };
    std::mutex q_mu_;
    std::vector<Info> queue_;
    void enqueue(const Info& i) {
        std::lock_guard g{q_mu_};
        if (i.signo < 32)                                 // merges: replace
            for (auto& q : queue_)
                if (q.signo == i.signo) { q = i; return; }
        queue_.push_back(i);
        bits.fetch_or(1ull << (i.signo - 1), std::memory_order_relaxed);
    }
    // Take the lowest pending signal in `set`: its record if there is one
    // (else a bare SI_USER from no one). The bit is CLAIMED atomically
    // first -- a host handler may set it again at any moment, and clearing
    // it after reading the queue would drop that next signal -- and set
    // back if more queued records of a real-time signal remain.
    [[nodiscard]] std::optional<Info> take(std::uint64_t set) {
        std::lock_guard g{q_mu_};
        for (;;) {
            const std::uint64_t ready = bits.load(std::memory_order_acquire) & set;
            if (!ready) return std::nullopt;
            const int s = std::countr_zero(ready) + 1;
            const std::uint64_t b = 1ull << (s - 1);
            if (!(bits.fetch_and(~b, std::memory_order_acq_rel) & b)) continue;   // lost a race: retry
            Info out{s, 0, 0, 0};
            bool more = false;
            for (auto it = queue_.begin(); it != queue_.end(); ++it)
                if (it->signo == s) {
                    out = *it;
                    queue_.erase(it);
                    if (s >= 32)
                        for (const auto& q : queue_) if (q.signo == s) { more = true; break; }
                    break;
                }
            if (more) bits.fetch_or(b, std::memory_order_release);
            return out;
        }
    }
    [[nodiscard]] std::size_t queued() {
        std::lock_guard g{q_mu_};
        return queue_.size();
    }
    // A self-pipe the host signal handler writes one byte into. Every
    // blocking host poll/select a guest call turns into also polls its read
    // end, so a signal landing between the guest's last check and the host
    // call still wakes it -- the classic lost-wakeup race, which hung the
    // test runner's select() when SIGCHLD arrived just before it slept.
    int wake_rd{-1}, wake_wr{-1};
    void open_wake_pipe() noexcept {
        if (wake_rd >= 0) return;
        int p[2];
        if (::pipe(p) != 0) return;
        for (int e : p) {
            ::fcntl(e, F_SETFD, FD_CLOEXEC);
            ::fcntl(e, F_SETFL, ::fcntl(e, F_GETFL) | O_NONBLOCK);
        }
        wake_rd = p[0];
        wake_wr = p[1];
    }
    void poke() noexcept {
        if (wake_wr >= 0) { const char c = 1; (void)::write(wake_wr, &c, 1); }
    }
    void drain_wake() noexcept {
        if (wake_rd < 0) return;
        char b[64];
        while (::read(wake_rd, b, sizeof b) > 0) {}
    }
    // The sender of a classic signal whose delivery the HOST does (it arrives
    // as a host signal and sets `bits`): remembered for its siginfo, never
    // pending by itself.
    void note_sender(const Info& i) {
        std::lock_guard g{q_mu_};
        for (auto& q : queue_)
            if (q.signo == i.signo) { q = i; return; }
        queue_.push_back(i);
    }
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
    // The same, for at most `ns` nanoseconds.
    void wait_for_signal(std::uint64_t interesting, std::uint64_t ns) {
        std::unique_lock lk{wait_mu_};
        const auto end = std::chrono::steady_clock::now() + std::chrono::nanoseconds{ns};
        while (!(bits.load(std::memory_order_relaxed) & interesting)) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= end) return;
            const auto step = std::min<std::chrono::nanoseconds>(end - now, std::chrono::milliseconds{50});
            wait_cv_.wait_for(lk, step);
        }
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
        std::lock_guard g{q_mu_};
        queue_.clear();
    }
};
inline PendingSignals g_pending;

extern "C" inline void hvf_host_signal(int host_sig) {
    const int ls = signal_to_linux(host_sig);
    if (ls > 0 && ls <= kLinuxNsig)
        g_pending.bits.fetch_or(sigbit(ls), std::memory_order_relaxed);
    g_pending.poke();
    g_pending.kick_all();
    // notify_all() on a condvar is not formally async-signal-safe, but the
    // waiter also re-checks on a 50 ms timeout, so a missed wake costs
    // latency rather than correctness.
    g_pending.notify_waiters();
}

// linuxity's internal mailbox kick: wake every vCPU and blocked host call,
// raise nothing for the guest. No SA_RESTART, so a blocked read/pause/wait
// returns EINTR, traps, and the trap loop reads the mailbox.
inline void install_kick_handler() {
    g_pending.open_wake_pipe();
    struct ::sigaction sa{};
    sa.sa_handler = [](int) { g_pending.poke(); g_pending.kick_all(); g_pending.notify_waiters(); };
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    ::sigaction(kKickSignal, &sa, nullptr);
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
