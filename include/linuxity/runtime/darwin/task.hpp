// linuxity/runtime/darwin/task.hpp
//
// The guest process and its threads.
//
// Linux's clone(2) is one call with a flag word, but it creates two very
// different things, and the difference is exactly what state is SHARED:
//
//   fork      (no CLONE_VM)  -- a new address space, a new everything.
//                               On macOS: a new host process. See hvf_fork.
//   thread    (CLONE_VM|...) -- the SAME address space, fd table, signal
//                               dispositions and pid; its own stack, TLS and
//                               tid. On macOS: a new host thread with its
//                               own vCPU over the same guest RAM.
//
// So the state is split along that seam, which is also the concurrency seam:
//
//   ProcessState -- shared by every thread in the process. Mutated under one
//                   mutex. This is the small, contended part: the fd table,
//                   the VMA map, signal dispositions, the tid list.
//   TaskState    -- per thread, touched only by its own thread, so no
//                   locking at all. Registers live in the vCPU; this holds
//                   the tid, the blocked signal mask, the alt stack, and
//                   clear_child_tid.
//
// Keeping per-thread state genuinely thread-local (not a map keyed by tid
// under the same lock) is what makes the syscall fast path lock-free for
// everything that doesn't touch shared tables.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/runtime/darwin/fd.hpp"
#include "linuxity/runtime/darwin/signal.hpp"
#include "linuxity/runtime/shared/address_space.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace lx::runtime {

// clone(2) flags, named.
namespace clone_flag {
inline constexpr std::uint64_t vm             = 0x00000100;
inline constexpr std::uint64_t fs             = 0x00000200;
inline constexpr std::uint64_t files          = 0x00000400;
inline constexpr std::uint64_t sighand        = 0x00000800;
inline constexpr std::uint64_t ptrace         = 0x00002000;
inline constexpr std::uint64_t vfork          = 0x00004000;
inline constexpr std::uint64_t parent         = 0x00008000;
inline constexpr std::uint64_t thread         = 0x00010000;
inline constexpr std::uint64_t sysvsem        = 0x00040000;
inline constexpr std::uint64_t settls         = 0x00080000;
inline constexpr std::uint64_t parent_settid  = 0x00100000;
inline constexpr std::uint64_t child_cleartid = 0x00200000;
inline constexpr std::uint64_t child_settid   = 0x01000000;
}  // namespace clone_flag

// What a clone request asks for, decoded once.
struct CloneRequest {
    std::uint64_t flags{};
    std::uint64_t stack{};          // child's new sp (threads always pass one)
    std::uint64_t parent_tid_addr{};
    std::uint64_t tls{};
    std::uint64_t child_tid_addr{};

    [[nodiscard]] bool is_thread() const noexcept {
        return (flags & clone_flag::vm) && (flags & clone_flag::thread);
    }
    [[nodiscard]] bool is_vfork() const noexcept {
        return (flags & clone_flag::vfork) != 0;
    }
    // CLONE_VM without CLONE_THREAD is vfork-style posix_spawn: the child
    // only execs or _exits, so a full fork satisfies the contract.
    [[nodiscard]] bool is_fork_like() const noexcept { return !is_thread(); }
};

// -- Per-thread state ------------------------------------------------------
// Owned by exactly one host thread. No synchronization, by construction.
struct TaskState {
    std::int32_t tid{};
    std::uint64_t sig_mask{};              // blocked signals for THIS thread
    LinuxStack alt_stack{};                // sigaltstack is per-thread
    std::uint64_t clear_child_tid{};       // CLONE_CHILD_CLEARTID
    bool in_sigreturn{false};
    std::optional<std::uint64_t> suspend_restore;

    // Pending signals targeted at this thread specifically (tgkill), as
    // opposed to the process-wide set.
    std::atomic<std::uint64_t> pending{0};
};

// -- Process-wide state ----------------------------------------------------
// Shared by every thread. Every accessor takes the lock; the handles below
// hand out a reference plus the guard, so a caller cannot forget it.
class ProcessState {
public:
    // Run `fn` with exclusive access to the shared tables.
    //
    // Deliberately a CALLBACK rather than a handle that holds the lock:
    // handles invite `auto h = proc.fds()->host(fd);` -- which keeps the
    // guard alive for the rest of the scope and then self-deadlocks the
    // moment the same function locks again. (That exact bug wedged every
    // bash pipeline here.) With a callback the critical section is the
    // lambda body and nothing else, and a nested lock is a visible nested
    // call rather than an invisible temporary's lifetime.
    template <class Fn>
    decltype(auto) with(Fn&& fn) {
        std::lock_guard g{mu_};
        return fn(Shared{fds_, space_, signals_});
    }

    // The shared tables, handed to `with`'s callback as one aggregate.
    struct Shared {
        FdTable& fds;
        AddressSpace& space;
        SignalDispositions& signals;
    };

    // Convenience wrappers for the common single-table operations. Each
    // locks exactly once.
    template <class Fn>
    decltype(auto) with_fds(Fn&& fn) {
        std::lock_guard g{mu_};
        return fn(fds_);
    }
    template <class Fn>
    decltype(auto) with_space(Fn&& fn) {
        std::lock_guard g{mu_};
        return fn(space_);
    }
    template <class Fn>
    decltype(auto) with_signals(Fn&& fn) {
        std::lock_guard g{mu_};
        return fn(signals_);
    }

    // The thread group. A thread exiting removes itself; exit_group marks
    // the whole group dead and kicks every other vCPU out of hv_vcpu_run.
    struct Thread {
        std::int32_t tid;
        HvfCpu* cpu;                 // for kick(); owned by its own thread
    };

    void add_thread(std::int32_t tid, HvfCpu* cpu) {
        std::lock_guard g{mu_};
        threads_.push_back({tid, cpu});
    }
    void remove_thread(std::int32_t tid) {
        std::lock_guard g{mu_};
        std::erase_if(threads_, [tid](const Thread& t) { return t.tid == tid; });
    }
    [[nodiscard]] std::size_t thread_count() {
        std::lock_guard g{mu_};
        return threads_.size();
    }
    // exit_group(2): every thread in the process dies. Mark it, then kick
    // the others so they leave the guest and notice promptly even if they
    // are blocked in a long-running guest loop.
    void request_group_exit(int status) {
        std::lock_guard g{mu_};
        if (group_exiting_.exchange(true)) return;
        group_status_ = status;
        for (const Thread& t : threads_) if (t.cpu) t.cpu->kick();
    }
    [[nodiscard]] bool group_exiting() const noexcept {
        return group_exiting_.load(std::memory_order_acquire);
    }
    [[nodiscard]] int group_status() const noexcept { return group_status_; }

    // Process-wide pending signals (kill(2) targets the process; any thread
    // that doesn't block the signal may take it).
    std::atomic<std::uint64_t> pending{0};
    std::atomic<std::uint32_t> umask{022};

    // -- Writable MAP_SHARED file mappings ---------------------------------
    // Guest RAM is one flat allocation, so a file mapping here is a pread
    // COPY of the file. For MAP_PRIVATE that is exactly the semantics; for a
    // writable MAP_SHARED mapping the guest's stores must reach the file, or
    // a program that writes through mmap (apk extracts every package that
    // way) leaves files full of zeros. So each such mapping keeps its own
    // dup of the fd and is written back when it goes away (munmap, a
    // MAP_FIXED overlay, exit) or on msync. Without other processes mapping
    // the same pages, write-back-on-sync is indistinguishable from coherent
    // page sharing to everything except a concurrent reader -- the same
    // guarantee msync(2) itself gives.
    struct SharedMap {
        std::uint64_t at, len;   // guest range (len = what the file backs)
        int fd;                  // our own dup, closed with the mapping
        std::int64_t off;        // file offset of `at`
    };
    template <class Fn>
    decltype(auto) with_shared_maps(Fn&& fn) {
        std::lock_guard g{mu_};
        return fn(shared_maps_);
    }

    // (No tid allocator here on purpose: tids share ONE namespace with pids
    // across the whole guest tree, so they come from the shared PidSpace.
    // A per-process counter collides with other processes' pids.)

private:
    std::mutex mu_;
    FdTable fds_;
    AddressSpace space_;
    SignalDispositions signals_;
    std::vector<Thread> threads_;
    std::vector<SharedMap> shared_maps_;
    std::atomic<bool> group_exiting_{false};
    int group_status_{0};
};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
