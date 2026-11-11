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

#include "linuxity/runtime/darwin/accept_pump.hpp"
#include "linuxity/runtime/darwin/fd.hpp"
#include "linuxity/runtime/darwin/signal.hpp"
#include "linuxity/runtime/shared/address_space.hpp"

#include <array>
#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
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
    decltype(auto) with_fds(Fn&& fn) const {
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
    [[nodiscard]] std::vector<std::int32_t> thread_ids() const {
        std::lock_guard g{mu_};
        std::vector<std::int32_t> v;
        for (const Thread& t : threads_) v.push_back(t.tid);
        return v;
    }

    // -- What /proc reports that only this process knows (macOS has no host
    //    /proc to ask). The initial environment of the current image, as
    //    NUL-separated bytes; the read/write counters of /proc/<pid>/io; and
    //    the names of file-backed and special ranges for /proc/<pid>/maps.
    void set_environ(std::string blob) {
        std::lock_guard g{mu_};
        environ_ = std::move(blob);
    }
    [[nodiscard]] std::string environ() const {
        std::lock_guard g{mu_};
        return environ_;
    }
    // The aux vector the current image started with, as /proc/<pid>/auxv.
    void set_auxv(std::string blob) {
        std::lock_guard g{mu_};
        auxv_ = std::move(blob);
    }
    [[nodiscard]] std::string auxv() const {
        std::lock_guard g{mu_};
        return auxv_;
    }
    // argv of the current image, NUL-terminated each (/proc/<pid>/cmdline)
    void set_cmdline(std::string blob) {
        std::lock_guard g{mu_};
        cmdline_ = std::move(blob);
    }
    [[nodiscard]] std::string cmdline() const {
        std::lock_guard g{mu_};
        return cmdline_;
    }
    std::atomic<std::uint64_t> rchar{0}, wchar{0}, syscr{0}, syscw{0};
    // The guest-address window whose page-table permissions were narrowed
    // from the default RWX (mmap/mprotect); exec resets it. Empty: lo >= hi.
    std::uint64_t pte_lo{~std::uint64_t{0}}, pte_hi{0};
    // RLIMIT_* as the guest set them (Linux numbering, 16 resources), kept
    // per process and inherited across fork and exec. Only NOFILE and STACK
    // shape this backend; the rest round-trip so a guest sees what it set.
    struct Rlim { std::uint64_t cur, max; };
    static constexpr std::uint64_t kInf = ~std::uint64_t{0};
    std::array<Rlim, 16> rlimits{{
        {kInf, kInf}, {kInf, kInf}, {kInf, kInf}, {8ull << 20, kInf},   // CPU FSIZE DATA STACK
        {0, kInf}, {kInf, kInf}, {63432, 63432}, {1024, 1024},          // CORE RSS NPROC NOFILE
        {8ull << 20, 8ull << 20}, {kInf, kInf}, {kInf, kInf},           // MEMLOCK AS LOCKS
        {63432, 63432}, {819200, 819200}, {0, 0}, {0, 0}, {kInf, kInf}, // SIGPENDING MSGQUEUE NICE RTPRIO RTTIME
    }};
    struct NamedRange { std::uint64_t begin, end; std::string name; std::uint64_t off{0}; bool shared{false}; };
    template <class Fn>
    decltype(auto) with_names(Fn&& fn) {
        std::lock_guard g{mu_};
        return fn(names_);
    }
    // Forget names under [b, e): the range was unmapped or remapped.
    void unname(std::uint64_t b, std::uint64_t e) {
        std::lock_guard g{mu_};
        std::vector<NamedRange> keep;
        for (auto& r : names_) {
            if (r.end <= b || r.begin >= e) { keep.push_back(std::move(r)); continue; }
            if (r.begin < b) keep.push_back({r.begin, b, r.name, r.off, r.shared});
            if (r.end > e) keep.push_back({e, r.end, r.name, r.off + (e - r.begin), r.shared});
        }
        names_ = std::move(keep);
    }
    void name(std::uint64_t b, std::uint64_t e, std::string n, std::uint64_t off = 0, bool shared = false) {
        unname(b, e);
        std::lock_guard g{mu_};
        names_.push_back({b, e, std::move(n), off, shared});
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
    // The thread-group leader's blocked-signal mask, published at each trap
    // boundary, so /proc/<pid>/status's SigBlk shows it (it lives in the
    // leader's TaskState, which nothing else can see).
    std::atomic<std::uint64_t> leader_sigmask{0};
    // procfs redirected an open of /proc/<pid>/mem to /dev/null: that pid
    // (0 = none). The backend's open turns the fd into its memory.
    std::atomic<std::int32_t> pending_mem_pid{0};

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

    // What getuid/geteuid/getgid/getegid answer in-guest for THIS process.
    // Credentials are per process, as is the in-guest table they go in, so
    // the record of what was published is too: a new thread must not reset
    // it. nullopt = not learned yet (nothing published; the guest traps).
    struct Ids {
        std::uint32_t uid{0}, euid{0}, gid{0}, egid{0};
        bool operator==(const Ids&) const = default;
    };
    // Record `now`; true if it differs from what was published.
    [[nodiscard]] bool note_ids(const Ids& now) {
        std::lock_guard g{mu_};
        if (ids_ && *ids_ == now) return false;
        ids_ = now;
        return true;
    }
    [[nodiscard]] std::optional<Ids> ids() const {
        std::lock_guard g{mu_};
        return ids_;
    }
    void forget_ids() {
        std::lock_guard g{mu_};
        ids_.reset();
    }

    // mlock'd guest pages, for /proc/<pid>/status VmLck. A set of page
    // numbers: locking twice counts once, munlock of part of a range
    // unlocks exactly that part, as the kernel's VM_LOCKED does.
    void lock_pages(std::uint64_t at, std::uint64_t len, bool on) {
        std::lock_guard g{mu_};
        const std::uint64_t first = at / 4096, end = (at + len + 4095) / 4096;
        for (std::uint64_t p = first; p < end; ++p) {
            if (on) locked_.insert(p);
            else locked_.erase(p);
        }
    }
    [[nodiscard]] std::uint64_t locked_bytes() const {
        std::lock_guard g{mu_};
        return locked_.size() * 4096;
    }

    // (No tid allocator here on purpose: tids share ONE namespace with pids
    // across the whole guest tree, so they come from the shared PidSpace.
    // A per-process counter collides with other processes' pids.)

private:
    mutable std::mutex mu_;
    FdTable fds_;
    AddressSpace space_;
    SignalDispositions signals_;
    std::vector<Thread> threads_;
    std::vector<SharedMap> shared_maps_;
public:
    // Guest ranges whose host pages ARE a shared object's (HvfMachine::
    // back_shared): MAP_SHARED anonymous memory (an unlinked shm object) and
    // page-aligned MAP_SHARED file maps. Coherent with every other mapping
    // of the object, across fork and with read()/write(); `fd` is our own
    // reference, kept so a fork can map the same object in the child.
    struct Backing { std::uint64_t at, len; int fd; std::int64_t off; };
    template <class Fn>
    decltype(auto) with_backings(Fn&& fn) {
        std::lock_guard g{mu_};
        return fn(backings_);
    }
    // Listeners whose guest backlog is deeper than the host allows, by
    // host fd (darwin/accept_pump.hpp). Every thread's accept takes from
    // the same pump, so the map is the process's, not a thread's.
    using Pumps = std::map<int, std::unique_ptr<AcceptPump>>;
    template <class Fn>
    decltype(auto) with_pumps(Fn&& fn) {
        std::lock_guard g{pumps_mu_};
        return fn(pumps_);
    }
    [[nodiscard]] bool has_pumps() const noexcept { return any_pump_.load(std::memory_order_relaxed); }
    void note_pumps(bool any) noexcept { any_pump_.store(any, std::memory_order_relaxed); }
private:
    std::mutex pumps_mu_;
    Pumps pumps_;
    std::atomic<bool> any_pump_{false};
private:
    std::vector<Backing> backings_;
    std::optional<Ids> ids_;
    std::set<std::uint64_t> locked_;
    std::string environ_;
    std::string auxv_;
    std::string cmdline_;
    std::vector<NamedRange> names_;
    std::atomic<bool> group_exiting_{false};
    int group_status_{0};
};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
