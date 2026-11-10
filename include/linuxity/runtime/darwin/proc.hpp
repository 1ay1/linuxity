// linuxity/runtime/darwin/proc.hpp
//
// The guest process model for the HVF backend.
//
// One guest process == one host process. fork() is a real Darwin fork of
// linuxity itself (the VM is torn down and rebuilt on both sides, see
// HvfVm::fork_process), so the host kernel does everything it is good at:
// copy-on-write memory, scheduling across cores, process lifetime, reaping,
// and exit statuses. linuxity only VIRTUALIZES the numbering, so the guest
// sees a Linux pid namespace -- init is pid 1, children count up from 2 --
// rather than macOS pids like 48211.
//
// The mapping lives in an anonymous MAP_SHARED page created before the first
// fork, so every process in the tree sees one table: a grandchild's getppid()
// and a sibling's kill(pid) resolve through the same numbers.
#pragma once

#if defined(__APPLE__)

#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lx::runtime {

class PidSpace {
public:
    static constexpr int kMax = 4096;   // concurrent guest processes

    // Root of the tree: create the table in an anonymous file the children
    // can inherit. (A MAP_SHARED|MAP_ANON page is NOT inherited across
    // posix_spawn, which is how macOS forks -- see hvf_fork.hpp -- so the
    // table is a file descriptor, passed down like any other.)
    PidSpace() {
        char tmpl[] = "/tmp/linuxity-pids-XXXXXX";
        fd_ = ::mkstemp(tmpl);
        if (fd_ < 0) return;
        ::unlink(tmpl);
        if (::ftruncate(fd_, sizeof(Shared)) != 0) return;
        map();
        if (!shared_) return;
        new (shared_) Shared{};
        shared_->next.store(2, std::memory_order_relaxed);
        shared_->host[1].store(::getpid(), std::memory_order_relaxed);
    }
    // A fork child: attach to the parent's table through the inherited fd.
    explicit PidSpace(int inherited_fd) : fd_{inherited_fd} { map(); }
    [[nodiscard]] int fd() const noexcept { return fd_; }
    PidSpace(const PidSpace&) = delete;
    PidSpace& operator=(const PidSpace&) = delete;
    // Deliberately no munmap in the destructor: forked children inherit the
    // object and must not unmap the table out from under the rest of the tree.

    [[nodiscard]] bool valid() const noexcept { return shared_ != nullptr; }

    // -- The VM budget --------------------------------------------------------
    // Every guest process is a host process holding a Hypervisor.framework
    // VM, and a Mac allows kMaxVms of those at once (measured: 128, the
    // framework's limit). Warm zygotes hold one each while parked, so they
    // are budgeted across the WHOLE tree: a deep process tree must not
    // spend its VMs on idle spares and then fail the fork that needed one.
    // Spares may use what is left above kKeepFree; a real fork never waits
    // on this -- it falls back to a fresh process (its own VM) when no
    // spare is parked.
    static constexpr int kMaxVms = 128;
    static constexpr int kKeepFree = 32;   // never parked: real processes' headroom
    // Processes holding (or about to hold) a VM: every bound or reserved
    // slot -- a fork in flight (kReserved) needs one as much as a live one.
    [[nodiscard]] int live_processes() const noexcept {
        int n = 0;
        for (int g = 1; g < kMax; ++g)
            if (shared_->host[g].load(std::memory_order_relaxed) != 0) ++n;
        return n;
    }
    // Reserve a VM for one more parked zygote, if the tree can spare it.
    [[nodiscard]] bool reserve_warm_vm() noexcept {
        if (!shared_) return false;
        const int busy = live_processes();
        int w = shared_->warm_vms.load(std::memory_order_relaxed);
        do {
            if (busy + w + 1 > kMaxVms - kKeepFree) return false;
        } while (!shared_->warm_vms.compare_exchange_weak(w, w + 1));
        return true;
    }
    // A parked zygote was claimed (it becomes a live process) or exited.
    void release_warm_vm() noexcept {
        if (shared_) shared_->warm_vms.fetch_sub(1, std::memory_order_relaxed);
    }

    // Allocate a guest pid. `host` may be 0 to RESERVE the slot before the
    // host process exists (fork assigns the child's pid up front); bind()
    // fills it in once the host pid is known.
    [[nodiscard]] std::int32_t allocate(pid_t host) noexcept {
        const pid_t mark = host ? host : kReserved;
        for (int tries = 0; tries < kMax; ++tries) {
            int g = shared_->next.fetch_add(1, std::memory_order_relaxed);
            if (g >= kMax) { shared_->next.store(2); g = shared_->next.fetch_add(1); }
            pid_t expected = 0;
            if (shared_->host[g].compare_exchange_strong(expected, mark))
                return g;
        }
        return -1;
    }
    void bind(std::int32_t g, pid_t host) noexcept {
        if (g > 0 && g < kMax) {
            shared_->execed[g].store(false, std::memory_order_relaxed);
            shared_->host[g].store(host, std::memory_order_release);
        }
    }

    // -- Process groups -----------------------------------------------------
    // Every guest process belongs to a group, identified by its leader's
    // guest pid. A group is what `kill(-pgid)` and a terminal's ^C target,
    // and what a shell puts a pipeline into.
    //
    // This has to be REAL rather than "every process is its own group":
    // pacman asks for its group with getpgrp() and then SIGTERMs it to stop
    // its download workers. With a flat model that group contains only
    // pacman, so pacman kills itself -- `pacman -Sy` died with "Terminated"
    // right after reporting every database up to date.
    void set_pgid(std::int32_t pid, std::int32_t pgid) noexcept {
        if (pid > 0 && pid < kMax && pgid > 0 && pgid < kMax)
            shared_->pgid[pid].store(pgid, std::memory_order_release);
    }
    [[nodiscard]] std::int32_t pgid_of(std::int32_t pid) const noexcept {
        if (pid <= 0 || pid >= kMax) return 0;
        const std::int32_t g = shared_->pgid[pid].load(std::memory_order_acquire);
        return g ? g : pid;                 // unset => its own leader
    }
    // Every live member of a group, for kill(-pgid) and kill(0).
    [[nodiscard]] std::vector<std::int32_t> members_of(std::int32_t pgid) const {
        std::vector<std::int32_t> out;
        for (std::int32_t p = 1; p < kMax; ++p) {
            if (!shared_->host[p].load(std::memory_order_relaxed)) continue;
            if (pgid_of(p) == pgid) out.push_back(p);
        }
        return out;
    }
    // Sessions, same model: the leader's pid names the session.
    void set_sid(std::int32_t pid, std::int32_t sid) noexcept {
        if (pid > 0 && pid < kMax && sid > 0 && sid < kMax)
            shared_->sid[pid].store(sid, std::memory_order_release);
    }
    [[nodiscard]] std::int32_t sid_of(std::int32_t pid) const noexcept {
        if (pid <= 0 || pid >= kMax) return 0;
        const std::int32_t s = shared_->sid[pid].load(std::memory_order_acquire);
        return s ? s : pid;
    }
    // vfork support: a child announces it has exec'd (its parent may run).
    void mark_execed(std::int32_t g) noexcept {
        if (g > 0 && g < kMax) shared_->execed[g].store(true, std::memory_order_release);
    }
    [[nodiscard]] bool has_execed(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_->execed[g].load(std::memory_order_acquire);
    }
    void release(std::int32_t g) noexcept {
        if (g > 1 && g < kMax) {
            shared_->exe[g][0] = '\0';
            shared_->host[g].store(0, std::memory_order_relaxed);
        }
    }

    // /proc/<pid>/exe for any guest pid. Children inherit until they exec.
    void set_exe(std::int32_t g, std::string_view path) noexcept {
        if (g <= 0 || g >= kMax || !shared_) return;
        const std::size_t n = std::min(path.size(), kExe - 1);
        std::memcpy(shared_->exe[g], path.data(), n);
        shared_->exe[g][n] = '\0';
    }
    [[nodiscard]] std::string exe_of(std::int32_t g) const {
        if (g <= 0 || g >= kMax || !shared_) return {};
        char buf[kExe];
        std::memcpy(buf, shared_->exe[g], kExe);
        buf[kExe - 1] = '\0';
        return buf;
    }
    // A live guest PROCESS (not a thread: threads allocate a tid here too,
    // but only processes record an image). Its host pid must still exist.
    [[nodiscard]] bool is_process(std::int32_t g) const noexcept {
        if (g <= 0 || g >= kMax || !shared_ || !shared_->exe[g][0]) return false;
        const pid_t h = shared_->host[g].load(std::memory_order_relaxed);
        return h > 0 && (::kill(h, 0) == 0 || errno == EPERM);
    }
    [[nodiscard]] std::vector<std::int32_t> processes() const {
        std::vector<std::int32_t> out;
        if (!shared_) return out;
        for (int g = 1; g < kMax; ++g)
            if (shared_->exe[g][0] && is_process(g)) out.push_back(g);
        return out;
    }
    // The guest pid that forked g (0 for init). Recorded at fork.
    void set_ppid(std::int32_t g, std::int32_t parent) noexcept {
        if (g > 0 && g < kMax && shared_) shared_->ppid[g].store(parent, std::memory_order_relaxed);
    }
    [[nodiscard]] std::int32_t ppid_of(std::int32_t g) const noexcept {
        return (g > 0 && g < kMax && shared_) ? shared_->ppid[g].load(std::memory_order_relaxed) : 0;
    }

    [[nodiscard]] std::optional<pid_t> host_of(std::int32_t g) const noexcept {
        if (g <= 0 || g >= kMax) return std::nullopt;
        pid_t h = shared_->host[g].load(std::memory_order_relaxed);
        return h ? std::optional{h} : std::nullopt;
    }
    [[nodiscard]] std::int32_t guest_of(pid_t host) const noexcept {
        for (int g = 1; g < kMax; ++g)
            if (shared_->host[g].load(std::memory_order_relaxed) == host) return g;
        return -1;
    }

private:
    void map() {
        void* p = ::mmap(nullptr, sizeof(Shared), PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd_, 0);
        shared_ = p == MAP_FAILED ? nullptr : static_cast<Shared*>(p);
    }
    static constexpr pid_t kReserved = -1;
    static constexpr std::size_t kExe = 256;
    struct Shared {
        std::atomic<int> next{2};
        std::atomic<pid_t> host[kMax]{};
        std::atomic<bool> execed[kMax]{};
        // Process-group and session leader per pid; 0 means "itself".
        std::atomic<std::int32_t> pgid[kMax]{};
        std::atomic<std::int32_t> sid[kMax]{};
        // Guest path of each process's current image, for /proc/<pid>/exe.
        // Every guest process is its own HOST process, so only this shared
        // page can answer "what is pid N running" for a pid other than us.
        // Written by the process itself on exec; a seqlock-free best effort
        // (a torn read can only produce a wrong name, never a crash: the
        // buffer is always NUL-terminated at kExe-1).
        char exe[kMax][kExe]{};
        std::atomic<std::int32_t> ppid[kMax]{};
        // Hypervisor.framework VMs held by PARKED zygotes, tree-wide.
        std::atomic<int> warm_vms{0};
    };
    Shared* shared_{nullptr};
    int fd_{-1};
};

// Linux and Darwin agree on the wait status ENCODING (WIFEXITED etc. are the
// same bit layout), but not on every signal NUMBER. Translate the ones that
// differ so a guest shell reports "Killed"/"Terminated"/"Segmentation fault"
// correctly. The low 15 are POSIX-fixed and identical.
[[nodiscard]] constexpr int signal_to_linux(int s) noexcept {
    switch (s) {
        case SIGBUS:  return 7;
        case SIGUSR1: return 10;
        case SIGUSR2: return 12;
        case SIGCHLD: return 17;
        case SIGCONT: return 18;
        case SIGSTOP: return 19;
        case SIGTSTP: return 20;
        case SIGURG:  return 23;
        case SIGSYS:  return 31;
        default:      return s;
    }
}
[[nodiscard]] constexpr int signal_from_linux(int s) noexcept {
    switch (s) {
        case 7:  return SIGBUS;
        case 10: return SIGUSR1;
        case 12: return SIGUSR2;
        case 17: return SIGCHLD;
        case 18: return SIGCONT;
        case 19: return SIGSTOP;
        case 20: return SIGTSTP;
        case 23: return SIGURG;
        case 31: return SIGSYS;
        default: return s;
    }
}

// A Darwin wait status -> the Linux encoding of the same event.
[[nodiscard]] constexpr int wstatus_to_linux(int st) noexcept {
    if (WIFEXITED(st))   return (WEXITSTATUS(st) & 0xff) << 8;
    if (WIFSIGNALED(st)) return (signal_to_linux(WTERMSIG(st)) & 0x7f) | (WCOREDUMP(st) ? 0x80 : 0);
    if (WIFSTOPPED(st))  return (signal_to_linux(WSTOPSIG(st)) << 8) | 0x7f;
    return st;
}

} // namespace lx::runtime

#endif // __APPLE__
