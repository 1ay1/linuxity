// linuxity/runtime/hvf_proc.hpp
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
#include <cstdint>
#include <optional>

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
    // vfork support: a child announces it has exec'd (its parent may run).
    void mark_execed(std::int32_t g) noexcept {
        if (g > 0 && g < kMax) shared_->execed[g].store(true, std::memory_order_release);
    }
    [[nodiscard]] bool has_execed(std::int32_t g) const noexcept {
        return g > 0 && g < kMax && shared_->execed[g].load(std::memory_order_acquire);
    }
    void release(std::int32_t g) noexcept {
        if (g > 1 && g < kMax) shared_->host[g].store(0, std::memory_order_relaxed);
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
    struct Shared {
        std::atomic<int> next{2};
        std::atomic<pid_t> host[kMax]{};
        std::atomic<bool> execed[kMax]{};
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
