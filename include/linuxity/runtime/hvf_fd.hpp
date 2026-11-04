// linuxity/runtime/hvf_fd.hpp
//
// The guest file-descriptor table.
//
// On the ptrace backend the guest is a separate host process, so its fd
// table IS a host fd table and nothing can leak. Here the guest runs inside
// linuxity's own process, and the naive design (guest fd == host fd) is
// wrong in a way that only shows up late: coreutils closes stdout at exit,
// and with a shared table that closes LINUXITY'S stdout -- every later line
// the host prints silently vanishes.
//
// So the guest gets its own table: guest fd -> refcounted host fd. Guest
// close() drops a reference; the host fd only closes when no guest fd names
// it, and the three inherited stdio fds are dup()'d at construction, so a
// guest closing 0/1/2 never touches the host's.
//
// Lookup is a flat vector indexed by guest fd: O(1), and guest fds are small
// dense integers by POSIX's lowest-free rule, so the vector stays compact.
#pragma once

#if defined(__APPLE__)

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace lx::runtime {

// One host fd, closed when the last guest fd referring to it goes away.
// dup()/dup2() share the same HostFd, exactly like the open file description
// they share on Linux.
class HostFd {
public:
    explicit HostFd(int fd) noexcept : fd_{fd} {}
    HostFd(const HostFd&) = delete;
    HostFd& operator=(const HostFd&) = delete;
    ~HostFd() { if (fd_ >= 0) ::close(fd_); }
    [[nodiscard]] int get() const noexcept { return fd_; }
private:
    int fd_;
};

class FdTable {
public:
    static constexpr int kMaxFds = 1024;   // matches the RLIMIT_NOFILE we report

    // Seed 0/1/2 from DUPLICATES of the host's stdio, so the guest owns its
    // copies and can close or redirect them freely.
    FdTable() {
        for (int fd = 0; fd < 3; ++fd) {
            int d = ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
            if (d >= 0) install_at(fd, std::make_shared<HostFd>(d), false);
        }
    }

    // Host fd backing guest fd `g`, or nullopt (EBADF).
    [[nodiscard]] std::optional<int> host(int g) const noexcept {
        if (g < 0 || static_cast<std::size_t>(g) >= slots_.size()) return std::nullopt;
        const Slot& s = slots_[static_cast<std::size_t>(g)];
        if (!s.file) return std::nullopt;
        return s.file->get();
    }

    // Adopt a freshly opened host fd under the lowest free guest fd (POSIX).
    // Returns the guest fd, or -24 (EMFILE).
    [[nodiscard]] int install(int host_fd, bool cloexec) {
        auto file = std::make_shared<HostFd>(host_fd);
        for (std::size_t g = 0; g < slots_.size(); ++g)
            if (!slots_[g].file) { slots_[g] = {std::move(file), cloexec}; return static_cast<int>(g); }
        if (slots_.size() >= kMaxFds) return -24;
        slots_.push_back({std::move(file), cloexec});
        return static_cast<int>(slots_.size() - 1);
    }

    // close(g): drop this guest fd's reference. -9 (EBADF) if unknown.
    [[nodiscard]] int close(int g) {
        if (!host(g)) return -9;
        slots_[static_cast<std::size_t>(g)] = {};
        return 0;
    }

    // dup(g) -> lowest free; dup3(g, to) -> exactly `to` (closing it first).
    [[nodiscard]] int dup(int g, std::optional<int> to, bool cloexec) {
        if (!host(g)) return -9;
        auto file = slots_[static_cast<std::size_t>(g)].file;
        if (!to) {
            for (std::size_t i = 0; i < slots_.size(); ++i)
                if (!slots_[i].file) { slots_[i] = {std::move(file), cloexec}; return static_cast<int>(i); }
            if (slots_.size() >= kMaxFds) return -24;
            slots_.push_back({std::move(file), cloexec});
            return static_cast<int>(slots_.size() - 1);
        }
        if (*to < 0 || *to >= kMaxFds) return -9;
        if (*to == g) return g;
        install_at(*to, std::move(file), cloexec);
        return *to;
    }

    [[nodiscard]] bool cloexec(int g) const noexcept {
        return host(g) && slots_[static_cast<std::size_t>(g)].cloexec;
    }
    void set_cloexec(int g, bool on) noexcept {
        if (host(g)) slots_[static_cast<std::size_t>(g)].cloexec = on;
    }

    // execve: drop every FD_CLOEXEC descriptor.
    void on_exec() {
        for (auto& s : slots_) if (s.cloexec) s = {};
    }

    // -- Fork handoff -------------------------------------------------------
    // A spawn-based fork (runtime/hvf_fork.hpp) gives the child a fresh fd
    // table, so the parent describes its table as (guest fd, host fd, flags)
    // and arranges for each distinct host fd to arrive in the child at a
    // known number. Guest fds sharing one HostFd (dup) must STILL share one
    // after the fork -- they share a file offset on Linux -- so entries are
    // grouped by the HostFd object, not by host fd number.
    struct Exported {
        int guest;
        int host;      // number in the PARENT (posix_spawn dup2's it across)
        int group;     // equal for guest fds that share an open file
        bool cloexec;
    };
    [[nodiscard]] std::vector<Exported> export_table() const {
        std::vector<Exported> out;
        std::vector<const HostFd*> groups;
        for (std::size_t g = 0; g < slots_.size(); ++g) {
            const Slot& s = slots_[g];
            if (!s.file) continue;
            auto it = std::find(groups.begin(), groups.end(), s.file.get());
            int grp = static_cast<int>(it - groups.begin());
            if (it == groups.end()) groups.push_back(s.file.get());
            out.push_back({static_cast<int>(g), s.file->get(), grp, s.cloexec});
        }
        return out;
    }
    // Child side: `host_of_group[i]` is where group i's fd landed.
    void import_table(const std::vector<Exported>& in,
                      const std::vector<int>& host_of_group) {
        slots_.clear();
        std::vector<std::shared_ptr<HostFd>> files(host_of_group.size());
        for (const Exported& e : in) {
            auto gi = static_cast<std::size_t>(e.group);
            if (gi >= files.size()) continue;
            if (!files[gi]) files[gi] = std::make_shared<HostFd>(host_of_group[gi]);
            install_at(e.guest, files[gi], e.cloexec);
        }
    }

private:
    struct Slot {
        std::shared_ptr<HostFd> file;
        bool cloexec{false};
    };

    void install_at(int g, std::shared_ptr<HostFd> file, bool cloexec) {
        if (static_cast<std::size_t>(g) >= slots_.size())
            slots_.resize(static_cast<std::size_t>(g) + 1);
        slots_[static_cast<std::size_t>(g)] = {std::move(file), cloexec};
    }

    std::vector<Slot> slots_;
};

} // namespace lx::runtime

#endif // __APPLE__
