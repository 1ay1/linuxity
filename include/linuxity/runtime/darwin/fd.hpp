// linuxity/runtime/darwin/fd.hpp
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
    // What a pipe-pair descriptor IS (the read end carries it, so every dup
    // and forked copy agrees): a plain pipe end, an eventfd counter (and
    // whether EFD_SEMAPHORE), or another pollable record source (timerfd,
    // signalfd) whose reads the backend formats itself. `full` is /dev/full,
    // which the host lacks: host /dev/zero for reads, ENOSPC for writes.
    enum class Kind : std::uint8_t { plain, eventfd, eventfd_sem, records, full };
    Kind kind{Kind::plain};
private:
    int fd_;
};

class FdTable {
public:
    static constexpr int kMaxFds = 1024;   // matches the RLIMIT_NOFILE we report

    // RLIMIT_NOFILE's soft limit: a new fd must be below it (EMFILE), as
    // Linux checks at every allocation. Lowering it leaves open fds alone.
    void set_limit(std::size_t soft) noexcept { limit_ = std::min<std::size_t>(soft, kMaxFds); }
    [[nodiscard]] std::size_t limit() const noexcept { return limit_; }

    // Seed 0/1/2 from DUPLICATES of the host's stdio, so the guest owns its
    // copies and can close or redirect them freely.
    FdTable() {
        for (int fd = 0; fd < 3; ++fd) {
            int d = ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
            if (d >= 0) install_at(fd, std::make_shared<HostFd>(d), false);
        }
    }

    // Occupy guest fds 3..8 with harmless /dev/null handles, so the guest's
    // own descriptors begin at 9 -- exactly like a program launched from a
    // real login session, which always inherits a few (terminal, journal,
    // dbus socket).
    //
    // This is load-bearing, not cosmetic. pacman's download worker closes a
    // low descriptor and immediately reopens that SAME number for core.db,
    // while sibling threads still believe the number is the old libcurl
    // wakeup channel and keep writing 8-byte wakeups to it. In a bare
    // 0,1,2-only process the two collide on fd 3 and the wakeups land INSIDE
    // the database: measured, core.db began 01 00 00 00 00 00 00 00 and
    // pacman rejected it as "Unrecognized archive format". The Linux backend
    // reserves these slots for the same reason (src/run_linux.cpp,
    // reserve_low_fds); both backends must agree.
    void reserve_low_fds() {
        for (int want = 3; want <= 8; ++want) {
            const int h = ::open("/dev/null", O_RDWR | O_CLOEXEC);
            if (h < 0) return;
            if (install(h, false) != want) return;       // dense from 0, so this holds
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
        for (std::size_t g = 0; g < slots_.size() && g < limit_; ++g)
            if (!slots_[g].file) { slots_[g] = {std::move(file), cloexec, {}}; return static_cast<int>(g); }
        if (slots_.size() >= limit_) return -24;
        slots_.push_back({std::move(file), cloexec, {}});
        return static_cast<int>(slots_.size() - 1);
    }

    // close(g): drop this guest fd's reference. -9 (EBADF) if unknown.
    [[nodiscard]] int close(int g) {
        if (!host(g)) return -9;
        slots_[static_cast<std::size_t>(g)] = {};
        return 0;
    }

    // dup(g) -> lowest free; dup3(g, to) -> exactly `to` (closing it first).
    // A dup of an eventfd is still an eventfd: the peer travels with it.
    [[nodiscard]] int dup(int g, std::optional<int> to, bool cloexec) {
        if (!host(g)) return -9;
        const Slot& src = slots_[static_cast<std::size_t>(g)];
        auto file = src.file;
        auto peer = src.peer;
        if (!to) {
            for (std::size_t i = 0; i < slots_.size() && i < limit_; ++i)
                if (!slots_[i].file) {
                    slots_[i] = {std::move(file), cloexec, std::move(peer)};
                    return static_cast<int>(i);
                }
            if (slots_.size() >= limit_) return -24;
            slots_.push_back({std::move(file), cloexec, std::move(peer)});
            return static_cast<int>(slots_.size() - 1);
        }
        if (*to < 0 || *to >= kMaxFds) return -9;
        if (*to == g) return g;
        install_at(*to, std::move(file), cloexec, std::move(peer));
        return *to;
    }

    [[nodiscard]] bool cloexec(int g) const noexcept {
        return host(g) && slots_[static_cast<std::size_t>(g)].cloexec;
    }
    void set_cloexec(int g, bool on) noexcept {
        if (host(g)) slots_[static_cast<std::size_t>(g)].cloexec = on;
    }

    // eventfd(2): ONE guest fd backed by a pipe PAIR. The guest reads and
    // writes the same descriptor, so the table holds both ends and keeps the
    // write end alive -- otherwise the read end would report EOF instead of
    // blocking, and an event loop would spin.
    [[nodiscard]] int install_eventfd(int read_end, int write_end, bool cloexec,
                                      HostFd::Kind kind = HostFd::Kind::records) {
        auto file = std::make_shared<HostFd>(read_end);
        file->kind = kind;
        auto peer = std::make_shared<HostFd>(write_end);
        for (std::size_t g = 0; g < slots_.size() && g < limit_; ++g)
            if (!slots_[g].file) {
                slots_[g] = {std::move(file), cloexec, std::move(peer)};
                return static_cast<int>(g);
            }
        if (slots_.size() >= limit_) return -24;
        slots_.push_back({std::move(file), cloexec, std::move(peer)});
        return static_cast<int>(slots_.size() - 1);
    }

    // What guest fd `g`'s open file is (plain when unknown).
    [[nodiscard]] HostFd::Kind kind(int g) const noexcept {
        if (g < 0 || static_cast<std::size_t>(g) >= slots_.size()) return HostFd::Kind::plain;
        const Slot& s = slots_[static_cast<std::size_t>(g)];
        return s.file ? s.file->kind : HostFd::Kind::plain;
    }
    void set_kind(int g, HostFd::Kind k) noexcept {
        if (g < 0 || static_cast<std::size_t>(g) >= slots_.size()) return;
        if (auto& f = slots_[static_cast<std::size_t>(g)].file) f->kind = k;
    }

    // If `g` is an eventfd (a counter): its two host ends and its mode.
    struct EventFdEnds { int read, write; bool semaphore; };
    [[nodiscard]] std::optional<EventFdEnds> eventfd(int g) const noexcept {
        if (g < 0 || static_cast<std::size_t>(g) >= slots_.size()) return std::nullopt;
        const Slot& s = slots_[static_cast<std::size_t>(g)];
        if (!s.file || !s.peer) return std::nullopt;
        const auto k = s.file->kind;
        if (k != HostFd::Kind::eventfd && k != HostFd::Kind::eventfd_sem) return std::nullopt;
        return EventFdEnds{s.file->get(), s.peer->get(), k == HostFd::Kind::eventfd_sem};
    }

    // The write end, if `g` is an eventfd; a write must go there, not to the
    // read end the guest holds.
    [[nodiscard]] std::optional<int> write_host(int g) const noexcept {
        if (g < 0 || static_cast<std::size_t>(g) >= slots_.size()) return std::nullopt;
        const Slot& s = slots_[static_cast<std::size_t>(g)];
        if (!s.file) return std::nullopt;
        return s.peer ? s.peer->get() : s.file->get();
    }

    // execve: drop every FD_CLOEXEC descriptor.
    void on_exec() {
        for (auto& s : slots_) if (s.cloexec) s = {};
    }
    // The guest fds on_exec() is about to drop.
    [[nodiscard]] std::vector<int> cloexec_fds() const {
        std::vector<int> v;
        for (std::size_t g = 0; g < slots_.size(); ++g)
            if (slots_[g].file && slots_[g].cloexec) v.push_back(static_cast<int>(g));
        return v;
    }
    [[nodiscard]] bool open(int g) const noexcept { return host(g).has_value(); }

    // -- Fork handoff -------------------------------------------------------
    // A spawn-based fork (runtime/darwin/fork.hpp) gives the child a fresh fd
    // table, so the parent describes its table and arranges for each distinct
    // host fd to arrive in the child at a known number.
    //
    // The unit of identity is the OPEN FILE (the HostFd object), not the fd
    // number: guest fds sharing one HostFd (dup) must still share one after
    // the fork, because they share an offset on Linux. And an eventfd is ONE
    // guest fd over TWO host fds -- its read end and its write end -- so the
    // write end must travel too. Dropping it (as an earlier version did) left
    // the child believing fd 3 was an eventfd while holding only half of it;
    // pacman's download worker then reopened fd 3 for core.db, and its
    // sibling threads' 8-byte wakeups landed IN the database file.
    struct Exported {
        int guest;
        int group;          // the open file, numbered densely
        int peer_group;     // eventfd write end's group, or -1
        bool cloexec;
        HostFd::Kind kind;  // what the open file is (see HostFd::Kind)
    };
    struct Export {
        std::vector<Exported> entries;
        std::vector<int> host_fds;      // host fd for each group, in the PARENT
        // The open files themselves: held for as long as the fork needs
        // host_fds, so a sibling thread's close() can't free a number under
        // it. (Not dup'd: on macOS closing ANY fd of a file drops the
        // process's POSIX record locks on it.)
        std::vector<std::shared_ptr<HostFd>> keep;
    };
    [[nodiscard]] Export export_table() const {
        Export out;
        std::vector<const HostFd*> seen;
        auto group_of = [&](const std::shared_ptr<HostFd>& f) -> int {
            if (!f) return -1;
            auto it = std::find(seen.begin(), seen.end(), f.get());
            if (it != seen.end()) return static_cast<int>(it - seen.begin());
            seen.push_back(f.get());
            out.host_fds.push_back(f->get());
            out.keep.push_back(f);
            return static_cast<int>(seen.size() - 1);
        };
        for (std::size_t g = 0; g < slots_.size(); ++g) {
            const Slot& s = slots_[g];
            if (!s.file) continue;
            out.entries.push_back({static_cast<int>(g), group_of(s.file),
                                   group_of(s.peer), s.cloexec, s.file->kind});
        }
        return out;
    }
    // Child side: `host_of_group[i]` is where group i's host fd landed.
    void import_table(const std::vector<Exported>& in,
                      const std::vector<int>& host_of_group) {
        slots_.clear();
        std::vector<std::shared_ptr<HostFd>> files(host_of_group.size());
        auto file_for = [&](int gi) -> std::shared_ptr<HostFd> {
            if (gi < 0 || static_cast<std::size_t>(gi) >= files.size()) return {};
            auto& f = files[static_cast<std::size_t>(gi)];
            if (!f) f = std::make_shared<HostFd>(host_of_group[static_cast<std::size_t>(gi)]);
            return f;
        };
        for (const Exported& e : in) {
            auto file = file_for(e.group);
            if (!file) continue;
            file->kind = e.kind;
            install_at(e.guest, std::move(file), e.cloexec, file_for(e.peer_group));
        }
    }

private:
    struct Slot {
        std::shared_ptr<HostFd> file;
        bool cloexec{false};
        // eventfd's write end (null for an ordinary descriptor).
        std::shared_ptr<HostFd> peer;
    };

    void install_at(int g, std::shared_ptr<HostFd> file, bool cloexec,
                    std::shared_ptr<HostFd> peer = {}) {
        if (static_cast<std::size_t>(g) >= slots_.size())
            slots_.resize(static_cast<std::size_t>(g) + 1);
        slots_[static_cast<std::size_t>(g)] = {std::move(file), cloexec, std::move(peer)};
    }

    std::vector<Slot> slots_;
    std::size_t limit_{kMaxFds};      // RLIMIT_NOFILE soft (set_limit)
};

} // namespace lx::runtime

#endif // __APPLE__
