// linuxity/runtime/hvf_fdobj.hpp
//
// Kernel objects that are file descriptors: timerfd, signalfd, inotify,
// memfd, pidfd.
//
// Linux exposes a lot of kernel state as "an fd you can poll", which is why
// these turn up in every event loop: systemd, containerd, inotifywait,
// Chrome's sandbox, Go's os/signal, cargo's file watcher. Darwin has none of
// them under those names, but it has the same CAPABILITIES in other shapes,
// and in every case the fd-ness is the part that matters -- callers poll it,
// read it, and pass it around.
//
// So each one is built from a Darwin primitive that gives it the right
// observable behaviour:
//
//   timerfd   -- a pipe fed by the shared TimerSet wheel; a read yields the
//                expiration count, exactly like Linux.
//   signalfd  -- a pipe fed at signal-delivery time with signalfd_siginfo
//                records, so a program can select() on signals.
//   inotify   -- a kqueue with EVFILT_VNODE watches, re-encoded as
//                inotify_event records.
//   memfd     -- an unlinked temp file: anonymous, sizeable, mappable,
//                sealable-ish. What memfd is FOR (shared buffers, passing
//                an fd instead of a path) works unchanged.
//   pidfd     -- a kqueue with EVFILT_PROC, so poll() wakes on child exit.
#pragma once

#if defined(__APPLE__)

#include <fcntl.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace lx::runtime {

// -- timerfd ---------------------------------------------------------------
// struct itimerspec is already in hvf_timer.hpp; a timerfd read returns the
// number of expirations as a u64.
struct TimerFd {
    int read_end{-1};
    int write_end{-1};
    int timer_id{-1};          // into the process TimerSet
};

// -- signalfd --------------------------------------------------------------
// struct signalfd_siginfo, as Linux lays it out. 128 bytes; only the first
// few fields are read in practice, but the SIZE is load-bearing because
// callers read in multiples of it.
struct LinuxSignalfdSiginfo {
    std::uint32_t ssi_signo, ssi_errno_, ssi_code;
    std::uint32_t ssi_pid, ssi_uid;
    std::int32_t  ssi_fd;
    std::uint32_t ssi_tid, ssi_band, ssi_overrun, ssi_trapno;
    std::int32_t  ssi_status, ssi_int;
    std::uint64_t ssi_ptr, ssi_utime, ssi_stime, ssi_addr;
    std::uint16_t ssi_addr_lsb;
    std::uint8_t  pad_[46];
};
static_assert(sizeof(LinuxSignalfdSiginfo) == 128);

// -- inotify ---------------------------------------------------------------
// struct inotify_event { int wd; u32 mask, cookie, len; char name[]; }
struct LinuxInotifyEvent {
    std::int32_t wd;
    std::uint32_t mask, cookie, len;
};
static_assert(sizeof(LinuxInotifyEvent) == 16);

namespace inotify_bit {
inline constexpr std::uint32_t access      = 0x001;
inline constexpr std::uint32_t modify      = 0x002;
inline constexpr std::uint32_t attrib      = 0x004;
inline constexpr std::uint32_t close_write = 0x008;
inline constexpr std::uint32_t close_nowr  = 0x010;
inline constexpr std::uint32_t open_       = 0x020;
inline constexpr std::uint32_t moved_from  = 0x040;
inline constexpr std::uint32_t moved_to    = 0x080;
inline constexpr std::uint32_t create      = 0x100;
inline constexpr std::uint32_t delete_     = 0x200;
inline constexpr std::uint32_t delete_self = 0x400;
inline constexpr std::uint32_t move_self   = 0x800;
}  // namespace inotify_bit

// One inotify instance: a kqueue plus its watch descriptors.
class InotifyFd {
public:
    InotifyFd() : kq_{::kqueue()} {}
    InotifyFd(const InotifyFd&) = delete;
    InotifyFd& operator=(const InotifyFd&) = delete;
    ~InotifyFd() {
        for (const Watch& w : watches_) if (w.fd >= 0) ::close(w.fd);
        if (kq_ >= 0) ::close(kq_);
    }

    [[nodiscard]] bool valid() const noexcept { return kq_ >= 0; }
    [[nodiscard]] int kq() const noexcept { return kq_; }

    // add_watch(host_path, mask) -> wd, or -errno.
    [[nodiscard]] std::int64_t add_watch(const std::string& path, std::uint32_t mask) {
        // An existing watch on the same path is UPDATED and keeps its wd,
        // which is what inotify_add_watch promises.
        for (Watch& w : watches_)
            if (w.path == path) { w.mask = mask; return w.wd; }
        const int fd = ::open(path.c_str(), O_EVTONLY | O_CLOEXEC);
        if (fd < 0) return -static_cast<std::int64_t>(errno == ENOENT ? 2 : 13);
        struct ::kevent ev{};
        const std::uint32_t fflags = NOTE_WRITE | NOTE_DELETE | NOTE_RENAME
                                   | NOTE_ATTRIB | NOTE_EXTEND | NOTE_LINK;
        const int wd = next_wd_++;
        EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, fflags, 0,
               reinterpret_cast<void*>(static_cast<std::intptr_t>(wd)));
        if (::kevent(kq_, &ev, 1, nullptr, 0, nullptr) < 0) {
            ::close(fd);
            return -static_cast<std::int64_t>(errno);
        }
        watches_.push_back({wd, fd, mask, path});
        return wd;
    }

    [[nodiscard]] std::int64_t rm_watch(int wd) {
        for (auto it = watches_.begin(); it != watches_.end(); ++it)
            if (it->wd == wd) {
                ::close(it->fd);
                watches_.erase(it);
                return 0;
            }
        return -22;                          // EINVAL
    }

    // Drain ready events into Linux inotify_event records. Returns the byte
    // count written, 0 if nothing is ready (the caller reports EAGAIN).
    [[nodiscard]] std::size_t drain(std::span<std::byte> out) {
        struct ::kevent evs[32];
        struct ::timespec zero{};
        const int n = ::kevent(kq_, nullptr, 0, evs, 32, &zero);
        std::size_t used = 0;
        for (int i = 0; i < n; ++i) {
            const int wd = static_cast<int>(reinterpret_cast<std::intptr_t>(evs[i].udata));
            std::uint32_t mask = 0;
            const auto f = evs[i].fflags;
            if (f & (NOTE_WRITE | NOTE_EXTEND)) mask |= inotify_bit::modify;
            if (f & NOTE_ATTRIB) mask |= inotify_bit::attrib;
            if (f & NOTE_DELETE) mask |= inotify_bit::delete_self;
            if (f & NOTE_RENAME) mask |= inotify_bit::move_self;
            if (f & NOTE_LINK)   mask |= inotify_bit::create;
            if (!mask) continue;
            // A directory NOTE_WRITE means "something inside changed";
            // inotify would name the entry, but kqueue does not tell us
            // which, so report the directory itself modified. Watchers
            // rescan on any event, which is why this is sufficient in
            // practice (it is also what every kqueue-based inotify shim does).
            if (used + sizeof(LinuxInotifyEvent) > out.size()) break;
            const LinuxInotifyEvent e{wd, mask, 0, 0};
            std::memcpy(out.data() + used, &e, sizeof e);
            used += sizeof e;
        }
        return used;
    }

private:
    struct Watch { int wd; int fd; std::uint32_t mask; std::string path; };
    int kq_;
    int next_wd_{1};
    std::vector<Watch> watches_;
};

// -- memfd ----------------------------------------------------------------
// An unlinked temp file. Anonymous (no name in the namespace), growable with
// ftruncate, mappable, and passable as an fd -- which is the whole point of
// memfd_create. F_SEAL_* has no Darwin equivalent; sealing is recorded so
// F_GET_SEALS reports back what was set.
[[nodiscard]] inline int make_memfd(const std::string& name) {
    std::string tmpl = "/tmp/linuxity-memfd-" + name + "-XXXXXX";
    const int fd = ::mkstemp(tmpl.data());
    if (fd < 0) return -1;
    ::unlink(tmpl.c_str());
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

// -- pidfd ----------------------------------------------------------------
// A kqueue with EVFILT_PROC, so poll()/epoll on the fd wakes when the
// process exits -- the property pidfd exists for.
[[nodiscard]] inline int make_pidfd(::pid_t pid) {
    const int kq = ::kqueue();
    if (kq < 0) return -1;
    struct ::kevent ev{};
    EV_SET(&ev, pid, EVFILT_PROC, EV_ADD | EV_CLEAR, NOTE_EXIT, 0, nullptr);
    if (::kevent(kq, &ev, 1, nullptr, 0, nullptr) < 0) { ::close(kq); return -1; }
    ::fcntl(kq, F_SETFD, FD_CLOEXEC);
    return kq;
}

} // namespace lx::runtime

#endif // __APPLE__
