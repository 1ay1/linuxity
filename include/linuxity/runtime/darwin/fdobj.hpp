// linuxity/runtime/darwin/fdobj.hpp
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
#include <sys/xattr.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <optional>
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
            if (w.path == path) {
                w.mask = mask;
                struct ::kevent ev{};
                EV_SET(&ev, w.fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
                       notes_for(mask, w.is_dir), 0,
                       reinterpret_cast<void*>(static_cast<std::intptr_t>(w.wd)));
                (void)::kevent(kq_, &ev, 1, nullptr, 0, nullptr);
                return w.wd;
            }
        const int fd = ::open(path.c_str(), O_EVTONLY | O_CLOEXEC);
        if (fd < 0) return -static_cast<std::int64_t>(errno == ENOENT ? 2 : 13);
        struct ::stat st{};
        const bool is_dir = ::fstat(fd, &st) == 0 && S_ISDIR(st.st_mode);
        struct ::kevent ev{};
        const std::uint32_t fflags = notes_for(mask, is_dir);
        const int wd = next_wd_++;
        EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, fflags, 0,
               reinterpret_cast<void*>(static_cast<std::intptr_t>(wd)));
        if (::kevent(kq_, &ev, 1, nullptr, 0, nullptr) < 0) {
            ::close(fd);
            return -static_cast<std::int64_t>(errno);
        }
        watches_.push_back({wd, fd, mask, path, is_dir});
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
            const Watch* w = nullptr;
            for (const Watch& x : watches_) if (x.wd == wd) { w = &x; break; }
            if (!w) continue;                        // removed since queued
            std::uint32_t mask = 0;
            const auto f = evs[i].fflags;
            if (w->is_dir) {
                // kqueue says only "this directory's contents changed". The
                // honest inotify rendering is an event about the DIRECTORY
                // with no name, which watchers treat as "rescan". Never turn
                // it into DELETE_SELF/MOVE_SELF of a child: gpg-agent
                // watches its homedir's parent and shuts down ("homedir has
                // been removed") on any such event.
                //
                // Report it with whichever entry-level bits the watcher ASKED
                // for: notes_for() only registered NOTE_WRITE because of
                // them, so dropping it would leave a readable fd that
                // read() blocks on forever. (gpg-agent watches its socket
                // dir for IN_DELETE alone; filtering to modify|create here
                // hung it inside read() and wedged `pacman-key --init`.)
                // With len=0 there is no name, so name-matching watchers
                // correctly conclude "not my file" and rescan.
                constexpr std::uint32_t kEntry = inotify_bit::create | inotify_bit::delete_
                    | inotify_bit::moved_from | inotify_bit::moved_to
                    | inotify_bit::modify | inotify_bit::close_write;
                if (f & (NOTE_WRITE | NOTE_EXTEND | NOTE_LINK))
                    mask |= w->mask & kEntry;
            } else {
                if (f & (NOTE_WRITE | NOTE_EXTEND))
                    mask |= w->mask & (inotify_bit::modify | inotify_bit::close_write);
            }
            if (f & NOTE_ATTRIB) mask |= w->mask & inotify_bit::attrib;
            // These really are about the watched object itself.
            if (f & (NOTE_DELETE | NOTE_REVOKE)) mask |= inotify_bit::delete_self;   // always reported
            if (f & NOTE_RENAME) mask |= w->mask & inotify_bit::move_self;
            if (!mask) continue;
            if (used + sizeof(LinuxInotifyEvent) > out.size()) break;
            const LinuxInotifyEvent e{wd, mask, 0, 0};
            std::memcpy(out.data() + used, &e, sizeof e);
            used += sizeof e;
        }
        return used;
    }

private:
    // Ask kqueue ONLY for what the inotify mask can report. The inotify fd
    // IS the kqueue, so any queued kevent makes it poll-readable -- even one
    // drain() then filters away. gpg-agent watches its homedir for
    // IN_DELETE_SELF alone and treats "select says readable" as "homedir
    // removed": with every note registered, the agent's own socket creation
    // and key writes woke it, and it shut down mid `pacman-key --init`
    // ("can't connect to the gpg-agent: End of file").
    [[nodiscard]] static std::uint32_t notes_for(std::uint32_t m, bool is_dir) noexcept {
        using namespace inotify_bit;
        std::uint32_t n = 0;
        if (m & (delete_self | 0x2000 /*IN_UNMOUNT*/)) n |= NOTE_DELETE | NOTE_REVOKE;
        if (m & move_self) n |= NOTE_RENAME;
        if (m & attrib)    n |= NOTE_ATTRIB;
        if (is_dir) {
            // Entry-level events (create/delete/move inside) surface as a
            // directory write; kqueue cannot name the entry.
            if (m & (create | delete_ | moved_from | moved_to | modify | close_write))
                n |= NOTE_WRITE | NOTE_LINK;
        } else if (m & (modify | close_write)) {
            n |= NOTE_WRITE | NOTE_EXTEND;
        }
        return n;
    }

    struct Watch { int wd; int fd; std::uint32_t mask; std::string path; bool is_dir; };
    int kq_;
    int next_wd_{1};
    std::vector<Watch> watches_;
};

// -- memfd ----------------------------------------------------------------
// An unlinked temp file. Anonymous (no name in the namespace), growable with
// ftruncate, mappable, and passable as an fd -- which is the whole point of
// memfd_create. Its guest name ("/memfd:NAME (deleted)") and its seals live
// in extended attributes ON THE INODE, so every fd for it -- dup'd, forked,
// passed over SCM_RIGHTS -- agrees, with no table to keep in sync.
inline constexpr const char* kMemfdNameXattr = "org.linuxity.memfd";
inline constexpr const char* kMemfdSealXattr = "org.linuxity.seals";
inline constexpr std::uint32_t kSealSeal = 1, kSealShrink = 2, kSealGrow = 4,
                               kSealWrite = 8, kSealFutureWrite = 16;
[[nodiscard]] inline int make_memfd(const std::string& name, bool allow_sealing) {
    std::string tmpl = "/tmp/linuxity-memfd-" + name + "-XXXXXX";
    const int fd = ::mkstemp(tmpl.data());
    if (fd < 0) return -1;
    ::unlink(tmpl.c_str());
    ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    (void)::fsetxattr(fd, kMemfdNameXattr, name.data(), name.size(), 0, 0);
    // Without MFD_ALLOW_SEALING a memfd starts with F_SEAL_SEAL: no seal
    // may ever be added.
    const std::uint32_t s = allow_sealing ? 0 : kSealSeal;
    (void)::fsetxattr(fd, kMemfdSealXattr, &s, sizeof s, 0, 0);
    return fd;
}
// The memfd's name, if `fd` is one.
[[nodiscard]] inline std::optional<std::string> memfd_name(int fd) {
    char b[256];
    const ssize_t n = ::fgetxattr(fd, kMemfdNameXattr, b, sizeof b, 0, 0);
    if (n < 0) return std::nullopt;
    return std::string(b, static_cast<std::size_t>(n));
}
// Its seals; nullopt if not a memfd.
[[nodiscard]] inline std::optional<std::uint32_t> memfd_seals(int fd) {
    std::uint32_t s = 0;
    if (::fgetxattr(fd, kMemfdSealXattr, &s, sizeof s, 0, 0) != sizeof s) return std::nullopt;
    return s;
}
inline bool set_memfd_seals(int fd, std::uint32_t s) {
    return ::fsetxattr(fd, kMemfdSealXattr, &s, sizeof s, 0, 0) == 0;
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
