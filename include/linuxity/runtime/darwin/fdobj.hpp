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

#include <atomic>
#include <mutex>
#include <thread>
#include <span>
#include <fcntl.h>

#include "linuxity/kernel/fsnotify.hpp"
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


// One inotify instance. The events are linuxity's own (kernel/fsnotify.hpp):
// every guest process's dispatcher appends what it did to this instance's
// log when it concerns one of its watches, so names, cookies, opens, reads
// and changes made by other guest processes all arrive -- what kqueue on the
// watched inodes could not say.
//
// The guest's fd is the read end of a PIPE: forkable (a kqueue can't cross
// a fork, so a watcher's fork() failed with EAGAIN) and pollable. A thread
// sleeps in kevent on the log and keeps ONE byte in the pipe while records
// are pending, so poll/select/epoll say readable exactly when read() has
// records; read() drains the records and the byte together.
class InotifyFd {
public:
    explicit InotifyFd(kernel::fsnotify::Hub& hub) : hub_{hub} {
        id_ = hub_.open_instance();
        if (id_.empty() || ::pipe(pipe_) != 0) return;
        for (const int fd : pipe_) {
            (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
            (void)::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
        }
        kq_ = ::kqueue();
        log_fd_ = ::open(hub_.log_path(id_).c_str(), O_RDONLY | O_EVTONLY | O_CLOEXEC);
        if (kq_ < 0 || log_fd_ < 0) return;
        struct ::kevent ev[2]{};
        EV_SET(&ev[0], log_fd_, EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_EXTEND, 0, nullptr);
        EV_SET(&ev[1], 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, nullptr);   // wake to stop
        if (::kevent(kq_, ev, 2, nullptr, 0, nullptr) != 0) return;
        ok_ = true;
        thread_ = std::thread([this] { watch(); });
    }
    InotifyFd(const InotifyFd&) = delete;
    InotifyFd& operator=(const InotifyFd&) = delete;
    ~InotifyFd() {
        if (thread_.joinable()) {
            stop_ = true;
            struct ::kevent ev{};
            EV_SET(&ev, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, nullptr);
            (void)::kevent(kq_, &ev, 1, nullptr, 0, nullptr);
            thread_.join();
        }
        if (!id_.empty()) hub_.close_instance(id_);
        for (const int fd : {log_fd_, kq_, pipe_[0], pipe_[1]}) if (fd >= 0) ::close(fd);
    }

    [[nodiscard]] bool valid() const noexcept { return ok_; }
    // The guest's fd (a dup of the pipe's read end, owned by the fd table).
    [[nodiscard]] int read_end() const noexcept { return pipe_[0]; }

    // add_watch(guest path, host path, mask) -> wd, or -errno.
    [[nodiscard]] std::int64_t add_watch(const std::string& guest, const std::string& host,
                                         std::uint32_t mask) {
        struct ::stat st{};
        if (::stat(host.c_str(), &st) != 0) return -static_cast<std::int64_t>(errno == ENOENT ? 2 : 13);
        const bool is_dir = S_ISDIR(st.st_mode);
        if ((mask & 0x01000000u /*IN_ONLYDIR*/) && !is_dir) return -20;   // ENOTDIR
        if ((mask & kernel::fsnotify::kAllEvents) == 0) return -22;       // EINVAL
        std::lock_guard l{mu_};
        catch_up_locked();           // events before the watch are not its own
        const int wd = in_.add(guest, mask, is_dir);
        hub_.publish(id_, in_.specs());
        return wd;
    }
    [[nodiscard]] std::int64_t rm_watch(int wd) {
        std::lock_guard l{mu_};
        catch_up_locked();
        const int r = in_.remove(wd);
        if (r == 0) hub_.publish(id_, in_.specs());
        signal_locked();
        return r;
    }

    // Records into `out`: the byte count, 0 if none are ready (the caller
    // blocks or says EAGAIN), -EINVAL if the first record doesn't fit.
    [[nodiscard]] long drain(std::span<std::byte> out) {
        std::lock_guard l{mu_};
        catch_up_locked();
        const long n = in_.encode(out.data(), out.size());
        signal_locked();
        return n;
    }

private:
    void watch() {
        for (;;) {
            struct ::kevent ev{};
            const int n = ::kevent(kq_, nullptr, 0, &ev, 1, nullptr);
            if (stop_) return;
            if (n < 0 && errno != EINTR) return;
            std::lock_guard l{mu_};
            catch_up_locked();
            signal_locked();
        }
    }
    void catch_up_locked() {
        const auto before = in_.specs().size();
        for (const auto& e : kernel::fsnotify::read_log(hub_.log_path(id_), at_)) in_.deliver(e);
        // a oneshot or DELETE_SELF ended a watch: emitters stop sending it
        if (in_.specs().size() != before) hub_.publish(id_, in_.specs());
    }
    // One byte in the pipe iff records are pending.
    void signal_locked() {
        const bool want = in_.pending();
        if (want == byte_) return;
        if (want) { const char b = 1; byte_ = ::write(pipe_[1], &b, 1) == 1; }
        else { char b; byte_ = !(::read(pipe_[0], &b, 1) == 1); }
    }
    kernel::fsnotify::Hub& hub_;
    std::string id_;
    int pipe_[2]{-1, -1};
    int kq_{-1};
    int log_fd_{-1};
    bool ok_{false};
    bool byte_{false};
    std::atomic<bool> stop_{false};
    std::mutex mu_;
    std::thread thread_;
    long long at_{0};
    kernel::fsnotify::Instance in_;
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
