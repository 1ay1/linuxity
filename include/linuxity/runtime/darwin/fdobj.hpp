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
//   pidfd     -- one end of a socketpair whose other end a watcher thread
//                closes on the process's exit (EVFILT_PROC): poll() wakes,
//                and unlike a kqueue it survives fork.
#pragma once

#if defined(__APPLE__)

#include <atomic>
#include <map>
#include <mutex>
#include <thread>
#include <span>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>

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
// The guest's pidfd is one end of an AF_UNIX socketpair; a single watcher
// thread holds the other and closes it when the process exits, so the
// guest's end polls readable (EOF) exactly then -- the property pidfd
// exists for. Not a kqueue, which is what it was: a kqueue can't cross a
// fork, so a process holding a pidfd (asyncio's child watcher, between a
// spawn and its reaping) failed every other fork with EAGAIN. A socket end
// is an ordinary fd: it forks, dups and goes into epoll like any other.
class PidfdWatcher {
public:
    static PidfdWatcher& get() {
        static PidfdWatcher* w = new PidfdWatcher;   // lives as long as the process
        return *w;
    }
    // Watch `pid`; returns the guest's end, or -1 with errno. `exited`: it
    // has (its end is readable at once).
    [[nodiscard]] int watch(::pid_t pid, bool exited) {
        int sv[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
        for (const int fd : sv) {
            (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
            const int one = 1;
            (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
        }
        if (exited) { ::close(sv[1]); return sv[0]; }
        std::lock_guard g{mu_};
        struct ::kevent ev[2]{};
        EV_SET(&ev[0], pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0,
               reinterpret_cast<void*>(static_cast<std::intptr_t>(sv[1])));
        // the guest closing every copy of its end: stop watching
        EV_SET(&ev[1], sv[1], EVFILT_READ, EV_ADD, 0, 0,
               reinterpret_cast<void*>(static_cast<std::intptr_t>(pid)));
        if (kq_ < 0 || ::kevent(kq_, ev, 2, nullptr, 0, nullptr) != 0) {
            const int e = errno;
            ::close(sv[0]); ::close(sv[1]);
            errno = e;
            return -1;
        }
        ours_[sv[1]] = pid;
        return sv[0];
    }

private:
    PidfdWatcher() : kq_{::kqueue()} {
        if (kq_ < 0) return;
        (void)::fcntl(kq_, F_SETFD, FD_CLOEXEC);
        std::thread([this] { run(); }).detach();
    }
    void run() {
        for (;;) {
            struct ::kevent out[16]{};
            const int n = ::kevent(kq_, nullptr, 0, out, 16, nullptr);
            if (n < 0) { if (errno == EINTR) continue; return; }
            std::lock_guard g{mu_};
            for (int i = 0; i < n; ++i) {
                int ours = -1;
                if (out[i].filter == EVFILT_PROC)
                    ours = static_cast<int>(reinterpret_cast<std::intptr_t>(out[i].udata));
                else if (out[i].filter == EVFILT_READ && (out[i].flags & EV_EOF))
                    ours = static_cast<int>(out[i].ident);
                else
                    continue;
                auto it = ours_.find(ours);
                if (it == ours_.end()) continue;
                // closing our end removes its EVFILT_READ; the proc filter
                // was ONESHOT, or goes with the process
                if (out[i].filter == EVFILT_READ) {
                    struct ::kevent del{};
                    EV_SET(&del, it->second, EVFILT_PROC, EV_DELETE, 0, 0, nullptr);
                    (void)::kevent(kq_, &del, 1, nullptr, 0, nullptr);
                }
                ::close(ours);
                ours_.erase(it);
            }
        }
    }
    int kq_;
    std::mutex mu_;
    std::map<int, ::pid_t> ours_;     // our end -> the pid it watches
};

[[nodiscard]] inline int make_pidfd(::pid_t pid, bool guest_exited = false) {
    // Is it already past watching? XNU refuses EVFILT_PROC (ESRCH) on a
    // zombie, and on a process still EXITING -- alive to kill(0), not yet
    // a zombie, which for a process tearing down a VM is a wide window under
    // load. Linux opens a pidfd on either and it polls readable at once. A
    // child that exits right after its spawn (asyncio's watcher racing a
    // quick `sh -c 'exit 3'`) must not be "No such process". `guest_exited`:
    // the guest already posted its exit status (PidSpace::post_exit).
    int fd = PidfdWatcher::get().watch(pid, false);
    if (fd >= 0 || errno != ESRCH) return fd;
    siginfo_t si{};
    const bool zombie = ::waitid(P_PID, static_cast<id_t>(pid), &si,
                                 WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == pid;
    if (!zombie && !guest_exited) { errno = ESRCH; return -1; }
    return PidfdWatcher::get().watch(pid, true);
}

} // namespace lx::runtime

#endif // __APPLE__
