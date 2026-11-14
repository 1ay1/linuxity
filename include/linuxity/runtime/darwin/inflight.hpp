// linuxity/runtime/darwin/inflight.hpp
//
// Keep a socket alive while it is in flight over SCM_RIGHTS.
//
// XNU's unix-socket garbage collector (unp_gc in bsd/kern/uipc_usrreq.c)
// runs whenever a unix socket carrying fds is closed, and it flushes the
// receive buffer of every socket that only in-flight messages still refer
// to -- even when that message sits in the queue of a live socket that its
// receiver will read. Linux keeps such a socket and its data. Measured on
// macOS 15 with no linuxity involved: send one end of a socketpair to
// another process, close it, write 724 bytes into the other end, let any
// unrelated unix socket that carried an fd close; the receiver gets the
// end and reads 0 bytes (EOF). That is exactly Firefox's fork-server
// handoff: the browser sends a fresh channel's end, writes the child's
// launch info into the other end and closes both, so every content process
// came up with "SubprocessExecInfo receive error" and MOZ_CRASHed.
//
// The collector only takes a socket nothing but messages refers to. So the
// SENDER keeps a hidden duplicate of every socket it passes until a receiver
// has taken it: a marker file per send, which the receiving linuxity process
// removes (sockets have a unique inode, shared by every fd for them). A
// watcher thread drops the duplicate once its marker is gone, so the peer
// still sees EOF as soon as the receiver closes the socket. A message never
// read (its receiving socket closed with it queued) is let go after a
// timeout, which is when Linux would have dropped it too -- give or take.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include <dirent.h>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace lx::runtime::inflight {

// Shared by every linuxity process of this user: a socket can travel
// between any two of them.
[[nodiscard]] inline const std::string& dir() {
    static const std::string d = [] {
        char tmp[1024] = {};
        std::string base = ::confstr(_CS_DARWIN_USER_TEMP_DIR, tmp, sizeof tmp) > 0 ? tmp : "/tmp/";
        if (base.empty() || base.back() != '/') base += '/';
        std::string p = base + "linuxity-inflight";
        (void)::mkdir(p.c_str(), 0700);
        return p;
    }();
    return d;
}

[[nodiscard]] inline bool socket_ino(int fd, std::uint64_t& ino) {
    struct ::stat st{};
    if (::fstat(fd, &st) != 0 || !S_ISSOCK(st.st_mode)) return false;
    ino = static_cast<std::uint64_t>(st.st_ino);
    return true;
}

class Holder {
public:
    static Holder& get() {
        static Holder* h = new Holder;      // never destroyed: process exit frees the fds
        return *h;
    }

    // A sendmsg carrying these host fds succeeded: hold each socket.
    void sent(const std::vector<int>& fds) {
        for (int fd : fds) {
            std::uint64_t ino = 0;
            if (!socket_ino(fd, ino)) continue;
            const int dup = ::fcntl(fd, F_DUPFD_CLOEXEC, 64);
            if (dup < 0) continue;
            const std::string marker = dir() + "/" + std::to_string(ino) + "." +
                                       std::to_string(::getpid()) + "." +
                                       std::to_string(seq_.fetch_add(1));
            const int m = ::open(marker.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
            if (m < 0) { ::close(dup); continue; }
            ::close(m);
            {
                std::lock_guard l{mu_};
                held_.push_back({marker, dup, std::chrono::steady_clock::now()});
                if (!watcher_) {
                    watcher_ = true;
                    std::thread([this] { watch(); }).detach();
                }
            }
            cv_.notify_one();
        }
    }

    // recvmsg delivered this host fd: if it is a socket someone holds for
    // its flight, tell them it has landed (one send's worth).
    static void received(int fd) {
        std::uint64_t ino = 0;
        if (!socket_ino(fd, ino)) return;
        const std::string prefix = std::to_string(ino) + ".";
        DIR* d = ::opendir(dir().c_str());
        if (!d) return;
        while (const ::dirent* e = ::readdir(d)) {
            if (std::strncmp(e->d_name, prefix.c_str(), prefix.size()) != 0) continue;
            if (::unlink((dir() + "/" + e->d_name).c_str()) == 0) break;   // lost a race: next
        }
        ::closedir(d);
    }

private:
    struct Held { std::string marker; int dup; std::chrono::steady_clock::time_point since; };
    static constexpr auto kPoll = std::chrono::milliseconds(10);
    static constexpr auto kGiveUp = std::chrono::seconds(120);

    void watch() {
        sweep_dead();
        auto last_sweep = std::chrono::steady_clock::now();
        std::unique_lock l{mu_};
        for (;;) {
            cv_.wait_for(l, kPoll);
            if (held_.empty()) { cv_.wait(l, [this] { return !held_.empty(); }); continue; }
            const auto now = std::chrono::steady_clock::now();
            if (now - last_sweep > std::chrono::seconds(10)) { sweep_dead(); last_sweep = now; }
            for (auto it = held_.begin(); it != held_.end();) {
                const bool landed = ::access(it->marker.c_str(), F_OK) != 0;
                if (landed || now - it->since > kGiveUp) {
                    if (!landed) (void)::unlink(it->marker.c_str());
                    ::close(it->dup);
                    it = held_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    // Markers whose sender is gone (it exited holding them): nobody waits
    // on them any more, and a later receipt must not consume one.
    static void sweep_dead() {
        DIR* d = ::opendir(dir().c_str());
        if (!d) return;
        while (const ::dirent* e = ::readdir(d)) {
            const char* dot = std::strchr(e->d_name, '.');
            if (!dot) continue;
            const long pid = std::strtol(dot + 1, nullptr, 10);
            if (pid > 0 && ::kill(static_cast<pid_t>(pid), 0) != 0 && errno == ESRCH)
                (void)::unlink((dir() + "/" + e->d_name).c_str());
        }
        ::closedir(d);
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<Held> held_;
    bool watcher_{false};
    std::atomic<std::uint64_t> seq_{0};
};

} // namespace lx::runtime::inflight

#endif // __APPLE__ && __aarch64__
