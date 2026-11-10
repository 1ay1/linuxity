// linuxity/env/control.hpp
//
// The control socket of a running instance: how it is addressed, and how
// messages travel on it. Shared by the supervisor and every client (the CLI,
// the Android app's JNI layer).
//
// Wire format: newline-delimited JSON over a SOCK_STREAM unix socket. A
// request that hands over file descriptors carries them as SCM_RIGHTS on the
// same sendmsg as its line, and says how many in "fds". Replies are one line;
// a client that asked to wait also gets later {"event":...} lines.
//
// Addressing: a filesystem socket at <env>/run/control.sock. Where the host
// forbids that (Android's SELinux refuses AF_UNIX binds in many places) the
// supervisor binds an abstract name derived from the same path instead, and
// clients try both.
#pragma once

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <string>
#include <string_view>
#include <vector>

namespace lx::env::control {

// An AF_UNIX stream socket, close-on-exec (and non-blocking if asked):
// atomically where the host has SOCK_CLOEXEC, else right after creation.
// The only window is a fork in another thread between the two calls, and
// this process doesn't fork from threads.
[[nodiscard]] inline int unix_socket(bool nonblock) {
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    return ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), 0);
#else
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
    if (nonblock) (void)::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
#if defined(SO_NOSIGPIPE)
    const int one = 1;   // Darwin has no MSG_NOSIGNAL: say it once per socket
    (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    return fd;
#endif
}

#if defined(MSG_NOSIGNAL)
inline constexpr int kSendFlags = MSG_NOSIGNAL;
#else
inline constexpr int kSendFlags = 0;   // SO_NOSIGPIPE, set in unix_socket
#endif
#if defined(MSG_CMSG_CLOEXEC)
inline constexpr int kRecvFlags = MSG_CMSG_CLOEXEC;
#else
inline constexpr int kRecvFlags = 0;   // received fds get FD_CLOEXEC below
#endif

inline constexpr int kMaxFds = 8;

[[nodiscard]] inline std::string abstract_name_for(std::string_view path) {
    std::uint64_t h = 1469598103934665603ULL;
    for (const char c : path) { h ^= static_cast<unsigned char>(c); h *= 1099511628211ULL; }
    char buf[48];
    std::snprintf(buf, sizeof buf, "linuxity-ctl/%016llx", static_cast<unsigned long long>(h));
    return buf;
}

// Fill a sockaddr_un. `abstract` puts `name` in the abstract namespace.
[[nodiscard]] inline socklen_t make_addr(::sockaddr_un& sa, std::string_view name, bool abstract) {
    std::memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    const std::size_t off = abstract ? 1 : 0;
    const std::size_t n = std::min(name.size(), sizeof sa.sun_path - 1 - off);
    std::memcpy(sa.sun_path + off, name.data(), n);
    return static_cast<socklen_t>(offsetof(::sockaddr_un, sun_path) + off + n + (abstract ? 0 : 1));
}

struct Listener {
    int fd{-1};
    bool abstract{false};
    std::string path;
};

// Bind the control socket for `path`. Removes a stale socket file first
// (the caller has already made sure no live instance owns it).
[[nodiscard]] inline Listener listen_at(const std::string& path, std::string& why) {
    Listener l;
    l.path = path;
    l.fd = unix_socket(/*nonblock=*/true);
    if (l.fd < 0) { why = std::strerror(errno); return l; }
    ::sockaddr_un sa{};
    ::unlink(path.c_str());
    socklen_t len = make_addr(sa, path, false);
    if (::bind(l.fd, reinterpret_cast<::sockaddr*>(&sa), len) != 0) {
        len = make_addr(sa, abstract_name_for(path), true);
        if (::bind(l.fd, reinterpret_cast<::sockaddr*>(&sa), len) != 0) {
            why = std::strerror(errno);
            ::close(l.fd);
            l.fd = -1;
            return l;
        }
        l.abstract = true;
    } else {
        (void)::chmod(path.c_str(), 0600);
    }
    if (::listen(l.fd, 16) != 0) {
        why = std::strerror(errno);
        ::close(l.fd);
        l.fd = -1;
    }
    return l;
}

// Connect to the instance whose control socket is `path`. -1 if none.
[[nodiscard]] inline int connect_to(const std::string& path) {
    for (const bool abstract : {false, true}) {
        const int fd = unix_socket(/*nonblock=*/false);
        if (fd < 0) return -1;
        ::sockaddr_un sa{};
        const socklen_t len = make_addr(sa, abstract ? abstract_name_for(path) : path, abstract);
        if (::connect(fd, reinterpret_cast<::sockaddr*>(&sa), len) == 0) return fd;
        ::close(fd);
    }
    return -1;
}

// Send one line (a '\n' is added) with optional fds. Blocking; false on error.
inline bool send_line(int fd, std::string_view line, const std::vector<int>& fds = {}) {
    std::string buf{line};
    buf.push_back('\n');
    std::size_t done = 0;
    bool first = true;
    while (done < buf.size()) {
        ::iovec iov{buf.data() + done, buf.size() - done};
        ::msghdr m{};
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        alignas(::cmsghdr) char ctl[CMSG_SPACE(sizeof(int) * kMaxFds)];
        if (first && !fds.empty()) {
            const std::size_t n = std::min<std::size_t>(fds.size(), kMaxFds);
            std::memset(ctl, 0, sizeof ctl);
            m.msg_control = ctl;
            m.msg_controllen = static_cast<socklen_t>(CMSG_SPACE(sizeof(int) * n));
            ::cmsghdr* c = CMSG_FIRSTHDR(&m);
            c->cmsg_level = SOL_SOCKET;
            c->cmsg_type = SCM_RIGHTS;
            c->cmsg_len = static_cast<socklen_t>(CMSG_LEN(sizeof(int) * n));
            std::memcpy(CMSG_DATA(c), fds.data(), sizeof(int) * n);
        }
        const ::ssize_t w = ::sendmsg(fd, &m, kSendFlags);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        first = false;
        done += static_cast<std::size_t>(w);
    }
    return true;
}

// A reader that splits a stream into lines and keeps fds that arrived.
class LineReader {
public:
    explicit LineReader(int fd = -1) : fd_{fd} {}
    void reset(int fd) { fd_ = fd; buf_.clear(); close_fds(); }
    ~LineReader() { close_fds(); }
    LineReader(const LineReader&) = delete;
    LineReader& operator=(const LineReader&) = delete;
    LineReader(LineReader&& o) noexcept : fd_{o.fd_}, buf_{std::move(o.buf_)}, fds_{std::move(o.fds_)} { o.fds_.clear(); }
    LineReader& operator=(LineReader&& o) noexcept {
        if (this != &o) { close_fds(); fd_ = o.fd_; buf_ = std::move(o.buf_); fds_ = std::move(o.fds_); o.fds_.clear(); }
        return *this;
    }

    // Read what is available (or block once if the fd is blocking).
    // Returns false on EOF or error.
    bool fill() {
        char data[8192];
        ::iovec iov{data, sizeof data};
        alignas(::cmsghdr) char ctl[CMSG_SPACE(sizeof(int) * kMaxFds)];
        ::msghdr m{};
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = ctl;
        m.msg_controllen = sizeof ctl;
        ::ssize_t n;
        do { n = ::recvmsg(fd_, &m, kRecvFlags); } while (n < 0 && errno == EINTR);
        if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK;
        for (::cmsghdr* c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
            const std::size_t k = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
            for (std::size_t i = 0; i < k; ++i) {
                int f;
                std::memcpy(&f, CMSG_DATA(c) + i * sizeof(int), sizeof f);
                if constexpr (kRecvFlags == 0) (void)::fcntl(f, F_SETFD, FD_CLOEXEC);
                fds_.push_back(f);
            }
        }
        if (n == 0) return false;
        buf_.append(data, static_cast<std::size_t>(n));
        if (buf_.size() > (1u << 20)) return false;   // a runaway client
        return true;
    }

    // The next complete line, if one is buffered.
    bool next(std::string& line) {
        const auto nl = buf_.find('\n');
        if (nl == std::string::npos) return false;
        line = buf_.substr(0, nl);
        buf_.erase(0, nl + 1);
        return true;
    }

    // Blocking: read until a full line arrives. false on EOF.
    bool read_line(std::string& line) {
        while (!next(line))
            if (!fill()) return false;
        return true;
    }

    // Take up to n received fds (oldest first).
    std::vector<int> take_fds(std::size_t n) {
        std::vector<int> out;
        while (n-- > 0 && !fds_.empty()) { out.push_back(fds_.front()); fds_.pop_front(); }
        return out;
    }

private:
    void close_fds() {
        for (const int f : fds_) ::close(f);
        fds_.clear();
    }
    int fd_;
    std::string buf_;
    std::deque<int> fds_;
};

}  // namespace lx::env::control
