// src/display/wire/channel.hpp -- one client connection's byte+fd transport.
//
// POSIX: an AF_UNIX stream socket with SCM_RIGHTS. This is the seam a host
// without fd passing replaces (Windows: the guest's sockets and memfds are
// linuxity's own objects, so the channel there is in-process and an "fd" is
// a handle linuxity duplicates); everything above it speaks bytes and fds.
#pragma once

#include "wire.hpp"

#include <cerrno>
#include <deque>
#include <span>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/uio.h>

namespace lx::display::wire {

class Channel final : public FdSource {
public:
    explicit Channel(Fd sock) : sock_(std::move(sock)) {
        const int fl = ::fcntl(sock_.get(), F_GETFL);
        (void)::fcntl(sock_.get(), F_SETFL, fl | O_NONBLOCK);
        (void)::fcntl(sock_.get(), F_SETFD, FD_CLOEXEC);
#if defined(SO_NOSIGPIPE)
        const int one = 1;
        (void)::setsockopt(sock_.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    }
    ~Channel() override { for (int fd : in_fds_) ::close(fd); }

    [[nodiscard]] int fd() const noexcept { return sock_.get(); }

    enum class Io { ok, again, closed };

    // Append whatever is available to `in`; queue received fds.
    [[nodiscard]] Io read_some(std::vector<std::byte>& in) {
        std::byte buf[8192];
        alignas(::cmsghdr) char ctl[CMSG_SPACE(sizeof(int) * kMaxFdsPerMessage)];
        ::iovec iov{buf, sizeof buf};
        ::msghdr m{};
        m.msg_iov = &iov;
        m.msg_iovlen = 1;
        m.msg_control = ctl;
        m.msg_controllen = sizeof ctl;
        const ssize_t n = ::recvmsg(sock_.get(), &m, 0);
        if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? Io::again : Io::closed;
        for (::cmsghdr* c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
            if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
            const auto bytes = static_cast<std::size_t>(c->cmsg_len) - CMSG_LEN(0);
            const auto* p = reinterpret_cast<const int*>(CMSG_DATA(c));
            for (std::size_t k = 0; k < bytes / sizeof(int); ++k) {
                (void)::fcntl(p[k], F_SETFD, FD_CLOEXEC);
                in_fds_.push_back(p[k]);
            }
        }
        if (n == 0) return Io::closed;
        in.insert(in.end(), buf, buf + n);
        return Io::ok;
    }

    int pop_fd() override {
        if (in_fds_.empty()) return -1;
        const int fd = in_fds_.front();
        in_fds_.pop_front();
        return fd;
    }

    // Write as much of `out` as the socket takes, fds with the first byte
    // they belong to. Consumed bytes/fds are erased.
    [[nodiscard]] Io write_some(std::vector<std::byte>& out, std::vector<int>& fds) {
        while (!out.empty()) {
            ::iovec iov{out.data(), out.size()};
            ::msghdr m{};
            m.msg_iov = &iov;
            m.msg_iovlen = 1;
            alignas(::cmsghdr) char ctl[CMSG_SPACE(sizeof(int) * kMaxFdsPerMessage)];
            const std::size_t nfds = std::min(fds.size(), kMaxFdsPerMessage);
            if (nfds) {
                m.msg_control = ctl;
                m.msg_controllen = static_cast<socklen_t>(CMSG_SPACE(sizeof(int) * nfds));
                ::cmsghdr* c = CMSG_FIRSTHDR(&m);
                c->cmsg_level = SOL_SOCKET;
                c->cmsg_type = SCM_RIGHTS;
                c->cmsg_len = static_cast<socklen_t>(CMSG_LEN(sizeof(int) * nfds));
                std::memcpy(CMSG_DATA(c), fds.data(), sizeof(int) * nfds);
            }
            int flags = 0;
#if defined(MSG_NOSIGNAL)
            flags |= MSG_NOSIGNAL;
#endif
            const ssize_t n = ::sendmsg(sock_.get(), &m, flags);
            if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? Io::again : Io::closed;
            for (std::size_t k = 0; k < nfds; ++k) ::close(fds[k]);
            fds.erase(fds.begin(), fds.begin() + static_cast<std::ptrdiff_t>(nfds));
            out.erase(out.begin(), out.begin() + n);
        }
        return Io::ok;
    }

private:
    Fd sock_;
    std::deque<int> in_fds_;
};

}  // namespace lx::display::wire
