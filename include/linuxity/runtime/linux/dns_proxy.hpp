// linuxity/runtime/linux/dns_proxy.hpp
//
// Android keeps no resolv.conf: apps resolve through netd, which follows the
// current network (Wi-Fi, mobile, VPN) and Private DNS. A guest's glibc or
// musl only speaks DNS to an address, and the public resolvers linuxity
// otherwise falls back to are often unreachable (a carrier drops UDP 53 to
// anything but its own servers): every lookup then hung for 20-40 s.
//
// So on Android linuxity runs a tiny DNS forwarder: it listens on
// 127.0.0.53:<port>, the guest's resolv.conf says 127.0.0.53, the trap points
// the guest's port 53 at <port>, and each query goes to netd through the NDK's
// android_res_nsend -- the same resolver every Android app uses.
#pragma once

#if defined(__ANDROID__)
#include "linuxity/kernel/resolver.hpp"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>

namespace lx::runtime {

class DnsProxy {
public:
    // Start once per linuxity process. Returns false (and the guest gets the
    // usual fallback) if netd's API or the socket isn't available.
    static bool start() {
        static const bool ok = [] {
            void* h = ::dlopen("libandroid.so", RTLD_NOW | RTLD_LOCAL);
            if (!h) return false;
            auto* ns = reinterpret_cast<NSend>(::dlsym(h, "android_res_nsend"));
            auto* nr = reinterpret_cast<NResult>(::dlsym(h, "android_res_nresult"));
            auto* nc = reinterpret_cast<NCancel>(::dlsym(h, "android_res_cancel"));
            if (!ns || !nr || !nc) return false;
            const int s = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (s < 0) return false;
            sockaddr_in a{};
            a.sin_family = AF_INET;
            std::memcpy(&a.sin_addr, kernel::kDnsGuestAddr.data(), 4);
            socklen_t al = sizeof a;
            if (::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a) != 0 ||
                ::getsockname(s, reinterpret_cast<sockaddr*>(&a), &al) != 0) {
                ::close(s);
                return false;
            }
            kernel::dns_proxy_port_ref().store(ntohs(a.sin_port), std::memory_order_relaxed);
            // A separate process, not a thread: linuxity is a ptrace tracer
            // that reaps with waitpid(-1, __WALL) and takes SIGCHLD on a
            // signalfd; a thread there stalled guests. Double-forked so it is
            // never our child (waitpid(-1) must only ever see guests); it
            // exits when linuxity does, seen as EOF on `life`.
            int life[2];
            if (::pipe2(life, O_CLOEXEC) != 0) { ::close(s); kernel::dns_proxy_port_ref().store(0); return false; }
            const ::pid_t mid = ::fork();
            if (mid < 0) { ::close(s); ::close(life[0]); ::close(life[1]); kernel::dns_proxy_port_ref().store(0); return false; }
            if (mid == 0) {
                if (::fork() != 0) ::_exit(0);
                ::setsid();
                ::sigset_t all;
                ::sigfillset(&all);
                (void)::sigprocmask(SIG_SETMASK, &all, nullptr);
                for (int fd = 3; fd < 1024; ++fd)
                    if (fd != s && fd != life[0]) (void)::close(fd);
                serve(s, life[0], ns, nr, nc);
            }
            int st = 0;
            while (::waitpid(mid, &st, 0) < 0 && errno == EINTR) {}
            ::close(s);
            ::close(life[0]);   // our end, life[1], stays open (CLOEXEC) until we exit
            return true;
        }();
        return ok;
    }

private:
    using NSend = int (*)(std::uint64_t, const std::uint8_t*, std::size_t, std::uint32_t);
    using NResult = int (*)(int, int*, std::uint8_t*, std::size_t);
    using NCancel = void (*)(int);

    struct Pending {
        int fd;
        sockaddr_in from;
        std::chrono::steady_clock::time_point since;
        std::uint8_t id[2];
    };

    // An answer with only the header: id kept, QR set, RCODE 2 (SERVFAIL).
    static void servfail(int s, const std::uint8_t* q, std::size_t n, const sockaddr_in& to) {
        if (n < 12) return;
        std::uint8_t r[512];
        const std::size_t len = n < sizeof r ? n : sizeof r;
        std::memcpy(r, q, len);
        r[2] |= 0x80;
        r[3] = static_cast<std::uint8_t>((r[3] & 0xf0) | 2);
        (void)::sendto(s, r, len, 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
    }

    [[noreturn]] static void serve(int s, int life, NSend nsend, NResult nresult, NCancel cancel) {
        std::vector<Pending> pend;
        std::vector<std::uint8_t> buf(65536);
        for (;;) {
            std::vector<pollfd> p;
            p.push_back({s, POLLIN, 0});
            p.push_back({life, POLLIN, 0});
            for (const auto& q : pend) p.push_back({q.fd, POLLIN, 0});
            (void)::poll(p.data(), static_cast<nfds_t>(p.size()), 1000);
            if (p[1].revents) ::_exit(0);   // linuxity is gone
            const auto now = std::chrono::steady_clock::now();
            // answers from netd
            for (std::size_t i = 2; i < p.size(); ++i) {
                auto& q = pend[i - 2];
                if (p[i].revents) {
                    int rcode = 0;
                    const int n = nresult(q.fd, &rcode, buf.data(), buf.size());   // closes q.fd
                    if (n >= 12) {
                        (void)::sendto(s, buf.data(), static_cast<std::size_t>(n), 0,
                                       reinterpret_cast<const sockaddr*>(&q.from), sizeof q.from);
                    } else {
                        std::uint8_t h[12] = {q.id[0], q.id[1]};
                        servfail(s, h, sizeof h, q.from);
                    }
                    q.fd = -1;
                } else if (now - q.since > std::chrono::seconds(10)) {
                    cancel(q.fd);
                    q.fd = -1;
                }
            }
            std::erase_if(pend, [](const Pending& q) { return q.fd < 0; });
            // new queries from guests
            if (p[0].revents & POLLIN) {
                for (;;) {
                    sockaddr_in from{};
                    socklen_t fl = sizeof from;
                    const ::ssize_t n = ::recvfrom(s, buf.data(), buf.size(), MSG_DONTWAIT,
                                                   reinterpret_cast<sockaddr*>(&from), &fl);
                    if (n < 12) break;
                    const int fd = nsend(0 /*default network*/, buf.data(), static_cast<std::size_t>(n), 0);
                    if (fd < 0) { servfail(s, buf.data(), static_cast<std::size_t>(n), from); continue; }
                    pend.push_back({fd, from, now, {buf[0], buf[1]}});
                }
            }
        }
    }
};

}  // namespace lx::runtime
#endif
