// linuxity/runtime/darwin/rtnetlink.hpp
//
// NETLINK_ROUTE for a host that has none (macOS). glibc's if_nameindex,
// getifaddrs and getaddrinfo(AI_ADDRCONFIG), iproute2's `ip addr`/`ip link`,
// Go's net.Interfaces and libuv's uv_interface_addresses all ask the kernel
// through an AF_NETLINK socket: RTM_GETLINK and RTM_GETADDR dumps. A guest
// that got EAFNOSUPPORT saw no interfaces at all.
//
// The guest's socket is one end of a host SOCK_DGRAM socketpair; linuxity
// keeps the other. Each request the guest sends is answered by writing the
// reply datagrams (one per message, then NLMSG_DONE) into the far end, so
// recvmsg, MSG_PEEK, poll and epoll all behave as on a real netlink socket.
// The answers come from the host's getifaddrs(): the real interfaces, their
// real addresses, Linux-shaped (lo0 is "lo", indices from if_nametoindex).
#pragma once
#if defined(__APPLE__)

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace lx::runtime::rtnl {

inline constexpr std::uint16_t kNlmsgDone = 3, kNlmsgError = 2;
inline constexpr std::uint16_t kRtmNewLink = 16, kRtmGetLink = 18, kRtmNewAddr = 20, kRtmGetAddr = 22,
                               kRtmNewRoute = 24, kRtmGetRoute = 26;
inline constexpr std::uint16_t kNlmFRequest = 1, kNlmFMulti = 2, kNlmFDump = 0x300;

struct NlMsgHdr { std::uint32_t len; std::uint16_t type, flags; std::uint32_t seq, pid; };
struct IfInfoMsg { std::uint8_t family, pad; std::uint16_t type; std::int32_t index; std::uint32_t flags, change; };
struct IfAddrMsg { std::uint8_t family, prefixlen, flags, scope; std::uint32_t index; };

inline void align(std::string& b) { while (b.size() % 4) b.push_back('\0'); }

inline void attr(std::string& b, std::uint16_t type, const void* data, std::size_t n) {
    const std::uint16_t len = static_cast<std::uint16_t>(4 + n);
    b.append(reinterpret_cast<const char*>(&len), 2);
    b.append(reinterpret_cast<const char*>(&type), 2);
    b.append(static_cast<const char*>(data), n);
    align(b);
}

// Linux interface names: macOS's loopback is lo0, Linux's lo.
[[nodiscard]] inline std::string linux_name(const char* n) {
    return std::strcmp(n, "lo0") == 0 ? std::string{"lo"} : std::string{n};
}

// Linux IFF_* flags agree with Darwin's for the low bits we report.
[[nodiscard]] inline std::uint32_t linux_flags(unsigned f) {
    std::uint32_t l = 0;
    if (f & IFF_UP) l |= 0x1;
    if (f & IFF_BROADCAST) l |= 0x2;
    if (f & IFF_LOOPBACK) l |= 0x8;
    if (f & IFF_POINTOPOINT) l |= 0x10;
    if (f & IFF_RUNNING) l |= 0x40 | 0x10000;      // IFF_RUNNING | IFF_LOWER_UP
    if (f & IFF_NOARP) l |= 0x80;
    if (f & IFF_PROMISC) l |= 0x100;
    if (f & IFF_MULTICAST) l |= 0x1000;
    return l;
}

[[nodiscard]] inline int prefix_len(const sockaddr* m) {
    if (!m) return 0;
    const unsigned char* p; std::size_t n;
    if (m->sa_family == AF_INET) { p = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in*>(m)->sin_addr); n = 4; }
    else if (m->sa_family == AF_INET6) { p = reinterpret_cast<const unsigned char*>(&reinterpret_cast<const sockaddr_in6*>(m)->sin6_addr); n = 16; }
    else {
        // a netmask's sa_family may be 0 on Darwin: count by the address size
        p = reinterpret_cast<const unsigned char*>(m) + 4; n = m->sa_len > 4 ? std::min<std::size_t>(m->sa_len - 4, 4) : 0;
    }
    int bits = 0;
    for (std::size_t i = 0; i < n; ++i) for (int b = 7; b >= 0; --b) if (p[i] >> b & 1) ++bits;
    return bits;
}

// One complete netlink message.
[[nodiscard]] inline std::string message(std::uint16_t type, std::uint16_t flags, std::uint32_t seq,
                                         std::uint32_t pid, const std::string& body) {
    std::string m(sizeof(NlMsgHdr), '\0');
    m += body;
    align(m);
    NlMsgHdr h{static_cast<std::uint32_t>(m.size()), type, flags, seq, pid};
    std::memcpy(m.data(), &h, sizeof h);
    return m;
}

// The reply datagrams for one request (each element is one recv's worth).
[[nodiscard]] inline std::vector<std::string> answer(const std::string& req, std::uint32_t port) {
    std::vector<std::string> out;
    if (req.size() < sizeof(NlMsgHdr)) return out;
    NlMsgHdr h{};
    std::memcpy(&h, req.data(), sizeof h);
    const std::uint16_t multi = kNlmFMulti;
    const bool dump = (h.flags & kNlmFDump) != 0;
    ifaddrs* ifs = nullptr;
    if (::getifaddrs(&ifs) != 0) ifs = nullptr;
    // interfaces, by name, with their index and link-layer facts
    struct Link { int index; unsigned flags; std::string mac; std::uint32_t mtu; bool loop; };
    std::map<std::string, Link> links;
    for (auto* i = ifs; i; i = i->ifa_next) {
        auto& l = links[i->ifa_name];
        l.index = static_cast<int>(::if_nametoindex(i->ifa_name));
        l.flags = i->ifa_flags;
        l.loop = (i->ifa_flags & IFF_LOOPBACK) != 0;
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_LINK) {
            const auto* dl = reinterpret_cast<const sockaddr_dl*>(i->ifa_addr);
            if (dl->sdl_alen == 6) l.mac.assign(LLADDR(dl), 6);
            if (i->ifa_data) l.mtu = static_cast<const if_data*>(i->ifa_data)->ifi_mtu;
        }
    }
    std::string batch;
    auto emit = [&](std::string m) {
        // several messages per datagram, like the kernel, but never huge
        if (batch.size() + m.size() > 8192) { out.push_back(std::move(batch)); batch.clear(); }
        batch += m;
    };
    if (h.type == kRtmGetLink) {
        for (const auto& [name, l] : links) {
            std::string b(sizeof(IfInfoMsg), '\0');
            IfInfoMsg ii{0, 0, static_cast<std::uint16_t>(l.loop ? 772 : 1), l.index, linux_flags(l.flags), 0};
            std::memcpy(b.data(), &ii, sizeof ii);
            const std::string ln = linux_name(name.c_str());
            attr(b, 3 /*IFLA_IFNAME*/, ln.c_str(), ln.size() + 1);
            const std::uint32_t mtu = l.mtu ? l.mtu : (l.loop ? 65536 : 1500);
            attr(b, 4 /*IFLA_MTU*/, &mtu, 4);
            const std::string mac = l.mac.empty() ? std::string(6, '\0') : l.mac;
            attr(b, 1 /*IFLA_ADDRESS*/, mac.data(), 6);
            const std::string bc = l.loop ? std::string(6, '\0') : std::string(6, '\xff');
            attr(b, 2 /*IFLA_BROADCAST*/, bc.data(), 6);
            const std::uint8_t oper = (l.flags & IFF_RUNNING) ? 6 /*UP*/ : 2 /*DOWN*/;
            attr(b, 16 /*IFLA_OPERSTATE*/, &oper, 1);
            const std::uint32_t txq = 1000;
            attr(b, 13 /*IFLA_TXQLEN*/, &txq, 4);
            emit(message(kRtmNewLink, multi, h.seq, port, b));
        }
    } else if (h.type == kRtmGetAddr) {
        std::uint8_t want = 0;
        if (req.size() >= sizeof h + 1) want = static_cast<std::uint8_t>(req[sizeof h]);
        for (auto* i = ifs; i; i = i->ifa_next) {
            if (!i->ifa_addr) continue;
            const int fam = i->ifa_addr->sa_family;
            if (fam != AF_INET && fam != AF_INET6) continue;
            const std::uint8_t lfam = fam == AF_INET ? 2 : 10;
            if (want && want != lfam) continue;
            const auto& l = links[i->ifa_name];
            std::string b(sizeof(IfAddrMsg), '\0');
            const void* addr; std::size_t alen;
            std::uint8_t scope = l.loop ? 254 /*host*/ : 0 /*universe*/;
            if (fam == AF_INET) {
                addr = &reinterpret_cast<const sockaddr_in*>(i->ifa_addr)->sin_addr; alen = 4;
            } else {
                const auto* a6 = reinterpret_cast<const sockaddr_in6*>(i->ifa_addr);
                addr = &a6->sin6_addr; alen = 16;
                if (IN6_IS_ADDR_LINKLOCAL(&a6->sin6_addr)) scope = 253;
            }
            // Darwin embeds the scope id in a link-local address's 2nd word
            unsigned char a[16]{};
            std::memcpy(a, addr, alen);
            if (alen == 16 && a[0] == 0xfe && (a[1] & 0xc0) == 0x80) { a[2] = 0; a[3] = 0; }
            IfAddrMsg am{lfam, static_cast<std::uint8_t>(prefix_len(i->ifa_netmask)), 0x80 /*PERMANENT*/,
                         scope, static_cast<std::uint32_t>(l.index)};
            std::memcpy(b.data(), &am, sizeof am);
            attr(b, 1 /*IFA_ADDRESS*/, a, alen);
            attr(b, 2 /*IFA_LOCAL*/, a, alen);
            if (fam == AF_INET && i->ifa_broadaddr && (i->ifa_flags & IFF_BROADCAST))
                attr(b, 4 /*IFA_BROADCAST*/, &reinterpret_cast<const sockaddr_in*>(i->ifa_broadaddr)->sin_addr, 4);
            const std::string ln = linux_name(i->ifa_name);
            attr(b, 3 /*IFA_LABEL*/, ln.c_str(), ln.size() + 1);
            emit(message(kRtmNewAddr, multi, h.seq, port, b));
        }
    } else if (h.type == kRtmGetRoute && dump) {
        // no route table to report: an empty dump (programs fall back)
    } else {
        // anything else: a netlink error reply, EOPNOTSUPP, echoing the request
        std::string b(4, '\0');
        const std::int32_t e = -95;
        std::memcpy(b.data(), &e, 4);
        b.append(req.data(), std::min(req.size(), sizeof h));
        if (ifs) ::freeifaddrs(ifs);
        out.push_back(message(kNlmsgError, 0, h.seq, port, b));
        return out;
    }
    if (ifs) ::freeifaddrs(ifs);
    std::string done(4, '\0');
    emit(message(kNlmsgDone, multi, h.seq, port, done));
    if (!batch.empty()) out.push_back(std::move(batch));
    return out;
}

} // namespace lx::runtime::rtnl

#include <poll.h>
#include <unistd.h>
#include <mutex>
#include <thread>

namespace lx::runtime::rtnl {

// The answering side. Each guest netlink socket is one end of a host
// datagram pair; the responder holds the other ends and answers whatever
// arrives there. It doesn't matter how the guest sent the request -- send,
// sendto, sendmsg, write, writev (Firefox's quinn-udp writes, then reads)
// -- or from which thread: the bytes land on the far end either way. The
// first version intercepted only sendto/sendmsg on the creating thread, so
// a write() left Firefox's socket thread waiting forever and every page
// stopped loading.
class Responder {
public:
    static Responder& get() {
        static Responder* r = new Responder;       // process lifetime
        return *r;
    }
    // Adopt `far`, the host end that answers a guest netlink socket.
    void adopt(int far, std::uint32_t port) {
        {
            std::lock_guard l{mu_};
            ends_.push_back({far, port});
            if (!running_) {
                running_ = true;
                if (::pipe(wake_) == 0) {
                    for (int fd : wake_) ::fcntl(fd, F_SETFD, FD_CLOEXEC);
                    std::thread([this] { run(); }).detach();
                }
            }
        }
        if (wake_[1] >= 0) { const char c = 1; (void)::write(wake_[1], &c, 1); }
    }

private:
    struct End { int fd; std::uint32_t port; };
    void run() {
        std::vector<char> buf(64 << 10);
        for (;;) {
            std::vector<pollfd> p;
            std::vector<End> ends;
            {
                std::lock_guard l{mu_};
                ends = ends_;
            }
            p.push_back({wake_[0], POLLIN, 0});
            for (const End& e : ends) p.push_back({e.fd, POLLIN, 0});
            // 5 s ticks: a datagram peer's close wakes no poller on XNU, so
            // closed guest sockets are found by asking (getpeername)
            const int pr = ::poll(p.data(), static_cast<nfds_t>(p.size()), 5000);
            if (pr < 0) continue;
            if (p[0].revents) { char c[64]; (void)::read(wake_[0], c, sizeof c); }
            std::vector<int> gone;
            if (pr == 0)
                for (const End& e : ends) {
                    ::sockaddr_storage ss{};
                    socklen_t sl = sizeof ss;
                    if (::getpeername(e.fd, reinterpret_cast<::sockaddr*>(&ss), &sl) != 0 && errno == ENOTCONN)
                        gone.push_back(e.fd);
                }
            for (std::size_t i = 1; i < p.size(); ++i) {
                const End& e = ends[i - 1];
                if (p[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
                    // the guest closed its end (every copy of it)
                    char c;
                    if (::recv(e.fd, &c, 1, MSG_PEEK | MSG_DONTWAIT) <= 0) { gone.push_back(e.fd); continue; }
                }
                if (!(p[i].revents & POLLIN)) continue;
                for (;;) {
                    const auto n = ::recv(e.fd, buf.data(), buf.size(), MSG_DONTWAIT);
                    if (n <= 0) {
                        if (n == 0 || (errno != EAGAIN && errno != EINTR)) gone.push_back(e.fd);
                        break;
                    }
                    for (const std::string& d : answer(std::string(buf.data(), static_cast<std::size_t>(n)), e.port))
                        (void)::send(e.fd, d.data(), d.size(), 0);
                }
            }
            if (!gone.empty()) {
                std::lock_guard l{mu_};
                for (int fd : gone) {
                    std::erase_if(ends_, [fd](const End& x) { return x.fd == fd; });
                    ::close(fd);
                }
            }
        }
    }
    std::mutex mu_;
    std::vector<End> ends_;
    bool running_{false};
    int wake_[2]{-1, -1};
};

} // namespace lx::runtime::rtnl

#endif // __APPLE__
