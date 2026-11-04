// linuxity/runtime/hvf_net.hpp
//
// Linux sockets on Darwin.
//
// Both kernels implement BSD sockets, which is exactly why this layer is
// needed and easy to get wrong: the NAMES match, so a forgotten translation
// compiles and then fails at runtime in a way that looks like a network
// problem. The divergences that matter:
//
//   * sockaddr. Linux has no sa_len; Darwin's first TWO bytes are
//     { u8 sa_len, u8 sa_family }, Linux's are a little-endian u16 family.
//     Hand Darwin a Linux sockaddr_in and it reads sa_len = 2 and fails
//     EINVAL; hand Linux a Darwin one and the family is 0x0210 (528).
//   * Address families. AF_INET agrees (2) but AF_INET6 is 10 on Linux and
//     30 on Darwin; AF_UNIX is 1 on both.
//   * Socket types. SOCK_STREAM/DGRAM agree (1/2), but Linux packs
//     SOCK_NONBLOCK (0x800) and SOCK_CLOEXEC (0x80000) into the type word
//     and Darwin has no such flags -- they must be applied with fcntl.
//   * Option levels and names. SOL_SOCKET is 1 on Linux, 0xffff on Darwin,
//     and almost every SO_* number differs.
//   * MSG_NOSIGNAL (0x4000) doesn't exist on Darwin; the equivalent is the
//     SO_NOSIGPIPE socket option.
#pragma once

#if defined(__APPLE__)

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>

namespace lx::runtime::net {

// -- Address families ------------------------------------------------------
enum class LinuxAf : std::uint16_t {
    unspec = 0, unix_ = 1, inet = 2, inet6 = 10, netlink = 16, packet = 17,
};

[[nodiscard]] inline std::optional<int> af_to_darwin(std::uint16_t la) noexcept {
    switch (static_cast<LinuxAf>(la)) {
        case LinuxAf::unspec: return AF_UNSPEC;
        case LinuxAf::unix_:  return AF_UNIX;
        case LinuxAf::inet:   return AF_INET;
        case LinuxAf::inet6:  return AF_INET6;
        default:              return std::nullopt;   // netlink/packet: EAFNOSUPPORT
    }
}

[[nodiscard]] inline std::uint16_t af_to_linux(int da) noexcept {
    switch (da) {
        case AF_UNIX:  return static_cast<std::uint16_t>(LinuxAf::unix_);
        case AF_INET:  return static_cast<std::uint16_t>(LinuxAf::inet);
        case AF_INET6: return static_cast<std::uint16_t>(LinuxAf::inet6);
        default:       return static_cast<std::uint16_t>(LinuxAf::unspec);
    }
}

// -- socket(2) type flags --------------------------------------------------
inline constexpr std::uint64_t kSockNonblock = 0x800;
inline constexpr std::uint64_t kSockCloexec  = 0x80000;

// -- sockaddr --------------------------------------------------------------
// Linux's wire form, as the guest lays it out.
struct LinuxSockaddr {
    std::uint16_t sa_family;
    char sa_data[126];
};

// Translate a guest sockaddr into a Darwin one. Returns the Darwin length,
// or nullopt if the family isn't supported.
[[nodiscard]] inline std::optional<socklen_t> to_darwin(
        std::span<const std::byte> guest, ::sockaddr_storage& out) {
    if (guest.size() < 2) return std::nullopt;
    std::uint16_t fam = 0;
    std::memcpy(&fam, guest.data(), 2);
    const auto da = af_to_darwin(fam);
    if (!da) return std::nullopt;
    std::memset(&out, 0, sizeof out);

    switch (*da) {
        case AF_INET: {
            if (guest.size() < 16) return std::nullopt;
            auto* sin = reinterpret_cast<::sockaddr_in*>(&out);
            sin->sin_len = sizeof(::sockaddr_in);
            sin->sin_family = AF_INET;
            // port and addr are network byte order in BOTH ABIs: copy raw.
            std::memcpy(&sin->sin_port, guest.data() + 2, 2);
            std::memcpy(&sin->sin_addr, guest.data() + 4, 4);
            return sizeof(::sockaddr_in);
        }
        case AF_INET6: {
            if (guest.size() < 28) return std::nullopt;
            auto* sin6 = reinterpret_cast<::sockaddr_in6*>(&out);
            sin6->sin6_len = sizeof(::sockaddr_in6);
            sin6->sin6_family = AF_INET6;
            std::memcpy(&sin6->sin6_port, guest.data() + 2, 2);
            std::memcpy(&sin6->sin6_flowinfo, guest.data() + 4, 4);
            std::memcpy(&sin6->sin6_addr, guest.data() + 8, 16);
            std::memcpy(&sin6->sin6_scope_id, guest.data() + 24, 4);
            return sizeof(::sockaddr_in6);
        }
        case AF_UNIX: {
            auto* sun = reinterpret_cast<::sockaddr_un*>(&out);
            sun->sun_family = AF_UNIX;
            const char* p = reinterpret_cast<const char*>(guest.data()) + 2;
            const std::size_t cap = guest.size() - 2;
            const std::size_t n = ::strnlen(p, std::min(cap, sizeof sun->sun_path - 1));
            std::memcpy(sun->sun_path, p, n);
            sun->sun_path[n] = '\0';
            sun->sun_len = static_cast<std::uint8_t>(offsetof(::sockaddr_un, sun_path) + n + 1);
            return static_cast<socklen_t>(sun->sun_len);
        }
        case AF_UNSPEC:
            out.ss_family = AF_UNSPEC;
            return sizeof(::sockaddr);
        default:
            return std::nullopt;
    }
}

// Darwin sockaddr -> the Linux layout, for getsockname/getpeername/accept.
// Returns the number of bytes the Linux form occupies.
[[nodiscard]] inline std::size_t to_linux(const ::sockaddr_storage& in,
                                          std::span<std::byte> out) {
    LinuxSockaddr la{};
    std::size_t len = 2;
    switch (in.ss_family) {
        case AF_INET: {
            const auto* sin = reinterpret_cast<const ::sockaddr_in*>(&in);
            la.sa_family = static_cast<std::uint16_t>(LinuxAf::inet);
            std::memcpy(la.sa_data, &sin->sin_port, 2);
            std::memcpy(la.sa_data + 2, &sin->sin_addr, 4);
            len = 16;
            break;
        }
        case AF_INET6: {
            const auto* sin6 = reinterpret_cast<const ::sockaddr_in6*>(&in);
            la.sa_family = static_cast<std::uint16_t>(LinuxAf::inet6);
            std::memcpy(la.sa_data, &sin6->sin6_port, 2);
            std::memcpy(la.sa_data + 2, &sin6->sin6_flowinfo, 4);
            std::memcpy(la.sa_data + 6, &sin6->sin6_addr, 16);
            std::memcpy(la.sa_data + 22, &sin6->sin6_scope_id, 4);
            len = 28;
            break;
        }
        case AF_UNIX: {
            const auto* sun = reinterpret_cast<const ::sockaddr_un*>(&in);
            la.sa_family = static_cast<std::uint16_t>(LinuxAf::unix_);
            const std::size_t n = ::strnlen(sun->sun_path, sizeof sun->sun_path);
            std::memcpy(la.sa_data, sun->sun_path, n);
            len = 2 + n + 1;
            break;
        }
        default:
            la.sa_family = static_cast<std::uint16_t>(LinuxAf::unspec);
            break;
    }
    const std::size_t n = std::min(out.size(), len);
    if (n) std::memcpy(out.data(), &la, n);
    return len;                     // Linux reports the FULL length, even if truncated
}

// -- setsockopt/getsockopt -------------------------------------------------
struct Option { int level, name; };

[[nodiscard]] inline std::optional<Option> opt_to_darwin(int level, int name) noexcept {
    constexpr int kSolSocket = 1, kSolTcp = 6, kSolIp = 0, kSolIpv6 = 41;
    if (level == kSolSocket) {
        switch (name) {
            case 1:  return Option{SOL_SOCKET, SO_DEBUG};
            case 2:  return Option{SOL_SOCKET, SO_REUSEADDR};
            case 3:  return Option{SOL_SOCKET, SO_TYPE};
            case 4:  return Option{SOL_SOCKET, SO_ERROR};
            case 5:  return Option{SOL_SOCKET, SO_DONTROUTE};
            case 6:  return Option{SOL_SOCKET, SO_BROADCAST};
            case 7:  return Option{SOL_SOCKET, SO_SNDBUF};
            case 8:  return Option{SOL_SOCKET, SO_RCVBUF};
            case 9:  return Option{SOL_SOCKET, SO_KEEPALIVE};
            case 10: return Option{SOL_SOCKET, SO_OOBINLINE};
            case 13: return Option{SOL_SOCKET, SO_LINGER};
            case 15: return Option{SOL_SOCKET, SO_REUSEPORT};
            case 20: return Option{SOL_SOCKET, SO_RCVLOWAT};
            case 19: return Option{SOL_SOCKET, SO_SNDLOWAT};
            case 21: return Option{SOL_SOCKET, SO_RCVTIMEO};
            case 22: return Option{SOL_SOCKET, SO_SNDTIMEO};
            default: return std::nullopt;
        }
    }
    if (level == kSolTcp) {
        switch (name) {
            case 1:  return Option{IPPROTO_TCP, TCP_NODELAY};
            case 2:  return Option{IPPROTO_TCP, TCP_MAXSEG};
            case 4:  return Option{IPPROTO_TCP, TCP_KEEPALIVE};
            default: return std::nullopt;
        }
    }
    if (level == kSolIp || level == kSolIpv6) return Option{level == kSolIp ? IPPROTO_IP : IPPROTO_IPV6, name};
    return std::nullopt;
}

// -- send/recv flags -------------------------------------------------------
inline constexpr std::uint64_t kMsgNosignal = 0x4000;

[[nodiscard]] inline int msg_flags_to_darwin(std::uint64_t lf) noexcept {
    int df = 0;
    if (lf & 0x1)    df |= MSG_OOB;
    if (lf & 0x2)    df |= MSG_PEEK;
    if (lf & 0x4)    df |= MSG_DONTROUTE;
    if (lf & 0x40)   df |= MSG_DONTWAIT;
    if (lf & 0x100)  df |= MSG_WAITALL;
    if (lf & 0x80)   df |= MSG_EOR;
    // MSG_NOSIGNAL has no Darwin flag: the socket gets SO_NOSIGPIPE instead.
    return df;
}

} // namespace lx::runtime::net

#endif // __APPLE__
