// SPDX-License-Identifier: LGPL-2.0-or-later
//
// Where an AF_UNIX socket actually lives.
//
// A guest binds a filesystem socket (/root/.gnupg/S.gpg-agent) and the
// runtime translates that into the overlay, so both peers resolve to the same
// node. That requires the HOST to permit a filesystem bind -- which is not
// universal: Android's SELinux policy denies AF_UNIX binds anywhere an app
// can write, including app-private storage, while permitting the ABSTRACT
// namespace (a \0-prefixed sun_path with no filesystem node at all).
//
// Measured on a Pixel 6a, outside linuxity entirely, as the `shell` domain:
//
//     ABSTRACT:\0                            bind=0  OK
//     /data/local/tmp/probe.sock             bind=-1 Permission denied
//     /data/local/tmp/arch-upper/probe.sock  bind=-1 Permission denied
//
// So the socket NAMESPACE is a host capability, not a constant. This header
// is the one place that decides which to use and how a guest path becomes an
// abstract name; abi/syscall.hpp's do_sockaddr_un consults it for bind and
// connect alike, which is what keeps the two peers meeting.
#ifndef LX_KERNEL_SOCKET_NS_HPP
#define LX_KERNEL_SOCKET_NS_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace lx::kernel {

// How this host wants AF_UNIX sockets named.
enum class SocketNs {
    // The normal answer: a real node in the overlay, visible to `ls`, with
    // filesystem permissions. Everything POSIX expects.
    filesystem,
    // The Android answer: no node, a name in the kernel's abstract namespace.
    // Invisible to the filesystem, so a guest that stats its own socket sees
    // nothing -- accepted because the alternative is no sockets at all.
    abstract,
};

// Derive the abstract NAME for a guest socket path.
//
// Must be a pure function of the GUEST path, never the host path: bind and
// connect translate at different times and (for bind) against the writable
// upper, so hashing the host path would give the two peers different names
// and they would never meet. The guest path is the thing both agree on.
//
// Namespaced with a prefix so two linuxity instances on one device don't
// collide with each other or with Android's own abstract sockets, and so the
// name is recognisable in `ss -x` output when debugging.
[[nodiscard]] inline std::string abstract_name_for(std::string_view guest_path,
                                                   std::uint64_t instance) {
    // FNV-1a over the guest path. A hash rather than the path itself because
    // sun_path is 108 bytes and a deep guest path plus a prefix would not fit
    // -- and truncating would silently alias two different sockets.
    std::uint64_t h = 1469598103934665603ull;
    for (const char c : guest_path) {
        h ^= static_cast<std::uint8_t>(c);
        h *= 1099511628211ull;
    }

    static constexpr char kHex[] = "0123456789abcdef";
    std::string out = "linuxity/";
    // The instance id keeps concurrent runs apart; without it two guests
    // would share one gpg-agent socket.
    for (int shift = 60; shift >= 0; shift -= 4)
        out.push_back(kHex[(instance >> shift) & 0xF]);
    out.push_back('/');
    for (int shift = 60; shift >= 0; shift -= 4)
        out.push_back(kHex[(h >> shift) & 0xF]);
    return out;
}

}  // namespace lx::kernel

#endif  // LX_KERNEL_SOCKET_NS_HPP
