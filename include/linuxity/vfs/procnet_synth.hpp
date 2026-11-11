// linuxity/vfs/procnet_synth.hpp
//
// /proc/net for a host that has no /proc (macOS): the files programs read
// to learn the machine's interfaces -- dev, if_inet6, route, and the socket
// tables (which a guest can't see into on this host, so they list none) --
// Linux-formatted, from getifaddrs(). Without them /proc/net/dev was
// ENOENT, and tools that size their interface list from it saw nothing.
#pragma once
#if defined(__APPLE__)

#include "linuxity/abi/result.hpp"
#include "linuxity/kernel/file_namespace.hpp"

#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lx::vfs::procnet {

inline constexpr std::string_view kFiles[] = {
    "dev", "if_inet6", "route", "ipv6_route", "tcp", "tcp6", "udp", "udp6", "unix",
    "raw", "raw6", "icmp", "igmp", "arp", "netstat", "snmp", "sockstat", "protocols"};

[[nodiscard]] inline std::string lname(const char* n) {
    return std::strcmp(n, "lo0") == 0 ? std::string{"lo"} : std::string{n};
}

// nullopt: no such file; otherwise the text (a directory listing when
// `rest` is empty is handled by the caller via kFiles).
[[nodiscard]] inline std::optional<std::string> file(std::string_view rest) {
    bool known = false;
    for (auto f : kFiles) known |= rest == f;
    if (!known) return std::nullopt;
    ifaddrs* ifs = nullptr;
    if (::getifaddrs(&ifs) != 0) ifs = nullptr;
    std::string out;
    char b[512];
    if (rest == "dev") {
        out = "Inter-|   Receive                                                |  Transmit\n"
              " face |bytes    packets errs drop fifo frame compressed multicast|"
              "bytes    packets errs drop fifo colls carrier compressed\n";
        for (auto* i = ifs; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_LINK || !i->ifa_data) continue;
            const auto* d = static_cast<const if_data*>(i->ifa_data);
            std::snprintf(b, sizeof b, "%6s: %7u %7u %4u %4u %4u %5u %10u %9u %8u %7u %4u %4u %4u %5u %7u %10u\n",
                          lname(i->ifa_name).c_str(), d->ifi_ibytes, d->ifi_ipackets, d->ifi_ierrors,
                          d->ifi_iqdrops, 0u, 0u, 0u, d->ifi_imcasts, d->ifi_obytes, d->ifi_opackets,
                          d->ifi_oerrors, 0u, 0u, d->ifi_collisions, 0u, 0u);
            out += b;
        }
    } else if (rest == "if_inet6") {
        for (auto* i = ifs; i; i = i->ifa_next) {
            if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET6) continue;
            unsigned char a[16];
            std::memcpy(a, &reinterpret_cast<const sockaddr_in6*>(i->ifa_addr)->sin6_addr, 16);
            const bool ll = a[0] == 0xfe && (a[1] & 0xc0) == 0x80;
            if (ll) { a[2] = 0; a[3] = 0; }               // Darwin's embedded scope id
            std::string hex;
            for (unsigned char c : a) { char h[3]; std::snprintf(h, sizeof h, "%02x", c); hex += h; }
            int plen = 0;
            if (i->ifa_netmask) {
                const auto* m = reinterpret_cast<const unsigned char*>(
                    &reinterpret_cast<const sockaddr_in6*>(i->ifa_netmask)->sin6_addr);
                for (int k = 0; k < 16; ++k)
                    for (int bit = 7; bit >= 0; --bit) plen += m[k] >> bit & 1;
            }
            const bool lo = (i->ifa_flags & IFF_LOOPBACK) != 0;
            std::snprintf(b, sizeof b, "%s %02x %02x %02x %02x %8s\n", hex.c_str(),
                          ::if_nametoindex(i->ifa_name), plen, lo ? 0x10 : ll ? 0x20 : 0, 0x80,
                          lname(i->ifa_name).c_str());
            out += b;
        }
    } else if (rest == "route") {
        out = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
    } else if (rest == "tcp" || rest == "udp" || rest == "raw") {
        out = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    } else if (rest == "tcp6" || rest == "udp6" || rest == "raw6") {
        out = "  sl  local_address                         remote_address                        "
              "st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    } else if (rest == "unix") {
        out = "Num       RefCount Protocol Flags    Type St Inode Path\n";
    } else if (rest == "sockstat") {
        out = "sockets: used 0\nTCP: inuse 0 orphan 0 tw 0 alloc 0 mem 0\nUDP: inuse 0 mem 0\n"
              "RAW: inuse 0\nFRAG: inuse 0 memory 0\n";
    }
    if (ifs) ::freeifaddrs(ifs);
    return out;
}

} // namespace lx::vfs::procnet

#endif // __APPLE__
