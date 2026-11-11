// linuxity/kernel/nl80211.hpp — the wifi link over nl80211, when the host
// won't let us open the real socket.
//
// Android refuses generic netlink to the shell user, so `iw` and monitors
// inside the guest can't see the link. Its wifi service still tells the
// shell (`cmd wifi status`). This turns that answer into the replies the
// kernel would give to the few requests a monitor makes: resolving the
// nl80211 family, GET_INTERFACE, a station dump and a scan dump. Anything
// else is EOPNOTSUPP, which is what a driver without the feature says.
//
// Pure: bytes in, bytes out. The socket plumbing lives in the dispatcher.
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#if !defined(_WIN32)
#include <time.h>
#include <unistd.h>
#endif

namespace lx::kernel::nl80211 {

struct WifiStatus {
    bool connected{false};
    std::string ssid;
    std::array<std::uint8_t, 6> bssid{};
    int rssi{0}, freq{0}, tx_mbps{0}, rx_mbps{0};
};

// The WifiInfo line of `cmd wifi status` / `dumpsys wifi`:
//   WifiInfo: SSID: "name", BSSID: 8c:90:..., ... RSSI: -38, Link speed: 866Mbps,
//   Tx Link speed: 866Mbps, ... Rx Link speed: 780Mbps, ... Frequency: 5180MHz, ...
inline WifiStatus parse_android_status(std::string_view text) {
    WifiStatus s;
    const auto at = text.find("WifiInfo:");
    if (at == std::string_view::npos) return s;
    const std::string_view line = text.substr(at, text.find('\n', at) - at);
    auto after = [&](std::string_view key) -> std::string_view {
        const auto k = line.find(key);
        return k == std::string_view::npos ? std::string_view{} : line.substr(k + key.size());
    };
    auto num = [&](std::string_view key) {
        const std::string_view v = after(key);
        return v.empty() ? 0 : std::atoi(std::string{v.substr(0, 12)}.c_str());
    };
    if (const auto v = after("SSID: \""); !v.empty()) {
        const auto q = v.find('"');
        if (q != std::string_view::npos && q <= 32) s.ssid.assign(v.substr(0, q));
    }
    if (const auto v = after("BSSID: "); v.size() >= 17) {
        unsigned b[6];
        if (std::sscanf(std::string{v.substr(0, 17)}.c_str(), "%x:%x:%x:%x:%x:%x",
                        &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6)
            for (int i = 0; i < 6; ++i) s.bssid[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(b[i]);
    }
    s.rssi = num("RSSI: ");
    s.freq = num("Frequency: ");
    s.tx_mbps = num("Tx Link speed: ");
    s.rx_mbps = num("Rx Link speed: ");
    if (!s.tx_mbps) s.tx_mbps = num("Link speed: ");
    s.connected = !s.ssid.empty() && s.ssid != "<unknown ssid>" && s.rssi < 0 && s.rssi > -127;
    return s;
}

// The live status from Android's wifi service, cached a second: a monitor
// sends three requests per sample. Empty off Android.
inline WifiStatus android_status() {
    static WifiStatus cache;
    static long long at_ms = -1;
    timespec ts{};
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
    const long long now = ts.tv_sec * 1000ll + ts.tv_nsec / 1000000;
    if (at_ms >= 0 && now - at_ms < 1000) return cache;
    at_ms = now;
    std::string out;
    if (::access("/system/bin/cmd", X_OK) == 0)
        if (std::FILE* p = ::popen("/system/bin/cmd wifi status 2>/dev/null", "re")) {
            char buf[4096];
            while (std::size_t n = std::fread(buf, 1, sizeof buf, p)) out.append(buf, n);
            ::pclose(p);
        }
    cache = parse_android_status(out);
    return cache;
}

namespace detail {

constexpr std::uint16_t kNlmsgError = 2, kNlmsgDone = 3;
constexpr std::uint16_t kFRequest = 1, kFMulti = 2, kFAck = 4, kFDump = 0x300;
constexpr std::uint16_t kGenlCtrl = 0x10;
constexpr std::uint8_t kCtrlGetFamily = 3, kCtrlNewFamily = 1;
constexpr std::uint16_t kCtrlFamilyId = 1, kCtrlFamilyName = 2;
constexpr std::uint8_t kGetInterface = 5, kNewInterface = 7, kGetStation = 17,
                       kNewStation = 19, kGetScan = 32, kNewScan = 34;
constexpr std::uint16_t kIfindex = 3, kIfname = 4, kIftype = 5, kMac = 6, kStaInfo = 21,
                        kBss = 47, kSsid = 52, kWiphyFreq = 38;
constexpr std::uint16_t kStaSignal = 7, kStaTx = 8, kStaRx = 14, kRateBitrate32 = 5;
constexpr std::uint16_t kBssBssid = 1, kBssFreq = 2, kBssIes = 6, kBssStatus = 9;
constexpr std::uint16_t kNested = 0x8000;

using Bytes = std::vector<std::uint8_t>;

inline void put16(Bytes& b, std::uint16_t v) { b.push_back(static_cast<std::uint8_t>(v & 0xff)); b.push_back(static_cast<std::uint8_t>(v >> 8)); }
inline void put32(Bytes& b, std::uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff)); }
inline void pad4(Bytes& b) { while (b.size() % 4) b.push_back(0); }

inline void attr(Bytes& b, std::uint16_t type, const void* data, std::size_t len) {
    put16(b, static_cast<std::uint16_t>(4 + len));
    put16(b, type);
    const auto* p = static_cast<const std::uint8_t*>(data);
    b.insert(b.end(), p, p + len);
    pad4(b);
}
inline void attr32(Bytes& b, std::uint16_t t, std::uint32_t v) { attr(b, t, &v, 4); }
inline void attr16(Bytes& b, std::uint16_t t, std::uint16_t v) { attr(b, t, &v, 2); }
// a nest: the caller appends children, then closes it
inline std::size_t nest_open(Bytes& b, std::uint16_t type) {
    const std::size_t at = b.size();
    put16(b, 0);
    put16(b, static_cast<std::uint16_t>(type | kNested));
    return at;
}
inline void nest_close(Bytes& b, std::size_t at) {
    const auto len = static_cast<std::uint16_t>(b.size() - at);
    b[at] = static_cast<std::uint8_t>(len & 0xff);
    b[at + 1] = static_cast<std::uint8_t>(len >> 8);
}

// One netlink message: header, genl header (when cmd >= 0), payload.
inline void message(Bytes& out, std::uint16_t type, std::uint16_t flags, std::uint32_t seq,
                    std::uint32_t pid, int cmd, const Bytes& payload) {
    const std::size_t at = out.size();
    put32(out, 0);
    put16(out, type);
    put16(out, flags);
    put32(out, seq);
    put32(out, pid);
    if (cmd >= 0) { out.push_back(static_cast<std::uint8_t>(cmd)); out.push_back(1); put16(out, 0); }
    out.insert(out.end(), payload.begin(), payload.end());
    const auto len = static_cast<std::uint32_t>(out.size() - at);
    std::memcpy(out.data() + at, &len, 4);
    pad4(out);
}

inline void error(Bytes& out, const std::uint8_t* req, std::uint32_t pid, int err) {
    Bytes p;
    put32(p, static_cast<std::uint32_t>(err));       // error: negative errno, 0 = ack
    p.insert(p.end(), req, req + 16);                 // the request's header
    std::uint32_t seq;
    std::memcpy(&seq, req + 8, 4);
    message(out, kNlmsgError, 0, seq, pid, -1, p);
}

inline void done(Bytes& out, std::uint32_t seq, std::uint32_t pid) {
    Bytes p;
    put32(p, 0);
    message(out, kNlmsgDone, kFMulti, seq, pid, -1, p);
}

// Find a top-level attribute in a genl payload.
inline std::string_view find_attr(const std::uint8_t* p, std::size_t len, std::uint16_t type) {
    while (len >= 4) {
        std::uint16_t al, at;
        std::memcpy(&al, p, 2);
        std::memcpy(&at, p + 2, 2);
        if (al < 4 || al > len) break;
        if ((at & 0x3fff) == type)
            return {reinterpret_cast<const char*>(p + 4), static_cast<std::size_t>(al - 4)};
        const std::size_t step = (al + 3u) & ~3u;
        if (step > len) break;
        p += step;
        len -= step;
    }
    return {};
}

}  // namespace detail

// The family id we hand out for "nl80211". Any free genl id works.
inline constexpr std::uint16_t kFamily = 0x1d;

// Answer every netlink message in `req`. `ifindex`/`ifname` name the wifi
// interface; `pid` is the socket's port id.
inline std::vector<std::uint8_t> answer(const std::uint8_t* req, std::size_t len,
                                        const WifiStatus& w, std::uint32_t ifindex,
                                        const std::string& ifname, std::uint32_t pid) {
    using namespace detail;
    Bytes out;
    while (len >= 20) {   // nlmsghdr + genlmsghdr
        std::uint32_t mlen, seq;
        std::uint16_t type, flags;
        std::memcpy(&mlen, req, 4);
        std::memcpy(&type, req + 4, 2);
        std::memcpy(&flags, req + 6, 2);
        std::memcpy(&seq, req + 8, 4);
        if (mlen < 20 || mlen > len) break;
        const std::uint8_t cmd = req[16];
        const std::uint8_t* attrs = req + 20;
        const std::size_t alen = mlen - 20;
        const bool dump = (flags & kFDump) == kFDump;
        // the interface asked about, if any (0 = all)
        std::uint32_t want = 0;
        if (const auto v = find_attr(attrs, alen, kIfindex); v.size() >= 4) std::memcpy(&want, v.data(), 4);
        const bool ours = want == 0 || want == ifindex;
        bool answered = true;

        if (type == kGenlCtrl && cmd == kCtrlGetFamily) {
            const auto name = find_attr(attrs, alen, kCtrlFamilyName);
            if (std::string_view{name.data(), name.find('\0') == std::string_view::npos
                                                  ? name.size() : name.find('\0')} == "nl80211") {
                Bytes p;
                attr16(p, kCtrlFamilyId, kFamily);
                attr(p, kCtrlFamilyName, "nl80211", 8);
                message(out, kGenlCtrl, 0, seq, pid, kCtrlNewFamily, p);
            } else {
                error(out, req, pid, -2);   // ENOENT: no such family
                answered = false;
            }
        } else if (type == kFamily && cmd == kGetInterface) {
            if (!ours) { error(out, req, pid, -19); answered = false; }   // ENODEV
            else {
                Bytes p;
                attr32(p, kIfindex, ifindex);
                attr(p, kIfname, ifname.c_str(), ifname.size() + 1);
                attr32(p, kIftype, 2);   // station
                if (w.connected) {
                    attr32(p, kWiphyFreq, static_cast<std::uint32_t>(w.freq));
                    attr(p, kSsid, w.ssid.data(), w.ssid.size());
                }
                message(out, kFamily, dump ? kFMulti : 0, seq, pid, kNewInterface, p);
                if (dump) done(out, seq, pid);
            }
        } else if (type == kFamily && cmd == kGetStation && dump) {
            if (ours && w.connected) {
                Bytes p;
                attr32(p, kIfindex, ifindex);
                attr(p, kMac, w.bssid.data(), 6);
                const auto si = nest_open(p, kStaInfo);
                const std::int8_t sig = static_cast<std::int8_t>(std::clamp(w.rssi, -128, 0));
                attr(p, kStaSignal, &sig, 1);
                for (const auto& [t, mbps] : {std::pair{kStaTx, w.tx_mbps}, std::pair{kStaRx, w.rx_mbps}}) {
                    if (mbps <= 0) continue;
                    const auto r = nest_open(p, t);
                    attr32(p, kRateBitrate32, static_cast<std::uint32_t>(mbps) * 10);  // 100 kbit/s
                    nest_close(p, r);
                }
                nest_close(p, si);
                message(out, kFamily, kFMulti, seq, pid, kNewStation, p);
            }
            done(out, seq, pid);
        } else if (type == kFamily && cmd == kGetScan && dump) {
            if (ours && w.connected) {
                Bytes p;
                attr32(p, kIfindex, ifindex);
                const auto bss = nest_open(p, kBss);
                attr(p, kBssBssid, w.bssid.data(), 6);
                attr32(p, kBssFreq, static_cast<std::uint32_t>(w.freq));
                Bytes ie{0, static_cast<std::uint8_t>(w.ssid.size())};   // SSID element
                ie.insert(ie.end(), w.ssid.begin(), w.ssid.end());
                attr(p, kBssIes, ie.data(), ie.size());
                attr32(p, kBssStatus, 1);   // associated
                nest_close(p, bss);
                message(out, kFamily, kFMulti, seq, pid, kNewScan, p);
            }
            done(out, seq, pid);
        } else {
            error(out, req, pid, -95);   // EOPNOTSUPP
            answered = false;
        }
        if (answered && (flags & kFAck) && !dump) error(out, req, pid, 0);   // the ack
        const std::size_t step = (mlen + 3u) & ~3u;
        if (step >= len) break;
        req += step;
        len -= step;
    }
    return out;
}

}  // namespace lx::kernel::nl80211
