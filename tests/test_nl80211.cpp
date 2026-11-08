// The nl80211 replies linuxity gives where the host refuses generic netlink.
//
// Checked by parsing them with the same code rockbottom uses on a real
// kernel (its nl80211 reader walks exactly these attributes), so a reply
// that a real client would misread fails here, not on a phone.
#include "linuxity/kernel/nl80211.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

using namespace lx::kernel::nl80211;

namespace {

int failures = 0;
void check(bool ok, const char* what) {
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", what); ++failures; }
}

std::vector<std::uint8_t> request(std::uint16_t type, std::uint8_t cmd, std::uint16_t flags,
                                  std::uint32_t seq, std::vector<std::uint8_t> attrs) {
    std::vector<std::uint8_t> m(20, 0);
    const std::uint32_t len = static_cast<std::uint32_t>(20 + attrs.size());
    std::memcpy(m.data(), &len, 4);
    std::memcpy(m.data() + 4, &type, 2);
    flags |= 1;   // NLM_F_REQUEST
    std::memcpy(m.data() + 6, &flags, 2);
    std::memcpy(m.data() + 8, &seq, 4);
    m[16] = cmd;
    m[17] = 1;
    m.insert(m.end(), attrs.begin(), attrs.end());
    return m;
}

std::vector<std::uint8_t> attr(std::uint16_t type, const void* d, std::size_t n) {
    std::vector<std::uint8_t> a(4 + ((n + 3) & ~std::size_t{3}), 0);
    const auto l = static_cast<std::uint16_t>(4 + n);
    std::memcpy(a.data(), &l, 2);
    std::memcpy(a.data() + 2, &type, 2);
    std::memcpy(a.data() + 4, d, n);
    return a;
}

struct Msg { std::uint16_t type, flags; std::uint32_t seq; std::uint8_t cmd; std::vector<std::uint8_t> attrs; int err; };

std::vector<Msg> split(const std::vector<std::uint8_t>& b) {
    std::vector<Msg> out;
    std::size_t at = 0;
    while (at + 16 <= b.size()) {
        Msg m{};
        std::uint32_t len;
        std::memcpy(&len, b.data() + at, 4);
        std::memcpy(&m.type, b.data() + at + 4, 2);
        std::memcpy(&m.flags, b.data() + at + 6, 2);
        std::memcpy(&m.seq, b.data() + at + 8, 4);
        if (len < 16 || at + len > b.size()) break;
        if (m.type == 2) std::memcpy(&m.err, b.data() + at + 16, 4);
        else if (m.type != 3 && len >= 20) {
            m.cmd = b[at + 16];
            m.attrs.assign(b.begin() + static_cast<long>(at + 20), b.begin() + static_cast<long>(at + len));
        }
        out.push_back(std::move(m));
        at += (len + 3) & ~3u;
    }
    return out;
}

// value of a (possibly nested) attribute path in an attr block
std::vector<std::uint8_t> find(const std::vector<std::uint8_t>& a, std::initializer_list<std::uint16_t> path) {
    const std::uint8_t* p = a.data();
    std::size_t n = a.size();
    std::vector<std::uint8_t> cur;
    for (std::uint16_t want : path) {
        bool hit = false;
        while (n >= 4) {
            std::uint16_t l, t;
            std::memcpy(&l, p, 2);
            std::memcpy(&t, p + 2, 2);
            if (l < 4 || l > n) return {};
            if ((t & 0x3fff) == want) {
                cur.assign(p + 4, p + l);
                hit = true;
                break;
            }
            const std::size_t step = (l + 3u) & ~3u;
            if (step > n) return {};
            p += step;
            n -= step;
        }
        if (!hit) return {};
        p = cur.data();
        n = cur.size();
    }
    return cur;
}

}  // namespace

int main() {
    const std::string status =
        "Wifi is connected to \"TP-Link_6090_5G\"\n"
        "WifiInfo: SSID: \"TP-Link_6090_5G\", BSSID: 8c:90:2d:36:60:8b, MAC: 62:e1:0f:ef:d8:58, "
        "IP: /192.168.0.149, Security type: 2, Supplicant state: COMPLETED, Wi-Fi standard: 11ac, "
        "RSSI: -38, Link speed: 866Mbps, Tx Link speed: 866Mbps, Max Supported Tx Link speed: 866Mbps, "
        "Rx Link speed: 780Mbps, Frequency: 5180MHz, Net ID: 2\n";
    const WifiStatus w = parse_android_status(status);
    check(w.connected, "parsed as connected");
    check(w.ssid == "TP-Link_6090_5G", "ssid");
    check(w.rssi == -38 && w.freq == 5180 && w.tx_mbps == 866 && w.rx_mbps == 780, "numbers");
    check(w.bssid[0] == 0x8c && w.bssid[5] == 0x8b, "bssid");
    check(!parse_android_status("Wifi is disabled\n").connected, "disabled is not connected");

    // family lookup
    auto fr = request(0x10, 3, 4, 7, attr(2, "nl80211", 8));
    auto r = answer(fr.data(), fr.size(), w, 47, "wlan0", 99);
    auto ms = split(r);
    check(ms.size() == 2 && ms[0].cmd == 1 && ms[1].type == 2 && ms[1].err == 0, "family + ack");
    if (ms.empty()) return 1;
    auto fid = find(ms[0].attrs, {1});
    check(fid.size() == 2 && fid[0] == kFamily, "family id");
    auto br = request(0x10, 3, 0, 8, attr(2, "devlink", 8));
    ms = split(answer(br.data(), br.size(), w, 47, "wlan0", 99));
    check(ms.size() == 1 && ms[0].type == 2 && ms[0].err == -2, "unknown family is ENOENT");

    const std::uint32_t idx = 47;
    // interface
    auto rq = request(kFamily, 5, 0, 9, attr(3, &idx, 4));
    ms = split(answer(rq.data(), rq.size(), w, 47, "wlan0", 99));
    check(ms.size() == 1 && ms[0].cmd == 7, "interface reply");
    const auto ss = find(ms[0].attrs, {52});
    check(std::string(ss.begin(), ss.end()) == "TP-Link_6090_5G", "interface ssid");
    auto f = find(ms[0].attrs, {38});
    std::uint32_t fv = 0;
    if (f.size() == 4) std::memcpy(&fv, f.data(), 4);
    check(fv == 5180, "interface freq");
    const std::uint32_t other = 3;
    rq = request(kFamily, 5, 0, 10, attr(3, &other, 4));
    ms = split(answer(rq.data(), rq.size(), w, 47, "wlan0", 99));
    check(ms.size() == 1 && ms[0].err == -19, "other interface is ENODEV");

    // station dump
    rq = request(kFamily, 17, 0x300, 11, attr(3, &idx, 4));
    ms = split(answer(rq.data(), rq.size(), w, 47, "wlan0", 99));
    check(ms.size() == 2 && ms[0].cmd == 19 && ms[1].type == 3, "station + done");
    auto sig = find(ms[0].attrs, {21, 7});
    check(sig.size() == 1 && static_cast<std::int8_t>(sig[0]) == -38, "station signal");
    auto tx = find(ms[0].attrs, {21, 8, 5});
    std::uint32_t txv = 0;
    if (tx.size() == 4) std::memcpy(&txv, tx.data(), 4);
    check(txv == 8660, "tx bitrate in 100 kbit/s");

    // scan dump: the associated bss with the ssid element
    rq = request(kFamily, 32, 0x300, 12, attr(3, &idx, 4));
    ms = split(answer(rq.data(), rq.size(), w, 47, "wlan0", 99));
    check(ms.size() == 2 && ms[0].cmd == 34, "scan + done");
    auto ies = find(ms[0].attrs, {47, 6});
    check(ies.size() >= 2 && ies[0] == 0 && ies[1] == 15 &&
              std::string(ies.begin() + 2, ies.end()) == "TP-Link_6090_5G",
          "scan ssid element");

    // anything else is EOPNOTSUPP; disconnected dumps are empty
    rq = request(kFamily, 1 /*GET_WIPHY*/, 0, 13, {});
    ms = split(answer(rq.data(), rq.size(), w, 47, "wlan0", 99));
    check(ms.size() == 1 && ms[0].err == -95, "other command is EOPNOTSUPP");
    WifiStatus off;
    rq = request(kFamily, 17, 0x300, 14, attr(3, &idx, 4));
    ms = split(answer(rq.data(), rq.size(), off, 47, "wlan0", 99));
    check(ms.size() == 1 && ms[0].type == 3, "disconnected station dump is just done");

    if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
    std::printf("nl80211 emulation: ok\n");
    return 0;
}
