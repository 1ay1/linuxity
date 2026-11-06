// SPDX-License-Identifier: LGPL-2.0-or-later
//
// Where the guest's nameservers come from.
//
// A guest rootfs ships /etc/resolv.conf empty or absent, so the runtime has
// to supply one. The question "what resolver should the guest use" has a
// different ANSWER on every host but only one SHAPE: a list of nameserver
// addresses. So this is one ordered list of SOURCES, each a pure function
// from the host to addresses, and the first that yields any wins.
//
// Why not "bind the host's /etc/resolv.conf" (what the runtime used to do):
// that conflates DISCOVERING the resolver with READING A FILE, and the file
// is a glibc-ism. Android keeps DNS in netd and has no /etc/resolv.conf at
// all, so the bind silently did nothing and every guest lookup failed with
// "Could not resolve host" -- while the host itself resolved fine. The file
// is one source among several, not the definition.
//
// The guest always sees a real /etc/resolv.conf: the namespace serves it as
// a VIRTUAL file (like /proc and /dev) rather than mutating the pristine
// rootfs. One code path for every host.
#ifndef LX_KERNEL_RESOLVER_HPP
#define LX_KERNEL_RESOLVER_HPP

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace lx::kernel {

// A nameserver address, as text (v4 or v6 literal). Text because that is
// what resolv.conf carries and what every consumer parses.
using Nameservers = std::vector<std::string>;

// --- sources ---------------------------------------------------------------
// Each source answers "what nameservers does this host use?" or nothing.
// Ordered most-specific-to-least by the caller; none of them mutate state.

// 1. A resolv.conf on the host. The glibc/musl answer, and the most accurate
//    one when it exists: it tracks VPNs, split-horizon and corporate
//    resolvers. Absent on Android.
[[nodiscard]] inline Nameservers nameservers_from_file(const char* path) {
    Nameservers out;
    std::FILE* f = std::fopen(path, "r");
    if (!f) return out;
    char line[512];
    while (std::fgets(line, sizeof line, f)) {
        const char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '#' || *p == ';') continue;
        if (std::strncmp(p, "nameserver", 10) != 0) continue;
        p += 10;
        if (*p != ' ' && *p != '\t') continue;
        while (*p == ' ' || *p == '\t') ++p;
        std::string addr;
        while (*p && *p != '\n' && *p != '\r' && *p != ' ' && *p != '\t')
            addr.push_back(*p++);
        if (!addr.empty()) out.push_back(std::move(addr));
    }
    std::fclose(f);
    return out;
}

// 2. The last resort: public resolvers. Correct in the sense that it WORKS
//    (a guest with no resolver is a guest that cannot install anything), and
//    wrong in the sense that it ignores a split-horizon setup -- which is
//    why it is last and why the caller says so on stderr.
//
//    Not a "bandaid for Android": any host whose resolver isn't a file nor
//    enumerable lands here, and the guest needs SOMETHING to put in
//    resolv.conf. Overridable with LINUXITY_DNS.
[[nodiscard]] inline Nameservers nameservers_public() {
    return {"1.1.1.1", "8.8.8.8"};
}

// 3. An explicit override, highest priority: LINUXITY_DNS=10.0.0.1,10.0.0.2.
//    The escape hatch for anyone whose resolver we guess wrong.
[[nodiscard]] inline Nameservers nameservers_from_env(const char* spec) {
    Nameservers out;
    if (!spec || !*spec) return out;
    std::string_view s{spec};
    while (!s.empty()) {
        const auto comma = s.find(',');
        std::string_view one = s.substr(0, comma);
        while (!one.empty() && (one.front() == ' ')) one.remove_prefix(1);
        while (!one.empty() && (one.back() == ' ')) one.remove_suffix(1);
        if (!one.empty()) out.emplace_back(one);
        if (comma == std::string_view::npos) break;
        s.remove_prefix(comma + 1);
    }
    return out;
}

// --- the policy ------------------------------------------------------------

// Where a resolver list came from, so the caller can tell the user. The guest
// never sees this; it exists because "DNS silently did nothing" is the bug
// this module was written to kill.
enum class ResolverOrigin { none, env, host_file, guest_file, fallback };

struct ResolverChoice {
    Nameservers     servers{};
    ResolverOrigin  origin{ResolverOrigin::none};

    [[nodiscard]] bool empty() const noexcept { return servers.empty(); }
};

[[nodiscard]] constexpr std::string_view origin_name(ResolverOrigin o) noexcept {
    switch (o) {
        case ResolverOrigin::none:       return "none";
        case ResolverOrigin::env:        return "LINUXITY_DNS";
        case ResolverOrigin::host_file:  return "host /etc/resolv.conf";
        case ResolverOrigin::guest_file: return "rootfs /etc/resolv.conf";
        case ResolverOrigin::fallback:   return "public resolvers";
    }
    return "?";
}

// Pick the guest's nameservers. `guest_resolv` is the rootfs's own
// resolv.conf as a HOST path (empty if it has none) -- if the image ships a
// real one, the image wins and we serve it unchanged.
//
// One ordered policy, evaluated the same way on every host. A host that
// grows a better discovery source adds it here and every platform gets it.
[[nodiscard]] inline ResolverChoice choose_nameservers(
    const char* env_spec, const char* host_resolv, const std::string& guest_resolv) {

    if (auto v = nameservers_from_env(env_spec); !v.empty())
        return {std::move(v), ResolverOrigin::env};

    // The image's own resolver, if it actually names one.
    if (!guest_resolv.empty())
        if (auto v = nameservers_from_file(guest_resolv.c_str()); !v.empty())
            return {std::move(v), ResolverOrigin::guest_file};

    if (host_resolv && *host_resolv)
        if (auto v = nameservers_from_file(host_resolv); !v.empty())
            return {std::move(v), ResolverOrigin::host_file};

    return {nameservers_public(), ResolverOrigin::fallback};
}

// Render a resolv.conf. The guest reads this through the normal VFS, so it
// looks exactly like a file the image shipped.
[[nodiscard]] inline std::string render_resolv_conf(const Nameservers& ns) {
    std::string out =
        "# Generated by linuxity. The host's resolver, as the guest sees it.\n";
    for (const std::string& a : ns) {
        out += "nameserver ";
        out += a;
        out += '\n';
    }
    // options: keep the defaults small and predictable; a guest that wants
    // more can still ship its own resolv.conf, which wins above.
    out += "options edns0\n";
    return out;
}

}  // namespace lx::kernel

#endif  // LX_KERNEL_RESOLVER_HPP
