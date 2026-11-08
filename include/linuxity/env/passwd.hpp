// linuxity/env/passwd.hpp
//
// Reads the GUEST's /etc/passwd and /etc/group, so login.user can name a
// user and the session gets that user's uid, gid, supplementary groups,
// home and shell. The files are read from the host path that backs the
// guest's view (the overlay upper first, so a guest `useradd` is seen).
#pragma once

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace lx::env {

struct UserInfo {
    std::string name;
    std::uint32_t uid{0};
    std::uint32_t gid{0};
    std::string home{"/root"};
    std::string shell{"/bin/sh"};
    std::vector<std::uint32_t> groups;   // supplementary, primary included
};

namespace detail {

[[nodiscard]] inline std::vector<std::string_view> split_colons(std::string_view line) {
    std::vector<std::string_view> f;
    while (true) {
        const auto c = line.find(':');
        f.push_back(line.substr(0, c));
        if (c == std::string_view::npos) break;
        line.remove_prefix(c + 1);
    }
    return f;
}

[[nodiscard]] inline std::optional<std::uint32_t> to_id(std::string_view s) {
    if (s.empty() || s.size() > 10 || s.find_first_not_of("0123456789") != std::string_view::npos)
        return std::nullopt;
    const unsigned long long v = std::strtoull(std::string{s}.c_str(), nullptr, 10);
    if (v > 0xfffffffeULL) return std::nullopt;
    return static_cast<std::uint32_t>(v);
}

}  // namespace detail

// Look `who` up in passwd text; `who` may be a name or a numeric uid.
[[nodiscard]] inline std::optional<UserInfo> find_user(std::string_view passwd, std::string_view who) {
    const auto want_uid = detail::to_id(who);
    std::istringstream in{std::string{passwd}};
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto f = detail::split_colons(line);
        if (f.size() < 7) continue;
        const auto uid = detail::to_id(f[2]);
        const auto gid = detail::to_id(f[3]);
        if (!uid || !gid) continue;
        if (f[0] != who && !(want_uid && *want_uid == *uid)) continue;
        UserInfo u;
        u.name = std::string{f[0]};
        u.uid = *uid;
        u.gid = *gid;
        u.home = f[5].empty() ? std::string{"/"} : std::string{f[5]};
        u.shell = f[6].empty() ? std::string{"/bin/sh"} : std::string{f[6]};
        return u;
    }
    return std::nullopt;
}

// The groups `user` belongs to: its primary group plus every group whose
// member list names it, the way initgroups(3) builds the list.
[[nodiscard]] inline std::vector<std::uint32_t> groups_of(std::string_view group_text,
                                                          std::string_view user,
                                                          std::uint32_t primary) {
    std::vector<std::uint32_t> out{primary};
    std::istringstream in{std::string{group_text}};
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto f = detail::split_colons(line);
        if (f.size() < 4) continue;
        const auto gid = detail::to_id(f[2]);
        if (!gid) continue;
        std::string_view members = f[3];
        while (!members.empty()) {
            const auto c = members.find(',');
            if (members.substr(0, c) == user) {
                bool have = false;
                for (auto g : out) have = have || g == *gid;
                if (!have) out.push_back(*gid);
                break;
            }
            if (c == std::string_view::npos) break;
            members.remove_prefix(c + 1);
        }
    }
    return out;
}

[[nodiscard]] inline std::string read_text(const std::string& path) {
    std::ifstream f{path, std::ios::binary};
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// The first of `layers` (host dirs, top layer first) that has `rel`.
[[nodiscard]] inline std::string read_layered(const std::vector<std::string>& layers,
                                              const std::string& rel) {
    for (const auto& l : layers) {
        std::ifstream f{l + rel, std::ios::binary};
        if (!f) continue;
        std::ostringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }
    return {};
}

// Resolve a login user against a rootfs. Root always resolves, even in an
// image with no passwd file, so a bare tree still runs.
[[nodiscard]] inline std::optional<UserInfo> resolve_user(const std::vector<std::string>& layers,
                                                          std::string_view who) {
    const std::string passwd = read_layered(layers, "/etc/passwd");
    auto u = find_user(passwd, who);
    if (!u) {
        if (who != "root" && who != "0") return std::nullopt;
        u = UserInfo{};
        u->name = "root";
    }
    u->groups = groups_of(read_layered(layers, "/etc/group"), u->name, u->gid);
    return u;
}

}  // namespace lx::env
