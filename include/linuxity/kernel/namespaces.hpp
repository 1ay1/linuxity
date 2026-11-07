// linuxity/kernel/namespaces.hpp
//
// The guest's namespaces (namespaces(7)). A host that forbids them (Android
// compiles user namespaces out, and an app has no CAP_SYS_ADMIN) still gives
// the guest working unshare/setns/clone(CLONE_NEW*): linuxity keeps the
// namespaces itself, for the state it owns. UTS names and user id maps are
// fully virtual. A new network namespace has no route out. pid numbering
// lives in process_table.hpp next to the pids it renumbers.
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace lx::kernel {

enum class NsKind : int { cgroup, ipc, mnt, net, pid, time, user, uts };
inline constexpr int kNsKinds = 8;
inline constexpr std::array<std::string_view, kNsKinds> kNsName = {
    "cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"};
// The CLONE_NEW* flag for each kind, in NsKind order.
inline constexpr std::array<std::uint64_t, kNsKinds> kNsFlag = {
    0x02000000, 0x08000000, 0x00020000, 0x40000000,
    0x20000000, 0x00000080, 0x10000000, 0x04000000};
inline constexpr std::uint64_t kCloneNewMask = 0x7e020080;

// Which namespaces a process is in. 0 = the initial one.
struct NsSet {
    std::array<std::uint64_t, kNsKinds> id{};
    std::uint64_t pid_for_children{0};    // where its next child's pid lives
    std::uint64_t time_for_children{0};
};

// One line of a uid_map/gid_map: ids [inside, inside+count) of the namespace
// are [outside, outside+count) of its parent.
struct IdExtent { std::uint32_t inside, outside, count; };

class Namespaces {
public:
    static constexpr std::uint32_t kOverflowId = 65534;

    Namespaces() {
        // The canonical init namespace inodes, used where the host hides its own.
        static constexpr std::array<std::uint64_t, kNsKinds> kCanon = {
            4026531835, 4026531839, 4026531841, 4026531840,
            4026531836, 4026531834, 4026531837, 4026531838};
        initial_ = kCanon;
#if !defined(_WIN32)
        for (int k = 0; k < kNsKinds; ++k) {
            const std::string p = "/proc/self/ns/" + std::string{kNsName[k]};
            char buf[64];
            const ::ssize_t n = ::readlink(p.c_str(), buf, sizeof buf - 1);
            if (n <= 0) continue;
            buf[n] = '\0';
            if (const char* b = std::strchr(buf, '['))
                if (const auto v = std::strtoull(b + 1, nullptr, 10)) initial_[k] = v;
        }
#endif
        next_ = 4026532400;
        for (const auto v : initial_) if (v >= next_) next_ = v + 64;
    }

    [[nodiscard]] std::uint64_t initial(NsKind k) const { return initial_[static_cast<int>(k)]; }
    // The namespace a set names for `k`, 0 resolved to the initial one.
    [[nodiscard]] std::uint64_t resolve(const NsSet& s, NsKind k) const {
        const auto v = s.id[static_cast<int>(k)];
        return v ? v : initial(k);
    }
    [[nodiscard]] bool is_initial(const NsSet& s, NsKind k) const {
        return resolve(s, k) == initial(k);
    }
    [[nodiscard]] std::uint64_t fresh() { return next_++; }

    // -- UTS: hostname and domainname per namespace --------------------------
    void set_initial_hostname(std::string h) { uts_[0] = {std::move(h), "(none)"}; }
    [[nodiscard]] const std::pair<std::string, std::string>& uts(std::uint64_t id) const {
        if (auto it = uts_.find(id); it != uts_.end()) return it->second;
        return uts_.at(0);
    }
    void copy_uts(std::uint64_t from, std::uint64_t to) { uts_[to] = uts(from); }
    void set_hostname(std::uint64_t id, std::string h) { auto u = uts(id); u.first = std::move(h); uts_[id] = std::move(u); }
    void set_domainname(std::uint64_t id, std::string d) { auto u = uts(id); u.second = std::move(d); uts_[id] = std::move(u); }

    // -- user namespaces -----------------------------------------------------
    struct UserNs {
        std::uint64_t parent{0};
        std::vector<IdExtent> uid_map, gid_map;
        bool uid_set{false}, gid_set{false};
        bool setgroups_allowed{true};
    };
    void new_user_ns(std::uint64_t id, std::uint64_t parent) { users_[id].parent = parent; }
    [[nodiscard]] UserNs* user_ns(std::uint64_t id) {
        auto it = users_.find(id);
        return it == users_.end() ? nullptr : &it->second;
    }
    [[nodiscard]] const UserNs* user_ns(std::uint64_t id) const {
        auto it = users_.find(id);
        return it == users_.end() ? nullptr : &it->second;
    }
    // An id of the initial namespace as seen from user namespace `ns`.
    [[nodiscard]] std::uint32_t to_ns(std::uint64_t ns, std::uint32_t id, bool gid) const {
        const UserNs* u = user_ns(ns);
        if (!u) return id;   // the initial namespace
        const std::uint32_t up = to_ns(u->parent, id, gid);
        if (up == kOverflowId) return kOverflowId;
        for (const auto& e : gid ? u->gid_map : u->uid_map)
            if (up >= e.outside && up - e.outside < e.count) return e.inside + (up - e.outside);
        return kOverflowId;
    }
    // An id as user namespace `ns` names it, back to the initial namespace;
    // nullopt when it isn't mapped there.
    [[nodiscard]] std::optional<std::uint32_t> from_ns(std::uint64_t ns, std::uint32_t id, bool gid) const {
        const UserNs* u = user_ns(ns);
        if (!u) return id;
        for (const auto& e : gid ? u->gid_map : u->uid_map)
            if (id >= e.inside && id - e.inside < e.count)
                return from_ns(u->parent, e.outside + (id - e.inside), gid);
        return std::nullopt;
    }
    // The text of /proc/<pid>/uid_map (or gid_map) for a process in `ns`.
    [[nodiscard]] std::string map_text(std::uint64_t ns, bool gid) const {
        const UserNs* u = user_ns(ns);
        if (!u) return "         0          0 4294967295\n";
        std::string s;
        char line[64];
        for (const auto& e : gid ? u->gid_map : u->uid_map) {
            std::snprintf(line, sizeof line, "%10u %10u %10u\n", e.inside, e.outside, e.count);
            s += line;
        }
        return s;
    }
    // Apply a write to uid_map/gid_map. Once per namespace, like the kernel.
    static std::vector<IdExtent> parse_map(std::string_view text) {
        std::vector<IdExtent> out;
        while (!text.empty()) {
            const auto nl = text.find('\n');
            const std::string line{text.substr(0, nl)};
            text.remove_prefix(nl == std::string_view::npos ? text.size() : nl + 1);
            unsigned long a = 0, b = 0, c = 0;
            if (std::sscanf(line.c_str(), "%lu %lu %lu", &a, &b, &c) == 3 && c > 0 && out.size() < 340)
                out.push_back({static_cast<std::uint32_t>(a), static_cast<std::uint32_t>(b),
                               static_cast<std::uint32_t>(c)});
        }
        return out;
    }

    // -- network: a new namespace starts with only a downed loopback ---------
    [[nodiscard]] bool net_isolated(const NsSet& s) const { return !is_initial(s, NsKind::net); }

private:
    std::array<std::uint64_t, kNsKinds> initial_{};
    std::uint64_t next_{0};
    std::map<std::uint64_t, std::pair<std::string, std::string>> uts_{{0, {"linuxity", "(none)"}}};
    std::map<std::uint64_t, UserNs> users_;
};

}  // namespace lx::kernel
