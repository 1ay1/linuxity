// linuxity/abi/creds.hpp
//
// The kernel's credential rules: who may change which ids, and what that
// does to capabilities (credentials(7), capabilities(7)). Pure functions
// over a ProcInfo, so every backend shares them and they can be tested.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/kernel/process_table.hpp"

#include <cstdint>

namespace lx::abi::creds {

using kernel::ProcInfo;

inline constexpr int kCapChown = 0, kCapDacOverride = 1, kCapDacReadSearch = 2,
    kCapFowner = 3, kCapFsetid = 4, kCapKill = 5, kCapSetgid = 6, kCapSetuid = 7,
    kCapSetpcap = 8, kCapLinuxImmutable = 9, kCapSysNice = 23, kCapSysResource = 24,
    kCapMknod = 27, kCapMacOverride = 32, kCapLast = 40;

inline constexpr std::uint32_t kKeep = 0xffffffffu;   // "-1": leave this id alone

[[nodiscard]] constexpr std::uint64_t bit(int c) noexcept { return std::uint64_t{1} << c; }
[[nodiscard]] inline bool capable(const ProcInfo& p, int c) noexcept { return (p.cap_eff & bit(c)) != 0; }

// The capabilities that follow fsuid between 0 and non-zero.
inline constexpr std::uint64_t kFsCaps =
    bit(kCapChown) | bit(kCapDacOverride) | bit(kCapDacReadSearch) | bit(kCapFowner) |
    bit(kCapFsetid) | bit(kCapLinuxImmutable) | bit(kCapMacOverride) | bit(kCapMknod);

// After a uid change: the fixups of capabilities(7) "Effect of user ID
// changes on capabilities".
inline void fix_caps_after_uid_change(ProcInfo& p, const std::array<std::uint32_t, 4>& old) {
    const bool had_root = old[0] == 0 || old[1] == 0 || old[2] == 0;
    const bool no_root = p.uids[0] != 0 && p.uids[1] != 0 && p.uids[2] != 0;
    if (had_root && no_root) {
        if (!p.keepcaps) p.cap_prm = 0;
        p.cap_eff = 0;
        p.cap_amb = 0;
    }
    if (old[1] == 0 && p.uids[1] != 0) p.cap_eff = 0;
    if (old[1] != 0 && p.uids[1] == 0) p.cap_eff = p.cap_prm;
    if (old[3] == 0 && p.uids[3] != 0) p.cap_eff &= ~kFsCaps;
    if (old[3] != 0 && p.uids[3] == 0) p.cap_eff |= p.cap_prm & kFsCaps;
}

[[nodiscard]] inline bool one_of(std::uint32_t v, std::uint32_t a, std::uint32_t b, std::uint32_t c) noexcept {
    return v == a || v == b || v == c;
}

// setresuid / setresgid. `ids` is p.uids or p.gids, `cap` the capability
// that lifts the restriction.
[[nodiscard]] inline Errno setres(ProcInfo& p, std::array<std::uint32_t, 4>& ids, int cap,
                                  std::uint32_t r, std::uint32_t e, std::uint32_t s) {
    if (!capable(p, cap)) {
        for (const std::uint32_t v : {r, e, s})
            if (v != kKeep && !one_of(v, ids[0], ids[1], ids[2])) return Errno::eperm;
    }
    const auto old = p.uids;
    if (r != kKeep) ids[0] = r;
    if (e != kKeep) ids[1] = e;
    if (s != kKeep) ids[2] = s;
    ids[3] = ids[1];
    if (&ids == &p.uids) fix_caps_after_uid_change(p, old);
    return Errno::ok;
}

// setreuid / setregid.
[[nodiscard]] inline Errno setre(ProcInfo& p, std::array<std::uint32_t, 4>& ids, int cap,
                                 std::uint32_t r, std::uint32_t e) {
    if (!capable(p, cap)) {
        if (r != kKeep && r != ids[0] && r != ids[1]) return Errno::eperm;
        if (e != kKeep && !one_of(e, ids[0], ids[1], ids[2])) return Errno::eperm;
    }
    const auto old = p.uids;
    const std::uint32_t old_real = ids[0];
    if (r != kKeep) ids[0] = r;
    if (e != kKeep) ids[1] = e;
    // the saved id follows the new effective one when the real id was set,
    // or the effective one changed to something other than the old real id
    if (r != kKeep || (e != kKeep && e != old_real)) ids[2] = ids[1];
    ids[3] = ids[1];
    if (&ids == &p.uids) fix_caps_after_uid_change(p, old);
    return Errno::ok;
}

// setuid / setgid: privileged sets all three, otherwise only the effective.
[[nodiscard]] inline Errno set_one(ProcInfo& p, std::array<std::uint32_t, 4>& ids, int cap,
                                   std::uint32_t v) {
    const auto old = p.uids;
    if (capable(p, cap)) {
        ids[0] = ids[1] = ids[2] = v;
    } else if (v == ids[0] || v == ids[2]) {
        ids[1] = v;
    } else {
        return Errno::eperm;
    }
    ids[3] = ids[1];
    if (&ids == &p.uids) fix_caps_after_uid_change(p, old);
    return Errno::ok;
}

// setfsuid / setfsgid: always returns the previous value, changes only
// when allowed.
[[nodiscard]] inline std::uint32_t set_fs(ProcInfo& p, std::array<std::uint32_t, 4>& ids, int cap,
                                          std::uint32_t v) {
    const std::uint32_t prev = ids[3];
    if (v == kKeep) return prev;   // -1 is no id: the kernel's way to read the current one
    if (capable(p, cap) || one_of(v, ids[0], ids[1], ids[2]) || v == ids[3]) {
        const auto old = p.uids;
        ids[3] = v;
        if (&ids == &p.uids) fix_caps_after_uid_change(p, old);
    }
    return prev;
}

// execve's transform (capabilities(7) "Transformation of capabilities
// during execve()"), with no file capabilities and the root special case.
// `set_uid`/`set_gid` are a set-user/group-ID file's owner, or kKeep.
inline void on_exec(ProcInfo& p, std::uint32_t set_uid, std::uint32_t set_gid) {
    if (p.no_new_privs) set_uid = set_gid = kKeep;
    if (set_uid != kKeep) p.uids[1] = set_uid;
    if (set_gid != kKeep) p.gids[1] = set_gid;
    p.uids[2] = p.uids[3] = p.uids[1];
    p.gids[2] = p.gids[3] = p.gids[1];
    const bool root = p.uids[0] == 0 || p.uids[1] == 0;
    // ambient only survives where it is also permitted and inheritable
    p.cap_amb &= p.cap_prm & p.cap_inh;
    if (root) {
        p.cap_prm = (p.cap_inh | p.cap_bnd) | p.cap_amb;
        p.cap_eff = p.uids[1] == 0 ? p.cap_prm : p.cap_amb;
    } else {
        p.cap_prm = p.cap_amb;
        p.cap_eff = p.cap_amb;
    }
    p.keepcaps = false;
}

// capset(2): the new sets must be within what the caller may grant itself.
[[nodiscard]] inline Errno capset(ProcInfo& p, std::uint64_t eff, std::uint64_t prm, std::uint64_t inh) {
    const std::uint64_t allowed_inh = capable(p, kCapSetpcap) ? (p.cap_inh | p.cap_bnd)
                                                              : (p.cap_inh | p.cap_prm);
    if ((inh & ~allowed_inh) != 0) return Errno::eperm;
    if ((prm & ~p.cap_prm) != 0) return Errno::eperm;
    if ((eff & ~prm) != 0) return Errno::eperm;
    p.cap_eff = eff;
    p.cap_prm = prm;
    p.cap_inh = inh;
    p.cap_amb &= prm & inh;
    return Errno::ok;
}

// The kernel's generic_permission: may `p` access a file with this mode,
// owner and group for `want` (a mask of 4 read, 2 write, 1 exec/search)?
[[nodiscard]] inline bool permitted(const ProcInfo& p, std::uint32_t mode, std::uint32_t uid,
                                    std::uint32_t gid, int want, bool is_dir,
                                    bool use_real_ids = false) {
    const std::uint32_t fsuid = use_real_ids ? p.uids[0] : p.uids[3];
    const std::uint32_t fsgid = use_real_ids ? p.gids[0] : p.gids[3];
    std::uint32_t bits;
    if (fsuid == uid) {
        bits = (mode >> 6) & 7;
    } else {
        bool in_group = fsgid == gid;
        for (std::uint32_t g : p.groups) in_group = in_group || g == gid;
        bits = in_group ? (mode >> 3) & 7 : mode & 7;
    }
    if ((bits & static_cast<std::uint32_t>(want)) == static_cast<std::uint32_t>(want)) return true;
    // the capability shortcut (access(2) checks the real uid's caps, which
    // for us are the same sets)
    const ProcInfo& c = p;
    if (is_dir) {
        if (!(want & 2) && capable(c, kCapDacReadSearch)) return true;
        return capable(c, kCapDacOverride);
    }
    if (want & 1) {   // exec: override only if some x bit is set
        if (!capable(c, kCapDacOverride) || (mode & 0111) == 0) return false;
        return true;
    }
    if (!(want & 2) && capable(c, kCapDacReadSearch)) return true;
    return capable(c, kCapDacOverride);
}

}  // namespace lx::abi::creds
