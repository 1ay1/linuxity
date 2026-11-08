// Landlock rule sets kept by linuxity, for hosts whose kernel has none.
//
// The guest builds a rule set, adds "this path, these accesses" rules, and
// restricts itself. Each restriction stacks a layer; an access is allowed
// only if every layer allows it (fs/landlock in the kernel works the same
// way). The dispatcher asks `allows` before it lets a path call through.
//
// Rules are keyed by guest path. The kernel keys them by inode, so a rule on
// a directory still covers it after a rename; linuxity's guest paths are
// stable for the life of a run, which is the case that matters here.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lx::kernel {

namespace landlock {

// The access bits, as in <linux/landlock.h>.
inline constexpr std::uint64_t kExecute = 1ull << 0, kWriteFile = 1ull << 1, kReadFile = 1ull << 2,
                               kReadDir = 1ull << 3, kRemoveDir = 1ull << 4, kRemoveFile = 1ull << 5,
                               kMakeChar = 1ull << 6, kMakeDir = 1ull << 7, kMakeReg = 1ull << 8,
                               kMakeSock = 1ull << 9, kMakeFifo = 1ull << 10, kMakeBlock = 1ull << 11,
                               kMakeSym = 1ull << 12, kRefer = 1ull << 13, kTruncate = 1ull << 14,
                               kIoctlDev = 1ull << 15;
// Everything up to ABI 5. We report ABI 5 and accept exactly these.
inline constexpr std::uint64_t kAllFs = (1ull << 16) - 1;
inline constexpr std::uint64_t kBindTcp = 1ull << 0, kConnectTcp = 1ull << 1;
inline constexpr std::uint64_t kAllNet = kBindTcp | kConnectTcp;
inline constexpr std::uint64_t kScopeAbstractUnix = 1ull << 0, kScopeSignal = 1ull << 1;
inline constexpr std::uint64_t kAllScope = kScopeAbstractUnix | kScopeSignal;
inline constexpr int kAbi = 6;
// Rights that only make sense on a directory: a rule on a file can't hold them.
inline constexpr std::uint64_t kDirOnly = kReadDir | kRemoveDir | kRemoveFile | kMakeChar | kMakeDir |
                                          kMakeReg | kMakeSock | kMakeFifo | kMakeBlock | kMakeSym |
                                          kRefer;

struct PathRule { std::string path; std::uint64_t access; };
struct PortRule { std::uint64_t port; std::uint64_t access; };

// What the guest built with landlock_create_ruleset and add_rule.
struct Ruleset {
    std::uint64_t handled_fs{0}, handled_net{0}, scoped{0};
    std::vector<PathRule> paths;
    std::vector<PortRule> ports;
};

// One restriction, frozen when landlock_restrict_self ran.
struct Layer {
    Ruleset rules;
    std::uint64_t domain_id;   // which restriction made it, for scoping
};

// A process's stack of layers. Shared, copy-on-restrict: a fork shares its
// parent's domain, a new restriction makes a new one.
using Domain = std::shared_ptr<const std::vector<Layer>>;

[[nodiscard]] inline bool under(std::string_view p, std::string_view dir) noexcept {
    if (dir == "/") return true;
    return p.starts_with(dir) && (p.size() == dir.size() || p[dir.size()] == '/');
}

// May `want` happen on guest path `path` under `d`? `path` must be absolute,
// normalized and with symlinks resolved (the kernel checks the object, not a
// name for it). Only the first `upto` layers count: a file keeps the rights
// it was opened with, so one opened before a restriction isn't judged by it.
[[nodiscard]] inline bool allows(const Domain& d, std::string_view path, std::uint64_t want,
                                 std::size_t upto = ~std::size_t{0}) {
    if (!d || want == 0) return true;
    std::size_t n = 0;
    for (const Layer& l : *d) {
        if (n++ >= upto) break;
        const std::uint64_t handled = l.rules.handled_fs | kRefer;   // REFER is always handled
        std::uint64_t need = want & handled;
        if (need == 0) continue;
        // the rules beneath this path grant the union of their accesses
        std::uint64_t granted = 0;
        for (const PathRule& r : l.rules.paths)
            if (under(path, r.path)) granted |= r.access;
        if ((need & ~granted) != 0) return false;
    }
    return true;
}

// Device ioctls IOCTL_DEV never covers, as in fs/landlock: they act on the
// open file or the filesystem, not the device.
[[nodiscard]] inline bool ioctl_always_ok(std::uint32_t cmd) {
    switch (cmd) {
        case 0x5451: case 0x5450:        // FIOCLEX, FIONCLEX
        case 0x5421: case 0x5452:        // FIONBIO, FIOASYNC
        case 0x5460:                     // FIOQSIZE
        case 0xC0045877: case 0xC0045878:  // FIFREEZE, FITHAW
        case 0xC020660B:                 // FS_IOC_FIEMAP
        case 2:                          // FIGETBSZ
        case 0x40049409: case 0x4020940D: case 0xC0189436:  // FICLONE, FICLONERANGE, FIDEDUPERANGE
        case 0x81111500: case 0x80811501:  // FS_IOC_GETFSUUID, FS_IOC_GETFSSYSFSPATH
            return true;
        default:
            return false;
    }
}

// May a TCP bind/connect on `port` happen? `want` is kBindTcp or kConnectTcp.
[[nodiscard]] inline bool allows_port(const Domain& d, std::uint64_t port, std::uint64_t want) {
    if (!d) return true;
    for (const Layer& l : *d) {
        if ((l.rules.handled_net & want) == 0) continue;
        bool ok = false;
        for (const PortRule& r : l.rules.ports)
            if (r.port == port && (r.access & want)) { ok = true; break; }
        if (!ok) return false;
    }
    return true;
}

// Does any layer scope `what` (signals, abstract unix sockets)?
[[nodiscard]] inline bool scopes(const Domain& d, std::uint64_t what) {
    if (!d) return false;
    for (const Layer& l : *d)
        if (l.rules.scoped & what) return true;
    return false;
}

// Is domain `inner` the same as or nested inside `outer`? A scoped process
// may only reach processes in its own domain or one nested inside it.
[[nodiscard]] inline bool within(const Domain& inner, const Domain& outer) {
    if (!outer || outer->empty()) return true;   // outer is unrestricted: everyone is inside
    if (!inner || inner->size() < outer->size()) return false;
    return (*inner)[outer->size() - 1].domain_id == outer->back().domain_id;
}

}  // namespace landlock

}  // namespace lx::kernel
