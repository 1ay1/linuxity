// linuxity/conform/report.hpp
//
// Rendering for conformance results, and the scenario registry.
//
// Header-only with `inline`, because linuxity_core is an INTERFACE (header-
// only) target and this must stay usable on all four hosts without adding a
// compiled library to the portable test set.
#pragma once

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include "linuxity/conform/observation.hpp"
#include "linuxity/conform/oracle.hpp"
#include "linuxity/conform/scenario.hpp"

namespace lx::conform {

namespace detail {

// errno -> name, for reports. Unlisted values render as a number, which is
// still unambiguous; this is presentation, never comparison.
[[nodiscard]] inline const char* errno_name(std::int32_t e) noexcept {
    switch (e) {
        case EPERM:   return "EPERM";
        case ENOENT:  return "ENOENT";
        case EBADF:   return "EBADF";
        case EACCES:  return "EACCES";
        case EEXIST:  return "EEXIST";
        case ENOTDIR: return "ENOTDIR";
        case EISDIR:  return "EISDIR";
        case EINVAL:  return "EINVAL";
        case ENOSYS:  return "ENOSYS";
        case ERANGE:  return "ERANGE";
        case ESPIPE:  return "ESPIPE";
        case ELOOP:   return "ELOOP";
        default:      return nullptr;
    }
}

} // namespace detail

inline std::string Returned::describe() const {
    return match(
        [](std::int64_t v) { return std::to_string(v); },
        [](std::int32_t e) {
            const char* n = detail::errno_name(e);
            return n ? std::string{"-"} + n
                     : std::string{"-errno("} + std::to_string(e) + ")";
        });
}

inline std::string render_buffers(std::span<const Written> bufs) {
    if (bufs.empty()) return "(wrote nothing)";

    std::string out;
    for (const Written& w : bufs) {
        out += "arg" + std::to_string(w.arg) + "[" +
               std::to_string(w.bytes.size()) + "B]=";
        // A short hex prefix: enough to see WHICH bytes differ without
        // dumping kilobytes into a failure message.
        constexpr std::size_t preview = 16;
        const std::size_t n = std::min(preview, w.bytes.size());
        for (std::size_t i = 0; i < n; ++i) {
            char hex[4] = {};
            std::snprintf(hex, sizeof hex, "%02x ",
                          static_cast<unsigned>(
                              static_cast<unsigned char>(w.bytes[i])));
            out += hex;
        }
        if (w.bytes.size() > n) out += "...";
        out += "; ";
    }
    return out;
}

inline std::string Divergence::describe() const {
    std::string s = "step " + std::to_string(index);
    if (!note.empty()) s += " (" + note + ")";
    s += ": ";
    s += field_name(field);
    s += " differs\n";
    s += "    native: " + native + "\n";
    s += "    guest:  " + guest;
    return s;
}

inline std::string Unavailable::describe() const {
    std::string s{cause_name(cause)};
    if (!this->detail.empty()) s += ": " + this->detail;
    return s;
}

inline std::string Scenario::key() const {
    std::string k{name};
    for (const std::string& a : args) {
        k += '_';
        // Keep the key filesystem-safe: a scenario arg is usually a path.
        for (const char c : a) k += (c == '/' || c == '.') ? '-' : c;
    }
    return k;
}

// -- the registry ----------------------------------------------------------
//
// THE single place conformance scenarios are declared. A case added here runs
// under linuxity on all four hosts, natively on the Linux hosts, and against
// the recorded golden on macOS/Windows, with no other edit.
[[nodiscard]] inline std::vector<Scenario> all_scenarios() {
    std::vector<Scenario> v;

    // Directory seek/cookie behaviour, per flavour. The flavours are the whole
    // point: the lseek-cookie bug was invisible on host_backed (which forwards
    // to the real kernel) and appeared only on virtualised.
    v.push_back(Scenario{"dirseek-host", "dirseek"}
                    .with("/usr/bin")
                    .exercising(abi::Sysno::getdents64)
                    .exercising(abi::Sysno::lseek)
                    .on(DirFlavour::host_backed));

    v.push_back(Scenario{"dirseek-proc", "dirseek"}
                    .with("/proc")
                    .exercising(abi::Sysno::getdents64)
                    .exercising(abi::Sysno::lseek)
                    .on(DirFlavour::virtualised));

    v.push_back(Scenario{"dirseek-sys", "dirseek"}
                    .with("/sys")
                    .exercising(abi::Sysno::getdents64)
                    .exercising(abi::Sysno::lseek)
                    .on(DirFlavour::virtualised));

    // stat/access/statx/readlink across realms, with the error paths that
    // matter: empty path (ENOENT), trailing slash on a file (ENOTDIR),
    // file-as-directory (ENOTDIR), and /proc/self as a real symlink. All four
    // were divergent before the differential harness found them.
    v.push_back(Scenario{"statpaths", "statpaths"}
                    .exercising(abi::Sysno::newfstatat)
                    .exercising(abi::Sysno::faccessat)
                    .exercising(abi::Sysno::statx)
                    .exercising(abi::Sysno::readlinkat)
                    .exercising(abi::Sysno::fstat)
                    .on(DirFlavour::virtualised));

    // fd lifecycle: dup/dup2/dup3, fcntl, and the EBADF boundaries. This is
    // where linuxity keeps its own table alongside the host's real fds, so a
    // drift between the two surfaces as a wrong errno -- a bad dirfd with a
    // relative path was ENOENT instead of EBADF.
    v.push_back(Scenario{"fdops", "fdops"}
                    .exercising(abi::Sysno::dup)
                    .exercising(abi::Sysno::dup2)
                    .exercising(abi::Sysno::dup3)
                    .exercising(abi::Sysno::fcntl)
                    .exercising(abi::Sysno::close)
                    .exercising(abi::Sysno::openat)
                    .exercising(abi::Sysno::read)
                    .on(DirFlavour::host_backed));

    // read/write/pread/readv/lseek on a regular file. Most of these FORWARD
    // on Linux, which is the point: this pins that the forwarding path keeps
    // offsets, short reads and errnos exact, and catches it if someone later
    // decides to intercept one. Buffer CONTENT is compared here (unlike a
    // directory listing) because a file this probe wrote is deterministic.
    v.push_back(Scenario{"rwio", "rwio"}
                    .exercising(abi::Sysno::read)
                    .exercising(abi::Sysno::write)
                    .exercising(abi::Sysno::pread64)
                    .exercising(abi::Sysno::pwrite64)
                    .exercising(abi::Sysno::readv)
                    .exercising(abi::Sysno::writev)
                    .exercising(abi::Sysno::ftruncate)
                    .exercising(abi::Sysno::unlinkat)
                    .on(DirFlavour::host_backed));

    // Process identity and the /proc views of it. linuxity SYNTHESIZES almost
    // all of this -- fake pid 1, own pid namespace, procfs built from its own
    // process table -- so interception is near-total and the risk is highest.
    // The pid VALUE is exempt (the guest is 1, a native run is not), so this
    // asserts invariants instead: tid == pid for a thread-group leader, and
    // /proc/self/status agreeing with the syscalls. The tid invariant is what
    // caught gettid returning the raw host tid.
    v.push_back(Scenario{"procid", "procid"}
                    .exercising(abi::Sysno::getpid)
                    .exercising(abi::Sysno::gettid)
                    .exercising(abi::Sysno::getppid)
                    .exercising(abi::Sysno::getuid)
                    .exercising(abi::Sysno::getgid)
                    .exercising(abi::Sysno::uname)
                    .exercising(abi::Sysno::prlimit64)
                    .exercising(abi::Sysno::sched_getaffinity)
                    .exercising(abi::Sysno::kill)
                    .on(DirFlavour::virtualised));

    // Filesystem MUTATION through the overlay. Every write has to land in the
    // UPPER layer, copying up from the read-only lower first, and that
    // machinery (classify for_write, WriteIntent, whiteouts) is linuxity's own
    // code. It is where a wrong errno or a write to the wrong layer hides:
    // mkdir was behaving like `mkdir -p`, and chmod on a missing file reported
    // success. Both found here.
    v.push_back(Scenario{"fsmutate", "fsmutate"}
                    .exercising(abi::Sysno::mkdirat)
                    .exercising(abi::Sysno::linkat)
                    .exercising(abi::Sysno::symlinkat)
                    .exercising(abi::Sysno::renameat)
                    .exercising(abi::Sysno::fchmodat)
                    .exercising(abi::Sysno::fchownat)
                    .exercising(abi::Sysno::truncate)
                    .exercising(abi::Sysno::utimensat)
                    .on(DirFlavour::host_backed));

    return v;
}

} // namespace lx::conform
