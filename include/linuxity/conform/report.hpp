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

    return v;
}

} // namespace lx::conform
