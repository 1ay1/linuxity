// linuxity/host/stat_fields.hpp
//
// A host `struct stat` -> abi::wire::StatFields, in one place.
//
// Three places filled StatFields from a host stat, field by field, and all
// three spelled the timestamps st_mtim/st_atim/st_ctim. That is the Linux
// (and POSIX.1-2008) name; Darwin calls the same fields st_mtimespec et al.
// and the Win32 CRT has only whole seconds. So every copy broke the macOS
// and Windows builds the same way, and each would have needed the same
// #ifdef. The translation is host policy over a host value -- like
// abi/wire/errno_map.hpp -- so it lives here once and the callers just ask.
//
// Timestamps keep nanosecond resolution where the host has it: truncating
// to seconds makes `make` see a just-written file as unchanged.
#pragma once

#include <cstdint>
#include <ctime>
#include <sys/stat.h>

#include "linuxity/abi/wire/stat.hpp"

namespace lx::host {

struct StatTimes {
    std::uint64_t atime_ns{0}, mtime_ns{0}, ctime_ns{0};
};

[[nodiscard]] inline StatTimes stat_times(const struct ::stat& st) noexcept {
#if defined(_WIN32)
    // The CRT keeps whole seconds only.
    auto s = [](std::time_t t) { return static_cast<std::uint64_t>(t) * 1'000'000'000ull; };
    return {s(st.st_atime), s(st.st_mtime), s(st.st_ctime)};
#else
    auto ns = [](const struct ::timespec& t) {
        return static_cast<std::uint64_t>(t.tv_sec) * 1'000'000'000ull +
               static_cast<std::uint64_t>(t.tv_nsec);
    };
#if defined(__APPLE__)
    return {ns(st.st_atimespec), ns(st.st_mtimespec), ns(st.st_ctimespec)};
#else
    return {ns(st.st_atim), ns(st.st_mtim), ns(st.st_ctim)};
#endif
#endif
}

// Every StatFields field, from the host's stat.
[[nodiscard]] inline abi::wire::StatFields stat_fields(const struct ::stat& st) noexcept {
    abi::wire::StatFields h;
    h.mode  = static_cast<std::uint32_t>(st.st_mode);
    h.dev   = static_cast<std::uint64_t>(st.st_dev);
    h.ino   = static_cast<std::uint64_t>(st.st_ino);
    // A Darwin directory's link count is 2 + EVERY entry, not Linux's 2 +
    // subdirectories; find(1) would trust it to skip leaf directories.
    // Report 1, Linux's "not counted" (btrfs, FUSE), which find knows.
#if defined(__APPLE__)
    h.nlink = S_ISDIR(st.st_mode) ? 1u : static_cast<std::uint64_t>(st.st_nlink);
#else
    h.nlink = static_cast<std::uint64_t>(st.st_nlink);
#endif
    h.rdev  = static_cast<std::uint64_t>(st.st_rdev);
    h.size  = static_cast<std::uint64_t>(st.st_size);
#if defined(_WIN32)
    // No st_blksize/st_blocks in the CRT: report what a 4 KiB-block
    // filesystem would, so `du` and `ls -s` stay plausible.
    h.blocks = static_cast<std::int64_t>((h.size + 4095) / 4096 * 8);
#else
    h.blksize = static_cast<std::int64_t>(st.st_blksize);
    h.blocks  = static_cast<std::int64_t>(st.st_blocks);
#endif
    const StatTimes t = stat_times(st);
    h.atime_ns = t.atime_ns;
    h.mtime_ns = t.mtime_ns;
    h.ctime_ns = t.ctime_ns;
    return h;
}

}  // namespace lx::host
