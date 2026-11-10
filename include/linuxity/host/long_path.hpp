// linuxity/host/long_path.hpp
//
// Host paths longer than PATH_MAX, walked one component at a time.
//
// An overlay layer's host path is the guest path PLUS a layer prefix, so a
// guest directory tree that is legal on Linux can be too deep for the host's
// open(2). Two copies of the same walk grew to handle that (open_long in the
// dispatcher, at_long_parent in the file namespace), each opening the
// intermediate directories with O_PATH -- which only Linux has. This is the
// one walk, and kWalkDirFlags is the one spelling of "a directory I only
// pass through": O_PATH on Linux, O_SEARCH (POSIX.1-2008, which Darwin has)
// elsewhere. Both open a directory that has search but not read permission,
// which a plain O_RDONLY would refuse.
#pragma once

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstddef>
#include <string>
#include <string_view>

#include <fcntl.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "linuxity/host/win_posix.hpp"

namespace lx::host {

#if defined(__linux__)
inline constexpr int kWalkDirFlags = O_PATH | O_DIRECTORY | O_CLOEXEC;
#elif defined(O_SEARCH)
inline constexpr int kWalkDirFlags = O_SEARCH | O_DIRECTORY | O_CLOEXEC;
#else
inline constexpr int kWalkDirFlags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
#endif

// Below this a single open(2) is fine: the host's own PATH_MAX (4096 on
// Linux, 1024 on Darwin -- which is why a guest tree that is merely deep on
// Linux is already too long for a Mac).
#if defined(PATH_MAX)
inline constexpr std::size_t kHostPathMax = PATH_MAX;
#else
inline constexpr std::size_t kHostPathMax = 260;   // Win32 MAX_PATH
#endif

// Run fn(dirfd, leaf) with dirfd open on the parent of `path`, reached a
// component at a time. Returns fn's answer, or false if the walk fails.
// errno is preserved from the failing step (or from fn) across the closes.
template <class F>
[[nodiscard]] bool at_long_parent(std::string_view path, F&& fn) {
#if defined(_WIN32)
    (void)path; (void)fn;
    return false;
#else
    while (path.size() > 1 && path.back() == '/') path.remove_suffix(1);
    const std::size_t cut = path.rfind('/');
    if (cut == std::string_view::npos || cut + 1 >= path.size()) return false;
    int fd = ::open("/", kWalkDirFlags);
    std::size_t i = 0;
    while (fd >= 0 && i < cut) {
        while (i < cut && path[i] == '/') ++i;
        if (i >= cut) break;
        const std::size_t j = std::min(path.find('/', i), cut);
        const std::string part{path.substr(i, j - i)};
        i = j;
        const int nfd = ::openat(fd, part.c_str(), kWalkDirFlags);
        const int e = errno;
        ::close(fd);
        fd = nfd;
        errno = e;
    }
    if (fd < 0) return false;
    const std::string leaf{path.substr(cut + 1)};
    const bool ok = fn(fd, leaf.c_str());
    const int e = errno;
    ::close(fd);
    errno = e;
    return ok;
#endif
}

// open(2) for a host path of any length. Returns an fd or -1 with errno set.
[[nodiscard]] inline int open_long(const std::string& path, int flags) {
    if (path.size() < kHostPathMax) return ::open(path.c_str(), flags);
#if defined(_WIN32)
    errno = ENAMETOOLONG;
    return -1;
#else
    int fd = -1;
    (void)at_long_parent(path, [&](int dfd, const char* leaf) {
        fd = ::openat(dfd, leaf, flags);
        return fd >= 0;
    });
    return fd;
#endif
}

}  // namespace lx::host
