// linuxity/host/fd_link.hpp
//
// An open host fd's path, and giving an open fd a new name -- the two host
// questions behind linkat(fd, "", AT_EMPTY_PATH) and the O_TMPFILE idiom
// (open unnamed, write, then link into place: apk, systemd, python).
//
// Both were spelled with /proc/self/fd/N, which only Linux has. On a Mac
// that link failed ENOENT, so `apk update` could never install an index and
// every fresh Alpine environment answered "no such package".
#pragma once

#include <cerrno>
#include <climits>
#include <cstdio>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace lx::host {

// The host path `fd` refers to, or "" (unnamed, or the host can't say).
[[nodiscard]] inline std::string fd_path(int fd) {
#if defined(F_GETPATH)
    char p[PATH_MAX];
    return ::fcntl(fd, F_GETPATH, p) == 0 ? std::string{p} : std::string{};
#elif defined(__linux__)
    char link[64], tgt[PATH_MAX];
    std::snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    const ::ssize_t n = ::readlink(link, tgt, sizeof tgt - 1);
    return n > 0 ? std::string(tgt, static_cast<std::size_t>(n)) : std::string{};
#else
    (void)fd;
    return {};
#endif
}

// Make `dst` a hard link to the file open on `fd`. Returns 0 or an errno.
// ENOENT for a file with no name at all (an O_TMPFILE where the host can't
// link one): the caller copies it into place instead.
[[nodiscard]] inline int link_fd(int fd, const std::string& dst) {
#if defined(__linux__)
    char self[64];
    std::snprintf(self, sizeof self, "/proc/self/fd/%d", fd);
    return ::linkat(AT_FDCWD, self, AT_FDCWD, dst.c_str(), AT_SYMLINK_FOLLOW) == 0 ? 0 : errno;
#else
    struct ::stat st{};
    if (::fstat(fd, &st) != 0) return errno;
    if (st.st_nlink == 0) return ENOENT;              // unnamed: nothing to link to
    const std::string src = fd_path(fd);
    if (src.empty()) return ENOENT;
    return ::link(src.c_str(), dst.c_str()) == 0 ? 0 : errno;
#endif
}

}  // namespace lx::host
