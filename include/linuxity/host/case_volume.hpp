// linuxity/host/case_volume.hpp
//
// Linux trees need a CASE-SENSITIVE filesystem. A Mac's is case-insensitive
// by default, so `_exit.2` and `_Exit.2`, `xt_connmark.h` and
// `xt_CONNMARK.h` -- or a guest's `A` and `a` -- were one file: dpkg failed
// installing manpages-dev and linux-libc-dev ("unable to open
// ...dpkg-new: No such file or directory"), and anything else silently
// overwrote its twin.
//
// So on such a host the environments live on a case-sensitive APFS volume:
// a sparse bundle beside the directory, created on first use, attached
// (invisible to Finder) at the directory itself whenever it isn't. No root
// is needed. A directory that is already case-sensitive (a mounted volume,
// a case-sensitive disk, every Linux filesystem) is left alone, so the
// whole cost on later runs is one pathconf(2).
#pragma once

#include <string>

#if defined(__APPLE__)
#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "linuxity/host/environ.hpp"
#endif

namespace lx::host {

// Is `dir` (or, if it doesn't exist, its parent) case-sensitive?
[[nodiscard]] inline bool case_sensitive(const std::string& dir) {
#if defined(__APPLE__) && defined(_PC_CASE_SENSITIVE)
    std::string d = dir;
    for (;;) {
        const long v = ::pathconf(d.c_str(), _PC_CASE_SENSITIVE);
        if (v >= 0) return v == 1;
        const auto cut = d.find_last_of('/');
        if (errno != ENOENT || cut == std::string::npos || cut == 0) return true;   // unknown: assume fine
        d.resize(cut);
    }
#else
    (void)dir;
    return true;
#endif
}

#if defined(__APPLE__)
namespace detail {
inline int run_tool(std::vector<std::string> argv, bool quiet = true) {
    std::vector<char*> av;
    for (auto& a : argv) av.push_back(a.data());
    av.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    ::posix_spawn_file_actions_init(&fa);
    if (quiet) {
        ::posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        ::posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    }
    ::pid_t pid = -1;
    const int rc = ::posix_spawnp(&pid, av[0], &fa, nullptr, av.data(), host_environ());
    ::posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) return -1;
    int st = 0;
    while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
inline bool is_empty_dir(const std::string& d) {
    // our own listing: no <dirent> dependency on the hot path
    return run_tool({"/bin/sh", "-c", "[ -z \"$(ls -A \"$1\" 2>/dev/null)\" ]", "sh", d}) == 0;
}
// Is another linuxity running (a session that may have environments open)?
// Moving its files out from under it would delete them mid-use.
inline bool other_linuxity_running() {
    const std::string me = std::to_string(::getpid()), parent = std::to_string(::getppid());
    return run_tool({"/bin/sh", "-c",
                     "pgrep -x linuxity | grep -vx -e \"$1\" -e \"$2\" | grep -q .",
                     "sh", me, parent}) == 0;
}
}  // namespace detail
#endif

// Make `dir` case-sensitive, backed by `image` (a sparse bundle) where the
// host's own filesystem isn't. What `dir` already holds is moved onto the
// volume the first time. Returns false (with `why`) if that wasn't possible;
// the caller then carries on case-insensitively, as before.
[[nodiscard]] inline bool ensure_case_sensitive(const std::string& dir, const std::string& image,
                                                std::string& why, bool announce = true) {
#if defined(__APPLE__)
    if (case_sensitive(dir)) return true;
    auto attach = [&](const std::string& at) {
        return detail::run_tool({"hdiutil", "attach", "-quiet", "-nobrowse", "-owners", "on",
                                 "-mountpoint", at, image}) == 0;
    };
    struct ::stat st{};
    const bool have_image = ::stat(image.c_str(), &st) == 0;
    (void)::mkdir(dir.c_str(), 0755);
    // Anything in `dir` (environments from before, or an interrupted move)
    // must be MOVED onto the volume -- never hidden by mounting over it.
    const bool needs_move = !detail::is_empty_dir(dir);
    if (needs_move && detail::other_linuxity_running()) {
        why = "environments need moving onto case-sensitive storage, but another linuxity "
              "is running; close it and run linuxity again";
        return false;
    }
    if (!have_image) {
        if (announce)
            std::fputs("linuxity: setting up case-sensitive storage for environments "
                       "(Linux needs it; once)\n", stderr);
        if (detail::run_tool({"hdiutil", "create", "-quiet", "-type", "SPARSEBUNDLE",
                              "-fs", "Case-sensitive APFS", "-size", "4t", "-volname", "linuxity",
                              image}) != 0) {
            why = "hdiutil could not create " + image;
            return false;
        }
    }
    if (needs_move) {
        // Copy onto the volume mounted aside, then swap. The originals stay
        // until the copy is complete; an interrupted move just resumes here
        // (ditto merges into what was already copied).
        const std::string stage = dir + ".moving";
        const std::string old = dir + ".case-insensitive";
        (void)detail::run_tool({"hdiutil", "detach", "-quiet", "-force", stage});   // a stale one
        (void)::mkdir(stage.c_str(), 0755);
        if (announce)
            std::fputs("linuxity: moving your environments onto it (one time)...\n", stderr);
        if (!attach(stage) ||
            // tar, not ditto: ditto OPENS a FIFO to copy it and blocks forever
            // waiting for a writer (fish leaves one in the guest's /tmp, and
            // the move hung right there). tar archives it as a FIFO entry,
            // keeps hardlinks, modes and xattrs, and overwrites a partial copy.
            detail::run_tool({"/bin/sh", "-c",
                              "/usr/bin/tar -C \"$1\" -cf - . | /usr/bin/tar -C \"$2\" -xpf -",
                              "sh", dir, stage}) != 0 ||
            detail::run_tool({"hdiutil", "detach", "-quiet", stage}) != 0 ||
            ::rename(dir.c_str(), old.c_str()) != 0) {
            (void)detail::run_tool({"hdiutil", "detach", "-quiet", "-force", stage});
            why = "could not move " + dir + " onto the case-sensitive volume";
            return false;
        }
        (void)::rmdir(stage.c_str());
        (void)::mkdir(dir.c_str(), 0755);
        if (!attach(dir)) { (void)::rmdir(dir.c_str()); (void)::rename(old.c_str(), dir.c_str()); why = "hdiutil attach failed"; return false; }
        (void)detail::run_tool({"/bin/rm", "-rf", old});
        if (announce)
            std::fputs("linuxity: done. Packages installed before may have lost files whose names\n"
                       "          differ only in case; reinstall them if something is missing\n"
                       "          (apt install --reinstall PKG).\n", stderr);
        return case_sensitive(dir);
    }
    if (!attach(dir) && !case_sensitive(dir)) {   // (another linuxity may have just attached it)
        why = "hdiutil could not attach " + image;
        return false;
    }
    return case_sensitive(dir);
#else
    (void)dir; (void)image; (void)why; (void)announce;
    return true;
#endif
}

}  // namespace lx::host
