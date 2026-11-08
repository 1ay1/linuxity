// Real network namespaces for the guest.
//
// linuxity keeps most namespaces in its own tables, but a network namespace
// it only pretends to make leaves the guest on the host's network. So where
// the host lets an unprivileged process make one (inside a user namespace of
// its own), the guest's task makes it for real. The tracer then writes
// identity id maps, so the task keeps its uid and gid and every file check
// stays the same.
#pragma once

#if defined(__linux__)
#include <fcntl.h>
#include <sched.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#endif

#include <cstdint>

namespace lx::host {

inline constexpr std::uint64_t kCloneNewnet = 0x40000000, kCloneNewuser = 0x10000000;

// The flags a task unshares (or clones with) to get a real netns: a user
// namespace too, unless the tracer is root.
[[nodiscard]] inline std::uint64_t real_netns_flags() noexcept {
#if defined(__linux__)
    return ::getuid() == 0 ? kCloneNewnet : (kCloneNewuser | kCloneNewnet);
#else
    return 0;
#endif
}

// Can a task of ours make one? Asked once, by trying it in a child.
[[nodiscard]] inline bool host_can_netns() {
#if defined(__linux__)
    static const bool yes = [] {
        const pid_t pid = ::fork();
        if (pid < 0) return false;
        if (pid == 0) ::_exit(::unshare(static_cast<int>(real_netns_flags())) == 0 ? 0 : 1);
        int st = 0;
        return ::waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0;
    }();
    return yes;
#else
    return false;
#endif
}

// Map the tracer's uid and gid to themselves in host task `tid`'s new user
// namespace. Only the parent namespace can write these, and the tracer is
// there. No-op when the tracer is root (no user namespace was made).
inline bool write_identity_maps(int tid) {
#if defined(__linux__)
    if (::getuid() == 0) return true;
    auto put = [&](const char* leaf, const char* body) {
        char path[64];
        std::snprintf(path, sizeof path, "/proc/%d/%s", tid, leaf);
        const int fd = ::open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0) return false;
        const auto n = static_cast<ssize_t>(std::strlen(body));
        const bool ok = ::write(fd, body, static_cast<std::size_t>(n)) == n;
        ::close(fd);
        return ok;
    };
    char u[32], g[32];
    std::snprintf(u, sizeof u, "%u %u 1\n", ::getuid(), ::getuid());
    std::snprintf(g, sizeof g, "%u %u 1\n", ::getgid(), ::getgid());
    // an unprivileged gid_map needs setgroups denied first; the guest's
    // setgroups is ours anyway
    (void)put("setgroups", "deny");
    return put("uid_map", u) && put("gid_map", g);
#else
    (void)tid;
    return false;
#endif
}

}  // namespace lx::host
