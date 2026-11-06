// SPDX-License-Identifier: LGPL-2.0-or-later
//
// What the host calls a pty slave.
//
// The guest always says /dev/pts/N -- that is the Linux ABI and the whole
// point of the runtime. The HOST's name for the same device is not
// universal: Linux and Android use /dev/pts/N too, Darwin uses /dev/ttysNNN.
//
// devfs.hpp used to hardcode the Darwin spelling, so on Linux a guest that
// inherited a real terminal resolved /dev/pts/0 to a nonexistent
// /dev/ttys000. isatty() said no, bash's readline turned line editing off,
// and the arrow keys arrived as literal ^[[A instead of recalling history.
// Invisible unless you actually attach a terminal, which the live tests did
// not.
#ifndef LX_VFS_PTY_NAMES_HPP
#define LX_VFS_PTY_NAMES_HPP

#include <cstdio>
#include <string>
#include <string_view>

namespace lx::vfs {

// The host path for pty slave number `n`.
//
// One function, consulted by every arm that resolves a slave, so a host with
// yet another convention is a single edit and there is no second spelling to
// miss.
[[nodiscard]] inline std::string pty_slave_path(int n) {
    char buf[32];
#if defined(__APPLE__)
    // Darwin: /dev/ttys000, /dev/ttys001, ... zero-padded to three digits.
    std::snprintf(buf, sizeof buf, "/dev/ttys%03d", n);
#else
    // Linux and Android: the devpts mount uses the guest's own spelling, so
    // this is an identity mapping -- which is exactly why getting it wrong
    // was invisible on the host that needed no translation at all.
    std::snprintf(buf, sizeof buf, "/dev/pts/%d", n);
#endif
    return buf;
}

// The slave NUMBER behind a host path, or -1 if it is not a pty slave.
//
// The inverse of pty_slave_path, and it lives next to it so a host with its
// own spelling is still a single edit. Needed to identify an fd we never saw
// opened: /proc/<pid>/fd/<n> gives the host's name, and this turns it back
// into the number the guest's ctty bookkeeping is keyed on.
[[nodiscard]] inline int pty_slave_number(std::string_view host_path) {
#if defined(__APPLE__)
    constexpr std::string_view kPre = "/dev/ttys";
#else
    constexpr std::string_view kPre = "/dev/pts/";
#endif
    if (!host_path.starts_with(kPre)) return -1;
    const std::string_view n = host_path.substr(kPre.size());
    if (n.empty() || n.find_first_not_of("0123456789") != std::string_view::npos)
        return -1;
    int v = 0;
    for (char c : n) v = v * 10 + (c - '0');
    return v;
}

}  // namespace lx::vfs

#endif  // LX_VFS_PTY_NAMES_HPP
