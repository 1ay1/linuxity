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

}  // namespace lx::vfs

#endif  // LX_VFS_PTY_NAMES_HPP
