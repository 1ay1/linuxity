// linuxity/vfs/devfs.hpp
//
// A synthesized /dev — the devtmpfs the guest expects to find populated.
//
// Every real distro program assumes /dev/null, /dev/zero, /dev/urandom and
// friends exist and behave: a shell redirects to /dev/null, a package manager
// seeds a PRNG from /dev/urandom, a build tool writes to /dev/stderr. A bare
// extracted rootfs ships an EMPTY /dev (the real nodes are created at boot by
// the kernel's devtmpfs), so under linuxity those opens ENOENT and programs
// die early ("can't open '/dev/null'").
//
// The faithful, zero-emulation fix that matches linuxity's whole thesis:
// the character devices are REAL on the host, with exactly the semantics the
// guest wants (an endless sink, an endless zero source, a CSPRNG). So we don't
// re-implement them — we REDIRECT the guest's /dev/null to the host's real
// /dev/null (via VirtualFile::redirect_host). The guest gets a genuine host
// device fd: read()/write()/mmap() all work at native speed with true device
// behaviour, and the owner-scrub already presents it as root-owned.
//
// The pseudo-symlinks (/dev/stdin -> /proc/self/fd/0, /dev/fd -> /proc/self/fd)
// point back into OUR synthesized /proc, so they resolve inside the guest
// world. The directory listing unions the redirected nodes + the symlinks so
// `ls /dev` and getdents see a populated devtmpfs.
#pragma once

#include "linuxity/kernel/file_namespace.hpp"

#include <array>
#include <string>
#include <string_view>

namespace lx::vfs {

// Build a /dev producer. Character devices redirect to the host's real nodes;
// stdio/fd links resolve into the guest's /proc. The set is exactly what real
// userspace (busybox, musl/glibc, package managers, build tools) reaches for.
[[nodiscard]] inline kernel::FileNamespace::Producer make_devfs() {
    return [](std::string_view abs) -> Result<kernel::VirtualFile> {
        // The character devices we pass straight through to the host. Each is
        // a genuine host device node with the exact semantics the guest wants.
        static constexpr std::array<std::string_view, 7> kChar = {
            "null", "zero", "full", "random", "urandom", "tty", "ptmx",
        };
        // The pseudo-symlinks a POSIX /dev provides, pointing into /proc.
        // stdin/stdout/stderr must work when OPENED (a shell's `> /dev/stdout`
        // does open(2), not readlink), so they REDIRECT straight to the real
        // host fd path rather than presenting as symlinks. /dev/fd is a
        // directory link, kept as a symlink.
        struct Node { std::string_view name, target; bool is_link; };
        static constexpr std::array<Node, 4> kLinks = {{
            {"stdin",  "/proc/self/fd/0", false},
            {"stdout", "/proc/self/fd/1", false},
            {"stderr", "/proc/self/fd/2", false},
            {"fd",     "/proc/self/fd",   true},
        }};

        // /dev itself: the union of redirected nodes + symlinks.
        if (abs == "/dev") {
            kernel::VirtualFile vf;
            vf.is_dir = true;
            for (auto n : kChar) vf.entries.push_back({std::string{n}, false});
            for (auto& l : kLinks) vf.entries.push_back({std::string{l.name}, false});
            // Common subdirs programs probe; empty is fine (getdents enumerates
            // nothing, but the dir exists so opendir/stat succeed).
            vf.entries.push_back({"shm", true});
            vf.entries.push_back({"pts", true});
            return ok(std::move(vf));
        }

        // /dev/fd/N (bash process substitution `<(...)` opens /dev/fd/63):
        // /dev/fd is a symlink to /proc/self/fd, but a path WITH a trailing
        // component (/dev/fd/63) arrives here whole rather than being resolved
        // through the symlink. Redirect the descriptor path straight to the
        // guest's real host fd via /proc/self/fd/N.
        if (abs.starts_with("/dev/fd/")) {
            kernel::VirtualFile vf;
            vf.redirect_host =
                std::string{"/proc/self/fd/"} +
                std::string{abs.substr(std::string_view{"/dev/fd/"}.size())};
            return ok(std::move(vf));
        }

        std::string_view leaf = abs;
        leaf.remove_prefix(std::string_view{"/dev/"}.size());

        // A redirected character device: hand back the real host node so the
        // guest opens the TRUE device (native sink/source/CSPRNG semantics).
        for (auto n : kChar) {
            if (leaf == n) {
                kernel::VirtualFile vf;
                vf.redirect_host = std::string{"/dev/"} + std::string{n};
                return ok(std::move(vf));
            }
        }

        // A pseudo-symlink / redirect into /proc.
        for (auto& l : kLinks) {
            if (leaf == l.name) {
                kernel::VirtualFile vf;
                if (l.is_link) vf.symlink_target = std::string{l.target};
                else           vf.redirect_host  = std::string{l.target};
                return ok(std::move(vf));
            }
        }

        // Subdirectories (empty, but real).
        if (leaf == "shm" || leaf == "pts") {
            kernel::VirtualFile vf; vf.is_dir = true;
            return ok(std::move(vf));
        }

        return err<kernel::VirtualFile>(Errno::enoent);
    };
}

} // namespace lx::vfs
