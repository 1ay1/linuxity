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
#include "linuxity/vfs/pty_names.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <string_view>

namespace lx::vfs {

// Build a /dev producer. Character devices redirect to the host's real nodes;
// stdio/fd links resolve into the guest's /proc. The set is exactly what real
// userspace (busybox, musl/glibc, package managers, build tools) reaches for.
//
// `ctty` answers "which pty slave is the calling guest's controlling
// terminal" (-1 = none). /dev/tty MUST go through it rather than redirecting
// to the host's /dev/tty: the host's controlling terminal is linuxity's, not
// the guest's, and under adb or any daemon the host has none at all -- so the
// redirect answered ENXIO for a guest that was sitting on a perfectly good
// pty. Left null, /dev/tty falls back to the host node, which is right for
// the simple case where the guest inherited the host's own terminal.
[[nodiscard]] inline kernel::FileNamespace::Producer make_devfs(
    std::function<int()> ctty = nullptr,
    std::string shm_dir = "/dev/shm") {
    return [ctty = std::move(ctty), shm = std::move(shm_dir)]
           (std::string_view abs) -> Result<kernel::VirtualFile> {
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

        // /dev/tty -- "my controlling terminal", by name.
        //
        // Resolve it to the slave the guest actually claimed, because the
        // host's /dev/tty is a DIFFERENT terminal (linuxity's) or none at
        // all. With no ctty the kernel's answer is ENXIO, and that is what a
        // daemon after setsid expects to see.
        if (leaf == "tty" && ctty) {
            const int n = ctty();
            if (n < 0) return err<kernel::VirtualFile>(Errno::enxio);
            kernel::VirtualFile vf;
            vf.redirect_host = pty_slave_path(n);
            return ok(std::move(vf));
        }

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

        // /dev/pts/N -> the host's name for that slave, which is NOT
        // universal (vfs/pty_names.hpp: identity on Linux/Android,
        // /dev/ttysNNN on Darwin). Every guest-created pty -- tmux, script,
        // expect, python pty, ssh -- opens its slave here, and so does a
        // guest that simply INHERITED the terminal it was launched from.
        if (abs.starts_with("/dev/pts/")) {
            const std::string_view n = abs.substr(std::string_view{"/dev/pts/"}.size());
            if (n.empty() || n.find_first_not_of("0123456789") != std::string_view::npos)
                return err<kernel::VirtualFile>(Errno::enoent);
            kernel::VirtualFile vf;
            vf.redirect_host = pty_slave_path(std::atoi(std::string{n}.c_str()));
            return ok(std::move(vf));
        }

        // /dev/shm/NAME -> the same name on the host's tmpfs. The producer is
        // called with the FULL path, so children need their own arm (as
        // /dev/pts/N does above): redirecting only the directory let stat see
        // the right mode while every create still failed ENOENT.
        if (abs.starts_with("/dev/shm/")) {
            const std::string_view n = abs.substr(std::string_view{"/dev/shm/"}.size());
            // No traversal out of the directory, and no nested paths: POSIX
            // shm names are a single component by definition.
            if (n.empty() || n.find('/') != std::string_view::npos ||
                n == "." || n == "..")
                return err<kernel::VirtualFile>(Errno::enoent);
            kernel::VirtualFile vf;
            vf.redirect_host = shm + "/" + std::string{n};
            return ok(std::move(vf));
        }

        // /dev/shm must be WRITABLE: it is the backing store for POSIX shared
        // memory (shm_open), which glibc, LTP and anything using sem_open or
        // shm_open depends on. It used to be a synthesized empty directory
        // with no storage behind it, so every create in it failed ENOENT --
        // LTP's whole suite TBROK'd on open(/dev/shm/...) before running a
        // single assertion.
        //
        // The host's own /dev/shm when it has one. Android does NOT -- it
        // uses ashmem/memfd and ships no shm tmpfs at all -- so main.cpp
        // hands us a directory it made instead. Without that,
        // multiprocessing.Queue and every ProcessPoolExecutor died with
        // FileNotFoundError from sem_open.
        if (leaf == "shm") {
            kernel::VirtualFile vf;
            vf.is_dir = true;
            vf.redirect_host = shm;
            return ok(std::move(vf));
        }

        // /dev/pts stays synthesized: a pty allocation goes through ptmx,
        // which is handled above, and handing the guest the host's pts tree
        // would let it reach terminals outside its namespace.
        if (leaf == "pts") {
            kernel::VirtualFile vf; vf.is_dir = true;
            return ok(std::move(vf));
        }

        return err<kernel::VirtualFile>(Errno::enoent);
    };
}

} // namespace lx::vfs
