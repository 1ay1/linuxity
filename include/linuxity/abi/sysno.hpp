// linuxity/abi/sysno.hpp
//
// Canonical syscall identity, and per-architecture number tables.
//
// A syscall NUMBER is arch-specific: write(2) is 1 on x86-64 but 64 on
// aarch64; exit is 60 vs 93. But the OPERATION is the same. So we decode the
// raw, arch-specific number into a canonical `Sysno` once, at the trap
// boundary, and the dispatcher switches on the canonical identity — arch
// -neutral, written a single time.
//
// This is the seam that lets "run the native distro" mean: the guest's ISA
// equals the host's ISA, we read that arch's number table, and everything
// above decode is identical.
#pragma once

#include <cstdint>

namespace lx::abi {

// The host/guest instruction set (they are equal in the native-speed model).
enum class Arch { x86_64, aarch64 };

// Canonical, arch-independent syscall identities. Extend as subsystems grow.
enum class Sysno {
    unknown,
    read, write, open, openat, close,
    mmap, munmap, mprotect, brk,
    getpid, gettid, clone, fork, vfork, execve, execveat, wait4,
    kill, tgkill, tkill, exit, exit_group,
    uname, arch_prctl, set_tid_address, ioctl, writev, readv,
    rt_sigaction, rt_sigprocmask, getuid, geteuid, getgid, getegid,
    // The RESolved-uid queries bash/sudo use at startup to fill $UID/$EUID.
    // These MUST answer 0 like getuid/geteuid, or the guest believes it's the
    // host uid (no /etc/passwd match -> bash prints "I have no name!").
    getresuid, getresgid,
    // File metadata & directory path family (virtualized through the VFS).
    stat, lstat, fstat, newfstatat, statx, lseek, pread64, pwrite64,
    getdents64, readlink, readlinkat, getcwd, chdir, fchdir,
    access, faccessat, faccessat2, dup, dup2, dup3, fcntl,
    // The modern openat replacement (glibc/systemd/newer toolchains prefer
    // it). Its flags live in a `struct open_how` in guest memory, not a
    // register, so it needs its own decode + a flags-from-struct read.
    openat2,
    // Filesystem statistics: statfs names a PATH (translate); fstatfs acts on
    // an already-translated fd (forward is correct).
    statfs, fstatfs,
    // chroot: the guest would chroot the HOST child to an untranslated host
    // path — accepted as a namespace no-op (path translation already confines).
    chroot,
    // Extended-attribute family. The *-path variants carry a guest path in
    // arg0 that must be translated to the overlay host path; `f`-variants act
    // on an already-open fd and forward. tar --xattrs / cp -a / setcap rely
    // on these round-tripping against the ROOTFS, not the host.
    getxattr, lgetxattr, fgetxattr,
    setxattr, lsetxattr, fsetxattr,
    listxattr, llistxattr, flistxattr,
    removexattr, lremovexattr, fremovexattr,
    // A file watcher's path registration: inotify_add_watch names a guest
    // path (arg1) that must be translated to the overlay so build tools /
    // `inotifywait` watch the ROOTFS tree, not the host's. inotify_init[1]
    // and inotify_rm_watch carry no path and forward.
    inotify_add_watch,
    // fanotify_mark(fanotify_fd, flags, mask, dirfd, path): path in arg4
    // (needs CAP_SYS_ADMIN and will EPERM unprivileged, but translate the
    // path anyway so a privileged host can't be tricked into marking a host
    // path through an untranslated guest string).
    fanotify_mark,
    // File-handle API (name_to_handle_at / open_by_handle_at): the handle
    // encodes HOST filesystem inode identity, so round-tripping it would leak
    // host-fs structure into the guest. We REFUSE with ENOTSUP; glibc, nfs,
    // and tar's handle fast-paths fall back to path-based operations.
    name_to_handle_at, open_by_handle_at,
    // The new mount API (fsopen/fsconfig/fsmount/move_mount/open_tree/
    // mount_setattr) and the mount-info API (statmount/listmount). All are
    // privileged and describe/mutate the HOST mount namespace; linuxity owns a
    // synthesized mount table (surfaced via /proc/self/mountinfo). We refuse
    // these with ENOSYS so callers fall back to classic mount(2) + the
    // procfs mount views, which we already serve.
    fsopen, fsconfig, fsmount, move_mount, open_tree, mount_setattr,
    statmount, listmount,
    // Privileged system-administration ops with no coherent guest meaning:
    // pivot_root swaps the root mount, swapon/swapoff manage host swap, acct
    // toggles host process accounting, quotactl touches host quotas, ustat
    // reports a host device's fs stats. Refuse cleanly (EPERM/ENOSYS) rather
    // than forward a raw host-scoped operation.
    pivot_root, swapon, swapoff, acct, quotactl, ustat,
    // Namespace / mount ops we own.
    mount, umount2, getpgrp, getppid, sysinfo, sched_getaffinity,
    // Time (virtualized to linuxity's own boot epoch + monotonic clock).
    clock_gettime, gettimeofday, time, clock_getres, times,
    // Resource limits & usage.
    getrlimit, setrlimit, prlimit64, getrusage,
    // Signal state (per-task mask + disposition table).
    rt_sigreturn, rt_sigpending, rt_sigsuspend, sigaltstack,
    // Session / process-group control.
    setpgid, getpgid, setsid, getsid, getpriority, setpriority,
    // Namespace MUTATION: create/remove/rename/relink/chmod/chown paths.
    // Every one names a guest path that must be translated to its overlay
    // upper host path before the kernel touches the real filesystem.
    mkdir, mkdirat, rmdir, unlink, unlinkat,
    chmod, fchmod, fchmodat, chown, lchown, fchown, fchownat,
    truncate, ftruncate, utimensat, futimesat, utimes, utime,
    mknod, mknodat,
    // Two-path mutations (both args are paths needing translation).
    rename, renameat, renameat2, link, linkat, symlink, symlinkat,
    // Privilege drops. linuxity presents a ROOT-OWNED world and the guest
    // runs as our unprivileged host process, so a real setuid to a non-root
    // user (pacman's 'alpm', apk's build user) EPERMs. We accept them
    // vacuously: the guest believes it dropped privilege; the host process is
    // unchanged (already the only identity we have).
    setuid, setgid, setreuid, setregid, setresuid, setresgid,
    setfsuid, setfsgid, setgroups,
    // Landlock (pacman 7's download sandbox). We can't apply an LSM ruleset
    // through ptrace, but linuxity's namespace already confines the guest, so
    // we ACCEPT the sandbox calls as satisfied no-ops rather than let pacman
    // treat the failure as fatal.
    landlock_create_ruleset, landlock_add_rule, landlock_restrict_self,
    // AF_UNIX sockets: bind/connect carry a filesystem path in sockaddr_un
    // that must be translated to the overlay upper like any other path arg.
    bind, connect,
    // Miscellany the guest may probe; forwarded or benign by default.
    prctl,
};

// Decode an arch-specific raw syscall number into the canonical identity.
[[nodiscard]] constexpr Sysno decode(Arch a, std::uint64_t nr) noexcept {
    switch (a) {
        case Arch::x86_64:
            switch (nr) {
                case 0:   return Sysno::read;
                case 1:   return Sysno::write;
                case 3:   return Sysno::close;
                case 9:   return Sysno::mmap;
                case 10:  return Sysno::mprotect;
                case 11:  return Sysno::munmap;
                case 12:  return Sysno::brk;
                case 16:  return Sysno::ioctl;
                case 19:  return Sysno::readv;
                case 20:  return Sysno::writev;
                case 13:  return Sysno::rt_sigaction;
                case 14:  return Sysno::rt_sigprocmask;
                case 39:  return Sysno::getpid;
                case 56:  return Sysno::clone;
                case 57:  return Sysno::fork;
                case 59:  return Sysno::execve;
                case 322: return Sysno::execveat;
                case 58:  return Sysno::vfork;
                case 60:  return Sysno::exit;
                case 61:  return Sysno::wait4;
                case 62:  return Sysno::kill;
                case 234: return Sysno::tgkill;
                case 200: return Sysno::tkill;
                case 63:  return Sysno::uname;
                case 102: return Sysno::getuid;
                case 104: return Sysno::getgid;
                case 107: return Sysno::geteuid;
                case 108: return Sysno::getegid;
                case 118: return Sysno::getresuid;
                case 120: return Sysno::getresgid;
                case 158: return Sysno::arch_prctl;
                case 186: return Sysno::gettid;
                case 218: return Sysno::set_tid_address;
                case 231: return Sysno::exit_group;
                case 257: return Sysno::openat;
                case 2:   return Sysno::open;
                case 4:   return Sysno::stat;
                case 5:   return Sysno::fstat;
                case 6:   return Sysno::lstat;
                case 8:   return Sysno::lseek;
                case 17:  return Sysno::pread64;
                case 18:  return Sysno::pwrite64;
                case 21:  return Sysno::access;
                case 32:  return Sysno::dup;
                case 33:  return Sysno::dup2;
                case 72:  return Sysno::fcntl;
                case 79:  return Sysno::getcwd;
                case 80:  return Sysno::chdir;
                case 81:  return Sysno::fchdir;
                case 89:  return Sysno::readlink;
                case 99:  return Sysno::sysinfo;
                case 110: return Sysno::getppid;
                case 111: return Sysno::getpgrp;
                case 165: return Sysno::mount;
                case 166: return Sysno::umount2;
                case 217: return Sysno::getdents64;
                case 262: return Sysno::newfstatat;
                case 267: return Sysno::readlinkat;
                case 269: return Sysno::faccessat;
                case 292: return Sysno::dup3;
                case 204: return Sysno::sched_getaffinity;
                case 228: return Sysno::clock_gettime;
                case 229: return Sysno::clock_getres;
                case 96:  return Sysno::gettimeofday;
                case 201: return Sysno::time;
                case 100: return Sysno::times;
                case 97:  return Sysno::getrlimit;
                case 160: return Sysno::setrlimit;
                case 302: return Sysno::prlimit64;
                case 98:  return Sysno::getrusage;
                case 15:  return Sysno::rt_sigreturn;
                case 127: return Sysno::rt_sigpending;
                case 130: return Sysno::rt_sigsuspend;
                case 131: return Sysno::sigaltstack;
                case 109: return Sysno::setpgid;
                case 121: return Sysno::getpgid;
                case 112: return Sysno::setsid;
                case 124: return Sysno::getsid;
                case 140: return Sysno::getpriority;
                case 141: return Sysno::setpriority;
                case 332: return Sysno::statx;
                case 439: return Sysno::faccessat2;
                case 437: return Sysno::openat2;
                case 137: return Sysno::statfs;
                case 138: return Sysno::fstatfs;
                case 161: return Sysno::chroot;
                case 191: return Sysno::getxattr;
                case 192: return Sysno::lgetxattr;
                case 193: return Sysno::fgetxattr;
                case 188: return Sysno::setxattr;
                case 189: return Sysno::lsetxattr;
                case 190: return Sysno::fsetxattr;
                case 194: return Sysno::listxattr;
                case 195: return Sysno::llistxattr;
                case 196: return Sysno::flistxattr;
                case 197: return Sysno::removexattr;
                case 198: return Sysno::lremovexattr;
                case 199: return Sysno::fremovexattr;
                case 254: return Sysno::inotify_add_watch;
                case 301: return Sysno::fanotify_mark;
                case 303: return Sysno::name_to_handle_at;
                case 304: return Sysno::open_by_handle_at;
                case 430: return Sysno::fsopen;
                case 431: return Sysno::fsconfig;
                case 432: return Sysno::fsmount;
                case 429: return Sysno::move_mount;
                case 428: return Sysno::open_tree;
                case 442: return Sysno::mount_setattr;
                case 457: return Sysno::statmount;
                case 458: return Sysno::listmount;
                case 155: return Sysno::pivot_root;
                case 167: return Sysno::swapon;
                case 168: return Sysno::swapoff;
                case 163: return Sysno::acct;
                case 179: return Sysno::quotactl;
                case 136: return Sysno::ustat;
                // -- namespace mutation (path args need translation) ------
                case 83:  return Sysno::mkdir;
                case 258: return Sysno::mkdirat;
                case 84:  return Sysno::rmdir;
                case 87:  return Sysno::unlink;
                case 263: return Sysno::unlinkat;
                case 90:  return Sysno::chmod;
                case 91:  return Sysno::fchmod;
                case 268: return Sysno::fchmodat;
                case 92:  return Sysno::chown;
                case 94:  return Sysno::lchown;
                case 93:  return Sysno::fchown;
                case 260: return Sysno::fchownat;
                case 76:  return Sysno::truncate;
                case 77:  return Sysno::ftruncate;
                case 280: return Sysno::utimensat;
                case 261: return Sysno::futimesat;
                case 235: return Sysno::utimes;
                case 132: return Sysno::utime;
                case 133: return Sysno::mknod;
                case 259: return Sysno::mknodat;
                case 82:  return Sysno::rename;
                case 264: return Sysno::renameat;
                case 316: return Sysno::renameat2;
                case 86:  return Sysno::link;
                case 265: return Sysno::linkat;
                case 88:  return Sysno::symlink;
                case 266: return Sysno::symlinkat;
                // -- privilege drops (vacuous in a root-owned world) ------
                case 105: return Sysno::setuid;
                case 106: return Sysno::setgid;
                case 113: return Sysno::setreuid;
                case 114: return Sysno::setregid;
                case 117: return Sysno::setresuid;
                case 119: return Sysno::setresgid;
                case 122: return Sysno::setfsuid;
                case 123: return Sysno::setfsgid;
                case 116: return Sysno::setgroups;
                case 157: return Sysno::prctl;
                // -- Landlock (accepted no-op; namespace already confines) --
                case 444: return Sysno::landlock_create_ruleset;
                case 445: return Sysno::landlock_add_rule;
                case 446: return Sysno::landlock_restrict_self;
                case 49:  return Sysno::bind;
                case 42:  return Sysno::connect;
                default:  return Sysno::unknown;
            }
        case Arch::aarch64:
            switch (nr) {
                case 63:  return Sysno::read;
                case 64:  return Sysno::write;
                case 57:  return Sysno::close;
                case 222: return Sysno::mmap;
                case 226: return Sysno::mprotect;
                case 215: return Sysno::munmap;
                case 214: return Sysno::brk;
                case 29:  return Sysno::ioctl;
                case 66:  return Sysno::writev;
                case 65:  return Sysno::readv;
                case 172: return Sysno::getpid;
                case 178: return Sysno::gettid;
                case 220: return Sysno::clone;
                case 221: return Sysno::execve;
                case 281: return Sysno::execveat;
                case 93:  return Sysno::exit;
                case 94:  return Sysno::exit_group;
                case 260: return Sysno::wait4;
                case 129: return Sysno::kill;
                case 131: return Sysno::tgkill;
                case 130: return Sysno::tkill;
                case 160: return Sysno::uname;
                case 174: return Sysno::getuid;
                case 176: return Sysno::getgid;
                case 175: return Sysno::geteuid;
                case 177: return Sysno::getegid;
                case 148: return Sysno::getresuid;
                case 150: return Sysno::getresgid;
                case 96:  return Sysno::set_tid_address;
                case 56:  return Sysno::openat;
                case 62:  return Sysno::lseek;
                case 67:  return Sysno::pread64;
                case 68:  return Sysno::pwrite64;
                case 79:  return Sysno::newfstatat;
                case 80:  return Sysno::fstat;
                case 291: return Sysno::statx;
                case 61:  return Sysno::getdents64;
                case 78:  return Sysno::readlinkat;
                case 17:  return Sysno::getcwd;
                case 49:  return Sysno::chdir;
                case 50:  return Sysno::fchdir;
                case 48:  return Sysno::faccessat;
                case 439: return Sysno::faccessat2;
                case 437: return Sysno::openat2;
                case 43:  return Sysno::statfs;
                case 44:  return Sysno::fstatfs;
                case 51:  return Sysno::chroot;
                case 8:   return Sysno::getxattr;
                case 9:   return Sysno::lgetxattr;
                case 10:  return Sysno::fgetxattr;
                case 5:   return Sysno::setxattr;
                case 6:   return Sysno::lsetxattr;
                case 7:   return Sysno::fsetxattr;
                case 11:  return Sysno::listxattr;
                case 12:  return Sysno::llistxattr;
                case 13:  return Sysno::flistxattr;
                case 14:  return Sysno::removexattr;
                case 15:  return Sysno::lremovexattr;
                case 16:  return Sysno::fremovexattr;
                case 27:  return Sysno::inotify_add_watch;
                case 263: return Sysno::fanotify_mark;
                case 264: return Sysno::name_to_handle_at;
                case 265: return Sysno::open_by_handle_at;
                case 430: return Sysno::fsopen;
                case 431: return Sysno::fsconfig;
                case 432: return Sysno::fsmount;
                case 429: return Sysno::move_mount;
                case 428: return Sysno::open_tree;
                case 442: return Sysno::mount_setattr;
                case 457: return Sysno::statmount;
                case 458: return Sysno::listmount;
                case 41:  return Sysno::pivot_root;
                case 224: return Sysno::swapon;
                case 225: return Sysno::swapoff;
                case 89:  return Sysno::acct;
                case 60:  return Sysno::quotactl;
                case 23:  return Sysno::dup;
                case 24:  return Sysno::dup3;
                case 25:  return Sysno::fcntl;
                case 40:  return Sysno::mount;
                case 39:  return Sysno::umount2;
                case 179: return Sysno::sysinfo;
                case 173: return Sysno::getppid;
                case 123: return Sysno::sched_getaffinity;
                case 113: return Sysno::clock_gettime;
                case 114: return Sysno::clock_getres;
                case 169: return Sysno::gettimeofday;
                case 153: return Sysno::times;
                case 261: return Sysno::prlimit64;
                case 165: return Sysno::getrusage;
                case 139: return Sysno::rt_sigreturn;
                case 136: return Sysno::rt_sigpending;
                case 133: return Sysno::rt_sigsuspend;
                case 132: return Sysno::sigaltstack;
                case 154: return Sysno::setpgid;
                case 155: return Sysno::getpgid;
                case 157: return Sysno::setsid;
                case 156: return Sysno::getsid;
                case 141: return Sysno::getpriority;
                case 140: return Sysno::setpriority;
                // -- namespace mutation (aarch64 has only the *at forms) --
                case 34:  return Sysno::mkdirat;
                case 35:  return Sysno::unlinkat;   // AT_REMOVEDIR => rmdir
                case 53:  return Sysno::fchmodat;
                case 52:  return Sysno::fchmod;
                case 54:  return Sysno::fchownat;
                case 55:  return Sysno::fchown;
                case 45:  return Sysno::truncate;
                case 46:  return Sysno::ftruncate;
                case 88:  return Sysno::utimensat;
                case 33:  return Sysno::mknodat;
                case 38:  return Sysno::renameat;
                case 276: return Sysno::renameat2;
                case 37:  return Sysno::linkat;
                case 36:  return Sysno::symlinkat;
                case 200: return Sysno::bind;
                case 203: return Sysno::connect;
                default:  return Sysno::unknown;
            }
    }
    return Sysno::unknown;
}

} // namespace lx::abi
