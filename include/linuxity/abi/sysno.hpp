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
    // File metadata & directory path family (virtualized through the VFS).
    stat, lstat, fstat, newfstatat, statx, lseek, pread64, pwrite64,
    getdents64, readlink, readlinkat, getcwd, chdir, fchdir,
    access, faccessat, faccessat2, dup, dup2, dup3, fcntl,
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
                default:  return Sysno::unknown;
            }
    }
    return Sysno::unknown;
}

} // namespace lx::abi
