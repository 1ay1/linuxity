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
                case 332: return Sysno::statx;
                case 439: return Sysno::faccessat2;
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
                default:  return Sysno::unknown;
            }
    }
    return Sysno::unknown;
}

} // namespace lx::abi
