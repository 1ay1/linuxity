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
    read, write, openat, close,
    mmap, munmap, mprotect, brk,
    getpid, gettid, clone, fork, execve, wait4, kill, exit, exit_group,
    uname, arch_prctl, set_tid_address, ioctl, writev, readv,
    rt_sigaction, rt_sigprocmask, getuid, geteuid, getgid, getegid,
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
                case 60:  return Sysno::exit;
                case 61:  return Sysno::wait4;
                case 62:  return Sysno::kill;
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
                case 93:  return Sysno::exit;
                case 94:  return Sysno::exit_group;
                case 260: return Sysno::wait4;
                case 129: return Sysno::kill;
                case 160: return Sysno::uname;
                case 174: return Sysno::getuid;
                case 176: return Sysno::getgid;
                case 175: return Sysno::geteuid;
                case 177: return Sysno::getegid;
                case 96:  return Sysno::set_tid_address;
                case 56:  return Sysno::openat;
                default:  return Sysno::unknown;
            }
    }
    return Sysno::unknown;
}

} // namespace lx::abi
