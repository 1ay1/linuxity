// linuxity/abi/syscall.hpp
//
// The syscall boundary: from a trapped register file to a typed subsystem call.
//
// A guest issues a syscall as an opaque tuple of arg words plus a number. We
// decode the arch-specific number into a canonical Sysno (see sysno.hpp),
// then switch on that identity — so the dispatcher is written ONCE and works
// for any guest ISA that equals the host ISA. Everything dangerous (guest
// pointers, untrusted lengths) is validated against the address space before
// the subsystem ever touches memory.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/sysno.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/kernel/subsystem.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace lx::abi {

// The trapped register file: 6 args + the raw (arch-specific) syscall number.
struct Regs {
    std::array<std::uint64_t, 6> arg{};
    std::uint64_t nr{};
};

// The outcome of servicing one syscall: the value to place in the guest's
// return register, and whether the guest asked to terminate.
struct Outcome {
    std::int64_t ret{};
    bool         exited{false};
    int          exit_code{0};
};

// A guest-memory accessor the dispatcher uses to copy_in/copy_out. Modeled as
// a concept so the dispatcher stays decoupled from the concrete AddressSpace;
// a trap backend that shares the guest's real memory (ptrace on the same
// pages) supplies a peek/poke over /proc/pid/mem or process_vm_readv.
template <class M>
concept GuestMem = requires(M m, UAddr a, std::span<std::byte> out,
                            std::span<const std::byte> in) {
    { m.copy_in(a, out) } -> std::same_as<Status>;   // guest -> host buffer
    { m.copy_out(a, in) } -> std::same_as<Status>;   // host buffer -> guest
};

// -- The dispatcher --------------------------------------------------------
// Generic over any kernel and any guest-memory accessor.
template <kernel::IsKernel K, GuestMem M>
class Syscalls {
public:
    Syscalls(K& k, M& mem, Arch arch) noexcept : k_{k}, mem_{mem}, arch_{arch} {}

    [[nodiscard]] Outcome dispatch(const Regs& r) {
        const Sysno sc = decode(arch_, r.nr);
        switch (sc) {
            // -- process lifecycle --------------------------------------
            case Sysno::exit:
            case Sysno::exit_group:
                return Outcome{0, true, static_cast<int>(r.arg[0])};

            case Sysno::getpid:  return val(k_.self().raw());
            case Sysno::gettid:  return val(k_.self().raw());

            // -- credentials (our virtual world: root) -------------------
            case Sysno::getuid:  case Sysno::geteuid:
            case Sysno::getgid:  case Sysno::getegid:
                return val(0);

            // -- I/O ------------------------------------------------------
            case Sysno::write:   return do_write(r);
            case Sysno::writev:  return do_writev(r);
            case Sysno::read:    return enc(k_.read(fd(r.arg[0]), {}));
            case Sysno::close:   return enc(k_.close(fd(r.arg[0])));

            // -- memory ---------------------------------------------------
            case Sysno::mmap:    return enc(k_.mmap(uaddr(r.arg[0]), r.arg[1]));
            case Sysno::munmap:  return enc(k_.munmap(uaddr(r.arg[0]), r.arg[1]));
            case Sysno::brk:     return enc(k_.brk(uaddr(r.arg[0])));

            // -- benign process-init syscalls libc issues early ----------
            // These succeed trivially in our virtual world so _start can run.
            case Sysno::arch_prctl:
            case Sysno::set_tid_address:
            case Sysno::rt_sigaction:
            case Sysno::rt_sigprocmask:
            case Sysno::ioctl:
                return val(0);

            default:
                return val(-static_cast<std::int64_t>(Errno::enosys));
        }
    }

private:
    static Fd fd(std::uint64_t v) { return Fd{static_cast<std::int32_t>(v)}; }
    static Outcome val(std::int64_t v) { return Outcome{v, false, 0}; }

    template <class T>
    static Outcome enc(const Result<T>& r) { return val(to_kernel(r)); }
    static Outcome enc(const Status& r) { return val(to_kernel(r)); }

    // write(fd, buf, len): copy the guest bytes out, hand them to the VFS.
    Outcome do_write(const Regs& r) {
        std::uint64_t len = r.arg[2];
        std::vector<std::byte> tmp(len);
        if (!mem_.copy_in(uaddr(r.arg[1]), tmp))
            return val(-static_cast<std::int64_t>(Errno::efault));
        return enc(k_.write(fd(r.arg[0]), tmp));
    }

    // writev(fd, iov, iovcnt): gather the iovec array, then each buffer.
    Outcome do_writev(const Regs& r) {
        struct IoVec { std::uint64_t base; std::uint64_t len; };
        std::uint64_t cnt = r.arg[2];
        std::size_t total = 0;
        for (std::uint64_t i = 0; i < cnt; ++i) {
            IoVec v{};
            if (!mem_.copy_in(uaddr(r.arg[1] + i * sizeof(IoVec)),
                              {reinterpret_cast<std::byte*>(&v), sizeof v}))
                return val(-static_cast<std::int64_t>(Errno::efault));
            std::vector<std::byte> tmp(v.len);
            if (!mem_.copy_in(uaddr(v.base), tmp))
                return val(-static_cast<std::int64_t>(Errno::efault));
            auto w = k_.write(fd(r.arg[0]), tmp);
            if (!w) return enc(w);
            total += *w;
        }
        return val(static_cast<std::int64_t>(total));
    }

    K& k_;
    M& mem_;
    Arch arch_;
};

} // namespace lx::abi
