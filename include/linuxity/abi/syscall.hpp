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
// return register, whether to FORWARD it to the host kernel instead, and
// whether the guest asked to terminate.
struct Outcome {
    std::int64_t ret{};
    bool         forward{false};   // let the host kernel run it in the guest
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
            // -- process lifecycle (virtual: our process model) ----------
            case Sysno::exit:
            case Sysno::exit_group:
                return Outcome{0, false, true, static_cast<int>(r.arg[0])};

            // -- identity + credentials (virtual: our world is pid 1, root)
            case Sysno::getpid:  return val(k_.self().raw());
            case Sysno::gettid:  return val(k_.self().raw());
            case Sysno::getuid:  case Sysno::geteuid:
            case Sysno::getgid:  case Sysno::getegid:
                return val(0);

            // -- benign process-init syscalls libc issues early ----------
            // Serviced trivially so _start proceeds; they carry no host
            // resource we need to allocate.
            case Sysno::set_tid_address:
            case Sysno::rt_sigaction:
            case Sysno::rt_sigprocmask:
                return val(0);

            // -- uname (virtual: report LINUXITY's identity, not the host)
            // The guest must believe it runs on linuxity, so we synthesize
            // the utsname and copy_out into the guest buffer ourselves
            // rather than forwarding to the host kernel.
            case Sysno::uname:
                return do_uname(uaddr(r.arg[0]));

            // -- everything else: FORWARD to the real host kernel. -------
            // Memory (mmap/brk/mprotect) MUST run in the child so it gets
            // real pages in its own address space; file I/O, arch_prctl,
            // ioctl, clock, random, etc. likewise need real host action.
            // This is what carries native libc all the way to main().
            default:
                return fwd();
        }
    }

private:
    static Outcome val(std::int64_t v) { return Outcome{v, false, false, 0}; }
    static Outcome fwd() { return Outcome{0, true, false, 0}; }

    // struct utsname: 6 fixed-size NUL-terminated char[65] fields. We
    // synthesize linuxity's identity and copy it into the guest buffer.
    Outcome do_uname(UAddr buf) {
        struct Uts { char sysname[65], nodename[65], release[65],
                          version[65], machine[65], domainname[65]; };
        Uts u{};
        auto set = [](char (&dst)[65], const char* s) {
            std::size_t i = 0; for (; s[i] && i < 64; ++i) dst[i] = s[i]; dst[i] = 0;
        };
        set(u.sysname,  "Linux");
        set(u.nodename, "linuxity");
        set(u.release,  "6.6.0-linuxity");
        set(u.version,  "#1 linuxity portable Linux ABI");
        set(u.machine,  arch_ == Arch::aarch64 ? "aarch64" : "x86_64");
        set(u.domainname, "(none)");
        if (!mem_.copy_out(buf, {reinterpret_cast<const std::byte*>(&u), sizeof u}))
            return val(-static_cast<std::int64_t>(Errno::efault));
        return val(0);
    }

    K& k_;
    M& mem_;
    Arch arch_;
};

} // namespace lx::abi
