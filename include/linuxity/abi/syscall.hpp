// linuxity/abi/syscall.hpp
//
// The syscall boundary: from a register file to a typed subsystem call.
//
// A guest issues a syscall as an opaque tuple of six machine words plus a
// number. Our job is the inverse of the kernel's: decode the number, coerce
// the argument words into the *strong* types the subsystem method wants,
// invoke it, and re-encode the Result<T> back into the single return
// register. Everything dangerous (guest pointers, untrusted lengths) is
// held in un-dereferenceable types until the subsystem validates it.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"
#include "linuxity/kernel/subsystem.hpp"

#include <array>
#include <cstdint>

namespace lx::abi {

// The AArch64 Linux syscall register file (x0..x5 + syscall nr in x8).
struct Regs {
    std::array<std::uint64_t, 6> arg{};
    std::uint64_t nr{};
};

// A curated slice of the AArch64 syscall numbers. (Full table lives in a
// generated header; these are enough to prove the architecture.)
enum class Nr : std::uint64_t {
    openat = 56, close = 57, read = 63, write = 64,
    mmap = 222, munmap = 215, brk = 214,
    getpid = 172, fork = 220 /*clone*/, kill = 129,
    exit = 93,
};

// -- The dispatcher --------------------------------------------------------
// Generic over any type that models kernel::Kernel. Because the kernel is a
// *concept*, this dispatcher is written exactly once and works for the
// production kernel, a mock kernel in tests, or a future JIT-backed kernel.
template <kernel::IsKernel K>
class Syscalls {
public:
    explicit Syscalls(K& k) noexcept : k_{k} {}

    // Decode -> typed call -> re-encode. Returns the guest's return
    // register. Never throws; every error path becomes -errno.
    [[nodiscard]] std::int64_t dispatch(const Regs& r) {
        switch (static_cast<Nr>(r.nr)) {
            case Nr::getpid:
                return static_cast<std::int64_t>(k_.self().raw());

            case Nr::write: {
                auto fd  = Fd{static_cast<std::int32_t>(r.arg[0])};
                auto buf = guest_bytes<const std::byte>(r.arg[1], r.arg[2]);
                return to_kernel(k_.write(fd, buf));
            }
            case Nr::read: {
                auto fd  = Fd{static_cast<std::int32_t>(r.arg[0])};
                auto buf = guest_bytes<std::byte>(r.arg[1], r.arg[2]);
                return to_kernel(k_.read(fd, buf));
            }
            case Nr::close:
                return to_kernel(k_.close(Fd{static_cast<std::int32_t>(r.arg[0])}));

            case Nr::mmap:
                return to_kernel(k_.mmap(uaddr(r.arg[0]), r.arg[1]));
            case Nr::munmap:
                return to_kernel(k_.munmap(uaddr(r.arg[0]), r.arg[1]));
            case Nr::brk:
                return to_kernel(k_.brk(uaddr(r.arg[0])));

            case Nr::kill:
                return to_kernel(k_.kill(
                    Pid{static_cast<std::int32_t>(r.arg[0])},
                    Signal{static_cast<std::int32_t>(r.arg[1])}));

            case Nr::fork:
                return to_kernel(k_.fork());

            default:
                // The one honest answer for an unimplemented syscall.
                return -static_cast<std::int64_t>(Errno::enosys);
        }
    }

private:
    // NOTE: a placeholder. In the real runtime this consults the Memory
    // subsystem's page tables to translate + bounds-check the guest range,
    // and would itself return Result<std::span<T>>. It is intentionally the
    // ONLY place a UAddr becomes a real span, so validation has a single home.
    template <class T>
    static std::span<T> guest_bytes(std::uint64_t /*addr*/, std::uint64_t /*len*/) {
        return {};
    }

    K& k_;
};

} // namespace lx::abi
