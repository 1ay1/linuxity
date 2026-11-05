// linuxity/runtime/windows/regs.hpp
//
// The vCPU register file, cached across one syscall service.
//
// WHvGetVirtualProcessorRegisters / WHvSetVirtualProcessorRegisters are
// hypercalls into the root partition: each one is a user->kernel->hypervisor
// round trip costing on the order of a microsecond. The Linux x86-64 syscall
// ABI touches eight GPRs plus RIP/RFLAGS, so reading them one at a time costs
// ten round trips -- and a naive backend pays that TWICE per guest syscall
// (once to decode the request, once to write the answer back).
//
// But WHP's register API is inherently BATCHED: it takes an array of register
// names and an array of values, and services the whole vector in one
// hypercall. Since the guest is stopped for the entire time we service a
// trap, its register file cannot change under us -- so read the whole working
// set ONCE into a POD, decide everything against that cheap in-memory
// snapshot, and write back only what we actually changed.
//
// That is the same phase-split hvf_regs.hpp uses on Darwin, and the same one
// claybin uses: all decisions happen against a snapshot, and the expensive
// boundary is crossed a fixed, minimal number of times. Here the minimum is
// literally one hypercall in and one out, regardless of how many registers the
// syscall touches.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#include "linuxity/runtime/windows/api.hpp"

#include <array>
#include <cstdint>

namespace lx::runtime {

// -- The working set -------------------------------------------------------
// The registers the Linux x86-64 syscall ABI can read or write, in ONE fixed
// order so the name array is a compile-time constant and the value array is
// indexed positionally. Do not reorder without updating `kWhpSyscallRegs`:
// the two must agree index-for-index.
enum class GReg : std::size_t {
    rax = 0,  // syscall number in, return value out
    rdi = 1,  // arg0
    rsi = 2,  // arg1
    rdx = 3,  // arg2
    r10 = 4,  // arg3   (NOT rcx: the syscall instruction clobbers rcx)
    r8  = 5,  // arg4
    r9  = 6,  // arg5
    rip = 7,  // faulting instruction (points AT the syscall, see below)
    rflags = 8,
    rsp = 9,  // not an argument register, but clone/sigreturn need it
    count = 10
};

// The WHP register names, in GReg order.
inline constexpr std::array<WHV_REGISTER_NAME, std::size_t(GReg::count)>
kWhpSyscallRegs{
    WHvX64RegisterRax, WHvX64RegisterRdi, WHvX64RegisterRsi,
    WHvX64RegisterRdx, WHvX64RegisterR10, WHvX64RegisterR8,
    WHvX64RegisterR9,  WHvX64RegisterRip, WHvX64RegisterRflags,
    WHvX64RegisterRsp,
};

// A snapshot of the guest's syscall-relevant register file.
//
// On x86-64 the Linux syscall ABI is:
//   rax      = syscall number        (and the return value on the way out)
//   rdi rsi rdx r10 r8 r9 = args 0..5
//   rcx, r11 = CLOBBERED by the `syscall` instruction (it stashes the return
//              address in rcx and RFLAGS in r11). The guest's ABI treats them
//              as call-clobbered, so we need not preserve them.
//
// The one subtlety versus Darwin: on aarch64 `svc` has already RETIRED when
// the trap is taken, so ELR_EL1 points after it. Here the trap is a #UD FAULT
// on the `syscall` instruction itself, so RIP points AT the two-byte 0F 05 --
// resuming without advancing RIP would re-fault forever. `advance()` is the
// only correct way to resume, and it is why that method exists at all.
struct GuestRegs {
    std::array<std::uint64_t, std::size_t(GReg::count)> v{};

    [[nodiscard]] std::uint64_t  operator[](GReg r) const noexcept {
        return v[std::size_t(r)];
    }
    [[nodiscard]] std::uint64_t& operator[](GReg r) noexcept {
        return v[std::size_t(r)];
    }

    // -- The Linux x86-64 syscall ABI, named ------------------------------
    [[nodiscard]] std::uint64_t nr()   const noexcept { return (*this)[GReg::rax]; }
    [[nodiscard]] std::uint64_t arg(unsigned i) const noexcept {
        switch (i) {
            case 0:  return (*this)[GReg::rdi];
            case 1:  return (*this)[GReg::rsi];
            case 2:  return (*this)[GReg::rdx];
            case 3:  return (*this)[GReg::r10];
            case 4:  return (*this)[GReg::r8];
            default: return (*this)[GReg::r9];
        }
    }
    [[nodiscard]] std::uint64_t sp()  const noexcept { return (*this)[GReg::rsp]; }
    [[nodiscard]] std::uint64_t pc()  const noexcept { return (*this)[GReg::rip]; }

    // The length of the `syscall` instruction (0F 05). `sysenter` and the
    // 32-bit `int 0x80` gate are not supported on this backend by design --
    // the seccomp filter on Linux returns ENOSYS for i386/x32 for the same
    // reason: a 32-bit entry that we half-serve is worse than one we refuse.
    static constexpr std::uint64_t kSyscallInsnLen = 2;

    // Set the return value and step over the trapping instruction.
    void advance(std::int64_t ret) noexcept {
        (*this)[GReg::rax] = static_cast<std::uint64_t>(ret);
        (*this)[GReg::rip] += kSyscallInsnLen;
    }
};

// -- Crossing the boundary -------------------------------------------------

// Read the whole working set in ONE hypercall.
[[nodiscard]] inline bool read_regs(WHV_PARTITION_HANDLE part, UINT32 vp,
                                    GuestRegs& out) noexcept {
    static_assert(sizeof(WHV_REGISTER_VALUE) >= sizeof(std::uint64_t));
    std::array<WHV_REGISTER_VALUE, std::size_t(GReg::count)> vals{};
    if (FAILED(whp().GetVirtualProcessorRegisters(
            part, vp, kWhpSyscallRegs.data(),
            UINT32(kWhpSyscallRegs.size()), vals.data())))
        return false;
    for (std::size_t i = 0; i < std::size_t(GReg::count); ++i)
        out.v[i] = vals[i].Reg64;
    return true;
}

// Write back ONLY rax and rip: the two registers servicing a syscall can
// change. Two names, one hypercall. (RFLAGS is untouched because, unlike
// aarch64's PSTATE restore, nothing we do perturbs it -- the #UD fault did
// not push a flags change, and we are not emulating `sysret`.)
inline bool write_return(WHV_PARTITION_HANDLE part, UINT32 vp,
                         const GuestRegs& r) noexcept {
    const WHV_REGISTER_NAME names[2]{WHvX64RegisterRax, WHvX64RegisterRip};
    WHV_REGISTER_VALUE vals[2]{};
    vals[0].Reg64 = r[GReg::rax];
    vals[1].Reg64 = r[GReg::rip];
    return SUCCEEDED(whp().SetVirtualProcessorRegisters(part, vp, names, 2, vals));
}

// Write an arbitrary subset back (used by clone/sigreturn, which rewrite rsp
// and the argument registers of a freshly minted thread).
inline bool write_regs(WHV_PARTITION_HANDLE part, UINT32 vp,
                       const GuestRegs& r) noexcept {
    std::array<WHV_REGISTER_VALUE, std::size_t(GReg::count)> vals{};
    for (std::size_t i = 0; i < std::size_t(GReg::count); ++i)
        vals[i].Reg64 = r.v[i];
    return SUCCEEDED(whp().SetVirtualProcessorRegisters(
        part, vp, kWhpSyscallRegs.data(), UINT32(kWhpSyscallRegs.size()),
        vals.data()));
}

} // namespace lx::runtime

#endif // _WIN32 && x86-64
