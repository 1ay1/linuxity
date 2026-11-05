// linuxity/runtime/darwin/regs.hpp
//
// The vCPU register file, cached across one syscall service.
//
// hv_vcpu_get_reg / set_reg are kernel calls. Reading x0..x8 individually
// costs nine round-trips, and a naive backend does that TWICE per guest
// syscall (once to decode, once to emulate). Since the guest is stopped for
// the entire time we service a trap, its register file cannot change under
// us -- so read it ONCE into a POD, operate on that, and write back only
// what we changed.
//
// This is the same phase-split claybin uses: all decisions happen against a
// cheap in-memory snapshot, and the expensive boundary is crossed a fixed,
// minimal number of times.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include <Hypervisor/Hypervisor.h>

#include <array>
#include <cstdint>

namespace lx::runtime {

// The Linux aarch64 syscall ABI touches x0..x8 plus PC/PSTATE. Everything
// else (x9..x30, SIMD) is callee state the guest owns; we never read it, so
// it never crosses the hypervisor boundary.
struct GuestRegs {
    std::array<std::uint64_t, 9> x{};   // x0..x8: 6 args, x8 = syscall nr
    std::uint64_t elr{};                // return address (PC after the svc)
    std::uint64_t spsr{};               // PSTATE to restore
    std::uint64_t esr{};                // why we trapped

    [[nodiscard]] std::uint64_t nr() const noexcept { return x[8]; }
    [[nodiscard]] std::uint64_t arg(std::size_t i) const noexcept { return x[i]; }
    [[nodiscard]] std::uint64_t ec() const noexcept { return esr >> 26; }
};

// Pull the syscall-relevant register file out of the vCPU in one pass.
// Deliberately NOT a loop over hv_reg_t arithmetic: the enum values for
// HV_REG_X0..X8 are contiguous, but spelling them out lets the compiler
// unroll into nine direct calls with no indirection.
//
// FAR_EL1 is deliberately NOT read here. It is meaningful only for an abort,
// and an abort is the rare exit -- the overwhelming majority of exits are
// `svc`, where FAR holds a stale address from whenever the guest last
// faulted. Each get_sys_reg is ~14 ns of kernel round trip, so paying for it
// on every syscall to serve the one-in-ten-thousand fault is backwards:
// `fault_address()` fetches it on demand instead.
[[nodiscard]] inline GuestRegs read_regs(hv_vcpu_t cpu) {
    GuestRegs r;
    for (std::size_t i = 0; i < r.x.size(); ++i)
        ::hv_vcpu_get_reg(cpu, static_cast<hv_reg_t>(HV_REG_X0 + i), &r.x[i]);
    ::hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_ELR_EL1, &r.elr);
    ::hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_SPSR_EL1, &r.spsr);
    ::hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_ESR_EL1, &r.esr);
    return r;
}

// The address that caused an abort. Valid only when ec() names a data or
// instruction abort; the register is architecturally UNKNOWN otherwise.
[[nodiscard]] inline std::uint64_t fault_address(hv_vcpu_t cpu) {
    std::uint64_t far = 0;
    ::hv_vcpu_get_sys_reg(cpu, HV_SYS_REG_FAR_EL1, &far);
    return far;
}

// Return from the syscall: the result in x0, then PC/PSTATE restored. Three
// kernel calls, the irreducible minimum -- the svc instruction has already
// retired, so ELR_EL1 is the instruction after it and there is no sysret
// sequence to emulate.
inline void write_return(hv_vcpu_t cpu, const GuestRegs& r, std::int64_t ret) {
    ::hv_vcpu_set_reg(cpu, HV_REG_X0, static_cast<std::uint64_t>(ret));
    ::hv_vcpu_set_reg(cpu, HV_REG_PC, r.elr);
    ::hv_vcpu_set_reg(cpu, HV_REG_CPSR, r.spsr);
}

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
