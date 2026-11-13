// linuxity/runtime/darwin/inguest.hpp
//
// the in-guest handler: answer the pure ones WITHOUT a VM exit.
//
// Every guest `svc` is a VM exit, and an exit costs ~900 ns on an M-series
// (measured: hv_vcpu_run round trip 894 ns, register shuffling 169 ns) --
// against ~70 ns for a real syscall on the host. But the exception is taken
// at EL1, in the GUEST, at our own vector stub: if the stub can answer the
// call itself and `eret`, the host never runs. Measured: 31.8 ns, zero
// exits. A 29x win on the calls it covers.
//
// What may be answered here is a short list, and the rule is strict: the
// answer must be a CONSTANT for the lifetime of this process image, with no
// side effect and no memory the host must write. That is exactly the
// identity calls (getpid/getuid/...) plus sched_yield and the handful of
// "always this errno" refusals. Everything else falls through to `hvc`,
// which is the existing path, unchanged.
//
// The table lives in the hypervisor-private page below priv_end: EL1-only,
// so a guest cannot read or forge it, and the handler runs with the MMU on
// at EL1 where that mapping is readable.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include <cstdint>
#include <cstring>

namespace lx::runtime::inguest {

// One entry per syscall number, in the private page.
//   value  -- what x0 becomes
//   live   -- 1: answer in-guest; 0: hvc to the host
struct Entry {
    std::uint64_t value;
    std::uint64_t live;
};
inline constexpr std::size_t kMaxNr = 512;          // aarch64 uses < 512
inline constexpr std::size_t kTableBytes = kMaxNr * sizeof(Entry);

// The EL1 handler, hand-assembled. It replaces the `hvc #<n>` at the
// lower-EL-AArch64 synchronous vector (VBAR + 0x400) only; the other 15
// vectors keep their stub, so faults, IRQs and EL1 traps exit as before.
//
// Registers: x16/x17 are IP0/IP1 -- the procedure-call standard lets any
// linker veneer clobber them across a call, so no guest code can hold a
// live value in them at an `svc`. But this vector also takes every OTHER
// synchronous exception from EL0 -- page faults above all, which with
// memory populated on first touch happen at any instruction, including a
// PLT stub that has just put the GOT slot's address in x16 for the lazy
// resolver. So x16 is parked in TPIDR_EL1 (an EL1 register the guest
// cannot see) before anything else, and put back on the non-svc path:
// a fault must reach the host with every register exactly as the guest had
// it. (Clobbering it made the resolver read address 0xb: EC 0x20 - 0x15.)
// x8 holds the syscall number, x0 the first argument and the return value,
// per the Linux aarch64 ABI.
//
//   msr  tpidr_el1, x16        park x16
//   mrs  x16, esr_el1          what kind of exception?
//   lsr  x16, x16, #26         EC
//   subs x16, x16, #0x15       SVC64?
//   b.ne restore
//   cmp  x8, #kMaxNr           in range?
//   b.hs slow
//   movz x16, #<table & 0xffff>
//   movk x16, #<table >> 16>, lsl #16
//   add  x16, x16, x8, lsl #4  &table[nr]
//   ldr  x17, [x16, #8]        .live
//   cbz  x17, slow
//   ldr  x16, [x16]            .value
//   mov  x0, x16
//   eret                       ELR already points past the svc
// slow:
//   hvc  #imm                  a syscall for the host (x16/x17 are scratch)
// restore:
//   mrs  x16, tpidr_el1        not a syscall: x16 as the guest left it
//   hvc  #imm
inline constexpr std::uint32_t kEretOffset = 0x38;      // see HvfCpu::unwind_el1
[[nodiscard]] inline std::size_t emit_handler(std::uint32_t* out,
                                              std::uint64_t table_addr,
                                              std::uint32_t hvc_imm) {
    const auto lo = static_cast<std::uint32_t>(table_addr & 0xffff);
    const auto hi = static_cast<std::uint32_t>((table_addr >> 16) & 0xffff);
    std::uint32_t c[] = {
        0xd518d090u,                               // 0x00 msr  tpidr_el1, x16
        0xd5385210u,                               // 0x04 mrs  x16, esr_el1
        0xd35afe10u,                               // 0x08 lsr  x16, x16, #26
        0xf1005610u,                               // 0x0c subs x16, x16, #0x15
        0x54000181u,                               // 0x10 b.ne  0x40 (restore)
        0xf108011fu,                               // 0x14 cmp  x8, #512
        0x54000122u,                               // 0x18 b.hs  0x3c (slow)
        0xd2800010u | (lo << 5),                   // 0x1c movz x16, #lo
        0xf2a00010u | (hi << 5),                   // 0x20 movk x16, #hi, lsl #16
        0x8b081210u,                               // 0x24 add  x16, x16, x8, lsl #4
        0xf9400611u,                               // 0x28 ldr  x17, [x16, #8]
        0xb4000091u,                               // 0x2c cbz  x17, 0x3c (slow)
        0xf9400210u,                               // 0x30 ldr  x16, [x16]
        0xaa1003e0u,                               // 0x34 mov  x0, x16
        0xd69f03e0u,                               // 0x38 eret
        0xd4000002u | (hvc_imm << 5),              // 0x3c slow: hvc #imm
        0xd538d090u,                               // 0x40 restore: mrs x16, tpidr_el1
        0xd4000002u | (hvc_imm << 5),              // 0x44 hvc #imm
    };
    static_assert(kMaxNr == 512, "the cmp immediate below encodes 512");
    static_assert(sizeof c <= 0x80, "one vector slot");
    std::memcpy(out, c, sizeof c);
    return sizeof c / sizeof c[0];
}

}  // namespace lx::runtime::inguest

#endif  // __APPLE__ && __aarch64__
