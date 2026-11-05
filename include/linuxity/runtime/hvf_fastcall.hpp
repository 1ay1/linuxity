// linuxity/runtime/hvf_fastcall.hpp
//
// The in-guest syscall fast path: answer what we can WITHOUT a VM exit.
//
// Every guest `svc` is a VM exit, and an exit costs ~930 ns on an M-series
// (measured: hv_vcpu_run round trip 894 ns, register shuffling 169 ns) --
// against ~70 ns for a real syscall on the host. But the exception is taken
// at EL1, in the GUEST, at our own vector stub: if the stub can answer the
// call itself and `eret`, the host never runs. Measured: 28 ns.
//
// What may be answered here is a short list, and the rule is strict: no
// host state may be involved, and nothing may be needed that the handler
// cannot see. Two kinds qualify:
//
//   kConst       a value fixed for this process image -- the identity
//                calls (getpid, getuid, ...) and sched_yield.
//   kSigprocmask a read-modify-write of one 64-bit mask plus up to two
//                guest memory accesses. 7% of all syscalls in a real
//                workload, and the host learns the new mask by re-reading
//                the scratch word on its next trap.
//
// Everything else falls through to `hvc`, the original stub, and is
// serviced exactly as before. A missing entry is a lost optimisation,
// never a wrong answer.
//
// The table and scratch live in the hypervisor-private area below
// priv_end: EL1-only, so a guest can neither read them nor forge an entry
// (tests/guest/fastcall_security.c asserts exactly that).
//
// The handler itself is tools/fastcall/handler.S, assembled into
// hvf_fastcall_blob.hpp by tools/fastcall/build.py. It is NOT hand-encoded:
// a `lsl #7` that should have been `lsl #4` once cost an afternoon, because
// a mis-encoded lookup silently misses and every call takes the slow path,
// which looks exactly like "the fast handler never runs".
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/runtime/hvf_fastcall_blob.hpp"

#include <cstdint>
#include <cstring>

namespace lx::runtime::fastcall {

// One entry per syscall number.
//   live == kOff         hvc to the host (the default for everything)
//   live == kConst       answer with `value`
//   live == kSigprocmask `value` is the address of the scratch mask
struct Entry {
    std::uint64_t value;
    std::uint64_t live;
};
enum : std::uint64_t { kOff = 0, kConst = 1, kSigprocmask = 2 };

inline constexpr std::size_t kMaxNr = 512;          // aarch64 uses < 512
inline constexpr std::size_t kTableBytes = kMaxNr * sizeof(Entry);

// Scratch the handler owns, right after the table.
struct Scratch {
    std::uint64_t sig_mask;
    std::uint64_t pad[7];
};
inline constexpr std::size_t kScratchOff = kTableBytes;
inline constexpr std::size_t kTotalBytes = kTableBytes + sizeof(Scratch);

// Copy the assembled handler into `out`, patching its movz/movk pair with
// the dispatch table's guest-physical address. Returns instruction words.
[[nodiscard]] inline std::size_t emit_handler(std::uint32_t* out,
                                              std::uint64_t table_addr) {
    std::memcpy(out, kCode, sizeof kCode);
    out[kTableImmWord]     |= static_cast<std::uint32_t>((table_addr & 0xffffu) << 5);
    out[kTableImmWord + 1] |= static_cast<std::uint32_t>(((table_addr >> 16) & 0xffffu) << 5);
    return kCodeWords;
}

}  // namespace lx::runtime::fastcall

#endif  // __APPLE__ && __aarch64__
