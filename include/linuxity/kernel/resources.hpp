// linuxity/kernel/resources.hpp
//
// The RESOURCE POLICY the guest world is bounded by — the enforcement half of
// the machine, and the twin of MachineSpec (kernel/machine.hpp).
//
// linuxity is an ABI translator, not a hypervisor: the guest runs native on
// the host CPU and draws memory/CPU straight from the host's global pool via
// FORWARDED mmap/brk (see abi/syscall.hpp). So there is nothing to "allocate".
// What we CAN do — because the guest is a real host process tree — is ask the
// host kernel to BOUND that tree, exactly as Docker / systemd / Termux do:
// cgroup v2 limits (cpu.max, memory.max, pids.max) or, where a cgroup can't be
// created unprivileged, setrlimit ceilings.
//
// TWO NUMBERS, KEPT EQUAL. A program sizes its caches and thread pools to what
// it BELIEVES the machine has (MachineSpec, surfaced via sysinfo//proc//sys).
// If belief exceeds the ENFORCED reality, the host OOM-kills it or starves it.
// So a ResourceSpec both (a) drives the host-side enforcement and (b) DERIVES
// the MachineSpec the guest sees — belief == enforced reality by construction.
// This is the single-source-of-truth discipline extended one level up: author
// the policy once, and the limits AND the advertised machine move together.
#pragma once

#include "linuxity/kernel/machine.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace lx::kernel {

// The requested bound on the guest world. Every field is OPTIONAL: an unset
// field means "unbounded — inherit the host's global pool", which is the
// native-speed default (the guest is just another host process). A set field
// is a ceiling the host kernel enforces.
struct ResourceSpec {
    // CPU as a fraction of ONE logical core: 1.0 == one full core, 2.5 ==
    // two-and-a-half cores' worth of runtime per scheduling period, 0.5 ==
    // half a core. Maps to cgroup cpu.max = <quota> <period> with a 100ms
    // period. Unset == no CPU cap (host scheduler shares freely).
    std::optional<double>        cpus;

    // Hard memory ceiling in BYTES (cgroup memory.max). The host kernel
    // reclaims then OOM-kills the guest tree if it exceeds this. Unset ==
    // unbounded (host memory manager governs, same as any process).
    std::optional<std::uint64_t> mem_max;

    // Ceiling on memory+swap in BYTES (cgroup memory.swap.max is the SWAP-only
    // ceiling; we expose the intuitive combined number and derive swap =
    // swap_and_mem_max - mem_max). Unset == no swap bound.
    std::optional<std::uint64_t> swap_and_mem_max;

    // Max number of tasks in the guest tree (cgroup pids.max) — a fork-bomb
    // guard. Unset == unbounded.
    std::optional<std::uint64_t> pids_max;

    // Pin the guest tree to a set of physical CPUs (cgroup cpuset.cpus),
    // e.g. "0-1" or "0,2,4". Unset == all host CPUs eligible. cpuset is often
    // NOT delegated to unprivileged users, so this is best-effort.
    std::optional<std::string>   cpuset;

    [[nodiscard]] bool any() const {
        return cpus || mem_max || swap_and_mem_max || pids_max || cpuset;
    }

    // -- Belief derived from enforced reality ------------------------------
    // Fold this policy into `base` so the machine the guest SEES matches the
    // machine it is BOUNDED to. A program that sizes a cache to "half of RAM"
    // then fits inside memory.max; a runtime that starts one worker per CPU
    // then matches its CPU quota instead of oversubscribing. Fields left unset
    // in the policy keep `base`'s value (the host's real capacity).
    [[nodiscard]] MachineSpec advertise(MachineSpec base) const {
        if (mem_max) base.mem_total = *mem_max;
        if (cpus) {
            // Advertise the CEILING of the fractional quota as whole CPUs, at
            // least 1 — a runtime keys its thread pool off an integer count,
            // and rounding up lets a 1.5-core budget still use 2 threads that
            // the quota then time-slices, rather than pinning it to 1.
            double c = *cpus;
            long n = static_cast<long>(c <= 0.0 ? 1.0 : c);
            if (static_cast<double>(n) < c) ++n;   // ceil
            base.ncpu = n < 1 ? 1 : n;
        }
        base.normalize();
        return base;
    }

    // cgroup cpu.max period we standardize on (100ms, the kernel default).
    static constexpr std::uint64_t kCpuPeriodUs = 100'000;

    // The cpu.max quota (microseconds of runtime per period) for `cpus`.
    [[nodiscard]] std::uint64_t cpu_quota_us() const {
        double c = cpus.value_or(0.0);
        if (c <= 0.0) return 0;
        return static_cast<std::uint64_t>(c * static_cast<double>(kCpuPeriodUs));
    }
};

// Parse a human size like "512M", "2G", "1500k", "1073741824" into bytes.
// Returns nullopt on a malformed string. Suffixes are binary (K=1024).
[[nodiscard]] inline std::optional<std::uint64_t> parse_bytes(std::string_view s) {
    if (s.empty()) return std::nullopt;
    std::uint64_t mult = 1;
    char last = s.back();
    switch (last) {
        case 'k': case 'K': mult = std::uint64_t{1} << 10; s.remove_suffix(1); break;
        case 'm': case 'M': mult = std::uint64_t{1} << 20; s.remove_suffix(1); break;
        case 'g': case 'G': mult = std::uint64_t{1} << 30; s.remove_suffix(1); break;
        case 't': case 'T': mult = std::uint64_t{1} << 40; s.remove_suffix(1); break;
        default: break;
    }
    if (s.empty()) return std::nullopt;
    std::uint64_t v = 0;
    for (char ch : s) {
        if (ch < '0' || ch > '9') return std::nullopt;
        v = v * 10 + static_cast<std::uint64_t>(ch - '0');
    }
    return v * mult;
}

} // namespace lx::kernel
