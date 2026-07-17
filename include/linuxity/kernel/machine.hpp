// linuxity/kernel/machine.hpp
//
// The SINGLE SOURCE OF TRUTH for the virtual machine linuxity presents.
//
// A process/hardware monitor reads the same fact through many windows —
// sysinfo(2), sched_getaffinity(2), /proc/stat, /proc/cpuinfo, /proc/meminfo,
// /proc/uptime, /sys/devices/system/cpu, ... If each window hardcoded its own
// number, they would drift (2 GiB in /proc but 4 GiB from sysinfo) and the
// guest would see an incoherent machine. So every fact lives HERE, once, and
// every synthesizer takes a `const MachineSpec&` and reads from it. Change a
// value in one place and /proc, /sys, and the syscalls all move together.
//
// Facts are stored in their most natural units and DERIVED accessors convert
// (bytes <-> kB, Hz <-> kHz), so no caller repeats a unit conversion either.
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace lx::kernel {

class MachineSpec {
public:
    // -- CPU ---------------------------------------------------------------
    long          ncpu{1};                 // logical CPUs
    std::uint64_t cpu_hz{3'000'000'000};   // nominal core frequency, Hz

    // -- Memory (bytes; the one canonical unit) ----------------------------
    std::uint64_t mem_total{std::uint64_t{2048} << 20};   // 2 GiB
    std::uint64_t swap_total{0};

    // -- Identity ----------------------------------------------------------
    std::string   release{"6.6.0-linuxity"};   // uname -r, /proc/version
    std::string   nodename{"linuxity"};        // hostname
    std::string   machine_arch{"x86_64"};      // uname -m

    // -- Time --------------------------------------------------------------
    // Wall-clock at boot (for /proc/stat btime); fixed so it is stable across
    // reads within a run. Uptime is measured live from a monotonic origin.
    std::int64_t  boot_wall{1'700'000'000};

    // Seconds of virtual uptime since the runtime started. ONE monotonic
    // origin (captured on first call) feeds /proc/uptime, /proc/stat jiffies,
    // and sysinfo(2).uptime — so every clock a monitor reads agrees.
    [[nodiscard]] double uptime_seconds() const {
        static const auto boot = std::chrono::steady_clock::now();
        return std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - boot).count();
    }

    // -- Derived views (so no caller repeats a unit conversion) ------------
    [[nodiscard]] long          cpu_khz()      const { return static_cast<long>(cpu_hz / 1000); }
    [[nodiscard]] double        cpu_mhz()      const { return static_cast<double>(cpu_hz) / 1e6; }
    [[nodiscard]] std::uint64_t mem_total_kb() const { return mem_total >> 10; }
    [[nodiscard]] std::uint64_t swap_total_kb()const { return swap_total >> 10; }
    // A plausible free/available split so /proc/meminfo and sysinfo agree.
    [[nodiscard]] std::uint64_t mem_free()     const { return mem_total / 2; }
    [[nodiscard]] std::uint64_t mem_available()const { return mem_total * 3 / 4; }
    [[nodiscard]] std::uint64_t mem_cached()   const { return mem_total / 4; }
    [[nodiscard]] std::uint64_t mem_buffers()  const { return mem_total / 64; }

    // "0-3"-style inclusive CPU range for /sys and cpuset listings.
    [[nodiscard]] std::string cpu_range() const {
        return ncpu <= 1 ? std::string{"0"} : "0-" + std::to_string(ncpu - 1);
    }

    void normalize() { if (ncpu < 1) ncpu = 1; if (cpu_hz == 0) cpu_hz = 1'000'000; }
};

} // namespace lx::kernel
