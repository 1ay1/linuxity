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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "linuxity/conform/arch.hpp"
#if defined(__APPLE__)
#include <mach/mach.h>
#include <unistd.h>
#endif

namespace lx::kernel {

class MachineSpec {
public:
    // -- CPU ---------------------------------------------------------------
    long          ncpu{1};                 // logical CPUs
    std::uint64_t cpu_hz{3'000'000'000};   // nominal core frequency, Hz

    // Show the host's real hardware (cpuinfo, disks, sensors, GPU, battery)
    // in /proc, /sys and /dev, falling back to the synthesized machine where
    // the host hides a node. The guest runs on that hardware, so it is the
    // truth. Off by default so tests see a fixed machine.
    bool          host_hw{false};
    // The host directory that is the guest's "/", for the mount table.
    std::string   root_host{"/"};
    // --bind mounts as (guest path, host dir), for the mount table.
    std::vector<std::pair<std::string, std::string>> binds;
    // Most tasks (processes + threads) the guest may have; 0 = no limit.
    // linuxity enforces it itself at fork/clone, so it holds on hosts with no
    // cgroups to delegate (Android).
    std::uint64_t task_limit{0};

    // -- Memory (bytes; the one canonical unit) ----------------------------
    std::uint64_t mem_total{std::uint64_t{2048} << 20};   // 2 GiB
    std::uint64_t swap_total{0};

    // -- Identity ----------------------------------------------------------
    std::string   release{"6.6.0-linuxity"};   // uname -r, /proc/version
    std::string   nodename{"linuxity"};        // hostname
    // uname -m. The guest runs natively, so this IS the host's ISA -- a
    // literal here told an aarch64 guest it was on x86_64, which breaks any
    // build system that picks a target triple from uname.
    std::string   machine_arch{conform::arch_name(conform::host_arch())};
    std::string   cpu_model{"linuxity native CPU"};   // /proc/cpuinfo model name
    std::string   cpu_part{"000"};             // arm64 MIDR part number (hex)
    // arm64 /proc/cpuinfo "Features". The guest runs NATIVELY, so this has to
    // describe the real CPU: libgcrypt and friends read it, pick an
    // instruction path from it, and a feature we claim but the CPU lacks is a
    // SIGILL. (gpg --import died exactly that way on a Snapdragon, because a
    // hardcoded Apple M-series list promised sha3/sha512.) main.cpp fills this
    // from the host's own cpuinfo; this default is the ARMv8.0 baseline every
    // arm64 Linux CPU has.
    std::string   cpu_features{"fp asimd evtstrm aes pmull sha1 sha2 crc32"};
    std::string   cpu_implementer{"0x41"};     // 0x41 = ARM Ltd
    std::string   cpu_architecture{"8"};

    // -- Time --------------------------------------------------------------
    // Wall-clock at boot (for /proc/stat btime); fixed so it is stable across
    // reads within a run. Uptime is measured live from a monotonic origin.
    std::int64_t  boot_wall{1'700'000'000};

    // Seconds since the HOST booted -- this machine's real uptime, which is
    // what `uptime`, /proc/uptime and screenfetch report on Linux. (Counting
    // from linuxity's own start showed "Uptime: 0m" on every run.) One
    // monotonic origin, captured once, still feeds /proc/uptime, /proc/stat
    // jiffies and sysinfo(2).uptime, so every clock a monitor reads agrees.
    [[nodiscard]] double uptime_seconds() const {
        static const double host_up_at_start = host_uptime_now();
        static const auto boot = std::chrono::steady_clock::now();
        return host_up_at_start + std::chrono::duration<double>(
                   std::chrono::steady_clock::now() - boot).count();
    }
    [[nodiscard]] static double host_uptime_now() {
#if defined(__APPLE__)
        // CLOCK_MONOTONIC on Darwin includes sleep and starts at boot.
        constexpr clockid_t kBootClock = CLOCK_MONOTONIC;
#elif defined(__linux__)
        constexpr clockid_t kBootClock = CLOCK_BOOTTIME;
#endif
#if defined(__APPLE__) || defined(__linux__)
        timespec ts{};
        if (::clock_gettime(kBootClock, &ts) == 0)
            return static_cast<double>(ts.tv_sec) + static_cast<double>(ts.tv_nsec) / 1e9;
#endif
        return 0.0;
    }

    // Wall-clock second the host booted: now - uptime, fixed at first use so
    // /proc/stat btime is stable across reads and agrees with /proc/uptime.
    [[nodiscard]] std::int64_t boot_epoch() const {
        static const std::int64_t b = [this] {
            const auto now = std::chrono::system_clock::now().time_since_epoch();
            const double s = std::chrono::duration<double>(now).count();
            const double up = host_uptime_now();
            return up > 0 ? static_cast<std::int64_t>(s - up) : boot_wall;
        }();
        return b;
    }

    // -- Derived views (so no caller repeats a unit conversion) ------------
    [[nodiscard]] long          cpu_khz()      const { return static_cast<long>(cpu_hz / 1000); }
    [[nodiscard]] double        cpu_mhz()      const { return static_cast<double>(cpu_hz) / 1e6; }
    [[nodiscard]] std::uint64_t mem_total_kb() const { return mem_total >> 10; }
    [[nodiscard]] std::uint64_t swap_total_kb()const { return swap_total >> 10; }
    // Free/available follow the HOST's real memory pressure, scaled to the
    // guest's size: the guest is a slice of this Mac, so it is as loaded as
    // the Mac is. (A fixed 50% never moved; capping host-free at mem_total
    // reported 0 used on any Mac with more free RAM than the guest's size.)
    // Cached for a second: monitors poll.
    [[nodiscard]] std::uint64_t mem_available()const {
#if defined(__linux__)
        if (const auto v = host_meminfo_kb("MemAvailable:")) return *v << 10;
#endif
        const double f = host_free_fraction();
        return static_cast<std::uint64_t>(static_cast<double>(mem_total) * f);
    }
    [[nodiscard]] std::uint64_t mem_free()     const {
#if defined(__linux__)
        if (const auto v = host_meminfo_kb("MemFree:")) return *v << 10;
#endif
        return mem_available() * 2 / 3;
    }
    [[nodiscard]] std::uint64_t mem_cached()   const {
#if defined(__linux__)
        if (const auto v = host_meminfo_kb("Cached:")) return *v << 10;
#endif
        return (mem_available() - mem_free()) * 3 / 4;
    }
    [[nodiscard]] std::uint64_t mem_buffers()  const {
#if defined(__linux__)
        if (const auto v = host_meminfo_kb("Buffers:")) return *v << 10;
#endif
        return mem_total / 128;
    }
    [[nodiscard]] std::uint64_t swap_free()    const {
#if defined(__linux__)
        if (const auto v = host_meminfo_kb("SwapFree:")) return *v << 10;
#endif
        return swap_total;
    }
    // One field of the host's /proc/meminfo, in kB, read live.
    [[nodiscard]] static std::optional<std::uint64_t> host_meminfo_kb(std::string_view key) {
        std::FILE* f = std::fopen("/proc/meminfo", "re");
        if (!f) return std::nullopt;
        char line[256];
        std::optional<std::uint64_t> out;
        while (std::fgets(line, sizeof line, f))
            if (std::string_view{line}.starts_with(key)) {
                out = std::strtoull(line + key.size(), nullptr, 10);
                break;
            }
        std::fclose(f);
        return out;
    }
    [[nodiscard]] double host_free_fraction() const {
        using clk = std::chrono::steady_clock;
        static std::atomic<double> cached{-1.0};
        static std::atomic<clk::rep> at{0};
        const auto now = clk::now().time_since_epoch().count();
        if (cached.load() >= 0 && now - at.load() < std::chrono::duration_cast<clk::duration>(
                std::chrono::seconds(1)).count())
            return cached.load();
        double v = 0.5;
#if defined(__APPLE__)
        vm_statistics64_data_t st{};
        mach_msg_type_number_t cnt = HOST_VM_INFO64_COUNT;
        if (::host_statistics64(::mach_host_self(), HOST_VM_INFO64,
                                reinterpret_cast<host_info64_t>(&st), &cnt) == KERN_SUCCESS) {
            const double avail = static_cast<double>(st.free_count) + st.inactive_count
                               + st.purgeable_count + st.speculative_count;
            const double total = avail + st.active_count + st.wire_count
                               + st.compressor_page_count;
            if (total > 0) v = std::clamp(avail / total, 0.05, 0.95);
        }
#endif
        cached.store(v); at.store(now);
        return v;
    }

    // "0-3"-style inclusive CPU range for /sys and cpuset listings.
    [[nodiscard]] std::string cpu_range() const {
        return ncpu <= 1 ? std::string{"0"} : "0-" + std::to_string(ncpu - 1);
    }

    void normalize() { if (ncpu < 1) ncpu = 1; if (cpu_hz == 0) cpu_hz = 1'000'000; }
};

} // namespace lx::kernel
