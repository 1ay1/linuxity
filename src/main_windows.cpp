// src/main_windows.cpp
//
// linuxity on Windows: run a Linux x86-64 distro's programs natively, with no
// VM kernel, no WSL, no Docker, and no administrator rights.
//
//     linuxity --root C:\arch /usr/bin/bash
//
// HOW THIS WORKS, AND WHY IT IS NOT WSL
// -------------------------------------
// WSL1 put a Linux syscall layer inside the NT kernel (a driver, picoprocesses
// -- and it needed Microsoft to ship it). WSL2 boots a real Linux kernel in a
// VM. linuxity does neither: the guest's instructions execute BARE on the host
// CPU inside a kernel-less WHP partition at CPL 3, and every syscall traps back
// into this process, where the SAME portable core (kernel/, vfs/, abi/) that
// the Linux ptrace build and the macOS HVF build use services it.
//
// The interception is the interesting part. There is no ptrace on Windows that
// can catch a Linux `syscall`, and WHP has no syscall-exit reason. But on
// x86-64 the `syscall` instruction is only legal when IA32_EFER.SCE is set --
// with that one bit CLEAR it raises #UD, and WHP can route a chosen exception
// vector to the host as a VM exit. So:
//
//     EFER.SCE = 0  +  ExceptionExitBitmap |= (1 << 6)
//         => every guest syscall becomes a VM exit, delivered here, with the
//            guest stopped on the instruction and no guest kernel in sight.
//
// See runtime/whp_vm.hpp for the mechanism and runtime/whp_trap.hpp for the
// trap loop.
//
// STATUS
// ------
// The backend's CPU/memory/trap layers are implemented and tested
// (tests/test_whp.cpp exercises a live partition: it enters long mode, runs
// guest code natively, and decodes a real trapped syscall). What is NOT yet
// wired on this host is the Win32 side of the *emulation* surface that the
// kernel-less backends need in place of a host Linux kernel -- the fd table on
// Win32 handles, the ELF loader into guest-physical memory, and guest
// fork/exec as NT processes. On macOS those are hvf_fd/hvf_load/hvf_fork; the
// Windows equivalents are the remaining work, and this file reports that
// honestly rather than pretending to run a shell.
#include "linuxity/host/win_posix.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/whp_api.hpp"
#include "linuxity/runtime/whp_trap.hpp"
#include "linuxity/runtime/whp_vm.hpp"
#include "linuxity/runtime/whp_win32.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

using namespace lx;
using namespace lx::runtime;

namespace {

void usage() {
    std::fputs(
        "usage: linuxity [--root DIR] [--memory MiB] [--check] PROGRAM [ARGS...]\n"
        "\n"
        "Run a Linux x86-64 program natively on this PC (no VM kernel, no WSL).\n"
        "\n"
        "  --root DIR     an extracted distro rootfs to use as the guest '/'\n"
        "  --memory MiB   guest RAM (default 2048)\n"
        "  --check        report whether this machine can host the backend,\n"
        "                 and what the hypervisor supports, then exit\n"
        "\n"
        "Requirements:\n"
        "  * 64-bit x86 with virtualization enabled in firmware\n"
        "  * the \"Windows Hypervisor Platform\" optional feature:\n"
        "      dism /online /Enable-Feature /FeatureName:HypervisorPlatform /All\n"
        "    (or: Settings -> Optional Features -> More Windows features)\n",
        stderr);
}

// Report what this machine can actually do. Worth its own flag: every
// failure mode here is an environment problem with a specific fix, and a
// user staring at "cannot create partition" deserves to be told which.
int check() {
    std::printf("linuxity WHP backend check\n");

    std::printf("  WinHvPlatform.dll : %s\n",
                whp().ok() ? "loaded" : whp().why);
    if (!whp().ok()) {
        std::printf("\n  Fix: enable the Windows Hypervisor Platform feature:\n"
                    "    dism /online /Enable-Feature "
                    "/FeatureName:HypervisorPlatform /All\n");
        return 1;
    }

    const bool hv = hypervisor_present();
    std::printf("  hypervisor running: %s\n", hv ? "yes" : "no");
    if (!hv) {
        std::printf("\n  Fix: enable virtualization (VT-x/AMD-V) in firmware,\n"
                    "       and ensure Hyper-V/WHP is enabled in Windows.\n");
        return 1;
    }

    const bool exc = exception_exit_supported();
    std::printf("  exception VM exits: %s%s\n", exc ? "yes" : "no",
                exc ? "  (the #UD syscall trap is available)" : "");
    if (!exc) {
        std::printf("\n  This hypervisor cannot deliver exception exits, which\n"
                    "  the syscall trap requires. Windows 10 1803 or newer is\n"
                    "  needed.\n");
        return 1;
    }

    // Prove it rather than asserting it: build a real partition, enter long
    // mode, and trap one syscall out of natively-executed guest code.
    WhpMachine m;
    if (auto st = m.create(16 << 20, 1); !st) {
        std::printf("  partition         : FAILED to create\n");
        return 1;
    }
    std::printf("  partition         : created (16 MiB guest RAM)\n");

    WhpCpu cpu;
    if (auto st = cpu.create(m, 0); !st) {
        std::printf("  vcpu              : FAILED to create\n");
        return 1;
    }

    // mov eax, 60 (__NR_exit); mov edi, 42; syscall
    const unsigned char prog[]{0xb8, 0x3c, 0x00, 0x00, 0x00,
                               0xbf, 0x2a, 0x00, 0x00, 0x00,
                               0x0f, 0x05};
    const std::uint64_t code = 0x40'0000;
    auto dst = m.ram().at(code, sizeof(prog));
    if (dst.empty()) {
        std::printf("  guest RAM         : FAILED to address\n");
        return 1;
    }
    std::memcpy(dst.data(), prog, sizeof(prog));

    WhpTrap trap{m, cpu};
    if (auto st = trap.start(UAddr(code), UAddr(0x80'0000)); !st) {
        std::printf("  long mode         : FAILED to enter\n");
        return 1;
    }
    std::printf("  long mode         : entered at CPL 3\n");

    TrapFrame f{};
    auto got = trap.next(f);
    if (!got || !*got) {
        std::printf("  syscall trap      : FAILED (stop reason %d)\n",
                    int(trap.stop_reason()));
        return 1;
    }
    std::printf("  syscall trap      : nr=%llu arg0=%llu  "
                "(guest ran natively, #UD routed here)\n",
                (unsigned long long)f.regs.nr,
                (unsigned long long)f.regs.arg[0]);

    std::printf("\n  This machine can host the WHP backend.\n");
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    std::vector<std::string_view> args(argv + 1, argv + argc);

    std::string root;
    unsigned memory_mib = 2048;
    std::size_t i = 0;
    for (; i < args.size(); ++i) {
        auto a = args[i];
        if (a == "--check") return check();
        if (a == "--help" || a == "-h") { usage(); return 0; }
        if (a == "--root" && i + 1 < args.size()) { root = args[++i]; continue; }
        if (a == "--memory" && i + 1 < args.size()) {
            memory_mib = unsigned(std::strtoul(std::string{args[++i]}.c_str(),
                                               nullptr, 10));
            continue;
        }
        if (!a.empty() && a[0] == '-') {
            std::fprintf(stderr, "linuxity: unknown option '%.*s'\n",
                         int(a.size()), a.data());
            usage();
            return 2;
        }
        break;  // PROGRAM
    }

    if (i >= args.size()) { usage(); return 2; }

    // Refuse early and precisely if the host cannot do this at all, rather
    // than failing deep inside partition setup.
    if (const char* why = whp_unavailable_reason(); std::strcmp(why, "ok") != 0) {
        std::fprintf(stderr, "linuxity: %s\n", why);
        std::fprintf(stderr, "linuxity: run 'linuxity --check' for details.\n");
        return 1;
    }

    // The CPU, memory and trap layers are ready; the Win32 fd/loader/exec
    // layers are not. Say exactly that -- a misleading partial run would be
    // worse than a clear message.
    std::fprintf(stderr,
        "linuxity: the WHP backend's CPU/memory/trap layers are in place\n"
        "          (verify with 'linuxity --check'), but executing a rootfs\n"
        "          program additionally needs the Win32 fd table, the ELF\n"
        "          loader into guest-physical memory, and guest fork/exec as\n"
        "          NT processes. Those are not implemented yet.\n"
        "\n"
        "          requested: program=%.*s root=%s memory=%u MiB\n",
        int(args[i].size()), args[i].data(),
        root.empty() ? "(none)" : root.c_str(), memory_mib);
    return 69;  // EX_UNAVAILABLE
}
