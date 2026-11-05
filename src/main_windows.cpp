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
#include "linuxity/runtime/whp_load.hpp"
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

    // Translate the guest program path through the rootfs, if one was given.
    // This is the minimal stand-in for the file namespace: enough to load an
    // image out of a rootfs, but NOT the full path-translation the syscall
    // layer needs (that is the fd-table work still outstanding).
    const std::string program{args[i]};
    std::string host_path = program;
    if (!root.empty()) {
        host_path = root;
        if (!host_path.empty() && host_path.back() != '/' &&
            host_path.back() != '\\')
            host_path += '/';
        host_path += program.front() == '/' ? program.substr(1) : program;
    }

    std::vector<std::string> argv_guest{program};
    for (std::size_t a = i + 1; a < args.size(); ++a)
        argv_guest.emplace_back(args[a]);

    std::uint64_t ram = std::uint64_t(memory_mib) << 20;
    if (ram < WhpLayout::min_ram) {
        std::fprintf(stderr,
            "linuxity: --memory %u MiB is below the %llu MiB minimum this\n"
            "          backend's address-space layout needs\n",
            memory_mib,
            (unsigned long long)(WhpLayout::min_ram >> 20));
        return 2;
    }

    WhpMachine vm;
    if (auto st = vm.create(ram, 1); !st) {
        std::fprintf(stderr, "linuxity: could not create a %u MiB partition\n",
                     memory_mib);
        return 1;
    }

    auto img = whp_load_elf(vm, host_path, WhpLayout::pie_base(ram));
    if (!img) {
        std::fprintf(stderr, "linuxity: cannot load '%s'", host_path.c_str());
        if (img.error() == Errno::enoent)      std::fprintf(stderr, ": not found\n");
        else if (img.error() == Errno::enoexec) std::fprintf(stderr,
            ": not a native x86-64 Linux ELF\n"
            "          (this backend executes guest code on the host CPU, so\n"
            "          there is no cross-architecture emulation)\n");
        else std::fprintf(stderr, ": load failed\n");
        return 1;
    }

    // A dynamically linked program needs its interpreter loaded too, and
    // control must enter LD.SO, not the program -- ld.so relocates the image
    // and only then jumps to its entry. Reporting this rather than silently
    // entering the program (which would fault on its first PLT call) is the
    // difference between a clear limitation and a mystery crash.
    auto interp = whp_read_interp(host_path);
    if (interp && !interp->empty()) {
        std::fprintf(stderr,
            "linuxity: '%s' is dynamically linked (PT_INTERP=%s).\n"
            "          Loading the interpreter needs the guest fd table and\n"
            "          mmap service, which are not implemented yet; only\n"
            "          statically linked binaries run today.\n",
            program.c_str(), interp->c_str());
        return 69;
    }

    std::vector<std::string> envp{
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HOME=/root",
        "TERM=dumb",
        "LINUXITY=1",
    };

    auto sp = whp_build_stack(vm, *img, argv_guest, envp, 0, program);
    if (!sp) {
        std::fprintf(stderr, "linuxity: could not build the startup stack\n");
        return 1;
    }

    WhpCpu cpu;
    if (auto st = cpu.create(vm, 0); !st) {
        std::fprintf(stderr, "linuxity: could not create a vcpu\n");
        return 1;
    }

    WhpTrap trap{vm, cpu};
    if (auto st = trap.start(UAddr(img->entry), UAddr(*sp)); !st) {
        std::fprintf(stderr, "linuxity: could not enter long mode\n");
        return 1;
    }

    // The trap loop. The full runtime drives this through runtime::Cpu against
    // the portable kernel; here we service only the handful of syscalls that
    // need no fd table, so a static binary can actually run and report its
    // status. Anything else gets ENOSYS and is NAMED, so the next gap to
    // close is obvious rather than guessed at.
    TrapFrame f{};
    for (;;) {
        auto got = trap.next(f);
        if (!got) {
            switch (trap.stop_reason()) {
                case WhpStop::illegal:
                    std::fprintf(stderr, "linuxity: guest executed an illegal "
                                         "instruction (SIGILL)\n");
                    return 132;
                case WhpStop::fault:
                    std::fprintf(stderr, "linuxity: guest faulted at 0x%llx "
                                         "(SIGSEGV)\n",
                                 (unsigned long long)trap.fault_addr());
                    return 139;
                default:
                    std::fprintf(stderr, "linuxity: guest stopped "
                                         "unexpectedly (reason %d)\n",
                                 int(trap.stop_reason()));
                    return 1;
            }
        }
        if (!*got) break;   // exited

        const std::uint64_t nr = f.regs.nr;
        std::int64_t ret = -win32::LNOSYS;

        switch (nr) {
            case 60:    // exit
            case 231: { // exit_group
                return int(f.regs.arg[0] & 0xff);
            }
            case 1: {   // write(fd, buf, len) -- stdout/stderr only
                const std::uint64_t fd = f.regs.arg[0];
                const std::uint64_t buf = f.regs.arg[1];
                const std::uint64_t len = f.regs.arg[2];
                if (fd != 1 && fd != 2) { ret = -win32::LBADF; break; }
                std::vector<std::byte> tmp(static_cast<std::size_t>(len));
                const std::size_t n = vm.mem().copy_in(buf, tmp);
                if (n == 0 && len != 0) { ret = -win32::LFAULT; break; }
                std::fwrite(tmp.data(), 1, n, fd == 1 ? stdout : stderr);
                ret = std::int64_t(n);
                break;
            }
            case 20: {  // writev(fd, iov, cnt)
                const std::uint64_t fd = f.regs.arg[0];
                if (fd != 1 && fd != 2) { ret = -win32::LBADF; break; }
                std::int64_t total = 0;
                for (std::uint64_t k = 0; k < f.regs.arg[2]; ++k) {
                    GuestIovec iov{};
                    if (!vm.mem().get(f.regs.arg[1] + k * sizeof(GuestIovec), iov))
                        break;
                    if (iov.len == 0) continue;
                    std::vector<std::byte> tmp(static_cast<std::size_t>(iov.len));
                    const std::size_t n = vm.mem().copy_in(iov.base, tmp);
                    std::fwrite(tmp.data(), 1, n, fd == 1 ? stdout : stderr);
                    total += std::int64_t(n);
                }
                ret = total;
                break;
            }
            case 39:  ret = 1; break;            // getpid
            case 102: case 104: case 107: case 108:
                ret = 0; break;                  // getuid/getgid/geteuid/getegid
            case 158: ret = -win32::LINVAL; break;   // arch_prctl
            default:
                std::fprintf(stderr,
                    "linuxity: unimplemented syscall %llu "
                    "(needs the Win32 fd/mm layer)\n",
                    (unsigned long long)nr);
                ret = -win32::LNOSYS;
                break;
        }

        if (auto st = trap.resume(ret); !st) {
            std::fprintf(stderr, "linuxity: could not resume the guest\n");
            return 1;
        }
    }

    return trap.exit_code();
}
