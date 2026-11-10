// src/run_windows.cpp -- the Windows host's host_run() (WHP).
//
// linuxity on Windows: run a Linux x86-64 distro's programs natively, with no
// VM kernel, no WSL, no Docker, and no administrator rights. The command line
// is src/main.cpp's, shared with every host (see host_run.hpp).
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
// See runtime/windows/vm.hpp for the mechanism and runtime/windows/trap.hpp for the
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
#include "linuxity/runtime/windows/api.hpp"
#include "linuxity/runtime/windows/load.hpp"
#include "linuxity/runtime/windows/sys.hpp"
#include "linuxity/runtime/windows/trap.hpp"
#include "linuxity/runtime/windows/vm.hpp"
#include "linuxity/runtime/windows/win32.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "host_run.hpp"
#include "options.hpp"

using namespace lx;
using namespace lx::runtime;
using lx::cli::Options;

namespace {

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
    const std::uint64_t stack = 0x80'0000;
    // The partition starts with nothing mapped, so ask for these two pages.
    if (!m.map_pages(code, 4096, true, true) ||
        !m.map_pages(stack - 4096, 4096, true, false)) {
        std::printf("  page tables       : FAILED to map\n");
        return 1;
    }
    auto dst = m.ram().at(code, sizeof(prog));
    if (dst.empty()) {
        std::printf("  guest RAM         : FAILED to address\n");
        return 1;
    }
    std::memcpy(dst.data(), prog, sizeof(prog));

    WhpTrap trap{m, cpu};
    if (auto st = trap.start(UAddr(code), UAddr(stack)); !st) {
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

const char* lx::cli::host_name() noexcept { return "windows (WHP)"; }

// --check: report whether this machine can host the backend.
int lx::cli::host_internal(const Options&, int, char** argv, int i) {
    return std::string_view{argv[i]} == "--check" ? check() : -1;
}

int lx::cli::host_run(Options& o, int, char**) {
    // The requirements, which on Windows are the part people get wrong.
    if (o.argv.empty()) {
        std::fputs("Requirements:\n"
                   "  * 64-bit x86 with virtualization enabled in firmware\n"
                   "  * the \"Windows Hypervisor Platform\" optional feature:\n"
                   "      dism /online /Enable-Feature /FeatureName:HypervisorPlatform /All\n"
                   "  linuxity --check reports what this machine supports.\n", stderr);
        return 2;
    }
    const std::string root = o.root;
    const bool verbose = o.verbose;
    const std::uint64_t memory_mib = o.res.mem_max.value_or(std::uint64_t{2048} << 20) >> 20;

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
    const std::string program = o.argv[0];
    std::string host_path = program;
    if (!root.empty()) {
        host_path = root;
        if (!host_path.empty() && host_path.back() != '/' &&
            host_path.back() != '\\')
            host_path += '/';
        host_path += program.front() == '/' ? program.substr(1) : program;
    }

    const std::vector<std::string>& argv_guest = o.argv;

    std::uint64_t ram = memory_mib << 20;
    if (ram < WhpLayout::min_ram) {
        std::fprintf(stderr,
            "linuxity: --memory %llu MiB is below the %llu MiB minimum this\n"
            "          backend's address-space layout needs\n",
            static_cast<unsigned long long>(memory_mib),
            static_cast<unsigned long long>(WhpLayout::min_ram >> 20));
        return 2;
    }

    WhpMachine vm;
    if (auto st = vm.create(ram, 1); !st) {
        std::fprintf(stderr, "linuxity: could not create a %llu MiB partition\n",
                     static_cast<unsigned long long>(memory_mib));
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

    // The syscall surface: fd table, memory manager, emulation layer.
    FdTable fds;
    // Guest fds start at 9, as they would in a real login session. See
    // FdTable::reserve_low_fds -- this prevents a descriptor-reuse collision
    // that corrupted a database on the macOS backend.
    fds.reserve_low_fds();

    WhpMm mm{vm};
    WhpSys sys{vm, mm, fds, root};

    // A dynamically linked program needs its interpreter loaded too, and
    // control must enter LD.SO, not the program: ld.so relocates the image,
    // maps its libraries, and only then jumps to the program's entry. Enter
    // the program directly and it faults on its first PLT call.
    std::uint64_t entry = img->entry;
    std::uint64_t at_base = 0;
    std::uint64_t highest_end = img->image_end;
    std::vector<WhpImage::Segment> all_segments = img->segments;

    auto interp = whp_read_interp(host_path);
    if (interp && !interp->empty()) {
        // PT_INTERP is a GUEST path ("/lib64/ld-linux-x86-64.so.2"), so it
        // must be resolved through the rootfs like any other.
        const std::string interp_host = sys.host_path(*interp);
        auto ld = whp_load_elf(vm, interp_host, WhpLayout::interp_base(ram));
        if (!ld) {
            std::fprintf(stderr,
                "linuxity: cannot load the dynamic linker '%s'\n"
                "          (resolved to '%s')\n"
                "          A rootfs containing it is needed: try --root.\n",
                interp->c_str(), interp_host.c_str());
            return 1;
        }
        // AT_BASE tells ld.so where IT was loaded, so it can relocate
        // itself; control enters ld.so's entry, not the program's.
        at_base = ld->load_bias;
        entry = ld->entry;
        highest_end = std::max(highest_end, ld->image_end);
        all_segments.insert(all_segments.end(), ld->segments.begin(),
                            ld->segments.end());
    }

    // brk starts above every loaded image; the mmap arena sits below the
    // stack. Both must be set before the guest runs, since libc calls brk
    // and mmap during startup.
    mm.init(highest_end, WhpLayout::mmap_top(ram));

    // Tell the VMA map about everything the LOADER mapped. ld.so mprotects
    // its own and the program's segments after relocating, and that is
    // refused for any range the map does not fully cover.
    for (const auto& sg : all_segments) {
        mm.adopt(sg.begin, sg.end, prot_from_elf(sg.flags), /*anonymous=*/false);
    }

    std::vector<std::string> envp{
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HOME=/root",
        "TERM=dumb",
        "LINUXITY=1",
    };

    auto sp = whp_build_stack(vm, *img, argv_guest, envp, at_base, program);
    if (!sp) {
        std::fprintf(stderr, "linuxity: could not build the startup stack\n");
        return 1;
    }

    // The stack is loader-mapped too, so it also needs adopting -- libc
    // queries and occasionally mprotects it.
    {
        const std::uint64_t top = WhpLayout::stack_top(ram);
        mm.adopt(top - WhpLayout::stack_size, top,
                 GuestProt(unsigned(GuestProt::read) | unsigned(GuestProt::write)),
                 /*anonymous=*/true);
    }

    WhpCpu cpu;
    if (auto st = cpu.create(vm, 0); !st) {
        std::fprintf(stderr, "linuxity: could not create a vcpu\n");
        return 1;
    }

    WhpTrap trap{vm, cpu};
    sys.bind_cpu(&cpu);
    if (auto st = trap.start(UAddr(entry), UAddr(*sp)); !st) {
        std::fprintf(stderr, "linuxity: could not enter long mode\n");
        return 1;
    }

    TrapFrame f{};
    for (;;) {
        auto got = trap.next(f);
        if (!got) {
            switch (trap.stop_reason()) {
                case WhpStop::fault: {
                    // A fault inside a known VMA is LAZY MEMORY we promised
                    // and have not backed yet -- fill it and resume. Only a
                    // fault with no mapping behind it is a real SIGSEGV.
                    // This is what makes overcommit work, so it is on the hot
                    // path for every program that touches its heap.
                    //
                    // A PROTECTION fault (present page, wrong permission) is
                    // never fixable by backing a page: the page is already
                    // there. Trying would spin forever re-faulting on the
                    // same instruction, so it goes straight to SIGSEGV --
                    // which is also the correct answer for a guest writing
                    // its own read-only text.
                    const std::uint64_t at = trap.fault_addr();
                    if (!trap.fault_was_protection() && mm.handle_fault(at)) {
                        // #PF is a FAULT: RIP still points at the faulting
                        // instruction, which must be RETRIED now that the
                        // page exists. So resume without touching RIP --
                        // unlike the syscall path, which steps over `syscall`.
                        continue;
                    }
                    std::fprintf(stderr,
                        "linuxity: guest faulted at 0x%llx (SIGSEGV)%s\n",
                        (unsigned long long)at,
                        trap.fault_was_protection() ? " [protection]" : "");
                    return 139;
                }
                case WhpStop::illegal:
                    std::fprintf(stderr, "linuxity: guest executed an illegal "
                                         "instruction (SIGILL)\n");
                    return 132;
                default:
                    // Surface the RAW WHP exit reason, not just our bucket:
                    // "reason 5" is useless when debugging, whereas
                    // MemoryAccess vs UnrecoverableException vs
                    // InvalidVpRegisterValue each point at a different bug.
                    std::fprintf(stderr,
                        "linuxity: guest stopped unexpectedly "
                        "(WHP exit reason 0x%x, rip=0x%llx)\n",
                        unsigned(cpu.last_exit().ExitReason),
                        (unsigned long long)cpu.last_exit().VpContext.Rip);
                    return 1;
            }
        }
        if (!*got) break;   // exited

        // Every syscall goes through the emulation layer. There is no host
        // Linux kernel to forward to, so this IS the kernel for the guest.
        const SysResult r = sys.service(f);
        if (r.exited) {
            std::fflush(stdout);
            return r.exit_status;
        }
        if (verbose && r.ret == -win32::LNOSYS)
            std::fprintf(stderr, "linuxity: ENOSYS for syscall %llu\n",
                         (unsigned long long)f.regs.nr);

        if (auto st = trap.resume(r.ret); !st) {
            std::fprintf(stderr, "linuxity: could not resume the guest\n");
            return 1;
        }
    }

    std::fflush(stdout);
    return trap.exit_code();
}
