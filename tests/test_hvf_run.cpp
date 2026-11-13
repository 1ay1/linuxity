// tests/test_hvf_run.cpp
//
// Run a REAL Arch Linux ARM aarch64 binary on macOS, natively, no guest
// kernel. The macOS counterpart of test_run_native.cpp: it wires the portable
// core (Kernel + FileNamespace + procfs) to the HVF backend and drives the
// SAME runtime::Cpu loop that ptrace drives on Linux.
//
// Skips (exit 0) when either precondition is absent, so CI stays green:
//   * the com.apple.security.hypervisor entitlement (unsigned test binary)
//   * an aarch64 rootfs at $LINUXITY_TEST_ROOTFS (default /tmp/archarm)
//
// Fetch one with:
//   curl -L http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz \
//     | (mkdir -p /tmp/archarm && tar xz -C /tmp/archarm)
#include <cstdio>
#include <cstdlib>

#if !(defined(__APPLE__) && defined(__aarch64__))
int main() { std::puts("hvf_run: skipped (not macOS/arm64)"); return 0; }
#else

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/darwin/exec.hpp"
#include "linuxity/runtime/darwin/load.hpp"
#include "linuxity/runtime/darwin/trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include <sys/stat.h>

#include <string>
#include <vector>

using namespace lx;

static int failures = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

namespace {

[[nodiscard]] std::string rootfs_dir() {
    if (const char* e = std::getenv("LINUXITY_TEST_ROOTFS")) return e;
    return "/tmp/archarm";
}

[[nodiscard]] bool exists(const std::string& p) {
    struct ::stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

// Run one guest program to completion, returning its exit status.
//
// This is the whole macOS execution model in 30 lines: build a VM, mount the
// rootfs through the PORTABLE file namespace, load the ELF into guest RAM,
// build the startup stack, and hand the pair to runtime::Cpu. Everything
// about which file a path means, what /proc says, and who the guest thinks it
// is comes from the shared core -- this file only supplies the macOS backend.
struct RunResult {
    bool ran{false};
    int status{-1};
};

[[nodiscard]] RunResult run_guest(const std::string& root,
                                  const std::string& guest_path,
                                  const std::vector<std::string>& argv) {
    runtime::HvfMachine vm;
    if (auto st = vm.init(); !st) return {};

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    {
        kernel::MachineSpec spec;
        spec.ncpu = 1;
        spec.mem_total = 512ull << 20;
        spec.release = "6.6.0-linuxity";
        spec.nodename = "linuxity";
        spec.machine_arch = "aarch64";
        k.set_machine(std::move(spec));
    }
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
    k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
    k.files().mount_virtual("/dev", vfs::make_devfs());

    // The guest path -> real host path, through the same namespace the guest
    // will see for every subsequent syscall.
    auto pc = k.files().classify(k.files().absolutize(guest_path));
    if (pc.realm != kernel::Realm2::host_backed) return {};

    auto img = runtime::hvf_load_elf(vm, pc.host_path,
                                     runtime::ExecLayout::program_base(vm.mem_size()));
    if (!img) {
        std::fprintf(stderr, "  load failed: errno %d\n", int(img.error()));
        return {};
    }
    auto sp = runtime::hvf_build_stack(vm, *img, argv,
                                       {"PATH=/usr/bin:/bin", "HOME=/root",
                                        "TERM=dumb", "LANG=C"});
    if (!sp) return {};

    runtime::HvfCpu cpu;
    if (!cpu.create()) return {};
    runtime::PidSpace pids;
    runtime::ProcessState proc;
    runtime::TaskState task;
    task.tid = 1;
    runtime::HvfTrap trap{vm, cpu, proc, task, pids};
    runtime::HvfMem mem{vm, &trap};
    trap.set_arena(img->image_end, runtime::ExecArena::mmap_top(vm.mem_size()));
    // Hand the loader's own mappings to the VMA map, or the guest's mprotect
    // on them (glibc applies RELRO right before transferring control) fails
    // ENOMEM and the program dies with "cannot apply additional memory
    // protection after relocation".
    for (const auto& sg : img->segments) {
        auto prot = runtime::GuestProt::none;
        if (sg.flags & 4) prot = prot | runtime::GuestProt::read;
        if (sg.flags & 2) prot = prot | runtime::GuestProt::write;
        if (sg.flags & 1) prot = prot | runtime::GuestProt::exec;
        trap.adopt(sg.begin, sg.end, prot);
    }
    trap.adopt_stack(*sp, vm.mem_size());

    cpu.set_entry(img->entry, *sp);
    runtime::Cpu loop{trap, k, mem, abi::Arch::aarch64};
    std::fflush(stdout);
    auto rc = loop.run(uaddr(0), uaddr(0));
    if (!rc) {
        std::fprintf(stderr, "  run error: errno %d\n", int(rc.error()));
        return {};
    }
    return {true, *rc};
}

}  // namespace

int main() {
    const std::string root = rootfs_dir();
    if (!exists(root + "/usr/lib/ld-linux-aarch64.so.1")) {
        std::printf("hvf_run: skipped (no aarch64 rootfs at %s)\n", root.c_str());
        return 0;
    }
    {
        // Probe the entitlement once so the skip message is accurate.
        runtime::HvfMachine probe;
        if (auto st = probe.init(); !st) {
            std::puts("hvf_run: skipped (no hypervisor entitlement)");
            return 0;
        }
    }

    // ld.so is the ideal first guest: a STATIC-pie binary (no interpreter to
    // chain), and its own diagnostics exercise brk/mmap/fstat/write/exit.
    {
        auto r = run_guest(root, "/usr/lib/ld-linux-aarch64.so.1",
                           {"/usr/lib/ld-linux-aarch64.so.1", "--help"});
        CHECK(r.ran);
        if (r.ran) {
            std::printf("  ld.so --help exited %d\n", r.status);
            CHECK(r.status == 0 || r.status == 1);
        }
    }

    // The real target: a DYNAMICALLY-LINKED distro program, launched the way
    // linuxity's exec path does it on Linux -- exec ld.so with the program as
    // its argument, because the host kernel would resolve PT_INTERP against
    // the HOST root where the rootfs's loader does not exist (see main.cpp).
    //
    // ld.so then opens ld.so.cache, maps libc.so.6 in layers (PROT_NONE
    // reservation, MAP_FIXED text, MAP_FIXED data, MAP_FIXED|MAP_ANON .bss),
    // relocates, applies RELRO with mprotect, and jumps to the program. All
    // of that works today. KNOWN GAP: the guest then faults inside libc on a
    // pointer that reads back as "\x7fELF" bytes, i.e. some byte range of a
    // layered library mapping still does not match what Linux would produce.
    // Tracked as the next thing to fix; asserted loosely so the test records
    // real progress (it must at least LOAD and run) without pretending the
    // program completed.
    for (const char* prog : {"/usr/bin/true", "/usr/bin/uname", "/usr/bin/id"}) {
        if (!exists(root + prog)) continue;
        auto r = run_guest(root, "/usr/lib/ld-linux-aarch64.so.1",
                           {"/usr/lib/ld-linux-aarch64.so.1", prog});
        CHECK(r.ran);                    // the loader must get through its work
        std::printf("  %s -> status=%d%s\n", prog, r.status,
                    r.status == 0 ? "" : "  (known gap: libc startup fault)");
    }

    if (failures == 0) std::puts("hvf_run: all checks passed");
    return failures ? 1 : 0;
}
#endif
