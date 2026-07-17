// linuxity — run a native Linux binary under the runtime.
//
//   linuxity <program> [args...]
//
// The program executes DIRECTLY on the host CPU (native speed). Only its
// syscalls trap back into the runtime, where our subsystems service them.
// This is the whole thesis, made runnable: no VM, no emulation, native code,
// our kernel.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"

#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>

extern char** environ;

int main(int argc, char** argv) {
    using namespace lx;

    // Optional: `--root <dir>` chroots the guest into an extracted rootfs
    // before running the program (the 'install any distro' entry point).
    std::string root;
    int i = 1;
    if (i + 1 < argc && std::string(argv[i]) == "--root") {
        root = argv[i + 1];
        i += 2;
    }

    if (i >= argc) {
        std::fprintf(stderr,
            "usage: %s [--root <rootfs-dir>] <program> [args...]\n"
            "  Runs a native Linux binary; its syscalls are serviced by the\n"
            "  linuxity runtime (native speed, no VM, no emulation).\n"
            "  --root mounts an extracted distro rootfs as the guest '/'.\n",
            argv[0]);
        return 2;
    }

    std::string path = argv[i];
    std::vector<std::string> gargv;
    for (int j = i; j < argc; ++j) gargv.emplace_back(argv[j]);

    // Inherit the host environment for the guest (PATH etc.), so real
    // programs behave; identity syscalls are still virtualized.
    std::vector<std::string> genvp;
    for (char** e = environ; e && *e; ++e) genvp.emplace_back(*e);

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    runtime::PtraceTrap trap{path, gargv, genvp, root};

    // PtraceTrap is BOTH the trap backend and the guest-memory accessor
    // (it shares the child's real pages via process_vm_readv/writev).
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto rc = cpu.run(uaddr(0), uaddr(0));
    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", int(rc.error()));
        return 1;
    }
    return *rc;
}
