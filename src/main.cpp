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

int main(int argc, char** argv) {
    using namespace lx;

    if (argc < 2) {
        std::fprintf(stderr,
            "usage: %s <program> [args...]\n"
            "  runs a native Linux binary; its syscalls are serviced by the\n"
            "  linuxity runtime (native speed, no VM, no emulation).\n",
            argv[0]);
        return 2;
    }

    std::string path = argv[1];
    std::vector<std::string> gargv;
    for (int i = 1; i < argc; ++i) gargv.emplace_back(argv[i]);

    // The host, the kernel (our virtual Linux), the trap backend, the CPU.
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    runtime::PtraceTrap trap{path, gargv};

    // PtraceTrap is BOTH the trap backend and the guest-memory accessor
    // (it shares the child's real pages via process_vm_readv/writev).
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    // entry/sp are supplied by the exec'd binary itself in this backend, so
    // we pass zero — the kernel set them up when it exec'd the ELF.
    auto rc = cpu.run(uaddr(0), uaddr(0));
    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", int(rc.error()));
        return 1;
    }
    return *rc;
}
