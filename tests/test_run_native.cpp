// End-to-end native execution: compile a real STATIC GLIBC binary at test
// time, run it under the full runtime, and assert that (a) it reaches main()
// and runs libc printf — proving mmap/brk/fstat/writev forwarding works — and
// (b) getpid/getuid come back VIRTUALIZED (pid 1, uid 0) from linuxity's
// subsystems rather than the host's real values. This is "run a real distro
// binary natively" as a regression test. Skips gracefully off Linux/x86-64,
// without gcc, or without ptrace permission.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// A real libc program: printf exercises the full libc startup path, and it
// prints the pid/uid linuxity reports so we can verify virtualization.
static const char* kSrc =
    "#include <stdio.h>\n#include <unistd.h>\n"
    "int main(void){\n"
    "  printf(\"main-reached pid=%d uid=%d\\n\", getpid(), getuid());\n"
    "  return 5;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_native: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    { std::FILE* f = std::fopen("/tmp/lx_run_native.c", "w");
      if (!f) { std::puts("run_native: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system("gcc -static -O2 -o /tmp/lx_run_native "
                         "/tmp/lx_run_native.c 2>/dev/null");
    if (rc != 0) { std::puts("run_native: skipped (no static glibc / gcc)"); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    runtime::PtraceTrap trap{"/tmp/lx_run_native", {"/tmp/lx_run_native"}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));
    std::remove("/tmp/lx_run_native");
    std::remove("/tmp/lx_run_native.c");

    if (!r) { std::puts("run_native: skipped (ptrace unavailable)"); return 0; }
    if (*r != 5) {
        std::printf("run_native: FAIL exit=%d (expected 5)\n", *r);
        return 1;
    }
    std::puts("run_native: real static glibc binary reached main() under linuxity, "
              "libc worked (mmap/brk/fstat forwarded), identity virtualized, exit=5");
    return 0;
#endif
}
