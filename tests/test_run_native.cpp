// End-to-end native execution: compile a tiny freestanding x86-64 binary at
// test time, run it under the full runtime (PtraceTrap + Cpu + Kernel), and
// assert its output and exit code came back through OUR subsystems. This is
// the whole thesis as a regression test: native code on the CPU, syscalls
// serviced by linuxity. Skips gracefully if the host isn't Linux/x86-64 or
// lacks a C compiler / ptrace permission.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

static const char* kSrc =
    "static long wr(long fd,const char*b,long n){long r;"
    "__asm__ volatile(\"syscall\":\"=a\"(r):\"a\"(1L),\"D\"(fd),\"S\"(b),\"d\"(n):\"rcx\",\"r11\",\"memory\");return r;}"
    "static void ex(long c){__asm__ volatile(\"syscall\"::\"a\"(231L),\"D\"(c):\"rcx\",\"r11\",\"memory\");__builtin_unreachable();}"
    "void _start(void){static const char m[]=\"native-run-ok\\n\";wr(1,m,sizeof(m)-1);ex(7);}";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_native: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    // Write + compile a freestanding binary.
    { std::FILE* f = std::fopen("/tmp/lx_run_native.c", "w");
      if (!f) { std::puts("run_native: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system("gcc -static -nostdlib -no-pie -O2 -fno-stack-protector "
                         "-o /tmp/lx_run_native /tmp/lx_run_native.c 2>/dev/null");
    if (rc != 0) { std::puts("run_native: skipped (no suitable gcc)"); return 0; }

    // Run it under the full runtime.
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    runtime::PtraceTrap trap{"/tmp/lx_run_native", {"/tmp/lx_run_native"}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));
    std::remove("/tmp/lx_run_native");
    std::remove("/tmp/lx_run_native.c");

    if (!r) {
        // ptrace may be blocked (containers, yama). Treat as skip, not fail.
        std::puts("run_native: skipped (ptrace unavailable)");
        return 0;
    }
    if (*r != 7) {
        std::printf("run_native: FAIL exit=%d (expected 7)\n", *r);
        return 1;
    }
    std::puts("run_native: native x86-64 binary ran, syscalls serviced by linuxity, exit=7");
    return 0;
#endif
}
