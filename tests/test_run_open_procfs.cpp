// INJECT path-argument fix: opening a VIRTUAL file (e.g. /proc/stat) with the
// bare open(2) syscall — whose pathname is arg 0 (rdi), not arg 1 — must splice
// the backing temp path into the RIGHT register. A prior bug left the INJECT
// outcome's path_arg unset and the trap fell back to arg 1, corrupting the
// FLAGS register for open(2); every open()-based read of a /proc file failed
// flakily (btop "Failed to parse /proc/stat", busybox cat/ps). openat(2)
// callers (path_arg 1) coincidentally worked, which hid it. This test forces
// the raw open(2) path via syscall(SYS_open, ...) and asserts a clean read,
// repeated enough to catch the (formerly ~60%) flake. Skips gracefully off
// Linux/x86-64, without gcc, or without ptrace.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// Read /proc/stat via the RAW open(2) syscall (path in rdi), 32 times; exit 9
// iff every read returns bytes that start with "cpu". Any corrupted open would
// fail (negative fd) or read nothing, and we'd exit non-9.
static const char* kSrc =
    "#include <unistd.h>\n#include <sys/syscall.h>\n#include <string.h>\n"
    "int main(void){\n"
    "  for (int i = 0; i < 32; ++i) {\n"
    "    long fd = syscall(SYS_open, \"/proc/stat\", 0 /*O_RDONLY*/);\n"
    "    if (fd < 0) return 2;\n"
    "    char b[64]; long n = syscall(SYS_read, fd, b, sizeof b);\n"
    "    syscall(SYS_close, fd);\n"
    "    if (n < 3 || b[0] != 'c' || b[1] != 'p' || b[2] != 'u') return 3;\n"
    "  }\n"
    "  return 9;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_open_procfs: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_openprocfs_test";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/proc").c_str());

    { std::FILE* f = std::fopen("/tmp/lx_openprocfs_src.c", "w");
      if (!f) { std::puts("run_open_procfs: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_openprocfs_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_open_procfs: skipped (no static glibc / gcc)"); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_openprocfs_src.c");

    if (!r) { std::puts("run_open_procfs: skipped (ptrace unavailable)"); return 0; }
    if (*r == 2 || *r == 3) {
        std::printf("run_open_procfs: FAIL open(2) of /proc/stat corrupted "
                    "(exit=%d) — INJECT spliced the wrong register\n", *r);
        return 1;
    }
    if (*r != 9) {
        std::printf("run_open_procfs: FAIL exit=%d (expected 9)\n", *r);
        return 1;
    }
    std::puts("run_open_procfs: 32x raw open(2)+read of virtual /proc/stat "
              "all clean (INJECT path-arg spliced into rdi), exit=9");
    return 0;
#endif
}
