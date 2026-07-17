// End-to-end virtualized filesystem: build a static binary that opens
// "/etc/os-release", place it in a throwaway rootfs alongside a DISTINCT
// os-release, then run it under the full runtime with that rootfs mounted as
// the guest "/". Assert the guest reads the ROOTFS file, not the host's —
// proving unprivileged path translation at the syscall boundary (no chroot,
// no VM). Skips gracefully off Linux/x86-64, without gcc, or without ptrace.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// Opens the guest's /etc/os-release and writes its contents to stdout, then
// exits 5. Under the runtime, /etc/os-release must resolve inside the rootfs.
static const char* kSrc =
    "#include <fcntl.h>\n#include <unistd.h>\n"
    "int main(void){\n"
    "  char b[256];\n"
    "  int fd = open(\"/etc/os-release\", O_RDONLY);\n"
    "  if (fd < 0) return 2;\n"
    "  long n = read(fd, b, sizeof b);\n"
    "  if (n > 0) write(1, b, (unsigned long)n);\n"
    "  close(fd);\n"
    "  return 5;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_rootfs: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_rootfs_test";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/etc").c_str());

    // The rootfs os-release carries a marker string the HOST's cannot have.
    { std::FILE* f = std::fopen((root + "/etc/os-release").c_str(), "w");
      if (!f) { std::puts("run_rootfs: skipped (no /tmp)"); return 0; }
      std::fputs("ID=linuxity-rootfs-marker\n", f); std::fclose(f); }

    { std::FILE* f = std::fopen("/tmp/lx_rootfs_src.c", "w");
      if (!f) { std::puts("run_rootfs: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/reader /tmp/lx_rootfs_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_rootfs: skipped (no static glibc / gcc)"); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));

    // Translate the guest program path to its real host location under the
    // rootfs (the exec target is the one path the host kernel resolves).
    std::string exec = root + "/bin/reader";
    runtime::PtraceTrap trap{exec, {"/bin/reader"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    // Capture stdout to verify the guest read the rootfs file.
    std::fflush(stdout);
    std::FILE* cap = std::freopen("/tmp/lx_rootfs_out.txt", "w", stdout);
    (void)cap;
    auto r = cpu.run(uaddr(0), uaddr(0));
    std::fflush(stdout);
    std::freopen("/dev/tty", "w", stdout);  // best-effort restore

    std::string out;
    { std::FILE* f = std::fopen("/tmp/lx_rootfs_out.txt", "r");
      if (f) { char b[512]; std::size_t n = std::fread(b, 1, sizeof b, f);
               out.assign(b, n); std::fclose(f); } }

    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_rootfs_src.c");
    std::remove("/tmp/lx_rootfs_out.txt");

    if (!r) { std::puts("run_rootfs: skipped (ptrace unavailable)"); return 0; }
    if (*r != 5) { std::printf("run_rootfs: FAIL exit=%d (expected 5)\n", *r); return 1; }
    if (out.find("linuxity-rootfs-marker") == std::string::npos) {
        std::printf("run_rootfs: FAIL guest did not read the rootfs "
                    "/etc/os-release (got: %s)\n", out.c_str());
        return 1;
    }
    std::puts("run_rootfs: static binary under --root read the ROOTFS "
              "/etc/os-release via unprivileged path translation (no chroot), exit=5");
    return 0;
#endif
}
