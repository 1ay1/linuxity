// End-to-end virtualized filesystem: build a static binary that opens
// "/etc/os-release", place it in a throwaway rootfs alongside a DISTINCT
// os-release, then run it under the full runtime with that rootfs mounted as
// the guest "/". Assert the guest reads the ROOTFS file, not the host's —
// proving unprivileged path translation at the syscall boundary (no chroot,
// no VM). Skips gracefully off Linux/x86-64, without gcc, or without ptrace.
#include "guest_harness.hpp"

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
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
    // The rootfs os-release carries a marker string the HOST's cannot have,
    // which is how we prove the guest read the ROOTFS file and not the host's.
    const auto tree = lxtest::make_tree("rootfs", /*overlay=*/false,
        "mkdir -p /tmp/lx_rootfs_root/etc"
        " && printf 'ID=linuxity-rootfs-marker\\n' > /tmp/lx_rootfs_root/etc/os-release",
        "/bin/reader");
    if (!lxtest::compile_guest("run_rootfs", tree, kSrc)) return 0;
    const std::string root = tree.root;

    // Capture stdout to verify the guest read the rootfs file.
    std::fflush(stdout);
    std::FILE* cap = std::freopen("/tmp/lx_rootfs_out.txt", "w", stdout);
    (void)cap;
    auto r = lxtest::run_guest(tree);
    std::fflush(stdout);
    std::freopen("/dev/tty", "w", stdout);  // best-effort restore

    std::string out;
    { std::FILE* f = std::fopen("/tmp/lx_rootfs_out.txt", "r");
      if (f) { char b[512]; std::size_t n = std::fread(b, 1, sizeof b, f);
               out.assign(b, n); std::fclose(f); } }

    lxtest::remove_tree(tree);
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
