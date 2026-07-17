// Owner scrub: a host-backed stat is REDIRECTED, so the host kernel fills the
// guest buffer with the HOST file's uid/gid (whatever user unpacked the
// rootfs). linuxity presents a root-owned world, so after the redirect the
// dispatcher rewrites the owner fields to 0. This test stats a rootfs file
// (owned on disk by the running non-root user) and asserts the guest sees
// uid==0 && gid==0 — proving the post-redirect scrub. Skips gracefully off
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

// stat("/etc/marker"); exit(uid==0 && gid==0 ? 7 : 3). Uses newfstatat via
// glibc's stat wrapper, exercising the redirect+scrub path end to end.
static const char* kSrc =
    "#include <sys/stat.h>\n"
    "int main(void){\n"
    "  struct stat st;\n"
    "  if (stat(\"/etc/marker\", &st) != 0) return 2;\n"
    "  return (st.st_uid == 0 && st.st_gid == 0) ? 7 : 3;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_stat_owner: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_statowner_test";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/etc").c_str());

    { std::FILE* f = std::fopen((root + "/etc/marker").c_str(), "w");
      if (!f) { std::puts("run_stat_owner: skipped (no /tmp)"); return 0; }
      std::fputs("x\n", f); std::fclose(f); }
    // The on-disk file is owned by whoever runs the test (typically NOT root);
    // that is precisely the host owner the scrub must hide.

    { std::FILE* f = std::fopen("/tmp/lx_statowner_src.c", "w");
      if (!f) { std::puts("run_stat_owner: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_statowner_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_stat_owner: skipped (no static glibc / gcc)"); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_statowner_src.c");

    if (!r) { std::puts("run_stat_owner: skipped (ptrace unavailable)"); return 0; }
    if (*r == 3) {
        std::puts("run_stat_owner: FAIL guest saw the HOST owner, not root");
        return 1;
    }
    if (*r != 7) {
        std::printf("run_stat_owner: FAIL exit=%d (expected 7)\n", *r);
        return 1;
    }
    std::puts("run_stat_owner: host-backed stat of a rootfs file reports "
              "uid=0 gid=0 (owner scrubbed to root), exit=7");
    return 0;
#endif
}
