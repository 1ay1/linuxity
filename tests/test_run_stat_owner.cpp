// Owner scrub: a host-backed stat is REDIRECTED, so the host kernel fills the
// guest buffer with the HOST file's uid/gid (whatever user unpacked the
// rootfs). linuxity presents a root-owned world, so after the redirect the
// dispatcher rewrites the owner fields to 0. This test stats a rootfs file
// (owned on disk by the running non-root user) and asserts the guest sees
// uid==0 && gid==0 — proving the post-redirect scrub. Skips gracefully off
// Linux/x86-64, without gcc, or without ptrace.
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
    const auto tree = lxtest::make_tree("statowner", /*overlay=*/false,
                                        "mkdir -p /tmp/lx_statowner_root/etc");
    const std::string root = tree.root;

    { std::FILE* f = std::fopen((root + "/etc/marker").c_str(), "w");
      if (!f) { std::puts("run_stat_owner: skipped (no /tmp)"); return 0; }
      std::fputs("x\n", f); std::fclose(f); }
    // The on-disk file is owned by whoever runs the test (typically NOT root);
    // that is precisely the host owner the scrub must hide.

    if (!lxtest::compile_guest("run_stat_owner", tree, kSrc)) return 0;

    auto r = lxtest::run_guest(tree);
    lxtest::remove_tree(tree);

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
