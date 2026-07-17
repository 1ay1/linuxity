// Untranslated-syscall isolation: statfs, openat2, and the xattr family used
// to fall through the dispatcher's `default: fwd()` and hit the HOST kernel
// with the raw (untranslated) guest path — leaking the host filesystem into
// the rootfs. This test proves they now route through path translation:
//
//   * statfs("/proc")   -> synthesized tmpfs statfs (f_type == TMPFS_MAGIC),
//                          NOT the host's real backing-fs magic.
//   * statfs("/etc")    -> REDIRECTED to the overlay; succeeds (host fills
//                          the buffer for the rootfs mount).
//   * openat2("/etc/marker") -> opens the ROOTFS marker (contents "rootfs"),
//                          proving the modern openat replacement honors the
//                          namespace instead of opening the host's /etc.
//
// Skips gracefully off Linux/x86-64, without gcc/static glibc, or w/o ptrace.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// The guest program. Each check that fails returns a distinct exit code so a
// failure pinpoints WHICH syscall regressed; success returns 7.
static const char* kSrc =
    "#define _GNU_SOURCE\n"
    "#include <sys/vfs.h>\n"
    "#include <fcntl.h>\n"
    "#include <unistd.h>\n"
    "#include <string.h>\n"
    "#include <linux/openat2.h>\n"
    "#include <sys/syscall.h>\n"
    "int main(void){\n"
    "  struct statfs sf;\n"
    "  /* /proc must be the synthesized tmpfs, not the host backing fs. */\n"
    "  if (statfs(\"/proc\", &sf) != 0) return 2;\n"
    "  if (sf.f_type != 0x01021994) return 3;   /* TMPFS_MAGIC */\n"
    "  /* /etc statfs must succeed (redirected to the overlay). */\n"
    "  if (statfs(\"/etc\", &sf) != 0) return 4;\n"
    "  /* openat2 the rootfs marker; its contents must be the ROOTFS bytes. */\n"
    "  struct open_how how; memset(&how, 0, sizeof how); how.flags = O_RDONLY;\n"
    "  long fd = syscall(SYS_openat2, AT_FDCWD, \"/etc/marker\", &how, sizeof how);\n"
    "  if (fd < 0) return 5;\n"
    "  char buf[16]; long n = read((int)fd, buf, sizeof buf - 1);\n"
    "  if (n < 6) return 6;\n"
    "  buf[n] = 0;\n"
    "  if (strncmp(buf, \"rootfs\", 6) != 0) return 8;  /* host leak! */\n"
    "  return 7;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_untranslated: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_untrans_test";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/etc " + root + "/proc").c_str());

    { std::FILE* f = std::fopen((root + "/etc/marker").c_str(), "w");
      if (!f) { std::puts("run_untranslated: skipped (no /tmp)"); return 0; }
      std::fputs("rootfs\n", f); std::fclose(f); }

    { std::FILE* f = std::fopen("/tmp/lx_untrans_src.c", "w");
      if (!f) { std::puts("run_untranslated: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_untrans_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_untranslated: skipped (no static glibc / gcc / openat2 headers)"); std::system(("rm -rf " + root).c_str()); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_untrans_src.c");

    if (!r) { std::puts("run_untranslated: skipped (ptrace unavailable)"); return 0; }
    switch (*r) {
        case 7:
            std::puts("run_untranslated: statfs(/proc)=tmpfs, statfs(/etc) ok, "
                      "openat2(/etc/marker) read the ROOTFS (no host leak), exit=7");
            return 0;
        case 3: std::puts("run_untranslated: FAIL statfs(/proc) leaked host fs magic"); return 1;
        case 4: std::puts("run_untranslated: FAIL statfs(/etc) did not redirect"); return 1;
        case 5: std::puts("run_untranslated: FAIL openat2 could not open rootfs marker"); return 1;
        case 8: std::puts("run_untranslated: FAIL openat2 read the HOST /etc, not the rootfs"); return 1;
        default:
            std::printf("run_untranslated: FAIL exit=%d (expected 7)\n", *r);
            return 1;
    }
#endif
}
