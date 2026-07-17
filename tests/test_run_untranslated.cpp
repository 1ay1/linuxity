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
//   * inotify_add_watch("/etc/marker") -> succeeds against the ROOTFS inode
//                          (path translated to the overlay, not the host).
//   * name_to_handle_at    -> ENOTSUP (refused; would leak host inode identity).
//   * mount(...)           -> accepted as a satisfied no-op (returns 0).
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
    "#include <sys/inotify.h>\n"
    "#include <sys/mount.h>\n"
    "#include <errno.h>\n"
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
    "  /* inotify: adding a watch on the rootfs marker must translate the\n"
    "     path to the overlay and SUCCEED (>=0 watch descriptor). */\n"
    "  int ifd = inotify_init1(0);\n"
    "  if (ifd >= 0) {\n"
    "    int wd = inotify_add_watch(ifd, \"/etc/marker\", IN_MODIFY);\n"
    "    if (wd < 0) return 9;\n"
    "  }\n"
    "  /* name_to_handle_at must be refused (ENOTSUP), not leak a host handle. */\n"
    "  {\n"
    "    struct { struct file_handle h; char buf[128]; } fh;\n"
    "    fh.h.handle_bytes = 128; int mnt;\n"
    "    long rc = syscall(SYS_name_to_handle_at, AT_FDCWD, \"/etc/marker\",\n"
    "                      &fh.h, &mnt, 0);\n"
    "    if (rc == 0) return 10;              /* should NOT succeed */\n"
    "    if (errno != EOPNOTSUPP) return 11;  /* must be ENOTSUP */\n"
    "  }\n"
    "  /* mount must be accepted as a satisfied no-op (returns 0). */\n"
    "  if (mount(\"none\", \"/proc\", \"proc\", 0, 0) != 0) return 12;\n"
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
                      "openat2 read the ROOTFS, inotify path-translated, "
                      "name_to_handle_at refused, mount no-op'd, exit=7");
            return 0;
        case 3: std::puts("run_untranslated: FAIL statfs(/proc) leaked host fs magic"); return 1;
        case 4: std::puts("run_untranslated: FAIL statfs(/etc) did not redirect"); return 1;
        case 5: std::puts("run_untranslated: FAIL openat2 could not open rootfs marker"); return 1;
        case 8: std::puts("run_untranslated: FAIL openat2 read the HOST /etc, not the rootfs"); return 1;
        case 9: std::puts("run_untranslated: FAIL inotify_add_watch did not translate the path"); return 1;
        case 10: std::puts("run_untranslated: FAIL name_to_handle_at succeeded (host leak)"); return 1;
        case 11: std::puts("run_untranslated: FAIL name_to_handle_at wrong errno (not ENOTSUP)"); return 1;
        case 12: std::puts("run_untranslated: FAIL mount not accepted as no-op"); return 1;
        default:
            std::printf("run_untranslated: FAIL exit=%d (expected 7)\n", *r);
            return 1;
    }
#endif
}
