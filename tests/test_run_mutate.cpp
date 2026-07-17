// Namespace MUTATION: a package manager writes its whole world into the
// rootfs — mkdir, create+write, chmod, rename, symlink, chown (vacuous root
// no-op), unlink. Every path is a GUEST path that must be translated to the
// overlay UPPER host layer (never the host's own /usr, /etc), and the pristine
// lower rootfs must stay untouched. This test drives one static guest through
// the whole sequence and asserts each step succeeded end to end; it also
// checks, from the host side, that the writes landed in the upper layer and
// NOT in the read-only lower. Skips gracefully off Linux/x86-64, without gcc,
// or without ptrace.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/stat.h>

using namespace lx;

// The guest exercises the mutating-path family with libc wrappers and returns
// 42 iff every step succeeds. /base exists only in the read-only LOWER rootfs;
// creating children of it forces the overlay to mirror it into upper.
static const char* kSrc =
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "#include <fcntl.h>\n"
    "#include <sys/stat.h>\n"
    "int main(void){\n"
    "  if (mkdir(\"/base/pkg\", 0755) != 0) return 1;\n"
    "  if (mkdir(\"/base/pkg/bin\", 0755) != 0) return 2;\n"
    "  int fd = open(\"/base/pkg/bin/greet\", O_WRONLY|O_CREAT|O_TRUNC, 0644);\n"
    "  if (fd < 0) return 3;\n"
    "  if (write(fd, \"hello\\n\", 6) != 6) return 4;\n"
    "  close(fd);\n"
    "  if (chmod(\"/base/pkg/bin/greet\", 0755) != 0) return 5;\n"
    "  if (chown(\"/base/pkg/bin/greet\", 0, 0) != 0) return 6;\n"
    "  if (rename(\"/base/pkg/bin/greet\", \"/base/pkg/bin/hello\") != 0) return 7;\n"
    "  if (symlink(\"/base/pkg/bin/hello\", \"/base/pkg/link\") != 0) return 8;\n"
    "  char buf[128]; ssize_t n = readlink(\"/base/pkg/link\", buf, sizeof buf-1);\n"
    "  if (n <= 0) return 9; buf[n] = 0;\n"
    "  if (strcmp(buf, \"/base/pkg/bin/hello\") != 0) return 10;\n"
    "  char rd[16]; int rf = open(\"/base/pkg/bin/hello\", O_RDONLY);\n"
    "  if (rf < 0) return 11;\n"
    "  if (read(rf, rd, 6) != 6 || memcmp(rd, \"hello\\n\", 6) != 0) return 12;\n"
    "  close(rf);\n"
    "  if (unlink(\"/base/pkg/link\") != 0) return 13;\n"
    "  if (access(\"/base/pkg/link\", F_OK) == 0) return 14;\n"
    "  return 42;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_mutate: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root  = "/tmp/lx_mutate_root";
    const std::string upper = "/tmp/lx_mutate_upper";
    std::system(("rm -rf " + root + " " + upper +
                 " && mkdir -p " + root + "/bin " + root + "/base " + upper).c_str());

    { std::FILE* f = std::fopen("/tmp/lx_mutate_src.c", "w");
      if (!f) { std::puts("run_mutate: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_mutate_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_mutate: skipped (no static glibc / gcc)"); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root, upper);            // overlay: lower + upper
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));

    // Host-side invariants: the write landed in UPPER, the LOWER stayed clean.
    auto exists = [](const std::string& p) {
        struct ::stat st{}; return ::stat(p.c_str(), &st) == 0;
    };
    bool upper_has  = exists(upper + "/base/pkg/bin/hello");
    bool lower_clean = !exists(root + "/base/pkg");

    std::system(("rm -rf " + root + " " + upper).c_str());
    std::remove("/tmp/lx_mutate_src.c");

    if (!r) { std::puts("run_mutate: skipped (ptrace unavailable)"); return 0; }
    if (*r != 42) {
        std::printf("run_mutate: FAIL guest exit=%d (expected 42; a "
                    "mutating-path syscall failed)\n", *r);
        return 1;
    }
    if (!upper_has) {
        std::puts("run_mutate: FAIL the write did not land in the overlay upper layer");
        return 1;
    }
    if (!lower_clean) {
        std::puts("run_mutate: FAIL the pristine lower rootfs was mutated");
        return 1;
    }
    std::puts("run_mutate: mkdir/write/chmod/chown/rename/symlink/unlink all "
              "translate to the overlay upper layer, lower stays pristine, exit=42");
    return 0;
#endif
}
