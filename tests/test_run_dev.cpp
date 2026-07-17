// A populated /dev: every real distro program assumes /dev/null, /dev/zero,
// /dev/urandom and the stdio nodes exist and behave. linuxity synthesizes a
// devtmpfs that REDIRECTS the character devices to the host's real nodes (true
// sink/source/CSPRNG semantics, native fds) and wires /dev/std{in,out,err} to
// /proc/self/fd/N. This test drives a static guest through those nodes and
// asserts each behaves; it also feeds a known byte on stdin and checks
// /dev/stdin reads it back. Skips gracefully off Linux/x86-64 or without gcc.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace lx;

// Returns 42 iff /dev behaves. Writes are swallowed by /dev/null, /dev/zero
// yields zeros, /dev/urandom yields bytes, /dev/stdin echoes the byte the test
// pipes in ('Z'), and /dev/stdout carries a marker byte to fd 1.
static const char* kSrc =
    "#include <fcntl.h>\n"
    "#include <unistd.h>\n"
    "#include <string.h>\n"
    "int main(void){\n"
    "  int n = open(\"/dev/null\", O_WRONLY);\n"
    "  if (n < 0) return 1;\n"
    "  if (write(n, \"discarded\", 9) != 9) return 2;\n"    // sink accepts all
    "  close(n);\n"
    "  int z = open(\"/dev/zero\", O_RDONLY);\n"
    "  if (z < 0) return 3;\n"
    "  char zb[8]; memset(zb, 0xAA, sizeof zb);\n"
    "  if (read(z, zb, 8) != 8) return 4;\n"
    "  for (int i=0;i<8;i++) if (zb[i]!=0) return 5;\n"     // all zeros
    "  close(z);\n"
    "  int u = open(\"/dev/urandom\", O_RDONLY);\n"
    "  if (u < 0) return 6;\n"
    "  char ub[16]; if (read(u, ub, 16) != 16) return 7;\n" // bytes flow
    "  close(u);\n"
    "  int in = open(\"/dev/stdin\", O_RDONLY);\n"
    "  if (in < 0) return 8;\n"
    "  char c; if (read(in, &c, 1) != 1) return 9;\n"
    "  if (c != 'Z') return 10;\n"                          // piped byte echoes
    "  close(in);\n"
    "  int out = open(\"/dev/stdout\", O_WRONLY);\n"
    "  if (out < 0) return 11;\n"
    "  if (write(out, \"K\", 1) != 1) return 12;\n"         // marker to fd 1
    "  close(out);\n"
    "  return 42;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_dev: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_dev_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin").c_str());

    { std::FILE* f = std::fopen("/tmp/lx_dev_src.c", "w");
      if (!f) { std::puts("run_dev: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_dev_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_dev: skipped (no static glibc / gcc)"); return 0; }

    // Pipe a known byte 'Z' into the guest's stdin so /dev/stdin can echo it.
    int p[2];
    if (::pipe(p) != 0) { std::puts("run_dev: skipped (no pipe)"); return 0; }
    (void)!::write(p[1], "Z", 1);
    ::close(p[1]);
    int saved_stdin = ::dup(0);
    ::dup2(p[0], 0);
    ::close(p[0]);

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
    k.files().mount_virtual("/dev", vfs::make_devfs());

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));

    ::dup2(saved_stdin, 0);
    ::close(saved_stdin);
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_dev_src.c");

    if (!r) { std::puts("run_dev: skipped (ptrace unavailable)"); return 0; }
    if (*r != 42) {
        std::printf("run_dev: FAIL guest exit=%d (expected 42; a /dev node "
                    "misbehaved)\n", *r);
        return 1;
    }
    std::puts("run_dev: /dev/{null,zero,urandom,stdin,stdout} all behave — "
              "sink/zeros/entropy, piped stdin echoes, stdout reaches fd 1, exit=42");
    return 0;
#endif
}
