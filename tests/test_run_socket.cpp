// AF_UNIX socket path translation + PR_SET_DUMPABLE interception.
//
// The guest is NOT chroot'd when linuxity runs unprivileged (chroot(2) needs
// CAP_SYS_CHROOT), so a bind()/connect() with an absolute sun_path must have
// that path translated into the mounted root exactly like a file open — else
// the socket leaks onto the HOST filesystem and collides with stale host
// sockets (the bug that broke pacman-key --init / gpg-agent: "Address already
// in use", stat "Bad address").
//
// A security-conscious daemon (gpg-agent) also calls prctl(PR_SET_DUMPABLE,0),
// which makes its memory unreadable via BOTH process_vm_readv AND ptrace peek
// for an unprivileged tracer — so linuxity could no longer read the sockaddr
// to translate it. linuxity intercepts PR_SET_DUMPABLE as a no-op to stay able
// to inspect the guest.
//
// This test drives a static guest that: drops dumpable, binds an AF_UNIX
// socket at an ABSOLUTE guest path, and returns 42 on success. The harness
// then asserts the socket node materialized INSIDE the mounted root (host
// translation worked) and NOT at the literal host path.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace lx;

// Drops dumpable, then binds /run/test.sock (absolute guest path). Returns 42
// iff bind() succeeds.
static const char* kSrc =
    "#include <sys/prctl.h>\n"
    "#include <sys/socket.h>\n"
    "#include <sys/un.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "int main(void){\n"
    "  prctl(PR_SET_DUMPABLE, 0);\n"                 // mimic gpg-agent
    "  int fd = socket(AF_UNIX, SOCK_STREAM, 0);\n"
    "  if (fd < 0) return 1;\n"
    "  struct sockaddr_un a; memset(&a, 0, sizeof a);\n"
    "  a.sun_family = AF_UNIX;\n"
    "  strcpy(a.sun_path, \"/run/test.sock\");\n"
    "  unlink(\"/run/test.sock\");\n"
    "  if (bind(fd, (struct sockaddr*)&a, sizeof a) != 0) return 2;\n"
    "  return 42;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_socket: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_sock_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " +
                 root + "/run").c_str());

    { std::FILE* f = std::fopen("/tmp/lx_sock_src.c", "w");
      if (!f) { std::puts("run_socket: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_sock_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_socket: skipped (no static glibc / gcc)"); return 0; }

    // Ensure no leftover HOST socket at the literal path could mask a leak.
    (void)::unlink("/run/test.sock");

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto r = cpu.run(uaddr(0), uaddr(0));

    if (!r) {
        std::puts("run_socket: skipped (ptrace unavailable)");
        std::system(("rm -rf " + root).c_str());
        std::remove("/tmp/lx_sock_src.c");
        return 0;
    }

    bool guest_ok   = (*r == 42);
    // The socket must exist INSIDE the mounted root, not at the host path.
    struct ::stat st{};
    bool in_root    = (::stat((root + "/run/test.sock").c_str(), &st) == 0)
                      && S_ISSOCK(st.st_mode);
    bool host_leak  = (::stat("/run/test.sock", &st) == 0);

    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_sock_src.c");

    if (!guest_ok) {
        std::printf("run_socket: FAIL guest exit=%d (expected 42; bind failed "
                    "under PR_SET_DUMPABLE=0)\n", *r);
        return 1;
    }
    if (!in_root) {
        std::puts("run_socket: FAIL socket did NOT land inside the mounted "
                  "root — sun_path was not translated");
        return 1;
    }
    if (host_leak) {
        std::puts("run_socket: FAIL socket LEAKED to the host path "
                  "/run/test.sock");
        return 1;
    }
    std::puts("run_socket: AF_UNIX bind under PR_SET_DUMPABLE=0 translated into "
              "the mounted root (no host leak), guest exit=42");
    return 0;
#endif
}
