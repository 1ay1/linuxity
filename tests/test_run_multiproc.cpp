// End-to-end MULTI-PROCESS virtualization: a shell forks and execs an
// external command, and BOTH the shell and its child must live inside
// linuxity's namespace — the child must NOT escape to the host filesystem.
// Build a rootfs with a static binary that reads /etc/os-release, plus a
// distinct marker os-release, then run it BOTH directly and via a forked
// shell child, and assert both read the ROOTFS file. Proves the ptrace trap
// traces the whole process tree without deadlocking on the parent's wait4.
// Skips gracefully off Linux/x86-64, without gcc, or without ptrace.
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

static const char* kReader =
    "#include <fcntl.h>\n#include <unistd.h>\n"
    "int main(void){ char b[256]; int fd=open(\"/etc/os-release\",O_RDONLY);\n"
    "  if(fd<0) return 2; long n=read(fd,b,sizeof b);\n"
    "  if(n>0) write(1,b,(unsigned long)n); close(fd); return 5; }\n";

// A tiny static 'forker' that execs the reader — models a shell spawning a
// child. Uses only fork/execve/waitpid so it needs no shell in the rootfs.
static const char* kForker =
    "#include <unistd.h>\n#include <sys/wait.h>\n"
    "int main(void){ pid_t p=fork();\n"
    "  if(p==0){ char* av[]={(char*)\"/bin/reader\",0}; execve(av[0],av,0); _exit(127); }\n"
    "  int st=0; waitpid(p,&st,0); return WIFEXITED(st)?WEXITSTATUS(st):1; }\n";

// Run one of the two guests and return what it printed. Takes the tree by
// value so each call can point `exec` at a different program.
static std::string run(lxtest::GuestTree tree, const std::string& prog) {
    tree.exec = prog;
    std::fflush(stdout);
    std::freopen("/tmp/lx_mp_out.txt", "w", stdout);
    auto r = lxtest::run_guest(tree, [&](auto& k) {
        kernel::ProcInfo init;
        init.pid = 1;
        init.cmdline = prog;
        k.procs().upsert(init);
    });
    std::fflush(stdout);
    std::freopen("/dev/tty", "w", stdout);
    if (!r) return "<skip>";
    std::string out;
    if (std::FILE* f = std::fopen("/tmp/lx_mp_out.txt", "r")) {
        char b[512]; std::size_t n = std::fread(b, 1, sizeof b, f);
        out.assign(b, n); std::fclose(f);
    }
    return out;
}

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_multiproc: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    // The rootfs os-release carries a marker the host's cannot have, so the
    // output proves BOTH the direct run and the forked child read the rootfs.
    const auto tree = lxtest::make_tree("mp", /*overlay=*/false,
        "mkdir -p /tmp/lx_mp_root/etc"
        " && printf 'ID=rootfs-marker-mp\\n' > /tmp/lx_mp_root/etc/os-release",
        "/bin/reader");
    if (!lxtest::compile_guest("run_multiproc", tree, kReader)) return 0;
    if (!lxtest::compile_extra("run_multiproc", tree, "/bin/forker", kForker))
        return 0;

    std::string direct = run(tree, "/bin/reader");
    std::string forked = run(tree, "/bin/forker");

    lxtest::remove_tree(tree);
    std::remove("/tmp/lx_mp_out.txt");

    if (direct == "<skip>" || forked == "<skip>") {
        std::puts("run_multiproc: skipped (ptrace unavailable)"); return 0;
    }
    if (direct.find("rootfs-marker-mp") == std::string::npos) {
        std::printf("run_multiproc: FAIL direct did not read rootfs (got: %s)\n", direct.c_str());
        return 1;
    }
    if (forked.find("rootfs-marker-mp") == std::string::npos) {
        std::printf("run_multiproc: FAIL forked child ESCAPED to host fs (got: %s)\n", forked.c_str());
        return 1;
    }
    std::puts("run_multiproc: a forked+exec'd child stayed inside linuxity's "
              "namespace and read the ROOTFS /etc/os-release (no host escape)");
    return 0;
#endif
}
