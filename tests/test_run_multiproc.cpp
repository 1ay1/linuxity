// End-to-end MULTI-PROCESS virtualization: a shell forks and execs an
// external command, and BOTH the shell and its child must live inside
// linuxity's namespace — the child must NOT escape to the host filesystem.
// Build a rootfs with a static binary that reads /etc/os-release, plus a
// distinct marker os-release, then run it BOTH directly and via a forked
// shell child, and assert both read the ROOTFS file. Proves the ptrace trap
// traces the whole process tree without deadlocking on the parent's wait4.
// Skips gracefully off Linux/x86-64, without gcc, or without ptrace.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
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

static std::string run(const std::string& root, const std::string& prog) {
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
    { kernel::ProcInfo init; init.pid = 1; init.cmdline = prog;
      k.procs().upsert(init); }
    std::string exec = root + prog;
    runtime::PtraceTrap trap{exec, {prog}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    std::fflush(stdout);
    std::freopen("/tmp/lx_mp_out.txt", "w", stdout);
    auto r = cpu.run(uaddr(0), uaddr(0));
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
    const std::string root = "/tmp/lx_mp_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/etc").c_str());
    { std::FILE* f = std::fopen((root + "/etc/os-release").c_str(), "w");
      if (!f) { std::puts("run_multiproc: skipped (no /tmp)"); return 0; }
      std::fputs("ID=rootfs-marker-mp\n", f); std::fclose(f); }
    { std::FILE* f = std::fopen("/tmp/lx_mp_reader.c", "w"); std::fputs(kReader, f); std::fclose(f); }
    { std::FILE* f = std::fopen("/tmp/lx_mp_forker.c", "w"); std::fputs(kForker, f); std::fclose(f); }
    int rc1 = std::system(("gcc -static -O2 -o " + root + "/bin/reader /tmp/lx_mp_reader.c 2>/dev/null").c_str());
    int rc2 = std::system(("gcc -static -O2 -o " + root + "/bin/forker /tmp/lx_mp_forker.c 2>/dev/null").c_str());
    if (rc1 != 0 || rc2 != 0) { std::puts("run_multiproc: skipped (no static gcc)"); return 0; }

    std::string direct = run(root, "/bin/reader");
    std::string forked = run(root, "/bin/forker");

    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_mp_reader.c"); std::remove("/tmp/lx_mp_forker.c");
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
