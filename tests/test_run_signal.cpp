// End-to-end SIGNAL delivery across the guest process tree.
//
// A guest's kill(2)/tgkill(2)/tkill(2) names a pid in LINUXITY's namespace,
// which is unrelated to host pids — forwarding the raw number would signal an
// arbitrary host task. The runtime instead translates the target to the real
// host tid of the traced guest task and delivers the signal THERE.
//
// This test proves it: a static 'signaller' forks a child that blocks in
// pause(), the parent sends it SIGTERM, then waits. If the signal reached the
// child, wait4 reports WIFSIGNALED with SIGTERM and the program exits 0; if
// the signal went nowhere, the child never dies and the harness times out /
// the child returns a non-signalled status. No shell needed in the rootfs.
// Skips gracefully off Linux/x86-64, without static gcc, or without ptrace.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// fork a child that blocks forever in pause(); parent kills it with SIGTERM
// and reports success (exit 0) iff wait4 sees the child DIE FROM the signal.
static const char* kSignaller =
    "#include <unistd.h>\n#include <signal.h>\n#include <sys/wait.h>\n"
    "int main(void){\n"
    "  pid_t p=fork();\n"
    "  if(p==0){ for(;;) pause(); _exit(0); }\n"
    "  usleep(200000);\n"
    "  if(kill(p,SIGTERM)!=0) return 3;\n"
    "  int st=0; if(waitpid(p,&st,0)<0) return 4;\n"
    "  if(WIFSIGNALED(st) && WTERMSIG(st)==SIGTERM) return 0;\n"
    "  return 5;\n"
    "}\n";

static int run(const std::string& root, const std::string& prog) {
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc",
        vfs::make_procfs(k.procs(), "6.6.0-linuxity", "linuxity"));
    std::string exec = root + prog;
    runtime::PtraceTrap trap{exec, {prog}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};
    auto r = cpu.run(uaddr(0), uaddr(0));
    if (!r) return -1;   // ptrace unavailable
    return *r;
}

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_signal: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_sig_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/etc").c_str());
    { std::FILE* f = std::fopen("/tmp/lx_sig.c", "w");
      if (!f) { std::puts("run_signal: skipped (no /tmp)"); return 0; }
      std::fputs(kSignaller, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root + "/bin/signaller /tmp/lx_sig.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_signal: skipped (no static gcc)"); return 0; }

    int code = run(root, "/bin/signaller");

    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_sig.c");

    if (code == -1) { std::puts("run_signal: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_signal: FAIL child was not killed by SIGTERM (exit=%d)\n", code);
        return 1;
    }
    std::puts("run_signal: a guest kill(child, SIGTERM) was translated to the "
              "child's host tid and delivered - wait4 saw WIFSIGNALED(SIGTERM)");
    return 0;
#endif
}
