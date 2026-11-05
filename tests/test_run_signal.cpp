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

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_signal: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("sig", /*overlay=*/false,
                                        "mkdir -p /tmp/lx_sig_root/etc",
                                        "/bin/signaller");
    if (!lxtest::compile_guest("run_signal", tree, kSignaller)) return 0;

    auto r = lxtest::run_guest(tree, [&](auto& k) {
        kernel::ProcInfo init;
        init.pid = 1;
        init.comm = "signaller";
        init.cmdline = tree.exec;
        k.procs().upsert(init);
    });
    lxtest::remove_tree(tree);
    const int code = r ? *r : -1;

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
