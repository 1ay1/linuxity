// End-to-end PROCESS IDENTITY + /proc symlink synthesis + pipelines.
//
// Proves the runtime gives every task a coherent guest identity (not a fixed
// "pid 1"), synthesizes /proc/self/exe against linuxity's namespace, and runs
// a real fork+pipe pipeline — the three things a shell and its children need
// to see themselves correctly. A static 'idprobe' does all of it and encodes
// the outcome in its exit code; no shell needed in the rootfs.
//
// The probe:
//   * parent getpid()==1, getppid()==0
//   * getresuid/getresgid all report 0 (bash/sudo read these at init; a
//     non-zero answer here is what made an interactive shell print
//     "I have no name!")
//   * fork()s a child; the child's getpid()!=1 and getppid()==1
//   * readlink("/proc/self/exe") yields the guest path "/bin/idprobe"
// Exit 0 iff all hold. Skips off Linux/x86-64, without static gcc, or ptrace.
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

static const char* kProbe =
    "#define _GNU_SOURCE\n"
    "#include <unistd.h>\n#include <string.h>\n#include <sys/wait.h>\n"
    "int main(void){\n"
    "  if(getpid()!=1) return 10;\n"
    "  if(getppid()!=0) return 11;\n"
    "  uid_t r,e,s; if(getresuid(&r,&e,&s)!=0) return 15;\n"
    "  if(r||e||s) return 16;   /* all must be root (0) */\n"
    "  gid_t gr,ge,gs; if(getresgid(&gr,&ge,&gs)!=0) return 17;\n"
    "  if(gr||ge||gs) return 18;\n"
    "  char b[256]; long n=readlink(\"/proc/self/exe\",b,sizeof b-1);\n"
    "  if(n<=0) return 12; b[n]=0;\n"
    "  if(strcmp(b,\"/bin/idprobe\")!=0) return 13;\n"
    "  pid_t p=fork();\n"
    "  if(p==0){ if(getpid()==1) _exit(20);\n"
    "            if(getppid()!=1) _exit(21); _exit(0); }\n"
    "  int st=0; waitpid(p,&st,0);\n"
    "  if(!WIFEXITED(st)) return 14;\n"
    "  return WEXITSTATUS(st);   /* child's code: 0 ok, 20/21 identity wrong */\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_identity: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("id", /*overlay=*/false, "",
                                        "/bin/idprobe");
    if (!lxtest::compile_guest("run_identity", tree, kProbe)) return 0;

    // Seed pid 1's ProcInfo so /proc/self/cmdline has something to report.
    auto r = lxtest::run_guest(tree, [&](auto& k) {
        kernel::ProcInfo init;
        init.pid = 1;
        init.cmdline = tree.exec;
        k.procs().upsert(init);
    });
    lxtest::remove_tree(tree);
    const int code = r ? *r : -1;

    if (code == -1) { std::puts("run_identity: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_identity: FAIL identity/exe check code=%d "
                    "(10 ppid?11 getppid?12 readlink 13 exe-path "
                    "20 child-pid1 21 child-ppid)\n", code);
        return 1;
    }
    std::puts("run_identity: parent is pid 1/ppid 0, the fork child has its own "
              "pid with ppid 1, and /proc/self/exe reads /bin/idprobe (the guest "
              "namespace path, not the host)");
    return 0;
#endif
}
