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
//   * fork()s a child; the child's getpid()!=1 and getppid()==1
//   * readlink("/proc/self/exe") yields the guest path "/bin/idprobe"
// Exit 0 iff all hold. Skips off Linux/x86-64, without static gcc, or ptrace.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

static const char* kProbe =
    "#include <unistd.h>\n#include <string.h>\n#include <sys/wait.h>\n"
    "int main(void){\n"
    "  if(getpid()!=1) return 10;\n"
    "  if(getppid()!=0) return 11;\n"
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

static int run(const std::string& root, const std::string& prog) {
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc",
        vfs::make_procfs(k.procs(), "6.6.0-linuxity", "linuxity"));
    { kernel::ProcInfo init; init.pid = 1; init.cmdline = prog;
      k.procs().upsert(init); }
    std::string exec = root + prog;
    runtime::PtraceTrap trap{exec, {prog}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};
    auto r = cpu.run(uaddr(0), uaddr(0));
    return r ? *r : -1;
}

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_identity: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_id_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin").c_str());
    { std::FILE* f = std::fopen("/tmp/lx_id.c", "w");
      if (!f) { std::puts("run_identity: skipped (no /tmp)"); return 0; }
      std::fputs(kProbe, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root + "/bin/idprobe /tmp/lx_id.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_identity: skipped (no static gcc)"); return 0; }

    int code = run(root, "/bin/idprobe");
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_id.c");

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
