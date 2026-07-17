// COHERENT TINY PID NAMESPACE — fork/wait return GUEST pids, not host pids.
//
// linuxity runs the guest tree natively via ptrace, so fork/clone/wait4 are
// FORWARDED and the host kernel puts a real HOST pid in the parent's return
// register. Left raw, that host pid leaks into the guest: an interactive shell
// prints six-digit host pids for $! and `jobs`, and `wait N` on a small guest
// pid never matches. The trap translates these returns to the guest's own tiny
// pid space (root == 1, children counting up) so the whole tree is coherent —
// the way a PID-namespace container is.
//
// This probe proves it without a shell:
//   * getpid() == 1                       (root is pid 1)
//   * a fork() child's getpid() is small  (2..999, a guest pid) and != 1
//   * the PARENT's fork() return equals that same small pid (not a host pid)
//   * wait4() returns that same small pid (translated on the reaping path)
// The child ships its own getpid() to the parent over a pipe so the parent can
// compare "the pid I was handed by fork" against "the pid the child sees for
// itself" — they MUST be equal and MUST be small. Exit 0 iff all hold.
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
    "#include <unistd.h>\n#include <sys/wait.h>\n#include <stdlib.h>\n"
    "int main(void){\n"
    "  if(getpid()!=1) return 10;               /* root is pid 1 */\n"
    "  int fds[2]; if(pipe(fds)!=0) return 11;\n"
    "  pid_t p=fork();\n"
    "  if(p<0) return 12;\n"
    "  if(p==0){\n"
    "     close(fds[0]);\n"
    "     pid_t me=getpid();\n"
    "     if(write(fds[1],&me,sizeof me)!=sizeof me) _exit(41);\n"
    "     _exit(0);\n"
    "  }\n"
    "  close(fds[1]);\n"
    "  pid_t child_self=-1;\n"
    "  if(read(fds[0],&child_self,sizeof child_self)!=sizeof child_self) return 13;\n"
    "  int st=0; pid_t r=waitpid(p,&st,0);\n"
    "  if(!WIFEXITED(st)||WEXITSTATUS(st)!=0) return 14;\n"
    "  /* fork's return, the child's own getpid, and wait's return all agree */\n"
    "  if(p!=child_self) return 20;             /* fork ret == child getpid */\n"
    "  if(r!=p) return 21;                       /* wait ret == fork ret */\n"
    "  /* and it's a small GUEST pid, not a leaked host pid */\n"
    "  if(p<2 || p>4096) return 22;\n"
    "  return 0;\n"
    "}\n";

static int run(const std::string& root, const std::string& prog) {
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
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
    std::puts("run_pid_namespace: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_pidns_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin").c_str());
    { std::FILE* f = std::fopen("/tmp/lx_pidns.c", "w");
      if (!f) { std::puts("run_pid_namespace: skipped (no /tmp)"); return 0; }
      std::fputs(kProbe, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root + "/bin/pidprobe /tmp/lx_pidns.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_pid_namespace: skipped (no static gcc)"); return 0; }

    int code = run(root, "/bin/pidprobe");
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_pidns.c");

    if (code == -1) { std::puts("run_pid_namespace: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_pid_namespace: FAIL code=%d "
                    "(10 root!=1 11 pipe 12 fork 13 read 14 child-exit "
                    "20 fork-ret!=child-getpid[host pid leaked] "
                    "21 wait-ret!=fork-ret 22 pid not in guest range)\n", code);
        return 1;
    }
    std::puts("run_pid_namespace: fork() hands the parent the child's own small "
              "GUEST pid (not a host pid), and wait4() reports the same pid — the "
              "whole tree lives in one coherent tiny pid space, so $!/jobs/wait "
              "are consistent");
    return 0;
#endif
}
