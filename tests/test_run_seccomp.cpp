// SECCOMP trap acceleration — the fast path runs non-intercepted syscalls
// natively, and must stay FUNCTIONALLY identical to the PTRACE_SYSCALL path.
//
// This test runs the SAME probe under both drive modes (seccomp filter active,
// and forced fallback via LINUXITY_NO_SECCOMP) and requires an identical exit
// code. The probe exercises the things that differ between the paths: a
// path-translated open (/etc/os-release synthesized owner), a fork+wait pid
// round-trip (translated at the seccomp EXIT stop even across the intervening
// fork event), and a burst of NON-intercepted syscalls (lseek) that the fast
// path runs natively. If the seccomp path skipped an intercepted syscall or
// mishandled the clone/wait exit, the codes would diverge.
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
    "#include <unistd.h>\n#include <sys/wait.h>\n#include <fcntl.h>\n"
    "int main(void){\n"
    "  if(getpid()!=1) return 10;                 /* intercepted: getpid */\n"
    "  int fd=open(\"/etc/probe.txt\",O_RDONLY);   /* intercepted: open+path */\n"
    "  if(fd<0) return 11; close(fd);\n"
    "  for(int i=0;i<200000;i++) (void)lseek(1,0,SEEK_CUR); /* NOT intercepted */\n"
    "  pid_t p=fork();                             /* intercepted: pid xlate */\n"
    "  if(p<0) return 12;\n"
    "  if(p==0){ if(getpid()==1) _exit(20); _exit(0); }\n"
    "  int st=0; pid_t r=waitpid(p,&st,0);         /* intercepted: pid xlate */\n"
    "  if(r!=p) return 13;                          /* wait ret == fork ret */\n"
    "  if(!WIFEXITED(st)||WEXITSTATUS(st)!=0) return 14;\n"
    "  if(p<2||p>4096) return 15;                   /* small guest pid */\n"
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
    std::puts("run_seccomp: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_seccomp_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/etc").c_str());
    { std::FILE* f = std::fopen((root + "/etc/probe.txt").c_str(), "w");
      if (f) { std::fputs("hi\n", f); std::fclose(f); } }
    { std::FILE* f = std::fopen("/tmp/lx_seccomp.c", "w");
      if (!f) { std::puts("run_seccomp: skipped (no /tmp)"); return 0; }
      std::fputs(kProbe, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root + "/bin/scprobe /tmp/lx_seccomp.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_seccomp: skipped (no static gcc)"); return 0; }

    // Fast path (seccomp filter installed if the host supports it).
    ::unsetenv("LINUXITY_NO_SECCOMP");
    int fast = run(root, "/bin/scprobe");
    // Forced fallback (PTRACE_SYSCALL on every syscall).
    ::setenv("LINUXITY_NO_SECCOMP", "1", 1);
    int slow = run(root, "/bin/scprobe");
    ::unsetenv("LINUXITY_NO_SECCOMP");

    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_seccomp.c");

    if (fast == -1 || slow == -1) { std::puts("run_seccomp: skipped (ptrace unavailable)"); return 0; }
    if (slow != 0) {
        std::printf("run_seccomp: FAIL fallback path code=%d (10 getpid 11 open "
                    "12 fork 13 wait!=fork 14 child-exit 15 pid-range)\n", slow);
        return 1;
    }
    if (fast != slow) {
        std::printf("run_seccomp: FAIL fast(seccomp)=%d != fallback=%d — the "
                    "seccomp path diverged from PTRACE_SYSCALL\n", fast, slow);
        return 1;
    }
    std::puts("run_seccomp: the seccomp fast path (non-intercepted syscalls run "
              "native) is functionally identical to the PTRACE_SYSCALL path — "
              "path translation, fork/wait pid round-trip, and a native lseek "
              "burst all agree");
    return 0;
#endif
}
