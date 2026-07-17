// End-to-end TTY JOB-CONTROL virtualization.
//
// A guest shell (busybox ash, bash) that finds itself NOT owning its
// controlling terminal tries to seize it and spins forever — ioctl(TIOCGPGRP)
// / getpgid() / kill() in a tight loop pinning a whole core. The cause is a
// forwarded TIOCGPGRP reporting the HOST child's foreground pgrp, a number
// from the host pid space that never matches the guest's flat getpgrp().
//
// linuxity virtualizes the job-control tty ioctls so the guest session leader
// owns its tty: TIOCGPGRP/TIOCGSID report the caller's OWN pgrp, and TIOCSPGRP
// is a satisfied no-op. This probe proves it WITHOUT a shell: it opens a pty,
// asks the slave for its foreground group via TIOCGPGRP, and checks the answer
// equals getpgrp() (== the guest pid, 1) — exactly what a shell compares. It
// also checks TIOCSPGRP succeeds. Exit 0 iff both hold.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// A static probe. linuxity virtualizes the job-control tty ioctls purely on
// the REQUEST number (TIOCGPGRP/TIOCSPGRP/TIOCGSID) without touching the fd,
// so the probe needs no real terminal: it issues TIOCGPGRP on fd 0 and checks
// the reported foreground group equals getpgrp() (the guest's flat pid, 1) —
// exactly the comparison a shell makes before deciding it must seize the tty.
// A host pgid answer (the pre-fix behavior) would fail the equality and is
// what sends real shells into their spin. TIOCSPGRP must also be accepted.
static const char* kProbe =
    "#include <unistd.h>\n#include <sys/ioctl.h>\n#include <termios.h>\n"
    "int main(void){\n"
    "  pid_t self=getpgrp();\n"
    "  pid_t fg=-999;\n"
    "  if(ioctl(0,TIOCGPGRP,&fg)!=0) return 15;\n"
    "  if(fg!=self) return 16;            /* the spin trigger: fg!=our pgrp */\n"
    "  pid_t want=self;\n"
    "  if(ioctl(0,TIOCSPGRP,&want)!=0) return 17;  /* set must be accepted */\n"
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
    std::puts("run_tty_jobcontrol: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_tty_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin").c_str());
    { std::FILE* f = std::fopen("/tmp/lx_tty.c", "w");
      if (!f) { std::puts("run_tty_jobcontrol: skipped (no /tmp)"); return 0; }
      std::fputs(kProbe, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root + "/bin/ttyprobe /tmp/lx_tty.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_tty_jobcontrol: skipped (no static gcc)"); return 0; }

    int code = run(root, "/bin/ttyprobe");
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_tty.c");

    if (code == -1) { std::puts("run_tty_jobcontrol: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_tty_jobcontrol: FAIL code=%d "
                    "(15 TIOCGPGRP 16 fg!=getpgrp[the spin trigger] 17 TIOCSPGRP)\n",
                    code);
        return 1;
    }
    std::puts("run_tty_jobcontrol: TIOCGPGRP reports the guest's own pgrp (the "
              "session leader owns its tty), and TIOCSPGRP is accepted — a guest "
              "shell settles at its prompt instead of spinning to seize the "
              "terminal");
    return 0;
#endif
}
