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
#include "guest_harness.hpp"

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// A static probe. The job-control ioctls are answered in the guest's own
// namespace -- TIOCGPGRP/TIOCGSID report the caller's OWN pgrp/sid -- which is
// what stops a session leader spinning to seize a tty it already owns.
//
// But they are answered only for a fd the KERNEL agrees is a terminal we may
// ask about. That matters: on /dev/null the real kernel says ENOTTY, and
// linuxity used to return success for ANY fd, which the ioctls conformance
// probe caught by diffing against the live kernel.
//
// Both halves are checked here, and the tty half now MANUFACTURES its own
// terminal: setsid() + open(slave) + TIOCSCTTY is a real claim, because the
// ctty is linuxity's own bookkeeping (ProcessTable::set_ctty) rather than a
// forwarded ioctl. It used to be forwarded, which the host refused -- on
// Android every TIOCSCTTY was EPERM, so the guest never owned a terminal,
// TIOCGPGRP answered ENOTTY and bash printed "cannot set terminal process
// group" then turned job control off. Claiming a fresh pty here is what
// keeps that fixed.
static const char* kProbe =
    "#define _GNU_SOURCE\n"
    "#include <stdio.h>\n#include <stdlib.h>\n#include <fcntl.h>\n"
    "#include <unistd.h>\n#include <sys/ioctl.h>\n#include <termios.h>\n"
    "#include <signal.h>\n"
    "int main(void){\n"
    // Leaving the harness's session detaches us from its terminal, and the
    // master end closing later raises SIGHUP. We are testing ioctls, not
    // hangup delivery, so ignore it rather than dying at exit.
    "  signal(SIGHUP,SIG_IGN);\n"
    "  pid_t fg=-999;\n"
    // Make our own session and our own terminal, so the test does not
    // depend on what the harness inherited.
    "  int m=posix_openpt(O_RDWR|O_NOCTTY);\n"
    "  if(m<0) return 10;\n"
    "  if(grantpt(m)||unlockpt(m)) return 11;\n"
    "  char* sn=ptsname(m); if(!sn) return 12;\n"
    "  if(setsid()<0) return 13;\n"
    "  int s=open(sn,O_RDWR); if(s<0) return 14;\n"
    // A session leader opening a tty without O_NOCTTY acquires it; the
    // explicit claim must also succeed (and be idempotent).
    "  if(ioctl(s,TIOCSCTTY,0)!=0) return 23;\n"
    "  pid_t self=getpgrp();\n"
    "  if(ioctl(s,TIOCGPGRP,&fg)!=0) return 15;\n"
    "  if(fg!=self) return 16;          /* the spin trigger: fg!=our pgrp */\n"
    "  pid_t want=self;\n"
    "  if(ioctl(s,TIOCSPGRP,&want)!=0) return 17;\n"
    "  if(ioctl(s,TIOCGPGRP,&fg)!=0||fg!=want) return 20;\n"
    // Our own sid, and /dev/tty must now resolve to THIS terminal.
    "  pid_t sid=-1;\n"
    "  if(ioctl(s,TIOCGSID,&sid)!=0) return 24;\n"
    "  if(sid!=getsid(0)) return 25;\n"
    "  int t=open(\"/dev/tty\",O_RDWR);\n"
    "  if(t<0) return 26;\n"
    "  if(!isatty(t)) return 27;\n"
    // Giving it up must stick: the session ioctls go back to ENOTTY.
    "  if(ioctl(s,TIOCNOTTY,0)!=0) return 28;\n"
    "  if(ioctl(s,TIOCGPGRP,&fg)==0) return 29;\n"
    // The negative half always holds: a non-tty must be ENOTTY, not a
    // fabricated success. This is the part that was wrong before.
    "  int n=open(\"/dev/null\",O_RDONLY);\n"
    "  if(n<0) return 21;\n"
    "  if(ioctl(n,TIOCGPGRP,&fg)==0) return 19;\n"
    "  if(ioctl(n,TIOCSPGRP,&self)==0) return 22;\n"
    "  return 0;\n"
    "}\n";

int main() {
#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
    std::puts("run_tty_jobcontrol: skipped (needs Linux/x86-64 or aarch64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("tty", /*overlay=*/false, "",
                                        "/bin/ttyprobe");
    if (!lxtest::compile_guest("run_tty_jobcontrol", tree, kProbe)) return 0;

    auto r = lxtest::run_guest(tree, [&](auto& k) {
        // The probe needs a real pty, so it needs /dev/ptmx and /dev/pts.
        // /dev/tty must resolve to the guest's OWN controlling terminal, so
        // devfs gets the same resolver main.cpp gives it -- without it the
        // open falls through to the host's /dev/tty and the probe is
        // testing the harness's terminal instead of the one it claimed.
        k.files().mount_virtual("/dev", vfs::make_devfs(
            [&k] { return k.procs().ctty_of(k.files().current_pid()); }));
        kernel::ProcInfo init;
        init.pid = 1;
        init.cmdline = tree.exec;
        k.procs().upsert(init);
    });
    lxtest::remove_tree(tree);
    const int code = r ? *r : -1;

    if (code == -1) { std::puts("run_tty_jobcontrol: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_tty_jobcontrol: FAIL code=%d "
                    "(10-14 pty setup, 23 TIOCSCTTY refused, "
                    "15 TIOCGPGRP, 16 fg!=getpgrp[the spin trigger], "
                    "17 TIOCSPGRP, 20 tcsetpgrp did not stick, "
                    "24/25 TIOCGSID, 26/27 /dev/tty is not our terminal, "
                    "28 TIOCNOTTY refused, 29 ctty survived TIOCNOTTY, "
                    "19/22 TIOCGPGRP/TIOCSPGRP wrongly succeeded on /dev/null, "
                    "21 no /dev/null)\n",
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
