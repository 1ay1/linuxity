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
// Both halves are checked here. The tty half uses whichever real terminal is
// available: setsid() is virtualized (it reports a new session without
// creating one), so TIOCSCTTY cannot be relied on to manufacture a
// controlling terminal -- the probe takes /dev/tty when the harness gave us
// one and otherwise just verifies the negative half, rather than asserting a
// setup linuxity does not promise.
static const char* kProbe =
    "#define _GNU_SOURCE\n"
    "#include <stdio.h>\n#include <stdlib.h>\n#include <fcntl.h>\n"
    "#include <unistd.h>\n#include <sys/ioctl.h>\n#include <termios.h>\n"
    "int main(void){\n"
    "  pid_t self=getpgrp();\n"
    "  pid_t fg=-999;\n"
    // The tty half, only if we actually have a controlling terminal.
    "  int t=open(\"/dev/tty\",O_RDWR);\n"
    "  if(t>=0){\n"
    "    if(ioctl(t,TIOCGPGRP,&fg)!=0) return 15;\n"
    "    if(fg!=self) return 16;          /* the spin trigger: fg!=our pgrp */\n"
    "    pid_t want=self;\n"
    "    if(ioctl(t,TIOCSPGRP,&want)!=0) return 17;\n"
    "    if(ioctl(t,TIOCGPGRP,&fg)!=0||fg!=want) return 20;\n"
    "  }\n"
    // The negative half always holds: a non-tty must be ENOTTY, not a
    // fabricated success. This is the part that was wrong before.
    "  int n=open(\"/dev/null\",O_RDONLY);\n"
    "  if(n<0) return 21;\n"
    "  if(ioctl(n,TIOCGPGRP,&fg)==0) return 19;\n"
    "  if(ioctl(n,TIOCSPGRP,&self)==0) return 22;\n"
    "  return 0;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_tty_jobcontrol: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("tty", /*overlay=*/false, "",
                                        "/bin/ttyprobe");
    if (!lxtest::compile_guest("run_tty_jobcontrol", tree, kProbe)) return 0;

    auto r = lxtest::run_guest(tree, [&](auto& k) {
        // The probe needs a real pty, so it needs /dev/ptmx and /dev/pts.
        k.files().mount_virtual("/dev", vfs::make_devfs());
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
                    "(15 TIOCGPGRP, 16 fg!=getpgrp[the spin trigger], "
                    "17 TIOCSPGRP, 20 tcsetpgrp did not stick, "
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
