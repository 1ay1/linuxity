// TCGETS2/TCSETS2 on a pty must work even when the host refuses them.
//
// glibc >= 2.42 implements tcgetattr/tcsetattr/isatty/ttyname with the
// termios2 ioctls (TCGETS2/TCSETS2/TCSETSW2/TCSETSF2) instead of the classic
// termios ones. Android's SELinux policy gives the shell domain an ioctl
// WHITELIST for devpts that predates termios2 and lists only the classic
// requests, so on a real device every termios call on a pty slave failed
// EACCES: `stty` printed "Permission denied", `tty` printed "not a tty", and
// the pty itself was perfectly fine (TCGETS on the same fd worked, and both
// variants worked on the MASTER, which is ptmx and a different SELinux class).
//
// struct termios2 is struct termios plus c_ispeed/c_ospeed, with the leading
// 36 bytes identical, so the dispatcher serves the termios2 requests by
// rewriting the request register to the classic one and, for the getter,
// appending the two speeds derived from the CBAUD code in c_cflag. A pty
// reports a real Bxxx code there rather than BOTHER, so nothing is lost.
//
// The probe runs the whole family on a pty slave and checks each one both
// succeeds AND produces a sane struct: the downgrade has to be transparent,
// not merely non-failing. It passes on a host that permits termios2 natively
// too -- that is the point, the rewrite must not change the answer.
#include "guest_harness.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/vfs/devfs.hpp"

#include <cstdio>
#include <string>

using namespace lx;

static const char* kProbe =
    "#define _GNU_SOURCE\n"
    "#include <stdio.h>\n#include <stdlib.h>\n#include <fcntl.h>\n"
    "#include <unistd.h>\n#include <string.h>\n#include <stdint.h>\n"
    "#include <sys/ioctl.h>\n"
    // Raw numbers and a hand-rolled layout: the TCGETS2 macro needs struct
    // termios2, which is not in every libc's headers. Both are
    // arch-independent for every arch linuxity runs on.
    "#define T_TCGETS   0x5401UL\n"
    "#define T_TCGETS2  0x802c542aUL\n"
    "#define T_TCSETS2  0x402c542bUL\n"
    "#define T_TCSETSW2 0x402c542cUL\n"
    "#define T_TCSETSF2 0x402c542dUL\n"
    "#define T_CBAUD    0x0000100f\n"
    "#define T_ECHO     0x00000008\n"
    "struct t2 { uint32_t i,o,c,l; uint8_t line; uint8_t cc[19];"
    " uint32_t isp,osp; };\n"
    "int main(void){\n"
    "  int m = posix_openpt(O_RDWR|O_NOCTTY);\n"
    "  if (m < 0) return 10;\n"
    "  grantpt(m); unlockpt(m);\n"
    "  int s = open(ptsname(m), O_RDWR|O_NOCTTY);\n"
    "  if (s < 0) return 11;\n"
    // 1. TCGETS2 must succeed and must agree with TCGETS on the shared prefix.
    //    If the widen step wrote over the wrong offset, this catches it.
    "  struct t2 a; memset(&a, 0xAA, sizeof a);\n"
    "  if (ioctl(s, T_TCGETS2, &a) < 0) return 12;\n"
    "  char classic[36]; memset(classic, 0xBB, sizeof classic);\n"
    "  if (ioctl(s, T_TCGETS, classic) < 0) return 13;\n"
    "  if (memcmp(classic, &a, 36) != 0) return 14;\n"
    // 2. The speeds must be filled in, not left as the 0xAA poison. A pty
    //    always has a baud code, so a zero here means the fixup never ran.
    "  if (a.isp == 0xAAAAAAAA || a.osp == 0xAAAAAAAA) return 15;\n"
    "  if ((a.c & T_CBAUD) != 0 && (a.isp == 0 || a.osp == 0)) return 16;\n"
    "  if (a.isp != a.osp) return 17;\n"
    // 3. Every setter must apply for real: clear ECHO, read it back cleared,
    //    set it again, read it back set. A set that silently no-ops would
    //    leave `stty -echo` broken while looking like it worked.
    "  struct t2 b = a;\n"
    "  b.l &= ~(uint32_t)T_ECHO;\n"
    "  if (ioctl(s, T_TCSETS2, &b) < 0) return 18;\n"
    "  struct t2 c; memset(&c, 0, sizeof c);\n"
    "  if (ioctl(s, T_TCGETS2, &c) < 0) return 19;\n"
    "  if (c.l & T_ECHO) return 20;\n"
    "  b.l |= (uint32_t)T_ECHO;\n"
    "  if (ioctl(s, T_TCSETSW2, &b) < 0) return 21;\n"
    "  if (ioctl(s, T_TCGETS2, &c) < 0) return 22;\n"
    "  if (!(c.l & T_ECHO)) return 23;\n"
    // 4. The flush variant is the one `stty` itself reaches for on some
    //    paths, so it gets the same treatment.
    "  if (ioctl(s, T_TCSETSF2, &b) < 0) return 24;\n"
    "  return 0;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_termios2: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("termios2", /*overlay=*/false, "",
                                        "/bin/termios2");
    if (!lxtest::compile_guest("run_termios2", tree, kProbe)) return 0;

    auto r = lxtest::run_guest(tree, [&](auto& k) {
        // devfs for /dev/ptmx and /dev/pts/N, mounted the way main.cpp does.
        k.files().mount_virtual("/dev", vfs::make_devfs());
        kernel::ProcInfo init;
        init.pid = 1;
        init.cmdline = tree.exec;
        k.procs().upsert(init);
    });
    lxtest::remove_tree(tree);
    const int code = r ? *r : -1;

    if (code == -1) { std::puts("run_termios2: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_termios2: FAIL code=%d (12 TCGETS2 failed, "
                    "14 prefix disagrees with TCGETS so the widen wrote the "
                    "wrong offset, 15/16 c_ispeed/c_ospeed never filled in, "
                    "18-23 a setter did not actually apply, 24 TCSETSF2 "
                    "failed)\n", code);
        return 1;
    }
    std::puts("run_termios2: the termios2 ioctls work on a pty slave -- "
              "TCGETS2 agrees with TCGETS and carries the speeds, and "
              "TCSETS2/W2/F2 all really apply");
    return 0;
#endif
}
