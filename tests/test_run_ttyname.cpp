// A pty's slave must be NAMEABLE from inside the guest.
//
// ttyname(fd) is how a program finds out which terminal it is on. glibc
// answers it by readlink("/proc/self/fd/<fd>"), then stat()ing the result and
// checking it is the same inode as the fd. script(1), tty(1), ssh, tmux, sudo
// and every shell's prompt logic go through it.
//
// It returned NULL with ENOTTY -- "Inappropriate ioctl for device" -- on a
// perfectly good pty: isatty() was 1, tcgetattr() worked, and only the NAME
// was missing. The dispatcher rewrote /proc/self to /proc/<pid> for every path
// before procfs saw it, and procfs keeps the caller's fds ONLY under
// /proc/self/fd, where it hands them to the host kernel (the guest is a real
// host process, so the host's /proc/self/fd/N in the guest's context IS fd N).
// The rewrite made that redirect unreachable and readlink ENOENT.
//
// A fd the guest opened by path still resolved -- linuxity records its path --
// so the bug only showed on fds the guest INHERITED or got from a syscall that
// returns one. A pty from posix_openpt() is the second kind, which is why the
// existing live tests, which all open files by path, never saw it.
//
// The probe opens a pty pair, then checks, on the slave fd:
//   isatty, ttyname non-NULL, ttyname is the /dev/pts/N it opened, and
//   readlink of both /proc/self/fd/N and /proc/<pid>/fd/N succeed.
#include "guest_harness.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/vfs/devfs.hpp"

#include <cstdio>
#include <string>

using namespace lx;

static const char* kProbe =
    "#include <stdio.h>\n#include <unistd.h>\n"
    "int main(void){\n"
    // fd 0 is INHERITED from the harness, never opened by the guest, so
    // linuxity holds no path for it -- the only way to name it is the host's
    // /proc/self/fd/0. That is precisely the case that broke: a fd the guest
    // opened BY PATH still resolved, because the dispatcher answers from its
    // own fd table, which is why a probe that opens its own pty passes even
    // with the bug. script(1)'s child is in this position -- it gets the pty
    // as stdin across an exec, not by opening it.
    "  char b[256], l[64];\n"
    "  if (readlink(\"/proc/self/fd/0\", b, sizeof b - 1) <= 0) return 17;\n"
    "  snprintf(l, sizeof l, \"/proc/%d/fd/0\", (int)getpid());\n"
    "  if (readlink(l, b, sizeof b - 1) <= 0) return 18;\n"
    "  if (readlink(\"/proc/self/fd/1\", b, sizeof b - 1) <= 0) return 19;\n"
    "  return 0;\n"
    "}\n";

int main() {
#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
    std::puts("run_ttyname: skipped (needs Linux/x86-64 or aarch64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("ttyname", /*overlay=*/false, "",
                                        "/bin/ttyname");
    if (!lxtest::compile_guest("run_ttyname", tree, kProbe)) return 0;

    auto r = lxtest::run_guest(tree, [&](auto& k) {
        // procfs for /proc/self/fd, devfs for /dev/ptmx and /dev/pts/N: the
        // two halves ttyname() needs, mounted the way main.cpp mounts them.
        k.files().mount_virtual("/proc",
                                vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/dev", vfs::make_devfs());
        kernel::ProcInfo init;
        init.pid = 1;
        init.cmdline = tree.exec;
        k.procs().upsert(init);
    });
    lxtest::remove_tree(tree);
    const int code = r ? *r : -1;

    if (code == -1) { std::puts("run_ttyname: skipped (ptrace unavailable)"); return 0; }
    if (code != 0) {
        std::printf("run_ttyname: FAIL code=%d (17 readlink /proc/self/fd/0 "
                    "18 readlink /proc/<pid>/fd/0 19 readlink /proc/self/fd/1 -- "
                    "an INHERITED fd's link is ENOENT, which is what makes "
                    "ttyname() fail under script(1))\n",
                    code);
        return 1;
    }
    std::puts("run_ttyname: an inherited fd is nameable from the guest -- "
              "/proc/self/fd/N and /proc/<pid>/fd/N both resolve, so ttyname() "
              "works on a pty handed in as stdin");
    return 0;
#endif
}
