// Detached-daemon lifecycle: the runtime must return when the ROOT/session
// leader exits, even if the guest left a daemon running.
//
// gpg-agent (and dirmngr) daemonize via the classic double-fork + setsid and
// typically INHERIT the launcher's stdout/stderr, so the daemon neither exits
// on its own nor lets a downstream pipe EOF. If linuxity waited for EVERY task
// to exit (live_ == 0) before returning, `pacman-key --init` (which starts
// gpg-agent) would HANG the whole runtime forever. The fix: when the root task
// exits, the foreground session is over — reap the surviving tree (a real
// controlling terminal returns to the parent; linuxity OWNS the tree so it
// kills the orphans via reap_tree + PTRACE_O_EXITKILL) and return the root's
// exit code.
//
// A companion hazard this also guards: the double-fork intermediary exits very
// fast and can be first-seen at its OWN initial stop before the parent's
// PTRACE_EVENT_FORK. If that path failed to count it in live_, its later exit
// would UNDERcount the tree and tear the runtime down mid-run (the parent shell
// dying after the first `pacman-key --init`). So this test also asserts the
// program's LATER statements run — i.e. the tree was not torn down early.
//
// The guest: writes "A", double-forks a daemon that setsid()s and then sleeps
// far longer than the harness alarm, writes "B", and exits 42. Success = the
// runtime returns 42 PROMPTLY (well under the daemon's sleep) with both marks.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <unistd.h>

using namespace lx;

// Marks progress on fd 3 (a file the harness reads), spawns a detached daemon
// that outlives the process, and returns 42. The daemon sleeps 60s so if the
// runtime waited for it the harness alarm would fire first.
static const char* kSrc =
    "#include <unistd.h>\n"
    "#include <fcntl.h>\n"
    "#include <sys/types.h>\n"
    "int main(void){\n"
    "  int m = open(\"/marks\", O_WRONLY|O_CREAT|O_TRUNC, 0644);\n"
    "  if (m < 0) return 1;\n"
    "  (void)!write(m, \"A\", 1);\n"
    "  pid_t p = fork();\n"
    "  if (p == 0) {\n"
    "    setsid();\n"                          // detach: new session leader
    "    pid_t g = fork();\n"
    "    if (g > 0) _exit(0);\n"               // intermediary exits fast
    "    sleep(60);\n"                          // daemon outlives the process
    "    _exit(0);\n"
    "  }\n"
    "  (void)!write(m, \"B\", 1);\n"           // must run: tree not torn down early
    "  return 42;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_daemon: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_daemon_root";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin").c_str());

    { std::FILE* f = std::fopen("/tmp/lx_daemon_src.c", "w");
      if (!f) { std::puts("run_daemon: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_daemon_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_daemon: skipped (no static glibc / gcc)"); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    std::time_t t0 = std::time(nullptr);
    auto r = cpu.run(uaddr(0), uaddr(0));
    std::time_t elapsed = std::time(nullptr) - t0;

    if (!r) {
        std::puts("run_daemon: skipped (ptrace unavailable)");
        std::system(("rm -rf " + root).c_str());
        std::remove("/tmp/lx_daemon_src.c");
        return 0;
    }

    // Read the progress marks the guest wrote into the mounted root.
    std::string marks;
    { std::FILE* mf = std::fopen((root + "/marks").c_str(), "rb");
      if (mf) { int c; while ((c = std::fgetc(mf)) != EOF) marks.push_back((char)c);
                std::fclose(mf); } }

    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_daemon_src.c");

    if (elapsed >= 30) {
        std::printf("run_daemon: FAIL runtime blocked ~%llds waiting on the "
                    "detached daemon instead of returning at root exit\n",
                    static_cast<long long>(elapsed));
        return 1;
    }
    if (marks != "AB") {
        std::printf("run_daemon: FAIL progress marks=\"%s\" (expected \"AB\"; "
                    "the tree was torn down before the root finished)\n",
                    marks.c_str());
        return 1;
    }
    if (*r != 42) {
        std::printf("run_daemon: FAIL exit=%d (expected 42; the root's exit "
                    "code did not flow through)\n", *r);
        return 1;
    }
    std::puts("run_daemon: root exit returns promptly with a detached daemon "
              "still alive; tree not torn down early, exit=42");
    return 0;
#endif
}
