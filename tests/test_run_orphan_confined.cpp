// A guest process still running after pid 1 exits must stay inside its root.
//
// When the session leader exits, linuxity shuts the rest of the tree down:
// SIGTERM, a grace window for cleanup handlers, then SIGKILL. That window
// used to resume every survivor with PTRACE_CONT, and under seccomp a
// syscall stop resumed that way runs the call NATIVELY -- so any syscall a
// survivor made during its own SIGTERM handler hit the HOST filesystem.
// python's forkserver child, mid-import when its parent died, opened
// /usr/lib/python3.14/threading.py on the host and failed with "No module
// named 'threading'". pacman's cleanup handler was unlinking a host path
// instead of its own lock.
//
// The probe forks a child whose ONLY file access happens in its SIGTERM
// handler, i.e. strictly after pid 1 has gone. /canary exists solely in the
// guest rootfs, so the handler can only find it while still translated.
// Escaped, it sees the host: /canary is ENOENT there and /result cannot be
// created at the host's / either, so the result file never appears.
#include "guest_harness.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

static const char* kSrc =
    "#include <signal.h>\n#include <fcntl.h>\n#include <unistd.h>\n"
    "#include <string.h>\n"
    "static void on_term(int s) {\n"
    "  (void)s;\n"
    "  int c = open(\"/canary\", O_RDONLY);\n"
    "  const char* v = c >= 0 ? \"ok\" : \"escaped\";\n"
    "  int r = open(\"/result\", O_WRONLY|O_CREAT|O_TRUNC, 0644);\n"
    "  if (r >= 0) { write(r, v, strlen(v)); close(r); }\n"
    "  _exit(0);\n"
    "}\n"
    "int main(void) {\n"
    "  int p[2];\n"
    "  if (pipe(p)) return 1;\n"
    "  pid_t k = fork();\n"
    "  if (k < 0) return 2;\n"
    "  if (k == 0) {\n"
    "    close(p[0]);\n"
    "    struct sigaction sa; memset(&sa, 0, sizeof sa);\n"
    "    sa.sa_handler = on_term;\n"
    "    sigaction(SIGTERM, &sa, 0);\n"
    "    write(p[1], \"r\", 1);   /* handler installed: parent may go */\n"
    "    for (;;) pause();\n"
    "  }\n"
    "  close(p[1]);\n"
    "  char b; read(p[0], &b, 1);\n"
    "  return 0;              /* pid 1 exits with the child still alive */\n"
    "}\n";

int main() {
#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
    std::puts("run_orphan_confined: skipped (needs Linux/x86-64 or aarch64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("orphan_confined", /*overlay=*/false,
        "printf canary > /tmp/lx_orphan_confined_root/canary");
    if (!lxtest::compile_guest("run_orphan_confined", tree, kSrc)) return 0;

    auto r = lxtest::run_guest(tree);
    std::string result;
    {
        std::ifstream f(tree.root + "/result");
        std::ostringstream ss;
        ss << f.rdbuf();
        result = ss.str();
    }
    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_orphan_confined: skipped (ptrace unavailable)"); return 0; }
    if (*r != 0) {
        std::printf("run_orphan_confined: FAIL pid 1 exited %d (expected 0)\n", *r);
        return 1;
    }
    if (result != "ok") {
        std::printf("run_orphan_confined: FAIL the child's SIGTERM handler, which "
                    "runs after pid 1 exited, reported '%s' -- it %s. Survivors of "
                    "pid 1 must stay translated until they exit.\n",
                    result.empty() ? "<nothing>" : result.c_str(),
                    result.empty() ? "never wrote /result, so its syscalls ran "
                                     "against the HOST filesystem"
                                   : "could not see the guest rootfs");
        return 1;
    }
    std::puts("run_orphan_confined: a survivor of pid 1 stays inside the guest "
              "rootfs through its SIGTERM handler");
    return 0;
#endif
}
