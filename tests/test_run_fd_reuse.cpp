// A FILE fd that reuses the number of a closed DIRECTORY fd must seek as a
// file, not as the directory it replaced.
//
// close(2) runs natively on the seccomp fast path -- it fires on every fd
// teardown, so it is deliberately untrapped -- which means linuxity never
// hears that a guest closed a directory. That directory's DirStream stays
// registered against its fd number. The kernel then hands the SAME number
// to the next open(). When that open is a regular file, the stale stream
// makes its lseek look like a directory seek: the dispatcher rewinds the
// (stale) directory cursor, the host fd never moves, and the re-read
// returns the wrong bytes.
//
// That is exactly how `ps aux` died with "Signal 8 (FPE) caught by ps".
// libproc2 keeps /proc/meminfo open and re-reads it with lseek(fd,0,SEEK_SET)
// + read; it got the fd a just-closed /proc dir had held, the seek was
// swallowed, MemTotal parsed as 0, and pr_pmem divided by it.
//
// It became reachable only once lseek was trapped (so rewinddir would work
// on merged directories). Both fixes are right on their own; together they
// were wrong. This test pins the interaction.
#include "guest_harness.hpp"

#include <cstdio>

using namespace lx;

static const char* kSrc =
    "#include <dirent.h>\n"
    "#include <fcntl.h>\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "int main(void){\n"
    "  char buf[8192];\n"
    // 1. Open a VIRTUAL directory and enumerate it, so a DirStream is bound.
    "  DIR* d = opendir(\"/proc\");\n"
    "  if (!d) return 1;\n"
    "  int dfd = dirfd(d);\n"
    "  while (readdir(d)) {}\n"
    // 2. Close it. On the fast path linuxity does not see this.
    "  closedir(d);\n"
    // 3. Open a FILE; the kernel reuses the directory's fd number.
    "  int fd = open(\"/proc/meminfo\", O_RDONLY);\n"
    "  if (fd < 0) return 2;\n"
    "  if (fd != dfd) return 99;   /* number not reused: test can't apply */\n"
    // 4. libproc2's exact pattern: read, then lseek(0) and read AGAIN.
    "  for (int pass = 0; pass < 3; pass++) {\n"
    "    if (lseek(fd, 0, SEEK_SET) != 0) return 10 + pass;\n"
    "    ssize_t n = read(fd, buf, sizeof buf - 1);\n"
    "    if (n <= 0) return 20 + pass;\n"
    "    buf[n] = 0;\n"
    "    char* p = strstr(buf, \"MemTotal:\");\n"
    "    if (!p) return 30 + pass;\n"
    "    if (strtoul(p + 9, 0, 10) == 0) return 40 + pass;   /* the bug */\n"
    "  }\n"
    "  close(fd);\n"
    "  return 7;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_fd_reuse: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("fdreuse");
    if (!lxtest::compile_guest("run_fd_reuse", tree, kSrc)) return 0;
    auto r = lxtest::run_guest(tree);
    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_fd_reuse: skipped (ptrace unavailable)"); return 0; }
    const int code = *r;
    if (code == 99) {
        std::puts("run_fd_reuse: skipped (kernel did not reuse the fd number)");
        return 0;
    }
    if (code >= 40 && code < 50) {
        std::printf("run_fd_reuse: FAIL pass %d parsed MemTotal as 0 -- a file fd "
                    "that reused a closed directory's number had its lseek "
                    "swallowed by the stale DirStream. This is the `ps aux` "
                    "SIGFPE. note_opened_fd() must unbind_fd() the number "
                    "before binding the new open.\n", code - 40);
        return 1;
    }
    if (code != 7) {
        std::printf("run_fd_reuse: FAIL guest exit=%d (expected 7)\n", code);
        return 1;
    }
    std::puts("run_fd_reuse: a file fd reusing a closed directory's number "
              "seeks as a file; lseek+re-read returns real data on every pass, "
              "exit=7");
    return 0;
#endif
}
