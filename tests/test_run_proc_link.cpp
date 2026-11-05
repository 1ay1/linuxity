// readlink of a /proc symlink must never hand the guest linuxity's internal
// sentinel string.
//
// procfs marks cwd/root/exe with symlink_target = "(proc-link)", meaning "a
// symlink whose target only the dispatcher knows". do_readlink is supposed to
// substitute the real value via proc_symlink_target(); when that came back
// empty -- an exe we cannot name, a pid that just exited -- the fallback path
// served the literal 11-byte string "(proc-link)" instead.
//
// That is not a cosmetic leak. glibc's _dl_get_origin readlinks
// /proc/self/exe and asserts linkval[0] == '/'. A relative "(proc-link)"
// fails it and ABORTS the process:
//
//   Fatal glibc error: dl-origin.c:42 (_dl_get_origin):
//     assertion failed: linkval[0] == '/'
//   error: command terminated by signal 11
//
// which killed every pacman scriptlet -- `pacman -S cmatrix` died right after
// "reinstalling cmatrix", so the package installed but the transaction
// reported failure. ENOENT is the honest answer when we cannot resolve the
// link; callers handle that, and cannot handle a lie.
//
// HONEST LIMITATION: this test does NOT reproduce the bug. It passes with the
// fix reverted. The sentinel only escapes for a pid whose ProcInfo.exe cannot
// be resolved, and the one observed instance was `/proc/20/exe` during a real
// pacman scriptlet -- a state I could not synthesize (a plain fork chain, a
// fork+exec+sleep, and scanning every pid's exe all read back absolute).
//
// So what this file is: a GUARD, not a reproduction. It asserts the invariant
// "no /proc symlink ever reads back relative or parenthesised", which is the
// property that matters and which any future leak of an internal marker would
// break. The fix itself was verified against the real workload: 3/3 pacman
// reinstalls clean with it, and the abort returns the moment it is reverted.
#include "guest_harness.hpp"

#include <cstdio>

using namespace lx;

static const char* kSrc =
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "#include <sys/wait.h>\n"
    // Every /proc symlink the dispatcher resolves specially. Each must come
    // back ABSOLUTE or fail outright -- never a relative sentinel.
    "static int check(const char* p){\n"
    "  char b[512];\n"
    "  memset(b, 0, sizeof b);\n"
    "  ssize_t n = readlink(p, b, sizeof b - 1);\n"
    "  if (n < 0) return 0;              /* a clean failure is acceptable */\n"
    "  if (n == 0) return 1;             /* an empty target is not */\n"
    "  if (b[0] != '/') return 2;        /* THE BUG: relative/sentinel */\n"
    "  if (strchr(b, '(') || strchr(b, ')')) return 3;  /* a sentinel leaked */\n"
    "  return 0;\n"
    "}\n"
    "int main(int argc, char** argv){\n"
    "  const char* paths[] = {\n"
    "    \"/proc/self/exe\", \"/proc/self/cwd\", \"/proc/self/root\",\n"
    "    \"/proc/1/exe\", \"/proc/1/cwd\", \"/proc/1/root\",\n"
    "  };\n"
    "  for (unsigned i = 0; i < sizeof paths / sizeof *paths; i++) {\n"
    "    int rc = check(paths[i]);\n"
    "    if (rc) return 10 + (int)i * 4 + rc;\n"
    "  }\n"
    // And from a FORKED CHILD, which is the case that actually broke: its
    // exe could not be named from the parent's ProcInfo.
    "  if (argc > 1) return 0;\n"
    "  pid_t p = fork();\n"
    "  if (p == 0) { char* av[] = {argv[0], \"c\", 0}; execv(argv[0], av); _exit(127); }\n"
    "  int st = 0; waitpid(p, &st, 0);\n"
    "  if (!WIFEXITED(st)) return 90;        /* child died -- the glibc abort */\n"
    "  if (WEXITSTATUS(st) != 0) return WEXITSTATUS(st);\n"
    "  return 55;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_proc_link: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("proclink");
    if (!lxtest::compile_guest("run_proc_link", tree, kSrc)) return 0;
    auto r = lxtest::run_guest(tree);
    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_proc_link: skipped (ptrace unavailable)"); return 0; }
    const int code = *r;
    if (code == 55) {
        std::puts("run_proc_link: every /proc exe/cwd/root symlink reads back "
                  "absolute or fails cleanly -- no \"(proc-link)\" sentinel "
                  "reaches the guest, in the parent or a forked child, exit=55");
        return 0;
    }
    if (code == 90) {
        std::puts("run_proc_link: FAIL the forked child DIED -- almost certainly "
                  "glibc's _dl_get_origin abort on a relative /proc/self/exe "
                  "(dl-origin.c:42, assertion linkval[0] == '/').");
        return 1;
    }
    if (code >= 10 && code < 40) {
        const int idx = (code - 10) / 4, why = (code - 10) % 4;
        static const char* names[] = {"/proc/self/exe", "/proc/self/cwd",
                                      "/proc/self/root", "/proc/1/exe",
                                      "/proc/1/cwd", "/proc/1/root"};
        static const char* reasons[] = {"?", "returned an EMPTY target",
                                        "returned a RELATIVE target (the "
                                        "\"(proc-link)\" sentinel leaking)",
                                        "contains parentheses -- a sentinel leaked"};
        std::printf("run_proc_link: FAIL %s %s\n",
                    idx < 6 ? names[idx] : "?", reasons[why]);
        return 1;
    }
    std::printf("run_proc_link: FAIL guest exit=%d\n", code);
    return 1;
#endif
}
