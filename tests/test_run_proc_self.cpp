// /proc/self must mean the task making the syscall, and /proc/<pid>/cmdline
// must be the exact kernel wire format.
//
// Two bugs, found together because they produce the same symptom -- a forked
// child reading its own /proc/self/cmdline got the wrong bytes.
//
// 1. procfs canonicalized /proc/self to /proc/1 unconditionally, so EVERY
//    task saw pid 1's view. A child reading /proc/self/cmdline got its
//    PARENT's argv; /proc/self/stat reported pid 1 for every process. The
//    dispatcher knows the caller (ids()), so it now binds self before the
//    path reaches procfs.
//
// 2. ProcInfo::cmdline is documented as "NUL-joined for /proc/.../cmdline",
//    but both writers joined with SPACES. So the guest got
//    "/tmp/argv C two three" where the kernel gives
//    "/tmp/argv\0C\0two\0three\0" -- and an argument containing a space
//    became indistinguishable from two arguments.
//
// Fixing (1) exposed a third: the mount table was matched only as
// /proc/1/mounts, which had worked solely because self always meant 1. Once
// self bound to the real caller, /proc/self/mounts from any other pid was
// ENOENT, which breaks df, /etc/mtab and pacman's free-space check. This test
// covers that too.
#include "guest_harness.hpp"

#include <cstdio>

using namespace lx;

static const char* kSrc =
    "#include <stdio.h>\n"
    "#include <string.h>\n"
    "#include <unistd.h>\n"
    "#include <sys/wait.h>\n"
    "static size_t slurp(const char* p, unsigned char* b, size_t cap){\n"
    "  FILE* f = fopen(p, \"rb\"); if (!f) return (size_t)-1;\n"
    "  size_t n = fread(b, 1, cap, f); fclose(f); return n;\n"
    "}\n"
    "int main(int argc, char** argv){\n"
    "  if (argc > 1 && strcmp(argv[1], \"CHILD\") == 0) {\n"
    // The exact bytes a real kernel produces for argv {prog, CHILD, a b, z}.
    // Note the third arg contains a SPACE: with space-joining it would be
    // indistinguishable from two arguments.
    "    unsigned char b[512];\n"
    "    size_t n = slurp(\"/proc/self/cmdline\", b, sizeof b);\n"
    "    if (n == (size_t)-1) return 10;\n"
    "    const char want[] = \"/bin/prog\\0CHILD\\0a b\\0z\";\n"
    "    if (n != sizeof want) return 11;          /* wrong length */\n"
    "    if (memcmp(b, want, sizeof want) != 0) return 12;  /* wrong bytes */\n"
    // /proc/self/stat's first field is the CALLER's pid, not 1.
    "    char st[64] = {0};\n"
    "    FILE* f = fopen(\"/proc/self/stat\", \"r\"); if (!f) return 13;\n"
    "    if (!fgets(st, sizeof st, f)) return 14; fclose(f);\n"
    "    int spid = 0; sscanf(st, \"%d\", &spid);\n"
    "    if (spid != getpid()) return 15;\n"
    "    if (spid == 1) return 16;                  /* the old bug */\n"
    // The mount table must be reachable from a NON-1 pid.
    "    unsigned char m[256];\n"
    "    if (slurp(\"/proc/self/mounts\", m, sizeof m) == (size_t)-1) return 17;\n"
    "    if (slurp(\"/proc/self/mountinfo\", m, sizeof m) == (size_t)-1) return 18;\n"
    "    return 0;\n"
    "  }\n"
    "  pid_t p = fork();\n"
    "  if (p == 0) {\n"
    "    char* av[] = {argv[0], \"CHILD\", \"a b\", \"z\", 0};\n"
    "    execv(argv[0], av); _exit(127);\n"
    "  }\n"
    "  int st = 0; waitpid(p, &st, 0);\n"
    "  return WIFEXITED(st) ? (WEXITSTATUS(st) == 0 ? 77 : WEXITSTATUS(st)) : 99;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_proc_self: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("procself");
    if (!lxtest::compile_guest("run_proc_self", tree, kSrc)) return 0;
    auto r = lxtest::run_guest(tree);
    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_proc_self: skipped (ptrace unavailable)"); return 0; }
    switch (*r) {
        case 77:
            std::puts("run_proc_self: a forked child's /proc/self is ITSELF -- "
                      "cmdline is byte-exact kernel format (NUL-separated, a "
                      "spaced arg kept whole), stat reports its own pid, and the "
                      "mount table is reachable from a non-1 pid, exit=77");
            return 0;
        case 11: case 12:
            std::printf("run_proc_self: FAIL /proc/self/cmdline bytes are wrong "
                        "(code %d). Either self resolved to the PARENT, or argv "
                        "was SPACE-joined instead of NUL-joined (ProcInfo::cmdline "
                        "is documented as NUL-joined).\n", *r);
            return 1;
        case 15: case 16:
            std::printf("run_proc_self: FAIL /proc/self/stat reported the wrong "
                        "pid (code %d) -- self is not bound to the caller.\n", *r);
            return 1;
        case 17: case 18:
            std::printf("run_proc_self: FAIL /proc/self/mount%s is ENOENT from a "
                        "non-1 pid -- the mount table is still matched as "
                        "/proc/1/* only (breaks df, /etc/mtab, pacman).\n",
                        *r == 17 ? "s" : "info");
            return 1;
        default:
            std::printf("run_proc_self: FAIL guest exit=%d\n", *r);
            return 1;
    }
#endif
}
