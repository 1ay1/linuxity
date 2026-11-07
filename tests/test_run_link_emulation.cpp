// Hardlinks emulated on a host that refuses link(2) must behave like Linux.
//
// Android denies link(2) on /data, so linuxity keeps the first name as the
// real file and makes every later name an alias of it (link_table.hpp). This
// runs with LINUXITY_FORCE_LINK_EMULATION so the emulation is exercised on a
// host where links work.
//
// The first version copied the file instead: the names stopped sharing data
// on the first write, and removing the original lost what the others had
// written. Each check below is one of the ways that went wrong; the expected
// values are what a real Linux kernel returns.
#include "guest_harness.hpp"

#include <cstdio>
#include <cstdlib>

static const char* kSrc =
    "#define _GNU_SOURCE\n"
    "#include <fcntl.h>\n#include <unistd.h>\n#include <string.h>\n"
    "#include <errno.h>\n#include <stdio.h>\n#include <sys/stat.h>\n"
    "static int rd(const char* p, char* b) {\n"
    "  int f = open(p, O_RDONLY); if (f < 0) return -1;\n"
    "  int n = read(f, b, 63); close(f); b[n < 0 ? 0 : n] = 0; return n;\n"
    "}\n"
    "static void ap(const char* p, const char* s) {\n"
    "  int f = open(p, O_WRONLY|O_APPEND); write(f, s, strlen(s)); close(f);\n"
    "}\n"
    "static long nl(const char* p) { struct stat st; return stat(p, &st) ? -1 : (long)st.st_nlink; }\n"
    "int main(void) {\n"
    "  char b[64];\n"
    "  mkdir(\"/w\", 0755);\n"
    "  int f = open(\"/w/a\", O_WRONLY|O_CREAT|O_TRUNC, 0644);\n"
    "  write(f, \"one\", 3); close(f);\n"
    "  if (link(\"/w/a\", \"/w/b\")) return 10;\n"
    "  if (link(\"/w/b\", \"/w/c\")) return 11;          /* link of a link */\n"
    "  if (nl(\"/w/a\") != 3 || nl(\"/w/c\") != 3) return 12;\n"
    "  struct stat sa, sc; stat(\"/w/a\", &sa); stat(\"/w/c\", &sc);\n"
    "  if (sa.st_ino != sc.st_ino) return 13;       /* one inode */\n"
    "  ap(\"/w/c\", \"+two\");\n"
    "  rd(\"/w/a\", b); if (strcmp(b, \"one+two\")) return 14;   /* shared data */\n"
    "  if (unlink(\"/w/a\")) return 15;               /* drop the original name */\n"
    "  rd(\"/w/b\", b); if (strcmp(b, \"one+two\")) return 16;\n"
    "  if (nl(\"/w/b\") != 2) return 17;\n"
    "  if (rename(\"/w/c\", \"/w/c2\")) return 18;      /* rename a link */\n"
    "  ap(\"/w/b\", \"+3\");\n"
    "  rd(\"/w/c2\", b); if (strcmp(b, \"one+two+3\")) return 19;\n"
    "  mkdir(\"/w/d\", 0755);                         /* dir onto a linked file */\n"
    "  if (rename(\"/w/d\", \"/w/b\") == 0 || errno != ENOTDIR) return 20;\n"
    "  rd(\"/w/b\", b); if (strcmp(b, \"one+two+3\")) return 21;\n"
    "  if (rename(\"/w/b\", \"/w/c2\")) return 22;      /* onto its own twin: no-op */\n"
    "  if (access(\"/w/b\", F_OK)) return 23;\n"
    "  f = open(\"/w/x\", O_WRONLY|O_CREAT|O_TRUNC, 0644); write(f, \"X\", 1); close(f);\n"
    "  if (rename(\"/w/x\", \"/w/b\")) return 24;       /* replace one linked name */\n"
    "  rd(\"/w/c2\", b); if (strcmp(b, \"one+two+3\")) return 25;\n"
    "  if (nl(\"/w/c2\") != 1) return 26;\n"
    "  f = open(\"/w\", O_TMPFILE|O_RDWR, 0600);       /* name an O_TMPFILE */\n"
    "  if (f < 0) return 27;\n"
    "  write(f, \"tmp\", 3);\n"
    "  char pp[64]; snprintf(pp, sizeof pp, \"/proc/self/fd/%d\", f);\n"
    "  if (linkat(AT_FDCWD, pp, AT_FDCWD, \"/w/t\", AT_SYMLINK_FOLLOW)) return 28;\n"
    "  close(f);\n"
    "  rd(\"/w/t\", b); if (strcmp(b, \"tmp\")) return 29;\n"
    "  f = open(\"/w/keep\", O_WRONLY|O_CREAT|O_TRUNC, 0644); write(f, \"K\", 1); close(f);\n"
    "  if (link(\"/w/keep\", \"/w/keep2\")) return 30;  /* checked after restart */\n"
    "  return 42;\n"
    "}\n";

static const char* kAfter =
    "#include <fcntl.h>\n#include <unistd.h>\n#include <string.h>\n#include <sys/stat.h>\n"
    "int main(void) {\n"
    "  int f = open(\"/w/keep2\", O_WRONLY|O_APPEND); if (f < 0) return 50;\n"
    "  write(f, \"+R\", 2); close(f);\n"
    "  char b[16] = {0}; f = open(\"/w/keep\", O_RDONLY); read(f, b, 15); close(f);\n"
    "  if (strcmp(b, \"K+R\")) return 51;\n"
    "  struct stat st; stat(\"/w/keep\", &st); if (st.st_nlink != 2) return 52;\n"
    "  return 43;\n"
    "}\n";

int main() {
#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
    std::puts("run_link_emulation: skipped (needs Linux/x86-64 or aarch64 host)");
    return 0;
#else
    ::setenv("LINUXITY_FORCE_LINK_EMULATION", "1", 1);
    const auto tree = lxtest::make_tree("link_emulation", /*overlay=*/true);
    if (!lxtest::compile_guest("run_link_emulation", tree, kSrc)) return 0;
    auto r1 = lxtest::run_guest(tree);
    if (!r1) { lxtest::remove_tree(tree); std::puts("run_link_emulation: skipped (ptrace unavailable)"); return 0; }
    if (*r1 != 42) {
        lxtest::remove_tree(tree);
        std::printf("run_link_emulation: FAIL guest exit=%d (10-30 name the step, see the "
                    "source; 14/19 = names stopped sharing data, 16 = data lost when the "
                    "original was unlinked, 20/21 = a failed rename clobbered a linked "
                    "file, 28/29 = /proc/self/fd link)\n", *r1);
        return 1;
    }
    // A second, separate run on the same overlay: the link must survive.
    if (!lxtest::compile_guest("run_link_emulation", tree, kAfter)) { lxtest::remove_tree(tree); return 0; }
    auto r2 = lxtest::run_guest(tree);
    lxtest::remove_tree(tree);
    if (!r2 || *r2 != 43) {
        std::printf("run_link_emulation: FAIL after a restart, exit=%d (50/51 = the link "
                    "table was not journaled, so the alias became an empty placeholder)\n",
                    r2 ? *r2 : -1);
        return 1;
    }
    std::puts("run_link_emulation: emulated hardlinks share one inode, survive the "
              "original's unlink and a failed rename, name an O_TMPFILE, and persist "
              "across runs");
    return 0;
#endif
}
