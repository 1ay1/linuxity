// Empty-path + page-straddle path reads.
//
// Two loader-critical guest-memory bugs, both of which made real dynamic
// programs (gpg-agent, and thus pacman's keyring path) die with an opaque
// "runtime error 14" / "cannot read file data":
//
//   1. EMPTY PATH resolved to "/". openat(AT_FDCWD,"",...) without
//      AT_EMPTY_PATH must be ENOENT; linuxity used to absolutize "" -> "/"
//      and REDIRECT the open to the overlay ROOT (a directory), so the
//      caller's read/mmap got EISDIR. glibc's loader probes openat("")
//      during library search, so this hit nearly everything.
//
//   2. PAGE-STRADDLE cstring read. process_vm_readv reads a whole iovec or
//      nothing; a 64-byte chunk that crossed the end of a mapped page into an
//      unmapped one faulted entirely, losing a perfectly valid library path
//      placed right against a page boundary -> "" -> case (1).
//
// The probe exercises both: it opens a valid rootfs file whose path it places
// at the very end of a mapped page (forcing the straddle recovery), and it
// calls open("")/access("")/readlink("") and asserts each returns ENOENT
// rather than faulting. Exit 7 iff all hold.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

static const char* kSrc =
    "#define _GNU_SOURCE\n"
    "#include <sys/mman.h>\n"
    "#include <fcntl.h>\n"
    "#include <unistd.h>\n"
    "#include <string.h>\n"
    "#include <errno.h>\n"
    "int main(void){\n"
    "  /* empty-path family: each must ENOENT, not fault. */\n"
    "  if (open(\"\", O_RDONLY) != -1 || errno != ENOENT) return 2;\n"
    "  if (access(\"\", F_OK) != -1 || errno != ENOENT) return 3;\n"
    "  char lb[8]; if (readlink(\"\", lb, sizeof lb) != -1 || errno != ENOENT) return 4;\n"
    "  /* page-straddle: place \"/etc/marker\" so its NUL sits just past a page\n"
    "     end, forcing the chunked reader to straddle into the guard page. */\n"
    "  long pg = sysconf(_SC_PAGESIZE);\n"
    "  char* m = mmap(0, pg*2, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);\n"
    "  if (m == MAP_FAILED) return 5;\n"
    "  /* unmap the SECOND page so reads past the first page fault. */\n"
    "  if (munmap(m+pg, pg) != 0) return 6;\n"
    "  const char* p = \"/etc/marker\";\n"
    "  size_t len = strlen(p);\n"
    "  char* dst = m + pg - len - 1;   /* NUL lands at m+pg-1, last valid byte */\n"
    "  memcpy(dst, p, len+1);\n"
    "  int fd = open(dst, O_RDONLY);\n"
    "  if (fd < 0) return 7;           /* straddle recovery failed */\n"
    "  char buf[16]; long n = read(fd, buf, sizeof buf-1);\n"
    "  if (n < 6) return 8; buf[n]=0;\n"
    "  if (strncmp(buf, \"rootfs\", 6) != 0) return 9;\n"
    "  return 10;\n}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_empty_path: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_emptypath_test";
    std::system(("rm -rf " + root + " && mkdir -p " + root + "/bin " + root + "/etc").c_str());
    { std::FILE* f = std::fopen((root + "/etc/marker").c_str(), "w");
      if (!f) { std::puts("run_empty_path: skipped (no /tmp)"); return 0; }
      std::fputs("rootfs\n", f); std::fclose(f); }
    { std::FILE* f = std::fopen("/tmp/lx_emptypath_src.c", "w");
      if (!f) { std::puts("run_empty_path: skipped (no /tmp)"); return 0; }
      std::fputs(kSrc, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/prog /tmp/lx_emptypath_src.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_empty_path: skipped (no static glibc / gcc)"); std::system(("rm -rf " + root).c_str()); return 0; }

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));

    std::string exec = root + "/bin/prog";
    runtime::PtraceTrap trap{exec, {"/bin/prog"}, {}, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};
    auto r = cpu.run(uaddr(0), uaddr(0));
    std::system(("rm -rf " + root).c_str());
    std::remove("/tmp/lx_emptypath_src.c");

    if (!r) { std::puts("run_empty_path: skipped (ptrace unavailable)"); return 0; }
    switch (*r) {
        case 10:
            std::puts("run_empty_path: open/access/readlink(\"\")=ENOENT and a "
                      "page-straddled path read the ROOTFS, exit=10");
            return 0;
        case 2: std::puts("run_empty_path: FAIL open(\"\") did not ENOENT (bad / redirect)"); return 1;
        case 3: std::puts("run_empty_path: FAIL access(\"\") did not ENOENT"); return 1;
        case 4: std::puts("run_empty_path: FAIL readlink(\"\") did not ENOENT"); return 1;
        case 7: std::puts("run_empty_path: FAIL page-straddled path lost (open failed)"); return 1;
        case 9: std::puts("run_empty_path: FAIL straddled path read the wrong file"); return 1;
        default:
            std::printf("run_empty_path: FAIL exit=%d (expected 10)\n", *r);
            return 1;
    }
#endif
}
