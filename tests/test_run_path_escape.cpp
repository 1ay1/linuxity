// Every path-bearing syscall must be trapped, or it is a sandbox escape.
//
// linuxity confines a guest by TRANSLATING paths, not by chroot. So the
// confinement is exactly as strong as the set of syscalls that get
// intercepted: any syscall carrying a `char*` path that is NOT in
// kTrappedX86_64 hands that path straight to the host kernel, and the guest
// reaches the host filesystem.
//
// Two real escapes this caught, both verified by exploiting them first:
//
//   creat(85)      -- neither trapped NOR handled. A direct
//                     syscall(SYS_creat, "/tmp/x") returned fd 4 and created
//                     the file in the HOST's /tmp, with no /tmp in the guest
//                     tree at all.
//   fchmodat2(452) -- the inverse: do_chmod HANDLES it, but it was never
//                     trapped, so that handler was dead code and the chmod
//                     landed on the host path. Same shape as the
//                     lseek/rewinddir bug: a correct handler is useless if
//                     the syscall never reaches it.
//
// glibc routes creat() through openat, so nothing ordinary hits it -- but a
// direct syscall() does, and "nothing ordinary" is not a security boundary.
#include "guest_harness.hpp"

#include <cstdio>
#include <string>
#include <sys/stat.h>

using namespace lx;

// The guest writes through syscalls that take a path but which glibc would
// normally route elsewhere. If any lands on the host, we escaped.
static const char* kSrc =
    "#include <fcntl.h>\n"
    "#include <stdio.h>\n"
    "#include <unistd.h>\n"
    "#include <sys/syscall.h>\n"
    "int main(void){\n"
    // creat(2): open(O_CREAT|O_WRONLY|O_TRUNC) under another number.
    "  int fd = (int)syscall(SYS_creat, \"/tmp/lx_escape_probe\", 0644);\n"
    "  if (fd < 0) return 10;\n"
    "  if (write(fd, \"guest\\n\", 6) != 6) return 11;\n"
    "  close(fd);\n"
    // fchmodat2(452): chmod with a path, the newer form.
    "  long r = syscall(452, AT_FDCWD, \"/tmp/lx_escape_probe\", 0600, 0);\n"
    "  if (r != 0 && r != -38) return 12;   /* ENOSYS on an old kernel is ok */\n"
    // The guest must be able to read back what it just wrote, by the SAME
    // guest path -- proving the write went into our namespace, not nowhere.
    "  fd = open(\"/tmp/lx_escape_probe\", O_RDONLY);\n"
    "  if (fd < 0) return 13;\n"
    "  char b[16] = {0};\n"
    "  ssize_t n = read(fd, b, sizeof b - 1);\n"
    "  close(fd);\n"
    "  if (n != 6) return 14;\n"
    "  return 33;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_path_escape: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    // An overlay, so a guest write has a legitimate home (the upper) and we
    // can tell "landed in the sandbox" from "landed on the host".
    const auto tree = lxtest::make_tree("escape", /*overlay=*/true);
    if (!lxtest::compile_guest("run_path_escape", tree, kSrc)) return 0;

    // The exact host paths a failed translation would hit. The guest asks for
    // "/escape_creat"; untranslated, that is the HOST's root.
    // A HOST-WRITABLE target on purpose. The guest asks for
    // "/tmp/lx_escape_probe"; untranslated that is the host's real /tmp, which
    // this user CAN write -- so a failed translation is observable. Pointing
    // the probe at "/" instead would hide the escape behind a permission
    // error and the test would pass for the wrong reason.
    const char* host_targets[] = {"/tmp/lx_escape_probe"};
    for (const char* p : host_targets) ::remove(p);

    auto r = lxtest::run_guest(tree);

    // Check the host BEFORE cleaning up, and record it before asserting.
    bool escaped = false;
    std::string where;
    for (const char* p : host_targets)
        if (lxtest::host_exists(p)) { escaped = true; where = p; ::remove(p); }
    // The legitimate destination: inside the overlay upper.
    const bool in_sandbox = lxtest::host_exists(tree.upper + "/tmp/lx_escape_probe");

    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_path_escape: skipped (ptrace unavailable)"); return 0; }

    if (escaped) {
        std::printf("run_path_escape: FAIL *** SANDBOX ESCAPE *** the guest's "
                    "write landed on the HOST at %s. A path-bearing syscall is "
                    "missing from kTrappedX86_64 "
                    "(runtime/linux/seccomp_filter.hpp) -- an untrapped path "
                    "goes straight to the host kernel.\n", where.c_str());
        return 1;
    }
    if (*r == 10) {
        std::puts("run_path_escape: FAIL creat() itself failed -- it is trapped "
                  "but the dispatcher has no case for it, so it fell through to "
                  "a refusal instead of being translated.");
        return 1;
    }
    if (*r >= 11 && *r <= 14) {
        std::printf("run_path_escape: FAIL guest could not read back its own "
                    "write (code %d) -- the path was confined but not coherent: "
                    "creat and open resolved to DIFFERENT places.\n", *r);
        return 1;
    }
    if (*r != 33) {
        std::printf("run_path_escape: FAIL guest exit=%d (expected 33)\n", *r);
        return 1;
    }
    if (!in_sandbox) {
        std::puts("run_path_escape: FAIL nothing escaped, but the write is not "
                  "in the overlay upper either -- it went somewhere unexpected.");
        return 1;
    }
    std::puts("run_path_escape: creat(2) and fchmodat2(2) are translated into "
              "the overlay upper, nothing reaches the host filesystem, and the "
              "guest reads back its own write by the same guest path, exit=33");
    return 0;
#endif
}
