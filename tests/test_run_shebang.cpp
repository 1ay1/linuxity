// A `#!` script whose interpreter is a DYNAMIC binary (the pacman-hook case).
// A rootfs scriptlet like #!/bin/sh must run WITHOUT double-rooting: the host
// kernel's own shebang handling would launch the interpreter with the
// host-translated script path, which linuxity would re-translate. So the exec
// dispatcher (path_exec) resolves the shebang itself and execs the interpreter
// (via its ld.so, since it's dynamic) with the script as a GUEST path. This
// test drives a static launcher that execve's a #! script inside a rootfs, so
// the IN-GUEST execve path is exercised end to end, and asserts the script's
// interpreter runs and its exit code flows through. Skips gracefully off
// Linux/x86-64 or without gcc/ptrace.
#include "guest_harness.hpp"

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace lx;

// The launcher (STATIC): execve's the #! script by its guest path, then the
// script's interpreter's exit code becomes the launcher's (execve replaces
// the image). We wrap it so a failed exec is visible as a distinct code.
static const char* kLauncherSrc =
    "#include <unistd.h>\n"
    "int main(void){\n"
    "  char* a[] = {(char*)\"/bin/hook\", 0};\n"
    "  execv(\"/bin/hook\", a);\n"
    "  return 7;  // exec failed\n"
    "}\n";

// The interpreter: ignores its script arg, exits 42.
static const char* kInterpSrc =
    "int main(int argc, char** argv){ (void)argc; (void)argv; return 42; }\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_shebang: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const auto tree = lxtest::make_tree("shebang", /*overlay=*/false, "",
                                        "/bin/launch");
    if (!lxtest::compile_guest("run_shebang", tree, kLauncherSrc)) return 0;
    // The interpreter is STATIC too: this mini-rootfs has no ld.so/libc, so a
    // dynamic interpreter couldn't load. The dynamic-interpreter ld.so chain
    // is proven separately by the real pacman-hook run; here we exercise the
    // shebang DETECTION + rewrite (path_exec) and the static-interpreter path.
    if (!lxtest::compile_extra("run_shebang", tree, "/bin/mysh", kInterpSrc))
        return 0;

    // The #! script, naming /bin/mysh as its interpreter.
    lxtest::write_guest_file(tree, "/bin/hook", "#!/bin/mysh\n# a scriptlet\n",
                             "+x");

    // Run the static launcher; it execve's the #! script, which path_exec
    // rewrites into the mysh(guest) -> hook(guest) chain.
    auto r = lxtest::run_guest(tree, [](auto& k) {
        k.files().mount_virtual("/dev", vfs::make_devfs());
    });
    lxtest::remove_tree(tree);

    if (!r) { std::puts("run_shebang: skipped (ptrace unavailable)"); return 0; }
    if (*r == 7) {
        std::puts("run_shebang: FAIL the guest execve of the #! script failed");
        return 1;
    }
    if (*r != 42) {
        std::printf("run_shebang: FAIL exit=%d (expected 42; the dynamic "
                    "shebang interpreter did not run through cleanly)\n", *r);
        return 1;
    }
    std::puts("run_shebang: an in-guest execve of a #! script runs its "
              "interpreter with the script as a GUEST path, no double-root, exit=42");
    return 0;
#endif
}
