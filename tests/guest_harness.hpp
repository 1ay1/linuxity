// tests/guest_harness.hpp
//
// The boilerplate every `test_run_*` repeats, written once.
//
// WHY THIS EXISTS. Twenty of the twenty-one integration tests repeat the same
// ~15 lines: write a C source to /tmp, compile it statically, skip cleanly if
// there is no gcc, build a Kernel over PosixHost, mount the rootfs and a
// synthesized /proc, construct PtraceTrap + Cpu, run, then rm -rf the
// scratch tree. Only the guest program and the assertions differ.
//
// That repetition is not harmless. Each copy re-decides what to do when the
// host can't compile a static binary, and they do NOT agree: some print
// "skipped (no static glibc / gcc)", some "skipped (no static gcc)", some
// forget to remove the temp .c file, and one leaks its scratch directory when
// the compile fails. A test that leaks state makes the NEXT run's failure
// mysterious, which is worse than the duplication.
//
// So the skip policy, the cleanup and the kernel wiring live here. A test
// keeps what is actually its own: the guest source and what it checks.
//
// SKIP, not fail: this suite must pass on a machine without a static libc.
// Returning 0 with a printed reason is deliberate -- a test that fails for
// an absent toolchain trains people to ignore red.
#pragma once

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace lxtest {

// Where a harness-run guest lives, and how it was set up.
struct GuestTree {
    std::string root;    // the read-only lower rootfs
    std::string upper;   // the writable overlay upper ("" = no overlay)
    std::string exec;    // guest path of the program, e.g. "/bin/prog"
};

// Build a scratch rootfs under /tmp. Creates <root>/bin and, when `overlay`
// is set, a sibling upper directory.
//
// `seed` is appended to the setup shell command, for the fixtures a test
// needs in the LOWER layer -- extra directories, or files the guest will
// read. It takes shell rather than a structured list on purpose: these are
// one-line `mkdir -p`/`printf` fixtures, and inventing a mini-DSL for them
// would be more code than the thing it replaces.
//
// The tree is removed first: a previous run that crashed mid-test would
// otherwise leave files that silently change what this run observes.
[[nodiscard]] inline GuestTree make_tree(const std::string& name,
                                          bool overlay = false,
                                          const std::string& seed = "",
                                          const std::string& exec = "/bin/prog") {
    GuestTree g;
    g.root  = "/tmp/lx_" + name + "_root";
    g.upper = overlay ? "/tmp/lx_" + name + "_upper" : std::string{};
    g.exec  = exec;
    std::string cmd = "rm -rf " + g.root;
    if (overlay) cmd += " " + g.upper;
    cmd += " && mkdir -p " + g.root + "/bin";
    if (overlay) cmd += " " + g.upper;
    if (!seed.empty()) cmd += " && " + seed;
    std::system(cmd.c_str());
    return g;
}

inline void remove_tree(const GuestTree& g) {
    std::string cmd = "rm -rf " + g.root;
    if (!g.upper.empty()) cmd += " " + g.upper;
    std::system(cmd.c_str());
}

// Compile `src` into the guest tree at `g.exec`. Returns false if the host
// cannot produce a static binary, having already printed the skip reason --
// so a caller writes `if (!compile_guest(...)) return 0;`.
//
// Static on purpose: a dynamic guest would need its interpreter resolved
// through the very path-translation layer under test, so a failure there
// would look like a failure of whatever the test is actually about.
[[nodiscard]] inline bool compile_guest(const char* test_name,
                                         const GuestTree& g,
                                         const char* src) {
    const std::string csrc = "/tmp/lx_" + std::string{test_name} + "_src.c";
    {
        std::FILE* f = std::fopen(csrc.c_str(), "w");
        if (!f) {
            std::printf("%s: skipped (no writable /tmp)\n", test_name);
            return false;
        }
        std::fputs(src, f);
        std::fclose(f);
    }
    const std::string cmd = "gcc -static -O2 -o " + g.root + g.exec + " " +
                            csrc + " 2>/dev/null";
    const int rc = std::system(cmd.c_str());
    std::remove(csrc.c_str());          // always, even on failure
    if (rc != 0) {
        std::printf("%s: skipped (no static glibc / gcc)\n", test_name);
        // Don't leave the scratch tree behind on a skip: a leaked tree makes
        // the NEXT run's failure mysterious.
        remove_tree(g);
        return false;
    }
    return true;
}

// Run the compiled guest under the ptrace backend, with the rootfs mounted
// (over an overlay upper when `g.upper` is set) and /proc synthesized.
//
// `argv` defaults to just the program path, and `env` to EMPTY -- matching
// what the tests did before this harness existed, so converting one doesn't
// silently change what it exercises. A test that needs a populated
// environment passes one (run_bind does: a static glibc startup reads the
// environment, and an empty envp is a different code path).
//
// Returns the guest's exit code, or nullopt when ptrace is unavailable --
// which happens under a restrictive container or an existing tracer, and is
// a skip rather than a failure.
template <class Setup>
[[nodiscard]] inline std::optional<int> run_guest(
        const GuestTree& g, Setup&& extra_setup,
        std::vector<std::string> argv = {},
        std::vector<std::string> env = {}) {
    lx::host::PosixHost hw;
    lx::kernel::Kernel<lx::host::PosixHost> k{hw};
    if (g.upper.empty()) k.files().mount_host("/", g.root);
    else                 k.files().mount_host("/", g.root, g.upper);
    k.files().mount_virtual("/proc",
                            lx::vfs::make_procfs(k.procs(), k.machine()));
    // Whatever else this particular test needs mounted or bound.
    extra_setup(k);

    if (argv.empty()) argv.push_back(g.exec);
    const std::string host_exec = g.root + g.exec;
    lx::runtime::PtraceTrap trap{host_exec, argv, env, {}};
    lx::runtime::Cpu cpu{trap, k, trap, lx::abi::Arch::x86_64};
    auto r = cpu.run(lx::uaddr(0), lx::uaddr(0));
    if (!r) return std::nullopt;
    return *r;
}

[[nodiscard]] inline std::optional<int> run_guest(const GuestTree& g) {
    return run_guest(g, [](auto&) {});
}

// Does this path exist on the HOST? Used by tests asserting that a write
// landed in the overlay upper and left the lower pristine.
[[nodiscard]] inline bool host_exists(const std::string& p) {
    struct ::stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

// Read a small host file, for checking what a guest actually wrote.
[[nodiscard]] inline std::string host_read(const std::string& p) {
    std::FILE* f = std::fopen(p.c_str(), "r");
    if (!f) return {};
    char buf[4096];
    const std::size_t n = std::fread(buf, 1, sizeof buf, f);
    std::fclose(f);
    return std::string(buf, n);
}

} // namespace lxtest
