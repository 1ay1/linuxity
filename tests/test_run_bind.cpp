// --bind host:guest — expose a real host directory in the guest tree at an
// arbitrary guest prefix, riding linuxity's path-translation namespace (no
// privilege, no mount(2)). This is proot's -b / bwrap's --bind.
//
// The test builds a tiny rootfs and a SEPARATE host directory holding a marker
// file, then runs a static probe under linuxity with
//   --bind <hostdir>:/data
// The probe reads /data/marker and exits with a code derived from its content.
// Because /data exists in NEITHER the rootfs nor the host root, a correct read
// PROVES the bind mount resolved the guest path to the bound host directory.
//
// A second case binds to the SAME guest path as an existing rootfs dir and
// asserts the bind shadows it (longest-prefix / later-registration wins).
#include "guest_harness.hpp"

#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

using namespace lx;

// The probe reads a single byte from a path and returns it as the exit code,
// so the harness can assert the bytes came from the bound directory.
static const char* kProbe =
    "#include <unistd.h>\n#include <fcntl.h>\n"
    "int main(int argc,char**argv){\n"
    "  if(argc<2) return 100;\n"
    "  int fd=open(argv[1],O_RDONLY); if(fd<0) return 101;\n"
    "  char c=0; if(read(fd,&c,1)!=1) return 102; close(fd);\n"
    "  return (unsigned char)c;\n"
    "}\n";

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_bind: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string data = "/tmp/lx_bind_data";     // bound at /data
    const std::string shadow = "/tmp/lx_bind_shadow";  // bound over rootfs /etc
    // The bound dirs live OUTSIDE the guest tree -- that is the point: they
    // are host directories exposed at a guest prefix. marker='A' in the bound
    // dir; rootfs /etc/id='R' and the shadow bind's /etc/id='S', so which byte
    // comes back says which mount won.
    const auto tree = lxtest::make_tree("bind", /*overlay=*/false,
        "mkdir -p /tmp/lx_bind_root/etc /tmp/lx_bind_data /tmp/lx_bind_shadow"
        " && printf A > /tmp/lx_bind_data/marker"
        " && printf R > /tmp/lx_bind_root/etc/id"
        " && printf S > /tmp/lx_bind_shadow/id",
        "/bin/bprobe");
    if (!lxtest::compile_guest("run_bind", tree, kProbe)) {
        // The bound dirs live OUTSIDE the tree, so remove_tree cannot
        // reach them -- a skip must still not leave them behind.
        std::system(("rm -rf " + data + " " + shadow).c_str());
        return 0;
    }

    // Bind mounts are registered AFTER the rootfs -- exactly what main.cpp
    // does, and the ordering is what makes a bind shadow the rootfs.
    // A non-empty environment: a static glibc startup reads the env/auxv
    // block, and an entirely empty one can perturb its early I/O.
    using Binds = std::vector<std::pair<std::string, std::string>>;
    auto run = [&](const Binds& binds, const std::vector<std::string>& argv) {
        auto r = lxtest::run_guest(tree, [&](auto& k) {
            for (auto& [h, g] : binds) k.files().mount_host(g, h);
            kernel::ProcInfo init;
            init.pid = 1;
            init.cmdline = argv.empty() ? "" : argv[0];
            k.procs().upsert(init);
        }, argv, {"PATH=/bin:/usr/bin", "HOME=/root"});
        return r ? *r : -1;
    };

    // Case 1: bind an external host dir at a FRESH guest prefix /data.
    int c1 = run({{data, "/data"}}, {"/bin/bprobe", "/data/marker"});
    // Case 2: without the bind, /etc/id is the rootfs 'R'.
    int c2 = run({}, {"/bin/bprobe", "/etc/id"});
    // Case 3: bind SHADOWS the rootfs /etc — now /etc/id is the bind's 'S'.
    int c3 = run({{shadow, "/etc"}}, {"/bin/bprobe", "/etc/id"});

    lxtest::remove_tree(tree);
    std::system(("rm -rf " + data + " " + shadow).c_str());

    if (c1 == -1) { std::puts("run_bind: skipped (ptrace unavailable)"); return 0; }
    if (c1 != 'A') {
        std::printf("run_bind: FAIL /data bind read %d, want 'A'(65) — the bound "
                    "host dir did not resolve at the guest prefix\n", c1);
        return 1;
    }
    if (c2 != 'R') {
        std::printf("run_bind: FAIL rootfs /etc/id read %d, want 'R'(82)\n", c2);
        return 1;
    }
    if (c3 != 'S') {
        std::printf("run_bind: FAIL shadow bind read %d, want 'S'(83) — the bind "
                    "did not shadow the rootfs /etc\n", c3);
        return 1;
    }
    std::puts("run_bind: --bind exposes a host dir at a guest prefix (fresh /data "
              "and shadowing the rootfs /etc), resolving through linuxity's "
              "path-translation namespace unprivileged");
    return 0;
#endif
}
