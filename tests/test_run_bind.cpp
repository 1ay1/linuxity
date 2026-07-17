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
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
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

static int run(const std::string& root,
               const std::vector<std::pair<std::string,std::string>>& binds,
               const std::vector<std::string>& argv) {
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    k.files().mount_host("/", root);
    k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
    // Bind mounts registered AFTER the rootfs — exactly what main.cpp does.
    for (auto& [h, g] : binds) k.files().mount_host(g, h);
    { kernel::ProcInfo init; init.pid = 1; init.cmdline = argv.empty()?"":argv[0];
      k.procs().upsert(init); }
    std::string exec = root + argv[0];
    // A non-empty environment: a static glibc program's startup reads the
    // env/auxv block, and an entirely empty one can perturb its early I/O.
    std::vector<std::string> env{"PATH=/bin:/usr/bin", "HOME=/root"};
    runtime::PtraceTrap trap{exec, argv, env, {}};
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};
    auto r = cpu.run(uaddr(0), uaddr(0));
    return r ? *r : -1;
}

int main() {
#if !defined(__linux__) || !defined(__x86_64__)
    std::puts("run_bind: skipped (needs Linux/x86-64 host)");
    return 0;
#else
    const std::string root = "/tmp/lx_bind_root";
    const std::string data = "/tmp/lx_bind_data";     // bound at /data
    const std::string shadow = "/tmp/lx_bind_shadow";  // bound over rootfs /etc
    std::system(("rm -rf " + root + " " + data + " " + shadow +
                 " && mkdir -p " + root + "/bin " + root + "/etc " +
                 data + " " + shadow).c_str());
    // marker in the BOUND host dir: byte 'A' (0x41 = 65).
    { std::FILE* f = std::fopen((data + "/marker").c_str(), "w");
      if (f) { std::fputc('A', f); std::fclose(f); } }
    // rootfs /etc/id says 'R' (0x52 = 82); the shadow bind's /etc/id says 'S'.
    { std::FILE* f = std::fopen((root + "/etc/id").c_str(), "w");
      if (f) { std::fputc('R', f); std::fclose(f); } }
    { std::FILE* f = std::fopen((shadow + "/id").c_str(), "w");
      if (f) { std::fputc('S', f); std::fclose(f); } }

    { std::FILE* f = std::fopen("/tmp/lx_bind.c", "w");
      if (!f) { std::puts("run_bind: skipped (no /tmp)"); return 0; }
      std::fputs(kProbe, f); std::fclose(f); }
    int rc = std::system(("gcc -static -O2 -o " + root +
                          "/bin/bprobe /tmp/lx_bind.c 2>/dev/null").c_str());
    if (rc != 0) { std::puts("run_bind: skipped (no static gcc)"); return 0; }

    // Case 1: bind an external host dir at a FRESH guest prefix /data.
    int c1 = run(root, {{data, "/data"}}, {"/bin/bprobe", "/data/marker"});
    // Case 2: without the bind, /etc/id is the rootfs 'R'.
    int c2 = run(root, {}, {"/bin/bprobe", "/etc/id"});
    // Case 3: bind SHADOWS the rootfs /etc — now /etc/id is the bind's 'S'.
    int c3 = run(root, {{shadow, "/etc"}}, {"/bin/bprobe", "/etc/id"});

    std::system(("rm -rf " + root + " " + data + " " + shadow).c_str());
    std::remove("/tmp/lx_bind.c");

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
