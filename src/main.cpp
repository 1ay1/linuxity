// linuxity — run a native Linux binary under the runtime.
//
//   linuxity <program> [args...]
//
// The program executes DIRECTLY on the host CPU (native speed). Only its
// syscalls trap back into the runtime, where our subsystems service them.
// This is the whole thesis, made runnable: no VM, no emulation, native code,
// our kernel.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include <sys/stat.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unistd.h>

extern char** environ;

int main(int argc, char** argv) {
    using namespace lx;

    // Optional: `--root <dir>` chroots the guest into an extracted rootfs
    // before running the program (the 'install any distro' entry point).
    std::string root;
    int i = 1;
    if (i + 1 < argc && std::string(argv[i]) == "--root") {
        root = argv[i + 1];
        i += 2;
    }

    if (i >= argc) {
        std::fprintf(stderr,
            "usage: %s [--root <rootfs-dir>] <program> [args...]\n"
            "  Runs a native Linux binary; its syscalls are serviced by the\n"
            "  linuxity runtime (native speed, no VM, no emulation).\n"
            "  --root mounts an extracted distro rootfs as the guest '/'.\n",
            argv[0]);
        return 2;
    }

    std::string path = argv[i];
    std::vector<std::string> gargv;
    for (int j = i; j < argc; ++j) gargv.emplace_back(argv[j]);

    // Inherit the host environment for the guest (PATH etc.), so real
    // programs behave; identity syscalls are still virtualized.
    std::vector<std::string> genvp;
    for (char** e = environ; e && *e; ++e) genvp.emplace_back(*e);

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};

    // The virtual machine exposes as many logical CPUs as the host has online
    // (native execution means the guest genuinely runs on them). procfs and
    // sysfs share this count so /proc/stat, /proc/cpuinfo and
    // /sys/devices/system/cpu describe one coherent machine.
    long ncpu = ::sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;

    // Tell the kernel the virtual machine's shape so sysinfo(2) and
    // sched_getaffinity(2) match /proc and /sys (same ncpu, 2 GiB RAM).
    k.set_machine({ncpu, std::uint64_t{2048} << 20});

    // Seed the process table: pid 1 is our init (the traced root). Its
    // cmdline is the program we're about to run, so /proc/1/cmdline is real.
    {
        kernel::ProcInfo init;
        init.pid = 1; init.ppid = 0;
        init.comm = path.substr(path.find_last_of('/') + 1);
        init.cmdline.clear();
        for (std::size_t j = 0; j < gargv.size(); ++j) {
            init.cmdline += gargv[j];
            if (j + 1 < gargv.size()) init.cmdline.push_back(' ');
        }
        k.procs().upsert(init);
    }

    // Build the guest's filesystem namespace. When --root is given, the
    // rootfs directory becomes the guest '/' via PATH TRANSLATION (no chroot,
    // no privilege): every guest path the program names is rewritten to the
    // real host path underneath the rootfs before the syscall runs. /proc is
    // synthesized to report linuxity's own identity, not the host's.
    if (!root.empty()) {
        // Stack a writable, per-run overlay over the read-only rootfs so the
        // guest can write (to /tmp, /run, /var, ...) WITHOUT mutating the
        // pristine rootfs on disk — copy-up happens on first write.
        std::string upper = "/tmp/linuxity-upper-" + std::to_string(::getpid());
        (void)::mkdir(upper.c_str(), 0755);
        k.files().mount_host("/", root, upper);
        k.files().mount_virtual("/proc",
            vfs::make_procfs(k.procs(), "6.6.0-linuxity", "linuxity", ncpu));
        k.files().mount_virtual("/sys", vfs::make_sysfs(ncpu));
    } else {
        // No rootfs: the guest lives in the real host tree (paths translate
        // 1:1), but /proc and /sys are STILL synthesized so uname/pid/mounts
        // and hardware topology report linuxity's world, not the host's.
        k.files().mount_host("/", "/");
        k.files().mount_virtual("/proc",
            vfs::make_procfs(k.procs(), "6.6.0-linuxity", "linuxity", ncpu));
        k.files().mount_virtual("/sys", vfs::make_sysfs(ncpu));
    }

    // The rootfs makes the translation unprivileged, so we no longer need to
    // chroot the child. The one path the host kernel resolves itself is the
    // exec target, so translate it up front: the child execs the REAL host
    // path under the rootfs, then every syscall it makes is virtualized.
    std::string exec_path = path;
    {
        std::string abs = k.files().absolutize(path);
        auto pc = k.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) exec_path = pc.host_path;
    }
    runtime::PtraceTrap trap{exec_path, gargv, genvp, {}};

    // PtraceTrap is BOTH the trap backend and the guest-memory accessor
    // (it shares the child's real pages via process_vm_readv/writev).
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto rc = cpu.run(uaddr(0), uaddr(0));
    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", int(rc.error()));
        return 1;
    }
    return *rc;
}
