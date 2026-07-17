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
#include "linuxity/kernel/resources.hpp"
#include "linuxity/loader/interp.hpp"
#include "linuxity/runtime/ptrace_trap.hpp"
#include "linuxity/runtime/resource_governor.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include <sys/stat.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

extern char** environ;

namespace {

// If a real cgroup bound was requested but linuxity's OWN cgroup has no
// delegated controllers (the common unprivileged case), we can't create a
// child cgroup with live limit files. systemd, which owns the user session
// hierarchy, CAN carve out a properly-delegated scope for us. So re-exec the
// whole linuxity invocation inside `systemd-run --user --scope`: the guest
// then launches under a delegated scope where ResourceGovernor's direct-cgroup
// path works precisely. An env marker breaks the recursion, and if systemd-run
// is absent we simply proceed (the governor falls back to setrlimit).
void maybe_reexec_delegated(int argc, char** argv, bool want_cgroup) {
    if (!want_cgroup) return;
    if (std::getenv("LINUXITY_DELEGATED")) return;   // already re-exec'd
    // Probe: does our own cgroup already delegate cpu+memory? If so, the
    // governor can create a child directly — no need to involve systemd.
    if (std::FILE* f = std::fopen("/proc/self/cgroup", "r")) {
        char line[4096]; std::string rel;
        while (std::fgets(line, sizeof line, f)) {
            if (std::strncmp(line, "0::", 3) == 0) {
                rel = line + 3;
                if (!rel.empty() && rel.back() == '\n') rel.pop_back();
            }
        }
        std::fclose(f);
        std::string sc = "/sys/fs/cgroup" + (rel == "/" ? std::string{} : rel) +
                         "/cgroup.subtree_control";
        if (std::FILE* s = std::fopen(sc.c_str(), "r")) {
            char ctl[256] = {0}; (void)!std::fgets(ctl, sizeof ctl, s);
            std::fclose(s);
            if (std::strstr(ctl, "memory") || std::strstr(ctl, "cpu"))
                return;   // already delegated, direct path will work
        }
    }
    // Need systemd-run to carve a delegated scope. Absent => proceed to rlimit.
    if (::access("/usr/bin/systemd-run", X_OK) != 0 &&
        ::access("/bin/systemd-run", X_OK) != 0)
        return;

    std::vector<char*> a;
    a.push_back(const_cast<char*>("systemd-run"));
    a.push_back(const_cast<char*>("--user"));
    a.push_back(const_cast<char*>("--scope"));
    a.push_back(const_cast<char*>("-q"));
    // Delegate the controllers into the new scope so OUR child cgroup can set
    // limits; --pty would forward the tty, but linuxity's guest inherits our
    // stdio directly, so a plain scope suffices.
    a.push_back(const_cast<char*>("-p"));
    a.push_back(const_cast<char*>("Delegate=yes"));
    a.push_back(const_cast<char*>("--"));
    for (int j = 0; j < argc; ++j) a.push_back(argv[j]);
    a.push_back(nullptr);
    ::setenv("LINUXITY_DELEGATED", "1", 1);
    ::execvp("systemd-run", a.data());
    // execvp only returns on failure; fall through to run un-delegated.
    ::unsetenv("LINUXITY_DELEGATED");
}

}  // namespace

int main(int argc, char** argv) {
    using namespace lx;

    // Parse leading flags: `--root <dir>` mounts a rootfs; the resource flags
    // (`--cpus N`, `--memory SZ`, `--memory-swap SZ`, `--pids N`, `--cpuset
    // LIST`) BOUND the guest tree via the host kernel (cgroup v2 / rlimit) and
    // DERIVE the machine the guest believes it has, so belief == enforced
    // reality. Flags may appear in any order before the program.
    std::string root;
    kernel::ResourceSpec res;
    int i = 1;
    auto need = [&](const char* what) -> const char* {
        if (i + 1 >= argc) {
            std::fprintf(stderr, "linuxity: %s needs an argument\n", what);
            std::exit(2);
        }
        return argv[++i];
    };
    for (; i < argc; ++i) {
        std::string f = argv[i];
        if (f == "--root") { root = need("--root"); }
        else if (f == "--cpus")        { res.cpus = std::atof(need("--cpus")); }
        else if (f == "--memory" || f == "-m") {
            if (auto b = kernel::parse_bytes(need("--memory"))) res.mem_max = *b;
            else { std::fprintf(stderr, "linuxity: bad --memory size\n"); return 2; }
        }
        else if (f == "--memory-swap") {
            if (auto b = kernel::parse_bytes(need("--memory-swap"))) res.swap_and_mem_max = *b;
            else { std::fprintf(stderr, "linuxity: bad --memory-swap size\n"); return 2; }
        }
        else if (f == "--pids")   { res.pids_max = std::strtoull(need("--pids"), nullptr, 10); }
        else if (f == "--cpuset") { res.cpuset = need("--cpuset"); }
        else break;   // first non-flag: the program
    }

    if (i >= argc) {
        std::fprintf(stderr,
            "usage: %s [OPTIONS] <program> [args...]\n"
            "  Runs a native Linux binary; its syscalls are serviced by the\n"
            "  linuxity runtime (native speed, no VM, no emulation).\n"
            "\n"
            "  --root <dir>        mount an extracted distro rootfs as guest '/'\n"
            "  --cpus <N>          bound CPU to N cores' worth (e.g. 1.5)\n"
            "  --memory <SZ>       hard memory ceiling (e.g. 512M, 2G)\n"
            "  --memory-swap <SZ>  combined memory+swap ceiling\n"
            "  --pids <N>          max tasks in the guest tree (fork-bomb guard)\n"
            "  --cpuset <LIST>     pin to CPUs (e.g. 0-1, 0,2,4)\n"
            "\n"
            "  The resource bounds are enforced by the HOST kernel (cgroup v2,\n"
            "  or setrlimit where a cgroup can't be created unprivileged) and\n"
            "  the guest's /proc, /sys and sysinfo are derived to MATCH them.\n",
            argv[0]);
        return 2;
    }

    // If a hard bound was asked for, try to run under a delegated cgroup scope
    // (via systemd-run) so the enforcement is precise. This re-execs the whole
    // process; on return we are either delegated or proceeding with fallback.
    maybe_reexec_delegated(argc, argv, res.mem_max.has_value() ||
                                       res.cpus.has_value() ||
                                       res.pids_max.has_value());

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

    // Configure the virtual machine ONCE. This MachineSpec is the single
    // source of truth: /proc, /sys, and the sysinfo/sched_getaffinity syscalls
    // all read this same instance (owned by the kernel), so they can never
    // disagree. Native execution really runs on the host CPUs, so ncpu is the
    // host's online count; everything else is linuxity's own identity.
    {
        kernel::MachineSpec spec;
        spec.ncpu = ncpu;
        spec.mem_total = std::uint64_t{2048} << 20;   // 2 GiB
        spec.release = "6.6.0-linuxity";
        spec.nodename = "linuxity";
        // Fold the enforced resource policy INTO the advertised machine, so a
        // program that sizes its caches to "half of RAM" or starts "one worker
        // per CPU" shapes itself to the bound it will actually be held to —
        // belief == enforced reality (kernel/resources.hpp::advertise).
        spec = res.advertise(std::move(spec));
        k.set_machine(std::move(spec));
    }

    // Establish the host-side enforcement for the guest tree. The governor
    // creates a cgroup v2 subtree (when the controllers are delegated — e.g.
    // after the systemd-run re-exec above) or installs rlimit fallbacks; the
    // child adopts it via the pre-exec hook so every descendant inherits it.
    runtime::ResourceGovernor governor{res};
    if (std::string how = governor.describe(); !how.empty())
        std::fprintf(stderr, "linuxity: %s\n", how.c_str());

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
        k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
        k.files().mount_virtual("/dev", vfs::make_devfs());
    } else {
        // No rootfs: the guest lives in the real host tree (paths translate
        // 1:1), but /proc and /sys are STILL synthesized so uname/pid/mounts
        // and hardware topology report linuxity's world, not the host's.
        k.files().mount_host("/", "/");
        k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
        k.files().mount_virtual("/dev", vfs::make_devfs());
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

    // A dynamically-linked guest names its interpreter (ld-linux / ld-musl) in
    // PT_INTERP. The HOST kernel would resolve that path against the HOST root
    // at execve time — where a guest rootfs's /lib/ld-musl-x86_64.so.1 does
    // not exist, so the exec fails silently. Instead, read the interp, map it
    // through linuxity's namespace to its real host location, and exec the
    // INTERPRETER directly with the program as argv[1]. The loader then opens
    // every shared library via ordinary (redirected) openat syscalls, all
    // inside the rootfs — no chroot, no privilege. argv[0] stays the guest
    // program name so the process sees itself correctly.
    std::vector<std::string> child_argv = gargv;
    if (std::string interp = loader::read_elf_interp(exec_path); !interp.empty()) {
        std::string interp_abs = k.files().absolutize(interp);
        auto ipc = k.files().classify(interp_abs);
        std::string interp_host = interp;
        if (ipc.realm == kernel::Realm2::host_backed) interp_host = ipc.host_path;
        // ld.so <host-prog> <original-args...>; keep gargv[0] as argv[1] so the
        // guest program's own argv[0] is preserved by the loader.
        child_argv.clear();
        child_argv.push_back(interp_host);   // the interpreter to exec (host path)
        // The program the loader should open is named in the GUEST namespace:
        // the loader's own openat on it is virtualized/redirected into the
        // rootfs. Passing the host path would make linuxity re-translate it
        // (rootfs-under-rootfs) and fail. Use the guest path the user named.
        child_argv.push_back(k.files().absolutize(path));
        for (std::size_t j = 1; j < gargv.size(); ++j)
            child_argv.push_back(gargv[j]);  // the guest program's args
        exec_path = interp_host;             // exec the interpreter itself
    }
    runtime::PtraceTrap trap{exec_path, child_argv, genvp, {},
                             [&governor]() { governor.join_child(); }};

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
