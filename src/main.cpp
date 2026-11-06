// linuxity — run a native Linux binary under the runtime.
//
//   linuxity <program> [args...]
//
// The program executes DIRECTLY on the host CPU (native speed). Only its
// syscalls trap back into the runtime, where our subsystems service them.
// This is the whole thesis, made runnable: no VM, no emulation, native code,
// our kernel.
#include "linuxity/conform/arch.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/kernel/resolver.hpp"
#include "linuxity/kernel/resources.hpp"
#include "linuxity/loader/interp.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/resource_governor.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include <sys/stat.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

extern char** environ;

namespace {

// Copy the HOST's arm64 CPU identity into the advertised machine.
//
// /proc/cpuinfo's "Features" is not decoration on arm64: libgcrypt (and other
// hand-written crypto) reads it, picks an instruction path from it, and the
// guest executes NATIVELY on this CPU. Advertising a feature the silicon does
// not have is therefore a crash, not a cosmetic lie -- `gpg --import` died
// with SIGILL on a Snapdragon because a hardcoded Apple M-series list
// promised sha3/sha512. Anything we cannot read keeps the conservative
// ARMv8.0 default from MachineSpec.
#if defined(__linux__) && defined(__aarch64__)
void read_host_arm64_cpu(lx::kernel::MachineSpec& spec) {
    std::ifstream in{"/proc/cpuinfo"};
    if (!in) return;
    auto after_colon = [](const std::string& line) {
        const auto c = line.find(':');
        if (c == std::string::npos) return std::string{};
        auto v = line.substr(c + 1);
        const auto b = v.find_first_not_of(" \t");
        if (b == std::string::npos) return std::string{};
        auto e = v.find_last_not_of(" \t\r\n");
        return v.substr(b, e - b + 1);
    };
    // First processor block only: every core advertises the same features on
    // every arm64 system Linux will boot (big.LITTLE included -- the kernel
    // reports the common set).
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("Features", 0) == 0) {
            if (auto v = after_colon(line); !v.empty()) spec.cpu_features = v;
        } else if (line.rfind("CPU implementer", 0) == 0) {
            if (auto v = after_colon(line); !v.empty()) spec.cpu_implementer = v;
        } else if (line.rfind("CPU architecture", 0) == 0) {
            if (auto v = after_colon(line); !v.empty()) spec.cpu_architecture = v;
        } else if (line.rfind("CPU part", 0) == 0) {
            auto v = after_colon(line);
            if (v.rfind("0x", 0) == 0) v.erase(0, 2);   // stored without 0x
            if (!v.empty()) spec.cpu_part = v;
            break;   // CPU part is the last of the four in a block
        }
    }
}
#else
void read_host_arm64_cpu(lx::kernel::MachineSpec&) {}
#endif

// Occupy the low file-descriptor slots (3..8) with harmless /dev/null handles
// in the freshly forked child, BEFORE it execs the guest. This makes the
// guest's dynamic fd numbering start above the reserved range — mirroring a
// process launched from a real login session that inherits several open fds
// (the terminal, the journal, a dbus socket, ...). It is load-bearing for
// multi-threaded downloaders: pacman's libcurl workers create a short-lived
// wakeup fd and open the data file nearly simultaneously; when both compete
// for the SAME lowest-free descriptor (fd 3 in a bare 0,1,2-only process), a
// sibling thread's 8-byte wakeup write lands in the data file and corrupts it
// (observed: core.db gains 32 stray bytes). Holding the low slots open keeps
// the two on distinct descriptors, exactly as on a normal host. The handles
// survive execve (no CLOEXEC) so they still occupy the slots while the guest
// and its forked workers run; /dev/null makes any stray access a no-op.
void reserve_low_fds() {
    for (int want = 3; want <= 8; ++want) {
        int fd = ::open("/dev/null", O_RDWR);
        if (fd < 0) break;
        if (fd > want) { ::close(fd); }   // slot already taken; leave it be
        else if (fd < want) {
            // Shouldn't happen (we open in ascending order), but never leak.
            ::close(fd);
        }
        // fd == want: keep it open, occupying the slot.
    }
}

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
    // --persist <dir>: a DURABLE upper overlay layer. Without it the writable
    // upper is a fresh /tmp/linuxity-upper-<pid> torn down each run, so a
    // `pacman -S pkg` install evaporates when the process exits. Point
    // --persist at a directory and every write (installed packages, the pacman
    // local DB, config) survives across runs — a real, mutable machine.
    std::string persist;
    // Transparent pacman --overwrite "*": ON by default whenever a --root
    // distro is mounted (the bootstrap rootfs has orphan library files that
    // would otherwise abort installs). --no-pacman-overwrite disables it.
    bool pacman_overwrite = true;
    // A PRIVATE /tmp, on by default.
    //
    // The guest's top process is pid 1, correctly -- it is the guest's init.
    // But a shared /tmp turns that into a collision: anything that derives a
    // filename from getpid() gets the SAME name every run. GNU make names its
    // jobserver FIFO /tmp/GMfifo<pid>, so one interrupted `make -j` strands
    // /tmp/GMfifo1 and every later build fails with
    //
    //     make: jobserver mkfifo: /tmp/GMfifo1: File exists
    //
    // Natively pids are 7 digits and effectively never recur, which is why
    // this is invisible outside a pid namespace. A real container gets a
    // private /tmp for exactly this reason.
    //
    // Costs nothing at runtime: it is one more entry in the mount table the
    // path translator already walks for every syscall, not a namespace or a
    // mount. --shared-tmp opts out for workflows that hand files to the host
    // through /tmp.
    bool private_tmp = true;
    // Where that private /tmp landed, so it can be torn down on exit.
    std::string private_tmp_dir;
    // The EPHEMERAL overlay upper, likewise. Empty with --persist, which must
    // survive the run.
    std::string ephemeral_upper;
    kernel::ResourceSpec res;
    // --bind host[:guest] mounts a real host directory into the guest tree at
    // `guest` (default: same path). Thin wrapper over FileNamespace::mount_host
    // — exactly proot's -b / bubblewrap's --bind, but riding linuxity's own
    // path-translation namespace (no privilege, no real mount(2)).
    std::vector<std::pair<std::string, std::string>> binds;
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
        else if (f == "--persist" || f == "--upper") { persist = need("--persist"); }
        else if (f == "--no-pacman-overwrite") { pacman_overwrite = false; }
        else if (f == "--pacman-overwrite")    { pacman_overwrite = true; }
        else if (f == "--shared-tmp")  { private_tmp = false; }
        else if (f == "--private-tmp") { private_tmp = true; }
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
        else if (f == "--bind" || f == "-b") {
            // host[:guest] — split on the LAST ':' so a Windows-free host path
            // with no colon binds to itself; guest defaults to the host path.
            std::string spec = need("--bind");
            auto colon = spec.rfind(':');
            std::string host = colon == std::string::npos ? spec
                                                          : spec.substr(0, colon);
            std::string guest = colon == std::string::npos ? spec
                                                           : spec.substr(colon + 1);
            if (host.empty() || guest.empty() || guest.front() != '/') {
                std::fprintf(stderr,
                    "linuxity: bad --bind '%s' (want host[:/guest-abs])\n",
                    spec.c_str());
                return 2;
            }
            binds.emplace_back(std::move(host), std::move(guest));
        }
        else break;   // first non-flag: the program
    }

    if (i >= argc) {
        std::fprintf(stderr,
            "usage: %s [OPTIONS] <program> [args...]\n"
            "  Runs a native Linux binary; its syscalls are serviced by the\n"
            "  linuxity runtime (native speed, no VM, no emulation).\n"
            "\n"
            "  --root <dir>        mount an extracted distro rootfs as guest '/'\n"
            "  --persist <dir>     durable overlay upper: installs/writes survive\n"
            "                      across runs (default: ephemeral per-run)\n"
            "  --shared-tmp        share the host's /tmp (default: private, so a\n"
            "                      pid-derived name like make's GMfifo<pid>\n"
            "                      cannot collide across runs)\n"
            "  --no-pacman-overwrite  don't auto-pass pacman --overwrite \"*\"\n"
            "                      (default: on with --root, so a bootstrap\n"
            "                      rootfs's orphan lib files never block installs)\n"
            "  --cpus <N>          bound CPU to N cores' worth (e.g. 1.5)\n"
            "  --memory <SZ>       hard memory ceiling (e.g. 512M, 2G)\n"
            "  --memory-swap <SZ>  combined memory+swap ceiling\n"
            "  --pids <N>          max tasks in the guest tree (fork-bomb guard)\n"
            "  --cpuset <LIST>     pin to CPUs (e.g. 0-1, 0,2,4)\n"
            "  --bind host[:guest] expose a host dir in the guest tree\n"
            "                      (guest defaults to the same path)\n"
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

    // With a rootfs mounted, linuxity presents a ROOT-OWNED world (every guest
    // uid/gid is scrubbed to 0). But the host shell that launched us exported
    // its OWN identity — USER=ayush, LOGNAME=ayush, HOME=/home/ayush — and
    // those leak straight into the guest. That's why an interactive bash shows
    // `I have no name!`: its prompt resolves \u via getpwuid/LOGNAME, sees
    // "ayush" (a name that doesn't exist in the rootfs's /etc/passwd), and
    // falls back. It also points HOME at a host path the rootfs doesn't have.
    // Overwrite the identity vars to the coherent root values so bash, sudo,
    // ~ expansion, and $HOME/.config all agree with the uid=0 world we serve.
    // (Purely cosmetic-to-correctness; syscalls were already virtualized.)
    if (!root.empty()) {
        auto set_env = [&genvp](std::string_view key, std::string_view val) {
            std::string prefix = std::string{key} + "=";
            for (auto& kv : genvp)
                if (kv.rfind(prefix, 0) == 0) { kv = prefix + std::string{val}; return; }
            genvp.emplace_back(prefix + std::string{val});
        };
        set_env("USER", "root");
        set_env("LOGNAME", "root");
        set_env("HOME", "/root");
        set_env("SHELL", "/bin/bash");
        // A DISTRO umask, for the same reason as the environment above: the
        // guest is a Linux distro, not this host's shell session. Every
        // distro ships 022 (via /etc/profile or pam_umask); Android's adb
        // shell runs 000, and the guest inherits whatever it finds.
        //
        // That is not cosmetic. `mkdir -p` asks the kernel for 0777 and
        // lets umask subtract -- so under 000 every directory a package
        // manager creates really is world-writable, and pacman then reports
        // "directory permissions differ on /etc/, filesystem: 777 package:
        // 755" against its own manifest. Verified not to be a linuxity bug:
        // native Android `mkdir -p` gives 777 too. The guest just needs the
        // mask its own userland would have set.
        //
        // It is only a DEFAULT: umask(2) is not intercepted, so a guest
        // profile or program that sets its own still wins.
        (void)::umask(022);
        // PATH belongs to the ROOTFS, not the host. Inheriting it works by
        // luck on a Linux host (/usr/bin is /usr/bin either way) and fails
        // completely on Android, where the host PATH is /system/bin:/apex/...
        // -- none of which exists in the guest, so an interactive shell
        // answers "pacman: command not found" for a pacman that is sitting
        // right there in /usr/bin.
        //
        // Keep any extra directories the caller added that DO exist in the
        // guest, so `--root ... env PATH=/opt/mine:...` still means
        // something, and drop the host-only ones.
        {
            std::string merged = "/usr/local/sbin:/usr/local/bin:/usr/bin:"
                                 "/usr/sbin:/bin:/sbin";
            if (const char* hp = std::getenv("PATH"); hp != nullptr) {
                std::string_view rest{hp};
                while (!rest.empty()) {
                    const auto cut = rest.find(':');
                    const std::string_view dir = rest.substr(0, cut);
                    if (!dir.empty() && merged.find(std::string{dir}) ==
                                            std::string::npos) {
                        struct ::stat st{};
                        if (::stat((root + std::string{dir}).c_str(), &st) == 0)
                            merged += ":" + std::string{dir};
                    }
                    if (cut == std::string_view::npos) break;
                    rest.remove_prefix(cut + 1);
                }
            }
            set_env("PATH", merged);
        }
    }

    // Transparent pacman --overwrite "*": expose the mode to the dispatcher
    // (abi::path_exec reads this via getenv on the linuxity process) so a
    // pacman execve anywhere in the guest tree gets `--overwrite "*"` appended.
    // A bootstrap rootfs ships unowned lib files (libgcc_s/libstdc++/...) that
    // pacman would otherwise refuse to overwrite; the first install then
    // registers ownership, so it's a no-op afterward. Only with --root.
    if (!root.empty() && pacman_overwrite)
        ::setenv("LINUXITY_PACMAN_OVERWRITE", "1", 1);
    else
        ::unsetenv("LINUXITY_PACMAN_OVERWRITE");

    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};
    // Before any mount: the base mount_host() resolves relative host paths
    // against (`--root ./arch`, `--persist ./upper`, `--bind ./src`).
    if (char cwd[4096]; ::getcwd(cwd, sizeof cwd) != nullptr)
        k.files().set_host_cwd(cwd);

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
        // On arm64 the guest's /proc/cpuinfo "Features" must be the HOST's.
        // The guest executes natively, so libgcrypt (and anything else that
        // picks an instruction path from this line) will run what it reads: a
        // feature we advertise but the CPU lacks is a SIGILL. gpg --import
        // died that way under a hardcoded list. Copy the host's own values.
        if (spec.machine_arch == "aarch64")
            read_host_arm64_cpu(spec);
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
            if (j + 1 < gargv.size()) init.cmdline.push_back('\0');   // ProcInfo: NUL-joined
        }
        k.procs().upsert(init);

        // An INHERITED terminal is already our controlling one, and the guest
        // will never call TIOCSCTTY for it -- a shell launched from a
        // terminal just expects /dev/tty and tcgetpgrp to work on fd 0. So
        // seed the ctty from whatever stdin is, when stdin is a pty.
        //
        // The std fds also need their PATHS bound, not just the ctty. bash
        // reaches the terminal as dup(2)->9, dup3(9,255) and then does every
        // job-control ioctl on fd 255; the dup mirror copies fd 2's path, so
        // if fd 2 has none the whole chain is pathless and the ioctl cannot
        // tell it is looking at the terminal. That is what made bash say
        // "cannot set terminal process group (-1)" on Android.
        for (int fd = 0; fd <= 2; ++fd) {
            if (::isatty(fd) == 0) continue;
            const char* n = ::ttyname(fd);
            if (n == nullptr) continue;
            constexpr std::string_view kPre = "/dev/pts/";
            if (!std::string_view{n}.starts_with(kPre)) continue;
            k.files().bind_fd(fd, n);
            k.procs().set_ctty(1, std::atoi(n + kPre.size()));
        }
    }

    // Where /dev/shm gets its STORAGE.
    //
    // The host's own tmpfs when it has one: world-writable (drwxrwxrwt), so
    // this needs no privilege and shared memory is really shared. Android
    // ships no /dev/shm at all -- it uses ashmem/memfd -- and the guest
    // cannot create one, since /dev is a read-only tmpfs there. So fall back
    // to a directory of our own, which is on real storage rather than RAM
    // but satisfies everything that matters: sem_open, shm_open and
    // mmap(MAP_SHARED) all work on a plain file.
    //
    // Without this, python's multiprocessing died constructing any
    // ProcessPoolExecutor -- FileNotFoundError straight out of sem_open --
    // and LTP could not stage a single shm test. Chosen BEFORE the devfs
    // mounts below, which capture it.
    std::string shm_dir = "/dev/shm";
    {
        struct ::stat sst{};
        const bool host_has = ::stat("/dev/shm", &sst) == 0 &&
                              S_ISDIR(sst.st_mode) &&
                              ::access("/dev/shm", W_OK) == 0;
        if (!host_has) {
            // Same convention and location as the private /tmp below: named
            // with the SUPERVISOR's pid, since the guest's is always 1.
            shm_dir = "/tmp/linuxity-shm-" +
                      std::to_string(static_cast<long>(::getpid()));
            (void)::mkdir(shm_dir.c_str(), 01777);
            (void)::chmod(shm_dir.c_str(), 01777);
        }
    }

    // Build the guest's filesystem namespace. When --root is given, the
    // rootfs directory becomes the guest '/' via PATH TRANSLATION (no chroot,
    // no privilege): every guest path the program names is rewritten to the
    // real host path underneath the rootfs before the syscall runs. /proc is
    // synthesized to report linuxity's own identity, not the host's.
    if (!root.empty()) {
        // Stack a writable overlay over the read-only rootfs so the guest can
        // write WITHOUT mutating the pristine rootfs; copy-up happens on first
        // write. With --persist the upper is a caller-named DURABLE directory
        // (installs/DB/config survive across runs — a real machine); without
        // it, a fresh per-run /tmp dir that's implicitly discarded on exit.
        std::string upper = persist.empty()
            ? "/tmp/linuxity-upper-" + std::to_string(::getpid())
            : persist;
        if (persist.empty()) ephemeral_upper = upper;
        if (!persist.empty()) {
            // Create the persistent tree (and its parents) if new; existing
            // contents are reused as-is so prior installs are visible.
            std::string acc;
            for (std::size_t p = 1; p <= upper.size(); ++p) {
                if (p == upper.size() || upper[p] == '/') {
                    acc = upper.substr(0, p);
                    if (acc != "/") (void)::mkdir(acc.c_str(), 0755);
                }
            }
            std::fprintf(stderr, "linuxity: persistent overlay upper at %s\n",
                         upper.c_str());
        } else {
            (void)::mkdir(upper.c_str(), 0755);
        }
        k.files().mount_host("/", root, upper);
        k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
        k.files().mount_virtual("/dev", vfs::make_devfs(
            [&k] { return k.procs().ctty_of(k.files().current_pid()); },
            shm_dir));
    } else {
        // No rootfs: the guest lives in the real host tree (paths translate
        // 1:1), but /proc and /sys are STILL synthesized so uname/pid/mounts
        // and hardware topology report linuxity's world, not the host's.
        k.files().mount_host("/", "/");
        k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
        k.files().mount_virtual("/dev", vfs::make_devfs(
            [&k] { return k.procs().ctty_of(k.files().current_pid()); },
            shm_dir));
    }

    // Private /tmp (see `private_tmp` above). Registered BEFORE --bind so an
    // explicit `--bind /tmp` still wins by longest-prefix, and before the
    // guest starts so nothing has looked at /tmp yet.
    //
    // Named with the SUPERVISOR's pid, which is what makes it unique -- the
    // guest's own pid cannot, since it is always 1. Same convention as the
    // overlay upper dir above.
    if (private_tmp) {
        const std::string gt = "/tmp/linuxity-tmp-" + std::to_string(::getpid());
        // 1777, like a real /tmp: world-writable with the sticky bit. 0700 is
        // wrong here even though only one guest uses it -- the guest presents
        // as root while the directory is owned by the invoking uid, so a
        // 0700 dir denied every guest write. That showed up as gcc failing
        // with "Assembler messages: Fatal error: can't create s3.o: Permission
        // denied" under `make -j`, because gcc puts its assembler temporaries
        // in TMPDIR.
        (void)::mkdir(gt.c_str(), 01777);
        // mkdir's mode is masked by umask, and the sticky bit often does not
        // survive it, so set it explicitly.
        (void)::chmod(gt.c_str(), 01777);
        k.files().mount_host("/tmp", gt);
        private_tmp_dir = gt;
    }

    // --bind mounts: expose real host directories at guest prefixes. Registered
    // AFTER the rootfs so a deeper/explicit bind wins by longest-prefix (e.g.
    // --bind /home/me/proj:/proj shadows whatever /proj the rootfs had). These
    // are host-backed and WRITABLE in place (no overlay) — the point of a bind
    // is to share a live host directory with the guest, so writes land on the
    // real host files, exactly like a bind mount.
    for (auto& [host_dir, guest_at] : binds) {
        std::string norm = kernel::FileNamespace::normalize(guest_at);
        k.files().mount_host(norm, host_dir);
        std::fprintf(stderr, "linuxity: bind %s -> %s\n",
                     norm.c_str(), host_dir.c_str());
    }

    // Guarantee working DNS in a real rootfs (the proot-distro lesson, done
    // the modern way). proot-distro OVERWRITES the rootfs's /etc/resolv.conf on
    // disk with hardcoded 8.8.8.8; linuxity never mutates the image.
    //
    // DNS. A pristine rootfs ships /etc/resolv.conf empty or absent, so the
    // runtime supplies one: kernel/resolver.hpp picks the nameservers (env
    // override > the image's own > the host's resolv.conf > public) and the
    // namespace serves the result as a VIRTUAL file, like /proc and /dev.
    //
    // This used to BIND the host's /etc/resolv.conf, which is a glibc-ism:
    // Android has no such file (DNS lives in netd), so the bind silently did
    // nothing and every guest lookup failed while the host resolved fine.
    // Serving a virtual file is one path for every host and never mutates
    // the image. Opt out with LINUXITY_NO_DNS=1.
    if (!root.empty() && !std::getenv("LINUXITY_NO_DNS")) {
        const auto gpc = k.files().classify("/etc/resolv.conf");
        const std::string guest_resolv =
            gpc.realm == kernel::Realm2::host_backed ? gpc.host_path : std::string{};

        const auto choice = kernel::choose_nameservers(
            std::getenv("LINUXITY_DNS"), "/etc/resolv.conf", guest_resolv);

        // The image's own resolver needs no help: leave the file alone so the
        // guest keeps whatever it shipped (and any options with it).
        if (choice.origin != kernel::ResolverOrigin::guest_file &&
            !choice.empty()) {
            const std::string body = kernel::render_resolv_conf(choice.servers);
            k.files().mount_virtual(
                "/etc/resolv.conf",
                [body](std::string_view) -> Result<kernel::VirtualFile> {
                    kernel::VirtualFile vf;
                    vf.bytes.assign(
                        reinterpret_cast<const std::byte*>(body.data()),
                        reinterpret_cast<const std::byte*>(body.data() + body.size()));
                    return vf;
                });
            std::fprintf(stderr, "linuxity: dns from %s (%s)\n",
                         std::string{kernel::origin_name(choice.origin)}.c_str(),
                         choice.servers.front().c_str());
        }
    }

    // Which AF_UNIX namespace this host actually permits. Probed, not
    // assumed: Android's SELinux denies a filesystem bind in every directory
    // an app can write, so a guest gpg-agent/ssh-agent/dirmngr would fail
    // with EACCES on a path the runtime translated perfectly. Everywhere else
    // this succeeds and nothing changes.
    //
    // The probe binds a socket in the overlay upper (where a guest's would
    // go) and unlinks it. One syscall pair at startup beats a per-host #ifdef.
    {
        std::string probe = (persist.empty() ? std::string{"/tmp"} : persist) +
                            "/.linuxity-sock-probe";
        ::unlink(probe.c_str());
        bool fs_ok = false;
        if (int fd = ::socket(AF_UNIX, SOCK_STREAM, 0); fd >= 0) {
            ::sockaddr_un sa{};
            sa.sun_family = AF_UNIX;
            std::snprintf(sa.sun_path, sizeof sa.sun_path, "%s", probe.c_str());
            fs_ok = ::bind(fd, reinterpret_cast<::sockaddr*>(&sa), sizeof sa) == 0;
            ::close(fd);
            ::unlink(probe.c_str());
        }
        if (!fs_ok) {
            k.files().set_socket_ns(kernel::SocketNs::abstract);
            std::fprintf(stderr,
                "linuxity: host forbids filesystem AF_UNIX binds; using the "
                "abstract namespace\n");
        }
        k.files().set_instance_id(static_cast<std::uint64_t>(::getpid()));
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

    // Fail fast on a foreign-ISA program named on the command line (e.g. an
    // aarch64 rootfs's /bin/sh on an x86-64 host). linuxity runs guest code
    // natively on the host CPU — there is no cross-emulator — so a foreign
    // binary would only die in a cryptic loader crash. Diagnose it up front,
    // pointing at the ISA mismatch (this is termux's isNonNativeElf, surfaced
    // as an actionable error rather than routed to qemu).
    if (loader::read_elf_machine(exec_path) == loader::ForeignArch::foreign) {
        std::fprintf(stderr,
            "linuxity: '%s' is a foreign-architecture binary — linuxity runs "
            "guest code natively on this host's CPU and has no cross-emulator. "
            "Use a rootfs built for this machine's ISA.\n", path.c_str());
        return 1;
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
    // A `#!` script named directly on the command line: the host kernel would
    // launch its interpreter with the HOST-translated script path, which our
    // namespace re-translates (double-rooting). Resolve the shebang ourselves
    // and exec the interpreter with the script as a GUEST path (its own openat
    // redirects into the rootfs). If the interpreter is dynamic, chain its
    // ld.so too. This mirrors path_exec's in-guest handling for the FIRST hop.
    if (loader::Shebang sh = loader::read_shebang(exec_path); !sh.interp.empty()) {
        std::string si_abs = k.files().absolutize(sh.interp);
        auto sic = k.files().classify(si_abs);
        std::string si_host = sic.realm == kernel::Realm2::host_backed
                                  ? sic.host_path : sh.interp;
        std::string script_guest = k.files().absolutize(path);
        child_argv.clear();
        std::string si_interp = loader::read_elf_interp(si_host);
        if (!si_interp.empty()) {
            // Dynamic interpreter: exec its ld.so, then the interpreter (guest
            // path), then the shebang arg, then the script (guest path).
            std::string ld_abs = k.files().absolutize(si_interp);
            auto ldc = k.files().classify(ld_abs);
            std::string ld_host = ldc.realm == kernel::Realm2::host_backed
                                      ? ldc.host_path : si_interp;
            child_argv.push_back(ld_host);
            child_argv.push_back(si_abs);           // interpreter, guest path
            exec_path = ld_host;
        } else {
            child_argv.push_back(si_host);          // static interpreter
            exec_path = si_host;
        }
        if (!sh.arg.empty()) child_argv.push_back(sh.arg);
        child_argv.push_back(script_guest);         // the script, guest path
        for (std::size_t j = 1; j < gargv.size(); ++j)
            child_argv.push_back(gargv[j]);
    } else if (std::string interp = loader::read_elf_interp(exec_path); !interp.empty()) {
        std::string interp_abs = k.files().absolutize(interp);
        auto ipc = k.files().classify(interp_abs);
        std::string interp_host = interp;
        if (ipc.realm == kernel::Realm2::host_backed) interp_host = ipc.host_path;
        // ld.so <guest-prog> <original-args...>; keep gargv[0] as argv[1] so the
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

    // If the top-level program is pacman and transparent-overwrite is on,
    // append `--overwrite "*"` to the child argv (same rationale as the
    // in-guest path_exec handling — bootstrap rootfs orphan lib files).
    if (!root.empty() && pacman_overwrite) {
        auto slash = path.find_last_of('/');
        std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
        bool is_txn = false, end_opts = false;
        for (std::size_t j = 1; j < gargv.size(); ++j) {
            const std::string& a = gargv[j];
            if (a == "--") { end_opts = true; continue; }
            if (end_opts || a.size() < 2 || a[0] != '-') continue;
            if (a[1] == '-') { if (a == "--sync" || a == "--upgrade") is_txn = true; }
            else for (char c : a) if (c == 'S' || c == 'U') is_txn = true;
        }
        if (base == "pacman" && is_txn) {
            child_argv.push_back("--overwrite");
            child_argv.push_back("*");
        }
    }
    runtime::PtraceTrap trap{exec_path, child_argv, genvp, {},
                             [&governor]() {
                                 governor.join_child();
                                 // Occupy a handful of low file descriptors so
                                 // the guest's dynamic fd allocation starts
                                 // above them — exactly like a normal process
                                 // launched from a shell/login session that
                                 // inherits several open fds. Without this the
                                 // guest allocates from fd 3, and a program
                                 // that races a short-lived control fd (e.g.
                                 // curl_multi's wakeup eventfd in pacman's
                                 // download workers) against a data file can
                                 // see BOTH land on the same low number and
                                 // corrupt the file. Point the reservations at
                                 // /dev/null so they are harmless and let them
                                 // survive execve (NOT CLOEXEC) so they still
                                 // occupy the low slots once the guest program
                                 // and its forked download workers are running
                                 // — which is precisely when the collision would
                                 // otherwise occur. Inheriting a few open fds is
                                 // exactly what a shell-launched process sees.
                                 reserve_low_fds();
                             }};

    // PtraceTrap is BOTH the trap backend and the guest-memory accessor
    // (it shares the child's real pages via process_vm_readv/writev).
    //
    // The guest runs natively, so its syscall numbering IS the host's. Naming
    // a literal arch here is how the dispatcher came to decode aarch64's
    // openat(56) as an x86-64 number and forward it untranslated -- the guest
    // then loaded host libraries, or failed to load any. conform::host_arch()
    // is the one place that answers this.
    runtime::Cpu cpu{trap, k, trap, conform::host_arch()};

    auto rc = cpu.run(uaddr(0), uaddr(0));

    // Remove this run's throwaway dirs under /tmp. The upper-layer comment
    // above has always claimed these are "torn down each run" and nothing
    // actually did it -- this host had 119 /tmp/linuxity-upper-* left over.
    // Adding a private /tmp would have made that worse, so both get cleaned
    // here, on every exit path.
    //
    // Shelling out to rm -rf rather than walking the tree: these are our own
    // paths (we built the names), the guest is gone by now, and a hand-rolled
    // recursive unlink is a lot of code to get a temp dir removed. A --persist
    // upper is NEVER touched, only the per-pid one we created.
    const auto sweep = [](const std::string& d) {
        if (d.empty()) return;
        if (d.rfind("/tmp/linuxity-", 0) != 0) return;   // ours, or nothing
        std::string cmd = "rm -rf -- '" + d + "' 2>/dev/null";
        (void)!std::system(cmd.c_str());
    };
    sweep(private_tmp_dir);
    sweep(ephemeral_upper);

    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", int(rc.error()));
        return 1;
    }
    return *rc;
}
