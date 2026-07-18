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
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>

extern char** environ;

namespace {

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

// A rootfs's /etc/resolv.conf carries a usable nameserver line?
// A freshly extracted rootfs frequently ships resolv.conf as empty, absent,
// or a dangling symlink (Debian minbase points it at systemd-resolved's
// runtime stub), so DNS — and thus `pacman -Sy`, `apt update`, `curl` — breaks
// out of the box. Returns true iff the file exists and contains a non-comment
// `nameserver` directive.
[[nodiscard]] bool rootfs_has_usable_dns(const std::string& host_resolv) {
    std::FILE* f = std::fopen(host_resolv.c_str(), "r");
    if (!f) return false;
    char line[512];
    bool ok = false;
    while (std::fgets(line, sizeof line, f)) {
        const char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '#' || *p == ';') continue;
        if (std::strncmp(p, "nameserver", 10) == 0 &&
            (p[10] == ' ' || p[10] == '\t')) { ok = true; break; }
    }
    std::fclose(f);
    return ok;
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
        // Stack a writable overlay over the read-only rootfs so the guest can
        // write WITHOUT mutating the pristine rootfs; copy-up happens on first
        // write. With --persist the upper is a caller-named DURABLE directory
        // (installs/DB/config survive across runs — a real machine); without
        // it, a fresh per-run /tmp dir that's implicitly discarded on exit.
        std::string upper = persist.empty()
            ? "/tmp/linuxity-upper-" + std::to_string(::getpid())
            : persist;
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
    // disk with hardcoded 8.8.8.8; linuxity instead, only when the rootfs's own
    // resolv.conf has no usable nameserver, BINDS the HOST's live
    // /etc/resolv.conf over the guest path — so DNS tracks whatever the host
    // actually uses (VPN, split-horizon, corporate resolver) and the pristine
    // rootfs is never mutated. A single-FILE bind rides the same mount_host as
    // --bind. Opt out with LINUXITY_NO_DNS=1. Skipped without --root (the guest
    // already shares the host's real /etc).
    if (!root.empty() && !std::getenv("LINUXITY_NO_DNS")) {
        auto pc = k.files().classify("/etc/resolv.conf");
        bool guest_ok = pc.realm == kernel::Realm2::host_backed &&
                        rootfs_has_usable_dns(pc.host_path);
        if (!guest_ok && rootfs_has_usable_dns("/etc/resolv.conf")) {
            k.files().mount_host("/etc/resolv.conf", "/etc/resolv.conf");
            std::fprintf(stderr,
                "linuxity: bind /etc/resolv.conf -> host (rootfs had no DNS)\n");
        }
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
    runtime::Cpu cpu{trap, k, trap, abi::Arch::x86_64};

    auto rc = cpu.run(uaddr(0), uaddr(0));
    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", int(rc.error()));
        return 1;
    }
    return *rc;
}
