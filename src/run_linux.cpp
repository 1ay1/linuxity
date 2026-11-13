// src/run_linux.cpp -- the Linux (and Android) host's host_run().
//
// The program executes DIRECTLY on the host CPU (native speed). Only its
// syscalls trap back into the runtime, where our subsystems service them.
// No VM, no emulation, native code, our kernel. The command line that gets
// here is src/main.cpp's; see host_run.hpp for the seam.
#include "linuxity/conform/arch.hpp"
#include "linuxity/env/passwd.hpp"
#include "linuxity/env/status.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/host/tmpdir.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/kernel/resolver.hpp"
#include "linuxity/kernel/resources.hpp"
#include "linuxity/loader/interp.hpp"
#include "linuxity/runtime/linux/dns_proxy.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/resource_governor.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include "display_attach.hpp"
#include "guest_env.hpp"
#include "guest_files.hpp"
#include "host_run.hpp"
#include "options.hpp"
#include "supervisor.hpp"

#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "linuxity/host/environ.hpp"

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

// The Linux host: the guest's own syscalls run natively under ptrace and a
// seccomp filter; the trap is only for what linuxity must answer itself.
const char* lx::cli::host_name() noexcept { return "linux"; }
bool lx::cli::host_runs_instances() noexcept { return true; }

int lx::cli::host_internal(const Options&, int, char**, int) { return -1; }

int lx::cli::host_run(lx::cli::Options& o, int argc, char** argv) {
    using namespace lx;
    auto& st = env::status();

    // Everything below was configured by flags or env.vibe (see Options).
    std::string root = o.root;
    // A durable upper (--persist / storage.persist). Without it the writable
    // upper is a fresh /tmp/linuxity-upper-<pid> torn down each run.
    std::string persist = o.persist;
    bool pacman_overwrite = o.pacman_overwrite;
    bool host_pids = o.host_pids;
    // A PRIVATE /tmp by default: the guest's top process is always pid 1, so
    // a shared /tmp makes every pid-derived name (make's /tmp/GMfifo<pid>)
    // collide across runs.
    bool private_tmp = o.private_tmp;
    // Where that private /tmp landed, so it can be torn down on exit.
    std::string private_tmp_dir;
    // The EPHEMERAL overlay upper, likewise. Empty with --persist, which must
    // survive the run.
    std::string ephemeral_upper;
    kernel::ResourceSpec res = o.res;
    // host dir -> guest path, riding the path-translation namespace
    std::vector<std::pair<std::string, std::string>> binds = o.binds;

    // The compat and debug switches are read by the runtime from the
    // environment, once, where they take effect.
    auto flag_env = [](const char* k, bool on) { if (on) ::setenv(k, "1", 1); };
    flag_env("LINUXITY_EMULATE_FIFOS", o.emulate_fifos);
    flag_env("LINUXITY_EMULATE_SYSV", o.emulate_sysv);
    flag_env("LINUXITY_EMULATE_NL80211", o.emulate_nl80211);
    flag_env("LINUXITY_FORCE_LINK_EMULATION", o.emulate_hardlinks);
    flag_env("LINUXITY_SYNTH_HW", !o.host_hw);
    if (!o.trace.empty()) ::setenv("LINUXITY_TRACE", o.trace.c_str(), 1);

    // If a hard bound was asked for, try to run under a delegated cgroup scope
    // (via systemd-run) so the enforcement is precise. This re-execs the whole
    // process; on return we are either delegated or proceeding with fallback.
    // A detached instance can't re-exec: its launcher waits on a pipe that
    // the exec would close.
    if (o.ready_fd < 0)
        maybe_reexec_delegated(argc, argv, res.mem_max.has_value() ||
                                           res.cpus.has_value() ||
                                           res.pids_max.has_value());

    // The program (pid 1). Empty in instance mode: sessions come later.
    std::string prog_path = o.argv.empty() ? std::string{} : o.argv[0];
    std::vector<std::string> prog_argv = o.argv;

    // The guest's environment and login (src/guest_env.hpp, shared by every
    // host).
    auto ge = cli::guest_env(o);
    if (!ge.error.empty()) {
        std::fprintf(stderr, "linuxity: %s\n", ge.error.c_str());
        return 2;
    }
    if (!ge.notice.empty()) st.event("login", ge.notice);
    std::vector<std::string> genvp = std::move(ge.vars);
    // A private XDG_RUNTIME_DIR, and GUI apps on the desktop's compositor
    // or linuxity-display's (src/display_attach.hpp).
    {
        std::string why;
        const std::size_t had = o.binds.size();
        cli::display::setup(o, genvp, ge.login.uid, why);
        binds.insert(binds.end(), o.binds.begin() + static_cast<std::ptrdiff_t>(had), o.binds.end());
        if (!why.empty()) st.event("display", "no display: " + why);
    }
    std::vector<std::string> layers = std::move(ge.layers);   // host dirs, top first
    env::UserInfo login = std::move(ge.login);                 // who pid 1 / sessions run as
    // A DISTRO umask: the guest is a Linux distro, not this host's shell
    // session. Every distro ships 022 (via /etc/profile or pam_umask);
    // Android's adb shell runs 000, and under it every directory a package
    // manager creates really is world-writable (pacman: "directory
    // permissions differ on /etc/"). Only a DEFAULT: umask(2) is not
    // intercepted, so a guest profile that sets its own still wins.
    if (!root.empty()) (void)::umask(static_cast<mode_t>(o.umask));

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
#if defined(__linux__)
        // the guest's memory IS the host's, so its size and swap are too
        if (const auto t = kernel::MachineSpec::host_meminfo_kb("MemTotal:"); t && *t)
            spec.mem_total = *t << 10;
        if (const auto s = kernel::MachineSpec::host_meminfo_kb("SwapTotal:"))
            spec.swap_total = *s << 10;
#endif
        spec.release = o.release;
        spec.nodename = o.hostname;
        // the guest runs on the host's hardware, so show it (LINUXITY_SYNTH_HW=1
        // keeps the fixed virtual machine)
        spec.host_hw = !std::getenv("LINUXITY_SYNTH_HW");
        if (!root.empty())
            if (char* rp = ::realpath(root.c_str(), nullptr)) { spec.root_host = rp; std::free(rp); }
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
        if (res.pids_max) spec.task_limit = *res.pids_max;
        k.set_machine(std::move(spec));
    }

    // Establish the host-side enforcement for the guest tree. The governor
    // creates a cgroup v2 subtree (when the controllers are delegated — e.g.
    // after the systemd-run re-exec above) or installs rlimit fallbacks; the
    // child adopts it via the pre-exec hook so every descendant inherits it.
    runtime::ResourceGovernor governor{res};
    const std::string limits_text = governor.describe();
    if (!limits_text.empty())
        st.event("limits", limits_text, [&](env::Json& j) {
            j.kv("cgroup", governor.cgroup_active()).key("enforced").obj();
            for (const auto& [what, how] : governor.enforcement()) j.kv(what, how);
            j.end();
        });

    // Seed the process table: pid 1 is our init (the traced root). Its
    // cmdline is the program we're about to run, so /proc/1/cmdline is real.
    // An instance has no root program, so its pid 1 is a quiet init that
    // owns every session.
    {
        kernel::ProcInfo init;
        init.pid = 1; init.ppid = 0;
        if (o.instance) {
            init.comm = "init";
            init.cmdline = "/sbin/init";
            init.exe = "/sbin/init";
        } else {
            init.comm = prog_path.substr(prog_path.find_last_of('/') + 1);
            init.cmdline.clear();
            for (std::size_t j = 0; j < prog_argv.size(); ++j) {
                init.cmdline += prog_argv[j];
                if (j + 1 < prog_argv.size()) init.cmdline.push_back('\0');   // ProcInfo: NUL-joined
            }
            // pid 1 runs as the login user, with root's powers only if it is root
            abi::creds::login(init, login.uid, login.gid, login.groups);
        }
        k.procs().upsert(init);
        // login.cwd / --cwd: where pid 1 starts. Without a rootfs the guest
        // sees the host's tree, so it starts where you ran linuxity.
        std::string start_dir = o.cwd;
        if (start_dir.empty() && root.empty())
            if (char cwd[4096]; ::getcwd(cwd, sizeof cwd) != nullptr) start_dir = cwd;
        if (!o.instance && !start_dir.empty()) {
            k.files().set_current_pid(1);
            k.files().set_cwd(start_dir);
        }

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
        for (int fd = 0; fd <= 2 && !o.instance; ++fd) {
            if (::isatty(fd) == 0) continue;
            const char* n = ::ttyname(fd);
            if (n == nullptr) continue;
            constexpr std::string_view kPre = "/dev/pts/";
            if (!std::string_view{n}.starts_with(kPre)) continue;
            k.files().bind_fd(fd, n);
            k.procs().set_ctty(1, std::atoi(n + kPre.size()));
            k.procs().set_pty_owner(std::atoi(n + kPre.size()), login.uid);
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
            shm_dir = host::tmp_path("linuxity-shm-" +
                      std::to_string(static_cast<long>(::getpid())));
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
            ? host::tmp_path("linuxity-upper-" + std::to_string(::getpid()))
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
            st.event("storage", "persistent overlay upper at " + upper,
                     [&](env::Json& j) { j.kv("upper", upper).kv("persist", true); });
        } else {
            (void)::mkdir(upper.c_str(), 0755);
        }
        k.files().mount_host("/", root, upper);
        k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
        k.files().mount_virtual("/dev", vfs::make_devfs(
            [&k] { return k.procs().ctty_of(k.files().current_pid()); },
            shm_dir, k.machine().host_hw));
    } else {
        // No rootfs: the guest lives in the real host tree (paths translate
        // 1:1), but /proc and /sys are STILL synthesized so uname/pid/mounts
        // and hardware topology report linuxity's world, not the host's.
        k.files().mount_host("/", "/");
        k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
        k.files().mount_virtual("/dev", vfs::make_devfs(
            [&k] { return k.procs().ctty_of(k.files().current_pid()); },
            shm_dir, k.machine().host_hw));
    }

    // Private /tmp (see `private_tmp` above). Registered BEFORE --bind so an
    // explicit `--bind /tmp` still wins by longest-prefix, and before the
    // guest starts so nothing has looked at /tmp yet.
    //
    // Named with the SUPERVISOR's pid, which is what makes it unique -- the
    // guest's own pid cannot, since it is always 1. Same convention as the
    // overlay upper dir above.
    if (private_tmp) {
        const std::string gt = host::tmp_path("linuxity-tmp-" + std::to_string(::getpid()));
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
        if (char* rp = ::realpath(host_dir.c_str(), nullptr)) {
            k.machine().binds.emplace_back(norm, rp);   // for the mount table
            std::free(rp);
        }
        st.event("bind", "bind " + norm + " -> " + host_dir,
                 [&](env::Json& j) { j.kv("at", norm).kv("host", host_dir); });
    }

    // DNS, /etc/hostname and /etc/hosts, served as virtual files
    // (src/guest_files.hpp, shared by every host). The resolv.conf body is
    // shared so `linuxity reload` can change it live.
#if defined(__ANDROID__)
    // Android has no resolv.conf: forward to netd (runtime/linux/dns_proxy.hpp)
    if (o.manage_dns && o.dns.empty() && !std::getenv("LINUXITY_DNS")) (void)runtime::DnsProxy::start();
#endif
    auto resolv = cli::mount_guest_files(k, o);

    // Which AF_UNIX namespace this host actually permits. Probed, not
    // assumed: Android's SELinux denies a filesystem bind in every directory
    // an app can write, so a guest gpg-agent/ssh-agent/dirmngr would fail
    // with EACCES on a path the runtime translated perfectly. Everywhere else
    // this succeeds and nothing changes.
    //
    // The probe binds a socket in the overlay upper (where a guest's would
    // go) and unlinks it. One syscall pair at startup beats a per-host #ifdef.
    {
        std::string probe = (persist.empty() ? host::tmp_base() : persist) +
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
            st.event("compat", "host forbids filesystem AF_UNIX binds; using the abstract namespace",
                     [](env::Json& j) { j.kv("feature", "unix-sockets").kv("mode", "abstract"); });
        }
        k.files().set_instance_id(static_cast<std::uint64_t>(::getpid()));
    }

    // Same question for FIFOs. Android refuses mkfifo everywhere a shell can
    // write, so emulate them there (see Syscalls::fifo_*).
    {
        std::string probe = (persist.empty() ? host::tmp_base() : persist) +
                            "/.linuxity-fifo-probe";
        ::unlink(probe.c_str());
        int rc = ::mkfifo(probe.c_str(), 0600);
        if (rc != 0 && errno == ENOENT) {   // no host /tmp (Android): try here
            probe = ".linuxity-fifo-probe";
            ::unlink(probe.c_str());
            rc = ::mkfifo(probe.c_str(), 0600);
        }
        if (rc == 0 && !std::getenv("LINUXITY_EMULATE_FIFOS")) {
            ::unlink(probe.c_str());
        } else if (rc == 0 || errno == EACCES || errno == EPERM) {
            if (rc == 0) ::unlink(probe.c_str());
            k.files().set_fifos_emulated(true);
            st.event("compat", "host forbids mkfifo; emulating FIFOs",
                     [](env::Json& j) { j.kv("feature", "fifos").kv("mode", "emulated"); });
        }
    }

    // How to exec a guest program: the HOST path the kernel runs and its argv.
    // Shared by pid 1 and every session an instance starts.
    //
    // The rootfs makes the translation unprivileged, so we no longer need to
    // chroot the child. The one path the host kernel resolves itself is the
    // exec target, so translate it up front: the child execs the REAL host
    // path under the rootfs, then every syscall it makes is virtualized.
    auto prepare = [&k, &root, &pacman_overwrite](const std::string& path,
                                                  const std::vector<std::string>& gargv) {
    cli::Launch out;
    std::string exec_path = path;
    {
        std::string abs = k.files().absolutize(path);
        auto pc = k.files().classify(abs);
        if (pc.realm == kernel::Realm2::host_backed) exec_path = pc.host_path;
    }

    // Fail fast on a foreign-ISA program (e.g. an aarch64 rootfs's /bin/sh on
    // an x86-64 host). linuxity runs guest code natively on the host CPU and
    // has no cross-emulator, so it would only die in a cryptic loader crash.
    if (loader::read_elf_machine(exec_path) == loader::ForeignArch::foreign) {
        out.error = "'" + path + "' is a foreign-architecture binary — linuxity runs "
            "guest code natively on this host's CPU and has no cross-emulator. "
            "Use a rootfs built for this machine's ISA.";
        return out;
    }

    // A dynamically-linked guest names its interpreter (ld-linux / ld-musl) in
    // PT_INTERP. The HOST kernel would resolve that path against the HOST root
    // at execve time, where the guest's loader does not exist. So exec the
    // INTERPRETER directly (its host path) with the program as argv[1], named
    // in the GUEST namespace: the loader's own opens are then redirected into
    // the rootfs. argv[0] stays the guest program name.
    std::vector<std::string> child_argv = gargv;
    // A `#!` script: resolve the shebang ourselves and exec the interpreter
    // with the script as a GUEST path (the host kernel would hand it the HOST
    // path, which our namespace re-translates). A dynamic interpreter chains
    // its ld.so too. This mirrors path_exec's in-guest handling.
    if (loader::Shebang sh = loader::read_shebang(exec_path); !sh.interp.empty()) {
        std::string si_abs = k.files().absolutize(sh.interp);
        auto sic = k.files().classify(si_abs);
        std::string si_host = sic.realm == kernel::Realm2::host_backed
                                  ? sic.host_path : sh.interp;
        std::string script_guest = k.files().absolutize(path);
        child_argv.clear();
        std::string si_interp = loader::read_elf_interp(si_host);
        if (!si_interp.empty()) {
            // ld.so, the interpreter (guest path), its arg, the script
            std::string ld_abs = k.files().absolutize(si_interp);
            auto ldc = k.files().classify(ld_abs);
            std::string ld_host = ldc.realm == kernel::Realm2::host_backed
                                      ? ldc.host_path : si_interp;
            child_argv.push_back(ld_host);
            child_argv.push_back(si_abs);
            exec_path = ld_host;
        } else {
            child_argv.push_back(si_host);          // static interpreter
            exec_path = si_host;
        }
        if (!sh.arg.empty()) child_argv.push_back(sh.arg);
        child_argv.push_back(script_guest);
        for (std::size_t j = 1; j < gargv.size(); ++j)
            child_argv.push_back(gargv[j]);
    } else if (std::string interp = loader::read_elf_interp(exec_path); !interp.empty()) {
        std::string interp_abs = k.files().absolutize(interp);
        auto ipc = k.files().classify(interp_abs);
        std::string interp_host = interp;
        if (ipc.realm == kernel::Realm2::host_backed) interp_host = ipc.host_path;
        child_argv.clear();
        child_argv.push_back(interp_host);
        child_argv.push_back(k.files().absolutize(path));
        for (std::size_t j = 1; j < gargv.size(); ++j)
            child_argv.push_back(gargv[j]);
        exec_path = interp_host;
    }

    // A top-level pacman transaction gets `--overwrite "*"` (same rationale
    // as the in-guest path_exec handling: bootstrap rootfs orphan lib files).
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
            // before the guest's arguments, which may end in "--"
            const std::size_t at = child_argv.size() - (gargv.empty() ? 0 : gargv.size() - 1);
            child_argv.insert(child_argv.begin() + static_cast<std::ptrdiff_t>(at), {"--overwrite", "*"});
        }
    }
    out.exec_path = std::move(exec_path);
    out.argv = std::move(child_argv);
    return out;
    };

    // Occupy a handful of low file descriptors so the guest's dynamic fd
    // allocation starts above them, like a process launched from a login
    // session. Without this the guest allocates from fd 3, and a program that
    // races a short-lived control fd (curl_multi's wakeup eventfd in pacman's
    // download workers) against a data file can see BOTH land on the same low
    // number and corrupt the file. /dev/null, and NOT CLOEXEC, so they still
    // hold the slots once the guest is running.
    std::function<void()> pre_exec = [&governor]() {
        governor.join_child();
        reserve_low_fds();
    };
    governor.pin_supervisor();

    cli::Launch first;
    if (!o.instance) {
        first = prepare(prog_path, prog_argv);
        if (first.error.empty() && ::access(first.exec_path.c_str(), X_OK) != 0)
            first.error = prog_path + ": " + std::strerror(errno);
        if (!first.error.empty()) {
            std::fprintf(stderr, "linuxity: %s\n", first.error.c_str());
            return errno == ENOENT || errno == EACCES ? 127 : 1;
        }
    }
    runtime::PtraceTrap trap{first.exec_path, first.argv, genvp, {}, pre_exec};

    // PtraceTrap is BOTH the trap backend and the guest-memory accessor
    // (it shares the child's real pages via process_vm_readv/writev).
    //
    // The guest runs natively, so its syscall numbering IS the host's. Naming
    // a literal arch here is how the dispatcher came to decode aarch64's
    // openat(56) as an x86-64 number and forward it untranslated -- the guest
    // then loaded host libraries, or failed to load any. conform::host_arch()
    // is the one place that answers this.
    runtime::Cpu cpu{trap, k, trap, conform::host_arch()};
    trap.set_host_pids(host_pids);
    k.procs().set_host_pids(host_pids);
    // procfs reads live per-task facts from the guest's real host task
    k.procs().set_host_resolver([&trap](std::int32_t g) { return static_cast<int>(trap.host_tid_of(g)); });
    k.procs().set_guest_resolver([&trap](std::int32_t h) { return static_cast<int>(trap.guest_pid_of_host(h)); });
    k.procs().set_tracer_resolver([&trap](std::int32_t g) { return trap.guest_trace_info(g); });
    // a new mount namespace starts with its parent's guest mounts
    k.procs().set_on_new_mnt_ns([&k](std::uint64_t parent, std::uint64_t child) {
        k.files().clone_mnt_ns(parent, child);
    });
    trap.set_guest_ids([&k](std::int32_t g) {
        const auto* p = k.procs().find(g);
        return p ? std::pair{p->uids[1], p->gids[1]} : std::pair<std::uint32_t, std::uint32_t>{0, 0};
    });
    // pid namespaces: how one guest process numbers another
    trap.set_pid_view(
        [&k](std::int32_t viewer, std::int32_t pid) {
            auto& t = k.procs();
            const auto ns = kernel::ProcessTable::pid_ns(t.ns_of(viewer));
            if (!ns) return pid;
            if (const auto l = t.pid_in(ns, pid); l > 0) return l;
            // a child forked a moment ago, before its spawn event lands
            t.assign_ns_pid_from(pid, viewer);
            return t.pid_in(ns, pid);
        },
        [&k](std::int32_t viewer, std::int32_t pid) {
            const auto ns = kernel::ProcessTable::pid_ns(k.procs().ns_of(viewer));
            return k.procs().pid_from(ns, pid);
        });

    // Instance mode: no root program; the supervisor serves the control
    // socket from the trap's idle hook and starts sessions on request.
    std::unique_ptr<cli::Supervisor> sup;
    if (o.instance) {
        cli::RuntimeHooks h;
        h.prepare = prepare;
        h.which = [&k](const std::string& name, const std::string& path_var) -> std::string {
            std::string_view rest = path_var.empty() ? std::string_view{"/usr/local/bin:/usr/bin:/bin"}
                                                     : std::string_view{path_var};
            while (!rest.empty()) {
                const auto c = rest.find(':');
                const std::string dir{rest.substr(0, c)};
                if (!dir.empty()) {
                    const std::string cand = dir + "/" + name;
                    const auto pc = k.files().classify(cand);
                    if (pc.realm == kernel::Realm2::host_backed && ::access(pc.host_path.c_str(), X_OK) == 0)
                        return cand;
                }
                if (c == std::string_view::npos) break;
                rest.remove_prefix(c + 1);
            }
            return {};
        };
        h.pre_exec = pre_exec;
        // a session sets its own identity; drop pid 1's
        for (const auto& kv : genvp)
            if (!kv.starts_with("USER=") && !kv.starts_with("LOGNAME=") &&
                !kv.starts_with("HOME=") && !kv.starts_with("SHELL="))
                h.base_env.push_back(kv);
        h.layers = layers;
        h.resolv = resolv;
        h.limits_text = limits_text;
        h.cgroup = governor.cgroup_active();
        sup = std::make_unique<cli::Supervisor>(k, trap, o, std::move(h));
        std::string why;
        if (!sup->start(why)) {
            std::fprintf(stderr, "linuxity: %s: %s\n", o.env_name.c_str(), why.c_str());
            return why == "already running" ? 3 : 1;
        }
        trap.set_idle([&sup](int chld, bool block) { return sup->idle(chld, block); });
        trap.set_on_exit([&sup](::pid_t h2, std::int32_t g, int code) { sup->on_exit(h2, g, code); });
    }

    auto rc = cpu.run(uaddr(0), uaddr(0));
    if (sup) {
        sup->cleanup();
        st.event("down", "instance " + o.env_name + " stopped");
    }

    // Remove this run's throwaway dirs under /tmp. The upper-layer comment
    // above has always claimed these are "torn down each run" and nothing
    // actually did it -- this host had 119 /tmp/linuxity-upper-* left over.
    // Adding a private /tmp would have made that worse, so both get cleaned
    // here, on every exit path.
    // A --persist upper is never touched, only the per-pid dirs we made.
    // remove_all doesn't follow symlinks; forking rm -rf here cost 1.2ms a run.
    const auto sweep = [](const std::string& d) {
        if (d.empty()) return;
        if (d.rfind(host::tmp_path("linuxity-"), 0) != 0) return;   // ours, or nothing
        std::error_code ec;
        std::filesystem::remove_all(d, ec);
    };
    sweep(private_tmp_dir);
    sweep(ephemeral_upper);
    if (shm_dir != "/dev/shm") sweep(shm_dir);   // Android has no /dev/shm: one per run

    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", int(rc.error()));
        return 1;
    }
    return o.instance ? 0 : *rc;
}
