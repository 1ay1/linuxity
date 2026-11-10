// linuxity — run a native Linux binary under the runtime.
//
//   linuxity <program> [args...]
//
// The program executes DIRECTLY on the host CPU (native speed). Only its
// syscalls trap back into the runtime, where our subsystems service them.
// This is the whole thesis, made runnable: no VM, no emulation, native code,
// our kernel.
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
#include "linuxity/runtime/linux/ptrace_trap.hpp"
#include "linuxity/runtime/resource_governor.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

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

extern char** environ;

namespace {

// Can the guest's libc load locale `name`? Looks in each layer's
// /usr/lib/locale, as a directory or inside locale-archive.
bool guest_has_locale(const std::vector<std::string>& layers, std::string_view name) {
    if (name == "C" || name == "POSIX") return true;
    // split off the codeset and normalize it the way glibc does (UTF-8 -> utf8)
    std::string base{name}, mod;
    if (const auto at = base.find('@'); at != std::string::npos) { mod = base.substr(at); base.resize(at); }
    std::string lang = base, cs;
    if (const auto dot = base.find('.'); dot != std::string::npos) {
        lang = base.substr(0, dot);
        for (const char c : base.substr(dot + 1))
            if (std::isalnum(static_cast<unsigned char>(c)))
                cs.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (lang == "C" && cs == "utf8") return true;   // built into glibc and musl
    const std::string norm = cs.empty() ? lang + mod : lang + "." + cs + mod;
    bool any_locale_dir = false;
    for (const auto& l : layers) {
        const std::string dir = l + "/usr/lib/locale";
        struct ::stat st{};
        if (::stat(dir.c_str(), &st) != 0) continue;
        any_locale_dir = true;
        for (const std::string& n : {norm, std::string{name}})
            if (::stat((dir + "/" + n + "/LC_CTYPE").c_str(), &st) == 0) return true;
        // locale-archive keeps each name NUL-terminated; it can be large, so map it
        const int fd = ::open((dir + "/locale-archive").c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            struct ::stat ast{};
            bool hit = false;
            if (::fstat(fd, &ast) == 0 && ast.st_size > 0) {
                void* m = ::mmap(nullptr, static_cast<std::size_t>(ast.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
                if (m != MAP_FAILED) {
                    const std::string needle = std::string(1, '\0') + norm + '\0';
                    hit = ::memmem(m, static_cast<std::size_t>(ast.st_size), needle.data(), needle.size()) != nullptr;
                    ::munmap(m, static_cast<std::size_t>(ast.st_size));
                }
            }
            ::close(fd);
            if (hit) return true;
        }
    }
    // no locale files at all: musl, which accepts any name
    return !any_locale_dir;
}

bool is_utf8_name(std::string_view v) {
    std::string s;
    for (const char c : v) s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return s.find("utf-8") != std::string::npos || s.find("utf8") != std::string::npos;
}

// Give the guest a locale its libc can load, the way a distro login would.
// An unloadable one makes setlocale fail and every program falls back to
// ASCII: tmux then draws box and block characters as '_'.
void fix_guest_locale(std::vector<std::string>& env, const std::vector<std::string>& layers) {
    bool chosen = false;   // LANG, LC_ALL or LC_CTYPE picks the character set
    // a shell usually sets ten LC_* to the same value: check each name once
    std::vector<std::pair<std::string, bool>> known;
    const auto has = [&](std::string_view v) {
        for (const auto& [n, ok] : known) if (n == v) return ok;
        const bool ok = guest_has_locale(layers, v);
        known.emplace_back(std::string{v}, ok);
        return ok;
    };
    for (auto& kv : env) {
        if (!kv.starts_with("LANG=") && !kv.starts_with("LC_")) continue;
        const auto eq = kv.find('=');
        const std::string_view v = std::string_view{kv}.substr(eq + 1);
        if (v.empty()) continue;
        if (!has(v)) kv = kv.substr(0, eq + 1) + "C.UTF-8";
        if (kv.starts_with("LANG=") || kv.starts_with("LC_ALL=") || kv.starts_with("LC_CTYPE="))
            chosen = true;
    }
    if (chosen) return;
    // nothing chose a character set: the rootfs's own choice if it is a
    // usable UTF-8 one, else C.UTF-8 (every terminal today is UTF-8)
    std::string pick = "C.UTF-8";
    for (const auto& l : layers) {
        if (FILE* f = std::fopen((l + "/etc/locale.conf").c_str(), "r")) {
            char line[256];
            while (std::fgets(line, sizeof line, f)) {
                std::string_view s{line};
                if (!s.starts_with("LANG=")) continue;
                s.remove_prefix(5);
                while (!s.empty() && (s.back() == '\n' || s.back() == '"' || s.back() == '\'')) s.remove_suffix(1);
                while (!s.empty() && (s.front() == '"' || s.front() == '\'')) s.remove_prefix(1);
                if (is_utf8_name(s) && has(s)) pick = std::string{s};
            }
            std::fclose(f);
            break;   // the top layer's file wins
        }
    }
    env.emplace_back("LANG=" + pick);
}

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

int run_runtime(lx::cli::Options& o, int argc, char** argv) {
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
    flag_env("LINUXITY_NO_SECCOMP", !o.seccomp);
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

    // The guest's environment: the host's, or (login.clean-env) only the
    // variables named in login.pass-env. Identity syscalls are virtualized
    // either way.
    std::vector<std::string> genvp;
    for (char** e = environ; e && *e; ++e) {
        const std::string_view kv{*e};
        if (kv.starts_with("LINUXITY_")) continue;   // ours, not the guest's
        if (o.clean_env) {
            const auto eq = kv.find('=');
            const std::string_view name = kv.substr(0, eq);
            if (std::find(o.pass_env.begin(), o.pass_env.end(), name) == o.pass_env.end())
                continue;
        }
        genvp.emplace_back(kv);
    }
    std::vector<std::string> layers;   // host dirs of the guest tree, top first
    env::UserInfo login;               // who pid 1 / sessions run as
    login.name = "root";

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
        if (!persist.empty()) layers.push_back(persist);
        layers.push_back(root);
        // The login user's identity, from the guest's own /etc/passwd.
        auto who = env::resolve_user(layers, o.user);
        if (!who && o.instance && o.user != "root") {
            // the instance itself runs fine without it; sessions say why
            st.event("login", "login user " + o.user + " isn't in this environment; "
                     "add it back with `linuxity adduser " + o.user + "`");
            who = env::resolve_user(layers, "root");
        }
        if (!who) {
            std::fprintf(stderr, "linuxity: there's no user '%s' in this environment (a reset removes users). "
                                 "Add it back with `linuxity adduser %s`, or use `--user root`\n",
                         o.user.c_str(), o.user.c_str());
            return 2;
        }
        login = *who;
        if (!o.shell.empty()) login.shell = o.shell;
        set_env("USER", login.name);
        set_env("LOGNAME", login.name);
        set_env("HOME", login.home);
        set_env("SHELL", login.shell);
        // The host's temp dir means nothing in the guest's namespace (adb
        // exports TMPDIR=/data/local/tmp, so make put its jobserver FIFO
        // there). A distro leaves it unset and programs use /tmp.
        std::erase_if(genvp, [](const std::string& kv) { return kv.starts_with("TMPDIR="); });
        // a locale the rootfs can actually load (top layer first); an
        // explicit system.locale wins, and is still checked
        if (!o.locale.empty()) {
            std::erase_if(genvp, [](const std::string& kv) {
                return kv.starts_with("LANG=") || kv.starts_with("LC_");
            });
            genvp.push_back("LANG=" + o.locale);
        }
        fix_guest_locale(genvp, layers);
        if (!o.timezone.empty()) set_env("TZ", o.timezone);
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
        (void)::umask(static_cast<mode_t>(o.umask));
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
                        struct ::stat pst{};
                        if (::stat((root + std::string{dir}).c_str(), &pst) == 0)
                            merged += ":" + std::string{dir};
                    }
                    if (cut == std::string_view::npos) break;
                    rest.remove_prefix(cut + 1);
                }
            }
            set_env("PATH", merged);
        }
        // env.vibe's [env] and -e K=V come last, so they win
        for (const auto& [k, v] : o.env) set_env(k, v);
    }
    if (root.empty()) for (const auto& kv : o.env) genvp.push_back(kv.first + "=" + kv.second);

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
            init.uids = {login.uid, login.uid, login.uid, login.uid};
            init.gids = {login.gid, login.gid, login.gid, login.gid};
            init.groups = login.groups.empty() ? std::vector<std::uint32_t>{login.gid} : login.groups;
            init.groups_set = login.uid != 0;
            if (login.uid != 0) init.cap_eff = init.cap_prm = init.cap_inh = init.cap_amb = 0;
            init.creds_given = true;
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
    // The served body is shared so `linuxity reload` can change it live.
    auto resolv = std::make_shared<std::string>();
    if (!root.empty() && o.manage_dns && !std::getenv("LINUXITY_NO_DNS")) {
        const auto gpc = k.files().classify("/etc/resolv.conf");
        const std::string guest_resolv =
            gpc.realm == kernel::Realm2::host_backed ? gpc.host_path : std::string{};

        // network.dns (or --dns) is the explicit override, like LINUXITY_DNS
        std::string dns_spec;
        for (const auto& s : o.dns) dns_spec += (dns_spec.empty() ? "" : ",") + s;
        const auto choice = kernel::choose_nameservers(
            dns_spec.empty() ? std::getenv("LINUXITY_DNS") : dns_spec.c_str(),
            "/etc/resolv.conf", guest_resolv);

        // The image's own resolver needs no help: leave the file alone so the
        // guest keeps whatever it shipped (and any options with it).
        if (choice.origin != kernel::ResolverOrigin::guest_file &&
            !choice.empty()) {
            *resolv = kernel::render_resolv_conf(choice.servers);
            k.files().mount_virtual(
                "/etc/resolv.conf",
                [resolv](std::string_view) -> Result<kernel::VirtualFile> {
                    kernel::VirtualFile vf;
                    const std::string& body = *resolv;
                    vf.bytes.assign(
                        reinterpret_cast<const std::byte*>(body.data()),
                        reinterpret_cast<const std::byte*>(body.data() + body.size()));
                    return vf;
                });
        }
        const std::string origin{kernel::origin_name(choice.origin)};
        st.event("dns", choice.empty() ? std::string{"no nameservers found"}
                                       : "dns from " + origin + " (" + choice.servers.front() + ")",
                 [&](env::Json& j) { j.kv("origin", origin).kv("servers", choice.servers); });
    }

    // /etc/hostname follows system.hostname (and a live reload). With an env
    // the config owns the name; a bare --root run keeps the image's file if
    // it has one. Read from the machine on every open, like uname.
    if (!root.empty()) {
        const auto hpc = k.files().classify("/etc/hostname");
        if (hpc.realm != kernel::Realm2::host_backed || !o.env_name.empty()) {
            k.files().mount_virtual("/etc/hostname", [&k](std::string_view) -> Result<kernel::VirtualFile> {
                kernel::VirtualFile vf;
                const std::string body = k.machine().nodename + "\n";
                vf.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                                reinterpret_cast<const std::byte*>(body.data() + body.size()));
                return vf;
            });
        }
    }

    // /etc/hosts: the image's own, plus the hostname when it lacks it, so
    // sudo and friends can resolve it (WSL and Docker do the same). Live, so
    // a hostname change shows up at once. network.manage-hosts=false turns
    // it off and leaves the file editable.
    if (!root.empty() && o.manage_hosts) {
        const auto hpc = k.files().classify("/etc/hosts");
        const std::string image_hosts = hpc.realm == kernel::Realm2::host_backed ? hpc.host_path : std::string{};
        k.files().mount_virtual("/etc/hosts", [&k, image_hosts](std::string_view) -> Result<kernel::VirtualFile> {
            std::string body = image_hosts.empty() ? std::string{} : env::slurp(image_hosts).value_or("");
            if (body.empty()) body = "127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost ip6-loopback\n";
            if (!body.empty() && body.back() != '\n') body.push_back('\n');
            const std::string& h = k.machine().nodename;
            bool named = false;
            std::size_t at = 0;
            while (!named && (at = body.find(h, at)) != std::string::npos) {
                const bool left = at == 0 || body[at - 1] == ' ' || body[at - 1] == '\t';
                const std::size_t e = at + h.size();
                const bool right = e == body.size() || body[e] == ' ' || body[e] == '\t' || body[e] == '\n' || body[e] == '.';
                named = left && right;
                at = e;
            }
            if (!named) body += "127.0.1.1\t" + h + "\n";
            kernel::VirtualFile vf;
            vf.bytes.assign(reinterpret_cast<const std::byte*>(body.data()),
                            reinterpret_cast<const std::byte*>(body.data() + body.size()));
            return vf;
        });
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
            child_argv.push_back("--overwrite");
            child_argv.push_back("*");
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

    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", int(rc.error()));
        return 1;
    }
    return o.instance ? 0 : *rc;
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

namespace {

void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage: %s [OPTIONS] <program> [args...]\n"
        "       %s run <env> [OPTIONS] [-- program args...]\n"
        "       %s up <env> [--foreground]      start an environment in the background\n"
        "       %s <command> ...                 see `linuxity help`\n"
        "\n"
        "  Runs a native Linux binary; its syscalls are serviced by the\n"
        "  linuxity runtime (native speed, no VM, no emulation).\n"
        "\n"
        "  --env <name>        take every setting from that environment's env.vibe\n"
        "  --root <dir>        mount an extracted distro rootfs as guest '/'\n"
        "  --persist <dir>     keep the writable upper layer in <dir>, so writes persist\n"
        "                      across runs (default: ephemeral per-run)\n"
        "  --shared-tmp        share the host's /tmp (default: private)\n"
        "  --no-pacman-overwrite  don't auto-pass pacman --overwrite \"*\"\n"
        "  --cpus <N>          bound CPU to N cores' worth (e.g. 1.5)\n"
        "  --memory <SZ>       hard memory ceiling (e.g. 512M, 2G)\n"
        "  --memory-swap <SZ>  combined memory+swap ceiling\n"
        "  --pids <N>          max tasks in the guest tree (fork-bomb guard)\n"
        "  --cpuset <LIST>     pin to CPUs (e.g. 0-1, 0,2,4)\n"
        "  --bind host[:guest] expose a host dir in the guest tree\n"
        "  --host-pids         share the host's pid space, like docker --pid=host\n"
        "  --hostname <name>   hostname the guest sees\n"
        "  --kernel-release <r> kernel release the guest sees (uname -r)\n"
        "  --user <name|uid>   run as this guest user (from its /etc/passwd)\n"
        "  --cwd <dir>         start in this guest directory\n"
        "  --umask <octal>     file creation mask (default 022)\n"
        "  --dns <a,b,...>     nameservers for the guest's resolv.conf\n"
        "  -e, --setenv K=V    set a variable for the guest\n"
        "  --clean-env         don't inherit the host environment\n"
        "  --status-fd <fd>    write JSON status events, one per line, to <fd>\n"
        "  --quiet             no notices on stderr\n"
        "\n"
        "  The resource bounds are enforced by the HOST kernel (cgroup v2,\n"
        "  or setrlimit where a cgroup can't be created unprivileged) and\n"
        "  the guest's /proc, /sys and sysinfo are derived to MATCH them.\n",
        argv0, argv0, argv0, argv0);
}

// Load an environment's config into `o`. Returns false (having printed why).
bool load_env(const std::string& name, lx::cli::Options& o) {
    lx::env::Store store;
    if (!store.has(name)) {
        std::fprintf(stderr, "linuxity: no environment '%s' (see `linuxity list`)\n", name.c_str());
        return false;
    }
    auto r = store.load(name);
    std::vector<lx::env::Diag> diags = r.diags;
    lx::env::check_runnable(r.config, diags);
    bool bad = false;
    for (const auto& d : diags) {
        std::fprintf(stderr, "linuxity: %s: %s\n", store.config_path(name).c_str(),
                     lx::env::format_diag(d).c_str());
        bad = bad || d.error;
    }
    if (bad) return false;
    lx::cli::apply_config(r.config, o);
    o.env_name = name;
    o.config_path = store.config_path(name);
    o.run_dir = store.run_dir(name);
    o.logs_dir = store.logs_dir(name);
    o.control_path = store.socket_path(name);
    o.pid_path = store.pid_path(name);
    if (!o.persist.empty()) (void)lx::env::mkdirs(o.persist);
    return true;
}

// Parse leading flags into `o`. Returns the index of the first non-flag, or
// -1 on a bad flag (already reported).
int parse_flags(int argc, char** argv, int i, lx::cli::Options& o) {
    using namespace lx;
    auto need = [&](const char* what) -> const char* {
        if (i + 1 >= argc) {
            std::fprintf(stderr, "linuxity: %s needs an argument\n", what);
            std::exit(2);
        }
        return argv[++i];
    };
    for (; i < argc; ++i) {
        const std::string f = argv[i];
        if (f == "--") { ++i; break; }
        if (f == "--env") { if (!load_env(need("--env"), o)) return -1; }
        else if (f == "--root") { o.root = need("--root"); }
        else if (f == "--persist" || f == "--upper") { o.persist = need("--persist"); }
        else if (f == "--no-pacman-overwrite") { o.pacman_overwrite = false; }
        else if (f == "--pacman-overwrite")    { o.pacman_overwrite = true; }
        else if (f == "--shared-tmp")  { o.private_tmp = false; }
        else if (f == "--private-tmp") { o.private_tmp = true; }
        else if (f == "--cpus")        { o.res.cpus = std::atof(need("--cpus")); }
        else if (f == "--memory" || f == "-m") {
            if (auto b = kernel::parse_bytes(need("--memory"))) o.res.mem_max = *b;
            else { std::fprintf(stderr, "linuxity: bad --memory size\n"); return -1; }
        }
        else if (f == "--memory-swap") {
            if (auto b = kernel::parse_bytes(need("--memory-swap"))) o.res.swap_and_mem_max = *b;
            else { std::fprintf(stderr, "linuxity: bad --memory-swap size\n"); return -1; }
        }
        else if (f == "--pids")   { o.res.pids_max = std::strtoull(need("--pids"), nullptr, 10); }
        else if (f == "--cpuset") { o.res.cpuset = need("--cpuset"); }
        else if (f == "--host-pids") { o.host_pids = true; }
        else if (f == "--bind" || f == "-b" || f == "-v" || f == "--volume") {
            std::string spec = need("--bind");
            auto colon = spec.find(':');
            std::string host = colon == std::string::npos ? spec : spec.substr(0, colon);
            std::string guest = colon == std::string::npos ? spec : spec.substr(colon + 1);
            if (host.empty() || guest.empty() || guest.front() != '/') {
                std::fprintf(stderr, "linuxity: bad --bind '%s' (want host[:/guest-abs])\n", spec.c_str());
                return -1;
            }
            o.binds.emplace_back(std::move(host), std::move(guest));
        }
        else if (f == "--hostname") { o.hostname = need("--hostname"); }
        else if (f == "--kernel-release") { o.release = need("--kernel-release"); }
        else if (f == "--user" || f == "-u") { o.user = need("--user"); }
        else if (f == "--shell") { o.shell = need("--shell"); }
        else if (f == "--cwd" || f == "-C") { o.cwd = need("--cwd"); }
        else if (f == "--umask") {
            const std::string u = need("--umask");
            if (u.empty() || u.find_first_not_of("01234567") != std::string::npos) {
                std::fprintf(stderr, "linuxity: bad --umask '%s'\n", u.c_str());
                return -1;
            }
            o.umask = static_cast<unsigned>(std::strtoul(u.c_str(), nullptr, 8)) & 0777u;
        }
        else if (f == "--dns") {
            o.dns = kernel::nameservers_from_env(need("--dns"));
        }
        else if (f == "-e" || f == "--setenv") {
            const std::string kv = need("--setenv");
            const auto eq = kv.find('=');
            if (eq == std::string::npos || eq == 0) {
                std::fprintf(stderr, "linuxity: bad -e '%s' (want NAME=value)\n", kv.c_str());
                return -1;
            }
            o.env.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
        }
        else if (f == "--clean-env") { o.clean_env = true; }
        else if (f == "--timezone") { o.timezone = need("--timezone"); }
        else if (f == "--locale") { o.locale = need("--locale"); }
        else if (f == "--status-fd") { o.status_fd = std::atoi(need("--status-fd")); }
        else if (f == "--quiet" || f == "-q") { o.quiet = true; }
        else if (f == "--foreground") { /* handled by `up` */ }
        else if (f.size() > 1 && f[0] == '-' && f != "-") {
            std::fprintf(stderr, "linuxity: unknown option '%s'\n", f.c_str());
            return -1;
        }
        else break;   // first non-flag: the program
    }
    return i;
}

void setup_status(const lx::cli::Options& o) {
    auto& st = lx::env::status();
    st.set_quiet(o.quiet);
    if (o.status_fd >= 0 && ::fcntl(o.status_fd, F_GETFD) >= 0) {
        (void)::fcntl(o.status_fd, F_SETFD, FD_CLOEXEC);   // never leak into guests
        st.set_fd(o.status_fd);
    }
}

// `linuxity up <env>`: run the instance. In the background unless
// --foreground; the launcher returns once the control socket is live.
int cmd_up(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: linuxity up <env> [--foreground] [--status-fd N]\n"); return 2; }
    lx::cli::Options o;
    if (!load_env(argv[2], o)) return 1;
    const int rest = parse_flags(argc, argv, 3, o);
    if (rest < 0) return 2;
    bool fg = false;
    for (int j = 3; j < argc; ++j) fg = fg || std::string_view{argv[j]} == "--foreground";
    o.instance = true;
    o.argv.clear();

    lx::env::Store store;
    if (const ::pid_t p = store.running_pid(o.env_name); p > 0) {
        std::fprintf(stderr, "linuxity: %s is already running (pid %d)\n", o.env_name.c_str(), p);
        return 0;
    }
    if (fg) {
        setup_status(o);
        return run_runtime(o, argc, argv);
    }

    // Background: fork, detach, log to the env's log. The child writes a
    // byte to `ready` once it listens (or closes it on failure), so the
    // parent waits for exactly that and no longer.
    int ready[2];
    if (::pipe2(ready, O_CLOEXEC) != 0) { std::perror("linuxity: pipe"); return 1; }
    const ::pid_t pid = ::fork();
    if (pid < 0) { std::perror("linuxity: fork"); return 1; }
    if (pid == 0) {
        ::close(ready[0]);
        (void)::setsid();
        (void)lx::env::mkdirs(o.logs_dir);
        const int log = ::open(o.cfg.log.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        const int nul = ::open("/dev/null", O_RDWR | O_CLOEXEC);
        if (nul >= 0) ::dup2(nul, 0);
        if (log >= 0) { ::dup2(log, 1); ::dup2(log, 2); }
        o.ready_fd = ready[1];
        setup_status(o);
        std::_Exit(run_runtime(o, argc, argv));
    }
    ::close(ready[1]);
    char b = 0;
    ::ssize_t n;
    do { n = ::read(ready[0], &b, 1); } while (n < 0 && errno == EINTR);
    ::close(ready[0]);
    if (n == 1) {
        if (!o.quiet) std::fprintf(stderr, "linuxity: %s is up (pid %d)\n", o.env_name.c_str(), pid);
        return 0;
    }
    int stc = 0;
    ::waitpid(pid, &stc, 0);
    std::fprintf(stderr, "linuxity: %s failed to start; see %s\n", o.env_name.c_str(), o.cfg.log.c_str());
    return WIFEXITED(stc) && WEXITSTATUS(stc) ? WEXITSTATUS(stc) : 1;
}

// `linuxity run <env> [flags] [-- program...]`: one program as pid 1 with
// the environment's settings (the user's login shell if none is given).
int cmd_run(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: linuxity run [env] [--fresh] [-v host:guest] [-e K=V] [-- program args...]\n"); return 2; }
    lx::cli::Options o;
    if (!load_env(argv[2], o)) return 1;
    // --fresh: like docker run --rm, changes go to a throwaway layer
    bool fresh = false;
    const int orig_argc = argc;
    char** const orig_argv = argv;   // a re-exec under systemd-run must keep --fresh
    std::vector<char*> rest(argv, argv + argc);
    std::erase_if(rest, [&](char* a) { return std::string_view{a} == "--fresh" && (fresh = true); });
    argc = static_cast<int>(rest.size());
    argv = rest.data();
    std::string scratch;
    if (fresh) {
        lx::env::Store store;
        // a re-exec under systemd-run (for exact limits) reuses the same dir
        if (const char* d = std::getenv("LINUXITY_FRESH_DIR"); d && *d) scratch = d;
        else {
            scratch = lx::host::tmp_path("linuxity-fresh-" + std::to_string(::getpid()));
            (void)lx::env::mkdirs(scratch);
            // the image's own owners and modes still apply
            if (const auto m = lx::env::slurp(store.dir(o.env_name) + "/image.meta"))
                (void)lx::env::write_file_atomic(scratch + "/.linuxity-meta", *m);
            ::setenv("LINUXITY_FRESH_DIR", scratch.c_str(), 1);
        }
        o.persist = scratch;
    }
    const int i = parse_flags(argc, argv, 3, o);
    if (i < 0) return 2;
    for (int j = i; j < argc; ++j) o.argv.emplace_back(argv[j]);
    if (o.argv.empty()) o.argv = o.cfg.command;
    std::vector<std::string> layers;
    if (!o.persist.empty()) layers.push_back(o.persist);
    layers.push_back(o.root);
    auto u = lx::env::resolve_user(layers, o.user);
    if (!u && fresh) {
        // --fresh starts from the clean image, which predates users added later
        if (!std::getenv("LINUXITY_DELEGATED"))
            std::fprintf(stderr, "linuxity: %s isn't in the clean image; running as root\n", o.user.c_str());
        o.user = "root";
        o.shell.clear();
        u = lx::env::resolve_user(layers, o.user);
    }
    // a bare command name is looked up on the guest's PATH
    if (!o.argv.empty() && o.argv[0].find('/') == std::string::npos) {
        for (const char* dir : {"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}) {
            const std::string cand = std::string{dir} + "/" + o.argv[0];
            bool found = false;
            for (const auto& l : layers) {
                struct ::stat sst{};
                if (::lstat((l + cand).c_str(), &sst) == 0 && (S_ISREG(sst.st_mode) || S_ISLNK(sst.st_mode))) { found = true; break; }
            }
            if (found) { o.argv[0] = cand; break; }
        }
        if (o.argv[0].find('/') == std::string::npos) {
            std::fprintf(stderr, "linuxity: %s: command not found\n", o.argv[0].c_str());
            if (!scratch.empty()) (void)lx::env::remove_tree(scratch);
            return 127;
        }
    }
    if (o.argv.empty())
        o.argv = {o.shell.empty() ? (u ? u->shell : std::string{"/bin/sh"}) : o.shell, "-l"};
    if (o.cwd.empty() && u) o.cwd = u->home;
    setup_status(o);
    const int rc = run_runtime(o, orig_argc, orig_argv);
    if (!scratch.empty()) (void)lx::env::remove_tree(scratch);
    return rc;
}

}  // namespace

int lx_cli_main(int argc, char** argv);   // cli.cpp: new, list, shell, set, ...
std::vector<std::string> lx_with_default_env(int argc, char** argv);

namespace {

int with_args(int (*fn)(int, char**), std::vector<std::string> a) {
    std::vector<char*> av;
    for (auto& x : a) av.push_back(x.data());
    av.push_back(nullptr);
    return fn(static_cast<int>(a.size()), av.data());
}

// Words that are commands, not programs to run.
bool is_verb(std::string_view s) {
    static constexpr std::string_view kVerbs[] = {
        "new", "import", "export", "images", "list", "ls", "default", "shell", "exec", "ps",
        "kill", "status", "svc", "logs", "reload", "stop", "down", "set", "get", "unset",
        "edit", "info", "check", "path", "users", "adduser", "snapshot", "snapshots",
        "restore", "drop-snapshot", "reset", "rm", "remove", "rename", "schema", "env",
        "help", "--help", "-h", "version", "--version"};
    for (const auto v : kVerbs) if (s == v) return true;
    return false;
}

}  // namespace

int main(int argc, char** argv) {
    // `linuxity` alone opens the default environment
    if (argc < 2) return lx_cli_main(argc, argv);
    const std::string_view sub = argv[1];
    if (sub == "help" && argc > 2 && std::string_view{argv[2]} == "--all") { usage(argv[0]); return 0; }
    // the server side: an environment running in the background
    if (sub == "up" || sub == "start") {
        auto a = lx_with_default_env(argc, argv);
        a[1] = "up";
        return with_args(cmd_up, a);
    }
    if (sub == "run") return with_args(cmd_run, lx_with_default_env(argc, argv));
    if (is_verb(sub)) return lx_cli_main(argc, argv);
    // anything else: run one program, as linuxity always has
    lx::cli::Options o;
    const int i = parse_flags(argc, argv, 1, o);
    if (i < 0) return 2;
    if (i >= argc) { usage(argv[0]); return 2; }
    for (int j = i; j < argc; ++j) o.argv.emplace_back(argv[j]);
    setup_status(o);
    return run_runtime(o, argc, argv);
}
