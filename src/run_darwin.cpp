// src/run_darwin.cpp -- the macOS host's host_run() (Hypervisor.framework).
//
// linuxity on macOS: run a Linux aarch64 distro's programs natively on Apple
// Silicon, with no VM kernel, no Docker, and no root.
//
//     linuxity --root ~/arch /usr/bin/bash
//
// The program's instructions execute bare on the M-series CPU inside a
// kernel-less Hypervisor.framework VM; every syscall traps back here and is
// serviced by the SAME portable core (kernel/, vfs/, abi/) that the Linux
// ptrace build uses. This file is wiring: the namespace, exec, and the
// process-tree plumbing that guest fork() needs on this OS. The command line
// is src/main.cpp's, shared with every host (see host_run.hpp).
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/host/tmpdir.hpp"
#include "linuxity/runtime/darwin/exec.hpp"
#include "linuxity/runtime/darwin/fork.hpp"
#include "linuxity/runtime/darwin/procinfo.hpp"
#include "linuxity/runtime/darwin/trap.hpp"
#include "linuxity/runtime/darwin/wire.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include <execinfo.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <sys/event.h>
#include <sys/sysctl.h>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <climits>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "linuxity/host/environ.hpp"
#include "linuxity/host/self_exe.hpp"

#include "guest_env.hpp"
#include "guest_files.hpp"
#include "host_run.hpp"
#include "options.hpp"

using namespace lx;

namespace {

using cli::Options;

// The guest's RAM: --memory, else 2 GiB. A VM needs a size up front.
[[nodiscard]] std::uint64_t vm_bytes(const Options& o) {
    return o.res.mem_max.value_or(std::uint64_t{2048} << 20);
}

[[nodiscard]] bool is_dir(const std::string& p) {
    struct ::stat st{};
    return ::stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

void crash_handler(int sig) {
    void* frames[64];
    const int n = ::backtrace(frames, 64);
    std::fprintf(stderr, "\nlinuxity: HOST CRASH (signal %d) in pid %d\n", sig, ::getpid());
    ::backtrace_symbols_fd(frames, n, 2);
    ::signal(sig, SIG_DFL);
    ::raise(sig);
}


// -- The guest "machine": kernel + namespace ----------------------------------
struct Machine {
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};

    explicit Machine(const Options& o, bool fork_child = false) {
        // Before any mount, as in main.cpp: relative --root/--persist/--bind
        // paths are resolved against where the tool was launched.
        if (char cwd[4096]; ::getcwd(cwd, sizeof cwd) != nullptr)
            k.files().set_host_cwd(cwd);
        k.files().set_fork_child(fork_child);
        kernel::MachineSpec spec;
        const long n = ::sysconf(_SC_NPROCESSORS_ONLN);
        spec.ncpu = n > 0 ? n : 1;
        spec.mem_total = vm_bytes(o);
        spec.release = o.release;
        spec.nodename = o.hostname;
        spec.machine_arch = "aarch64";
        {
            // The real CPU: "Apple M3 Pro", not a made-up name, for
            // /proc/cpuinfo and the fetch tools that print it.
            char brand[128]{};
            std::size_t bl = sizeof brand - 1;
            if (::sysctlbyname("machdep.cpu.brand_string", brand, &bl, nullptr, 0) == 0 && brand[0])
                spec.cpu_model = brand;
            // Apple Silicon hides its clock from sysctl; hw.cpufrequency is
            // absent. Use the P-core max from the published tables when we
            // can recognise the family, else keep the spec default.
            const std::string_view b{spec.cpu_model};
            struct F { const char* tag; std::uint64_t hz; const char* part; };
            for (const F& f : {F{"M4", 4'400'000'000ull, "049"}, F{"M3", 4'050'000'000ull, "039"},
                               F{"M2", 3'490'000'000ull, "033"}, F{"M1", 3'200'000'000ull, "023"}})
                if (b.find(f.tag) != std::string_view::npos) {
                    spec.cpu_hz = f.hz; spec.cpu_part = f.part; break;
                }
        }
        k.set_machine(std::move(spec));

        // Stack a WRITABLE upper layer over the read-only rootfs. The core
        // implements the full overlayfs model -- copy-up on first write,
        // whiteouts for deletes, a shadow uid/mode journal -- so the distro
        // you extracted is never mutated by the guest. Without this the
        // guest writes straight into the rootfs directory and silently
        // corrupts it: `pacman -S` would half-install into your pristine
        // tree, and `rm` would delete from it for real.
        //
        // The upper is decided ONCE, by the root process, and every fork
        // child inherits the SAME path. That is load-bearing: a guest fork
        // is a fresh linuxity process (see hvf_fork.hpp), so deriving the
        // scratch dir from getpid() gave each child its own empty layer.
        // pacman's download worker then wrote core.db into a layer the
        // parent never looked at, and the sync silently "failed".
        upper_ = o.persist.empty() ? scratch_upper() : o.persist;
        mkdir_p(upper_);
        k.files().mount_host("/", o.root, upper_);
        k.files().mount_virtual("/proc", vfs::make_procfs(k.procs(), k.machine()));
        k.files().mount_virtual("/sys", vfs::make_sysfs(k.machine()));
        // macOS has no /dev/shm (POSIX shm is a name space without files),
        // but sem_open, shm_open and multiprocessing need one: a directory
        // of our own, named from the upper layer so every guest process of
        // the tree -- each a fresh linuxity -- lands in the SAME one.
        std::string shm_dir = "/dev/shm";
        if (struct ::stat sst{}; ::stat("/dev/shm", &sst) != 0 || !S_ISDIR(sst.st_mode)) {
            // BESIDE the upper, not in it (that would show at /.linuxity-shm)
            shm_dir = host::tmp_path("linuxity-shm-" + std::to_string(std::hash<std::string>{}(upper_)));
            (void)::mkdir(shm_dir.c_str(), 01777);
            (void)::chmod(shm_dir.c_str(), 01777);
        }
        k.files().mount_virtual("/dev", vfs::make_devfs(nullptr, shm_dir));
        for (auto& [host_dir, guest_at] : o.binds)
            k.files().mount_host(kernel::FileNamespace::normalize(guest_at), host_dir);
        // The terminal we were started on, at its real device name (e.g.
        // /dev/ttys003). glibc's ttyname() -- behind `tty`, ssh, sudo and
        // every program that prints "not a tty" -- readlinks /proc/self/fd/0
        // and then requires stat(that path) to be the same device as
        // fstat(0). Binding the device at its own name makes that true.
        for (int fd = 0; fd < 3; ++fd)
            if (const char* tty = ::isatty(fd) ? ::ttyname(fd) : nullptr)
                k.files().mount_host(tty, tty);
        k.files().mount_host("/dev/tty", "/dev/tty");
        // DNS, /etc/hostname, /etc/hosts -- the same as every host. A fork
        // child rebuilds the same files from the same flags, silently.
        resolv_ = cli::mount_guest_files(k, o, /*quiet_events=*/fork_child);
        root_ = o.root;
        real_root_ = canonical(root_);
        real_upper_ = canonical(upper_);
        if (real_root_ == root_) real_root_.clear();
        if (real_upper_ == upper_) real_upper_.clear();
    }

    // host path -> guest path: the inverse of resolve(). With an overlay a
    // guest path has TWO possible host homes (upper and lower), and
    // readlink("/proc/self/fd/N") must report the guest name whichever layer
    // the fd actually came from.
    [[nodiscard]] std::string unresolve(const std::string& host) const {
        // Match both the layer roots as given AND their canonical forms: on
        // macOS /tmp is a symlink to /private/tmp, so a realpath()'d or
        // F_GETPATH host path ("/private/tmp/hvx/persist/usr/bin/bash")
        // never prefix-matched "/tmp/hvx/persist" and leaked out verbatim --
        // /proc/<pid>/exe then named a path that does not exist in the guest
        // ("realpath: /proc/1/exe: No such file", empty Shell in screenfetch).
        for (const std::string* base : {&upper_, &real_upper_, &root_, &real_root_}) {
            if (base->empty()) continue;
            if (host.size() > base->size() && host.starts_with(*base) &&
                host[base->size()] == '/')
                return host.substr(base->size());
            if (host == *base) return "/";
        }
        return host;
    }
    [[nodiscard]] static std::string canonical(const std::string& p) {
        char buf[PATH_MAX];
        return (!p.empty() && ::realpath(p.c_str(), buf)) ? std::string{buf} : std::string{};
    }
    std::string root_;
    std::shared_ptr<std::string> resolv_;   // the served /etc/resolv.conf
    std::string upper_;
    std::string real_root_;     // canonical(root_), e.g. /private/tmp/archarm
    std::string real_upper_;

    // The per-RUN scratch upper. The root process picks it and exports it in
    // the environment; fork children are spawned with that environment, so
    // they find the same name instead of minting a new one.
    [[nodiscard]] static std::string scratch_upper() {
        constexpr const char* kVar = "LINUXITY_SCRATCH_UPPER";
        if (const char* inherited = std::getenv(kVar); inherited && *inherited)
            return inherited;
        std::string fresh = "/tmp/linuxity-upper-" + std::to_string(::getpid());
        ::setenv(kVar, fresh.c_str(), 1);
        return fresh;
    }

    // mkdir -p, so --persist can name a path that doesn't exist yet.
    static void mkdir_p(const std::string& p) {
        for (std::size_t i = 1; i <= p.size(); ++i)
            if (i == p.size() || p[i] == '/') {
                const std::string seg = p.substr(0, i);
                if (seg != "/") (void)::mkdir(seg.c_str(), 0755);
            }
    }

    [[nodiscard]] std::string resolve(const std::string& guest) {
        auto pc = k.files().classify(k.files().absolutize(guest));
        return pc.realm == kernel::Realm2::host_backed ? pc.host_path : std::string{};
    }
};

// The guest inherits the Mac terminal's TERM, but a distro rootfs only ships
// the common entries -- kitty, ghostty, wezterm, alacritty bring their own
// (`kitty-terminfo` etc.), so ncurses programs (vim, cmatrix, htop, less)
// died with "cannot initialize terminal type". The compiled terminfo format
// is OS-independent, and the host already knows this terminal, so compile
// its description into a guest-visible directory and point TERMINFO_DIRS at
// it. The rootfs is never touched; the rootfs's own entry wins when present.
// Returns the GUEST directory, or "" if nothing was needed or possible.
[[nodiscard]] std::string host_terminfo_bridge(const std::string& root, const char* term) {
    if (!term || !*term || std::strchr(term, '/') || root.empty()) return {};
    const std::string sub = std::string(1, term[0]) + "/" + term;
    char hex[8];
    std::snprintf(hex, sizeof hex, "%02x", static_cast<unsigned char>(term[0]));
    for (const std::string& d : {root + "/usr/share/terminfo/" + sub,
                                 root + "/usr/share/terminfo/" + hex + "/" + term,
                                 root + "/usr/lib/terminfo/" + sub,
                                 root + "/etc/terminfo/" + sub})
        if (::access(d.c_str(), R_OK) == 0) return {};     // rootfs has it

    // Guest /tmp is host /tmp through the overlay (see mount_host), so a
    // host directory under /tmp is visible at the same path in the guest.
    const std::string dir = "/tmp/linuxity-terminfo-" + std::to_string(::getuid());
    const std::string want = dir + "/" + sub;
    if (::access(want.c_str(), R_OK) == 0) return dir;     // already bridged
    (void)::mkdir(dir.c_str(), 0755);
    // `infocmp -x TERM | tic -x -o DIR -` with the host's ncurses. Plain
    // fork/exec with fixed argv: no shell, TERM was validated above.
    int pfd[2];
    if (::pipe(pfd) != 0) return {};
    const pid_t a = ::fork();
    if (a == 0) {
        ::dup2(pfd[1], 1); ::close(pfd[0]); ::close(pfd[1]);
        const int dn = ::open("/dev/null", O_WRONLY); if (dn >= 0) ::dup2(dn, 2);
        ::execlp("infocmp", "infocmp", "-x", term, static_cast<char*>(nullptr));
        ::_exit(127);
    }
    const pid_t b = ::fork();
    if (b == 0) {
        ::dup2(pfd[0], 0); ::close(pfd[0]); ::close(pfd[1]);
        const int dn = ::open("/dev/null", O_WRONLY); if (dn >= 0) { ::dup2(dn, 1); ::dup2(dn, 2); }
        ::execlp("tic", "tic", "-x", "-o", dir.c_str(), "-", static_cast<char*>(nullptr));
        ::_exit(127);
    }
    ::close(pfd[0]); ::close(pfd[1]);
    int st = 0;
    if (a > 0) ::waitpid(a, &st, 0);
    if (b > 0) ::waitpid(b, &st, 0);
    // tic on macOS may write the hashed ("78/") layout; ncurses on Linux
    // reads both, but check the letter layout and fall back to hex.
    if (::access(want.c_str(), R_OK) == 0) return dir;
    if (::access((dir + "/" + hex + "/" + term).c_str(), R_OK) == 0) {
        (void)::mkdir((dir + "/" + std::string(1, term[0])).c_str(), 0755);
        (void)::symlink((std::string("../") + hex + "/" + term).c_str(), want.c_str());
        return dir;
    }
    return {};
}

using host::self_exe;   // host/self_exe.hpp

// -- Fork, parent side ---------------------------------------------------------
// Spawn a fresh linuxity in --fork-child mode and hand it the guest. The
// child's guest fds arrive at host fds 3.. (one per distinct open file), and
// the pid table's fd rides along too. stdio stays where it is: the child
// inherits 0/1/2 just as a forked process would.
class Forker {
public:
    Forker(const Options& o, Machine& m, runtime::HvfMachine& machine, runtime::PidSpace& pids)
        : opts_{o}, machine_wrap_{m}, machine_{machine}, pids_{pids} {}

    // Every spare still parked when this process ends dies with it (it
    // watches us); its reserved VM goes back to the tree. Run from the one
    // process-exit hook (runtime::on_process_exit), whichever _exit ends us.
    void release_unclaimed() {
        auto& s = slot();
        std::lock_guard l{s.mu};
        for (std::size_t k = 0; k < s.ready.size() + static_cast<std::size_t>(s.pending); ++k)
            pids_.release_warm_vm();
        s.ready.clear();
        s.pending = 0;
    }

    [[nodiscard]] pid_t operator()(runtime::HvfTrap::ForkImage& img) {
        static const bool profile = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
        const auto t0 = std::chrono::steady_clock::now();
        auto mark = [&](const char* what) {
            if (!profile) return;
            const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - t0).count();
            std::fprintf(stderr, "[fork %d] %-10s %7lld us\n", ::getpid(), what,
                         static_cast<long long>(us));
        };
        {
            std::lock_guard l{machine_wrap_.k.mutex()};
            img.namespace_state = machine_wrap_.k.export_fork(img.parent);
        }
        // FAST PATH: a ZYGOTE -- a linuxity spawned ahead of time, already
        // through dyld, static init, Machine setup and the bootstrap lookup,
        // parked on its reply port. posix_spawn + a fresh process's startup
        // is ~5 ms of every fork (measured); with a warm zygote a fork is a
        // COW snapshot plus one Mach message. Its fds (including 0/1/2,
        // which must be the forking process's CURRENT ones) ride in that
        // message as fileports. A fresh zygote is started right after, off
        // the fork's critical path, for the next fork.
        if (static const bool no_zyg = std::getenv("LINUXITY_NO_ZYGOTE") != nullptr; !no_zyg) {
            Zygote z = take_zygote();
            if (z.pid > 0 && z.sid != ::getsid(0)) {     // spawned before a setsid: stale
                drop_stale_zygotes();
                z = {};
            }
            if (z.pid > 0) {
                std::vector<int> fds{0, 1, 2};
                fds.insert(fds.end(), img.fd_hosts.begin(), img.fd_hosts.end());
                fds.push_back(pids_.fd());
                const mach_port_t mem = runtime::fork_ipc::snapshot(machine_.raw_base(),
                                                                    machine_.mem_size());
                const bool sent = runtime::fork_ipc::send_with_fds(
                    z.reply, mem, machine_.mem_size(), runtime::wire::encode(img), fds);
                ::mach_port_deallocate(::mach_task_self(), z.reply);
                mark("zygote-sent");
                if (sent) { spawn_zygote_async(); return z.pid; }
                ::kill(z.pid, SIGKILL);
                int st = 0; ::waitpid(z.pid, &st, 0);
            }
            spawn_zygote_async();     // warm one for next time
        }

        // One host fd per distinct open file, placed at 3, 4, 5... in the child.
        //
        // posix_spawn applies file actions IN ORDER, so a naive sequence of
        // dup2(src_i, 3+i) is wrong whenever some later src_j happens to be
        // a number an earlier dup2 already overwrote: src_j then names the
        // wrong file. Classic parallel-assignment hazard. Fix: first dup
        // every source to a private HIGH number in the parent (above any
        // target), then dup2 from those. No high fd can be a target, so no
        // action can clobber another's source.
        //
        // The groups come straight from the table's export, which already
        // lists every distinct open file -- including each eventfd's hidden
        // write end -- so nothing the child's table refers to is left behind.
        posix_spawn_file_actions_t fa;
        ::posix_spawn_file_actions_init(&fa);
        const std::vector<int>& sources = img.fd_hosts;
        std::vector<int> placed(sources.size(), -1);
        std::vector<int> staged;                     // high copies, closed after spawn
        const int targets = static_cast<int>(sources.size()) + 1;   // + the pid table
        const int high_floor = 3 + targets + 64;
        auto stage = [&](int src) {
            const int h = ::fcntl(src, F_DUPFD_CLOEXEC, high_floor);
            staged.push_back(h);
            return h;
        };
        int next = 3;
        for (std::size_t gi = 0; gi < sources.size(); ++gi) {
            placed[gi] = next;
            ::posix_spawn_file_actions_adddup2(&fa, stage(sources[gi]), next);
            ++next;
        }
        const int pid_fd_child = next++;
        ::posix_spawn_file_actions_adddup2(&fa, stage(pids_.fd()), pid_fd_child);
        struct Closer {
            std::vector<int>& v;
            ~Closer() { for (int fd : v) if (fd >= 0) ::close(fd); }
        } close_staged{staged};

        // POSIX_SPAWN_CLOEXEC_DEFAULT: the child starts with ONLY 0/1/2 and
        // the fds placed above. Without it, every host fd linuxity happens
        // to have open is inherited at the same NUMBER -- and a dup2 target
        // above can land on top of one of them in the wrong order, leaving
        // e.g. the pid-table slot pointing at a guest file. (That produced a
        // pid table mapped over a 6-byte /etc/hostname: a SIGSEGV writing
        // the exec flag past its end.)
        posix_spawnattr_t attr;
        ::posix_spawnattr_init(&attr);
        ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK);
        // Born with every host signal BLOCKED: until the child has installed
        // the guest's dispositions (resume_fork_child), a signal the guest
        // parent sends at once -- a ping-pong's first SIGUSR1 -- would meet
        // the host DEFAULT and kill it. Blocked, it waits; run() unblocks.
        { sigset_t all; sigfillset(&all); ::posix_spawnattr_setsigmask(&attr, &all); }
        for (int fd = 0; fd < 3; ++fd) ::posix_spawn_file_actions_addinherit_np(&fa, fd);

        // The rendezvous: a uniquely named Mach service the child looks up.
        const std::string svc_name = runtime::fork_ipc::unique_service_name();
        mach_port_t svc = MACH_PORT_NULL;
        ::mach_port_allocate(::mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &svc);
        ::mach_port_insert_right(::mach_task_self(), svc, svc, MACH_MSG_TYPE_MAKE_SEND);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (::bootstrap_register(bootstrap_port, const_cast<char*>(svc_name.c_str()), svc)
            != KERN_SUCCESS) {
#pragma clang diagnostic pop
            ::posix_spawn_file_actions_destroy(&fa);
            return -1;
        }

        std::vector<std::string> args{self_exe()};
        args.insert(args.end(), opts_.flags.begin(), opts_.flags.end());
        args.emplace_back("--fork-child");
        args.emplace_back(svc_name);
        args.emplace_back(std::to_string(pid_fd_child));
        std::string groups;
        for (std::size_t g = 0; g < placed.size(); ++g)
            groups += (g ? "," : "") + std::to_string(placed[g]);
        args.emplace_back(groups.empty() ? "-" : groups);
        std::vector<char*> av;
        for (auto& s : args) av.push_back(s.data());
        av.push_back(nullptr);

        pid_t pid = -1;
        const int rc = ::posix_spawn(&pid, args[0].c_str(), &fa, &attr, av.data(), host::host_environ());
        ::posix_spawn_file_actions_destroy(&fa);
        ::posix_spawnattr_destroy(&attr);
        mark("spawned");
        if (rc != 0) { ::mach_port_deallocate(::mach_task_self(), svc); return -1; }

        // Wait for the child's hello (it carries the child's reply port),
        // then ship RAM + state. The child cannot run guest code until this
        // arrives, so the snapshot is exactly the guest at the fork point.
        //
        // BOUNDED: if the child dies before saying hello (no VM left, bad
        // exec path, signing problem), an unbounded receive would hang this
        // guest process -- and the user's whole shell -- forever. So wait in
        // short slices and check the child between them: its death ends the
        // wait at once, a wedged child after kHelloTimeoutMs.
        struct { mach_msg_header_t h; mach_msg_trailer_t t; } hello{};
        constexpr int kHelloTimeoutMs = 10'000, kSliceMs = 20;
        mach_msg_return_t got = MACH_RCV_TIMED_OUT;
        for (int waited = 0; waited < kHelloTimeoutMs; waited += kSliceMs) {
            got = ::mach_msg(&hello.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                             sizeof hello, svc, kSliceMs, MACH_PORT_NULL);
            if (got != MACH_RCV_TIMED_OUT) break;
            int st = 0;
            if (::waitpid(pid, &st, WNOHANG) == pid) { pid = -1; break; }   // died first
        }
        if (got != MACH_MSG_SUCCESS) {
            ::mach_port_mod_refs(::mach_task_self(), svc, MACH_PORT_RIGHT_RECEIVE, -1);
            if (pid > 0) {
                ::kill(pid, SIGKILL);
                int st = 0;
                ::waitpid(pid, &st, 0);
            }
            return -1;
        }
        mark("hello");
        const mach_port_t mem = runtime::fork_ipc::snapshot(machine_.raw_base(), machine_.mem_size());
        mark("snapshot");
        const bool sent = runtime::fork_ipc::send(hello.h.msgh_remote_port, mem,
                                                  machine_.mem_size(), runtime::wire::encode(img));
        mark("sent");
        ::mach_port_mod_refs(::mach_task_self(), svc, MACH_PORT_RIGHT_RECEIVE, -1);
        return sent ? pid : -1;
    }

private:
    // -- Zygotes ------------------------------------------------------------
    // A zygote is a linuxity started with `--zygote SERVICE`: it does all of
    // a fork child's process-level setup, looks up SERVICE, sends us its
    // reply port ("hello") and blocks receiving the handoff. We keep at most
    // ONE warm per guest process (it costs a parked process, ~6 MB RSS).
    // A spare inherits its creator's host SESSION when spawned and can never
    // change it. So it is only a valid fork child while the creator is still
    // in that session (a pty child setsid()s, then forks its job): record it.
    struct Zygote { pid_t pid{-1}; mach_port_t reply{MACH_PORT_NULL}; pid_t sid{-1}; };
    struct ZygoteSlot {
        std::mutex mu;
        std::condition_variable cv;
        int pending{0};                  // spawns in flight
        std::vector<Zygote> ready;
    };
    ZygoteSlot& slot() { static ZygoteSlot s; return s; }
    // Every parked spare belongs to a session we left (see Zygote): kill
    // them and give their VMs back; fresh ones are spawned in the new one.
    void drop_stale_zygotes() {
        std::vector<Zygote> old;
        {
            auto& s = slot();
            std::lock_guard l{s.mu};
            old.swap(s.ready);
        }
        for (const auto& z : old) {
            ::mach_port_deallocate(::mach_task_self(), z.reply);
            ::kill(z.pid, SIGKILL);
            int st = 0;
            ::waitpid(z.pid, &st, 0);
            pids_.release_warm_vm();
        }
    }
    // Pool depth: back-to-back forks (a shell loop, `make -j`, configure)
    // drain warm zygotes faster than fresh ones start (~5 ms each, spawned
    // in parallel). Measured: depth 3 ran dry every third fork of a tight
    // fork/wait loop (3.7 ms stall); 6 covers it. A parked zygote is ~6 MB
    // RSS and no CPU, and the pool only fills once forking starts.
    static constexpr int kPool = 6;

    // Take a warm zygote; if none is ready but one is coming, wait briefly.
    Zygote take_zygote() {
        auto& s = slot();
        std::unique_lock l{s.mu};
        static const bool zp = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
        const std::size_t had = s.ready.size();
        const auto w0 = std::chrono::steady_clock::now();
        s.cv.wait_for(l, std::chrono::milliseconds(20),
                      [&] { return !s.ready.empty() || s.pending == 0; });
        if (zp) std::fprintf(stderr, "[pool] ready=%zu pending=%d waited %lld us\n", had, s.pending,
            static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - w0).count()));
        if (s.ready.empty()) return {};
        Zygote z = s.ready.back();
        s.ready.pop_back();
        pids_.release_warm_vm();      // it becomes a live process: counted there
        return z;
    }
    void spawn_zygote_async() {
        auto& s = slot();
        int want = 0;
        {
            std::lock_guard l{s.mu};
            want = kPool - static_cast<int>(s.ready.size()) - s.pending;
            if (want <= 0) return;
            // only as many spares as the tree's VM budget allows
            int got = 0;
            while (got < want && pids_.reserve_warm_vm()) ++got;
            want = got;
            if (want <= 0) return;
            s.pending += want;
        }
        for (int k = 0; k < want; ++k)
            std::thread([this] {
                Zygote z = spawn_zygote();
                auto& sl = slot();
                std::lock_guard l{sl.mu};
                --sl.pending;
                if (z.pid > 0) sl.ready.push_back(z);
                else pids_.release_warm_vm();
                sl.cv.notify_all();
            }).detach();
    }
    // posix_spawn `linuxity <opts> --zygote SVC` and wait for its hello.
    Zygote spawn_zygote() {
        const std::string svc_name = runtime::fork_ipc::unique_service_name();
        mach_port_t svc = MACH_PORT_NULL;
        ::mach_port_allocate(::mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &svc);
        ::mach_port_insert_right(::mach_task_self(), svc, svc, MACH_MSG_TYPE_MAKE_SEND);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (::bootstrap_register(bootstrap_port, const_cast<char*>(svc_name.c_str()), svc)
            != KERN_SUCCESS) {
#pragma clang diagnostic pop
            ::mach_port_mod_refs(::mach_task_self(), svc, MACH_PORT_RIGHT_RECEIVE, -1);
            return {};
        }
        std::vector<std::string> args{self_exe()};
        args.insert(args.end(), opts_.flags.begin(), opts_.flags.end());
        args.emplace_back("--zygote");
        args.emplace_back(svc_name);
        std::vector<char*> av;
        for (auto& a : args) av.push_back(a.data());
        av.push_back(nullptr);
        // NO fds are inherited. A parked zygote that held the caller's
        // stderr kept every `linuxity ... 2>&1 | grep` pipeline open after
        // the guest exited (the pipe never reached EOF). The real 0/1/2
        // arrive with the fork; until then it talks to /dev/null.
        posix_spawn_file_actions_t fa;
        ::posix_spawn_file_actions_init(&fa);
        ::posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
        ::posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
        ::posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
        posix_spawnattr_t attr;
        ::posix_spawnattr_init(&attr);
        ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK);
        { sigset_t all; sigfillset(&all); ::posix_spawnattr_setsigmask(&attr, &all); }   // see the fork spawn
        pid_t pid = -1;
        const int rc = ::posix_spawn(&pid, args[0].c_str(), &fa, &attr, av.data(), host::host_environ());
        ::posix_spawn_file_actions_destroy(&fa);
        ::posix_spawnattr_destroy(&attr);
        if (rc != 0) {
            ::mach_port_mod_refs(::mach_task_self(), svc, MACH_PORT_RIGHT_RECEIVE, -1);
            return {};
        }
        struct { mach_msg_header_t h; mach_msg_trailer_t t; } hello{};
        const auto got = ::mach_msg(&hello.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    sizeof hello, svc, 10'000, MACH_PORT_NULL);
        ::mach_port_mod_refs(::mach_task_self(), svc, MACH_PORT_RIGHT_RECEIVE, -1);
        if (got != MACH_MSG_SUCCESS) {
            ::kill(pid, SIGKILL);
            int st = 0; ::waitpid(pid, &st, 0);
            return {};
        }
        return {pid, hello.h.msgh_remote_port, ::getsid(0)};
    }

    const Options& opts_;
    Machine& machine_wrap_;
    runtime::HvfMachine& machine_;
    runtime::PidSpace& pids_;
};

// -- Fork, child side ------------------------------------------------------------
struct ChildArgs {
    std::string service;
    int pid_fd{-1};
    std::vector<int> group_fds;
};

[[nodiscard]] bool receive_fork(const ChildArgs& ca, runtime::HvfMachine& vm,
                                runtime::HvfTrap::ForkImage& img) {
    // A VM first: Hypervisor.framework allows a fixed number at once (see
    // PidSpace::kMaxVms). A big tree hits that while most of it is about to
    // exit (341 short-lived processes four levels deep), and Linux would
    // simply have forked -- so wait for one to free up, for a while. Only if
    // none does, exit WITHOUT the hello: the parent's fork fails EAGAIN --
    // what a kernel out of process slots says -- instead of reporting a
    // child that then dies.
    if (!vm.prewarm()) {
        const auto give_up = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        useconds_t nap = 1000;
        do {
            ::usleep(nap);
            nap = std::min<useconds_t>(nap * 2, 20000);
            if (std::chrono::steady_clock::now() > give_up) ::_exit(127);
        } while (!vm.prewarm());
    }
    mach_port_t parent = MACH_PORT_NULL;
    static const bool prof = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
    const auto r0 = std::chrono::steady_clock::now();
    auto rmark = [&](const char* w) {
        if (prof) std::fprintf(stderr, "[recv %d] %-10s %7lld us\n", ::getpid(), w,
            static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - r0).count()));
    };
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    if (::bootstrap_look_up(bootstrap_port, const_cast<char*>(ca.service.c_str()), &parent)
        != KERN_SUCCESS)
        return false;
#pragma clang diagnostic pop
    mach_port_t reply = MACH_PORT_NULL;
    ::mach_port_allocate(::mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
    ::mach_port_insert_right(::mach_task_self(), reply, reply, MACH_MSG_TYPE_MAKE_SEND);
    struct { mach_msg_header_t h; } hello{};
    hello.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
    hello.h.msgh_size = sizeof hello;
    hello.h.msgh_remote_port = parent;
    hello.h.msgh_local_port = reply;
    if (::mach_msg(&hello.h, MACH_SEND_MSG, sizeof hello, 0, MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != MACH_MSG_SUCCESS)
        return false;

    runtime::fork_ipc::Received in;
    rmark("hello-sent");
    if (!runtime::fork_ipc::receive(reply, in, parent)) ::_exit(127);   // parent gave up: so do we
    rmark("received");
    void* ram = runtime::fork_ipc::map_snapshot(in.memory, in.mem_size);
    if (!ram) { std::fputs("linuxity: fork: cannot map the parent's memory\n", stderr); return false; }
    if (auto st = vm.init_from(ram, in.mem_size); !st) {
        std::fprintf(stderr, "linuxity: fork: %s\n", st.error() == Errno::enodev
            ? "the hypervisor refused another VM (too many guest processes at once?)"
            : "cannot map guest memory into the VM");
        return false;
    }
    return runtime::wire::decode(in.blob, img);
}

// -- Running one guest THREAD ------------------------------------------------
// Every guest thread is a host thread that owns its own vCPU and TaskState
// and runs its own copy of the portable Cpu loop. Hypervisor.framework binds
// a vcpu to its creating thread, so the vCPU must be created HERE, inside
// the thread that will run it -- which is also exactly what we want: XNU
// then schedules guest threads across the physical cores.
struct ThreadContext {
    const Options& opts;
    Machine& machine_wrap;
    runtime::HvfMachine& machine;
    runtime::ProcessState& proc;
    runtime::PidSpace& pids;
    Forker& forker;
    std::vector<std::thread>& threads;
    std::mutex& threads_mu;
};

void run_guest_thread(ThreadContext& ctx, runtime::HvfTrap::ThreadStart start);

// Install the hooks a trap needs to create more tasks. Shared by the initial
// thread and every thread it spawns, so a thread can itself fork or spawn.
void wire_spawners(runtime::HvfTrap& trap, ThreadContext& ctx) {
    trap.set_resolver([&ctx](const std::string& g) {
        std::lock_guard l{ctx.machine_wrap.k.mutex()};
        return ctx.machine_wrap.resolve(g);
    });
    trap.set_unresolver([&ctx](const std::string& h) {
        std::lock_guard l{ctx.machine_wrap.k.mutex()};
        return ctx.machine_wrap.unresolve(h);
    });
    trap.set_fork_spawner([&ctx](runtime::HvfTrap::ForkImage& img) {
        return ctx.forker(img);
    });
    trap.set_thread_spawner([&ctx](runtime::HvfTrap::ThreadStart s) {
        try {
            std::lock_guard g{ctx.threads_mu};
            ctx.threads.emplace_back([&ctx, s = std::move(s)]() mutable {
                run_guest_thread(ctx, std::move(s));
            });
            return true;
        } catch (const std::system_error&) {
            return false;                      // EAGAIN to the guest
        }
    });
}

void run_guest_thread(ThreadContext& ctx, runtime::HvfTrap::ThreadStart start) {
    runtime::HvfCpu cpu;
    if (!cpu.create()) {
        std::fputs("linuxity: cannot create a vCPU for a guest thread\n", stderr);
        return;
    }
    cpu.load(start.cpu);

    runtime::TaskState task;
    task.tid = start.tid;
    task.sig_mask = start.sig_mask;
    task.clear_child_tid = start.clear_child_tid;

    runtime::HvfTrap trap{ctx.machine, cpu, ctx.proc, task, ctx.pids};
    trap.adopt_thread(start.tgid);
    wire_spawners(trap, ctx);
    runtime::HvfMem mem{ctx.machine, &trap};

    ctx.proc.add_thread(task.tid, &cpu);
    runtime::g_pending.register_cpu(cpu.handle());

    runtime::Cpu loop{trap, ctx.machine_wrap.k, mem, abi::Arch::aarch64};
    (void)loop.run(uaddr(0), uaddr(0));          // already positioned

    runtime::g_pending.unregister_cpu(cpu.handle());
    ctx.proc.remove_thread(task.tid);
    ctx.pids.release(task.tid);          // the tid returns to the shared namespace
}

// -- Run a guest to completion (shared by root and fork children) ---------------
// Never returns: the process ends in HvfTrap::end_process.
[[noreturn]] void run(const Options& o, Machine& m, runtime::HvfMachine& machine,
                      runtime::HvfCpu& cpu, runtime::ProcessState& proc,
                      runtime::TaskState& task, runtime::PidSpace& pids,
                      runtime::HvfTrap& trap) {
    // The guest's dispositions are in place (root: fresh; fork child: just
    // restored), so the host signals a fork child was born blocking (see
    // Forker) may now arrive -- the guest's own mask is virtual, kept by
    // the trap, never the host thread's.
    { sigset_t none; sigemptyset(&none); ::pthread_sigmask(SIG_SETMASK, &none, nullptr); }
    runtime::HvfMem mem{machine, &trap};
    Forker forker{o, m, machine, pids};
    trap.on_exit([&forker] { forker.release_unclaimed(); });
    std::vector<std::thread> threads;
    std::mutex threads_mu;
    ThreadContext ctx{o, m, machine, proc, pids, forker, threads, threads_mu};
    wire_spawners(trap, ctx);
    // /proc's per-task facts: macOS has no host /proc, so this process
    // answers for itself (and its threads), Darwin for the others.
    m.k.procs().set_host_facts([&proc, &pids](std::int32_t g, std::string_view leaf)
                                   -> std::optional<std::string> {
        const auto h = pids.host_of(g);
        if (!h || *h <= 0) return std::nullopt;
        if (*h == ::getpid()) {
            const runtime::procinfo::Self self{proc, g};
            return runtime::procinfo::fact(leaf, *h, &self, pids.nice_of(g));
        }
        return runtime::procinfo::fact(leaf, *h, nullptr, pids.nice_of(g));
    });

    proc.add_thread(task.tid, &cpu);
    runtime::g_pending.register_cpu(cpu.handle());
    trap.start_timers();

    runtime::Cpu loop{trap, m.k, mem, abi::Arch::aarch64};
    auto rc = loop.run(uaddr(0), uaddr(0));

    // The process ends when the initial thread's loop ends (exit_group, or
    // the last thread). Linux does NOT wait for sibling threads here: the
    // kernel tears them down wherever they are. We must match that, because
    // a sibling blocked inside a HOST call (futex, poll, sigsuspend) is not
    // in hv_vcpu_run, so no kick can reach it -- and joining it hangs the
    // process forever.
    //
    // That hang was the real `pacman -Sy` failure: the download sandbox
    // child called _Exit(1) with worker threads parked in futex waits,
    // linuxity sat in join(), pacman's watchdog saw a child that would not
    // die, sent it SIGTERM, and then re-raised SIGTERM on itself (dload.c:
    // `kill(getpid(), childsig)`) -- "Terminated".
    //
    // _exit() is exactly the Linux semantics: every thread stops, every fd
    // closes, the parent's wait sees our status. Guest RAM is a mapping the
    // kernel reclaims; nothing in it needs unwinding.
    if (!rc) std::fprintf(stderr, "linuxity: runtime error %d\n", static_cast<int>(rc.error()));
    trap.end_process(rc ? *rc : 1);
}

}  // namespace

namespace {
// Set once a zygote received its fork: from then on it is a real guest
// process and outlives its parent like any child would.
std::atomic<bool>& zygote_claimed() { static std::atomic<bool> b{false}; return b; }
// /proc sees EVERY live guest process, not just this host process's
// fork-time snapshot of the process table. Each guest process is its own
// host process; the shared PidSpace page is the only cross-process truth.
void attach_live_procs(Machine& m, runtime::PidSpace& pids) {
    struct Live final : kernel::ProcessTable::LiveSource {
        runtime::PidSpace& ps;
        explicit Live(runtime::PidSpace& p) : ps{p} {}
        bool alive(std::int32_t pid) const override { return ps.is_process(pid); }
        std::vector<std::int32_t> pids() const override { return ps.processes(); }
        kernel::ProcInfo info(std::int32_t pid) const override {
            kernel::ProcInfo pi;
            const std::string exe = ps.exe_of(pid);
            pi.comm = exe.substr(exe.find_last_of('/') + 1).substr(0, 15);
            pi.cmdline = exe;
            pi.ppid = ps.ppid_of(pid);
            pi.state = 'S';
            pi.exe = exe;
            return pi;
        }
        std::int32_t pgid(std::int32_t pid) const override {
            return ps.is_process(pid) ? ps.pgid_of(pid) : 0;
        }
        std::int32_t sid(std::int32_t pid) const override {
            return ps.is_process(pid) ? ps.sid_of(pid) : 0;
        }
    };
    static Live live{pids};
    m.k.procs().set_live_source(&live);
}
// Startup stage timer (LINUXITY_PROFILE_START=1): where a fresh linuxity
// spends its first milliseconds. Every guest fork pays this.
bool start_profiling() {
    static const bool on = std::getenv("LINUXITY_PROFILE_START") != nullptr;
    return on;
}
void smark(const char* w) {
    static const auto s0 = std::chrono::steady_clock::now();
    if (start_profiling()) std::fprintf(stderr, "[start %d] %-12s %7lld us\n", ::getpid(), w,
        static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - s0).count()));
}

// Once per process, whichever way in: the start timer, the crash handler,
// and linuxity's own mailbox kick (kKickSignal). The kick handler must be in
// place from the first instruction: a parent can kick a fork child the
// moment it exists (a setpgid race), and SIGEMT's DEFAULT action kills.
void process_start() {
    runtime::install_kick_handler();
    // Every guest fd is a host fd here, and the guest is promised 1024
    // (FdTable::kMaxFds, the RLIMIT_NOFILE it reads), plus linuxity's own.
    // macOS starts a process at a soft limit of 256: raise ours to what
    // the hard limit allows, as a shell's `ulimit -n` would.
    if (struct ::rlimit rl{}; ::getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        const rlim_t want = std::min<rlim_t>(rl.rlim_max, OPEN_MAX);
        if (rl.rlim_cur < want) { rl.rlim_cur = want; (void)::setrlimit(RLIMIT_NOFILE, &rl); }
    }
    if (start_profiling()) {
        // Time from exec (kernel's process start) to main: dyld + static init.
        struct kinfo_proc kp{};
        std::size_t len = sizeof kp;
        int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, ::getpid()};
        if (::sysctl(mib, 4, &kp, &len, nullptr, 0) == 0) {
            timeval now{}; ::gettimeofday(&now, nullptr);
            const auto& st = kp.kp_proc.p_starttime;
            std::fprintf(stderr, "[start %d] exec->main  %7lld us\n", ::getpid(),
                static_cast<long long>((now.tv_sec - st.tv_sec) * 1000000LL + (now.tv_usec - st.tv_usec)));
        }
    }
    smark("main");
    if (std::getenv("LINUXITY_DEBUG")) {
        ::signal(SIGSEGV, crash_handler);
        ::signal(SIGBUS, crash_handler);
    }
}

}  // namespace

const char* cli::host_name() noexcept { return "macos (Hypervisor.framework)"; }
bool cli::host_runs_instances() noexcept { return false; }

// The private ways linuxity starts itself: a fork child (`--fork-child
// SERVICE PIDFD GROUPFDS`) or a pre-spawned zygote (`--zygote SERVICE`).
// Both follow the parent's flags, replayed through the one parser.
int cli::host_internal(const Options& o, int argc, char** argv, int i) {
    process_start();

    // -- Fork child: `--fork-child SERVICE PIDFD GROUPFDS` follows the options.
    if (i + 3 < argc && std::string_view{argv[i]} == "--fork-child") {
        const auto c0 = std::chrono::steady_clock::now();
        const bool prof = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
        auto cmark = [&](const char* what) {
            if (!prof) return;
            std::fprintf(stderr, "[child %d] %-10s %7lld us\n", ::getpid(), what,
                         static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now() - c0).count()));
        };
        cmark("main");
        ChildArgs ca;
        ca.service = argv[i + 1];
        ca.pid_fd = std::atoi(argv[i + 2]);
        if (std::string_view g = argv[i + 3]; g != "-") {
            for (std::size_t at = 0; at <= g.size();) {
                auto comma = g.find(',', at);
                ca.group_fds.push_back(std::atoi(std::string{g.substr(at, comma - at)}.c_str()));
                if (comma == std::string_view::npos) break;
                at = comma + 1;
            }
        }
        Machine m{o, /*fork_child=*/true};
        cmark("machine");
        smark("machine");
        runtime::HvfMachine machine;
        runtime::HvfTrap::ForkImage img;
        if (!receive_fork(ca, machine, img)) {
            std::fputs("linuxity: fork handoff failed\n", stderr);
            return 127;
        }
        cmark("vm-up");
        m.k.import_fork(img.namespace_state);
        runtime::g_pending.reset_for_fork_child();
        runtime::PidSpace pids{ca.pid_fd};
        // The initial thread of the forked process.
        runtime::HvfCpu cpu;
        if (!cpu.create()) {
            std::fputs("linuxity: cannot create a vCPU\n", stderr);
            return 127;
        }
        runtime::ProcessState proc;
        runtime::TaskState task;
        runtime::HvfTrap trap{machine, cpu, proc, task, pids};
        attach_live_procs(m, pids);
        trap.resume_fork_child(img, ca.group_fds);
        run(o, m, machine, cpu, proc, task, pids, trap);
    }

    // -- Zygote: `--zygote SERVICE`. A fork child spawned AHEAD of the fork.
    // Everything a process costs to start (dyld, static init, Machine and
    // overlay attach, the bootstrap lookup) happens now, while no guest is
    // waiting; then it parks in mach_msg until the parent forks. Its fds
    // arrive in the handoff as fileports: [0,1,2, groups..., pidspace].
    if (i + 1 < argc && std::string_view{argv[i]} == "--zygote") {
        smark("zyg-main");
        Machine m{o, /*fork_child=*/true};
        smark("zyg-machine");
        // Pre-warm the VM and this thread's vCPU while parked: hv_vm_create
        // + hv_vcpu_create are ~0.6 ms of a fork otherwise. A vCPU belongs
        // to the thread that made it, and this main thread is the one that
        // will run the guest, so it is safe to create it now.
        runtime::HvfMachine machine;
        if (!machine.prewarm()) return 127;
        runtime::HvfCpu cpu;
        if (!cpu.create()) return 127;
        smark("zyg-vcpu");
        mach_port_t parent = MACH_PORT_NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        if (::bootstrap_look_up(bootstrap_port, argv[i + 1], &parent) != KERN_SUCCESS)
            return 127;
#pragma clang diagnostic pop
        mach_port_t reply = MACH_PORT_NULL;
        ::mach_port_allocate(::mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
        ::mach_port_insert_right(::mach_task_self(), reply, reply, MACH_MSG_TYPE_MAKE_SEND);
        struct { mach_msg_header_t h; } hello{};
        hello.h.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND);
        hello.h.msgh_size = sizeof hello;
        hello.h.msgh_remote_port = parent;
        hello.h.msgh_local_port = reply;
        if (::mach_msg(&hello.h, MACH_SEND_MSG, sizeof hello, 0, MACH_PORT_NULL,
                       MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) != MACH_MSG_SUCCESS)
            return 127;
        // If the parent dies before forking, our send right's target goes
        // away; a dead-name notification would be the clean exit, but the
        // receive below simply fails when the parent's port set is torn
        // down with it. Either way: never run guest code without a handoff.
        // If our creator exits without forking (the guest session ended), a
        // parked zygote must not linger. Watch the creator pid; exit with it.
        // The creator comes from the service name: getppid() is already 1
        // if it died while we were starting, and launchd never exits.
        {
            pid_t creator = runtime::fork_ipc::service_creator(argv[i + 1]);
            if (creator <= 0) creator = ::getppid();
            if (creator <= 1 || ::getppid() != creator) ::_exit(0);   // orphaned already
            std::thread([creator] {
                const int kq = ::kqueue();
                struct ::kevent ev{};
                EV_SET(&ev, static_cast<uintptr_t>(creator), EVFILT_PROC, EV_ADD,
                       NOTE_EXIT, 0, nullptr);
                // ESRCH: it exited between the check above and here.
                if (kq < 0 || ::kevent(kq, &ev, 1, nullptr, 0, nullptr) < 0) {
                    if (!zygote_claimed().load()) ::_exit(0);
                    return;
                }
                struct ::kevent out{};
                while (::kevent(kq, nullptr, 0, &out, 1, nullptr) < 0 && errno == EINTR) {}
                if (!zygote_claimed().load()) ::_exit(0);
            }).detach();
        }
        runtime::fork_ipc::Received in;
        if (!runtime::fork_ipc::receive_with_fds(reply, in) || in.fds.size() < 4)
            return 127;
        zygote_claimed().store(true);
        static const bool zprof = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
        const auto z0 = std::chrono::steady_clock::now();
        auto zmark = [&](const char* w) {
            if (zprof) std::fprintf(stderr, "[zyg %d] %-10s %6lld us\n", ::getpid(), w,
                static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - z0).count()));
        };
        // Lay the fds out exactly like the posix_spawn path: 0/1/2 as given,
        // the open-file groups wherever they land, the pid space last.
        for (int t = 0; t < 3; ++t) {
            if (in.fds[static_cast<std::size_t>(t)] != t) {
                ::dup2(in.fds[static_cast<std::size_t>(t)], t);
                ::close(in.fds[static_cast<std::size_t>(t)]);
            }
        }
        const int pid_fd = in.fds.back();
        std::vector<int> groups(in.fds.begin() + 3, in.fds.end() - 1);
        void* ram = runtime::fork_ipc::map_snapshot(in.memory, in.mem_size);
        zmark("mapped");
        runtime::HvfTrap::ForkImage img;
        if (!ram || !machine.init_from(ram, in.mem_size) || !runtime::wire::decode(in.blob, img)) {
            std::fputs("linuxity: zygote handoff failed\n", stderr);
            return 127;
        }
        zmark("vm");
        m.k.import_fork(img.namespace_state);
        runtime::g_pending.reset_for_fork_child();
        runtime::PidSpace pids{pid_fd};
        zmark("vcpu");
        runtime::ProcessState proc;
        runtime::TaskState task;
        runtime::HvfTrap trap{machine, cpu, proc, task, pids};
        attach_live_procs(m, pids);
        trap.resume_fork_child(img, groups);
        zmark("resumed");
        run(o, m, machine, cpu, proc, task, pids, trap);
    }

    return -1;
}

int cli::host_run(Options& o, int, char**) {
    // The guest's pid 1 leads its own process group -- the guest believes it
    // does (an unset pgid is the pid itself), and bash hands the terminal
    // back to that group after every job with tcsetpgrp(getpgrp()). When
    // linuxity was started by something else that shares the terminal (the
    // `linuxity shell` CLI, a script, sudo), this process was a mere MEMBER
    // of the launcher's group: the hand-back named a group that doesn't
    // exist on the host (EINVAL), the terminal stayed with the finished
    // job, the shell's next read was EIO, and it logged out on its own.
    // So make the host agree, before any zygote inherits the old group,
    // and take the terminal's foreground if we were in it. SIGTTOU is held
    // off for the hand-over, as a job-control shell does.
    if (::getpgrp() != ::getpid()) {
        const int tty = ::isatty(0) ? 0 : -1;
        const bool was_fg = tty >= 0 && ::tcgetpgrp(tty) == ::getpgrp();
        if (::setpgid(0, 0) == 0 && was_fg) {
            sigset_t ttou, old;
            sigemptyset(&ttou); sigaddset(&ttou, SIGTTOU);
            ::pthread_sigmask(SIG_BLOCK, &ttou, &old);
            (void)::tcsetpgrp(tty, ::getpgrp());
            ::pthread_sigmask(SIG_SETMASK, &old, nullptr);
        }
    }
    process_start();
    if (o.instance) {
        // The CLI never asks for one here (host_runs_instances); a direct
        // `linuxity up` on a Mac lands here.
        std::fputs("linuxity: environments run in the foreground on macOS: "
                   "`linuxity shell` or `linuxity run` (no `up` needed)\n", stderr);
        return 2;
    }
    if (o.root.empty()) {
        // A Mac can't run Linux programs from its own disk: there has to be
        // a distro to run them in.
        std::fprintf(stderr,
            "linuxity: '%s' needs a Linux environment to run in, and you don't have one yet:\n"
            "  linuxity new alpine        a 4 MB distro; then `linuxity %s` just works\n"
            "  linuxity --root DIR %s     or use an extracted aarch64 rootfs\n",
            o.argv[0].c_str(), o.argv[0].c_str(), o.argv[0].c_str());
        return 2;
    }
    if (!is_dir(o.root)) {
        std::fprintf(stderr, "linuxity: --root %s is not a directory (an extracted aarch64 rootfs)\n",
                     o.root.c_str());
        return 2;
    }

    runtime::HvfMachine machine;
    if (auto st = machine.init(vm_bytes(o)); !st) {
        std::fprintf(stderr,
            "linuxity: cannot create a hypervisor VM. This binary must be signed\n"
            "with the com.apple.security.hypervisor entitlement:\n"
            "  codesign -s - --entitlements hypervisor.entitlements -f %s\n",
            self_exe().c_str());
        return 1;
    }
    // The initial guest thread's vCPU, created on THIS thread because
    // Hypervisor.framework binds a vcpu to its creator.
    runtime::HvfCpu cpu;
    if (auto st = cpu.create(); !st) {
        std::fputs("linuxity: cannot create a vCPU\n", stderr);
        return 1;
    }

    // Who runs, with what environment: the same policy as every host
    // (src/guest_env.hpp) -- the guest's /etc/passwd, --user, -e, its PATH
    // and a locale its libc can load -- not the Mac user's HOME and USER.
    auto ge = cli::guest_env(o);
    if (!ge.error.empty()) {
        std::fprintf(stderr, "linuxity: %s\n", ge.error.c_str());
        return 2;
    }
    if (!ge.notice.empty() && !o.quiet) std::fprintf(stderr, "linuxity: %s\n", ge.notice.c_str());
    std::vector<std::string> env = std::move(ge.vars);
    // Only on macOS: the host's terminfo for this terminal, compiled into a
    // guest-visible directory (see host_terminfo_bridge).
    if (const char* t = std::getenv("TERM"))
        if (auto dir = host_terminfo_bridge(o.root, t); !dir.empty())
            env.push_back("TERMINFO_DIRS=" + dir + ":/usr/share/terminfo");
    (void)::umask(static_cast<mode_t>(o.umask));

    Machine m{o};
    {
        kernel::ProcInfo init;
        init.pid = 1;
        init.ppid = 0;
        const std::string& prog = o.argv[0];
        init.comm = prog.substr(prog.find_last_of('/') + 1);
        for (std::size_t j = 0; j < o.argv.size(); ++j) {
            init.cmdline += o.argv[j];
            if (j + 1 < o.argv.size()) init.cmdline.push_back('\0');   // ProcInfo: NUL-joined
        }
        // pid 1 runs as the login user (the same rule as every host)
        abi::creds::login(init, ge.login.uid, ge.login.gid, ge.login.groups);
        m.k.procs().upsert(init);
    }
    // --cwd / login.cwd: where pid 1 starts (a missing one falls back to /)
    if (!o.cwd.empty()) {
        struct ::stat cst{};
        const std::string h = m.resolve(o.cwd);
        if (!h.empty() && ::stat(h.c_str(), &cst) == 0 && S_ISDIR(cst.st_mode))
            m.k.files().set_cwd(o.cwd);
    }

    const std::vector<std::string>& gargv = o.argv;
    auto ex = runtime::hvf_exec(machine, [&m](const std::string& g) { return m.resolve(g); },
                                gargv[0], gargv, env);
    if (!ex) {
        std::fprintf(stderr, "linuxity: %s: cannot execute (errno %d)\n",
                     gargv[0].c_str(), static_cast<int>(ex.error()));
        return 127;
    }

    runtime::PidSpace pids;
    runtime::ProcessState proc;
    runtime::TaskState task;
    task.tid = 1;                      // the initial thread IS the process
    runtime::HvfTrap trap{machine, cpu, proc, task, pids};
    {
        // /proc/1/exe: the real image, symlinks resolved (as the kernel does).
        std::string exe = gargv[0];
        char real[PATH_MAX];
        if (const std::string h = m.resolve(gargv[0]); !h.empty() && ::realpath(h.c_str(), real))
            exe = m.unresolve(real);
        pids.set_exe(1, exe);
    }
    attach_live_procs(m, pids);
    // Only the ROOT process reserves the low fds: a fork child inherits its
    // parent's whole table (reservations included) through the handoff.
    proc.with_fds([](runtime::FdTable& t) { t.reserve_low_fds(); });
    trap.set_arena(ex->brk_base, runtime::ExecArena::mmap_top(machine.mem_size()));
    for (const auto& sg : ex->segments)
        trap.adopt(sg.begin, sg.end, runtime::prot_from_elf(sg.flags));
    trap.note_image(*ex);
    trap.adopt_stack(ex->sp, machine.mem_size());
    cpu.set_entry(ex->entry, ex->sp);
    run(o, m, machine, cpu, proc, task, pids, trap);
}
