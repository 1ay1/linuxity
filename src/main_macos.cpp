// src/main_macos.cpp
//
// linuxity on macOS: run a Linux aarch64 distro's programs natively on Apple
// Silicon, with no VM kernel, no Docker, and no root.
//
//     linuxity --root ~/arch /usr/bin/bash
//
// The program's instructions execute bare on the M-series CPU inside a
// kernel-less Hypervisor.framework VM; every syscall traps back here and is
// serviced by the SAME portable core (kernel/, vfs/, abi/) that the Linux
// ptrace build uses. This file is wiring: options, the namespace, exec, and
// the process-tree plumbing that guest fork() needs on this OS.
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/hvf_exec.hpp"
#include "linuxity/runtime/hvf_fork.hpp"
#include "linuxity/runtime/hvf_trap.hpp"
#include "linuxity/runtime/hvf_wire.hpp"
#include "linuxity/runtime/trap.hpp"
#include "linuxity/vfs/devfs.hpp"
#include "linuxity/vfs/procfs.hpp"
#include "linuxity/vfs/sysfs.hpp"

#include <execinfo.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <mutex>
#include <thread>
#include <sys/sysctl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

extern char** environ;

using namespace lx;

namespace {

void usage() {
    std::fputs(
        "usage: linuxity [--root DIR] [--persist DIR] [--bind HOST[:GUEST]]...\n"
        "                [--memory MiB] PROGRAM [ARGS...]\n"
        "\n"
        "Run a Linux aarch64 program natively on this Mac.\n"
        "\n"
        "  --root DIR     an extracted distro rootfs to use as the guest '/'\n"
        "  --persist DIR  keep guest writes here across runs (installs, config).\n"
        "                 Without it, writes go to a per-run scratch dir and\n"
        "                 are discarded. Either way the rootfs stays pristine.\n"
        "  --bind H[:G]   expose host directory H at guest path G (default H)\n"
        "  --memory MiB   guest RAM (default 2048)\n"
        "\n"
        "Get a rootfs:\n"
        "  mkdir ~/arch && curl -L \\\n"
        "    http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz \\\n"
        "    | tar xz -C ~/arch\n",
        stderr);
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

// -- Options -----------------------------------------------------------------
// Parsed once by the root process and forwarded VERBATIM to every fork
// child, which rebuilds an identical namespace from them. Keeping the
// configuration as "the argv that produced it" is what makes that trivially
// correct: there is no second representation to keep in sync.
struct Options {
    std::string root;
    std::string persist;             // --persist DIR: a durable upper layer
    std::vector<std::pair<std::string, std::string>> binds;
    std::uint64_t mem_mib = 2048;
    std::vector<std::string> raw;     // exactly the option tokens we consumed
};

[[nodiscard]] int parse(int argc, char** argv, Options& o) {
    int i = 1;
    for (; i < argc; ++i) {
        std::string_view a = argv[i];
        auto need = [&]() -> const char* {
            if (i + 1 >= argc) { usage(); std::exit(2); }
            o.raw.emplace_back(argv[i]);
            o.raw.emplace_back(argv[i + 1]);
            return argv[++i];
        };
        if (a == "--root") o.root = need();
        else if (a == "--persist") o.persist = need();
        else if (a == "--bind") {
            std::string spec = need();
            auto colon = spec.find(':');
            o.binds.emplace_back(spec.substr(0, colon),
                                 colon == std::string::npos ? spec : spec.substr(colon + 1));
        }
        else if (a == "--memory") o.mem_mib = std::strtoull(need(), nullptr, 10);
        else if (a == "-h" || a == "--help") { usage(); std::exit(0); }
        else if (a == "--fork-child") break;      // internal: see main()
        else if (a.starts_with("--")) {
            std::fprintf(stderr, "linuxity: unknown option %s\n", argv[i]);
            usage();
            std::exit(2);
        }
        else break;
    }
    return i;
}

// -- The guest "machine": kernel + namespace ----------------------------------
struct Machine {
    host::PosixHost hw;
    kernel::Kernel<host::PosixHost> k{hw};

    explicit Machine(const Options& o) {
        kernel::MachineSpec spec;
        const long n = ::sysconf(_SC_NPROCESSORS_ONLN);
        spec.ncpu = n > 0 ? n : 1;
        spec.mem_total = o.mem_mib << 20;
        spec.release = "6.6.0-linuxity";
        spec.nodename = "linuxity";
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
        k.files().mount_virtual("/dev", vfs::make_devfs());
        for (auto& [host_dir, guest_at] : o.binds)
            k.files().mount_host(kernel::FileNamespace::normalize(guest_at), host_dir);
        // The terminal we were started on, at its real device name (e.g.
        // /dev/ttys003). glibc's ttyname() -- behind `tty`, ssh, sudo and
        // every program that prints "not a tty" -- readlinks /proc/self/fd/0
        // and then requires stat(that path) to be the same device as
        // fstat(0). Binding the device at its own name makes that true.
        for (int fd = 0; fd < 3; ++fd)
            if (const char* n = ::isatty(fd) ? ::ttyname(fd) : nullptr)
                k.files().mount_host(n, n);
        k.files().mount_host("/dev/tty", "/dev/tty");
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

[[nodiscard]] std::string self_exe() {
    char buf[4096];
    std::uint32_t n = sizeof buf;
    return ::_NSGetExecutablePath(buf, &n) == 0 ? std::string{buf} : std::string{};
}

// -- Fork, parent side ---------------------------------------------------------
// Spawn a fresh linuxity in --fork-child mode and hand it the guest. The
// child's guest fds arrive at host fds 3.. (one per distinct open file), and
// the pid table's fd rides along too. stdio stays where it is: the child
// inherits 0/1/2 just as a forked process would.
class Forker {
public:
    Forker(const Options& o, Machine& m, runtime::HvfMachine& machine, runtime::PidSpace& pids)
        : opts_{o}, machine_wrap_{m}, machine_{machine}, pids_{pids} {}

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
            img.namespace_state = machine_wrap_.k.files().export_process_state();
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
        ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);
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
        args.insert(args.end(), opts_.raw.begin(), opts_.raw.end());
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
        const int rc = ::posix_spawn(&pid, args[0].c_str(), &fa, &attr, av.data(), environ);
        ::posix_spawn_file_actions_destroy(&fa);
        ::posix_spawnattr_destroy(&attr);
        mark("spawned");
        if (rc != 0) { ::mach_port_deallocate(::mach_task_self(), svc); return -1; }

        // Wait for the child's hello (it carries the child's reply port),
        // then ship RAM + state. The child cannot run guest code until this
        // arrives, so the snapshot is exactly the guest at the fork point.
        //
        // BOUNDED: if the child dies before saying hello (bad exec path,
        // signing problem), an unbounded receive would hang this guest
        // process -- and the user's whole shell -- forever.
        struct { mach_msg_header_t h; mach_msg_trailer_t t; } hello{};
        constexpr mach_msg_timeout_t kHelloTimeoutMs = 10'000;
        const auto got = ::mach_msg(&hello.h, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
                                    sizeof hello, svc, kHelloTimeoutMs, MACH_PORT_NULL);
        if (got != MACH_MSG_SUCCESS) {
            ::mach_port_mod_refs(::mach_task_self(), svc, MACH_PORT_RIGHT_RECEIVE, -1);
            ::kill(pid, SIGKILL);
            int st = 0;
            ::waitpid(pid, &st, 0);
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
    mach_port_t parent = MACH_PORT_NULL;
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
    if (!runtime::fork_ipc::receive(reply, in)) return false;
    void* ram = runtime::fork_ipc::map_snapshot(in.memory, in.mem_size);
    if (!ram || !vm.init_from(ram, in.mem_size)) return false;
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
[[nodiscard]] int run(const Options& o, Machine& m, runtime::HvfMachine& machine,
                      runtime::HvfCpu& cpu, runtime::ProcessState& proc,
                      runtime::TaskState& task, runtime::PidSpace& pids,
                      runtime::HvfTrap& trap) {
    runtime::HvfMem mem{machine, &trap};
    Forker forker{o, m, machine, pids};
    std::vector<std::thread> threads;
    std::mutex threads_mu;
    ThreadContext ctx{o, m, machine, proc, pids, forker, threads, threads_mu};
    wire_spawners(trap, ctx);

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
    proc.request_group_exit(rc ? *rc : 1);
    std::fflush(nullptr);
    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", static_cast<int>(rc.error()));
        ::_exit(1);
    }
    ::_exit(*rc);
}

}  // namespace

namespace {
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
    };
    static Live live{pids};
    m.k.procs().set_live_source(&live);
}
}  // namespace

int main(int argc, char** argv) {
    if (std::getenv("LINUXITY_DEBUG")) {
        ::signal(SIGSEGV, crash_handler);
        ::signal(SIGBUS, crash_handler);
    }

    Options o;
    int i = parse(argc, argv, o);

    // -- Fork child: `--fork-child SERVICE PIDFD GROUPFDS` follows the options.
    if (i + 3 < argc && std::string_view{argv[i]} == "--fork-child") {
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
        Machine m{o};
        runtime::HvfMachine machine;
        runtime::HvfTrap::ForkImage img;
        const auto c0 = std::chrono::steady_clock::now();
        const bool prof = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
        auto cmark = [&](const char* what) {
            if (!prof) return;
            std::fprintf(stderr, "[child %d] %-10s %7lld us\n", ::getpid(), what,
                         static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now() - c0).count()));
        };
        if (!receive_fork(ca, machine, img)) {
            std::fputs("linuxity: fork handoff failed\n", stderr);
            return 127;
        }
        cmark("vm-up");
        m.k.files().import_process_state(img.namespace_state);
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
        return run(o, m, machine, cpu, proc, task, pids, trap);
    }

    if (i >= argc) { usage(); return 2; }
    if (o.root.empty() || !is_dir(o.root)) {
        std::fputs("linuxity: --root must name an extracted aarch64 rootfs\n", stderr);
        return 2;
    }

    runtime::HvfMachine machine;
    if (auto st = machine.init(o.mem_mib << 20); !st) {
        std::fprintf(stderr,
            "linuxity: cannot create a hypervisor VM. This binary must be signed\n"
            "with the com.apple.security.hypervisor entitlement:\n"
            "  codesign -s - --entitlements hypervisor.entitlements -f %s\n",
            argv[0]);
        return 1;
    }
    // The initial guest thread's vCPU, created on THIS thread because
    // Hypervisor.framework binds a vcpu to its creator.
    runtime::HvfCpu cpu;
    if (auto st = cpu.create(); !st) {
        std::fputs("linuxity: cannot create a vCPU\n", stderr);
        return 1;
    }

    Machine m{o};
    {
        kernel::ProcInfo init;
        init.pid = 1;
        init.ppid = 0;
        const std::string prog = argv[i];
        init.comm = prog.substr(prog.find_last_of('/') + 1);
        for (int j = i; j < argc; ++j) {
            init.cmdline += argv[j];
            if (j + 1 < argc) init.cmdline.push_back(' ');
        }
        m.k.procs().upsert(init);
    }

    // A root login in the guest's own world, not the Mac user's (whose
    // HOME/USER don't exist in the rootfs).
    std::vector<std::string> env = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin",
        "HOME=/root", "USER=root", "LOGNAME=root", "SHELL=/bin/bash",
        "LANG=C.UTF-8",
    };
    if (const char* t = std::getenv("TERM")) {
        env.push_back(std::string{"TERM="} + t);
        if (auto dir = host_terminfo_bridge(o.root, t); !dir.empty())
            env.push_back("TERMINFO_DIRS=" + dir + ":/usr/share/terminfo");
    }
    for (const char* keep : {"COLORTERM", "TERM_PROGRAM", "KITTY_WINDOW_ID"})
        if (const char* v = std::getenv(keep)) env.push_back(std::string{keep} + "=" + v);

    std::vector<std::string> gargv(argv + i, argv + argc);
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
    trap.adopt_stack(ex->sp, machine.mem_size());
    cpu.set_entry(ex->entry, ex->sp);
    return run(o, m, machine, cpu, proc, task, pids, trap);
}
