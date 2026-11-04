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
        "usage: linuxity [--root DIR] [--bind HOST[:GUEST]]... [--memory MiB]\n"
        "                PROGRAM [ARGS...]\n"
        "\n"
        "Run a Linux aarch64 program natively on this Mac.\n"
        "\n"
        "  --root DIR     an extracted distro rootfs to use as the guest '/'\n"
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
        k.set_machine(std::move(spec));
        k.files().mount_host("/", o.root);
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
    }

    // host path -> guest path: the inverse of resolve() for the rootfs.
    [[nodiscard]] std::string unresolve(const std::string& host) const {
        if (host.size() > root_.size() && host.starts_with(root_) && host[root_.size()] == '/')
            return host.substr(root_.size());
        return host;
    }
    std::string root_;

    [[nodiscard]] std::string resolve(const std::string& guest) {
        auto pc = k.files().classify(k.files().absolutize(guest));
        return pc.realm == kernel::Realm2::host_backed ? pc.host_path : std::string{};
    }
};

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
    Forker(const Options& o, Machine& m, runtime::HvfVm& vm, runtime::PidSpace& pids)
        : opts_{o}, machine_{m}, vm_{vm}, pids_{pids} {}

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
        img.namespace_state = machine_.k.files().export_process_state();

        // One host fd per distinct open file, placed at 3, 4, 5... in the child.
        //
        // posix_spawn applies file actions IN ORDER, so a naive sequence of
        // dup2(src_i, 3+i) is wrong whenever some later src_j happens to be
        // a number an earlier dup2 already overwrote: src_j then names the
        // wrong file. Classic parallel-assignment hazard. Fix: first dup
        // every source to a private HIGH number in the parent (above any
        // target), then dup2 from those. No high fd can be a target, so no
        // action can clobber another's source.
        int max_group = -1;
        for (const auto& e : img.fds) max_group = std::max(max_group, e.group);
        posix_spawn_file_actions_t fa;
        ::posix_spawn_file_actions_init(&fa);
        std::vector<int> placed(static_cast<std::size_t>(max_group + 1), -1);
        std::vector<int> staged;                     // high copies, closed after spawn
        const int targets = static_cast<int>(placed.size()) + 1;   // + the pid table
        const int high_floor = 3 + targets + 64;
        auto stage = [&](int src) {
            const int h = ::fcntl(src, F_DUPFD_CLOEXEC, high_floor);
            staged.push_back(h);
            return h;
        };
        int next = 3;
        for (const auto& e : img.fds) {
            auto gi = static_cast<std::size_t>(e.group);
            if (placed[gi] >= 0) continue;
            placed[gi] = next;
            ::posix_spawn_file_actions_adddup2(&fa, stage(e.host), next);
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
        const mach_port_t mem = runtime::fork_ipc::snapshot(vm_.raw_base(), vm_.mem_size());
        mark("snapshot");
        const bool sent = runtime::fork_ipc::send(hello.h.msgh_remote_port, mem,
                                                  vm_.mem_size(), runtime::wire::encode(img));
        mark("sent");
        ::mach_port_mod_refs(::mach_task_self(), svc, MACH_PORT_RIGHT_RECEIVE, -1);
        return sent ? pid : -1;
    }

private:
    const Options& opts_;
    Machine& machine_;
    runtime::HvfVm& vm_;
    runtime::PidSpace& pids_;
};

// -- Fork, child side ------------------------------------------------------------
struct ChildArgs {
    std::string service;
    int pid_fd{-1};
    std::vector<int> group_fds;
};

[[nodiscard]] bool receive_fork(const ChildArgs& ca, runtime::HvfVm& vm,
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

// -- Run a guest to completion (shared by root and fork children) ---------------
[[nodiscard]] int run(const Options& o, Machine& m, runtime::HvfVm& vm,
                      runtime::PidSpace& pids, runtime::HvfTrap& trap) {
    runtime::HvfMem mem{vm, &trap};
    Forker forker{o, m, vm, pids};
    trap.set_resolver([&m](const std::string& g) { return m.resolve(g); });
    trap.set_unresolver([&m](const std::string& h) { return m.unresolve(h); });
    trap.set_fork_spawner([&forker](runtime::HvfTrap::ForkImage& img) { return forker(img); });

    runtime::Cpu cpu{trap, m.k, mem, abi::Arch::aarch64};
    // The root enters at the image entry; a fork child is already positioned
    // (its PC/SP came from the parent), so it starts with entry 0 = "as is".
    auto rc = cpu.run(uaddr(0), uaddr(0));
    if (!rc) {
        std::fprintf(stderr, "linuxity: runtime error %d\n", static_cast<int>(rc.error()));
        return 1;
    }
    return *rc;
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
        runtime::HvfVm vm;
        runtime::HvfTrap::ForkImage img;
        const auto c0 = std::chrono::steady_clock::now();
        const bool prof = std::getenv("LINUXITY_PROFILE_FORK") != nullptr;
        auto cmark = [&](const char* what) {
            if (!prof) return;
            std::fprintf(stderr, "[child %d] %-10s %7lld us\n", ::getpid(), what,
                         static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(
                             std::chrono::steady_clock::now() - c0).count()));
        };
        if (!receive_fork(ca, vm, img)) {
            std::fputs("linuxity: fork handoff failed\n", stderr);
            return 127;
        }
        cmark("vm-up");
        m.k.files().import_process_state(img.namespace_state);
        runtime::PidSpace pids{ca.pid_fd};
        runtime::HvfTrap trap{vm, pids};
        trap.resume_fork_child(img, ca.group_fds);
        return run(o, m, vm, pids, trap);
    }

    if (i >= argc) { usage(); return 2; }
    if (o.root.empty() || !is_dir(o.root)) {
        std::fputs("linuxity: --root must name an extracted aarch64 rootfs\n", stderr);
        return 2;
    }

    runtime::HvfVm vm;
    if (auto st = vm.init(o.mem_mib << 20); !st) {
        std::fprintf(stderr,
            "linuxity: cannot create a hypervisor VM. This binary must be signed\n"
            "with the com.apple.security.hypervisor entitlement:\n"
            "  codesign -s - --entitlements hypervisor.entitlements -f %s\n",
            argv[0]);
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
    if (const char* t = std::getenv("TERM")) env.push_back(std::string{"TERM="} + t);

    std::vector<std::string> gargv(argv + i, argv + argc);
    auto ex = runtime::hvf_exec(vm, [&m](const std::string& g) { return m.resolve(g); },
                                gargv[0], gargv, env);
    if (!ex) {
        std::fprintf(stderr, "linuxity: %s: cannot execute (errno %d)\n",
                     gargv[0].c_str(), static_cast<int>(ex.error()));
        return 127;
    }

    runtime::PidSpace pids;
    runtime::HvfTrap trap{vm, pids};
    trap.set_arena(ex->brk_base, runtime::ExecArena::mmap_top(vm.mem_size()));
    for (const auto& sg : ex->segments)
        trap.adopt(sg.begin, sg.end, runtime::prot_from_elf(sg.flags));
    trap.adopt_stack(ex->sp, vm.mem_size());
    vm.set_entry(ex->entry, ex->sp);
    return run(o, m, vm, pids, trap);
}
