// linuxity -- the one entry point, on every host.
//
//   lx [...] [CMD]                     run things in an environment (cli.cpp)
//   linuxity VERB ...                  manage environments (cli.cpp)
//   linuxity --root DIR [FLAGS] PROG   the engine on its own (here)
//
// `lx` is the same binary under another name (a symlink); argv[0] picks the
// front door. Re-runs of ourselves use hidden verbs: `__up ENV` runs an
// instance, `__run ENV FLAGS -- CMD` a one-off foreground run.
//
// One command line for every host: one flag parser, one usage text, one set
// of verbs, one Options. What differs per host is only how the guest runs --
// ptrace+seccomp on Linux, Hypervisor.framework on macOS, WHP on Windows --
// and that is host_run() in src/run_<host>.cpp (see host_run.hpp).
#include "host_run.hpp"
#include "options.hpp"
#include "verbs.hpp"

#include "linuxity/kernel/resolver.hpp"
#include "linuxity/kernel/resources.hpp"

#if !defined(_WIN32)
#include "linuxity/env/config.hpp"
#include "linuxity/env/passwd.hpp"
#include "linuxity/env/status.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/host/tmpdir.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
int lx_cli_main(int argc, char** argv);   // cli.cpp: the linuxity verbs
int lx_main(int argc, char** argv);       // cli.cpp: lx
#endif

namespace {

using lx::cli::Options;

void usage(const char* argv0) {
    std::fprintf(stderr,
        "The engine on its own: one program, no environment.\n"
        "\n"
        "usage: %s [OPTIONS] <program> [args...]\n"
#if !defined(_WIN32)
        "       (environments: lx, and `linuxity help`)\n"
#endif
        "\n"
        "  Runs a native Linux binary; its syscalls are serviced by the\n"
        "  linuxity runtime (native speed, no emulation). Host: %s.\n"
        "\n"
#if !defined(_WIN32)
        "  --env <name>        take every setting from that environment's env.vibe\n"
#endif
        "  --root <dir>        mount an extracted distro rootfs as guest '/'\n"
        "  --persist <dir>     keep the writable upper layer in <dir>, so writes persist\n"
        "                      across runs (default: ephemeral per-run)\n"
        "  --shared-tmp        share the host's /tmp (default: private)\n"
        "  --no-pacman-overwrite  don't auto-pass pacman --overwrite \"*\"\n"
        "  --cpus <N>          bound CPU to N cores' worth (e.g. 1.5)\n"
        "  --memory <SZ>       memory ceiling, or the VM's RAM on macOS/Windows\n"
        "                      (e.g. 512M, 2G; a bare number is MiB there)\n"
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
        "  --verbose           report every syscall the backend cannot serve yet\n"
        "\n"
        "  The resource bounds are enforced by the HOST kernel where it can\n"
        "  (cgroup v2 or setrlimit on Linux) and the guest's /proc, /sys and\n"
        "  sysinfo are derived to MATCH them.\n",
        argv0,
        lx::cli::host_name());
}

#if !defined(_WIN32)
// Load an environment's config into `o`. Returns false (having printed why).
bool load_env(const std::string& name, Options& o) {
    lx::env::Store store;
    if (std::string why; !store.ensure_storage(false, why))
        std::fprintf(stderr, "linuxity: %s\n", why.c_str());
    if (!store.has(name)) {
        std::fprintf(stderr, "linuxity: no environment '%s' (see `linuxity ls`)\n", name.c_str());
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
#endif

// --memory: a size with a unit, or (a bare number) MiB -- what the VM hosts
// always took, and too small to mean bytes as a ceiling anyway.
[[nodiscard]] std::optional<std::uint64_t> memory_arg(std::string_view s) {
    if (!s.empty() && s.find_first_not_of("0123456789") == std::string_view::npos) {
        const auto v = lx::kernel::parse_bytes(s);
        return v ? std::optional{*v << 20} : std::nullopt;
    }
    return lx::kernel::parse_bytes(s);
}

// Parse leading flags into `o`. Returns the index of the first non-flag, or
// -1 on a bad flag (already reported). THE flag parser: every host, every
// verb that takes run flags, and every re-exec of linuxity by itself.
int parse_flags(int argc, char** argv, int i, Options& o) {
    using namespace lx;
    auto need = [&](const char* what) -> const char* {
        if (i + 1 >= argc) {
            std::fprintf(stderr, "linuxity: %s needs an argument\n", what);
            std::exit(2);
        }
        o.flags.emplace_back(argv[i + 1]);
        return argv[++i];
    };
    for (; i < argc; ++i) {
        const std::string f = argv[i];
        if (f == "--") { ++i; break; }
        if (f.size() > 1 && f[0] == '-') o.flags.push_back(f);
#if !defined(_WIN32)
        if (f == "--env") { if (!load_env(need("--env"), o)) return -1; }
        else
#endif
        if (f == "--root") { o.root = need("--root"); }
        else if (f == "--persist" || f == "--upper") { o.persist = need("--persist"); }
        else if (f == "--no-pacman-overwrite") { o.pacman_overwrite = false; }
        else if (f == "--pacman-overwrite")    { o.pacman_overwrite = true; }
        else if (f == "--shared-tmp")  { o.private_tmp = false; }
        else if (f == "--private-tmp") { o.private_tmp = true; }
        else if (f == "--cpus")        { o.res.cpus = std::atof(need("--cpus")); }
        else if (f == "--memory" || f == "-m") {
            if (auto b = memory_arg(need("--memory"))) o.res.mem_max = *b;
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
        else if (f == "--verbose") { o.verbose = true; }
        else if (f == "--foreground") { /* handled by `up` */ }
        else if (f == "-h" || f == "--help") { usage(argv[0]); std::exit(0); }
        else if (f.size() > 1 && f[0] == '-' && f != "-") {
            o.flags.pop_back();
            return i;    // not a run flag: a host's internal mode, or an error
        }
        else break;   // first non-flag: the program
    }
    return i;
}

void setup_status(const Options& o) {
#if !defined(_WIN32)
    auto& st = lx::env::status();
    st.set_quiet(o.quiet);
    if (o.status_fd >= 0 && ::fcntl(o.status_fd, F_GETFD) >= 0) {
        (void)::fcntl(o.status_fd, F_SETFD, FD_CLOEXEC);   // never leak into guests
        st.set_fd(o.status_fd);
    }
#else
    (void)o;
#endif
}

#if !defined(_WIN32)
// `__up ENV`: run the instance. In the background unless
// --foreground; the launcher returns once the control socket is live.
int cmd_up(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: linuxity __up ENV [--foreground] [--status-fd N]\n"); return 2; }
    Options o;
    o.flags = {"--env", argv[2]};
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
        return lx::cli::host_run(o, argc, argv);
    }

    // Background: fork, detach, log to the env's log. The child writes a
    // byte to `ready` once it listens (or closes it on failure), so the
    // parent waits for exactly that and no longer.
    int ready[2];
    if (::pipe(ready) != 0) { std::perror("linuxity: pipe"); return 1; }
    for (const int fd : ready) (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
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
        std::_Exit(lx::cli::host_run(o, argc, argv));
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

// `__run ENV [--fresh] [flags] [-- program...]`: one program as pid 1 with
// the environment's settings (the user's login shell if none is given).
int cmd_run(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: linuxity __run ENV [--fresh] [-v host:guest] [-e K=V] [-- program args...]\n"); return 2; }
    Options o;
    o.flags = {"--env", argv[2]};
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
        o.flags.insert(o.flags.end(), {"--persist", scratch});
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
        o.flags.insert(o.flags.end(), {"--user", "root"});
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
    const int rc = lx::cli::host_run(o, orig_argc, orig_argv);
    if (!scratch.empty()) (void)lx::env::remove_tree(scratch);
    return rc;
}

int with_args(int (*fn)(int, char**), std::vector<std::string> a) {
    std::vector<char*> av;
    for (auto& x : a) av.push_back(x.data());
    av.push_back(nullptr);
    return fn(static_cast<int>(a.size()), av.data());
}

// Called as `lx` (or lx.exe): argv[0]'s last part, without a suffix.
bool called_as_lx(const char* argv0) {
    std::string_view n = argv0;
    if (const auto s = n.find_last_of('/'); s != std::string_view::npos) n.remove_prefix(s + 1);
    return n == "lx";
}
#endif

}  // namespace

int main(int argc, char** argv) {
#if !defined(_WIN32)
    if (called_as_lx(argv[0])) return lx_main(argc, argv);
    if (argc < 2) return lx_cli_main(argc, argv);
    const std::string_view sub = argv[1];
    if (sub == "help" && argc > 2 && std::string_view{argv[2]} == "--all") { usage(argv[0]); return 0; }
    // our own re-runs: an instance, a one-off run
    if (sub == "__up") return cmd_up(argc, argv);
    if (sub == "__run") return cmd_run(argc, argv);
    // `linuxity lx ...` works where there's no lx symlink
    if (sub == "lx") {
        std::vector<std::string> a(argv + 1, argv + argc);
        return with_args(lx_main, a);
    }
    // a flag or a path starts the engine on its own (linuxity --root DIR PROG,
    // linuxity /bin/sh); a plain word is a verb. Verbs never contain '/'.
    if (!sub.empty() && sub[0] != '-' && sub.find('/') == std::string_view::npos) return lx_cli_main(argc, argv);
#endif
    // anything else: run one program, as linuxity always has
    Options o;
    const int i = parse_flags(argc, argv, 1, o);
    if (i < 0) return 2;
    // a host's private re-entry (macOS fork child / zygote, Windows --check)
    if (i < argc && argv[i][0] == '-' && argv[i][1] != '\0') {
        if (const int rc = lx::cli::host_internal(o, argc, argv, i); rc >= 0) return rc;
        std::fprintf(stderr, "linuxity: unknown option '%s'\n", argv[i]);
        return 2;
    }
    if (i >= argc) { usage(argv[0]); return 2; }
    for (int j = i; j < argc; ++j) o.argv.emplace_back(argv[j]);
    setup_status(o);
    return lx::cli::host_run(o, argc, argv);
}
