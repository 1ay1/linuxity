// src/cli.cpp -- the commands that don't run a guest themselves:
//
//   linuxity env ...            manage environments (env.vibe, upper, snapshots)
//   linuxity shell <env>        a login shell in a running instance
//   linuxity exec <env> -- cmd  run a command there
//   linuxity ps|kill|status|svc|logs|reload|down <env>
//
// shell/exec start the instance if it isn't running. Everything here talks
// to the instance through its control socket (env/control.hpp); no kernel
// headers, so this file builds fast.
#include "linuxity/env/archive.hpp"
#include "linuxity/env/catalog.hpp"
#include "linuxity/env/config.hpp"
#include "linuxity/env/control.hpp"
#include "linuxity/env/digest.hpp"
#include "linuxity/env/json.hpp"
#include "linuxity/env/json_read.hpp"
#include "linuxity/env/passwd.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/env/vibe_edit.hpp"
#include "linuxity/host/self_exe.hpp"
#include "linuxity/kernel/meta_store.hpp"

#include "host_run.hpp"
#include "verbs.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/inotify.h>
#else
#include <sys/event.h>
#endif

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace lx::env;

// -- Terminal style: one place decides whether we colour ------------------
// Only on a terminal, never under NO_COLOR (no-color.org) or TERM=dumb.
bool styled(int fd) {
    static const bool off = [] {
        const char* nc = std::getenv("NO_COLOR");
        const char* t = std::getenv("TERM");
        return (nc && *nc) || (t && std::string_view{t} == "dumb");
    }();
    return !off && ::isatty(fd);
}
std::string paint(int fd, const char* sgr, std::string_view s) {
    if (!styled(fd)) return std::string{s};
    return std::string{"\033["} + sgr + "m" + std::string{s} + "\033[0m";
}
std::string bold(std::string_view s)  { return paint(1, "1", s); }
std::string dim(std::string_view s)   { return paint(1, "2", s); }
std::string green(std::string_view s) { return paint(1, "32", s); }

int fail(const std::string& why) {
    std::fprintf(stderr, "%s %s\n", paint(2, "1;31", "linuxity:").c_str(), why.c_str());
    return 1;
}

bool has_flag(int argc, char** argv, std::string_view f) {
    for (int i = 0; i < argc; ++i) if (f == argv[i]) return true;
    return false;
}

using lx::host::self_exe;

// Help, from the verb table (src/verbs.hpp): grouped, aligned, and only
// what this host can do.
void help() {
    using namespace lx::cli;
    const bool bg = host_runs_instances();
    std::printf("%s\n\n", bold("linuxity: Linux, without a VM.").c_str());
    std::printf("  %-34s %s\n", "linuxity", dim("a shell in your default environment").c_str());
    if (!bg) std::printf("  %-34s %s\n", "linuxity CMD [ARGS...]", dim("run CMD in it (e.g. linuxity uname -a)").c_str());
    static constexpr std::pair<VerbGroup, const char*> kGroups[] = {
        {VerbGroup::environments, "Environments"}, {VerbGroup::use, "Using one"},
        {VerbGroup::running, "In the background"}, {VerbGroup::settings, "Settings and users"},
        {VerbGroup::state, "Snapshots"}, {VerbGroup::other, "Other"}};
    for (const auto& [g, title] : kGroups) {
        bool any = false;
        for (const auto& v : kVerbTable) {
            if (v.group != g || !verb_listed(v, bg)) continue;
            if (!any) { std::printf("\n%s\n", bold(title).c_str()); any = true; }
            std::printf("  linuxity %-25s %s\n", std::string{v.usage}.c_str(), dim(v.summary).c_str());
        }
    }
    std::puts(
        "\n"
        "ENV can be left out when you have a default (the first env you make is).\n"
        "Run one program without an environment: linuxity --root DIR PROGRAM  (linuxity help --all).\n"
        "Environments live in $LINUXITY_HOME (default ~/.local/share/linuxity).");
}

// `linuxity help VERB`: that verb's line, and what it stands for.
int help_verb(std::string_view name) {
    using namespace lx::cli;
    const Verb* v = canonical_verb(name);
    if (!v || v->usage.empty()) return fail("no command '" + std::string{name} + "' (linuxity help)");
    std::printf("linuxity %s\n    %s\n", std::string{v->usage}.c_str(), std::string{v->summary}.c_str());
    if (v->instances_only && !host_runs_instances())
        std::printf("    (needs background environments, which %s doesn't have)\n", host_name());
    return 0;
}

// ---- talking to an instance ------------------------------------------------

struct Conn {
    int fd{-1};
    control::LineReader in;
    // Set instead of fd where this host runs no background instances: a
    // session is then a foreground run of this environment (run_session).
    std::string foreground_env;
    ~Conn() { if (fd >= 0) ::close(fd); }
};

std::optional<JValue> request(Conn& c, const std::string& line, const std::vector<int>& fds = {}) {
    if (!control::send_line(c.fd, line, fds)) return std::nullopt;
    std::string reply;
    if (!c.in.read_line(reply)) return std::nullopt;
    return parse_json(reply);
}

bool connect_env(const std::string& name, Conn& c) {
    Store s;
    if (!s.has(name)) { fail("no environment '" + name + "'"); return false; }
    c.fd = control::connect_to(s.socket_path(name));
    if (c.fd < 0) return false;
    c.in.reset(c.fd);
    return true;
}

// Somewhere to run a session in `name`: its live instance (started as
// `linuxity up` if need be), or -- on a host without background instances
// -- a foreground run of it. Every session verb goes through here.
bool ensure_up(const std::string& name, Conn& c) {
    if (!lx::cli::host_runs_instances()) {
        if (!Store{}.has(name)) { fail("no environment '" + name + "'"); return false; }
        c.foreground_env = name;
        return true;
    }
    if (connect_env(name, c)) return true;
    Store s;
    if (!s.has(name)) return false;
    const std::string exe = self_exe();
    const ::pid_t pid = ::fork();
    if (pid < 0) { fail("fork failed"); return false; }
    if (pid == 0) {
        ::execl(exe.c_str(), exe.c_str(), "up", name.c_str(), "--quiet", static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return false;
    return connect_env(name, c);
}

bool need_running(const std::string& name, Conn& c) {
    if (connect_env(name, c)) return true;
    if (!Store{}.has(name)) return false;
    if (!lx::cli::host_runs_instances())
        fail("on " + std::string{lx::cli::host_name()} + ", " + name +
             " runs only while a `linuxity shell` or `exec` is open, so there is "
             "no live instance to ask");
    else
        fail(name + " is not running (start it with `linuxity up " + name + "`)");
    return false;
}

int print_reply(const std::optional<JValue>& r) {
    if (!r) return fail("lost the connection to the instance");
    if (!r->flag("ok")) return fail(r->str("error", "request failed"));
    return 0;
}

// Run `argv` in env `name` as a foreground `linuxity run` of it: the same
// rootfs, upper and settings, its own kernel. What a session IS on a host
// with no background instances (lx::cli::host_runs_instances), and the
// reason the verbs below never ask which kind of host they're on.
int run_foreground(const std::string& name, const std::vector<std::string>& argv,
                   const std::string& user, const std::string& cwd,
                   const std::vector<std::pair<std::string, std::string>>& env,
                   int in_fd, int out_fd) {
    std::vector<std::string> a = {self_exe(), "run", name, "--quiet"};
    if (!user.empty()) a.insert(a.end(), {"--user", user});
    if (!cwd.empty())  a.insert(a.end(), {"--cwd", cwd});
    for (const auto& [k, v] : env) a.insert(a.end(), {"-e", k + "=" + v});
    a.emplace_back("--");
    a.insert(a.end(), argv.begin(), argv.end());
    std::vector<char*> av;
    for (auto& x : a) av.push_back(x.data());
    av.push_back(nullptr);
    const ::pid_t pid = ::fork();
    if (pid < 0) return fail("fork failed");
    if (pid == 0) {
        if (in_fd != 0)  ::dup2(in_fd, 0);
        if (out_fd != 1) ::dup2(out_fd, 1);
        ::execv(av[0], av.data());
        ::_exit(127);
    }
    // The child makes itself a process group and takes the terminal (see
    // host_run). When it's done, take the terminal back for our own group,
    // which the user's shell is waiting on -- otherwise fish/zsh would read
    // from a terminal it no longer owns. SIGTTOU held off, as a shell does.
    const int tty = in_fd == 0 && ::isatty(0) ? 0 : -1;
    const ::pid_t ours = ::getpgrp();
    int st = 0;
    while (::waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (tty >= 0 && ::tcgetpgrp(tty) != ours) {
        sigset_t ttou, old;
        sigemptyset(&ttou); sigaddset(&ttou, SIGTTOU);
        ::sigprocmask(SIG_BLOCK, &ttou, &old);
        (void)::tcsetpgrp(tty, ours);
        ::sigprocmask(SIG_SETMASK, &old, nullptr);
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

// ---- the terminal relay ------------------------------------------------------

struct RawTty {
    bool on{false};
    ::termios saved{};
    void enter() {
        if (::tcgetattr(0, &saved) != 0) return;
        ::termios t = saved;
        ::cfmakeraw(&t);
        if (::tcsetattr(0, TCSANOW, &t) == 0) on = true;
    }
    ~RawTty() { if (on) ::tcsetattr(0, TCSANOW, &saved); }
};

bool write_all(int fd, const char* p, std::size_t n) {
    while (n > 0) {
        const ::ssize_t w = ::write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += w;
        n -= static_cast<std::size_t>(w);
    }
    return true;
}

// Run a session. With a tty, allocate a pty, hand its slave to the
// instance, and relay between it and our terminal (like ssh -t). Without,
// hand over our own 0/1/2 and just wait. Returns the session's exit code.
int run_session(Conn& c, std::vector<std::string> argv, const std::string& user,
                const std::string& cwd, const std::vector<std::pair<std::string, std::string>>& env,
                bool tty, int in_fd = 0, int out_fd = 1) {
    if (!c.foreground_env.empty())
        return run_foreground(c.foreground_env, argv, user, cwd, env, in_fd, out_fd);
    Json j;
    j.obj().kv("op", "spawn").kv("argv", argv).kv("user", user).kv("cwd", cwd).kv("wait", true);
    j.key("env").obj();
    for (const auto& [k, v] : env) j.kv(k, v);
    if (const char* t = std::getenv("TERM")) j.kv("TERM", t);
    if (const char* t = std::getenv("COLORTERM")) j.kv("COLORTERM", t);
    j.end();

    int master = -1;
    std::vector<int> fds;
    if (tty) {
        master = ::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (master < 0 || ::grantpt(master) != 0 || ::unlockpt(master) != 0)
            return fail(std::string{"cannot allocate a pty: "} + std::strerror(errno));
        const char* sn = ::ptsname(master);
        const int slave = sn ? ::open(sn, O_RDWR | O_NOCTTY | O_CLOEXEC) : -1;
        if (slave < 0) return fail("cannot open the pty slave");
        ::winsize ws{};
        if (::ioctl(0, TIOCGWINSZ, &ws) == 0) (void)::ioctl(master, TIOCSWINSZ, &ws);
        ::termios t{};
        if (::tcgetattr(0, &t) == 0) (void)::tcsetattr(slave, TCSANOW, &t);
        fds = {slave};
        j.kv("fds", 1);
        const auto r = request(c, j.end().take(), fds);
        ::close(slave);
        if (print_reply(r)) { ::close(master); return 1; }
    } else {
        fds = {in_fd, out_fd, 2};
        j.kv("fds", 3);
        if (print_reply(request(c, j.end().take(), fds))) return 1;
    }

    // wait for {"event":"exit"}; relay the terminal meanwhile
    RawTty raw;
    if (tty) raw.enter();
    // SIGWINCH -> a byte on a pipe, so poll() sees it with the rest. (The
    // portable self-pipe; signalfd is Linux-only.)
    static int winch_pipe[2] = {-1, -1};
    int sfd = -1;
    if (tty && ::pipe(winch_pipe) == 0) {
        for (const int fd : winch_pipe) {
            (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
            (void)::fcntl(fd, F_SETFL, O_NONBLOCK);
        }
        struct ::sigaction sa{};
        sa.sa_handler = [](int) { const char b = 0; (void)!::write(winch_pipe[1], &b, 1); };
        sa.sa_flags = SA_RESTART;
        ::sigaction(SIGWINCH, &sa, nullptr);
        sfd = winch_pipe[0];
    }
    bool stdin_open = tty;
    int code = 255;
    for (;;) {
        ::pollfd p[4] = {{c.fd, POLLIN, 0}, {master, POLLIN, 0},
                         {stdin_open ? 0 : -1, POLLIN, 0}, {sfd, POLLIN, 0}};
        if (::poll(p, 4, -1) < 0) { if (errno == EINTR) continue; break; }
        if (p[0].revents) {
            if (!c.in.fill()) break;
            std::string line;
            bool done = false;
            while (c.in.next(line)) {
                const auto ev = parse_json(line);
                if (ev && ev->str("event") == "exit") { code = static_cast<int>(ev->num("code")); done = true; }
            }
            if (done) break;
        }
        if (master >= 0 && (p[1].revents & (POLLIN | POLLHUP))) {
            char buf[16384];
            const ::ssize_t n = ::read(master, buf, sizeof buf);
            if (n > 0) write_all(1, buf, static_cast<std::size_t>(n));
            else if (n < 0 && errno == EIO) { ::close(master); master = -1; }   // every slave closed
        }
        if (stdin_open && p[2].revents) {
            char buf[4096];
            const ::ssize_t n = ::read(0, buf, sizeof buf);
            if (n > 0 && master >= 0) write_all(master, buf, static_cast<std::size_t>(n));
            else if (n <= 0) stdin_open = false;
        }
        if (sfd >= 0 && p[3].revents) {
            char drain[64];
            while (::read(sfd, drain, sizeof drain) > 0) {}
            ::winsize ws{};
            if (master >= 0 && ::ioctl(0, TIOCGWINSZ, &ws) == 0) (void)::ioctl(master, TIOCSWINSZ, &ws);
        }
    }
    // the guest may have printed its last bytes just before it exited
    if (master >= 0) {
        (void)::fcntl(master, F_SETFL, O_NONBLOCK);
        char buf[16384];
        ::ssize_t n;
        while ((n = ::read(master, buf, sizeof buf)) > 0) write_all(1, buf, static_cast<std::size_t>(n));
        ::close(master);
    }
    return code;
}

// Shared by shell and exec: --user, --cwd, -e K=V, -t/-T, then [--] cmd.
struct SessionArgs {
    std::string user, cwd;
    std::vector<std::pair<std::string, std::string>> env;
    std::vector<std::string> argv;
    int tty{-1};   // -1 auto
};

bool parse_session_args(int argc, char** argv, int i, SessionArgs& a) {
    for (; i < argc; ++i) {
        const std::string_view f = argv[i];
        auto need = [&]() -> const char* {
            if (i + 1 >= argc) { fail(std::string{f} + " needs an argument"); return nullptr; }
            return argv[++i];
        };
        if (f == "--") { ++i; break; }
        if (f == "--user" || f == "-u") { const char* v = need(); if (!v) return false; a.user = v; }
        else if (f == "--cwd" || f == "-C") { const char* v = need(); if (!v) return false; a.cwd = v; }
        else if (f == "-e" || f == "--setenv") {
            const char* v = need();
            if (!v) return false;
            const std::string kv = v;
            const auto eq = kv.find('=');
            if (eq == std::string::npos || eq == 0) { fail("bad -e '" + kv + "'"); return false; }
            a.env.emplace_back(kv.substr(0, eq), kv.substr(eq + 1));
        }
        else if (f == "-t") a.tty = 1;
        else if (f == "-T") a.tty = 0;
        else if (!f.empty() && f[0] == '-') { fail("unknown option '" + std::string{f} + "'"); return false; }
        else break;
    }
    for (; i < argc; ++i) a.argv.emplace_back(argv[i]);
    return true;
}

int cmd_shell(int argc, char** argv, bool exec) {
    if (argc < 3) return fail(exec ? "usage: linuxity exec <env> [options] -- cmd ..."
                                   : "usage: linuxity shell <env> [--user U]");
    SessionArgs a;
    if (!parse_session_args(argc, argv, 3, a)) return 2;
    if (exec && a.argv.empty()) return fail("exec needs a command");
    Conn c;
    if (!ensure_up(argv[2], c)) return fail("cannot start " + std::string{argv[2]});
    const bool tty = a.tty >= 0 ? a.tty == 1 : (::isatty(0) && ::isatty(1));
    return run_session(c, a.argv, a.user, a.cwd, a.env, tty);
}

// ---- simple requests -----------------------------------------------------------

int cmd_ps(int argc, char** argv) {
    if (argc < 3) return fail("usage: linuxity ps <env> [--json]");
    Conn c;
    if (!need_running(argv[2], c)) return 1;
    if (!control::send_line(c.fd, R"({"op":"ps"})")) return fail("lost the connection");
    std::string line;
    if (!c.in.read_line(line)) return fail("lost the connection");
    if (has_flag(argc, argv, "--json")) { std::puts(line.c_str()); return 0; }
    const auto r = parse_json(line);
    if (print_reply(r)) return 1;
    std::printf("%7s %7s %-10s %8s %s\n", "PID", "PPID", "USER", "RSS", "COMMAND");
    if (const JValue* ps = r->get("procs"))
        for (const auto& p : ps->a) {
            std::string cmd = p.str("cmdline");
            if (cmd.empty()) cmd = "[" + p.str("comm") + "]";
            if (const auto s = p.str("service"); !s.empty()) cmd += "   (service " + s + ")";
            std::printf("%7lld %7lld %-10s %7lldK %s\n", static_cast<long long>(p.num("pid")),
                        static_cast<long long>(p.num("ppid")), p.str("user").c_str(),
                        static_cast<long long>(p.num("rss_kb")), cmd.c_str());
        }
    return 0;
}

int signal_number(std::string_view s) {
    if (s.starts_with("SIG")) s.remove_prefix(3);
    if (!s.empty() && s.find_first_not_of("0123456789") == std::string_view::npos)
        return std::atoi(std::string{s}.c_str());
    static constexpr std::pair<std::string_view, int> kNames[] = {
        {"HUP", SIGHUP}, {"INT", SIGINT}, {"QUIT", SIGQUIT}, {"KILL", SIGKILL}, {"USR1", SIGUSR1},
        {"USR2", SIGUSR2}, {"TERM", SIGTERM}, {"CONT", SIGCONT}, {"STOP", SIGSTOP}, {"WINCH", SIGWINCH},
    };
    for (const auto& [n, v] : kNames) if (n == s) return v;
    return -1;
}

int cmd_kill(int argc, char** argv) {
    if (argc < 4) return fail("usage: linuxity kill <env> <pid> [signal]");
    const int sig = argc > 4 ? signal_number(argv[4]) : SIGTERM;
    if (sig < 0) return fail("unknown signal '" + std::string{argv[4]} + "'");
    Conn c;
    if (!need_running(argv[2], c)) return 1;
    Json j;
    j.obj().kv("op", "kill").kv("pid", static_cast<std::int64_t>(std::atoll(argv[3]))).kv("signal", sig).end();
    return print_reply(request(c, j.text()));
}

std::string human_bytes(std::uint64_t b) {
    char buf[32];
    const char* u[] = {"B", "K", "M", "G", "T"};
    double v = static_cast<double>(b);
    int i = 0;
    while (v >= 1024 && i < 4) { v /= 1024; ++i; }
    std::snprintf(buf, sizeof buf, i ? "%.1f%s" : "%.0f%s", v, u[i]);
    return buf;
}

int cmd_status(int argc, char** argv) {
    if (argc < 3) return fail("usage: linuxity status <env> [--json]");
    const bool json = has_flag(argc, argv, "--json");
    Conn c;
    if (!connect_env(argv[2], c)) {
        if (!Store{}.has(argv[2])) return 1;
        if (json) std::puts(R"({"ok":true,"running":false})");
        else if (!lx::cli::host_runs_instances())
            std::printf("%s: ready (each `linuxity shell` runs it in the foreground)\n", argv[2]);
        else std::printf("%s: not running\n", argv[2]);
        return 0;
    }
    if (!control::send_line(c.fd, R"({"op":"status"})")) return fail("lost the connection");
    std::string line;
    if (!c.in.read_line(line)) return fail("lost the connection");
    if (json) { std::puts(line.c_str()); return 0; }
    const auto r = parse_json(line);
    if (print_reply(r)) return 1;
    std::printf("%s: running (pid %lld, up %llds)\n", r->str("env").c_str(),
                static_cast<long long>(r->num("pid")), static_cast<long long>(r->num("uptime_s")));
    std::printf("  hostname   %s\n  user       %s\n  rootfs     %s\n  processes  %lld\n",
                r->str("hostname").c_str(), r->str("user").c_str(), r->str("rootfs").c_str(),
                static_cast<long long>(r->num("processes")));
    if (const auto l = r->str("limits"); !l.empty()) std::printf("  limits     %s\n", l.c_str());
    if (const auto b = r->str("bridge"); !b.empty()) std::printf("  bridge     %s\n", b.c_str());
    if (const JValue* ss = r->get("sessions"); ss && !ss->a.empty()) {
        std::puts("  sessions");
        for (const auto& s : ss->a) {
            std::string cmd;
            if (const JValue* av = s.get("argv")) for (const auto& x : av->a) cmd += (cmd.empty() ? "" : " ") + x.s;
            std::printf("    %-6lld %-10s %s%s\n", static_cast<long long>(s.num("pid")), s.str("user").c_str(),
                        cmd.c_str(), s.flag("attached") ? "  (attached)" : "");
        }
    }
    if (const JValue* sv = r->get("services"); sv && !sv->a.empty()) {
        std::puts("  services");
        for (const auto& s : sv->a)
            std::printf("    %-12s %-10s pid %-6lld restarts %lld\n", s.str("name").c_str(), s.str("state").c_str(),
                        static_cast<long long>(s.num("pid")), static_cast<long long>(s.num("restarts")));
    }
    if (const JValue* n = r->get("notes"); n && !n->a.empty()) {
        std::puts("  notes");
        for (const auto& e : n->a)
            if (const auto t = e.str("text"); !t.empty()) std::printf("    %s\n", t.c_str());
    }
    return 0;
}

int cmd_svc(int argc, char** argv) {
    if (argc < 3) return fail("usage: linuxity svc <env> [list|start|stop|restart] [name]");
    const std::string action = argc > 3 ? argv[3] : "list";
    Conn c;
    if (!need_running(argv[2], c)) return 1;
    Json j;
    j.obj().kv("op", "svc").kv("action", action);
    if (argc > 4) j.kv("name", argv[4]);
    j.end();
    const auto r = request(c, j.text());
    if (print_reply(r)) return 1;
    if (action == "list") {
        if (has_flag(argc, argv, "--json")) { std::puts(R"(see `linuxity status --json`)"); return 0; }
        const JValue* sv = r->get("services");
        if (!sv || sv->a.empty()) { std::puts("no services (add one under `service` in env.vibe)"); return 0; }
        for (const auto& s : sv->a)
            std::printf("%-12s %-10s pid %-6lld restarts %-3lld last exit %lld\n", s.str("name").c_str(),
                        s.str("state").c_str(), static_cast<long long>(s.num("pid")),
                        static_cast<long long>(s.num("restarts")), static_cast<long long>(s.num("last_code")));
    }
    return 0;
}

int cmd_down(int argc, char** argv) {
    if (argc < 3) return fail("usage: linuxity stop <env>");
    Conn c;
    if (!connect_env(argv[2], c)) { std::printf("%s is not running\n", argv[2]); return 0; }
    if (print_reply(request(c, R"({"op":"down"})"))) return 1;
    // the instance closes the socket once it is gone
    std::string line;
    while (c.in.read_line(line)) {}
    return 0;
}

int cmd_reload(int argc, char** argv) {
    if (argc < 3) return fail("usage: linuxity reload <env>");
    Conn c;
    if (!need_running(argv[2], c)) return 1;
    const auto r = request(c, R"({"op":"reload"})");
    if (print_reply(r)) return 1;
    const auto applied = r->strs("applied");
    if (applied.empty()) std::puts("nothing changed that applies live");
    for (const auto& a : applied) std::printf("applied %s\n", a.c_str());
    if (r->flag("restart_needed"))
        std::printf("other changes need a restart: linuxity stop %s, then use it again\n", argv[2]);
    return 0;
}

int cmd_logs(int argc, char** argv) {
    if (argc < 3) return fail("usage: linuxity logs <env> [service] [-f]");
    Store s;
    if (!s.has(argv[2])) return fail("no environment '" + std::string{argv[2]} + "'");
    std::string file = s.logs_dir(argv[2]) + "/linuxity.log";
    if (argc > 3 && argv[3][0] != '-') file = s.logs_dir(argv[2]) + "/" + argv[3] + ".log";
    const bool follow = has_flag(argc, argv, "-f");
    const int fd = ::open(file.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return fail("no log at " + file);
    char buf[65536];
    ::ssize_t n;
    while ((n = ::read(fd, buf, sizeof buf)) > 0) write_all(1, buf, static_cast<std::size_t>(n));
    if (!follow) { ::close(fd); return 0; }
    // follow: woken by the kernel when the file grows, no polling loop
#if defined(__linux__)
    const int in = ::inotify_init1(IN_CLOEXEC);
    if (in < 0 || ::inotify_add_watch(in, file.c_str(), IN_MODIFY) < 0) { ::close(fd); return fail("cannot watch " + file); }
#else
    const int in = ::kqueue();
    struct ::kevent kev{};
    EV_SET(&kev, static_cast<uintptr_t>(fd), EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE | NOTE_EXTEND, 0, nullptr);
    if (in < 0 || ::kevent(in, &kev, 1, nullptr, 0, nullptr) < 0) { ::close(fd); return fail("cannot watch " + file); }
#endif
    for (;;) {
#if defined(__linux__)
        char ev[4096];
        if (::read(in, ev, sizeof ev) < 0 && errno != EINTR) break;
#else
        struct ::kevent out{};
        if (::kevent(in, nullptr, 0, &out, 1, nullptr) < 0 && errno != EINTR) break;
#endif
        while ((n = ::read(fd, buf, sizeof buf)) > 0) write_all(1, buf, static_cast<std::size_t>(n));
    }
    return 0;
}

// ---- env management ---------------------------------------------------------------

// A key as the user typed it: the full path, or its last part when that's
// unique ("hostname" -> system.hostname, "memory" -> limits.memory).
[[nodiscard]] std::string resolve_key(const std::string& key) {
    if (find_field(key) || find_dyn_field(key) || key.find('.') != std::string::npos) return key;
    std::string hit;
    for (const auto& f : kFields) {
        const auto dot = f.path.rfind('.');
        if (dot != std::string_view::npos && f.path.substr(dot + 1) == key) {
            if (!hit.empty()) return key;   // ambiguous: let the caller complain
            hit = std::string{f.path};
        }
    }
    return hit.empty() ? key : hit;
}

// Render a CLI value for `key` as VIBE text, checked against the schema.
std::optional<std::string> render_value(const std::string& key, const std::vector<std::string>& words,
                                        std::string& why) {
    Type t = Type::string;
    if (const Field* f = find_field(key)) t = f->type;
    else if (const DynField* d = find_dyn_field(key)) t = d->type;
    else {
        why = "unknown key '" + key + "'";
        if (const auto s = suggest(key); !s.empty()) why += ", did you mean " + s + "?";
        return std::nullopt;
    }
    if (words.empty()) { why = "no value"; return std::nullopt; }
    std::string text;
    if (t == Type::strings) {
        // one word with spaces is split like a shell would (quotes group),
        // several words are the list
        std::vector<std::string> items = words;
        if (items.size() == 1 && items[0].find_first_of(" \t") != std::string::npos) {
            items.clear();
            std::string cur;
            bool have = false;
            char q = 0;
            for (const char c : words[0]) {
                if (q) { if (c == q) q = 0; else cur.push_back(c); continue; }
                if (c == '\'' || c == '"') { q = c; have = true; continue; }
                if (c == ' ' || c == '\t') { if (have) items.push_back(cur); cur.clear(); have = false; continue; }
                cur.push_back(c);
                have = true;
            }
            if (q) { why = "unclosed quote in " + key; return std::nullopt; }
            if (have) items.push_back(cur);
        }
        text = "[";
        for (const auto& w : items) text += " " + vibe_edit::string_text(w);
        text += " ]";
    } else {
        std::string v = words[0];
        for (std::size_t i = 1; i < words.size(); ++i) v += " " + words[i];
        if (t == Type::boolean) {
            if (v == "on" || v == "yes" || v == "1") v = "true";
            if (v == "off" || v == "no" || v == "0") v = "false";
            if (v != "true" && v != "false") { why = key + " is a boolean (true/false)"; return std::nullopt; }
            text = v;
        } else if (t == Type::integer || t == Type::number) {
            char* end = nullptr;
            (void)std::strtod(v.c_str(), &end);
            if (v.empty() || *end) { why = key + " is a number"; return std::nullopt; }
            text = v;
        } else if (t == Type::size) {
            if (!lx::kernel::parse_bytes(v)) { why = key + " is a size, e.g. 512M or 2G"; return std::nullopt; }
            text = v;
        } else if (key == "login.umask") {
            text = vibe_edit::quote(v);
        } else {
            text = vibe_edit::string_text(v);
        }
    }
    // the edit must also pass the real parser and the type check: build
    // "a { b { key value } }" and parse it
    std::string probe;
    {
        std::vector<std::string> segs;
        std::string_view k = key;
        while (true) {
            const auto d = k.find('.');
            segs.emplace_back(k.substr(0, d));
            if (d == std::string_view::npos) break;
            k.remove_prefix(d + 1);
        }
        for (std::size_t i = 0; i + 1 < segs.size(); ++i) probe += vibe_edit::key_text(segs[i]) + " { ";
        probe += vibe_edit::key_text(segs.back()) + " " + text;
        for (std::size_t i = 0; i + 1 < segs.size(); ++i) probe += " }";
    }
    // only this key's own errors: a lone "service x { restart always }" is
    // missing its command, but the real document may well have one
    const auto pr = parse_config(probe);
    for (const auto& d : pr.diags)
        if (d.error && d.path == key) { why = format_diag(d); return std::nullopt; }
    return text;
}

int print_diags(const std::vector<Diag>& diags, const std::string& file, bool json) {
    bool bad = false;
    if (json) {
        Json j;
        j.obj().key("diagnostics").arr();
        for (const auto& d : diags) {
            j.obj().kv("path", d.path).kv("message", d.message).kv("error", d.error).kv("line", d.line).end();
            bad = bad || d.error;
        }
        j.end().kv("ok", !bad).end();
        std::puts(j.text().c_str());
        return bad ? 1 : 0;
    }
    for (const auto& d : diags) {
        std::fprintf(stderr, "%s: %s\n", file.c_str(), format_diag(d).c_str());
        bad = bad || d.error;
    }
    return bad ? 1 : 0;
}

// Write a new env.vibe after an edit, refusing one that no longer parses.
int save_config(const Store& s, const std::string& name, const std::string& text) {
    const auto r = parse_config(text);
    for (const auto& d : r.diags)
        if (d.error) return fail("refusing to save: " + format_diag(d));
    if (!write_file_atomic(s.config_path(name), text)) return fail("cannot write " + s.config_path(name));
    // tell a running instance, which applies what it can live
    Conn c;
    if (connect_env(name, c)) {
        const auto rr = request(c, R"({"op":"reload"})");
        if (rr && rr->flag("ok") && rr->flag("restart_needed"))
            std::fprintf(stderr, "linuxity: saved; it applies the next time %s starts (linuxity stop %s)\n", name.c_str(), name.c_str());
    }
    return 0;
}

std::string value_text(const JValue& v) {
    switch (v.kind) {
        case JValue::Kind::string: return v.s;
        case JValue::Kind::boolean: return v.b ? "true" : "false";
        case JValue::Kind::number: {
            char buf[32];
            std::snprintf(buf, sizeof buf, "%g", v.n);
            return buf;
        }
        case JValue::Kind::array: {
            std::string out;
            for (const auto& e : v.a) out += (out.empty() ? "" : " ") + value_text(e);
            return out;
        }
        case JValue::Kind::null: return "";
        case JValue::Kind::object: return "{...}";
    }
    return "";
}

// ---- users ---------------------------------------------------------------------------

// Runs as root inside the instance. POSIX sh, so it works on bash, dash and
// busybox images alike. Inputs come in the environment, never spliced into
// the script text.
constexpr const char* kAddUserScript = R"SH(
set -e
say() { printf 'linuxity: %s\n' "$*" >&2; }
U=$LX_USER
[ -x "$LX_SHELL" ] || { say "$LX_SHELL is not in this image, using /bin/sh"; LX_SHELL=/bin/sh; }

created=0
if id -u "$U" >/dev/null 2>&1; then
  say "$U already exists, updating it"
  if command -v usermod >/dev/null 2>&1; then usermod -s "$LX_SHELL" "$U"; fi
elif command -v useradd >/dev/null 2>&1; then
  useradd -m -U -s "$LX_SHELL" "$U" 2>/dev/null || useradd -m -g "$U" -s "$LX_SHELL" "$U"
  created=1
elif command -v adduser >/dev/null 2>&1; then
  adduser -D -s "$LX_SHELL" "$U"
  created=1
else
  say "the image has neither useradd nor adduser"; exit 1
fi

H=$(awk -F: -v u="$U" '$1==u{print $6}' /etc/passwd)
if [ -n "$H" ] && [ ! -d "$H" ]; then mkdir -p "$H"; fi
[ -n "$H" ] && chown "$U" "$H" && chmod 0700 "$H"

if [ -n "$LX_PASSWORD" ]; then
  printf '%s:%s\n' "$U" "$LX_PASSWORD" | chpasswd
elif [ "$created" = 1 ]; then
  passwd -d "$U" >/dev/null 2>&1 || true
fi

if [ "$LX_SUDO" = 1 ]; then
  if ! command -v sudo >/dev/null 2>&1; then
    say "installing sudo"
    if command -v pacman >/dev/null 2>&1; then
      # a fresh image has no keyring and no package database yet
      if [ ! -s /etc/pacman.d/gnupg/pubring.gpg ] && [ ! -s /etc/pacman.d/gnupg/pubring.kbx ]; then
        pacman-key --init >/dev/null && pacman-key --populate >/dev/null
      fi
      pacman -S --noconfirm --needed sudo 2>/dev/null || pacman -Sy --noconfirm --needed sudo
    elif command -v apk >/dev/null 2>&1; then apk add --no-cache sudo
    elif command -v apt-get >/dev/null 2>&1; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get install -y sudo || { apt-get update && apt-get install -y sudo; }
    elif command -v dnf >/dev/null 2>&1; then dnf install -y sudo
    elif command -v zypper >/dev/null 2>&1; then zypper -n install sudo
    fi
  fi
  command -v sudo >/dev/null 2>&1 || { say "sudo is not installed and could not be installed"; exit 1; }

  for g in wheel sudo; do
    if grep -q "^$g:" /etc/group; then
      if command -v usermod >/dev/null 2>&1; then usermod -aG "$g" "$U"; else addgroup "$U" "$g"; fi
      break
    fi
  done

  mkdir -p /etc/sudoers.d
  chmod 0750 /etc/sudoers.d
  f=/etc/sudoers.d/90-linuxity-$U
  # "last matching rule wins" in sudo, so a later %wheel rule in the image's
  # sudoers would bring the password prompt back. A per-user Defaults line
  # applies whatever the rule order is.
  if [ -n "$LX_PASSWORD" ]; then rule="$U ALL=(ALL:ALL) ALL"
  elif [ "$created" = 1 ] || [ ! -f "$f" ] || grep -q NOPASSWD "$f"; then
    rule="Defaults:$U !authenticate
$U ALL=(ALL:ALL) ALL"
  else rule=$(cat "$f"); fi
  # sudo skips names with a dot, so the temp file is ignored until the move
  printf '%s\n' "$rule" > "$f.new"
  chown root:root "$f.new"
  chmod 0440 "$f.new"
  if command -v visudo >/dev/null 2>&1 && ! visudo -cqf "$f.new"; then
    rm -f "$f.new"; say "visudo rejected the rule"; exit 1
  fi
  mv -f "$f.new" "$f"
  [ -f /etc/sudoers ] || { printf 'root ALL=(ALL:ALL) ALL\n' > /etc/sudoers; chmod 0440 /etc/sudoers; }
  grep -Eq '^[@#]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers ||
    { chmod u+w /etc/sudoers; printf '@includedir /etc/sudoers.d\n' >> /etc/sudoers; chmod 0440 /etc/sudoers; }
  # prove it, as the user, without asking for anything
  if [ -z "$LX_PASSWORD" ]; then
    su -s /bin/sh -c 'sudo -n true' "$U" || { say "sudo does not work for $U"; exit 1; }
  fi
fi
)SH";

[[nodiscard]] bool valid_user_name(std::string_view n) {
    if (n.empty() || n.size() > 32 || n == "root") return false;
    if (!((n[0] >= 'a' && n[0] <= 'z') || n[0] == '_')) return false;
    for (const char c : n)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    return true;
}

// Read a password from the terminal, without echo.
std::optional<std::string> prompt_password(const char* what) {
    const int fd = ::open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    ::termios old{};
    const bool tty = ::tcgetattr(fd, &old) == 0;
    if (tty) {
        ::termios t = old;
        t.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(fd, TCSAFLUSH, &t);
    }
    (void)!::write(fd, what, std::strlen(what));
    std::string pw;
    char c;
    while (::read(fd, &c, 1) == 1 && c != '\n' && c != '\r') pw.push_back(c);
    (void)!::write(fd, "\n", 1);
    if (tty) ::tcsetattr(fd, TCSAFLUSH, &old);
    ::close(fd);
    return pw;
}

// linuxity env adduser <env> <user> [--no-sudo] [--password | --password-stdin]
//                                   [--shell PATH] [--no-default]
int cmd_adduser(const Store& s, const std::string& name, int argc, char** argv) {
    if (argc < 5)
        return fail("usage: linuxity adduser <env> <user> [--no-sudo] [--password | --password-stdin] "
                    "[--shell PATH] [--no-default]");
    const std::string user = argv[4];
    if (!valid_user_name(user))
        return fail("bad user name '" + user + "' (lowercase letters, digits, _ and -, starting with a letter)");
    std::string shell, password;
    bool sudo = true, make_default = true, ask = false, from_stdin = false;
    for (int i = 5; i < argc; ++i) {
        const std::string_view f = argv[i];
        if (f == "--shell" && i + 1 < argc) shell = argv[++i];
        else if (f == "--no-sudo") sudo = false;
        else if (f == "--sudo") sudo = true;
        else if (f == "--no-default") make_default = false;
        else if (f == "--password") ask = true;
        else if (f == "--password-stdin") from_stdin = true;
        else return fail("unknown option '" + std::string{f} + "'");
    }
    if (ask) {
        const auto a = prompt_password("password: ");
        const auto b = a ? prompt_password("again: ") : std::nullopt;
        if (!a || !b) return fail("no terminal to ask for a password on (use --password-stdin)");
        if (*a != *b) return fail("the passwords don't match");
        password = *a;
    } else if (from_stdin) {
        std::getline(std::cin, password);
        if (!password.empty() && password.back() == '\r') password.pop_back();
    }
    if (password.find_first_of(":\n") != std::string::npos) return fail("a password can't contain ':' or a newline");
    if (shell.empty()) {
        const auto r = s.load(name);
        shell = r.config.shell.empty() ? "/bin/bash" : r.config.shell;
    }

    // inside the running instance, so there is one kernel and one view of
    // the files, never two writing the same upper
    Conn c;
    if (!ensure_up(name, c)) return fail("cannot start " + name);
    const int rc = run_session(c, {"/bin/sh", "-c", kAddUserScript}, "root", "/",
                               {{"LX_USER", user}, {"LX_SHELL", shell}, {"LX_PASSWORD", password},
                                {"LX_SUDO", sudo ? "1" : "0"}, {"PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}},
                               false);
    if (rc != 0) return fail("setting up " + user + " failed");

    if (make_default) {
        const auto cur = slurp(s.config_path(name)).value_or("");
        const auto next = vibe_edit::set(cur, "login.user", vibe_edit::string_text(user));
        if (!next || save_config(s, name, *next) != 0) return fail("created " + user + " but couldn't make it the default");
    }
    std::printf("%s is ready in %s%s%s\n", user.c_str(), name.c_str(),
                sudo ? (password.empty() ? ", with passwordless sudo" : ", with sudo") : "",
                make_default ? ", and new shells log in as it" : "");
    return 0;
}

// linuxity env users <env> [--json]: login users (root and uid >= 1000)
int cmd_users(const Store& s, const std::string& name, bool json) {
    const auto r = s.load(name);
    std::vector<std::string> layers;
    if (!r.config.upper.empty()) layers.push_back(r.config.upper);
    layers.push_back(r.config.rootfs);
    const std::string passwd = read_layered(layers, "/etc/passwd");
    const std::string groups = read_layered(layers, "/etc/group");
    // groups sudoers actually grants (Arch ships %wheel commented out)
    std::vector<std::string> granted;
    {
        std::istringstream si{read_layered(layers, "/etc/sudoers")};
        std::string sl;
        while (std::getline(si, sl))
            for (const char* g : {"wheel", "sudo", "admin"})
                if (sl.starts_with(std::string{"%"} + g + " ") || sl.starts_with(std::string{"%"} + g + "\t"))
                    granted.emplace_back(g);
    }
    struct Row { std::string name, home, shell; std::uint32_t uid; bool sudo; };
    std::vector<Row> rows;
    std::istringstream in{passwd};
    std::string line;
    while (std::getline(in, line)) {
        std::vector<std::string> f;
        std::size_t a = 0;
        for (;;) {
            const auto b = line.find(':', a);
            f.push_back(line.substr(a, b == std::string::npos ? std::string::npos : b - a));
            if (b == std::string::npos) break;
            a = b + 1;
        }
        if (f.size() < 7) continue;
        const auto uid = static_cast<std::uint32_t>(std::strtoul(f[2].c_str(), nullptr, 10));
        if (uid != 0 && (uid < 1000 || uid >= 60000)) continue;
        bool sudo = uid == 0;
        if (!sudo) {
            const std::string rule = "/etc/sudoers.d/90-linuxity-" + f[0];
            for (const auto& l : layers) sudo = sudo || exists(l + rule);
            const auto gs = groups_of(groups, f[0], static_cast<std::uint32_t>(std::strtoul(f[3].c_str(), nullptr, 10)));
            for (const auto& g : granted) {
                std::istringstream gi{groups};
                std::string gl;
                while (std::getline(gi, gl))
                    if (gl.starts_with(g + ":")) {
                        const auto gid = std::strtoul(gl.substr(gl.find(':', gl.find(':') + 1) + 1).c_str(), nullptr, 10);
                        for (const auto x : gs) sudo = sudo || x == gid;
                    }
            }
        }
        rows.push_back({f[0], f[5], f[6], uid, sudo});
    }
    if (json) {
        Json j;
        j.obj().kv("default", r.config.user).key("users").arr();
        for (const auto& u : rows)
            j.obj().kv("name", u.name).kv("uid", static_cast<std::int64_t>(u.uid)).kv("home", u.home)
                .kv("shell", u.shell).kv("sudo", u.sudo).kv("default", u.name == r.config.user).end();
        std::puts(j.end().end().take().c_str());
        return 0;
    }
    for (const auto& u : rows)
        std::printf("%-14s uid %-6u %-16s %s%s\n", u.name.c_str(), u.uid, u.shell.c_str(),
                    u.sudo ? "sudo" : "", u.name == r.config.user ? "  (default)" : "");
    return 0;
}

// ---- images: new, import, export -------------------------------------------------------

// Run a host command and capture stdout (for curl/wget). -1 if it couldn't run.
int capture(const std::vector<std::string>& argv, std::string& out) {
    int p[2];
    if (::pipe2(p, O_CLOEXEC) != 0) return -1;
    const ::pid_t pid = ::fork();
    if (pid == 0) {
        ::dup2(p[1], 1);
        std::vector<char*> a;
        for (const auto& s : argv) a.push_back(const_cast<char*>(s.c_str()));
        a.push_back(nullptr);
        ::execvp(a[0], a.data());
        ::_exit(127);
    }
    ::close(p[1]);
    char buf[4096];
    ::ssize_t n;
    while ((n = ::read(p[0], buf, sizeof buf)) > 0) out.append(buf, static_cast<std::size_t>(n));
    ::close(p[0]);
    int st = 0;
    ::waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

[[nodiscard]] bool have_fetcher() { return archive::have_tool("curl") || archive::have_tool("wget"); }

// Download with the host's curl or wget, showing their progress bar.
bool download(const std::string& url, const std::string& to) {
    const std::string part = to + ".part";
    std::vector<std::string> argv;
    if (archive::have_tool("curl")) argv = {"curl", "-fL", "--retry", "3", "-C", "-", "-o", part, url};
    else if (archive::have_tool("wget")) argv = {"wget", "-c", "-O", part, url};
    else return false;
    if (!::isatty(2) && argv[0] == "curl") argv.insert(argv.begin() + 1, "-sS");
    else if (argv[0] == "curl") argv.insert(argv.begin() + 1, "--progress-bar");
    const ::pid_t pid = ::fork();
    if (pid == 0) {
        std::vector<char*> a;
        for (const auto& s : argv) a.push_back(const_cast<char*>(s.c_str()));
        a.push_back(nullptr);
        ::dup2(2, 1);
        ::execvp(a[0], a.data());
        ::_exit(127);
    }
    int st = 0;
    ::waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 && ::rename(part.c_str(), to.c_str()) == 0;
}

void say(const std::string& s) { std::fprintf(stderr, "%s\n", s.c_str()); }

// Unpack an image into a new environment `name`: the rootfs lives inside the
// env (so `rm` takes it too) and the image's owners and modes go into the
// metadata journal, kept as image.meta so `reset` restores them.
std::string unpack_into_env(const Store& s, const std::string& name, const std::string& file,
                            const std::string& strip, bool auto_strip) {
    const std::string tmp = s.envs_dir() + "/." + name + ".unpacking";
    (void)remove_tree(tmp);
    if (!mkdirs(s.envs_dir())) return "cannot create " + s.envs_dir();
    const bool tty = ::isatty(2);
    auto r = archive::extract(file, tmp, strip, [tty](std::uint64_t n) {
        if (tty) std::fprintf(stderr, "\runpacking... %llu files", static_cast<unsigned long long>(n));
    });
    if (tty) std::fprintf(stderr, "\r\x1b[K");
    if (!r.error.empty()) { (void)remove_tree(tmp); return r.error; }
    // an imported tarball may wrap everything in one directory
    if (auto_strip && !exists(tmp + "/etc")) {
        const auto top = list_dir(tmp);
        if (top.size() == 1 && exists(tmp + "/" + top[0] + "/etc")) {
            const std::string inner = tmp + ".inner";
            if (::rename((tmp + "/" + top[0]).c_str(), inner.c_str()) == 0) {
                (void)remove_tree(tmp);
                (void)::rename(inner.c_str(), tmp.c_str());
                const std::string pre = "/" + top[0];
                for (auto& m : r.meta)
                    if (m.path.starts_with(pre)) m.path = m.path.substr(pre.size());
            }
        }
    }
    if (!exists(tmp + "/etc") || !(exists(tmp + "/bin") || exists(tmp + "/usr/bin"))) {
        (void)remove_tree(tmp);
        return "that doesn't look like a Linux root filesystem (no /etc or /bin)";
    }
    if (const auto e = s.create(name, tmp); !e.empty()) { (void)remove_tree(tmp); return e; }
    const std::string rootfs = s.dir(name) + "/rootfs";
    if (::rename(tmp.c_str(), rootfs.c_str()) != 0) return std::string{"cannot move the rootfs: "} + std::strerror(errno);
    const auto cur = slurp(s.config_path(name)).value_or("");
    if (const auto next = vibe_edit::set(cur, "rootfs", "rootfs")) (void)write_file_atomic(s.config_path(name), *next);

    lx::kernel::MetaStore meta;
    meta.attach(s.default_upper(name));
    for (const auto& m : r.meta) {
        if (m.uid || m.gid) meta.set_owner(m.path, m.uid, m.gid);
        struct ::stat st{};
        const bool have = ::lstat((rootfs + m.path).c_str(), &st) == 0;
        meta.set_mode(m.path, m.mode, have ? static_cast<std::uint32_t>(st.st_mode) : 0xffffffffu);
    }
    if (const auto j = slurp(s.default_upper(name) + "/.linuxity-meta"))
        (void)write_file_atomic(s.dir(name) + "/image.meta", *j);
    if (r.skipped)
        say("note: " + std::to_string(r.skipped) + " entries (devices, FIFOs) were skipped; linuxity provides /dev itself");
    return {};
}

// After unpacking: the distro's own setup, a user, and the default env.
int finish_env(const Store& s, const std::string& name, std::string_view setup,
               const std::string& user, bool ask_user, bool password) {
    Conn c;
    if (!setup.empty()) {
        say("setting up...");
        if (!ensure_up(name, c)) return fail("cannot start " + name);
        if (run_session(c, {"/bin/sh", "-c", std::string{setup}}, "root", "/", {}, false) != 0)
            say("note: the setup step failed; you may need to run it yourself");
    }
    std::string who = user;
    if (who.empty() && ask_user && ::isatty(0)) {
        const char* host_user = std::getenv("USER");
        const std::string suggest = host_user && valid_user_name(host_user) ? host_user : "";
        std::fprintf(stderr, "Your user name in %s%s (empty to stay root): ", name.c_str(),
                     suggest.empty() ? "" : (" [" + suggest + "]").c_str());
        std::string line;
        std::getline(std::cin, line);
        while (!line.empty() && (line.back() == ' ' || line.back() == '\r')) line.pop_back();
        who = line.empty() ? suggest : line;
        if (who == "root" || who == "-") who.clear();
    }
    if (!who.empty()) {
        std::vector<std::string> a = {"linuxity", "env", "adduser", name, who};
        if (password) a.emplace_back("--password");
        std::vector<char*> av;
        for (auto& x : a) av.push_back(x.data());
        if (cmd_adduser(s, name, static_cast<int>(av.size()), av.data()) != 0) return 1;
    }
    const bool first = !exists(s.home() + "/default") || s.default_env().empty();
    if (first) (void)s.set_default(name);
    const bool is_def = s.default_env() == name;
    std::printf("\n%s %s is ready.\n", green("✓").c_str(), bold(name).c_str());
    std::printf("  %-28s %s\n", is_def ? "linuxity" : ("linuxity shell " + name).c_str(), dim("a shell in it").c_str());
    const bool bare = is_def && !lx::cli::host_runs_instances();   // `linuxity CMD` runs in it
    std::printf("  %-28s %s\n", bare ? "linuxity uname -a"
                                      : ("linuxity exec " + (is_def ? std::string{} : name + " ") + "-- uname -a").c_str(),
                dim("run one command").c_str());
    return 0;
}

// linuxity new <distro>[:version] [name] [--user U | --root] [--password]
//                                        [--file F] [--checksum algo:hex]
int cmd_new(int argc, char** argv) {
    Store s;
    std::string ref, name, file, user, checksum;
    bool root_only = false, password = false, no_verify = false;
    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--file") file = next();
        else if (a == "--user" || a == "-u") user = next();
        else if (a == "--root") root_only = true;
        else if (a == "--password") password = true;
        else if (a == "--checksum") checksum = next();
        else if (a == "--no-verify") no_verify = true;
        else if (!a.empty() && a[0] == '-') return fail("unknown option '" + std::string{a} + "'");
        else if (ref.empty()) ref = a;
        else if (name.empty()) name = a;
        else return fail("too many arguments");
    }
    if (ref.empty()) {
        std::puts("usage: linuxity new <distro> [name]\n");
        std::string list;
        for (const auto& i : kImages)
            if (i.arch == kHostArch) std::printf("  %-8s %-24s %s\n", std::string{i.distro}.c_str(), std::string{i.title}.c_str(), std::string{i.note}.c_str());
        std::puts("\nOr bring your own: linuxity import <name> <rootfs.tar.gz>");
        return 2;
    }
    const Image* img = find_image(ref);
    if (!img) {
        std::string avail;
        for (const auto& i : kImages) if (i.arch == kHostArch) avail += " " + std::string{i.distro};
        return fail("no image '" + ref + "' for " + std::string{kHostArch} + ". Available:" + avail +
                    ". Or: linuxity import <name> <rootfs.tar.gz>");
    }
    if (name.empty()) name = std::string{img->distro};
    if (!valid_name(name)) return fail("bad name '" + name + "' (letters, digits, . _ -)");
    if (exists(s.dir(name))) return fail(name + " already exists. Pick another name: linuxity new " + ref + " <name>");

    // the image, from --file, the cache, or the network
    if (file.empty()) {
        (void)mkdirs(s.cache_dir());
        file = s.cache_dir() + "/" + image_file_name(*img);
    }
    std::string expect = std::string{img->checksum};
    std::string algo = std::string{img->algo};
    if (!checksum.empty()) {
        const auto colon = checksum.find(':');
        if (colon != std::string::npos) { algo = checksum.substr(0, colon); expect = checksum.substr(colon + 1); }
        else expect = checksum;
    }
    auto verify = [&](bool quiet) {
        if (no_verify) return true;
        if (expect.empty() && !img->checksum_url.empty() && have_fetcher()) {
            std::string body;
            const int rc = archive::have_tool("curl") ? capture({"curl", "-fsSL", std::string{img->checksum_url}}, body)
                                                      : capture({"wget", "-qO-", std::string{img->checksum_url}}, body);
            if (rc == 0) expect = body.substr(0, body.find_first_of(" \t\n"));
        }
        if (expect.empty()) {
            if (!quiet) say("note: no checksum to check this image against");
            return true;
        }
        if (!quiet) say("verifying...");
        std::string got = file_digest(file, algo);
        for (auto& ch : expect) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        return got == expect;
    };
    if (!exists(file) || !verify(true)) {
        if (exists(file) && checksum.empty() && file.starts_with(s.cache_dir())) (void)::unlink(file.c_str());
        if (!exists(file)) {
            if (!have_fetcher())
                return fail("this system has no curl or wget. Download\n  " + std::string{img->url} +
                            "\nand run: linuxity new " + ref + " " + name + " --file <the file>");
            say("downloading " + std::string{img->title} + " (about " + std::to_string(img->size_mb) + " MB)...");
            if (!download(std::string{img->url}, file)) return fail("the download failed");
        }
        if (!verify(false)) {
            if (file.starts_with(s.cache_dir())) (void)::unlink(file.c_str());
            return fail("the image doesn't match its checksum (a broken or tampered download); try again");
        }
    }

    say("unpacking " + std::string{img->title} + "...");
    if (const auto e = unpack_into_env(s, name, file, std::string{img->strip}, false); !e.empty())
        return fail(e);
    return finish_env(s, name, img->setup, user, !root_only, password);
}

// linuxity import <name> <rootfs.tar[.gz|.xz|.zst] | directory> [--user U | --root]
int cmd_import(int argc, char** argv) {
    if (argc < 4) return fail("usage: linuxity import <name> <rootfs tarball or directory> [--user U]");
    Store s;
    const std::string name = argv[2], src = argv[3];
    std::string user;
    bool root_only = false;
    for (int i = 4; i < argc; ++i) {
        const std::string_view a = argv[i];
        if ((a == "--user" || a == "-u") && i + 1 < argc) user = argv[++i];
        else if (a == "--root") root_only = true;
        else return fail("unknown option '" + std::string{a} + "'");
    }
    if (!valid_name(name)) return fail("bad name '" + name + "'");
    if (exists(s.dir(name))) return fail(name + " already exists");
    if (is_dir(src)) {
        // a directory is used in place, never copied or written to
        if (const auto e = s.create(name, src); !e.empty()) return fail(e);
    } else {
        say("unpacking " + src + "...");
        if (const auto e = unpack_into_env(s, name, src, {}, true); !e.empty()) return fail(e);
    }
    return finish_env(s, name, {}, user, !root_only, false);
}

// linuxity export <env> <file.tar[.gz]>: the whole environment as you see it
// inside, with owners and modes, ready for `linuxity import` anywhere.
int cmd_export(int argc, char** argv) {
    if (argc < 4) return fail("usage: linuxity export <env> <file.tar.gz>");
    const std::string name = argv[2], to = argv[3];
    Conn c;
    if (!ensure_up(name, c)) return fail("cannot start " + name);
    const std::string part = to + ".part";
    const int out = ::open(part.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out < 0) return fail("cannot write " + to + ": " + std::strerror(errno));
    const bool gz = to.ends_with(".gz") || to.ends_with(".tgz");
    const std::string script =
        "cd / && x='--exclude=./proc --exclude=./sys --exclude=./dev --exclude=./run --exclude=./tmp'; "
        "if tar --version 2>/dev/null | grep -q GNU; then tar --numeric-owner -cpf - $x .; else tar -cf - $x .; fi" +
        std::string{gz ? " | gzip -6" : ""};
    say("exporting " + name + "...");
    const int rc = run_session(c, {"/bin/sh", "-c", script}, "root", "/", {}, false, ::open("/dev/null", O_RDONLY | O_CLOEXEC), out);
    ::close(out);
    if (rc != 0 || ::rename(part.c_str(), to.c_str()) != 0) { ::unlink(part.c_str()); return fail("export failed"); }
    struct ::stat st{};
    (void)::stat(to.c_str(), &st);
    std::printf("wrote %s (%s). Bring it back with: linuxity import <name> %s\n", to.c_str(),
                human_bytes(static_cast<std::uint64_t>(st.st_size)).c_str(), to.c_str());
    return 0;
}

int cmd_images(bool json) {
    if (json) { std::puts(images_json().c_str()); return 0; }
    for (const auto& i : kImages) {
        if (i.arch != kHostArch) continue;
        std::printf("%-8s %-22s ~%4d MB  %s\n", std::string{i.distro}.c_str(), std::string{i.title}.c_str(),
                    i.size_mb, std::string{i.note}.c_str());
    }
    std::puts("\nlinuxity new <distro> [name]      or bring your own: linuxity import <name> <tarball>");
    return 0;
}

int cmd_env(int argc, char** argv) {
    if (argc < 3) { help(); return 2; }
    Store s;
    const std::string_view sub = argv[2];
    const bool json = has_flag(argc, argv, "--json");
    auto name_arg = [&](int i) -> std::string { return argc > i ? argv[i] : ""; };
    const std::string name = name_arg(3);
    auto need_env = [&]() {
        if (name.empty()) { fail("which environment?"); return false; }
        if (!s.has(name)) { fail("no environment '" + name + "'"); return false; }
        return true;
    };

    if (sub == "schema") { std::puts(schema_json().c_str()); return 0; }
    if (sub == "home") { std::puts(s.home().c_str()); return 0; }

    if (sub == "list" || sub == "ls") {
        const auto names = s.names();
        if (json) {
            Json j;
            j.obj().kv("home", s.home()).key("envs").arr();
            for (const auto& n : names) {
                const auto r = s.load(n);
                j.obj().kv("name", n).kv("running", s.running_pid(n) > 0)
                    .kv("rootfs", r.config.rootfs).kv("hostname", r.config.hostname)
                    .kv("user", r.config.user).kv("ok", r.ok()).end();
            }
            std::puts(j.end().end().take().c_str());
            return 0;
        }
        if (names.empty()) { std::puts("no environments yet: linuxity new alpine  (see `linuxity images`)"); return 0; }
        // NAME (the default starred), STATE, USER, how much it has changed
        // from its image, and the distro. Columns sized to the data.
        const std::string def = s.default_env();
        std::size_t w = 4;
        for (const auto& n : names) w = std::max(w, n.size());
        std::printf("  %s\n", bold(std::string{"NAME"} + std::string(w - 4, ' ') + "  STATE     USER       CHANGES   DISTRO").c_str());
        for (const auto& n : names) {
            const auto r = s.load(n);
            const bool up = s.running_pid(n) > 0;
            const std::string state = up ? "running" : lx::cli::host_runs_instances() ? "stopped" : "ready";
            std::string distro = "?";
            for (const auto& l : {r.config.upper, r.config.rootfs}) {
                const auto os = slurp(l + "/etc/os-release");
                if (!os) continue;
                const auto at = os->find("PRETTY_NAME=");
                if (at == std::string::npos) continue;
                distro = os->substr(at + 12, os->find('\n', at) - at - 12);
                std::erase(distro, '"');
                break;
            }
            std::string label = n + std::string(w - n.size(), ' ');
            std::string st = state + std::string(9 - state.size(), ' ');
            if (up) st = green(st);
            std::printf("%s %s  %s %-10s %-9s %s%s\n", n == def ? "*" : " ", bold(label).c_str(), st.c_str(),
                        r.config.user.c_str(), human_bytes(tree_bytes(r.config.upper)).c_str(),
                        dim(distro).c_str(), r.ok() ? "" : "  (config has errors: linuxity check)");
        }
        return 0;
    }

    if (sub == "create" || sub == "new") {
        if (argc < 5) return fail("usage: linuxity env create <name> <rootfs> [--set key=value ...]");
        std::string extra;
        std::string body;
        for (int i = 5; i < argc; ++i) {
            if (std::string_view{argv[i]} != "--set" || i + 1 >= argc) continue;
            const std::string kv = argv[++i];
            const auto eq = kv.find('=');
            if (eq == std::string::npos) return fail("bad --set '" + kv + "' (want key=value)");
            std::string why;
            const auto text = render_value(kv.substr(0, eq), {kv.substr(eq + 1)}, why);
            if (!text) return fail(why);
            extra += kv.substr(0, eq) + "=" + *text + "\n";
        }
        if (const auto e = s.create(name, argv[4]); !e.empty()) return fail(e);
        // apply --set through the editor so they land in their sections
        if (!extra.empty()) {
            auto text = slurp(s.config_path(name)).value_or("");
            std::string_view rest = extra;
            while (!rest.empty()) {
                const auto nl = rest.find('\n');
                const std::string line{rest.substr(0, nl)};
                rest.remove_prefix(nl == std::string_view::npos ? rest.size() : nl + 1);
                const auto eq = line.find('=');
                if (auto t = vibe_edit::set(text, line.substr(0, eq), line.substr(eq + 1))) text = *t;
            }
            if (save_config(s, name, text)) return 1;
        }
        if (!json) std::printf("created %s at %s\n", name.c_str(), s.dir(name).c_str());
        else std::printf("{\"ok\":true,\"path\":\"%s\"}\n", s.dir(name).c_str());
        return 0;
    }

    if (!need_env()) return 1;

    if (sub == "path") { std::puts(s.dir(name).c_str()); return 0; }

    if (sub == "check") {
        auto r = s.load(name);
        std::vector<Diag> d = r.diags;
        check_runnable(r.config, d);
        const int rc = print_diags(d, s.config_path(name), json);
        if (!rc && !json) std::printf("%s: ok\n", s.config_path(name).c_str());
        return rc;
    }

    if (sub == "info" || sub == "show") {
        auto r = s.load(name);
        const ::pid_t pid = s.running_pid(name);
        if (json) {
            Json j;
            j.obj().kv("name", name).kv("path", s.dir(name)).kv("running", pid > 0)
                .kv("pid", static_cast<std::int64_t>(pid)).kv("upper_bytes", tree_bytes(r.config.upper))
                .kv("snapshots", s.snapshots(name)).key("config").raw(config_json(r.config)).end();
            std::puts(j.text().c_str());
            return 0;
        }
        const auto& c = r.config;
        std::printf("%s  (%s)\n", name.c_str(), pid > 0 ? ("running, pid " + std::to_string(pid)).c_str() : "stopped");
        std::printf("  config     %s\n  rootfs     %s\n  changes    %s in %s\n", s.config_path(name).c_str(),
                    c.rootfs.c_str(), human_bytes(tree_bytes(c.upper)).c_str(), c.upper.c_str());
        std::printf("  hostname   %s\n  user       %s%s\n", c.hostname.c_str(), c.user.c_str(),
                    c.shell.empty() ? "" : (" (" + c.shell + ")").c_str());
        if (!c.dns.empty()) {
            std::string d;
            for (const auto& x : c.dns) d += (d.empty() ? "" : " ") + x;
            std::printf("  dns        %s\n", d.c_str());
        }
        if (c.limits.any()) {
            std::string l;
            if (c.limits.cpus) l += std::to_string(*c.limits.cpus).substr(0, 4) + " cpus ";
            if (c.limits.mem_max) l += human_bytes(*c.limits.mem_max) + " memory ";
            if (c.limits.pids_max) l += std::to_string(*c.limits.pids_max) + " tasks ";
            std::printf("  limits     %s\n", l.c_str());
        }
        for (const auto& m : c.mounts) std::printf("  mount      %s -> %s\n", m.host.c_str(), m.at.c_str());
        for (const auto& sv : c.services) {
            std::string cmd;
            for (const auto& a : sv.command) cmd += (cmd.empty() ? "" : " ") + a;
            std::printf("  service    %s: %s\n", sv.name.c_str(), cmd.c_str());
        }
        if (const auto snaps = s.snapshots(name); !snaps.empty()) {
            std::string l;
            for (const auto& x : snaps) l += (l.empty() ? "" : " ") + x;
            std::printf("  snapshots  %s\n", l.c_str());
        }
        for (const auto& d : r.diags) std::printf("  %s\n", format_diag(d).c_str());
        return 0;
    }

    if (sub == "get") {
        auto r = s.load(name);
        const auto cj = parse_json(config_json(r.config));
        auto lookup = [&](std::string_view k) -> const JValue* {
            const JValue* v = cj ? &*cj : nullptr;
            while (v && !k.empty()) {
                const auto d = k.find('.');
                v = v->get(k.substr(0, d));
                if (d == std::string_view::npos) break;
                k.remove_prefix(d + 1);
            }
            return v;
        };
        if (argc < 5) {
            // every setting and its value, defaults included
            for (const auto& f : kFields) {
                const JValue* v = lookup(f.path);
                std::string val = !v ? ""
                    : f.type == Type::size && v->kind == JValue::Kind::number ? human_bytes(static_cast<std::uint64_t>(v->n))
                    : value_text(*v);
                std::printf("%-24s %s\n", std::string{f.path}.c_str(),
                            val.empty() ? (f.def.empty() ? "-" : (std::string{f.def} + " (default)").c_str()) : val.c_str());
            }
            for (const auto& [k, v] : r.config.env) std::printf("env.%-20s %s\n", k.c_str(), v.c_str());
            for (const auto& m : r.config.mounts) std::printf("mount.%-18s %s -> %s\n", m.name.c_str(), m.host.c_str(), m.at.c_str());
            for (const auto& sv : r.config.services) std::printf("service.%-16s %s\n", sv.name.c_str(), sv.command.empty() ? "" : sv.command[0].c_str());
            return 0;
        }
        const std::string key = resolve_key(argv[4]);
        const JValue* v = lookup(key);
        if (!v) return fail("no key '" + std::string{argv[4]} + "'");
        const Field* f = find_field(key);
        if (f && f->type == Type::size && v->kind == JValue::Kind::number)
            std::puts(human_bytes(static_cast<std::uint64_t>(v->n)).c_str());
        else std::puts(value_text(*v).c_str());
        return 0;
    }

    if (sub == "set") {
        // `set ENV key value...` or `set ENV key=value key=value ...`
        if (argc < 5) return fail("usage: linuxity set [env] key=value ...   (or: set [env] key value)");
        std::vector<std::pair<std::string, std::vector<std::string>>> edits;
        if (std::string_view{argv[4]}.find('=') != std::string_view::npos) {
            for (int i = 4; i < argc; ++i) {
                const std::string kv = argv[i];
                const auto eq = kv.find('=');
                if (eq == std::string::npos || eq == 0) return fail("'" + kv + "' is not key=value");
                edits.push_back({resolve_key(kv.substr(0, eq)), {kv.substr(eq + 1)}});
            }
        } else {
            if (argc < 6) return fail("usage: linuxity set [env] key value");
            std::vector<std::string> words;
            for (int i = 5; i < argc; ++i) words.emplace_back(argv[i]);
            edits.push_back({resolve_key(argv[4]), words});
        }
        auto text = slurp(s.config_path(name)).value_or("");
        for (const auto& [key, words] : edits) {
            std::optional<std::string> next;
            if (words.size() == 1 && words[0].empty()) next = vibe_edit::unset(text, key);   // key= unsets
            else {
                std::string why;
                const auto v = render_value(key, words, why);
                if (!v) return fail(why);
                next = vibe_edit::set(text, key, *v);
            }
            if (!next) return fail("cannot edit " + s.config_path(name) + " automatically; use `linuxity edit`");
            text = *next;
        }
        return save_config(s, name, text);
    }

    if (sub == "unset") {
        if (argc < 5) return fail("usage: linuxity env unset <name> <key>");
        const auto cur = slurp(s.config_path(name)).value_or("");
        const auto next = vibe_edit::unset(cur, resolve_key(argv[4]));
        if (!next) return fail("cannot edit " + s.config_path(name) + " automatically; use `linuxity edit`");
        return save_config(s, name, *next);
    }

    if (sub == "edit") {
        const char* ed = std::getenv("VISUAL");
        if (!ed || !*ed) ed = std::getenv("EDITOR");
        if (!ed || !*ed) ed = "vi";
        const std::string file = s.config_path(name);
        const auto before = slurp(file).value_or("");
        for (;;) {
            const std::string cmd = std::string{ed} + " '" + file + "'";
            if (std::system(cmd.c_str()) != 0) return fail("editor failed");
            auto r = s.load(name);
            std::vector<Diag> d = r.diags;
            check_runnable(r.config, d);
            if (r.ok() && std::none_of(d.begin(), d.end(), [](const Diag& x) { return x.error; })) break;
            (void)print_diags(d, file, false);
            std::fprintf(stderr, "edit again? [Y/n] ");
            char a[8] = {0};
            if (!std::fgets(a, sizeof a, stdin) || a[0] == 'n' || a[0] == 'N') {
                (void)write_file_atomic(file, before);
                return fail("kept the old config");
            }
        }
        const auto after = slurp(file).value_or("");
        if (after != before) return save_config(s, name, after);
        return 0;
    }

    // stop a running environment (reset/restore/rename need it down)
    auto stop_env = [&] {
        if (s.running_pid(name) <= 0) return;
        Conn c;
        if (connect_env(name, c)) { (void)request(c, R"({"op":"down"})"); std::string l; while (c.in.read_line(l)) {} }
    };

    if (sub == "reset") {
        if (!has_flag(argc, argv, "--yes") && ::isatty(0)) {
            std::fprintf(stderr, "drop every change made in %s%s? [y/N] ", name.c_str(),
                         s.running_pid(name) > 0 ? " (it's running and will be stopped)" : "");
            char a[8] = {0};
            if (!std::fgets(a, sizeof a, stdin) || (a[0] != 'y' && a[0] != 'Y')) return 1;
        }
        stop_env();
        if (const auto e = s.reset(name); !e.empty()) return fail(e);
        std::printf("%s is back to the clean image\n", name.c_str());
        // the login user was one of the changes; make it again so `linuxity`
        // keeps working (its password, if it had one, isn't kept)
        const auto r = s.load(name);
        std::vector<std::string> layers{r.config.upper, r.config.rootfs};
        if (r.config.user != "root" && !resolve_user(layers, r.config.user) && !has_flag(argc, argv, "--no-user")) {
            std::printf("setting up %s again...\n", r.config.user.c_str());
            std::vector<std::string> a = {"linuxity", "env", "adduser", name, r.config.user};
            if (!r.config.shell.empty()) { a.emplace_back("--shell"); a.push_back(r.config.shell); }
            std::vector<char*> av;
            for (auto& x : a) av.push_back(x.data());
            if (cmd_adduser(s, name, static_cast<int>(av.size()), av.data()) != 0)
                return fail("couldn't set up " + r.config.user + " again; log in as root: linuxity shell " + name + " -u root");
        }
        return 0;
    }

    if (sub == "snapshot") {
        if (argc < 5) return fail("usage: linuxity env snapshot <name> <snapshot>");
        if (s.running_pid(name) > 0)
            std::fprintf(stderr, "linuxity: %s is running; the snapshot may catch files mid-write\n", name.c_str());
        if (const auto e = s.snapshot(name, argv[4]); !e.empty()) return fail(e);
        std::printf("saved %s as %s\n", name.c_str(), argv[4]);
        return 0;
    }

    if (sub == "restore") {
        if (argc < 5) return fail("usage: linuxity restore <env> <snapshot>");
        stop_env();
        if (const auto e = s.restore(name, argv[4]); !e.empty()) return fail(e);
        std::printf("%s restored to %s\n", name.c_str(), argv[4]);
        return 0;
    }

    if (sub == "snapshots") {
        const auto snaps = s.snapshots(name);
        if (json) {
            Json j;
            j.obj().kv("snapshots", snaps).end();
            std::puts(j.text().c_str());
            return 0;
        }
        for (const auto& x : snaps)
            std::printf("%-20s %s\n", x.c_str(), human_bytes(tree_bytes(s.snapshots_dir(name) + "/" + x)).c_str());
        return 0;
    }

    if (sub == "drop-snapshot") {
        if (argc < 5) return fail("usage: linuxity env drop-snapshot <name> <snapshot>");
        if (const auto e = s.drop_snapshot(name, argv[4]); !e.empty()) return fail(e);
        return 0;
    }

    if (sub == "rm" || sub == "remove") {
        const auto r = s.load(name);
        const bool owns_rootfs = r.config.rootfs.starts_with(s.dir(name) + "/");
        if (!has_flag(argc, argv, "--yes") && ::isatty(0)) {
            std::fprintf(stderr, "remove %s and everything in it%s? [y/N] ", name.c_str(),
                         owns_rootfs ? "" : (" (" + r.config.rootfs + " itself is kept)").c_str());
            char a[8] = {0};
            if (!std::fgets(a, sizeof a, stdin) || (a[0] != 'y' && a[0] != 'Y')) return 1;
        }
        if (s.running_pid(name) > 0) {
            Conn c;
            if (connect_env(name, c)) { (void)request(c, R"({"op":"down"})"); std::string l; while (c.in.read_line(l)) {} }
        }
        const bool was_default = s.default_env() == name;
        if (const auto e = s.remove(name); !e.empty()) return fail(e);
        if (was_default) ::unlink((s.home() + "/default").c_str());
        std::printf("removed %s\n", name.c_str());
        return 0;
    }

    if (sub == "rename") {
        if (argc < 5) return fail("usage: linuxity rename <old> <new>");
        stop_env();
        const bool was_default = s.default_env() == name;
        if (const auto e = s.rename(name, argv[4]); !e.empty()) return fail(e);
        if (was_default) (void)s.set_default(argv[4]);
        return 0;
    }

    if (sub == "users") return cmd_users(s, name, json);

    if (sub == "adduser") return cmd_adduser(s, name, argc, argv);

    return fail("unknown env command '" + std::string{sub} + "' (see `linuxity help`)");
}

}  // namespace

// Commands that act on one environment take its name first; leave it out and
// the default is used (`linuxity set memory=2G`, `linuxity exec -- ls`).
// Only when that's unambiguous: a word that isn't an environment is an error,
// never a reason to act on a different one, and commands that destroy data
// always need the name spelled out.
std::vector<std::string> lx_with_default_env(int argc, char** argv) {
    std::vector<std::string> a(argv, argv + argc);
    if (argc < 2) return a;
    Store s;
    if (argc >= 3 && s.has(argv[2])) return a;
    const std::string_view verb = argv[1];
    for (const char* v : {"rm", "remove", "reset", "restore", "rename", "drop-snapshot", "import"})
        if (verb == v) return a;
    const std::string d = s.default_env();
    if (d.empty()) return a;
    bool insert = argc < 3;
    if (!insert) {
        const std::string_view next = argv[2];
        if (next.starts_with("-")) insert = true;                       // flags or `--`
        else if (verb == "set" || verb == "get" || verb == "unset")
            insert = next.find('=') != std::string_view::npos || find_field(resolve_key(std::string{next})) ||
                     find_dyn_field(std::string{next});
        else if (verb == "snapshot" || verb == "adduser" || verb == "export" || verb == "kill" ||
                 verb == "logs" || verb == "svc")
            insert = true;   // their first word is a user, file, pid or service, never an env
    }
    if (insert) a.insert(a.begin() + 2, d);
    return a;
}

namespace {

int no_env_yet() {
    std::puts("No Linux environments yet. Make one:\n");
    for (const auto& i : kImages)
        if (i.arch == kHostArch)
            std::printf("  linuxity new %-8s %s\n", std::string{i.distro}.c_str(), std::string{i.title}.c_str());
    std::puts("\nor bring your own:  linuxity import <name> <rootfs.tar.gz>");
    return 1;
}

int run_argv(int (*fn)(int, char**), std::vector<std::string> a) {
    std::vector<char*> av;
    for (auto& x : a) av.push_back(x.data());
    av.push_back(nullptr);
    return fn(static_cast<int>(a.size()), av.data());
}

}  // namespace

// ---- shell completion --------------------------------------------------
// `linuxity __complete W1 W2 ... CUR` prints the candidates for CUR, one
// per line. The shell scripts below only forward their words, so every
// shell completes exactly the same things -- from the verb table, the
// environments, the settings schema and the image catalog.
int cmd_complete(int argc, char** argv) {
    using namespace lx::cli;
    std::vector<std::string> w(argv + 2, argv + argc);
    if (w.empty()) w.emplace_back();
    const std::string cur = w.back();
    w.pop_back();
    const bool bg = host_runs_instances();
    auto emit = [&](std::string_view c) {
        if (std::string_view{c}.starts_with(cur)) std::printf("%.*s\n", static_cast<int>(c.size()), c.data());
    };
    if (w.empty()) {   // the verb itself
        for (const auto& v : kVerbTable) if (verb_listed(v, bg)) emit(v.name);
        return 0;
    }
    const Verb* v = canonical_verb(w[0]);
    if (!v) return 0;
    std::vector<std::string> pos;   // positionals typed so far (flags skipped)
    for (std::size_t i = 1; i < w.size(); ++i) {
        if (w[i] == "--") return 0;  // a guest command line: the shell's own files
        if (!w[i].starts_with("-")) pos.push_back(w[i]);
    }
    Store s;
    const auto names = s.names();
    auto envs = [&] { for (const auto& n : names) emit(n); };
    auto keys = [&] { for (const auto& f : kFields) emit(f.path); };
    const bool named = !pos.empty() && s.has(pos[0]);
    switch (v->arg) {
        case VerbArg::env:
            if (pos.empty()) envs();
            break;
        case VerbArg::env_key:
            if (pos.empty()) { envs(); keys(); }
            else if (pos.size() == 1 && named) keys();
            break;
        case VerbArg::env_snapshot: {
            const std::string env = named ? pos[0] : s.default_env();
            if (pos.empty()) envs();
            if (pos.size() == (named ? 1u : 0u) && !env.empty())
                for (const auto& snap : s.snapshots(env)) emit(snap);
            break;
        }
        case VerbArg::image:
            if (pos.empty())
                for (const auto& i : kImages)
                    if (i.arch == kHostArch) emit(i.distro);
            break;
        case VerbArg::verb:
            if (pos.empty()) for (const auto& x : kVerbTable) if (verb_listed(x, bg)) emit(x.name);
            break;
        case VerbArg::shell:
            if (pos.empty()) for (const char* sh : {"bash", "zsh", "fish"}) emit(sh);
            break;
        case VerbArg::none:
            break;
    }
    return 0;
}

int cmd_completion(std::string_view shell) {
    if (shell == "bash") {
        std::puts(
            "# linuxity bash completion: source <(linuxity completion bash)\n"
            "_linuxity() {\n"
            "    local IFS=$'\\n'\n"
            "    COMPREPLY=($(command linuxity __complete \"${COMP_WORDS[@]:1:COMP_CWORD}\" 2>/dev/null))\n"
            "}\n"
            "complete -o default -o bashdefault -F _linuxity linuxity");
        return 0;
    }
    if (shell == "zsh") {
        std::puts(
            "#compdef linuxity\n"
            "# linuxity zsh completion: source <(linuxity completion zsh), or save as _linuxity in $fpath\n"
            "_linuxity() {\n"
            "    local -a c\n"
            "    c=(${(f)\"$(command linuxity __complete \"${(@)words[2,CURRENT]}\" 2>/dev/null)\"})\n"
            "    (( ${#c} )) && compadd -a c || _files\n"
            "}\n"
            "if (( $+functions[compdef] )); then compdef _linuxity linuxity; else _linuxity \"$@\"; fi");
        return 0;
    }
    if (shell == "fish") {
        std::puts(
            "# linuxity fish completion: linuxity completion fish > ~/.config/fish/completions/linuxity.fish\n"
            "function __linuxity_complete\n"
            "    set -l words (commandline -opc)\n"
            "    set -l cur (commandline -ct)\n"
            "    command linuxity __complete $words[2..-1] \"$cur\" 2>/dev/null\n"
            "end\n"
            "complete -c linuxity -f -a '(__linuxity_complete)'\n"
            "complete -c linuxity -n '__fish_seen_subcommand_from import export' -F");
        return 0;
    }
    std::fputs(
        "usage: linuxity completion bash|zsh|fish\n"
        "\n"
        "  bash   echo 'source <(linuxity completion bash)' >> ~/.bashrc\n"
        "  zsh    echo 'source <(linuxity completion zsh)' >> ~/.zshrc\n"
        "  fish   linuxity completion fish > ~/.config/fish/completions/linuxity.fish\n", stderr);
    return shell.empty() ? 0 : 2;
}

int lx_cli_main(int argc, char** argv) {
    Store s;
    // `linuxity` alone: a shell in the default environment
    if (argc < 2) {
        const std::string d = s.default_env();
        if (d.empty()) {
            if (s.names().empty()) return no_env_yet();
            std::puts("Which one? Pick a default with: linuxity default <name>\n");
            return run_argv(cmd_env, {argv[0], "env", "list"});
        }
        return run_argv([](int c, char** v) { return cmd_shell(c, v, false); }, {argv[0], "shell", d});
    }
    const std::string sub = argv[1];
    if (sub == "help" || sub == "--help" || sub == "-h") {
        if (argc > 2 && std::string_view{argv[2]} != "--all") return help_verb(argv[2]);
        help();
        return 0;
    }
    if (sub == "completion") return cmd_completion(argc > 2 ? argv[2] : "");
    if (sub == "__complete") return cmd_complete(argc, argv);
    if (sub == "version" || sub == "--version") { std::puts("linuxity 0.1.0"); return 0; }
    if (sub == "env") return cmd_env(argc, argv);
    if (sub == "new") return cmd_new(argc, argv);
    if (sub == "import") return cmd_import(argc, argv);
    if (sub == "images") return cmd_images(has_flag(argc, argv, "--json"));
    if (sub == "schema") { std::puts(schema_json().c_str()); return 0; }
    if (sub == "list" || sub == "ls") {
        if (s.names().empty() && !has_flag(argc, argv, "--json")) return no_env_yet();
        std::vector<std::string> a = {argv[0], "env", "list"};
        for (int i = 2; i < argc; ++i) a.emplace_back(argv[i]);
        return run_argv(cmd_env, a);
    }
    if (sub == "default") {
        if (argc < 3) {
            const auto d = s.default_env();
            if (d.empty()) return fail("no default environment; set one with: linuxity default <name>");
            std::puts(d.c_str());
            return 0;
        }
        if (!s.has(argv[2])) return fail("no environment '" + std::string{argv[2]} + "'");
        if (!s.set_default(argv[2])) return fail("cannot write the default");
        std::printf("`linuxity` now opens %s\n", argv[2]);
        return 0;
    }

    // everything below acts on one environment, the default if not named
    auto a = lx_with_default_env(argc, argv);
    if (a.size() < 3 || !s.has(a[2])) {
        if (s.names().empty()) return no_env_yet();
        if (a.size() >= 3 && !a[2].starts_with("-"))
            return fail("no environment '" + a[2] + "' (see `linuxity list`)");
        return fail("which environment? (see `linuxity list`, or set one with `linuxity default <name>`)");
    }
    if (const auto* v = lx::cli::find_verb(sub); v && v->via_env) {
        a.insert(a.begin() + 1, "env");
        return run_argv(cmd_env, a);
    }
    if (sub == "export") return run_argv(cmd_export, a);
    if (sub == "shell") return run_argv([](int c, char** v) { return cmd_shell(c, v, false); }, a);
    if (sub == "exec") return run_argv([](int c, char** v) { return cmd_shell(c, v, true); }, a);
    if (sub == "ps") return run_argv(cmd_ps, a);
    if (sub == "kill") return run_argv(cmd_kill, a);
    if (sub == "status") return run_argv(cmd_status, a);
    if (sub == "svc") return run_argv(cmd_svc, a);
    if (sub == "down" || sub == "stop") return run_argv(cmd_down, a);
    if (sub == "reload") return run_argv(cmd_reload, a);
    if (sub == "logs") return run_argv(cmd_logs, a);
    help();
    return 2;
}
