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
#include "linuxity/env/config.hpp"
#include "linuxity/env/control.hpp"
#include "linuxity/env/json.hpp"
#include "linuxity/env/json_read.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/env/vibe_edit.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

extern char** environ;

namespace {

using namespace lx::env;

int fail(const std::string& why) {
    std::fprintf(stderr, "linuxity: %s\n", why.c_str());
    return 1;
}

bool has_flag(int argc, char** argv, std::string_view f) {
    for (int i = 0; i < argc; ++i) if (f == argv[i]) return true;
    return false;
}

std::string self_exe() {
    char buf[4096];
    const ::ssize_t n = ::readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return "linuxity";
    buf[n] = '\0';
    return buf;
}

void help() {
    std::puts(
        "linuxity: a Linux userland without a VM.\n"
        "\n"
        "environments\n"
        "  env create <name> <rootfs> [--set key=value ...]   new environment\n"
        "  env list [--json]                                 every environment\n"
        "  env info <name> [--json]                          config, disk use, state\n"
        "  env get <name> <key>          env set <name> <key> <value>\n"
        "  env unset <name> <key>        env edit <name>      ($EDITOR on env.vibe)\n"
        "  env check <name> [--json]     validate env.vibe\n"
        "  env schema                    every key, as JSON (for frontends)\n"
        "  env path <name>               where it lives on disk\n"
        "  env reset <name>              drop every change, back to the clean image\n"
        "  env snapshot <name> <snap>    env restore <name> <snap>\n"
        "  env snapshots <name>          env drop-snapshot <name> <snap>\n"
        "  env rename <old> <new>        env rm <name>\n"
        "  env adduser <name> <user> [--sudo]   create a guest user\n"
        "\n"
        "running\n"
        "  run <env> [-- cmd ...]        one program in the foreground (pid 1)\n"
        "  up <env> [--foreground]       start the environment (services, sessions)\n"
        "  shell <env> [--user U]        a login shell in it (starts it if needed)\n"
        "  exec <env> [--user U] [--cwd D] [-e K=V] [-t|-T] -- cmd ...\n"
        "  ps <env> [--json]             kill <env> <pid> [signal]\n"
        "  status <env> [--json]         reload <env>   (apply env.vibe changes)\n"
        "  svc <env> [list|start|stop|restart] [name]\n"
        "  logs <env> [service] [-f]     down <env>\n"
        "\n"
        "Without a subcommand: linuxity [OPTIONS] <program> [args...]  (see --help).\n"
        "Environments live in $LINUXITY_HOME (default ~/.local/share/linuxity).");
}

// ---- talking to an instance ------------------------------------------------

struct Conn {
    int fd{-1};
    control::LineReader in;
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

// Start the instance (as `linuxity up`) if it isn't running.
bool ensure_up(const std::string& name, Conn& c) {
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
    if (Store{}.has(name)) fail(name + " is not running (start it with `linuxity up " + name + "`)");
    return false;
}

int print_reply(const std::optional<JValue>& r) {
    if (!r) return fail("lost the connection to the instance");
    if (!r->flag("ok")) return fail(r->str("error", "request failed"));
    return 0;
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
                bool tty) {
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
        fds = {0, 1, 2};
        j.kv("fds", 3);
        if (print_reply(request(c, j.end().take(), fds))) return 1;
    }

    // wait for {"event":"exit"}; relay the terminal meanwhile
    RawTty raw;
    if (tty) raw.enter();
    ::sigset_t s;
    ::sigemptyset(&s);
    ::sigaddset(&s, SIGWINCH);
    ::sigprocmask(SIG_BLOCK, &s, nullptr);
    const int sfd = tty ? ::signalfd(-1, &s, SFD_CLOEXEC) : -1;
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
            ::signalfd_siginfo si{};
            (void)!::read(sfd, &si, sizeof si);
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
    if (argc < 3) return fail("usage: linuxity down <env>");
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
        std::printf("other changes need a restart: linuxity down %s && linuxity up %s\n", argv[2], argv[2]);
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
    // follow: inotify on the file, no polling loop
    const int in = ::inotify_init1(IN_CLOEXEC);
    if (in < 0 || ::inotify_add_watch(in, file.c_str(), IN_MODIFY) < 0) { ::close(fd); return fail("cannot watch " + file); }
    for (;;) {
        char ev[4096];
        if (::read(in, ev, sizeof ev) < 0 && errno != EINTR) break;
        while ((n = ::read(fd, buf, sizeof buf)) > 0) write_all(1, buf, static_cast<std::size_t>(n));
    }
    return 0;
}

// ---- env management ---------------------------------------------------------------

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
        // one word with spaces is split, several words are the list
        std::vector<std::string> items = words;
        if (items.size() == 1 && items[0].find(' ') != std::string::npos) {
            items.clear();
            std::string_view s = words[0];
            while (!s.empty()) {
                const auto sp = s.find(' ');
                if (sp != 0) items.emplace_back(s.substr(0, sp));
                if (sp == std::string_view::npos) break;
                s.remove_prefix(sp + 1);
            }
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
            std::fprintf(stderr, "linuxity: %s is running; restart it for this to take effect\n", name.c_str());
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
        if (names.empty()) { std::puts("no environments yet: linuxity env create <name> <rootfs>"); return 0; }
        std::printf("%-16s %-9s %-10s %s\n", "NAME", "STATE", "USER", "ROOTFS");
        for (const auto& n : names) {
            const auto r = s.load(n);
            std::printf("%-16s %-9s %-10s %s%s\n", n.c_str(), s.running_pid(n) > 0 ? "running" : "stopped",
                        r.config.user.c_str(), r.config.rootfs.c_str(), r.ok() ? "" : "  (config has errors)");
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
        if (argc < 5) return fail("usage: linuxity env get <name> <key>");
        auto r = s.load(name);
        const auto cj = parse_json(config_json(r.config));
        const JValue* v = cj ? &*cj : nullptr;
        std::string_view k = argv[4];
        while (v && !k.empty()) {
            const auto d = k.find('.');
            v = v->get(k.substr(0, d));
            if (d == std::string_view::npos) break;
            k.remove_prefix(d + 1);
        }
        if (!v) return fail("no key '" + std::string{argv[4]} + "'");
        std::puts(value_text(*v).c_str());
        return 0;
    }

    if (sub == "set") {
        if (argc < 6) return fail("usage: linuxity env set <name> <key> <value...>");
        std::vector<std::string> words;
        for (int i = 5; i < argc; ++i) words.emplace_back(argv[i]);
        std::string why;
        const auto text = render_value(argv[4], words, why);
        if (!text) return fail(why);
        const auto cur = slurp(s.config_path(name)).value_or("");
        const auto next = vibe_edit::set(cur, argv[4], *text);
        if (!next) return fail("cannot edit " + s.config_path(name) + " automatically; use `linuxity env edit`");
        return save_config(s, name, *next);
    }

    if (sub == "unset") {
        if (argc < 5) return fail("usage: linuxity env unset <name> <key>");
        const auto cur = slurp(s.config_path(name)).value_or("");
        const auto next = vibe_edit::unset(cur, argv[4]);
        if (!next) return fail("cannot edit " + s.config_path(name) + " automatically; use `linuxity env edit`");
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

    if (sub == "reset") {
        if (s.running_pid(name) > 0) return fail(name + " is running; stop it first (linuxity down " + name + ")");
        if (!has_flag(argc, argv, "--yes") && ::isatty(0)) {
            std::fprintf(stderr, "drop every change made in %s? [y/N] ", name.c_str());
            char a[8] = {0};
            if (!std::fgets(a, sizeof a, stdin) || (a[0] != 'y' && a[0] != 'Y')) return 1;
        }
        if (const auto e = s.reset(name); !e.empty()) return fail(e);
        std::printf("%s is back to the clean image\n", name.c_str());
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
        if (argc < 5) return fail("usage: linuxity env restore <name> <snapshot>");
        if (s.running_pid(name) > 0) return fail(name + " is running; stop it first");
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
        if (s.running_pid(name) > 0) return fail(name + " is running; stop it first");
        if (!has_flag(argc, argv, "--yes") && ::isatty(0)) {
            std::fprintf(stderr, "remove %s and all its changes? (the rootfs is kept) [y/N] ", name.c_str());
            char a[8] = {0};
            if (!std::fgets(a, sizeof a, stdin) || (a[0] != 'y' && a[0] != 'Y')) return 1;
        }
        if (const auto e = s.remove(name); !e.empty()) return fail(e);
        return 0;
    }

    if (sub == "rename") {
        if (argc < 5) return fail("usage: linuxity env rename <old> <new>");
        if (s.running_pid(name) > 0) return fail(name + " is running; stop it first");
        if (const auto e = s.rename(name, argv[4]); !e.empty()) return fail(e);
        return 0;
    }

    if (sub == "adduser") {
        if (argc < 5) return fail("usage: linuxity env adduser <name> <user> [--sudo] [--shell PATH]");
        const std::string user = argv[4];
        std::string shell = "/bin/bash";
        for (int i = 5; i + 1 < argc; ++i) if (std::string_view{argv[i]} == "--shell") shell = argv[i + 1];
        const bool sudo = has_flag(argc, argv, "--sudo");
        // run the guest's own useradd as root, as a one-shot pid 1
        const auto r = s.load(name);
        auto exists_in = [&](const char* p) {
            return exists(r.config.upper + p) || exists(r.config.rootfs + p);
        };
        std::string script;
        if (exists_in("/usr/bin/useradd") || exists_in("/usr/sbin/useradd") || exists_in("/sbin/useradd")) {
            script = "useradd -m -U -s '" + shell + "' '" + user + "'";
            if (sudo) script += " && (getent group wheel >/dev/null && usermod -aG wheel '" + user +
                                "' || usermod -aG sudo '" + user + "')";
        } else if (exists_in("/usr/sbin/adduser") || exists_in("/bin/busybox")) {
            script = "adduser -D -s '" + shell + "' '" + user + "'";
            if (sudo) script += " && addgroup '" + user + "' wheel";
        } else {
            return fail("the image has no useradd or adduser");
        }
        if (sudo)
            script += " && mkdir -p /etc/sudoers.d && echo '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/10-wheel"
                      " && chmod 440 /etc/sudoers.d/10-wheel";
        const std::string exe = self_exe();
        const ::pid_t pid = ::fork();
        if (pid == 0) {
            ::execl(exe.c_str(), exe.c_str(), "run", name.c_str(), "--user", "root", "--quiet", "--",
                    "/bin/sh", "-c", script.c_str(), static_cast<char*>(nullptr));
            ::_exit(127);
        }
        int st = 0;
        ::waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return fail("adding " + user + " failed");
        std::printf("added %s to %s. Make it the default: linuxity env set %s login.user %s\n",
                    user.c_str(), name.c_str(), name.c_str(), user.c_str());
        return 0;
    }

    return fail("unknown env command '" + std::string{sub} + "' (see `linuxity help`)");
}

}  // namespace

int lx_cli_main(int argc, char** argv) {
    const std::string_view sub = argv[1];
    if (sub == "help" || sub == "--help" || sub == "-h") { help(); return 0; }
    if (sub == "version") { std::puts("linuxity 0.1.0"); return 0; }
    if (sub == "env") return cmd_env(argc, argv);
    if (sub == "shell") return cmd_shell(argc, argv, false);
    if (sub == "exec") return cmd_shell(argc, argv, true);
    if (sub == "ps") return cmd_ps(argc, argv);
    if (sub == "kill") return cmd_kill(argc, argv);
    if (sub == "status") return cmd_status(argc, argv);
    if (sub == "svc") return cmd_svc(argc, argv);
    if (sub == "down") return cmd_down(argc, argv);
    if (sub == "reload") return cmd_reload(argc, argv);
    if (sub == "logs") return cmd_logs(argc, argv);
    help();
    return 2;
}
