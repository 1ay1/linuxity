// src/supervisor.hpp -- the long-running side of an environment.
//
// `linuxity up` runs the trap with no root program (instance mode) and this
// class serves the control socket from the trap's idle hook. Everything is
// on one thread: the trap calls idle() when no task needs it (and every
// ~10ms while guests are busy), so there is nothing to lock beyond the
// kernel mutex the dispatcher already uses.
//
// What it does:
//   * sessions: start a process as a new session leader, a child of guest
//     init, with fds the client handed over (its pty, or plain pipes)
//   * services: start the env's [service.*] at boot, restart them on exit
//   * ps / kill / status / reload / down for the CLI and the app
//   * the bridge: guest programs (xdg-open, wl-copy, notify-send) reach the
//     host through an abstract socket; requests go to an attached app, else
//     to host tools
#pragma once

#include "options.hpp"

#include "linuxity/env/config.hpp"
#include "linuxity/env/control.hpp"
#include "linuxity/env/json.hpp"
#include "linuxity/env/json_read.hpp"
#include "linuxity/env/passwd.hpp"
#include "linuxity/env/status.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/runtime/linux/ptrace_trap.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

extern char** environ;

// the static guest helper, embedded at build time (bridge_blob.S)
extern "C" const unsigned char lx_bridge_blob[];
extern "C" const unsigned char lx_bridge_blob_end[];

namespace lx::cli {

using Kern = kernel::Kernel<host::PosixHost>;

// How to start a guest program: the HOST path to execve and its argv.
struct Launch {
    std::string exec_path;
    std::vector<std::string> argv;
    std::string error;
};

// What main.cpp hands the supervisor: the pieces of its own setup.
struct RuntimeHooks {
    std::function<Launch(const std::string& guest_path, const std::vector<std::string>& argv)> prepare;
    std::function<std::string(const std::string& name, const std::string& path_var)> which;
    std::function<void()> pre_exec;           // resource governor + low fds
    std::vector<std::string> base_env;        // NAME=value, no per-user vars
    std::vector<std::string> layers;          // host dirs, top first (for passwd)
    std::shared_ptr<std::string> resolv;      // served /etc/resolv.conf, live
    std::string limits_text;                  // how limits are enforced
    bool cgroup{false};                       // limits held by a cgroup
};

class Supervisor {
public:
    Supervisor(Kern& k, runtime::PtraceTrap& trap, Options& o, RuntimeHooks h)
        : k_{k}, trap_{trap}, o_{o}, h_{std::move(h)} {}

    ~Supervisor() { cleanup(); }

    // Listen, start services, tell the launcher we're up.
    bool start(std::string& why) {
        started_ = std::chrono::steady_clock::now();
        if (!env::mkdirs(o_.run_dir) || !env::mkdirs(o_.logs_dir)) {
            why = "cannot create " + o_.run_dir;
            return false;
        }
        lock_fd_ = ::open((o_.run_dir + "/lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (lock_fd_ < 0 || ::flock(lock_fd_, LOCK_EX | LOCK_NB) != 0) {
            why = "already running";
            return false;
        }
        listener_ = env::control::listen_at(o_.control_path, why);
        if (listener_.fd < 0) { why = "control socket: " + why; return false; }

        // stop signals arrive here instead of killing us mid-dispatch
        ::sigset_t s;
        ::sigemptyset(&s);
        for (const int sig : {SIGTERM, SIGINT, SIGHUP}) ::sigaddset(&s, sig);
        (void)::pthread_sigmask(SIG_BLOCK, &s, nullptr);
        sig_fd_ = ::signalfd(-1, &s, SFD_NONBLOCK | SFD_CLOEXEC);
        // orphaned guests come back to us, not to the host's init
        (void)::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

        if (o_.cfg.bridge) start_bridge();

        (void)env::write_file_atomic(o_.pid_path, std::to_string(::getpid()) + "\n");
        for (auto& sc : o_.cfg.services) {
            Svc sv;
            sv.cfg = sc;
            services_[sc.name] = std::move(sv);
        }
        for (auto& [name, sv] : services_)
            if (sv.cfg.autostart) start_service(sv);

        env::status().event("ready", "instance " + o_.env_name + " is up (pid " +
                                         std::to_string(::getpid()) + ")",
                            [&](env::Json& j) {
                                j.kv("env", o_.env_name).kv("pid", static_cast<std::int64_t>(::getpid()))
                                    .kv("socket", o_.control_path).kv("abstract", listener_.abstract);
                            });
        if (o_.ready_fd >= 0) {
            (void)!::write(o_.ready_fd, "ok\n", 3);
            ::close(o_.ready_fd);
            o_.ready_fd = -1;
        }
        return true;
    }

    // The trap's idle hook. `block`: wait for something to happen.
    bool idle(int chld_fd, bool block) {
        std::vector<::pollfd> p;
        p.push_back({chld_fd, POLLIN, 0});
        p.push_back({listener_.fd, POLLIN, 0});
        p.push_back({sig_fd_, POLLIN, 0});
        if (bridge_listen_ >= 0) p.push_back({bridge_listen_, POLLIN, 0});
        const std::size_t first_client = p.size();
        for (const auto& c : clients_) p.push_back({c->fd, POLLIN, 0});
        const std::size_t first_bridge = p.size();
        for (const auto& b : bridge_conns_) p.push_back({b->fd, POLLIN, 0});
        const std::size_t first_job = p.size();
        for (const auto& j : jobs_) p.push_back({j.out_fd, POLLIN, 0});

        int timeout = block ? next_timer_ms() : 0;
        const int n = ::poll(p.data(), p.size(), timeout);
        if (n < 0 && errno != EINTR) return false;

        if (p[2].revents & POLLIN) on_signal();
        if (p[1].revents & POLLIN) accept_clients();
        if (bridge_listen_ >= 0 && (p[3].revents & POLLIN)) accept_bridge();

        // work on copies of the fds: handlers may drop entries
        std::vector<int> ready_clients, ready_bridges, ready_jobs;
        for (std::size_t i = first_client; i < first_bridge; ++i)
            if (p[i].revents) ready_clients.push_back(p[i].fd);
        for (std::size_t i = first_bridge; i < first_job; ++i)
            if (p[i].revents) ready_bridges.push_back(p[i].fd);
        for (std::size_t i = first_job; i < p.size(); ++i)
            if (p[i].revents) ready_jobs.push_back(p[i].fd);
        for (const int fd : ready_clients) serve_client(fd);
        for (const int fd : ready_bridges) serve_bridge(fd);
        for (const int fd : ready_jobs) serve_job(fd);

        run_timers();
        return !stop_;
    }

    // Every process exit the trap sees: (host pid, guest pid, status).
    void on_exit(::pid_t host, std::int32_t g, int code) {
        if (g == 0) { job_exited(host, code); return; }
        if (auto it = sessions_.find(g); it != sessions_.end()) {
            Session s = std::move(it->second);
            sessions_.erase(it);
            env::Json j;
            j.obj().kv("event", "exit").kv("pid", g).kv("code", code).end();
            if (s.waiter >= 0) send(s.waiter, j.text());
            broadcast(j.text());
            if (!s.service.empty()) service_exited(s.service, code);
        }
    }

    void cleanup() {
        if (cleaned_) return;
        cleaned_ = true;
        for (auto& c : clients_) ::close(c->fd);
        clients_.clear();
        for (auto& b : bridge_conns_) ::close(b->fd);
        bridge_conns_.clear();
        if (listener_.fd >= 0) {
            ::close(listener_.fd);
            if (!listener_.abstract) ::unlink(o_.control_path.c_str());
        }
        if (bridge_listen_ >= 0) ::close(bridge_listen_);
        ::unlink(o_.pid_path.c_str());
        if (lock_fd_ >= 0) ::close(lock_fd_);
    }

private:
    // ---- state -----------------------------------------------------------

    struct Client {
        int fd;
        env::control::LineReader in;
        bool events{false};
        bool bridge{false};
        explicit Client(int f) : fd{f}, in{f} {}
    };
    struct Session {
        ::pid_t host{-1};
        int waiter{-1};          // client fd waiting for the exit, or -1
        std::string service;     // owning service, if any
        std::string user;
        std::vector<std::string> argv;
        std::chrono::steady_clock::time_point started;
    };
    enum class SvcState { stopped, running, backoff, failed };
    struct Svc {
        env::Service cfg;
        SvcState state{SvcState::stopped};
        std::int32_t pid{0};
        int restarts{0};
        int last_code{0};
        bool stopping{false};
        bool restart_after_stop{false};
        std::chrono::steady_clock::time_point started{}, next_start{};
        int quick_exits{0};
    };
    struct BridgeConn {
        int fd;
        env::control::LineReader in;
        explicit BridgeConn(int f) : fd{f}, in{f} {}
    };
    // a host helper the bridge ran (xdg-open, wl-paste, ...)
    struct Job {
        ::pid_t pid;
        int out_fd;              // its stdout, when we want the text
        int reply_to;            // bridge connection waiting for it
        std::string text;
        bool want_text{false};
    };

    // ---- control clients -------------------------------------------------

    void accept_clients() {
        for (;;) {
            const int fd = ::accept4(listener_.fd, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
            if (fd < 0) return;
            // only our own uid may drive the instance
            ::ucred cr{};
            socklen_t len = sizeof cr;
            if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0 || cr.uid != ::getuid()) {
                ::close(fd);
                continue;
            }
            clients_.push_back(std::make_unique<Client>(fd));
        }
    }

    Client* client_of(int fd) {
        for (auto& c : clients_) if (c->fd == fd) return c.get();
        return nullptr;
    }

    void drop_client(int fd) {
        for (auto& [g, s] : sessions_) if (s.waiter == fd) s.waiter = -1;
        std::erase_if(clients_, [fd](const auto& c) { return c->fd == fd; });
        ::close(fd);
    }

    void send(int fd, const std::string& line) {
        if (!env::control::send_line(fd, line)) {
            // a gone client is dropped on its next poll
        }
    }

    void broadcast(const std::string& line) {
        for (auto& c : clients_) if (c->events) send(c->fd, line);
    }

    static std::string error(std::string_view why) {
        env::Json j;
        return j.obj().kv("ok", false).kv("error", why).end().take();
    }
    static std::string ok() { return R"({"ok":true})"; }

    void serve_client(int fd) {
        Client* c = client_of(fd);
        if (!c) return;
        if (!c->in.fill()) { drop_client(fd); return; }
        std::string line;
        while ((c = client_of(fd)) && c->in.next(line)) {
            auto req = env::parse_json(line);
            if (!req || req->kind != env::JValue::Kind::object) { send(fd, error("bad request")); continue; }
            const std::string op = req->str("op");
            std::string reply;
            if (op == "hello") reply = hello();
            else if (op == "spawn") reply = spawn(*req, *c);
            else if (op == "ps") reply = ps();
            else if (op == "kill") reply = kill(*req);
            else if (op == "status") reply = status();
            else if (op == "svc") reply = svc(*req);
            else if (op == "reload") reply = reload();
            else if (op == "subscribe") {
                c->events = req->flag("events", true);
                c->bridge = req->flag("bridge", false);
                reply = ok();
            } else if (op == "bridge-reply") { bridge_reply(*req); continue; }
            else if (op == "down") {
                send(fd, ok());
                begin_stop();
                continue;
            } else {
                reply = error("unknown op '" + op + "'");
            }
            send(fd, reply);
        }
    }

    std::string hello() {
        env::Json j;
        return j.obj().kv("ok", true).kv("env", o_.env_name)
            .kv("pid", static_cast<std::int64_t>(::getpid())).kv("protocol", 1)
            .kv("sessions", static_cast<std::int64_t>(sessions_.size())).end().take();
    }

    // ---- sessions ----------------------------------------------------------

    // The environment a session gets: the instance's base, then the user's
    // identity, then what the client asked for.
    std::vector<std::string> session_env(const env::UserInfo& u, const std::string& shell,
                                         const std::vector<std::pair<std::string, std::string>>& extra) const {
        std::vector<std::string> e = h_.base_env;
        auto set = [&e](std::string_view k, std::string_view v) {
            const std::string pre = std::string{k} + "=";
            for (auto& kv : e) if (kv.starts_with(pre)) { kv = pre + std::string{v}; return; }
            e.push_back(pre + std::string{v});
        };
        set("USER", u.name);
        set("LOGNAME", u.name);
        set("HOME", u.home);
        set("SHELL", shell);
        if (!bridge_name_.empty()) set("LINUXITY_BRIDGE", bridge_name_);
        if (!helpers_path_.empty()) {
            const std::string p = env_get(e, "PATH");
            set("PATH", helpers_path_ + (p.empty() ? "" : ":" + p));
        }
        set("LINUXITY_ENV", o_.env_name);
        for (const auto& [k, v] : extra) set(k, v);
        return e;
    }

    [[nodiscard]] static std::string env_get(const std::vector<std::string>& e, std::string_view k) {
        const std::string pre = std::string{k} + "=";
        for (const auto& kv : e) if (kv.starts_with(pre)) return kv.substr(pre.size());
        return {};
    }

    struct SpawnSpec {
        std::vector<std::string> argv;    // empty = login shell
        std::vector<std::pair<std::string, std::string>> env;
        std::string user, cwd;
        std::vector<int> fds;             // 0..3; owned, closed after the fork
        std::string service;
    };

    // Start a session. Returns its guest pid, or 0 with `why`.
    std::int32_t start_session(SpawnSpec spec, std::string& why) {
        auto close_fds = [&spec] { for (const int f : spec.fds) ::close(f); spec.fds.clear(); };
        const std::string who = spec.user.empty() ? o_.user : spec.user;
        auto u = env::resolve_user(h_.layers, who);
        if (!u) {
            close_fds();
            why = "there's no user '" + who + "' in " + o_.env_name + " (a reset removes users). Add it back with `linuxity adduser " +
                  o_.env_name + " " + who + "`, or log in as root with `-u root`";
            return 0;
        }
        const std::string shell = !o_.shell.empty() && spec.user.empty() ? o_.shell : u->shell;
        std::vector<std::string> argv = spec.argv;
        if (argv.empty()) argv = o_.cfg.command;
        if (argv.empty()) argv = {shell, "-l"};
        auto envp = session_env(*u, shell, spec.env);
        std::string guest = argv[0];
        if (guest.find('/') == std::string::npos) {
            guest = h_.which(guest, env_get(envp, "PATH"));
            if (guest.empty()) { close_fds(); why = argv[0] + ": command not found"; return 0; }
        }
        Launch l = h_.prepare(guest, argv);
        if (!l.error.empty()) { close_fds(); why = l.error; return 0; }

        // fds: one means a terminal for all three, otherwise 0/1/2 in order
        int in = -1, out = -1, err = -1;
        if (spec.fds.size() == 1) in = out = err = spec.fds[0];
        else if (spec.fds.size() >= 3) { in = spec.fds[0]; out = spec.fds[1]; err = spec.fds[2]; }
        const int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
        if (in < 0) in = devnull;
        if (out < 0) out = devnull;
        if (err < 0) err = devnull;
        const bool tty = ::isatty(in) != 0;
        std::string pts;
        if (tty) {
            char buf[64];
            const std::string link = "/proc/self/fd/" + std::to_string(in);
            const ::ssize_t n = ::readlink(link.c_str(), buf, sizeof buf - 1);
            if (n > 0) { buf[n] = '\0'; if (std::string_view{buf}.starts_with("/dev/pts/")) pts = buf; }
        }

        auto setup = [in, out, err, tty] {
            (void)::setsid();
            ::dup2(in, 0);
            ::dup2(out, 1);
            ::dup2(err, 2);
            if (tty) (void)::ioctl(0, TIOCSCTTY, 0);
        };
        std::lock_guard g{k_.mutex()};
        const auto [host, gpid] = trap_.spawn(l.exec_path, l.argv, envp, h_.pre_exec, setup);
        close_fds();
        if (devnull >= 0) ::close(devnull);
        if (host < 0) { why = std::string{"fork failed: "} + std::strerror(errno); return 0; }

        // the guest's view of the new process
        kernel::ProcInfo pi;
        pi.pid = gpid;
        pi.ppid = k_.procs().init_pid();
        const auto slash = guest.find_last_of('/');
        pi.comm = guest.substr(slash + 1).substr(0, 15);
        pi.cmdline.clear();
        for (std::size_t i = 0; i < argv.size(); ++i) {
            if (i) pi.cmdline.push_back('\0');
            pi.cmdline += argv[i];
        }
        pi.exe = guest;
        abi::creds::login(pi, u->uid, u->gid, u->groups);
        if (const auto* init = k_.procs().find(pi.ppid)) k_.procs().inherit_ns(pi, *init, 0);
        k_.procs().upsert(pi);
        k_.procs().assign_ns_pid(gpid);
        k_.procs().set_sid(gpid);
        k_.files().set_current_pid(gpid);
        k_.files().set_cwd(spec.cwd.empty() ? (o_.cwd.empty() ? u->home : o_.cwd) : spec.cwd);
        if (!pts.empty()) {
            for (int fd = 0; fd <= 2; ++fd) k_.files().bind_fd(fd, pts);
            k_.procs().set_ctty(gpid, std::atoi(pts.c_str() + 9));
            k_.procs().set_pty_owner(std::atoi(pts.c_str() + 9), u->uid);
        }

        Session s;
        s.host = host;
        s.service = spec.service;
        s.user = u->name;
        s.argv = argv;
        s.started = std::chrono::steady_clock::now();
        sessions_[gpid] = std::move(s);
        return gpid;
    }

    std::string spawn(const env::JValue& req, Client& c) {
        SpawnSpec spec;
        spec.argv = req.strs("argv");
        spec.env = req.str_map("env");
        spec.user = req.str("user");
        spec.cwd = req.str("cwd");
        spec.fds = c.in.take_fds(static_cast<std::size_t>(std::max<std::int64_t>(0, req.num("fds"))));
        if (!spec.cwd.empty() && spec.cwd.front() != '/') {
            for (const int f : spec.fds) ::close(f);
            return error("cwd must be an absolute guest path");
        }
        std::string why;
        const std::int32_t g = start_session(std::move(spec), why);
        if (!g) return error(why);
        if (req.flag("wait")) sessions_[g].waiter = c.fd;
        env::Json j;
        return j.obj().kv("ok", true).kv("pid", g).end().take();
    }

    // ---- ps / kill / status ------------------------------------------------

    std::string user_name(std::uint32_t uid) const {
        const std::string pw = env::read_layered(h_.layers, "/etc/passwd");
        if (auto u = env::find_user(pw, std::to_string(uid))) return u->name;
        return std::to_string(uid);
    }

    std::string ps() {
        std::lock_guard g{k_.mutex()};
        const std::string pw = env::read_layered(h_.layers, "/etc/passwd");
        env::Json j;
        j.obj().kv("ok", true).key("procs").arr();
        for (const std::int32_t pid : k_.procs().pids()) {
            const auto* p = k_.procs().find(pid);
            if (!p) continue;
            std::string cmd = p->cmdline;
            for (auto& ch : cmd) if (ch == '\0') ch = ' ';
            const auto u = env::find_user(pw, std::to_string(p->uids[1]));
            j.obj().kv("pid", pid).kv("ppid", p->ppid).kv("uid", static_cast<std::int64_t>(p->uids[1]))
                .kv("user", u ? u->name : std::to_string(p->uids[1]))
                .kv("comm", p->comm).kv("cmdline", cmd).kv("state", std::string(1, p->state))
                .kv("rss_kb", p->rss_pages * 4).kv("session", k_.procs().sid_of(pid));
            if (auto it = sessions_.find(pid); it != sessions_.end() && !it->second.service.empty())
                j.kv("service", it->second.service);
            j.end();
        }
        return j.end().end().take();
    }

    std::string kill(const env::JValue& req) {
        const auto pid = static_cast<std::int32_t>(req.num("pid"));
        const int sig = static_cast<int>(req.num("signal", SIGTERM));
        if (pid <= 1) return error("refusing to signal init");
        if (sig < 0 || sig > 64) return error("bad signal");
        const ::pid_t host = trap_.host_tid_of(pid);
        if (host <= 0) return error("no such process: " + std::to_string(pid));
        const bool group = req.flag("session");
        if (::kill(group ? -host : host, sig) != 0) return error(std::strerror(errno));
        return ok();
    }

    std::string status() {
        std::lock_guard g{k_.mutex()};
        const auto up = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started_).count();
        env::Json j;
        j.obj().kv("ok", true).kv("env", o_.env_name).kv("pid", static_cast<std::int64_t>(::getpid()))
            .kv("uptime_s", static_cast<std::int64_t>(up)).kv("rootfs", o_.root).kv("upper", o_.persist)
            .kv("hostname", k_.machine().nodename).kv("user", o_.user)
            .kv("limits", h_.limits_text).kv("bridge", bridge_name_)
            .kv("processes", static_cast<std::int64_t>(k_.procs().pids().size()))
            .key("sessions").arr();
        for (const auto& [gp, s] : sessions_) {
            const auto age = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - s.started).count();
            j.obj().kv("pid", gp).kv("user", s.user).kv("argv", s.argv)
                .kv("service", s.service).kv("attached", s.waiter >= 0)
                .kv("age_s", static_cast<std::int64_t>(age)).end();
        }
        j.end().key("services").arr();
        for (const auto& [name, sv] : services_) svc_json(j, sv);
        j.end().key("notes").arr();
        for (const auto& line : env::status().history()) j.raw(line);
        return j.end().end().take();
    }

    // ---- services ----------------------------------------------------------

    static std::string_view state_name(SvcState s) {
        switch (s) {
            case SvcState::stopped: return "stopped";
            case SvcState::running: return "running";
            case SvcState::backoff: return "restarting";
            case SvcState::failed: return "failed";
        }
        return "?";
    }

    void svc_json(env::Json& j, const Svc& sv) const {
        j.obj().kv("name", sv.cfg.name).kv("state", state_name(sv.state)).kv("pid", sv.pid)
            .kv("restarts", sv.restarts).kv("last_code", sv.last_code)
            .kv("autostart", sv.cfg.autostart).kv("restart", env::restart_name(sv.cfg.restart))
            .kv("command", sv.cfg.command)
            .kv("log", o_.logs_dir + "/" + sv.cfg.name + ".log").end();
    }

    void start_service(Svc& sv) {
        const std::string log = o_.logs_dir + "/" + sv.cfg.name + ".log";
        const int lf = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        SpawnSpec spec;
        spec.argv = sv.cfg.command;
        spec.env = sv.cfg.env;
        spec.user = sv.cfg.user;
        spec.cwd = sv.cfg.cwd;
        spec.service = sv.cfg.name;
        if (lf >= 0) {
            const int in = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
            spec.fds = {in, lf, ::fcntl(lf, F_DUPFD_CLOEXEC, 3)};
        }
        std::string why;
        sv.stopping = false;
        sv.pid = start_session(std::move(spec), why);
        sv.started = std::chrono::steady_clock::now();
        if (!sv.pid) {
            sv.state = SvcState::failed;
            env::status().event("service", "service " + sv.cfg.name + " failed to start: " + why,
                                [&](env::Json& j) { j.kv("name", sv.cfg.name).kv("state", "failed").kv("error", why); });
            return;
        }
        sv.state = SvcState::running;
        env::status().event("service", "service " + sv.cfg.name + " started (pid " + std::to_string(sv.pid) + ")",
                            [&](env::Json& j) { j.kv("name", sv.cfg.name).kv("state", "running").kv("pid", sv.pid); });
    }

    void service_exited(const std::string& name, int code) {
        auto it = services_.find(name);
        if (it == services_.end()) return;
        Svc& sv = it->second;
        sv.pid = 0;
        sv.last_code = code;
        const bool quick = std::chrono::steady_clock::now() - sv.started < std::chrono::seconds(2);
        sv.quick_exits = quick ? sv.quick_exits + 1 : 0;
        const bool again = !stop_ && !sv.stopping &&
                           (sv.cfg.restart == env::Restart::always ||
                            (sv.cfg.restart == env::Restart::on_failure && code != 0));
        if (!again) {
            sv.state = sv.stopping || code == 0 ? SvcState::stopped : SvcState::failed;
        } else if (sv.quick_exits >= 5) {
            sv.state = SvcState::failed;   // crash loop: stop trying
        } else {
            // back off 100ms, 200ms, 400ms, ... up to 30s
            const int ms = std::min(30000, 100 << std::min(sv.quick_exits, 9));
            sv.state = SvcState::backoff;
            sv.next_start = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            ++sv.restarts;
        }
        env::status().event("service", "service " + name + " exited (" + std::to_string(code) + "), " +
                                           std::string{state_name(sv.state)},
                            [&](env::Json& j) {
                                j.kv("name", name).kv("state", state_name(sv.state)).kv("code", code);
                            });
        env::Json j;
        j.obj().kv("event", "service").kv("name", name).kv("state", state_name(sv.state)).kv("code", code).end();
        broadcast(j.text());
    }

    void stop_service(Svc& sv) {
        sv.stopping = true;
        if (sv.state == SvcState::backoff) sv.state = SvcState::stopped;
        if (sv.pid) {
            const ::pid_t host = trap_.host_tid_of(sv.pid);
            if (host > 0) (void)::kill(-host, SIGTERM);
        }
    }

    std::string svc(const env::JValue& req) {
        const std::string action = req.str("action", "list");
        if (action == "list") {
            env::Json j;
            j.obj().kv("ok", true).key("services").arr();
            for (const auto& [n, sv] : services_) svc_json(j, sv);
            return j.end().end().take();
        }
        const std::string name = req.str("name");
        auto it = services_.find(name);
        if (it == services_.end()) return error("no service '" + name + "'");
        Svc& sv = it->second;
        if (action == "start") {
            if (sv.state == SvcState::running) return error(name + " is already running");
            sv.quick_exits = 0;
            start_service(sv);
        } else if (action == "stop") {
            stop_service(sv);
        } else if (action == "restart") {
            if (sv.pid) { stop_service(sv); sv.restart_after_stop = true; }
            else { sv.quick_exits = 0; start_service(sv); }
        } else {
            return error("unknown action '" + action + "'");
        }
        return ok();
    }

    // ---- reload --------------------------------------------------------------

    std::string reload() {
        env::Store store{env::home_dir()};
        auto r = store.load(o_.env_name);
        if (!r.ok()) {
            std::string why = "config has errors:";
            for (const auto& d : r.diags) if (d.error) why += " " + env::format_diag(d) + ";";
            return error(why);
        }
        env::EnvConfig next = r.config;
        std::vector<std::string> applied;
        {
            std::lock_guard g{k_.mutex()};
            if (next.hostname != o_.cfg.hostname) {
                k_.machine().nodename = next.hostname;
                applied.emplace_back("system.hostname");
            }
        }
        if (next.dns != o_.cfg.dns && h_.resolv) {
            const auto servers = next.dns.empty() ? kernel::nameservers_public() : next.dns;
            *h_.resolv = kernel::render_resolv_conf(servers);
            applied.emplace_back("network.dns");
        }
        // services: add new ones, stop removed ones
        for (const auto& sc : next.services) {
            if (services_.count(sc.name)) { services_[sc.name].cfg = sc; continue; }
            Svc sv;
            sv.cfg = sc;
            auto& ref = services_[sc.name] = std::move(sv);
            if (sc.autostart) start_service(ref);
            applied.push_back("service." + sc.name);
        }
        for (auto it = services_.begin(); it != services_.end();) {
            const bool keep = std::any_of(next.services.begin(), next.services.end(),
                                          [&](const env::Service& s) { return s.name == it->first; });
            if (keep) { ++it; continue; }
            stop_service(it->second);
            applied.push_back("service." + it->first);
            if (!it->second.pid) it = services_.erase(it);
            else ++it;
        }
        // login settings only matter to sessions started from now on
        if (next.user != o_.cfg.user) { o_.user = next.user; applied.emplace_back("login.user"); }
        if (next.shell != o_.cfg.shell) { o_.shell = next.shell; applied.emplace_back("login.shell"); }
        if (next.cwd != o_.cfg.cwd) { o_.cwd = next.cwd; applied.emplace_back("login.cwd"); }
        if (next.command != o_.cfg.command) applied.emplace_back("login.command");
        // anything else needs a restart of the instance
        env::EnvConfig a = o_.cfg, b = next;
        a.hostname = b.hostname;
        a.dns = b.dns;
        a.services = b.services;
        a.user = b.user;
        a.shell = b.shell;
        a.cwd = b.cwd;
        a.command = b.command;
        const bool restart = env::config_json(a) != env::config_json(b);
        o_.cfg = next;
        o_.cfg.hostname = next.hostname;
        env::Json j;
        return j.obj().kv("ok", true).kv("applied", applied).kv("restart_needed", restart).end().take();
    }

    // ---- stop ----------------------------------------------------------------

    void on_signal() {
        ::signalfd_siginfo si{};
        while (::read(sig_fd_, &si, sizeof si) == static_cast<::ssize_t>(sizeof si)) {}
        begin_stop();
    }

    void begin_stop() {
        if (stopping_) return;
        stopping_ = true;
        for (auto& [n, sv] : services_) sv.stopping = true;
        env::status().event("stopping", "instance " + o_.env_name + " is stopping");
        if (trap_.live_count() == 0) { stop_ = true; return; }
        trap_.shutdown();
    }

    // ---- the bridge ----------------------------------------------------------

    void start_bridge() {
        bridge_name_ = "linuxity-bridge/" + std::to_string(::getpid());
        bridge_listen_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        ::sockaddr_un sa{};
        const socklen_t len = env::control::make_addr(sa, bridge_name_, true);
        if (bridge_listen_ < 0 || ::bind(bridge_listen_, reinterpret_cast<::sockaddr*>(&sa), len) != 0 ||
            ::listen(bridge_listen_, 16) != 0) {
            if (bridge_listen_ >= 0) ::close(bridge_listen_);
            bridge_listen_ = -1;
            bridge_name_.clear();
            env::status().event("bridge", "bridge unavailable: " + std::string{std::strerror(errno)});
            return;
        }
        // "@name": the guest helper reads it from $LINUXITY_BRIDGE
        bridge_name_ = "@" + bridge_name_;
        install_helpers();
    }

    // Put the bridge helper on the guest's PATH: a host dir of symlinks to
    // linuxity-bridge (found next to our own binary), mounted read-only at
    // /run/linuxity/bin and put first on every session's PATH.
    void install_helpers() {
        const std::string bin = o_.run_dir + "/bin";
        (void)env::remove_tree(bin);
        if (!env::mkdirs(bin)) return;
        // the helper is embedded in this binary (see CMakeLists.txt)
        const std::string_view blob{reinterpret_cast<const char*>(lx_bridge_blob),
                                    static_cast<std::size_t>(lx_bridge_blob_end - lx_bridge_blob)};
        const std::string helper = bin + "/linuxity-bridge";
        if (!env::write_file_atomic(helper, blob) || ::chmod(helper.c_str(), 0755) != 0) {
            env::status().event("bridge", "cannot write the bridge helper to " + bin);
            return;
        }
        // the other names link to it by a RELATIVE symlink, which resolves
        // inside the guest's view of the mount
        for (const char* name : {"xdg-open", "wl-copy", "wl-paste", "notify-send",
                                 "linuxity-open", "linuxity-copy", "linuxity-paste", "linuxity-notify"})
            (void)::symlink("linuxity-bridge", (bin + "/" + name).c_str());
        std::lock_guard g{k_.mutex()};
        k_.files().mount_host("/run/linuxity/bin", bin);
        helpers_path_ = "/run/linuxity/bin";
    }

    void accept_bridge() {
        for (;;) {
            const int fd = ::accept4(bridge_listen_, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
            if (fd < 0) return;
            bridge_conns_.push_back(std::make_unique<BridgeConn>(fd));
        }
    }

    void drop_bridge(int fd) {
        std::erase_if(bridge_conns_, [fd](const auto& b) { return b->fd == fd; });
        for (auto it = pending_.begin(); it != pending_.end();)
            it = it->second == fd ? pending_.erase(it) : std::next(it);
        for (auto& j : jobs_) if (j.reply_to == fd) j.reply_to = -1;
        ::close(fd);
    }

    void serve_bridge(int fd) {
        BridgeConn* b = nullptr;
        for (auto& x : bridge_conns_) if (x->fd == fd) b = x.get();
        if (!b) return;
        if (!b->in.fill()) { drop_bridge(fd); return; }
        std::string line;
        while (b->in.next(line)) {
            auto req = env::parse_json(line);
            if (!req) { send(fd, error("bad request")); continue; }
            bridge_request(fd, *req);
        }
    }

    void bridge_request(int from, const env::JValue& req) {
        const std::string op = req.str("op");
        env::status().event("bridge", "", [&](env::Json& j) { j.kv("op", op); });
        // an attached app handles it if one asked to
        for (auto& c : clients_) {
            if (!c->bridge) continue;
            const std::int64_t id = ++bridge_seq_;
            pending_[id] = from;
            env::Json j;
            j.obj().kv("event", "bridge").kv("id", id).kv("op", op);
            for (const char* k : {"url", "text", "title", "body", "mime"})
                if (const auto v = req.str(k); !v.empty()) j.kv(k, v);
            if (const auto p = req.str("path"); !p.empty()) {
                j.kv("path", p);
                std::lock_guard g{k_.mutex()};
                const auto pc = k_.files().classify(p);
                if (pc.realm == kernel::Realm2::host_backed) j.kv("host_path", pc.host_path);
            }
            j.end();
            send(c->fd, j.text());
            return;
        }
        if (!o_.cfg.bridge_host_fallback) { send(from, error("no app attached to handle " + op)); return; }
        host_fallback(from, op, req);
    }

    void bridge_reply(const env::JValue& req) {
        auto it = pending_.find(req.num("id"));
        if (it == pending_.end()) return;
        const int to = it->second;
        pending_.erase(it);
        env::Json j;
        j.obj().kv("ok", req.flag("ok"));
        if (const auto t = req.str("text"); !t.empty()) j.kv("text", t);
        if (const auto e = req.str("error"); !e.empty()) j.kv("error", e);
        send(to, j.end().take());
    }

    // Run a host tool for a bridge request when no app is attached.
    void host_fallback(int from, const std::string& op, const env::JValue& req) {
        std::vector<std::string> argv;
        std::string input;
        bool want_output = false;
        if (op == "open") {
            std::string target = req.str("url");
            if (target.empty()) {
                std::lock_guard g{k_.mutex()};
                const auto pc = k_.files().classify(req.str("path"));
                if (pc.realm == kernel::Realm2::host_backed) target = pc.host_path;
            }
            if (target.empty()) { send(from, error("nothing to open")); return; }
#if defined(__ANDROID__)
            // a file path needs a content:// URI and an app to grant it to;
            // without one only URLs can be opened from here
            if (req.str("url").empty()) { send(from, error("opening files needs the linuxity app attached")); return; }
            argv = {"/system/bin/am", "start", "-a", "android.intent.action.VIEW", "-d", target};
#else
            argv = {"xdg-open", target};
#endif
        } else if (op == "copy") {
#if defined(__ANDROID__)
            send(from, error("the clipboard needs the linuxity app attached"));
            return;
#else
            argv = {"wl-copy"};
            input = req.str("text");
#endif
        } else if (op == "paste") {
#if defined(__ANDROID__)
            send(from, error("the clipboard needs the linuxity app attached"));
            return;
#else
            argv = {"wl-paste", "-n"};
            want_output = true;
#endif
        } else if (op == "notify") {
#if defined(__ANDROID__)
            argv = {"/system/bin/cmd", "notification", "post", "-S", "bigtext", "-t",
                    req.str("title", "linuxity"), "linuxity", req.str("body", " ")};
#else
            argv = {"notify-send", req.str("title", "linuxity"), req.str("body")};
#endif
        } else {
            send(from, error("unknown bridge op '" + op + "'"));
            return;
        }
        int in_p[2] = {-1, -1}, out_p[2] = {-1, -1};
        if (::pipe2(in_p, O_CLOEXEC) != 0) { send(from, error(std::strerror(errno))); return; }
        if (want_output && ::pipe2(out_p, O_CLOEXEC) != 0) {
            ::close(in_p[0]); ::close(in_p[1]);
            send(from, error(std::strerror(errno)));
            return;
        }
        ::posix_spawn_file_actions_t fa;
        ::posix_spawn_file_actions_init(&fa);
        ::posix_spawn_file_actions_adddup2(&fa, in_p[0], 0);
        if (want_output) ::posix_spawn_file_actions_adddup2(&fa, out_p[1], 1);
        // a host tool, run untraced, with the supervisor's own environment
        ::posix_spawnattr_t at;
        ::posix_spawnattr_init(&at);
        ::sigset_t none;
        ::sigemptyset(&none);
        ::posix_spawnattr_setsigmask(&at, &none);
        ::posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGMASK);
        std::vector<char*> av;
        for (auto& a : argv) av.push_back(a.data());
        av.push_back(nullptr);
        ::pid_t pid = -1;
        const int rc = ::posix_spawnp(&pid, av[0], &fa, &at, av.data(), environ);
        ::posix_spawn_file_actions_destroy(&fa);
        ::posix_spawnattr_destroy(&at);
        ::close(in_p[0]);
        if (want_output) ::close(out_p[1]);
        if (rc != 0) {
            ::close(in_p[1]);
            if (want_output) ::close(out_p[0]);
            send(from, error(argv[0] + ": " + std::strerror(rc)));
            return;
        }
        if (!input.empty()) (void)!::write(in_p[1], input.data(), input.size());
        ::close(in_p[1]);
        // the reply waits for the tool's exit, so a failure is reported
        if (want_output) (void)::fcntl(out_p[0], F_SETFL, O_NONBLOCK);
        jobs_.push_back({pid, want_output ? out_p[0] : -1, from, {}, want_output});
    }

    void serve_job(int fd) {
        for (auto& j : jobs_) {
            if (j.out_fd != fd) continue;
            char buf[4096];
            ::ssize_t n;
            while ((n = ::read(fd, buf, sizeof buf)) > 0) j.text.append(buf, static_cast<std::size_t>(n));
            if (n == 0) { ::close(fd); j.out_fd = -1; }
            return;
        }
    }

    void job_exited(::pid_t pid, int code) {
        for (auto it = jobs_.begin(); it != jobs_.end(); ++it) {
            if (it->pid != pid) continue;
            if (it->out_fd >= 0) { serve_job(it->out_fd); if (it->out_fd >= 0) ::close(it->out_fd); }
            if (it->reply_to >= 0) {
                env::Json j;
                j.obj().kv("ok", code == 0);
                if (it->want_text) j.kv("text", it->text);
                // posix_spawn reports a missing tool as exit 127
                if (code == 127) j.kv("error", "no host tool for this on this system");
                else if (code != 0) j.kv("error", "host tool exited " + std::to_string(code));
                send(it->reply_to, j.end().take());
            }
            jobs_.erase(it);
            return;
        }
    }

    // ---- timers ----------------------------------------------------------------

    int next_timer_ms() const {
        int best = -1;
        const auto now = std::chrono::steady_clock::now();
        for (const auto& [n, sv] : services_) {
            if (sv.state != SvcState::backoff) continue;
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(sv.next_start - now).count();
            const int t = ms < 0 ? 0 : static_cast<int>(ms);
            if (best < 0 || t < best) best = t;
        }
        return best;
    }

    void run_timers() {
        const auto now = std::chrono::steady_clock::now();
        for (auto& [n, sv] : services_) {
            if (sv.restart_after_stop && !sv.pid && !stop_) {
                sv.restart_after_stop = false;
                sv.quick_exits = 0;
                start_service(sv);
                continue;
            }
            if (sv.state == SvcState::backoff && now >= sv.next_start && !stop_) start_service(sv);
        }
    }

    Kern& k_;
    runtime::PtraceTrap& trap_;
    Options& o_;
    RuntimeHooks h_;
    env::control::Listener listener_;
    int sig_fd_{-1};
    int lock_fd_{-1};
    int bridge_listen_{-1};
    std::string bridge_name_;
    std::string helpers_path_;
    std::int64_t bridge_seq_{0};
    std::map<std::int64_t, int> pending_;   // bridge request id -> guest conn
    std::vector<std::unique_ptr<Client>> clients_;
    std::vector<std::unique_ptr<BridgeConn>> bridge_conns_;
    std::vector<Job> jobs_;
    std::map<std::int32_t, Session> sessions_;
    std::map<std::string, Svc> services_;
    std::chrono::steady_clock::time_point started_;
    bool stopping_{false};
    bool stop_{false};
    bool cleaned_{false};
};

}  // namespace lx::cli
