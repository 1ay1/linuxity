// src/session_bus.hpp -- every session gets a D-Bus session bus, on demand.
//
// A Linux desktop session always has one: systemd's dbus.socket listens at
// $XDG_RUNTIME_DIR/bus from login, and the first client to connect starts
// the bus daemon, handed the listening socket (socket activation). GTK, Qt,
// Firefox, portals, notifications, gsettings and accessibility all expect
// it; without one GTK's accessibility bridge warns on every start ("Failed
// to create DBus proxy for org.a11y.Bus: Cannot autolaunch D-Bus without
// X11 $DISPLAY") and anything that needs the bus quietly does without.
//
// linuxity does what systemd does:
//   * at session start (before the guest runs) it binds the listening
//     socket at the host side of /run/user/<uid>/bus and exports
//     DBUS_SESSION_BUS_ADDRESS -- if the guest image has a dbus-daemon;
//   * a small host watcher (`linuxity __bus`) holds that socket and waits;
//     a session that never touches D-Bus costs nothing more;
//   * on the first connection it starts the guest's own dbus-daemon, as the
//     session's user, in this environment with this session's runtime dir,
//     as pid 1 of its own guest tree with the socket at fd 3 (LISTEN_FDS=1,
//     `--address=systemd:`), exactly as systemd would;
//   * when the session ends (its root linuxity process exits) the watcher
//     ends the bus and everything it activated.
#pragma once

#if defined(__APPLE__)

#include "options.hpp"

#include "linuxity/host/environ.hpp"
#include "linuxity/host/self_exe.hpp"
#include "linuxity/runtime/darwin/net.hpp"

#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <spawn.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace lx::cli::session_bus {

// Set up the bus for a session whose guest env is `env` and whose
// /run/user host dir is bound in `o.binds`. Returns quietly when there is
// nothing to do (no runtime dir, no dbus-daemon, an address already set).
inline void setup(Options& o, std::vector<std::string>& env, const std::string& user) {
    auto get = [&env](std::string_view k) -> std::string {
        const std::string prefix = std::string{k} + "=";
        for (const auto& kv : env)
            if (kv.starts_with(prefix)) return kv.substr(prefix.size());
        return {};
    };
    if (!get("DBUS_SESSION_BUS_ADDRESS").empty()) return;      // the user chose a bus
    const std::string rt = get("XDG_RUNTIME_DIR");
    if (!rt.starts_with("/run/user/")) return;
    std::string users_host;
    for (const auto& [h, g] : o.binds)
        if (g == "/run/user") users_host = h;
    if (users_host.empty()) return;
    // the guest image must have the daemon (any layer)
    bool have = false;
    for (const std::string& layer : {o.persist, o.root}) {
        struct ::stat st{};
        if (!layer.empty() && ::stat((layer + "/usr/bin/dbus-daemon").c_str(), &st) == 0) have = true;
    }
    if (!have) return;

    const std::string host_dir = users_host + rt.substr(std::string_view{"/run/user"}.size());
    const std::string path = host_dir + "/bus";
    (void)::unlink(path.c_str());
    const int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return;
    if (runtime::net::unix_path_call(s, path, /*bind=*/true) != 0 || ::listen(s, 64) != 0) {
        ::close(s);
        return;
    }
    (void)::chmod(path.c_str(), 0666);

    // the watcher, holding the socket; it watches us (this process becomes
    // the session's root linuxity) and ends the bus with us
    std::vector<std::string> args{host::pinned_self_exe(), "__bus", std::to_string(::getpid()),
                                  o.env_name, user, users_host, rt, get("WAYLAND_DISPLAY")};
    std::vector<char*> av;
    for (auto& a : args) av.push_back(a.data());
    av.push_back(nullptr);
    posix_spawn_file_actions_t fa;
    ::posix_spawn_file_actions_init(&fa);
    ::posix_spawn_file_actions_adddup2(&fa, s, 3);
    ::posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    ::posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    ::posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    posix_spawnattr_t at;
    ::posix_spawnattr_init(&at);
    ::posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSID);
    pid_t pid = 0;
    const bool ok = ::posix_spawn(&pid, av[0], &fa, &at, av.data(), environ) == 0;
    ::posix_spawn_file_actions_destroy(&fa);
    ::posix_spawnattr_destroy(&at);
    ::close(s);
    if (!ok) { (void)::unlink(path.c_str()); return; }
    env.push_back("DBUS_SESSION_BUS_ADDRESS=unix:path=" + rt + "/bus");
}

// Every host process in session `sid` (the bus and what it activated: the
// guest's fork children are host processes too, and may have left its
// process group, never its session).
inline void end_session(pid_t sid) {
    for (int sig : {SIGTERM, SIGKILL}) {
        int n = ::proc_listallpids(nullptr, 0);
        std::vector<pid_t> pids(static_cast<std::size_t>(n > 0 ? n + 64 : 64));
        n = ::proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
        bool any = false;
        for (int i = 0; i < n; ++i)
            if (pids[static_cast<std::size_t>(i)] != ::getpid() && ::getsid(pids[static_cast<std::size_t>(i)]) == sid) {
                ::kill(pids[static_cast<std::size_t>(i)], sig);
                any = true;
            }
        if (!any) return;
        for (int w = 0; w < 20; ++w) { ::usleep(50'000); while (::waitpid(-1, nullptr, WNOHANG) > 0) {} }
    }
}

// `linuxity __bus PARENT ENV USER USERS_HOST RUNTIME_DIR WAYLAND` with the
// listening socket at fd 3.
inline int watcher_main(int argc, char** argv) {
    if (argc < 8) return 2;
    const pid_t parent = static_cast<pid_t>(std::atoi(argv[2]));
    const std::string env_name = argv[3], user = argv[4], users_host = argv[5], rt = argv[6], wayland = argv[7];
    const int kq = ::kqueue();
    if (kq < 0) return 1;
    struct ::kevent ev[2];
    EV_SET(&ev[0], static_cast<uintptr_t>(parent), EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, nullptr);
    EV_SET(&ev[1], 3, EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0, nullptr);
    if (::kevent(kq, ev, 2, nullptr, 0, nullptr) < 0) return 0;   // the session already ended
    bool started = false;
    for (;;) {
        struct ::kevent out{};
        if (::kevent(kq, nullptr, 0, &out, 1, nullptr) <= 0) continue;
        if (out.filter == EVFILT_PROC) break;                       // the session is over
        if (out.filter == EVFILT_READ && !started) {
            started = true;
            // the guest's dbus-daemon, pid 1 of its own tree, fd 3 = us
            std::vector<std::string> a{host::pinned_self_exe(), "__run", env_name, "--quiet",
                                       "--user", user, "--pass-fd", "3",
                                       "--bind", users_host + ":/run/user",
                                       "-e", "XDG_RUNTIME_DIR=" + rt,
                                       "-e", "DBUS_SESSION_BUS_ADDRESS=unix:path=" + rt + "/bus",
                                       "-e", "WAYLAND_DISPLAY=" + (wayland.empty() ? std::string{"none"} : wayland),
                                       "-e", "LISTEN_FDS=1", "-e", "LISTEN_PID=1",
                                       "--", "/usr/bin/dbus-daemon", "--session", "--address=systemd:",
                                       "--nofork", "--nopidfile", "--nosyslog"};
            std::vector<char*> av;
            for (auto& x : a) av.push_back(x.data());
            av.push_back(nullptr);
            posix_spawn_file_actions_t fa;
            ::posix_spawn_file_actions_init(&fa);
            ::posix_spawn_file_actions_addinherit_np(&fa, 0);
            ::posix_spawn_file_actions_addinherit_np(&fa, 1);
            ::posix_spawn_file_actions_addinherit_np(&fa, 2);
            ::posix_spawn_file_actions_addinherit_np(&fa, 3);
            posix_spawnattr_t at;
            ::posix_spawnattr_init(&at);
            ::posix_spawnattr_setflags(&at, POSIX_SPAWN_CLOEXEC_DEFAULT);
            pid_t pid = 0;
            (void)::posix_spawn(&pid, av[0], &fa, &at, av.data(), environ);
            ::posix_spawn_file_actions_destroy(&fa);
            ::posix_spawnattr_destroy(&at);
        }
    }
    end_session(::getsid(0));
    return 0;
}

} // namespace lx::cli::session_bus

#else

namespace lx::cli::session_bus {
inline void setup(Options&, std::vector<std::string>&, const std::string&) {}
inline int watcher_main(int, char**) { return 2; }
}

#endif
