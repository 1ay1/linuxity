// src/display/main.cpp -- linuxity-display: the native Wayland compositor.
//
//   linuxity-display [--socket PATH] [--headless [--dump DIR]]
//                    [--idle-exit SECS] [--command-is-super] [--ready-fd N]
//
// linuxity starts it on demand (src/display_attach.hpp) and mounts its
// socket into the guest; it can also be run by hand for development. One
// instance serves every environment of the user, the way one compositor
// serves a desktop session.
#include "core/compositor.hpp"
#include "core/host_registry.hpp"
#include "hosts/headless/headless.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

namespace {

std::string default_socket() {
    if (const char* d = std::getenv("XDG_RUNTIME_DIR"); d && *d) return std::string{d} + "/wayland-0";
    const char* t = std::getenv("TMPDIR");
    std::string base = t && *t ? t : "/tmp";
    while (base.size() > 1 && base.back() == '/') base.pop_back();
    const std::string dir = base + "/linuxity-display-" + std::to_string(::getuid());
    ::mkdir(dir.c_str(), 0700);
    return dir + "/wayland-0";
}

// Sessions that are already running reach us through a hard link to our
// socket in their runtime dir (<root>/runtime/<env>/s<pid>/<uid>/wayland-0,
// see src/display_attach.hpp). A restarted server binds a NEW socket, so
// those links would still name the dead one -- "no compositor running?" in
// every open shell until the next lx. Point them all at us.
void relink_sessions(const std::string& socket) {
    const auto slash = socket.rfind('/');
    if (slash == std::string::npos) return;
    const std::string dir = socket.substr(0, slash);             // <root>/wayland
    const auto up = dir.rfind('/');
    if (up == std::string::npos) return;
    const std::string name = socket.substr(slash + 1);
    auto subdirs = [](const std::string& p) {
        std::vector<std::string> out;
        if (DIR* d = ::opendir(p.c_str())) {
            while (dirent* e = ::readdir(d))
                if (e->d_name[0] != '.') out.push_back(p + "/" + e->d_name);
            ::closedir(d);
        }
        return out;
    };
    for (const auto& env : subdirs(dir.substr(0, up) + "/runtime"))
        for (const auto& session : subdirs(env))
            for (const auto& user : subdirs(session)) {
                const std::string link = user + "/" + name;
                struct ::stat st{};
                if (::lstat(link.c_str(), &st) != 0) continue;    // that session has no display
                const std::string tmp = link + ".new";
                ::unlink(tmp.c_str());
                if (::link(socket.c_str(), tmp.c_str()) == 0) ::rename(tmp.c_str(), link.c_str());
            }
}

void usage() {
    std::fputs("usage: linuxity-display [--socket PATH] [--host NAME] [--host-opt KEY=VALUE]...\n"
               "                        [--headless [--dump DIR]] [--idle-exit SECS]\n"
               "                        [--command-is-super] [--ready-fd N] [--list-hosts]\n", stderr);
}

void list_hosts() {
    using namespace lx::display;
    const HostBackend* best = best_host();
    for (const HostBackend* b : host_backends()) {
        const bool up = !b->available || b->available();
        std::printf("%c %-10s %s%s\n", b == best ? '*' : ' ', std::string{b->name}.c_str(),
                    std::string{b->summary}.c_str(), up ? "" : "  (not available here)");
    }
}

}  // namespace

int main(int argc, char** argv) {
    using namespace lx::display;
    std::string socket, dump, host_name;
    HostConfig host_cfg;
    bool native_frames = false;
    int idle_exit = 0, ready_fd = -1;
    CompositorOptions opts;
#if defined(__APPLE__)
    // Mac hands press Cmd-C to copy: on a Mac keyboard Command is Control
    // to the guest, unless asked to keep it as Super.
    opts.command_is_control = true;
#endif
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        auto next = [&]() -> const char* {
            if (i + 1 >= argc) { usage(); std::exit(2); }
            return argv[++i];
        };
        if (a == "--socket") socket = next();
        else if (a == "--host") host_name = next();
        else if (a == "--host-opt") {
            const std::string_view kv = next();
            const auto eq = kv.find('=');
            host_cfg.params.insert_or_assign(std::string{kv.substr(0, eq)},
                                             eq == std::string_view::npos ? std::string{"1"} : std::string{kv.substr(eq + 1)});
        }
        else if (a == "--list-hosts") { list_hosts(); return 0; }
        else if (a == "--headless") host_name = "headless";
        else if (a == "--dump") { dump = next(); host_name = "headless"; }
        else if (a == "--idle-exit") idle_exit = std::atoi(next());
        else if (a == "--command-is-super") opts.command_is_control = false;
        else if (a == "--command-is-control") opts.command_is_control = true;
        else if (a == "--ready-fd") ready_fd = std::atoi(next());
        else if (a == "-v" || a == "--verbose") opts.verbose = true;
        else if (a == "--native-frames") native_frames = true;
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else { usage(); return 2; }
    }
    if (socket.empty()) socket = default_socket();
    ::signal(SIGPIPE, SIG_IGN);

    // --native-frames: a headless host that frames windows like a desktop
    // one (development); everything else goes through the registry
    static HeadlessLog dump_log;
    dump_log.native_frames = native_frames;
    host_cfg.dump_dir = dump;
    std::unique_ptr<Host> host;
    if (native_frames) {
        host = make_headless_host(dump, &dump_log);
    } else {
        const HostBackend* b = host_name.empty() ? best_host() : find_host(host_name);
        if (!b) {
            std::fprintf(stderr, "linuxity-display: no host named '%s' in this build (--list-hosts)\n", host_name.c_str());
            return 2;
        }
        if (b->available && !b->available())
            std::fprintf(stderr, "linuxity-display: host '%s' may not work here; trying anyway\n", std::string{b->name}.c_str());
        host = b->create(host_cfg);
        if (!host) {
            std::fprintf(stderr, "linuxity-display: host '%s' failed to start\n", std::string{b->name}.c_str());
            return 1;
        }
    }
    Server server{host->loop()};
    server.verbose = opts.verbose;
    std::string why;
    if (!server.listen(socket, why)) {
        std::fprintf(stderr, "linuxity-display: %s\n", why.c_str());
        return 1;
    }
    Compositor comp{server, *host, opts};
    relink_sessions(socket);

    // Exit once nobody has used us for a while (linuxity restarts us).
    std::unique_ptr<EventLoop::Source> idle_timer;
    auto arm_idle = [&] {
        if (idle_exit <= 0) return;
        if (server.client_count() > 0) { idle_timer.reset(); return; }
        idle_timer = host->loop().every(std::chrono::seconds(idle_exit), [&] {
            if (server.client_count() == 0) host->loop().stop();
        });
    };
    server.on_idle_change = arm_idle;
    arm_idle();

    if (ready_fd >= 0) {
        (void)!::write(ready_fd, "1", 1);
        ::close(ready_fd);
    }
    std::fprintf(stderr, "linuxity-display: listening on %s\n", socket.c_str());
    host->loop().run();
    return 0;
}
