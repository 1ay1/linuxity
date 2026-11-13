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

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

#include <sys/stat.h>
#include <unistd.h>

namespace lx::display {
std::unique_ptr<Host> make_headless_host(std::string dump_dir);
#if defined(LX_DISPLAY_COCOA)
std::unique_ptr<Host> make_cocoa_host();
#endif

std::unique_ptr<Host> make_host(bool headless) {
#if defined(LX_DISPLAY_COCOA)
    if (!headless) return make_cocoa_host();
#endif
    (void)headless;
    return make_headless_host({});
}
}  // namespace lx::display

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

void usage() {
    std::fputs("usage: linuxity-display [--socket PATH] [--headless [--dump DIR]] [--idle-exit SECS]\n"
               "                        [--command-is-super] [--ready-fd N]\n", stderr);
}

}  // namespace

int main(int argc, char** argv) {
    using namespace lx::display;
    std::string socket, dump;
    bool headless = false;
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
        else if (a == "--headless") headless = true;
        else if (a == "--dump") { dump = next(); headless = true; }
        else if (a == "--idle-exit") idle_exit = std::atoi(next());
        else if (a == "--command-is-super") opts.command_is_control = false;
        else if (a == "--command-is-control") opts.command_is_control = true;
        else if (a == "--ready-fd") ready_fd = std::atoi(next());
        else if (a == "-v" || a == "--verbose") opts.verbose = true;
        else if (a == "-h" || a == "--help") { usage(); return 0; }
        else { usage(); return 2; }
    }
    if (socket.empty()) socket = default_socket();
    ::signal(SIGPIPE, SIG_IGN);

    std::unique_ptr<Host> host = dump.empty() ? make_host(headless) : make_headless_host(dump);
    Server server{host->loop()};
    server.verbose = opts.verbose;
    std::string why;
    if (!server.listen(socket, why)) {
        std::fprintf(stderr, "linuxity-display: %s\n", why.c_str());
        return 1;
    }
    Compositor comp{server, *host, opts};

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
