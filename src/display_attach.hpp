// src/display_attach.hpp -- give a guest a Wayland display.
//
// GUI programs in the guest find their compositor through
// $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY. Which compositor that is depends on the
// host, and that decision lives here and nowhere else:
//
//   1. the host already runs one (a Linux desktop: $WAYLAND_DISPLAY) --
//      the guest joins it, like any native app;
//   2. otherwise linuxity-display, our own compositor, which shows guest
//      windows as native host windows (macOS today; the same binary with a
//      different host backend on Android and Windows). It is started on
//      demand, once per user, and stays: several environments share it --
//      the way a desktop session has one compositor -- and a shell that
//      outlived an idle exit would have no compositor to come back to.
//      Idle it costs nothing (no windows, no Dock icon, no timers).
//
// Either way the guest gets a standard XDG_RUNTIME_DIR (/run/user/UID) with
// the socket in it, private per environment and guest user: dconf, dbus and
// pipewire put their own sockets there, and nothing leaks between envs. No
// guest file is touched.
//
// On the host it all lives under one 0700 directory of the user's, so no
// other account on the machine can reach the compositor (it would see the
// windows and the clipboard). Inside it the guest-visible parts are
// world-searchable, because guest users are not the host user.
//
// Every host whose sockets resolve through the file namespace (all POSIX
// hosts) gets this for free; the call sites are the hosts' host_run().
#pragma once

#include "options.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/host/self_exe.hpp"
#include "linuxity/host/tmpdir.hpp"

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace lx::cli::display {

inline constexpr const char* kGuestDisplay = "/run/linuxity/display";

// Whether linuxity-display has a native window backend in this build (any
// host besides headless, see src/display/CMakeLists.txt). Elsewhere it would
// be a compositor with nowhere to show windows: apps would start and draw
// into nothing. There a guest gets the host's own compositor or no display
// at all, and says so ("cannot open display"). Adding a backend turns this
// on by itself.
#if defined(LX_DISPLAY_NATIVE_HOST)
inline constexpr bool kOwnCompositor = true;
#else
inline constexpr bool kOwnCompositor = false;
#endif

struct Attachment {
    std::string host_dir;        // mounted at kGuestDisplay
    std::string socket_name;     // e.g. wayland-0
    std::string source;          // "host" or "linuxity-display", for diagnostics
    std::string runtime_root;    // our private dir (per-env runtime dirs go under it); empty: none
};

#if !defined(_WIN32)

namespace detail {

// mkdir if missing, then insist it is a real directory of ours
[[nodiscard]] inline bool own_dir(const std::string& p, mode_t mode) {
    (void)::mkdir(p.c_str(), mode);
    struct ::stat st{};
    if (::lstat(p.c_str(), &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != ::getuid()) return false;
    if ((st.st_mode & 07777) != mode) (void)::chmod(p.c_str(), mode);
    return true;
}

[[nodiscard]] inline bool socket_live(const std::string& path) {
    ::sockaddr_un sa{};
    if (path.size() >= sizeof sa.sun_path) return false;
    sa.sun_family = AF_UNIX;
    std::memcpy(sa.sun_path, path.c_str(), path.size() + 1);
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;
    const bool ok = ::connect(fd, reinterpret_cast<::sockaddr*>(&sa), sizeof sa) == 0;
    ::close(fd);
    return ok;
}

// The host's own compositor, if it has one.
[[nodiscard]] inline std::optional<Attachment> host_compositor() {
    const char* wd = std::getenv("WAYLAND_DISPLAY");
    if (!wd || !*wd) return std::nullopt;
    std::string path = wd;
    if (path.front() != '/') {
        const char* rt = std::getenv("XDG_RUNTIME_DIR");
        if (!rt || !*rt) return std::nullopt;
        path = std::string{rt} + "/" + path;
    }
    if (!socket_live(path)) return std::nullopt;
    const auto slash = path.rfind('/');
    return Attachment{path.substr(0, slash), path.substr(slash + 1), "host"};
}

// The user's private root for display and runtime state (0700: no other
// account on the machine can reach the compositor or a session's sockets).
[[nodiscard]] inline std::string runtime_root() {
    const std::string root = host::tmp_path("linuxity-display-" + std::to_string(::getuid()));
    return own_dir(root, 0700) ? root : std::string{};
}

// The session's /run/user: what a Linux login gets from logind -- a fresh,
// empty tmpfs that lives exactly as long as the session. Sockets in it are
// named after pids (Firefox: wayland-proxy-<pid>), and every linuxity
// session on macOS is its own pid space starting at 1, so a directory
// shared between sessions, or kept across them, collides: a crashed
// Firefox left wayland-proxy-7 behind and the next one failed with
// "bind() error: Address already in use".
//
//   <env_dir>/s<pid>.lock   held (flock) by every process of the session:
//                           the fd is inherited by each guest process
//   <env_dir>/s<pid>/       the directory, created empty
//
// Before making its own, a session sweeps every s* whose lock nobody holds
// (sessions that ended or crashed). The lock is taken BEFORE the directory
// exists, so a sweep never sees a live session's directory unlocked; and a
// reused pid finds its predecessor's leftovers and clears them. Returns the
// directory, or "" if it can't be made.
[[nodiscard]] inline std::string session_dir(const std::string& env_dir) {
    const auto parent = env_dir.substr(0, env_dir.rfind('/'));
    if (!own_dir(parent, 0755) || !own_dir(env_dir, 0755)) return {};
    // sweep the dead
    if (DIR* d = ::opendir(env_dir.c_str())) {
        std::vector<std::string> locks;
        while (dirent* e = ::readdir(d)) {
            const std::string_view n = e->d_name;
            if (n.size() > 6 && n.front() == 's' && n.ends_with(".lock")) locks.emplace_back(n);
            // the old layout: one /run/user shared by every session forever
            else if (!n.empty() && n.find_first_not_of("0123456789") == std::string_view::npos)
                (void)env::remove_tree(env_dir + "/" + std::string{n});
        }
        ::closedir(d);
        for (const auto& n : locks) {
            const std::string lp = env_dir + "/" + n;
            const int fd = ::open(lp.c_str(), O_RDWR | O_CLOEXEC);
            if (fd < 0) continue;
            if (::flock(fd, LOCK_EX | LOCK_NB) == 0) {
                (void)env::remove_tree(env_dir + "/" + n.substr(0, n.size() - 5));
                ::unlink(lp.c_str());
            }
            ::close(fd);
        }
    }
    // ours
    const std::string id = "s" + std::to_string(::getpid());
    const std::string lock = env_dir + "/" + id + ".lock";
    const std::string dir = env_dir + "/" + id;
    // Not close-on-exec: every guest process (macOS: each its own linuxity,
    // spawned from this one) inherits it, so the session lasts as long as
    // any of them does, as a login session does. Never closed here.
    const int fd = ::open(lock.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd < 0 || ::flock(fd, LOCK_EX) != 0) {
        if (fd >= 0) ::close(fd);
        return {};
    }
    (void)env::remove_tree(dir);   // a dead predecessor with our pid
    if (!own_dir(dir, 0755)) return {};
    // Downgrade to shared: children inherit the same open file, and a
    // shared lock is all a sweep needs to see.
    (void)::flock(fd, LOCK_SH);
    return dir;
}

// linuxity-display ships next to linuxity.
[[nodiscard]] inline std::string display_binary() {
    std::string self = host::self_exe();
    const auto slash = self.rfind('/');
    std::string p = (slash == std::string::npos ? std::string{"."} : self.substr(0, slash)) + "/linuxity-display";
    if (::access(p.c_str(), X_OK) == 0) return p;
    // a signed private copy (tests, macOS fork children) may live elsewhere
    // than its build dir; LINUXITY_DISPLAY names the server explicitly
    if (const char* e = std::getenv("LINUXITY_DISPLAY"); e && *e && ::access(e, X_OK) == 0) return e;
    return {};
}

// Start linuxity-display detached, in its own session so it outlives this
// guest and isn't hit by the terminal's signals; wait until it listens.
[[nodiscard]] inline bool spawn_display(const std::string& bin, const std::string& socket, std::string& why) {
    int ready[2];
    if (::pipe(ready) != 0) { why = std::strerror(errno); return false; }
    (void)::fcntl(ready[0], F_SETFD, FD_CLOEXEC);
    const std::string log = host::tmp_path("linuxity-display-" + std::to_string(::getuid()) + ".log");
    const std::string fd_s = std::to_string(ready[1]);
    std::vector<std::string> args{bin, "--socket", socket, "--ready-fd", fd_s};
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) { why = std::strerror(errno); ::close(ready[0]); ::close(ready[1]); return false; }
    if (pid == 0) {
        // grandchild: reparented to launchd/init, nobody waits on it here
        if (::fork() != 0) ::_exit(0);
        ::setsid();
        const int null = ::open("/dev/null", O_RDWR);
        const int lfd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (null >= 0) ::dup2(null, 0);
        if (lfd >= 0) { ::dup2(lfd, 1); ::dup2(lfd, 2); }
        // Nothing else of the caller's: a pipe we kept open (its stdout
        // into `| less`, a test harness) would never see EOF.
        const int top = static_cast<int>(::sysconf(_SC_OPEN_MAX));
        for (int fd = 3; fd < (top > 0 ? top : 1024); ++fd)
            if (fd != ready[1]) (void)::close(fd);
        ::signal(SIGINT, SIG_DFL);
        ::signal(SIGHUP, SIG_DFL);
        ::execv(bin.c_str(), argv.data());
        ::_exit(127);
    }
    ::close(ready[1]);
    int st = 0;
    (void)::waitpid(pid, &st, 0);
    ::pollfd p{ready[0], POLLIN, 0};
    char c = 0;
    const bool ok = ::poll(&p, 1, 5000) == 1 && ::read(ready[0], &c, 1) == 1;
    ::close(ready[0]);
    if (!ok) why = "linuxity-display did not start (see " + log + ")";
    return ok;
}

}  // namespace detail

// Find or start the compositor for this guest. nullopt (with `why` when it
// matters) means: run without a display, as before.
[[nodiscard]] inline std::optional<Attachment> attach(const Options& o, std::string& why) {
    if (!o.wayland) return std::nullopt;
    const std::string root = detail::runtime_root();
    if (root.empty()) {
        why = host::tmp_path("linuxity-display-" + std::to_string(::getuid())) + " is not ours";
        return std::nullopt;
    }
    if (auto h = detail::host_compositor()) {
        h->runtime_root = root;
        return h;
    }
    if (!kOwnCompositor) return std::nullopt;
    // the part the guest sees: searchable by any guest user
    const std::string dir = root + "/wayland";
    if (!detail::own_dir(dir, 0755)) {
        why = dir + " is not ours";
        return std::nullopt;
    }
    const std::string socket = dir + "/wayland-0";
    if (!detail::socket_live(socket)) {
        const std::string bin = detail::display_binary();
        if (bin.empty()) return std::nullopt;   // a build without it: no display, quietly
        if (!detail::spawn_display(bin, socket, why)) return std::nullopt;
    }
    (void)::chmod(socket.c_str(), 0777);
    return Attachment{dir, "wayland-0", "linuxity-display", root};
}

inline void apply_hints(const Attachment& a, std::vector<std::string>& env);

// The guest's session: a private XDG_RUNTIME_DIR always (every desktop
// program expects one -- Firefox won't start without it, display or not),
// and a Wayland display unless display.wayland is off or the user named one
// (-e WAYLAND_DISPLAY=...). The binds also go into o.flags: hosts that
// re-run themselves per guest process (macOS fork children, zygotes)
// rebuild the namespace from those.
//
// The guest sees the standard layout -- XDG_RUNTIME_DIR=/run/user/UID with
// wayland-0 in it -- from ONE mount at /run/user (whose parent every distro
// has; a mount point under a missing directory leaves that directory
// unresolvable, and realpath($XDG_RUNTIME_DIR) would fail). wayland-0 there
// is a hard link to the compositor's socket (relinked by a compositor that
// restarts). Where a link can't be made (the host compositor's socket on
// another filesystem), the socket's directory is mounted at kGuestDisplay
// and WAYLAND_DISPLAY names it by absolute path, which libwayland accepts.
inline void setup(Options& o, std::vector<std::string>& env, std::uint32_t guest_uid, std::string& why) {
    auto bind = [&o](const std::string& host, const std::string& guest) {
        o.binds.emplace_back(host, guest);
        o.flags.insert(o.flags.end(), {"--bind", host + ":" + guest});
    };
    auto set = [&env](std::string_view k, const std::string& v) {
        const std::string prefix = std::string{k} + "=";
        for (auto& kv : env)
            if (kv.starts_with(prefix)) { kv = prefix + v; return; }
        env.push_back(prefix + v);
    };
    auto has = [&env](std::string_view k) {
        const std::string prefix = std::string{k} + "=";
        for (const auto& kv : env)
            if (kv.starts_with(prefix)) return true;
        return false;
    };

    // 1. the runtime dir
    std::string user_dir;   // host side of /run/user/<uid>
    if (!has("XDG_RUNTIME_DIR")) {
        const std::string root = detail::runtime_root();
        std::string env_name;
        for (const char c : o.env_name.empty() ? std::string{"run"} : o.env_name)
            env_name += (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_') ? c : '_';
        // this session's /run/user (detail::session_dir): fresh, ours alone;
        // <uid>/ in it is the user's (a root-owned dir it may write: 01777)
        const std::string users = root.empty() ? std::string{} : detail::session_dir(root + "/runtime/" + env_name);
        const std::string uid = std::to_string(guest_uid);
        if (!users.empty() && detail::own_dir(users + "/" + uid, 01777)) {
            user_dir = users + "/" + uid;
            bind(users, "/run/user");
            set("XDG_RUNTIME_DIR", "/run/user/" + uid);
        }
    }

    // 2. the display
    if (has("WAYLAND_DISPLAY")) return;   // the user chose a compositor
    const auto a = attach(o, why);
    if (!a) return;
    const std::string socket = a->host_dir + "/" + a->socket_name;
    bool linked = false;
    if (!user_dir.empty()) {
        const std::string link = user_dir + "/" + a->socket_name;
        (void)::unlink(link.c_str());
        linked = ::link(socket.c_str(), link.c_str()) == 0;
    }
    if (linked) {
        set("WAYLAND_DISPLAY", a->socket_name);
    } else {
        bind(a->host_dir, kGuestDisplay);
        set("WAYLAND_DISPLAY", std::string{kGuestDisplay} + "/" + a->socket_name);
    }
    apply_hints(*a, env);
}

// Toolkit settings for a guest with a Wayland display, unless already set.
inline void apply_hints(const Attachment& a, std::vector<std::string>& env) {
    auto set = [&env](std::string_view k, const std::string& v) {
        const std::string prefix = std::string{k} + "=";
        for (const auto& kv : env)
            if (kv.starts_with(prefix)) return;
        env.push_back(prefix + v);
    };
    // Toolkits: prefer Wayland; there is no X server unless the guest runs one.
    set("GDK_BACKEND", "wayland,x11");
    set("QT_QPA_PLATFORM", "wayland;xcb");
    set("SDL_VIDEODRIVER", "wayland,x11");
    set("MOZ_ENABLE_WAYLAND", "1");
    set("ELECTRON_OZONE_PLATFORM_HINT", "auto");
    set("XDG_SESSION_TYPE", "wayland");
    if (a.source != "linuxity-display") return;   // a host compositor is the host's business
    // linuxity-display takes wl_shm buffers only (no linux-dmabuf: the guest
    // has no GPU to share), so GL clients render with Mesa's llvmpipe and
    // hand over pixels. Say so up front: left to probe, Mesa tries zink and
    // DRI first, and its failure path crashes some clients (GTK4:
    // free(): invalid pointer).
    bool chosen = false;
    for (const auto& kv : env)
        if (kv.starts_with("LIBGL_ALWAYS_SOFTWARE=") || kv.starts_with("GALLIUM_DRIVER=")) chosen = true;
    if (!chosen) env.push_back("LIBGL_ALWAYS_SOFTWARE=1");
    // llvmpipe rasterizes on one thread per core. With 4+ threads GTK4
    // apps crash at renderer start-up on the macOS backend (a multi-vCPU
    // race still being chased; 1-2 threads never do), so cap it until then.
    set("LP_NUM_THREADS", "2");
}

#else

inline void setup(Options&, std::vector<std::string>&, std::uint32_t, std::string&) {}

#endif

}  // namespace lx::cli::display
