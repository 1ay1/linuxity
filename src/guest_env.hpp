// src/guest_env.hpp -- the guest's login environment, decided once.
//
// What a guest process starts with -- its variables, its identity, its
// PATH and locale -- is policy over the rootfs and Options, not over the
// host's way of running code. It used to be spelled twice: the Linux runner
// derived it from the guest's /etc/passwd, env.vibe and the host session,
// while the macOS runner hardcoded "root, /bin/bash, LANG=C.UTF-8" and
// ignored --user, -e, --clean-env, timezone and the rootfs's own locale.
// Now every host asks here.
#pragma once

#include "options.hpp"

#include "linuxity/env/passwd.hpp"
#include "linuxity/host/environ.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lx::cli {

// Can the guest's libc load locale `name`? Looks in each layer's
// /usr/lib/locale, as a directory or inside locale-archive.
inline bool guest_has_locale(const std::vector<std::string>& layers, std::string_view name) {
    if (name == "C" || name == "POSIX") return true;
    // split off the codeset and normalize it the way glibc does (UTF-8 -> utf8)
    std::string base{name}, mod;
    if (const auto at = base.find('@'); at != std::string::npos) { mod = base.substr(at); base.resize(at); }
    std::string lang = base, cs;
    if (const auto dot = base.find('.'); dot != std::string::npos) {
        lang = base.substr(0, dot);
        for (const char c : base.substr(dot + 1))
            if (std::isalnum(static_cast<unsigned char>(c)))
                cs.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (lang == "C" && cs == "utf8") return true;   // built into glibc and musl
    const std::string norm = cs.empty() ? lang + mod : lang + "." + cs + mod;
    bool any_locale_dir = false;
    for (const auto& l : layers) {
        const std::string dir = l + "/usr/lib/locale";
        struct ::stat st{};
        if (::stat(dir.c_str(), &st) != 0) continue;
        any_locale_dir = true;
        for (const std::string& n : {norm, std::string{name}})
            if (::stat((dir + "/" + n + "/LC_CTYPE").c_str(), &st) == 0) return true;
        // locale-archive keeps each name NUL-terminated; it can be large, so map it
        const int fd = ::open((dir + "/locale-archive").c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            struct ::stat ast{};
            bool hit = false;
            if (::fstat(fd, &ast) == 0 && ast.st_size > 0) {
                void* m = ::mmap(nullptr, static_cast<std::size_t>(ast.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
                if (m != MAP_FAILED) {
                    const std::string needle = std::string(1, '\0') + norm + '\0';
                    hit = ::memmem(m, static_cast<std::size_t>(ast.st_size), needle.data(), needle.size()) != nullptr;
                    ::munmap(m, static_cast<std::size_t>(ast.st_size));
                }
            }
            ::close(fd);
            if (hit) return true;
        }
    }
    // no locale files at all: musl, which accepts any name
    return !any_locale_dir;
}

inline bool is_utf8_name(std::string_view v) {
    std::string s;
    for (const char c : v) s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return s.find("utf-8") != std::string::npos || s.find("utf8") != std::string::npos;
}

// Give the guest a locale its libc can load, the way a distro login would.
// An unloadable one makes setlocale fail and every program falls back to
// ASCII: tmux then draws box and block characters as '_'.
inline void fix_guest_locale(std::vector<std::string>& env, const std::vector<std::string>& layers) {
    bool chosen = false;   // LANG, LC_ALL or LC_CTYPE picks the character set
    // a shell usually sets ten LC_* to the same value: check each name once
    std::vector<std::pair<std::string, bool>> known;
    const auto has = [&](std::string_view v) {
        for (const auto& [n, ok] : known) if (n == v) return ok;
        const bool ok = guest_has_locale(layers, v);
        known.emplace_back(std::string{v}, ok);
        return ok;
    };
    for (auto& kv : env) {
        if (!kv.starts_with("LANG=") && !kv.starts_with("LC_")) continue;
        const auto eq = kv.find('=');
        const std::string_view v = std::string_view{kv}.substr(eq + 1);
        if (v.empty()) continue;
        if (!has(v)) kv = kv.substr(0, eq + 1) + "C.UTF-8";
        if (kv.starts_with("LANG=") || kv.starts_with("LC_ALL=") || kv.starts_with("LC_CTYPE="))
            chosen = true;
    }
    if (chosen) return;
    // nothing chose a character set: the rootfs's own choice if it is a
    // usable UTF-8 one, else C.UTF-8 (every terminal today is UTF-8)
    std::string pick = "C.UTF-8";
    for (const auto& l : layers) {
        if (FILE* f = std::fopen((l + "/etc/locale.conf").c_str(), "r")) {
            char line[256];
            while (std::fgets(line, sizeof line, f)) {
                std::string_view s{line};
                if (!s.starts_with("LANG=")) continue;
                s.remove_prefix(5);
                while (!s.empty() && (s.back() == '\n' || s.back() == '"' || s.back() == '\'')) s.remove_suffix(1);
                while (!s.empty() && (s.front() == '"' || s.front() == '\'')) s.remove_prefix(1);
                if (is_utf8_name(s) && has(s)) pick = std::string{s};
            }
            std::fclose(f);
            break;   // the top layer's file wins
        }
    }
    env.emplace_back("LANG=" + pick);
}

// The guest's starting environment and who it runs as.
struct GuestEnv {
    std::vector<std::string> vars;            // NAME=value, in order
    std::vector<std::string> layers;          // host dirs of the tree, top first
    env::UserInfo login;                      // who pid 1 / sessions run as
    std::string error;                        // non-empty: refuse to start
    std::string notice;                       // non-empty: start, but say this
};

// The host's environment, or (login.clean-env) only login.pass-env; then,
// with a rootfs, the guest's own world: its user from /etc/passwd, its PATH,
// a loadable locale, TZ, and env.vibe's [env] / -e last so they win.
// Identity syscalls are virtualized either way; this is what programs READ.
[[nodiscard]] inline GuestEnv guest_env(const Options& o) {
    GuestEnv g;
    g.login.name = "root";
    for (char** e = host::host_environ(); e && *e; ++e) {
        const std::string_view kv{*e};
        if (kv.starts_with("LINUXITY_")) continue;   // ours, not the guest's
        if (o.clean_env) {
            const std::string_view name = kv.substr(0, kv.find('='));
            if (std::find(o.pass_env.begin(), o.pass_env.end(), name) == o.pass_env.end())
                continue;
        }
        g.vars.emplace_back(kv);
    }
    if (o.root.empty()) {
        for (const auto& [k, v] : o.env) g.vars.push_back(k + "=" + v);
        return g;
    }
    auto set_env = [&g](std::string_view key, std::string_view val) {
        const std::string prefix = std::string{key} + "=";
        for (auto& kv : g.vars)
            if (kv.starts_with(prefix)) { kv = prefix + std::string{val}; return; }
        g.vars.emplace_back(prefix + std::string{val});
    };
    if (!o.persist.empty()) g.layers.push_back(o.persist);
    g.layers.push_back(o.root);

    // With a rootfs, linuxity presents the guest's OWN world. The host shell
    // exported its identity (USER=ayush, HOME=/home/ayush) and those would
    // leak in: bash then shows `I have no name!` and HOME points at a host
    // path the rootfs doesn't have. So the identity comes from the guest's
    // /etc/passwd.
    auto who = env::resolve_user(g.layers, o.user);
    if (!who && o.instance && o.user != "root") {
        // the instance itself runs fine without it; sessions say why
        g.notice = "login user " + o.user + " isn't in this environment; "
                   "add it back with `linuxity adduser " + o.user + "`";
        who = env::resolve_user(g.layers, "root");
    }
    if (!who) {
        g.error = "there's no user '" + o.user + "' in this environment (a reset removes users). "
                  "Add it back with `linuxity adduser " + o.user + "`, or use `--user root`";
        return g;
    }
    g.login = *who;
    if (!o.shell.empty()) g.login.shell = o.shell;
    set_env("USER", g.login.name);
    set_env("LOGNAME", g.login.name);
    set_env("HOME", g.login.home);
    set_env("SHELL", g.login.shell);
    // The host's temp dir means nothing in the guest's namespace (adb
    // exports TMPDIR=/data/local/tmp; macOS a /var/folders path). A distro
    // leaves it unset and programs use /tmp.
    std::erase_if(g.vars, [](const std::string& kv) { return kv.starts_with("TMPDIR="); });
    // An X display that is a host socket PATH (macOS: XQuartz's launchd
    // socket, /private/tmp/com.apple.launchd.*/org.xquartz:0) names nothing
    // in the guest: Emacs and friends tried it, printed "Display ...
    // unavailable" and fell back. `:0`-style displays (a Linux host's
    // X11 socket) stay. Its XAUTHORITY goes with it.
    if (std::any_of(g.vars.begin(), g.vars.end(),
                    [](const std::string& kv) { return kv.starts_with("DISPLAY=/"); }))
        std::erase_if(g.vars, [](const std::string& kv) {
            return kv.starts_with("DISPLAY=") || kv.starts_with("XAUTHORITY=");
        });
    // a locale the rootfs can actually load (top layer first); an explicit
    // system.locale wins, and is still checked
    if (!o.locale.empty()) {
        std::erase_if(g.vars, [](const std::string& kv) {
            return kv.starts_with("LANG=") || kv.starts_with("LC_");
        });
        g.vars.push_back("LANG=" + o.locale);
    }
    fix_guest_locale(g.vars, g.layers);
    if (!o.timezone.empty()) set_env("TZ", o.timezone);
    // PATH belongs to the ROOTFS, not the host. Inheriting it works by luck
    // on a Linux host (/usr/bin is /usr/bin either way) and fails on Android
    // (/system/bin:/apex/...) and macOS (/opt/homebrew/bin...). Keep the
    // caller's extra directories that DO exist in the guest, so
    // `env PATH=/opt/mine:... linuxity` still means something.
    {
        std::string merged = "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin";
        if (const char* hp = std::getenv("PATH"); hp != nullptr) {
            std::string_view rest{hp};
            while (!rest.empty()) {
                const auto cut = rest.find(':');
                const std::string_view dir = rest.substr(0, cut);
                if (!dir.empty() && merged.find(std::string{dir}) == std::string::npos) {
                    struct ::stat pst{};
                    if (::stat((o.root + std::string{dir}).c_str(), &pst) == 0)
                        merged += ":" + std::string{dir};
                }
                if (cut == std::string_view::npos) break;
                rest.remove_prefix(cut + 1);
            }
        }
        set_env("PATH", merged);
    }
    // env.vibe's [env] and -e K=V come last, so they win
    for (const auto& [k, v] : o.env) set_env(k, v);
    return g;
}

}  // namespace lx::cli
