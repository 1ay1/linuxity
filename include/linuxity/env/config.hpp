// linuxity/env/config.hpp
//
// env.vibe: the per-environment config file, in VIBE (third_party/vibe).
//
// Every key is declared ONCE, in kFields below. That table drives parsing,
// type checking, "unknown key" warnings, `linuxity env set`, and the JSON
// schema the Android app builds its settings screen from. Adding a knob is
// one row here plus wherever it takes effect.
//
// Named tables (env, mount.<name>, service.<name>) have their own small
// parsers further down, because their keys are chosen by the user.
#pragma once

#include "linuxity/env/json.hpp"
#include "linuxity/kernel/resources.hpp"

#include "vibe.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lx::env {

enum class Type { string, integer, number, boolean, strings, size, choice };

[[nodiscard]] constexpr std::string_view type_name(Type t) {
    switch (t) {
        case Type::string:  return "string";
        case Type::integer: return "integer";
        case Type::number:  return "number";
        case Type::boolean: return "boolean";
        case Type::strings: return "strings";
        case Type::size:    return "size";
        case Type::choice:  return "choice";
    }
    return "?";
}

enum class Restart { no, on_failure, always };

struct Mount {
    std::string name;
    std::string host;   // host directory
    std::string at;     // guest path
};

struct Service {
    std::string name;
    std::vector<std::string> command;
    std::string user;   // "" = login.user
    std::string cwd;    // "" = the user's home
    bool autostart{true};
    Restart restart{Restart::on_failure};
    std::vector<std::pair<std::string, std::string>> env;
};

struct EnvConfig {
    std::string name;
    std::string rootfs;
    std::string upper;          // "" = <envdir>/upper

    // system
    std::string hostname{"linuxity"};
    std::string kernel_release{"6.6.0-linuxity"};
    bool host_hardware{true};
    bool host_pids{false};
    std::string timezone;
    std::string locale;

    // network
    std::vector<std::string> dns;
    bool manage_dns{true};
    bool manage_hosts{true};

    // login
    std::string user{"root"};
    std::string shell;
    std::string cwd;
    std::vector<std::string> command;
    std::string umask{"022"};
    bool clean_env{true};
    std::vector<std::string> pass_env{"TERM", "COLORTERM", "DISPLAY", "WAYLAND_DISPLAY"};

    // limits
    kernel::ResourceSpec limits;

    // storage
    bool persist{true};
    bool private_tmp{true};

    // compat
    bool emulate_fifos{false};
    bool emulate_sysv{false};
    bool emulate_nl80211{false};
    bool emulate_hardlinks{false};
    bool pacman_overwrite{true};

    // bridge
    bool bridge{true};
    bool bridge_host_fallback{true};

    // debug
    std::string trace;
    std::string log;

    std::vector<std::pair<std::string, std::string>> env;
    std::vector<Mount> mounts;
    std::vector<Service> services;
};

// A converted value, ready for a setter.
struct Val {
    std::string s;
    std::int64_t i{0};
    double d{0};
    bool b{false};
    std::vector<std::string> list;
};

struct Field {
    std::string_view path;
    Type type;
    std::string_view def;       // default as text, "" = none / automatic
    std::string_view doc;
    std::string_view choices;   // Type::choice: "a|b|c"
    bool live;                  // `linuxity reload` applies it to a running instance
    void (*set)(EnvConfig&, const Val&);
};

// clang-format off
inline constexpr Field kFields[] = {
    {"name", Type::string, "", "Display name of the environment.", "", false,
        [](EnvConfig& c, const Val& v) { c.name = v.s; }},
    {"rootfs", Type::string, "", "Host directory holding the distro tree. Never written to.", "", false,
        [](EnvConfig& c, const Val& v) { c.rootfs = v.s; }},
    {"upper", Type::string, "", "Host directory that receives every write (default: <env>/upper).", "", false,
        [](EnvConfig& c, const Val& v) { c.upper = v.s; }},

    {"system.hostname", Type::string, "linuxity", "Hostname the guest sees (uname -n, /etc/hostname).", "", true,
        [](EnvConfig& c, const Val& v) { c.hostname = v.s; }},
    {"system.kernel-release", Type::string, "6.6.0-linuxity", "Kernel release the guest sees (uname -r).", "", false,
        [](EnvConfig& c, const Val& v) { c.kernel_release = v.s; }},
    {"system.host-hardware", Type::boolean, "true", "Show the real CPU, memory, thermal and battery data instead of a synthetic machine.", "", false,
        [](EnvConfig& c, const Val& v) { c.host_hardware = v.b; }},
    {"system.host-pids", Type::boolean, "false", "Share the host's pid space, like docker --pid=host.", "", false,
        [](EnvConfig& c, const Val& v) { c.host_pids = v.b; }},
    {"system.timezone", Type::string, "", "Timezone name, e.g. Europe/Berlin (sets TZ). Empty: the image's /etc/localtime.", "", false,
        [](EnvConfig& c, const Val& v) { c.timezone = v.s; }},
    {"system.locale", Type::string, "", "Locale, e.g. en_US.UTF-8. Empty: the best one the image can load.", "", false,
        [](EnvConfig& c, const Val& v) { c.locale = v.s; }},

    {"network.dns", Type::strings, "", "Nameservers for /etc/resolv.conf. Empty: the image's own, else the host's, else public ones.", "", true,
        [](EnvConfig& c, const Val& v) { c.dns = v.list; }},
    {"network.manage-dns", Type::boolean, "true", "Serve a resolv.conf when the image has none. Off: leave DNS to the image.", "", false,
        [](EnvConfig& c, const Val& v) { c.manage_dns = v.b; }},
    {"network.manage-hosts", Type::boolean, "true", "Add the hostname to /etc/hosts, like WSL and Docker do. Off: /etc/hosts is the image's, editable.", "", false,
        [](EnvConfig& c, const Val& v) { c.manage_hosts = v.b; }},

    {"login.user", Type::string, "root", "User that shells and commands run as. Must exist in the guest's /etc/passwd (add one with `env adduser`).", "", true,
        [](EnvConfig& c, const Val& v) { c.user = v.s; }},
    {"login.shell", Type::string, "", "Login shell. Empty: the user's shell from /etc/passwd.", "", true,
        [](EnvConfig& c, const Val& v) { c.shell = v.s; }},
    {"login.cwd", Type::string, "", "Starting directory. Empty: the user's home.", "", true,
        [](EnvConfig& c, const Val& v) { c.cwd = v.s; }},
    {"login.command", Type::strings, "", "What a new session runs. Empty: the login shell with -l.", "", true,
        [](EnvConfig& c, const Val& v) { c.command = v.list; }},
    {"login.umask", Type::string, "022", "File creation mask, octal (umask 022 and umask \"022\" both work).", "", false,
        [](EnvConfig& c, const Val& v) { c.umask = v.s; }},
    {"login.clean-env", Type::boolean, "true", "Start from an empty environment instead of inheriting the host's.", "", false,
        [](EnvConfig& c, const Val& v) { c.clean_env = v.b; }},
    {"login.pass-env", Type::strings, "TERM COLORTERM DISPLAY WAYLAND_DISPLAY", "Host variables kept when clean-env is on.", "", false,
        [](EnvConfig& c, const Val& v) { c.pass_env = v.list; }},

    {"limits.cpus", Type::number, "", "CPU ceiling in cores, e.g. 1.5.", "", false,
        [](EnvConfig& c, const Val& v) { c.limits.cpus = v.d; }},
    {"limits.memory", Type::size, "", "Memory ceiling, e.g. 2G.", "", false,
        [](EnvConfig& c, const Val& v) { c.limits.mem_max = static_cast<std::uint64_t>(v.i); }},
    {"limits.memory-swap", Type::size, "", "Memory plus swap ceiling.", "", false,
        [](EnvConfig& c, const Val& v) { c.limits.swap_and_mem_max = static_cast<std::uint64_t>(v.i); }},
    {"limits.pids", Type::integer, "", "Most tasks the guest may run at once.", "", false,
        [](EnvConfig& c, const Val& v) { c.limits.pids_max = static_cast<std::uint64_t>(v.i); }},
    {"limits.cpuset", Type::string, "", "CPUs to pin to, e.g. 0-3 or 0,2,4.", "", false,
        [](EnvConfig& c, const Val& v) { c.limits.cpuset = v.s; }},

    {"storage.persist", Type::boolean, "true", "Keep writes across runs. Off: every run starts from the clean image.", "", false,
        [](EnvConfig& c, const Val& v) { c.persist = v.b; }},
    {"storage.private-tmp", Type::boolean, "true", "Give the guest its own /tmp.", "", false,
        [](EnvConfig& c, const Val& v) { c.private_tmp = v.b; }},

    {"compat.fifos", Type::choice, "auto", "Named FIFOs: real where the host allows them, or always emulated.", "auto|emulate", false,
        [](EnvConfig& c, const Val& v) { c.emulate_fifos = v.s == "emulate"; }},
    {"compat.sysv-ipc", Type::choice, "auto", "SysV IPC: the host's where it has one, or always emulated.", "auto|emulate", false,
        [](EnvConfig& c, const Val& v) { c.emulate_sysv = v.s == "emulate"; }},
    {"compat.nl80211", Type::choice, "auto", "Wifi netlink: the host's where allowed, or always emulated.", "auto|emulate", false,
        [](EnvConfig& c, const Val& v) { c.emulate_nl80211 = v.s == "emulate"; }},
    {"compat.hardlinks", Type::choice, "auto", "Hard links: real where the host allows them, or always emulated.", "auto|emulate", false,
        [](EnvConfig& c, const Val& v) { c.emulate_hardlinks = v.s == "emulate"; }},
    {"compat.pacman-overwrite", Type::boolean, "true", "Pass --overwrite \"*\" to pacman so bootstrap images can install packages.", "", false,
        [](EnvConfig& c, const Val& v) { c.pacman_overwrite = v.b; }},

    {"bridge.enabled", Type::boolean, "true", "Let the guest open links, use the clipboard and post notifications on the host.", "", false,
        [](EnvConfig& c, const Val& v) { c.bridge = v.b; }},
    {"bridge.host-fallback", Type::boolean, "true", "With no app attached, use host tools (xdg-open, wl-copy, notify-send).", "", false,
        [](EnvConfig& c, const Val& v) { c.bridge_host_fallback = v.b; }},

    {"debug.trace", Type::string, "", "Log every syscall decision: a file path, or stderr.", "", false,
        [](EnvConfig& c, const Val& v) { c.trace = v.s; }},
    {"debug.log", Type::string, "", "Where a detached instance logs (default: <env>/logs/linuxity.log).", "", false,
        [](EnvConfig& c, const Val& v) { c.log = v.s; }},
};
// clang-format on

// The user-named tables, described for the schema and for `env set`.
struct DynField {
    std::string_view pattern;   // "service.<name>.command"
    Type type;
    std::string_view def;
    std::string_view doc;
    std::string_view choices;
};

inline constexpr DynField kDynFields[] = {
    {"env.<NAME>", Type::string, "", "An environment variable for every session and service.", ""},
    {"mount.<name>.host", Type::string, "", "Host directory to expose. Writes land on the real files.", ""},
    {"mount.<name>.at", Type::string, "", "Guest path it appears at.", ""},
    {"service.<name>.command", Type::strings, "", "Program and arguments.", ""},
    {"service.<name>.user", Type::string, "", "User it runs as (default: login.user).", ""},
    {"service.<name>.cwd", Type::string, "", "Working directory (default: the user's home).", ""},
    {"service.<name>.autostart", Type::boolean, "true", "Start with the instance.", ""},
    {"service.<name>.restart", Type::choice, "on-failure", "When to restart it after it exits.", "no|on-failure|always"},
    {"service.<name>.env.<NAME>", Type::string, "", "An environment variable for this service only.", ""},
};

[[nodiscard]] inline const Field* find_field(std::string_view path) {
    for (const auto& f : kFields)
        if (f.path == path) return &f;
    return nullptr;
}

// The schema entry for a user-named path ("service.web.restart"), if any.
[[nodiscard]] inline const DynField* find_dyn_field(std::string_view path) {
    auto seg = [](std::string_view s) {
        std::vector<std::string_view> out;
        while (true) {
            const auto dot = s.find('.');
            out.push_back(s.substr(0, dot));
            if (dot == std::string_view::npos) break;
            s.remove_prefix(dot + 1);
        }
        return out;
    };
    const auto have = seg(path);
    for (const auto& d : kDynFields) {
        const auto want = seg(d.pattern);
        if (want.size() != have.size()) continue;
        bool ok = true;
        for (std::size_t i = 0; i < want.size() && ok; ++i) {
            if (want[i].starts_with('<')) ok = !have[i].empty();
            else ok = want[i] == have[i];
        }
        if (ok) return &d;
    }
    return nullptr;
}

struct Diag {
    std::string path;
    std::string message;
    bool error{true};
    int line{0};
};

[[nodiscard]] inline std::size_t edit_distance(std::string_view a, std::string_view b) {
    std::vector<std::size_t> row(b.size() + 1);
    for (std::size_t j = 0; j <= b.size(); ++j) row[j] = j;
    for (std::size_t i = 1; i <= a.size(); ++i) {
        std::size_t prev = row[0];
        row[0] = i;
        for (std::size_t j = 1; j <= b.size(); ++j) {
            const std::size_t cur = row[j];
            row[j] = std::min({row[j] + 1, row[j - 1] + 1, prev + (a[i - 1] == b[j - 1] ? 0 : 1)});
            prev = cur;
        }
    }
    return row[b.size()];
}

// The closest known key to a misspelt one, or "" if nothing is close.
[[nodiscard]] inline std::string suggest(std::string_view path) {
    std::string best;
    std::size_t best_d = 4;
    for (const auto& f : kFields) {
        const auto d = edit_distance(path, f.path);
        if (d < best_d) { best_d = d; best = std::string{f.path}; }
    }
    return best;
}

// --- value conversion ------------------------------------------------------

[[nodiscard]] inline std::string scalar_text(const VibeValue* v) {
    switch (v->type) {
        case VIBE_TYPE_STRING:  return v->as_string ? v->as_string : "";
        case VIBE_TYPE_INTEGER: return std::to_string(v->as_integer);
        case VIBE_TYPE_FLOAT: {
            char buf[32];
            std::snprintf(buf, sizeof buf, "%g", v->as_float);
            return buf;
        }
        case VIBE_TYPE_BOOLEAN: return v->as_boolean ? "true" : "false";
        default: return {};
    }
}

[[nodiscard]] inline bool is_scalar(const VibeValue* v) {
    return v->type == VIBE_TYPE_STRING || v->type == VIBE_TYPE_INTEGER ||
           v->type == VIBE_TYPE_FLOAT || v->type == VIBE_TYPE_BOOLEAN;
}

// Convert `v` to `t`. On failure returns nullopt and sets `why`.
[[nodiscard]] inline std::optional<Val> convert(const VibeValue* v, Type t,
                                                std::string_view choices, std::string& why) {
    Val out;
    switch (t) {
        case Type::string:
            // a hostname or release can look like a number; accept the text
            if (v->type == VIBE_TYPE_STRING || v->type == VIBE_TYPE_INTEGER ||
                v->type == VIBE_TYPE_FLOAT) {
                out.s = scalar_text(v);
                return out;
            }
            why = "expected a string";
            return std::nullopt;
        case Type::integer:
            if (v->type == VIBE_TYPE_INTEGER) { out.i = v->as_integer; return out; }
            why = "expected an integer";
            return std::nullopt;
        case Type::number:
            if (v->type == VIBE_TYPE_INTEGER) { out.d = static_cast<double>(v->as_integer); return out; }
            if (v->type == VIBE_TYPE_FLOAT) { out.d = v->as_float; return out; }
            why = "expected a number";
            return std::nullopt;
        case Type::boolean:
            if (v->type == VIBE_TYPE_BOOLEAN) { out.b = v->as_boolean; return out; }
            why = "expected true or false";
            return std::nullopt;
        case Type::strings:
            if (v->type == VIBE_TYPE_ARRAY) {
                for (std::size_t i = 0; i < v->as_array->count; ++i)
                    out.list.push_back(scalar_text(v->as_array->values[i]));
                return out;
            }
            if (is_scalar(v) && v->type != VIBE_TYPE_BOOLEAN) {
                out.list.push_back(scalar_text(v));
                return out;
            }
            why = "expected a list, e.g. [ a b c ]";
            return std::nullopt;
        case Type::size:
            if (v->type == VIBE_TYPE_INTEGER && v->as_integer >= 0) { out.i = v->as_integer; return out; }
            if (v->type == VIBE_TYPE_STRING && v->as_string) {
                if (auto b = kernel::parse_bytes(v->as_string)) {
                    out.i = static_cast<std::int64_t>(*b);
                    return out;
                }
            }
            why = "expected a size, e.g. 512M or 2G";
            return std::nullopt;
        case Type::choice: {
            const std::string s = is_scalar(v) ? scalar_text(v) : std::string{};
            std::string_view rest = choices;
            while (!rest.empty()) {
                const auto bar = rest.find('|');
                if (rest.substr(0, bar) == s) { out.s = s; return out; }
                if (bar == std::string_view::npos) break;
                rest.remove_prefix(bar + 1);
            }
            why = "expected one of: ";
            for (const char c : choices) why += c == '|' ? std::string{", "} : std::string(1, c);
            return std::nullopt;
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<Restart> parse_restart(std::string_view s) {
    if (s == "no") return Restart::no;
    if (s == "on-failure") return Restart::on_failure;
    if (s == "always") return Restart::always;
    return std::nullopt;
}

[[nodiscard]] inline std::string_view restart_name(Restart r) {
    switch (r) {
        case Restart::no: return "no";
        case Restart::on_failure: return "on-failure";
        case Restart::always: return "always";
    }
    return "?";
}

// --- the parser ------------------------------------------------------------

struct ParseResult {
    EnvConfig config;
    std::vector<Diag> diags;
    [[nodiscard]] bool ok() const {
        return std::none_of(diags.begin(), diags.end(), [](const Diag& d) { return d.error; });
    }
};

namespace detail {

inline void read_string_map(const VibeValue* obj, const std::string& at,
                            std::vector<std::pair<std::string, std::string>>& out,
                            std::vector<Diag>& diags) {
    if (obj->type != VIBE_TYPE_OBJECT) {
        diags.push_back({at, "expected a block of NAME value lines", true});
        return;
    }
    for (std::size_t i = 0; i < obj->as_object->count; ++i) {
        const auto& e = obj->as_object->entries[i];
        if (!is_scalar(e.value)) {
            diags.push_back({at + "." + e.key, "expected a single value", true});
            continue;
        }
        out.emplace_back(e.key, scalar_text(e.value));
    }
}

inline void read_mounts(const VibeValue* obj, EnvConfig& c, std::vector<Diag>& diags) {
    if (obj->type != VIBE_TYPE_OBJECT) {
        diags.push_back({"mount", "expected named mounts: mount NAME { host ... at ... }", true});
        return;
    }
    for (std::size_t i = 0; i < obj->as_object->count; ++i) {
        const auto& e = obj->as_object->entries[i];
        const std::string at = std::string{"mount."} + e.key;
        if (e.value->type != VIBE_TYPE_OBJECT) {
            diags.push_back({at, "expected a block with host and at", true});
            continue;
        }
        Mount m;
        m.name = e.key;
        for (std::size_t j = 0; j < e.value->as_object->count; ++j) {
            const auto& f = e.value->as_object->entries[j];
            const std::string fp = at + "." + f.key;
            std::string why;
            if (std::strcmp(f.key, "host") == 0 || std::strcmp(f.key, "at") == 0) {
                auto v = convert(f.value, Type::string, {}, why);
                if (!v) { diags.push_back({fp, why, true}); continue; }
                (f.key[0] == 'h' ? m.host : m.at) = v->s;
            } else {
                diags.push_back({fp, "unknown key (a mount has host and at)", false});
            }
        }
        if (m.host.empty()) diags.push_back({at + ".host", "missing", true});
        if (m.at.empty()) diags.push_back({at + ".at", "missing", true});
        else if (m.at.front() != '/') diags.push_back({at + ".at", "must be an absolute guest path", true});
        if (!m.host.empty() && !m.at.empty()) c.mounts.push_back(std::move(m));
    }
}

inline void read_services(const VibeValue* obj, EnvConfig& c, std::vector<Diag>& diags) {
    if (obj->type != VIBE_TYPE_OBJECT) {
        diags.push_back({"service", "expected named services: service NAME { command [ ... ] }", true});
        return;
    }
    for (std::size_t i = 0; i < obj->as_object->count; ++i) {
        const auto& e = obj->as_object->entries[i];
        const std::string at = std::string{"service."} + e.key;
        if (e.value->type != VIBE_TYPE_OBJECT) {
            diags.push_back({at, "expected a block with at least a command", true});
            continue;
        }
        Service s;
        s.name = e.key;
        for (std::size_t j = 0; j < e.value->as_object->count; ++j) {
            const auto& f = e.value->as_object->entries[j];
            const std::string fp = at + "." + f.key;
            const std::string_view k = f.key;
            std::string why;
            if (k == "env") {
                read_string_map(f.value, fp, s.env, diags);
                continue;
            }
            const DynField* d = find_dyn_field(fp);
            if (!d) {
                diags.push_back({fp, "unknown key (a service has command, user, cwd, autostart, restart, env)", false});
                continue;
            }
            auto v = convert(f.value, d->type, d->choices, why);
            if (!v) { diags.push_back({fp, why, true}); continue; }
            if (k == "command") s.command = v->list;
            else if (k == "user") s.user = v->s;
            else if (k == "cwd") s.cwd = v->s;
            else if (k == "autostart") s.autostart = v->b;
            else if (k == "restart") s.restart = *parse_restart(v->s);
        }
        if (s.command.empty()) {
            diags.push_back({at + ".command", "missing", true});
            continue;
        }
        c.services.push_back(std::move(s));
    }
}

inline void walk(const VibeValue* obj, const std::string& prefix, EnvConfig& c,
                 std::vector<Diag>& diags) {
    for (std::size_t i = 0; i < obj->as_object->count; ++i) {
        const auto& e = obj->as_object->entries[i];
        const std::string path = prefix.empty() ? std::string{e.key} : prefix + "." + e.key;
        if (prefix.empty()) {
            if (path == "env") { read_string_map(e.value, path, c.env, diags); continue; }
            if (path == "mount") { read_mounts(e.value, c, diags); continue; }
            if (path == "service") { read_services(e.value, c, diags); continue; }
        }
        if (const Field* f = find_field(path)) {
            std::string why;
            if (auto v = convert(e.value, f->type, f->choices, why)) f->set(c, *v);
            else diags.push_back({path, why, true});
            continue;
        }
        if (e.value->type == VIBE_TYPE_OBJECT) {
            // a known section ("system") or an unknown one: recurse either way
            // so a typo deeper down still gets its own message
            bool known = false;
            for (const auto& f : kFields)
                if (f.path.starts_with(path + ".")) { known = true; break; }
            if (known) { walk(e.value, path, c, diags); continue; }
        }
        std::string msg = "unknown key";
        if (const std::string s = suggest(path); !s.empty()) msg += ", did you mean " + s + "?";
        diags.push_back({path, msg, false});
    }
}

}  // namespace detail

[[nodiscard]] inline ParseResult parse_config(std::string_view text) {
    ParseResult r;
    VibeError err{};
    VibeValue* root = vibe_parse(text.data(), text.size(), &err);
    if (!root) {
        Diag d;
        d.message = err.message ? err.message : "parse error";
        d.line = err.line;
        r.diags.push_back(std::move(d));
        vibe_error_free(&err);
        return r;
    }
    if (root->type == VIBE_TYPE_OBJECT) detail::walk(root, "", r.config, r.diags);
    vibe_value_free(root);
    return r;
}

// What running an environment needs on top of a clean parse.
inline void check_runnable(const EnvConfig& c, std::vector<Diag>& diags) {
    if (c.rootfs.empty()) diags.push_back({"rootfs", "missing: which distro tree to run", true});
    if (c.umask.empty() || c.umask.size() > 4 ||
        c.umask.find_first_not_of("01234567") != std::string::npos)
        diags.push_back({"login.umask", "must be octal, e.g. 022", true});
}

[[nodiscard]] inline unsigned umask_value(const EnvConfig& c) {
    return static_cast<unsigned>(std::strtoul(c.umask.c_str(), nullptr, 8)) & 0777u;
}

[[nodiscard]] inline std::string format_diag(const Diag& d) {
    std::string s = d.error ? "error" : "warning";
    if (d.line > 0) s += " (line " + std::to_string(d.line) + ")";
    if (!d.path.empty()) s += ": " + d.path;
    s += ": " + d.message;
    return s;
}

// --- JSON views for the app -------------------------------------------------

[[nodiscard]] inline std::string schema_json() {
    Json j;
    j.obj().kv("version", 1).key("fields").arr();
    for (const auto& f : kFields) {
        j.obj().kv("path", f.path).kv("type", type_name(f.type)).kv("default", f.def)
            .kv("doc", f.doc).kv("live", f.live);
        if (!f.choices.empty()) {
            j.key("choices").arr();
            std::string_view rest = f.choices;
            while (true) {
                const auto bar = rest.find('|');
                j.str(rest.substr(0, bar));
                if (bar == std::string_view::npos) break;
                rest.remove_prefix(bar + 1);
            }
            j.end();
        }
        j.end();
    }
    j.end().key("tables").arr();
    for (const auto& d : kDynFields) {
        j.obj().kv("pattern", d.pattern).kv("type", type_name(d.type)).kv("default", d.def)
            .kv("doc", d.doc);
        if (!d.choices.empty()) j.kv("choices", std::string{d.choices});
        j.end();
    }
    return j.end().end().take();
}

[[nodiscard]] inline std::string config_json(const EnvConfig& c) {
    Json j;
    auto opt_u = [&](std::string_view k, const std::optional<std::uint64_t>& v) {
        if (v) j.kv(k, *v); else j.key(k).null();
    };
    j.obj()
        .kv("name", c.name).kv("rootfs", c.rootfs).kv("upper", c.upper)
        .key("system").obj()
            .kv("hostname", c.hostname).kv("kernel-release", c.kernel_release)
            .kv("host-hardware", c.host_hardware).kv("host-pids", c.host_pids)
            .kv("timezone", c.timezone).kv("locale", c.locale)
        .end()
        .key("network").obj().kv("dns", c.dns).kv("manage-dns", c.manage_dns).kv("manage-hosts", c.manage_hosts).end()
        .key("login").obj()
            .kv("user", c.user).kv("shell", c.shell).kv("cwd", c.cwd)
            .kv("command", c.command).kv("umask", c.umask)
            .kv("clean-env", c.clean_env).kv("pass-env", c.pass_env)
        .end()
        .key("limits").obj();
    if (c.limits.cpus) j.kv("cpus", *c.limits.cpus); else j.key("cpus").null();
    opt_u("memory", c.limits.mem_max);
    opt_u("memory-swap", c.limits.swap_and_mem_max);
    opt_u("pids", c.limits.pids_max);
    j.kv("cpuset", c.limits.cpuset.value_or("")).end()
        .key("storage").obj().kv("persist", c.persist).kv("private-tmp", c.private_tmp).end()
        .key("compat").obj()
            .kv("fifos", c.emulate_fifos ? "emulate" : "auto")
            .kv("sysv-ipc", c.emulate_sysv ? "emulate" : "auto")
            .kv("nl80211", c.emulate_nl80211 ? "emulate" : "auto")
            .kv("hardlinks", c.emulate_hardlinks ? "emulate" : "auto")
            .kv("pacman-overwrite", c.pacman_overwrite)
        .end()
        .key("bridge").obj().kv("enabled", c.bridge).kv("host-fallback", c.bridge_host_fallback).end()
        .key("debug").obj().kv("trace", c.trace).kv("log", c.log).end()
        .key("env").obj();
    for (const auto& [k, v] : c.env) j.kv(k, v);
    j.end().key("mount").obj();
    for (const auto& m : c.mounts) j.key(m.name).obj().kv("host", m.host).kv("at", m.at).end();
    j.end().key("service").obj();
    for (const auto& s : c.services) {
        j.key(s.name).obj().kv("command", s.command).kv("user", s.user).kv("cwd", s.cwd)
            .kv("autostart", s.autostart).kv("restart", restart_name(s.restart)).key("env").obj();
        for (const auto& [k, v] : s.env) j.kv(k, v);
        j.end().end();
    }
    return j.end().end().take();
}

}  // namespace lx::env
