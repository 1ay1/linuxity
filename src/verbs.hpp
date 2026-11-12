// src/verbs.hpp -- every linuxity command, listed once.
//
// Two front doors, one binary:
//   lx [@ENV] [-u U] [-C DIR] [-e K=V] [--temp] [-v H:G] [CMD...]   run things
//   linuxity VERB ...                                                manage environments
// Help, dispatch, typo hints and completion all read this table.
#pragma once

#include <string_view>

namespace lx::cli {

// What a verb's positionals are, for completion and env resolution.
enum class VerbArg {
    none,
    env,        // [ENV]: a bare first word is the environment (info, stop, rm, ...)
    image,      // new: a catalog image (or a file)
    key,        // config: settings keys
    snap,       // snap: save|restore|rm, then a snapshot
    user,       // user: add, then a name
    svc,        // svc: start|stop|restart, then a service
    verb,       // help: another verb
    shell,      // completion: bash|zsh|fish
};

enum class VerbGroup { environments, settings, state, running, other };

struct Verb {
    std::string_view name;
    std::string_view usage;      // what follows `linuxity `
    std::string_view summary;
    VerbGroup group;
    VerbArg arg;
    bool instances_only;         // needs background instances (host_runs_instances)
    bool needs_name;             // destroys data: the env must be named, never defaulted
};

// clang-format off
inline constexpr Verb kVerbTable[] = {
    {"new",    "new DISTRO|FILE|DIR [NAME]", "make an environment (no DISTRO: what you can download)", VerbGroup::environments, VerbArg::image, false, false},
    {"ls",     "ls",                    "your environments (* is the default)",                 VerbGroup::environments, VerbArg::none,  false, false},
    {"info",   "info [ENV]",            "everything about one, live state too",                 VerbGroup::environments, VerbArg::env,   false, false},
    {"use",    "use ENV",               "make it the default",                                  VerbGroup::environments, VerbArg::env,   false, false},
    {"mv",     "mv OLD NEW",            "rename one",                                           VerbGroup::environments, VerbArg::env,   false, true},
    {"rm",     "rm ENV",                "delete one, image and changes",                        VerbGroup::environments, VerbArg::env,   false, true},
    {"export", "export [@ENV] FILE",    "the whole environment as a tarball",                   VerbGroup::environments, VerbArg::none,  false, false},
    {"config", "config [@ENV] [KEY[=VALUE]...]", "show or change settings (KEY= resets, --edit)", VerbGroup::settings,   VerbArg::key,   false, false},
    {"user",   "user [@ENV] [add NAME]", "login users, or add one with sudo",                   VerbGroup::settings,     VerbArg::user,  false, false},
    {"snap",   "snap [@ENV] [save|restore|rm NAME]", "snapshots of your changes",               VerbGroup::state,        VerbArg::snap,  false, false},
    {"reset",  "reset ENV",             "drop every change: back to the clean image",           VerbGroup::state,        VerbArg::env,   false, true},
    {"start",  "start [ENV]",           "run it in the background (running: apply env.vibe)",   VerbGroup::running,      VerbArg::env,   true,  false},
    {"stop",   "stop [ENV]",            "stop it",                                              VerbGroup::running,      VerbArg::env,   true,  false},
    {"ps",     "ps [ENV]",              "its processes",                                        VerbGroup::running,      VerbArg::env,   true,  false},
    {"svc",    "svc [@ENV] [start|stop|restart NAME]", "its services",                          VerbGroup::running,      VerbArg::svc,   true,  false},
    {"logs",   "logs [@ENV] [SVC] [-f]", "its log, or a service's",                             VerbGroup::running,      VerbArg::none,  true,  false},
    {"help",   "help [VERB | --all]",   "this, a verb's details, or the engine flags",          VerbGroup::other,        VerbArg::verb,  false, false},
    {"completion", "completion bash|zsh|fish", "tab completion for linuxity and lx",            VerbGroup::other,        VerbArg::shell, false, false},
    {"version", "version",              "which linuxity this is",                               VerbGroup::other,        VerbArg::none,  false, false},
};
// clang-format on

// Old verbs, and the command that replaced each. Typing one prints its line.
inline constexpr std::pair<std::string_view, std::string_view> kMovedVerbs[] = {
    {"shell", "lx"},                      {"exec", "lx CMD"},
    {"run", "lx CMD   (lx --temp CMD for a throwaway run)"},
    {"list", "linuxity ls"},              {"default", "linuxity use ENV"},
    {"rename", "linuxity mv OLD NEW"},    {"remove", "linuxity rm ENV"},
    {"import", "linuxity new FILE|DIR [NAME]"}, {"images", "linuxity new"},
    {"up", "linuxity start"},             {"down", "linuxity stop"},
    {"status", "linuxity info"},          {"path", "linuxity info"},
    {"check", "linuxity info"},           {"show", "linuxity info"},
    {"kill", "lx kill PID"},              {"reload", "linuxity start (on a running env it applies env.vibe)"},
    {"set", "linuxity config KEY=VALUE"}, {"get", "linuxity config [KEY]"},
    {"unset", "linuxity config KEY="},    {"edit", "linuxity config --edit"},
    {"schema", "linuxity config --schema"},
    {"adduser", "linuxity user add NAME"}, {"users", "linuxity user"},
    {"snapshot", "linuxity snap save NAME"}, {"snapshots", "linuxity snap"},
    {"restore", "linuxity snap restore NAME"}, {"drop-snapshot", "linuxity snap rm NAME"},
    {"env", "linuxity help"},
};

[[nodiscard]] constexpr const Verb* find_verb(std::string_view name) noexcept {
    for (const auto& v : kVerbTable)
        if (v.name == name) return &v;
    return nullptr;
}

[[nodiscard]] constexpr std::string_view moved_verb(std::string_view name) noexcept {
    for (const auto& [from, to] : kMovedVerbs)
        if (from == name) return to;
    return {};
}

// Shown in help and offered by completion: usable on this host.
[[nodiscard]] constexpr bool verb_listed(const Verb& v, bool host_has_instances) noexcept {
    return host_has_instances || !v.instances_only;
}

static_assert(find_verb("new") && !find_verb("shell") && !moved_verb("shell").empty());

}  // namespace lx::cli
