// src/verbs.hpp -- every linuxity command, listed once.
//
// The verbs used to be spelled four ways: main.cpp's kVerbs (is this word a
// command?), cli.cpp's hand-written help(), its dispatch chain, and the
// kEnvVerbs list of what routes through `env`. A verb added to one and not
// the others was either unreachable, undocumented, or never suggested. Now
// each fact about a verb is a field here, and help, dispatch, typo hints and
// shell completion all read this table.
#pragma once

#include <string_view>

namespace lx::cli {

// What a verb's first argument is, for completion.
enum class VerbArg {
    none,
    env,             // [ENV] ...
    env_key,         // [ENV] KEY  (set/get/unset)
    env_snapshot,    // [ENV] SNAPSHOT  (restore/drop-snapshot)
    image,           // a catalog image (new)
    verb,            // another verb (help)
    shell,           // bash|zsh|fish (completion)
};

enum class VerbGroup { environments, use, running, settings, state, other };

struct Verb {
    std::string_view name;
    std::string_view usage;      // what follows `linuxity `; "" = an alias, not shown
    std::string_view summary;
    VerbGroup group;
    VerbArg arg;
    bool instances_only;         // needs background instances (host_runs_instances)
    bool via_env;                // dispatched as `linuxity env <verb> ...`
    std::string_view alias_of;   // non-empty: same command as that verb
};

// clang-format off
inline constexpr Verb kVerbTable[] = {
    // -- environments ----------------------------------------------------
    {"new",      "new DISTRO [NAME]",    "download and set up a distro (see `linuxity images`)", VerbGroup::environments, VerbArg::image, false, false, ""},
    {"import",   "import NAME FILE",     "bring your own rootfs (tar.gz/xz/zst, or a directory)", VerbGroup::environments, VerbArg::none, false, false, ""},
    {"export",   "export [ENV] FILE",    "the whole environment as a tarball",                    VerbGroup::environments, VerbArg::env,  false, false, ""},
    {"images",   "images",               "the distros `new` can download",                        VerbGroup::environments, VerbArg::none, false, false, ""},
    {"list",     "list",                 "your environments (* is the default)",                  VerbGroup::environments, VerbArg::none, false, false, ""},
    {"ls",       "", "", VerbGroup::environments, VerbArg::none, false, false, "list"},
    {"default",  "default ENV",          "which one `linuxity` opens",                            VerbGroup::environments, VerbArg::env,  false, false, ""},
    {"rename",   "rename OLD NEW",       "give it another name",                                  VerbGroup::environments, VerbArg::env,  false, true,  ""},
    {"rm",       "rm ENV",               "delete it, image and changes",                          VerbGroup::environments, VerbArg::env,  false, true,  ""},
    {"remove",   "", "", VerbGroup::environments, VerbArg::env, false, true, "rm"},
    // -- use -------------------------------------------------------------
    {"shell",    "shell [ENV]",          "a login shell",                                         VerbGroup::use, VerbArg::env, false, false, ""},
    {"exec",     "exec [ENV] -- CMD",    "run a command (-u USER, -C DIR, -e K=V, -t/-T)",         VerbGroup::use, VerbArg::env, false, false, ""},
    {"run",      "run ENV [-- CMD]",     "one program as pid 1, in the foreground",               VerbGroup::use, VerbArg::env, false, false, ""},
    // -- running in the background ---------------------------------------
    {"start",    "start [ENV]",          "keep it running in the background",                     VerbGroup::running, VerbArg::env, true,  false, ""},
    {"up",       "", "", VerbGroup::running, VerbArg::env, true, false, "start"},
    {"stop",     "stop [ENV]",           "stop it",                                               VerbGroup::running, VerbArg::env, true,  false, ""},
    {"down",     "", "", VerbGroup::running, VerbArg::env, true, false, "stop"},
    {"status",   "status [ENV]",         "is it running, and since when",                         VerbGroup::running, VerbArg::env, false, false, ""},
    {"ps",       "ps [ENV]",             "its processes",                                         VerbGroup::running, VerbArg::env, true,  false, ""},
    {"kill",     "kill [ENV] PID [SIG]", "signal one of them",                                    VerbGroup::running, VerbArg::env, true,  false, ""},
    {"svc",      "svc [ENV] [start|stop|restart NAME]", "its services",                           VerbGroup::running, VerbArg::env, true,  false, ""},
    {"logs",     "logs [ENV] [SVC] [-f]", "its log, or a service's",                              VerbGroup::running, VerbArg::env, true,  false, ""},
    {"reload",   "reload [ENV]",         "apply changed settings without a restart",              VerbGroup::running, VerbArg::env, true,  false, ""},
    // -- settings --------------------------------------------------------
    {"set",      "set [ENV] KEY=VALUE",  "change a setting (`linuxity get` lists them)",          VerbGroup::settings, VerbArg::env_key, false, true, ""},
    {"get",      "get [ENV] [KEY]",      "show settings",                                         VerbGroup::settings, VerbArg::env_key, false, true, ""},
    {"unset",    "unset [ENV] KEY",      "back to its default",                                   VerbGroup::settings, VerbArg::env_key, false, true, ""},
    {"edit",     "edit [ENV]",           "edit env.vibe in $EDITOR",                              VerbGroup::settings, VerbArg::env, false, true, ""},
    {"check",    "check [ENV]",          "validate env.vibe",                                     VerbGroup::settings, VerbArg::env, false, true, ""},
    {"info",     "info [ENV]",           "everything about it, at a glance",                      VerbGroup::settings, VerbArg::env, false, true, ""},
    {"path",     "path [ENV]",           "where it lives on the host",                            VerbGroup::settings, VerbArg::env, false, true, ""},
    {"adduser",  "adduser [ENV] USER",   "a user with sudo; new shells log in as it",             VerbGroup::settings, VerbArg::env, false, true, ""},
    {"users",    "users [ENV]",          "who can log in",                                        VerbGroup::settings, VerbArg::env, false, true, ""},
    // -- state -----------------------------------------------------------
    {"snapshot", "snapshot [ENV] NAME",  "save the current state",                                VerbGroup::state, VerbArg::env, false, true, ""},
    {"snapshots","snapshots [ENV]",      "the saved states",                                      VerbGroup::state, VerbArg::env, false, true, ""},
    {"restore",  "restore [ENV] NAME",   "go back to one",                                        VerbGroup::state, VerbArg::env_snapshot, false, true, ""},
    {"drop-snapshot", "drop-snapshot [ENV] NAME", "delete one",                                   VerbGroup::state, VerbArg::env_snapshot, false, true, ""},
    {"reset",    "reset [ENV]",          "back to the clean image",                               VerbGroup::state, VerbArg::env, false, true, ""},
    // -- other -----------------------------------------------------------
    {"completion", "completion bash|zsh|fish", "tab completion for your shell",                   VerbGroup::other, VerbArg::shell, false, false, ""},
    {"help",     "help [--all]",         "this, or every run flag too",                           VerbGroup::other, VerbArg::verb, false, false, ""},
    {"version",  "version",              "which linuxity this is",                                VerbGroup::other, VerbArg::none, false, false, ""},
    {"schema",   "schema",               "every setting, as JSON",                                VerbGroup::other, VerbArg::none, false, false, ""},
    {"env",      "", "", VerbGroup::other, VerbArg::none, false, false, "env"},   // the old `env <verb>` prefix
    {"--help",   "", "", VerbGroup::other, VerbArg::none, false, false, "help"},
    {"-h",       "", "", VerbGroup::other, VerbArg::none, false, false, "help"},
    {"--version","", "", VerbGroup::other, VerbArg::none, false, false, "version"},
    {"__complete","", "", VerbGroup::other, VerbArg::none, false, false, "__complete"},  // for the scripts
};
// clang-format on

[[nodiscard]] constexpr const Verb* find_verb(std::string_view name) noexcept {
    for (const auto& v : kVerbTable)
        if (v.name == name) return &v;
    return nullptr;
}

// The verb a name stands for (an alias resolves to its target).
[[nodiscard]] constexpr const Verb* canonical_verb(std::string_view name) noexcept {
    const Verb* v = find_verb(name);
    if (v && !v->alias_of.empty() && v->alias_of != v->name) return find_verb(v->alias_of);
    return v;
}

// Shown in help, offered by completion and typo hints: a real verb, not an
// alias, and usable on this host.
[[nodiscard]] constexpr bool verb_listed(const Verb& v, bool host_has_instances) noexcept {
    return !v.usage.empty() && (host_has_instances || !v.instances_only);
}

static_assert(find_verb("new") && find_verb("__complete"));
static_assert(canonical_verb("ls")->name == "list" && canonical_verb("down")->name == "stop");

}  // namespace lx::cli
