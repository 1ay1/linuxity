// src/front.inc -- the front doors, included at the end of cli.cpp.
//
//   lx [@ENV] [-u U] [-C DIR] [-e K=V] [-t|-T] [--temp] [-v H:G] [CMD...]
//   linuxity VERB [@ENV] ...
//
// Every verb maps onto the engine (cmd_env and friends above). The rules:
//   - @ENV names an environment anywhere; a verb that takes nothing else also
//     takes a bare ENV. Leaving it out means the default.
//   - Verbs that destroy data (rm, mv, reset) need the name spelled out.
//   - Old verbs print the command that replaced them.

namespace {

int cmd_completion(std::string_view shell);

int no_env_yet() {
    std::puts("No Linux environments yet. Make one:\n");
    for (const auto& i : kImages)
        if (i.arch == kHostArch)
            std::printf("  linuxity new %-8s %s\n", std::string{i.distro}.c_str(), std::string{i.title}.c_str());
    std::puts("\nor bring your own:  linuxity new ROOTFS.tar.gz NAME  (or a directory)");
    return 1;
}

int run_argv(int (*fn)(int, char**), std::vector<std::string> a) {
    std::vector<char*> av;
    for (auto& x : a) av.push_back(x.data());
    av.push_back(nullptr);
    return fn(static_cast<int>(a.size()), av.data());
}

int env_cmd(std::vector<std::string> a) {
    a.insert(a.begin(), {"linuxity", "env"});
    return run_argv(cmd_env, std::move(a));
}

// A verb's words with @ENV taken out. `env` stays empty if none was given.
struct Words {
    std::string env;
    std::vector<std::string> pos;     // positionals
    std::vector<std::string> flags;   // everything starting with '-', in order
};

bool split_words(int argc, char** argv, int from, Words& w) {
    for (int i = from; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a.size() > 1 && a[0] == '@') {
            if (!w.env.empty()) { fail("two environments: @" + w.env + " and " + std::string{a}); return false; }
            w.env = a.substr(1);
        } else if (a.size() > 1 && a[0] == '-') {
            w.flags.emplace_back(a);
        } else {
            w.pos.emplace_back(a);
        }
    }
    return true;
}

bool has(const Words& w, std::string_view f) {
    for (const auto& x : w.flags) if (x == f) return true;
    return false;
}

// The environment a command acts on: @ENV, else the default. Prints why not.
std::optional<std::string> pick_env(const std::string& given) {
    Store s;
    if (!given.empty()) {
        if (s.has(given)) return given;
        std::string hint;
        std::size_t best = 3;
        for (const auto& n : s.names())
            if (const auto d = edit_distance(given, n); d < best) { best = d; hint = n; }
        fail("no environment '" + given + "'" + (hint.empty() ? " (linuxity ls)" : ". Did you mean @" + hint + "?"));
        return std::nullopt;
    }
    if (const auto d = s.default_env(); !d.empty() && s.has(d)) return d;
    if (s.names().empty()) { no_env_yet(); return std::nullopt; }
    fail("which environment? Name one with @ENV, or pick a default: linuxity use ENV");
    return std::nullopt;
}

// The env for a verb that takes at most one bare word: @ENV or ENV.
std::optional<std::string> env_of(Words& w, std::string_view usage) {
    if (w.pos.size() > 1 || (w.pos.size() == 1 && !w.env.empty())) {
        fail("usage: linuxity " + std::string{usage});
        return std::nullopt;
    }
    if (w.pos.size() == 1) { w.env = w.pos[0]; w.pos.clear(); }
    return pick_env(w.env);
}

// The env for a verb that destroys or renames: it must be spelled out.
std::optional<std::string> named_env(const Words& w, std::string_view usage) {
    std::string n = w.env;
    if (n.empty() && !w.pos.empty()) n = w.pos[0];
    if (n.empty()) { fail("usage: linuxity " + std::string{usage} + " (the name is required)"); return std::nullopt; }
    return pick_env(n);
}

std::vector<std::string> with_flags(std::vector<std::string> a, const Words& w) {
    a.insert(a.end(), w.flags.begin(), w.flags.end());
    return a;
}

// ---- lx: run things --------------------------------------------------------

// `lx -v` or `--temp` needs a run of its own (the instance's mounts are fixed).
int lx_own_run(const std::string& env, const SessionArgs& a) {
    std::vector<std::string> v = {self_exe(), "__run", env, "--quiet"};
    if (a.temp) v.emplace_back("--fresh");
    for (const auto& m : a.volumes) v.insert(v.end(), {"-v", m});
    if (!a.user.empty()) v.insert(v.end(), {"--user", a.user});
    if (!a.cwd.empty()) v.insert(v.end(), {"--cwd", a.cwd});
    for (const auto& [k, val] : a.env_vars) v.insert(v.end(), {"-e", k + "=" + val});
    if (!a.argv.empty()) { v.emplace_back("--"); v.insert(v.end(), a.argv.begin(), a.argv.end()); }
    std::vector<char*> av;
    for (auto& x : v) av.push_back(x.data());
    av.push_back(nullptr);
    ::execv(av[0], av.data());
    return fail("cannot run " + v[0] + ": " + std::strerror(errno));
}

}  // namespace

int lx_main(int argc, char** argv) {
    SessionArgs a;
    if (!parse_session_args(argc, argv, 1, a)) return 2;
    if (a.help) { help_lx(); return 0; }
    const auto env = pick_env(a.env);
    if (!env) return 1;
    if (a.temp || !a.volumes.empty()) return lx_own_run(*env, a);
    Conn c;
    if (!ensure_up(*env, c)) return fail("cannot start " + *env + " (linuxity logs @" + *env + ")");
    const bool tty = a.tty >= 0 ? a.tty == 1 : (::isatty(0) && ::isatty(1));
    return run_session(c, a.argv, a.user, a.cwd, a.env_vars, tty);
}

namespace {

// ---- linuxity: manage them --------------------------------------------------

int v_new(int argc, char** argv) {
    Words w;
    if (!split_words(argc, argv, 2, w)) return 2;
    if (w.pos.empty()) { (void)cmd_images(has(w, "--json")); return 0; }
    if (w.pos.size() > 2) return fail("usage: linuxity new DISTRO|FILE|DIR [NAME]");
    const std::string src = w.pos[0];
    // a path is a rootfs you bring; a word is a catalog image
    if (src.find('/') != std::string::npos || is_dir(src) || exists(src)) {
        std::string name = w.pos.size() > 1 ? w.pos[1] : "";
        if (name.empty()) {
            name = src.substr(src.find_last_of('/') + 1);
            name = name.substr(0, name.find('.'));
            if (!valid_name(name)) return fail("name it: linuxity new " + src + " NAME");
        }
        return run_argv(cmd_import, with_flags({"linuxity", "import", name, src}, w));
    }
    std::vector<std::string> v = {"linuxity", "new", src};
    if (w.pos.size() > 1) v.push_back(w.pos[1]);
    // pass values of value-taking flags through as given
    for (int i = 2; i < argc; ++i) {
        const std::string_view f = argv[i];
        if (f.size() > 1 && f[0] == '-') {
            v.emplace_back(f);
            if ((f == "--user" || f == "-u" || f == "--file" || f == "--checksum") && i + 1 < argc) v.emplace_back(argv[++i]);
        }
    }
    return run_argv(cmd_new, v);
}

int v_config(int argc, char** argv) {
    Words w;
    if (!split_words(argc, argv, 2, w)) return 2;
    if (has(w, "--schema")) { std::puts(schema_json().c_str()); return 0; }
    const auto env = pick_env(w.env);
    if (!env) return 1;
    if (has(w, "--edit") || has(w, "-e")) return env_cmd({"edit", *env});
    std::vector<std::string> sets, gets;
    for (const auto& p : w.pos) (p.find('=') == std::string::npos ? gets : sets).push_back(p);
    if (!gets.empty() && !sets.empty()) return fail("either show keys or change them, not both in one go");
    if (sets.empty()) {
        if (gets.size() > 1) return fail("one key at a time: linuxity config KEY");
        std::vector<std::string> v = {"get", *env};
        v.insert(v.end(), gets.begin(), gets.end());
        return env_cmd(with_flags(v, w));
    }
    // KEY=VALUE sets, KEY= resets; one save, so a running instance reloads once
    std::vector<std::string> v = {"set", *env};
    v.insert(v.end(), sets.begin(), sets.end());
    return env_cmd(v);
}

int v_user(int argc, char** argv) {
    Words w;
    if (!split_words(argc, argv, 2, w)) return 2;
    const auto env = pick_env(w.env);
    if (!env) return 1;
    if (w.pos.empty()) return env_cmd(with_flags({"users", *env}, w));
    if (w.pos[0] != "add" || w.pos.size() != 2) return fail("usage: linuxity user [@ENV] [add NAME]");
    std::vector<std::string> v = {"adduser", *env, w.pos[1]};
    for (int i = 2; i < argc; ++i) {   // flags, with --shell's value
        const std::string_view f = argv[i];
        if (f.size() > 1 && f[0] == '-') {
            v.emplace_back(f);
            if (f == "--shell" && i + 1 < argc) v.emplace_back(argv[++i]);
        }
    }
    return env_cmd(v);
}

int v_snap(int argc, char** argv) {
    Words w;
    if (!split_words(argc, argv, 2, w)) return 2;
    const auto env = pick_env(w.env);
    if (!env) return 1;
    if (w.pos.empty()) return env_cmd(with_flags({"snapshots", *env}, w));
    if (w.pos.size() != 2) return fail("usage: linuxity snap [@ENV] [save|restore|rm NAME]");
    const std::string& op = w.pos[0];
    const std::string& snap = w.pos[1];
    if (op == "save") return env_cmd({"snapshot", *env, snap});
    if (op == "restore") return env_cmd(with_flags({"restore", *env, snap}, w));
    if (op == "rm") return env_cmd({"drop-snapshot", *env, snap});
    return fail("snap " + op + "? It's save, restore or rm");
}

int v_info(Words& w) {
    const auto env = env_of(w, "info [ENV]");
    if (!env) return 1;
    const auto live = live_status(*env);
    if (has(w, "--json")) {
        // the engine's config view, with the live status added as "live"
        std::fflush(stdout);
        std::FILE* tmp = std::tmpfile();
        if (!tmp) return fail("cannot make a temp file");
        const int saved = ::dup(1);
        ::dup2(::fileno(tmp), 1);
        const int rc = env_cmd({"info", *env, "--json"});
        std::fflush(stdout);
        ::dup2(saved, 1);
        ::close(saved);
        std::string body;
        std::rewind(tmp);
        char buf[4096];
        for (std::size_t n; (n = std::fread(buf, 1, sizeof buf, tmp)) > 0;) body.append(buf, n);
        std::fclose(tmp);
        while (!body.empty() && (body.back() == '\n' || body.back() == '}')) {
            const bool brace = body.back() == '}';
            body.pop_back();
            if (brace) break;
        }
        if (rc != 0 || body.empty()) return rc ? rc : 1;
        std::printf("%s,\"live\":%s}\n", body.c_str(), live ? live->c_str() : "null");
        return 0;
    }
    if (const int rc = env_cmd({"info", *env}); rc != 0) return rc;
    if (!live) {
        if (!lx::cli::host_runs_instances()) std::puts("  each lx runs it in the foreground");
        return 0;
    }
    const auto r = parse_json(*live);
    if (r && r->flag("ok")) print_live(&*r);
    return 0;
}

int dispatch(const lx::cli::Verb& v, int argc, char** argv) {
    using namespace lx::cli;
    const std::string_view name = v.name;
    Words w;
    if (name == "new") return v_new(argc, argv);
    if (name == "config") return v_config(argc, argv);
    if (name == "user") return v_user(argc, argv);
    if (name == "snap") return v_snap(argc, argv);
    if (!split_words(argc, argv, 2, w)) return 2;

    if (name == "ls") return env_cmd(with_flags({"list"}, w));
    if (name == "info") return v_info(w);
    if (name == "use") {
        if (w.pos.size() != 1 && w.env.empty()) return fail("usage: linuxity use ENV");
        const auto env = pick_env(w.env.empty() ? w.pos[0] : w.env);
        if (!env) return 1;
        if (!Store{}.set_default(*env)) return fail("cannot write the default");
        std::printf("%s is the default: lx opens it\n", env->c_str());
        return 0;
    }
    if (name == "mv") {
        if (w.pos.size() != 2) return fail("usage: linuxity mv OLD NEW");
        return env_cmd({"rename", w.pos[0], w.pos[1]});
    }
    if (name == "rm") {
        const auto env = named_env(w, v.usage);
        if (!env) return 1;
        return env_cmd(with_flags({"rm", *env}, w));
    }
    if (name == "reset") {
        const auto env = named_env(w, v.usage);
        if (!env) return 1;
        return env_cmd(with_flags({"reset", *env}, w));
    }
    if (name == "export") {
        if (w.pos.size() != 1) return fail("usage: linuxity export [@ENV] FILE");
        const auto env = pick_env(w.env);
        if (!env) return 1;
        return run_argv(cmd_export, {"linuxity", "export", *env, w.pos[0]});
    }
    if (name == "start") {
        const auto env = env_of(w, v.usage);
        if (!env) return 1;
        Conn c;
        if (!connect_env(*env, c)) return ensure_up(*env, c) ? 0 : 1;
        // already up: bring it up to date with env.vibe (hand edits included)
        const auto r = request(c, R"({"op":"reload"})");
        if (print_reply(r)) return 1;
        const auto applied = r->strs("applied");
        if (applied.empty()) std::printf("%s is running and up to date\n", env->c_str());
        for (const auto& x : applied) std::printf("applied %s\n", x.c_str());
        if (r->flag("restart_needed"))
            std::printf("other changes apply after a restart: linuxity stop %s\n", env->c_str());
        return 0;
    }
    if (name == "stop") {
        const auto env = env_of(w, v.usage);
        return env ? run_argv(cmd_down, {"linuxity", "stop", *env}) : 1;
    }
    if (name == "ps") {
        const auto env = env_of(w, v.usage);
        return env ? run_argv(cmd_ps, with_flags({"linuxity", "ps", *env}, w)) : 1;
    }
    if (name == "svc") {
        const auto env = pick_env(w.env);
        if (!env) return 1;
        std::vector<std::string> a = {"linuxity", "svc", *env};
        a.insert(a.end(), w.pos.begin(), w.pos.end());
        return run_argv(cmd_svc, with_flags(a, w));
    }
    if (name == "logs") {
        const auto env = pick_env(w.env);
        if (!env) return 1;
        std::vector<std::string> a = {"linuxity", "logs", *env};
        a.insert(a.end(), w.pos.begin(), w.pos.end());
        return run_argv(cmd_logs, with_flags(a, w));
    }
    if (name == "help") {
        if (has(w, "--all")) return -1;   // main prints the engine flags
        if (w.pos.empty()) { help(); return 0; }
        return help_verb(w.pos[0]);
    }
    if (name == "completion") return cmd_completion(w.pos.empty() ? "" : w.pos[0]);
    if (name == "version") { std::printf("linuxity %s\n", LINUXITY_VERSION); return 0; }
    return fail("no handler for " + std::string{name});
}

}  // namespace

namespace {

// ---- shell completion --------------------------------------------------
// `linuxity __complete [lx] W1 ... CUR` prints the candidates for CUR, one
// per line. The shell scripts only forward their words, so every shell
// completes the same things: verbs, @envs, settings keys, images.
int cmd_complete(int argc, char** argv) {
    using namespace lx::cli;
    std::vector<std::string> w(argv + 2, argv + argc);
    const bool lx = !w.empty() && w[0] == "lx";
    if (lx) w.erase(w.begin());
    if (w.empty()) w.emplace_back();
    const std::string cur = w.back();
    w.pop_back();
    const bool bg = host_runs_instances();
    auto emit = [&](std::string_view c) {
        if (std::string_view{c}.starts_with(cur)) std::printf("%.*s\n", static_cast<int>(c.size()), c.data());
    };
    Store s;
    const auto names = s.names();
    std::string env;
    for (const auto& x : w) if (x.size() > 1 && x[0] == '@') env = x.substr(1);
    if (cur.starts_with("@")) {
        for (const auto& n : names) emit("@" + n);
        return 0;
    }
    if (lx) {
        // after a command word it's the guest's command line: the shell's files
        for (const auto& x : w) if (!x.starts_with("-") && !x.starts_with("@")) return 0;
        for (const char* f : {"--temp", "-u", "-C", "-e", "-v", "-t", "-T", "--help"}) emit(f);
        return 0;
    }
    if (w.empty()) {
        for (const auto& v : kVerbTable) if (verb_listed(v, bg)) emit(v.name);
        return 0;
    }
    const Verb* v = find_verb(w[0]);
    if (!v) return 0;
    std::vector<std::string> pos;
    for (std::size_t i = 1; i < w.size(); ++i)
        if (!w[i].starts_with("-") && !w[i].starts_with("@")) pos.push_back(w[i]);
    auto envs = [&] { for (const auto& n : names) emit(n); };
    switch (v->arg) {
        case VerbArg::env:
            if (pos.empty() && env.empty()) envs();
            else if (v->name == "mv" && pos.size() == 1) {}
            break;
        case VerbArg::image:
            if (pos.empty()) for (const auto& i : kImages) if (i.arch == kHostArch) emit(i.distro);
            break;
        case VerbArg::key: {
            const auto eq = cur.find('=');
            if (eq == std::string::npos) {
                // full paths, and the short names that are unique (hostname = system.hostname)
                for (const auto& f : kFields) {
                    emit(std::string{f.path} + "=");
                    const auto dot = f.path.find_last_of('.');
                    if (dot != std::string_view::npos && resolve_key(std::string{f.path.substr(dot + 1)}) == f.path)
                        emit(std::string{f.path.substr(dot + 1)} + "=");
                }
                for (const char* f : {"--edit", "--schema", "--json"}) emit(f);
            }
            break;
        }
        case VerbArg::snap:
            if (pos.empty()) for (const char* o : {"save", "restore", "rm"}) emit(o);
            else if (pos.size() == 1 && pos[0] != "save") {
                const auto e = env.empty() ? s.default_env() : env;
                if (!e.empty()) for (const auto& x : s.snapshots(e)) emit(x);
            }
            break;
        case VerbArg::user:
            if (pos.empty()) emit("add");
            break;
        case VerbArg::svc:
            if (pos.empty()) for (const char* o : {"start", "stop", "restart"}) emit(o);
            else if (pos.size() == 1) {
                const auto e = env.empty() ? s.default_env() : env;
                if (!e.empty()) for (const auto& sv : s.load(e).config.services) emit(sv.name);
            }
            break;
        case VerbArg::verb:
            if (pos.empty()) { for (const auto& x : kVerbTable) if (verb_listed(x, bg)) emit(x.name); emit("lx"); emit("--all"); }
            break;
        case VerbArg::shell:
            if (pos.empty()) for (const char* sh : {"bash", "zsh", "fish"}) emit(sh);
            break;
        case VerbArg::none:
            break;
    }
    return 0;
}

int cmd_completion(std::string_view shell) {
    if (shell == "bash") {
        std::puts(
            "_linuxity() { COMPREPLY=($(linuxity __complete \"${COMP_WORDS[@]:1:COMP_CWORD}\")); }\n"
            "_lx() { COMPREPLY=($(linuxity __complete lx \"${COMP_WORDS[@]:1:COMP_CWORD}\")); [ ${#COMPREPLY[@]} -eq 0 ] && compopt -o default; }\n"
            "complete -F _linuxity linuxity\n"
            "complete -F _lx lx");
        return 0;
    }
    if (shell == "zsh") {
        std::puts(
            "#compdef linuxity lx\n"
            "_linuxity() {\n"
            "  local -a c\n"
            "  if [[ $service == lx ]]; then c=(${(f)\"$(linuxity __complete lx ${words[2,CURRENT]})\"})\n"
            "  else c=(${(f)\"$(linuxity __complete ${words[2,CURRENT]})\"}); fi\n"
            "  (( ${#c} )) && compadd -S '' -a c || _files\n"
            "}\n"
            "compdef _linuxity linuxity lx");
        return 0;
    }
    if (shell == "fish") {
        std::puts(
            "complete -c linuxity -f -a '(linuxity __complete (commandline -opc)[2..] (commandline -ct))'\n"
            "complete -c lx -a '(linuxity __complete lx (commandline -opc)[2..] (commandline -ct))'");
        return 0;
    }
    return fail("usage: linuxity completion bash|zsh|fish");
}

}  // namespace

int lx_cli_main(int argc, char** argv) {
    using namespace lx::cli;
    Store s;
    if (std::string why; !s.ensure_storage(true, why)) return fail(why);
    if (argc < 2) { help(); return 0; }
    const std::string sub = argv[1];
    if (sub == "__complete") return cmd_complete(argc, argv);
    if (sub == "--help" || sub == "-h") { help(); return 0; }
    if (sub == "--version") { std::printf("linuxity %s\n", LINUXITY_VERSION); return 0; }
    if (const Verb* v = find_verb(sub)) {
        if (!verb_listed(*v, host_runs_instances()))
            return fail("on " + std::string{host_name()} + " an environment runs only while an lx is open, so `" +
                        sub + "` has nothing to act on");
        return dispatch(*v, argc, argv);
    }
    if (const auto to = moved_verb(sub); !to.empty())
        return fail("`linuxity " + sub + "` is now `" + std::string{to} + "`");
    // a program on the host or in the default env was meant for lx, not a typo
    auto on_path = [&](const std::string& root) {
        for (const char* d : {"/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"})
            if (::access((root + d + "/" + sub).c_str(), F_OK) == 0) return true;
        return false;
    };
    const auto def = s.default_env();
    if (on_path("") || (!def.empty() && s.has(def) && on_path(s.load(def).config.rootfs)))
        return fail("'" + sub + "' is not a command (linuxity help). To run it in Linux: lx " + sub);
    // `linuxity htop`: almost always meant `lx htop`. Only a close match is a
    // typo; old verbs count, so `stauts` finds status -> info.
    std::string best;
    std::size_t best_d = sub.size() <= 4 ? 2 : 3;   // short words: one edit, or `htop` looks like `stop`
    auto consider = [&](std::string_view n) {
        if (const auto d = edit_distance(sub, n); d < best_d) { best_d = d; best = std::string{n}; }
    };
    for (const auto& [from, to] : kMovedVerbs) consider(from);
    for (const auto& v : kVerbTable) if (verb_listed(v, host_runs_instances())) consider(v.name);
    if (!best.empty()) {
        const auto to = moved_verb(best);
        return fail("'" + sub + "' is not a command. Did you mean `" +
                    (to.empty() ? "linuxity " + best : std::string{to}) + "`?");
    }
    return fail("'" + sub + "' is not a command (linuxity help). To run it in Linux: lx " + sub);
}
