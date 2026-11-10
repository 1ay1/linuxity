// tests/test_env_config.cpp
//
// env.vibe: parsing, type errors, unknown-key hints, the text editor that
// keeps comments, the passwd lookup, and the env store's
// create/reset/snapshot/restore cycle.
#include "linuxity/env/config.hpp"
#include "linuxity/env/json_read.hpp"
#include "linuxity/env/passwd.hpp"
#include "linuxity/env/store.hpp"
#include "linuxity/env/vibe_edit.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace lx::env;

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

bool has_diag(const ParseResult& r, std::string_view path, bool error) {
    for (const auto& d : r.diags)
        if (d.path == path && d.error == error) return true;
    return false;
}

void test_parse_full() {
    const auto r = parse_config(R"(
name dev
rootfs /srv/arch
system {
  hostname pixel
  kernel-release 6.12.0
  timezone Europe/Berlin
}
network {
  dns [ 1.1.1.1 9.9.9.9 ]
}
login {
  user ayush
  shell /usr/bin/zsh
  umask 027
  command [ /usr/bin/tmux new -A ]
}
limits {
  cpus 1.5
  memory 2G
  pids 512
}
env {
  EDITOR vim
  LANG "en_US.UTF-8"
}
mount {
  phone { host /sdcard at /mnt/phone }
}
service {
  web {
    command [ python -m http.server 8000 ]
    restart always
    env { PORT 8000 }
  }
}
)");
    check(r.ok(), "full config parses");
    const auto& c = r.config;
    check(c.name == "dev" && c.rootfs == "/srv/arch", "top-level keys");
    check(c.hostname == "pixel", "system.hostname");
    check(c.kernel_release == "6.12.0", "kernel-release that looks like a number");
    check(c.dns.size() == 2 && c.dns[1] == "9.9.9.9", "network.dns list");
    check(c.user == "ayush" && c.shell == "/usr/bin/zsh", "login user/shell");
    check(umask_value(c) == 027, "umask written bare is read as octal");
    check(c.command.size() == 3 && c.command[2] == "-A", "login.command list");
    check(c.limits.cpus && *c.limits.cpus == 1.5, "limits.cpus float");
    check(c.limits.mem_max && *c.limits.mem_max == (std::uint64_t{2} << 30), "limits.memory size");
    check(c.limits.pids_max && *c.limits.pids_max == 512, "limits.pids");
    check(c.env.size() == 2 && c.env[0].first == "EDITOR", "env table");
    check(c.mounts.size() == 1 && c.mounts[0].at == "/mnt/phone", "mount table");
    check(c.services.size() == 1 && c.services[0].restart == Restart::always &&
              c.services[0].env.size() == 1 && c.services[0].env[0].second == "8000",
          "service table");
}

void test_defaults() {
    const auto r = parse_config("");
    check(r.ok(), "empty config is valid");
    check(r.config.hostname == "linuxity" && r.config.user == "root" && r.config.persist,
          "defaults when nothing is set");
    std::vector<Diag> d;
    check_runnable(r.config, d);
    check(!d.empty() && d[0].path == "rootfs", "a runnable env needs a rootfs");
}

void test_errors() {
    auto r = parse_config("limits { cpus lots }\n");
    check(has_diag(r, "limits.cpus", true), "wrong type is an error");
    r = parse_config("system { hostnme x }\n");
    check(has_diag(r, "system.hostnme", false), "unknown key is a warning");
    bool hint = false;
    for (const auto& d : r.diags) hint = hint || d.message.find("system.hostname") != std::string::npos;
    check(hint, "unknown key suggests the near miss");
    r = parse_config("compat { fifos maybe }\n");
    check(has_diag(r, "compat.fifos", true), "a choice outside its set is an error");
    r = parse_config("service { x { user nobody } }\n");
    check(has_diag(r, "service.x.command", true), "a service needs a command");
    r = parse_config("mount { m { host /a at rel } }\n");
    check(has_diag(r, "mount.m.at", true), "a mount point must be absolute");
    r = parse_config("system {\n");
    check(!r.ok() && r.diags[0].line > 0, "a syntax error carries its line");
}

void test_editor() {
    const std::string doc =
        "# my env\n"
        "name dev   # keep me\n"
        "system {\n"
        "  hostname old  # the box\n"
        "}\n"
        "network {\n"
        "  dns [\n"
        "    1.1.1.1\n"
        "  ]\n"
        "}\n";
    auto t = vibe_edit::set(doc, "system.hostname", "pixel");
    check(t && t->find("hostname pixel  # the box") != std::string::npos, "set keeps the trailing comment");
    check(t && t->find("# my env") != std::string::npos, "set keeps other comments");
    t = vibe_edit::set(*t, "network.dns", "[ 9.9.9.9 ]");
    check(t && parse_config(*t).config.dns == std::vector<std::string>{"9.9.9.9"},
          "set replaces a multi-line array");
    t = vibe_edit::set(*t, "login.user", "ayush");
    check(t && parse_config(*t).config.user == "ayush", "set creates a missing section");
    t = vibe_edit::set(*t, "system.timezone", "UTC");
    check(t && parse_config(*t).config.timezone == "UTC" && parse_config(*t).config.hostname == "pixel",
          "set adds a key to an existing section");
    t = vibe_edit::set(*t, "env.EDITOR", "vim");
    check(t && parse_config(*t).config.env.size() == 1, "set into a user-named table");
    t = vibe_edit::unset(*t, "system.timezone");
    check(t && parse_config(*t).config.timezone.empty(), "unset removes the key");
    check(t && parse_config(*t).ok(), "the edited document still parses");
    check(vibe_edit::string_text("1.5") == "\"1.5\"", "a numeric-looking string is quoted");
    check(vibe_edit::string_text("/usr/bin/zsh") == "/usr/bin/zsh", "a path stays bare");
}

void test_passwd() {
    const char* pw =
        "root:x:0:0:root:/root:/bin/bash\n"
        "ayush:x:1000:1000::/home/ayush:/usr/bin/zsh\n";
    const char* gr =
        "root:x:0:\n"
        "wheel:x:10:ayush,other\n"
        "ayush:x:1000:\n"
        "audio:x:92:ayush\n";
    auto u = find_user(pw, "ayush");
    check(u && u->uid == 1000 && u->home == "/home/ayush" && u->shell == "/usr/bin/zsh", "passwd by name");
    check(find_user(pw, "1000").has_value(), "passwd by uid");
    check(!find_user(pw, "nobody"), "missing user");
    const auto g = groups_of(gr, "ayush", 1000);
    check(g.size() == 3 && g[0] == 1000, "primary first, then member groups");
}

void test_json_read() {
    auto v = parse_json(R"({"op":"spawn","argv":["a","b c"],"rows":24,"tty":true,"env":{"X":"1"}})");
    check(v && v->str("op") == "spawn", "json string");
    check(v && v->strs("argv").size() == 2 && v->strs("argv")[1] == "b c", "json array");
    check(v && v->num("rows") == 24 && v->flag("tty"), "json number and bool");
    check(v && v->str_map("env").size() == 1, "json object of strings");
    check(!parse_json("{\"a\":}"), "bad json is rejected");
    check(parse_json(R"({"s":"\u00e9\n"})")->str("s") == "\xc3\xa9\n", "json escapes");
}

void test_store() {
    const std::string home = "/tmp/lx-test-store-" + std::to_string(::getpid());
    const std::string rootfs = home + "-rootfs";
    (void)remove_tree(home);
    (void)mkdirs(rootfs + "/etc");
    Store s{home};
    check(s.create("box", rootfs).empty(), "create");
    check(s.has("box") && s.names() == std::vector<std::string>{"box"}, "list");
    check(!s.create("box", rootfs).empty(), "create twice fails");
    check(!s.create("../x", rootfs).empty(), "bad name rejected");
    auto r = s.load("box");
    // create() stores the rootfs canonicalized (on macOS /tmp is a symlink
    // to /private/tmp), so compare against what realpath says
    std::string canon = rootfs;
    if (char* rp = ::realpath(rootfs.c_str(), nullptr)) { canon = rp; std::free(rp); }
    check(r.ok() && r.config.rootfs == canon && r.config.hostname == "box", "template loads");
    check(r.config.upper == s.default_upper("box"), "upper defaults into the env dir");

    // reset / snapshot / restore only ever touch upper/
    (void)write_file_atomic(r.config.upper + "/marker", "one");
    check(s.snapshot("box", "s1").empty(), "snapshot");
    (void)write_file_atomic(r.config.upper + "/marker", "two");
    check(s.restore("box", "s1").empty(), "restore");
    check(slurp(r.config.upper + "/marker").value_or("") == "one", "restore brings the old upper back");
    check(s.reset("box").empty() && !exists(r.config.upper + "/marker") && is_dir(r.config.upper),
          "reset empties upper");
    check(s.snapshots("box") == std::vector<std::string>{"s1"}, "snapshot listed");
    check(s.drop_snapshot("box", "s1").empty() && s.snapshots("box").empty(), "drop snapshot");
    check(exists(rootfs + "/etc"), "the rootfs is never touched");
    check(s.rename("box", "box2").empty() && s.has("box2"), "rename");
    check(s.remove("box2").empty() && !s.has("box2"), "remove");
    (void)remove_tree(home);
    (void)remove_tree(rootfs);
}

void test_schema() {
    const auto v = parse_json(schema_json());
    check(v.has_value(), "schema is valid json");
    const JValue* f = v ? v->get("fields") : nullptr;
    check(f && f->a.size() == std::size(kFields), "schema lists every field");
    const auto c = parse_json(config_json(parse_config("system { hostname x }").config));
    check(c && c->get("system") && c->get("system")->str("hostname") == "x", "config as json");
}

}  // namespace

int main() {
    test_parse_full();
    test_defaults();
    test_errors();
    test_editor();
    test_passwd();
    test_json_read();
    test_store();
    test_schema();
    if (failures) {
        std::fprintf(stderr, "env_config: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("env_config: ok");
    return 0;
}
