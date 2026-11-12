// tests/test_run_instance.cpp
//
// The long-running mode, end to end through the real binary: make an env
// over a tiny static rootfs, start it, run sessions with `lx`, check that
// they share one kernel (one process table, one hostname), that a service
// starts and restarts, that a config change applies live, and that `stop`
// leaves nothing behind.
#include "guest_harness.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

std::string g_bin;
std::string g_home;

// Run `linuxity <args>` with LINUXITY_HOME set; capture stdout. `lx ...` is the lx door.
int run_cli(const std::string& args, std::string* out = nullptr) {
    const std::string cmd = "LINUXITY_HOME=" + g_home + " timeout 30 " + g_bin + " " + args + " 2>/dev/null";
    std::FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) return -1;
    std::string s;
    char buf[4096];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, p)) > 0) s.append(buf, n);
    const int st = ::pclose(p);
    if (out) *out = s;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// The guest: a tiny multi-call program, so no distro is needed.
//   prog name     print uname's nodename
//   prog loop     print a line every 10ms forever (a service)
//   prog crash    exit 3 at once
//   prog code N   exit N
const char* kProbe = R"(
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "name")) { struct utsname u; uname(&u); puts(u.nodename); return 0; }
    if (argc > 1 && !strcmp(argv[1], "loop")) {
        struct timespec t = {0, 10000000};
        for (;;) { puts("tick"); fflush(stdout); nanosleep(&t, 0); }
    }
    if (argc > 1 && !strcmp(argv[1], "crash")) return 3;
    if (argc > 2 && !strcmp(argv[1], "code")) return atoi(argv[2]);
    printf("pid=%d\n", getpid());
    return 0;
}
)";

}  // namespace

int main() {
    char self[4096];
    const ::ssize_t n = ::readlink("/proc/self/exe", self, sizeof self - 1);
    if (n <= 0) return 1;
    self[n] = '\0';
    std::string dir{self};
    dir.resize(dir.find_last_of('/'));
    g_bin = dir + "/../linuxity";
    if (::access(g_bin.c_str(), X_OK) != 0) {
        std::puts("run_instance: skipped (no linuxity binary next to the tests)");
        return 0;
    }
    g_home = "/tmp/lx_instance_home_" + std::to_string(::getpid());
    const auto tree = lxtest::make_tree("instance", false,
        "mkdir -p /tmp/lx_instance_root/etc && "
        "printf 'root:x:0:0:root:/:/bin/prog\\n' > /tmp/lx_instance_root/etc/passwd");
    if (!lxtest::compile_guest("run_instance", tree, kProbe)) return 0;

    check(run_cli("new " + tree.root + " box") == 0, "new from a directory");
    check(run_cli("config @box system.hostname=first") == 0, "config sets the hostname");

    // a service that restarts on failure, and one that runs
    {
        std::FILE* f = std::fopen((g_home + "/envs/box/env.vibe").c_str(), "a");
        std::fputs("\nservice {\n"
                   "  ticker { command [ /bin/prog loop ] restart always }\n"
                   "  crasher { command [ /bin/prog crash ] restart on-failure }\n"
                   "}\n", f);
        std::fclose(f);
    }
    std::string out;
    check(run_cli("info box", &out) == 0 && out.find("error") == std::string::npos, "the config with services is valid");
    check(run_cli("start box") == 0, "start");
    check(run_cli("start box") == 0, "start again is a no-op");

    check(run_cli("lx @box -T /bin/prog name", &out) == 0 && out == "first\n", "a session sees the hostname");
    check(run_cli("lx @box -T /bin/prog code 42") == 42, "a session's exit code comes back");
    check(run_cli("lx -T prog", &out) == 0 && out.starts_with("pid="), "the default env, a bare name found on PATH");
    check(run_cli("lx @box -T nosuchprog") != 0, "a name that isn't on PATH fails cleanly");

    // two sessions, one kernel: guest pids keep counting up across sessions
    std::string a, b;
    (void)run_cli("lx @box -T /bin/prog", &a);
    (void)run_cli("lx @box -T /bin/prog", &b);
    check(a.starts_with("pid=") && b.starts_with("pid=") &&
              std::atoi(b.c_str() + 4) > std::atoi(a.c_str() + 4),
          "sessions share one pid space");

    check(run_cli("ps box", &out) == 0 && out.find("/sbin/init") != std::string::npos &&
              out.find("service ticker") != std::string::npos,
          "ps shows init and the service");

    // the crasher gives up after its quick exits; wait for that, bounded
    bool failed = false;
    for (int i = 0; i < 4000 && !failed; ++i) {
        (void)run_cli("svc @box", &out);
        failed = out.find("crasher      failed") != std::string::npos;
    }
    check(failed, "a crash-looping service is marked failed");
    check(out.find("ticker       running") != std::string::npos, "the healthy service keeps running");

    check(run_cli("config @box hostname=second") == 0, "config while running");
    check(run_cli("lx @box -T /bin/prog name", &out) == 0 && out == "second\n", "the hostname applies live");

    check(run_cli("info box --json", &out) == 0 && out.find("\"ok\":true") != std::string::npos, "info --json has the live state");
    check(run_cli("stop box") == 0, "stop");
    check(run_cli("info box", &out) == 0 && out.find("stopped") != std::string::npos, "stop really stopped it");
    check(!lxtest::host_exists(g_home + "/envs/box/run/control.sock") &&
              !lxtest::host_exists(g_home + "/envs/box/run/pid"),
          "stop removes the socket and pid file");

    check(run_cli("rm box --yes") == 0, "rm");
    lxtest::remove_tree(tree);
    std::system(("rm -rf " + g_home).c_str());
    if (failures) {
        std::fprintf(stderr, "run_instance: %d failure(s)\n", failures);
        return 1;
    }
    std::puts("run_instance: ok");
    return 0;
}
