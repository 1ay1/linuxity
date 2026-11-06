// tests/test_resolver.cpp
//
// The two host-capability seams that made a guest work on Android: where the
// nameservers come from, and which AF_UNIX namespace a socket lives in.
//
// Both exist because a thing the runtime treated as a CONSTANT turned out to
// vary by host, and in each case the symptom was silent:
//
//   * DNS was "bind the host's /etc/resolv.conf". Android has no such file,
//     so the bind did nothing and every guest lookup failed with "Could not
//     resolve host" -- while the host itself resolved fine.
//   * Socket paths were translated into the overlay, which is correct and
//     still fails on Android: SELinux denies an AF_UNIX bind in every
//     directory an app can write, so gpg-agent could not start and
//     `pacman-key --init` died.
#include "linuxity/kernel/resolver.hpp"
#include "linuxity/kernel/socket_ns.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

using namespace lx;
using namespace lx::kernel;

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    if (!ok) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        ++failures;
    }
}

// Write a resolv.conf and hand back its path.
std::string temp_resolv(const char* body) {
    std::string path = "/tmp/lx-test-resolv-" + std::to_string(::getpid()) +
                       "-" + std::to_string(std::rand()) + ".conf";
    if (std::FILE* f = std::fopen(path.c_str(), "w")) {
        std::fputs(body, f);
        std::fclose(f);
    }
    return path;
}

}  // namespace

int main() {
    // --- parsing -----------------------------------------------------------
    {
        const std::string p = temp_resolv(
            "# a comment\n"
            "; another\n"
            "search example.com\n"
            "nameserver 10.0.0.1\n"
            "nameserver\t10.0.0.2\n"
            "nameserverbogus 1.2.3.4\n"   // must NOT match: no separator
            "options edns0\n");
        const auto ns = nameservers_from_file(p.c_str());
        check(ns.size() == 2, "two nameservers parsed");
        if (ns.size() == 2) {
            check(ns[0] == "10.0.0.1", "first nameserver");
            check(ns[1] == "10.0.0.2", "tab-separated nameserver");
        }
        std::remove(p.c_str());
    }

    // A file with no usable directive must yield nothing, so the policy falls
    // through to the next source rather than serving an empty resolv.conf.
    {
        const std::string p = temp_resolv("# nothing here\nsearch lan\n");
        check(nameservers_from_file(p.c_str()).empty(), "no nameservers found");
        std::remove(p.c_str());
    }

    check(nameservers_from_file("/nonexistent/resolv.conf").empty(),
          "absent file yields nothing (the Android case)");

    // --- the env override --------------------------------------------------
    {
        const auto ns = nameservers_from_env("1.1.1.1, 9.9.9.9,8.8.4.4");
        check(ns.size() == 3, "three from env");
        if (ns.size() == 3) check(ns[1] == "9.9.9.9", "env entry trimmed");
        check(nameservers_from_env("").empty(), "empty env yields nothing");
        check(nameservers_from_env(nullptr).empty(), "null env yields nothing");
    }

    // --- the policy order --------------------------------------------------
    {
        const std::string host = temp_resolv("nameserver 192.168.1.1\n");
        const std::string guest = temp_resolv("nameserver 172.16.0.1\n");

        // env beats everything
        auto c = choose_nameservers("1.2.3.4", host.c_str(), guest);
        check(c.origin == ResolverOrigin::env && c.servers[0] == "1.2.3.4",
              "env wins");

        // the image's own resolver beats the host's
        c = choose_nameservers(nullptr, host.c_str(), guest);
        check(c.origin == ResolverOrigin::guest_file &&
                  c.servers[0] == "172.16.0.1",
              "rootfs resolv.conf wins over the host's");

        // with no guest file, the host's is used
        c = choose_nameservers(nullptr, host.c_str(), std::string{});
        check(c.origin == ResolverOrigin::host_file &&
                  c.servers[0] == "192.168.1.1",
              "host resolv.conf used when the image has none");

        // and with neither -- the Android shape -- we still produce something
        // usable rather than an empty file.
        c = choose_nameservers(nullptr, "/nonexistent", std::string{});
        check(c.origin == ResolverOrigin::fallback && !c.empty(),
              "fallback when the host has no resolv.conf");

        std::remove(host.c_str());
        std::remove(guest.c_str());
    }

    // --- rendering ---------------------------------------------------------
    {
        const std::string out = render_resolv_conf({"1.1.1.1", "8.8.8.8"});
        check(out.find("nameserver 1.1.1.1\n") != std::string::npos,
              "renders the first nameserver");
        check(out.find("nameserver 8.8.8.8\n") != std::string::npos,
              "renders the second nameserver");
        // Round trip: what we render must parse back to what we rendered,
        // or the guest's resolver and ours disagree.
        const std::string p = temp_resolv(out.c_str());
        const auto back = nameservers_from_file(p.c_str());
        check(back.size() == 2 && back[0] == "1.1.1.1" && back[1] == "8.8.8.8",
              "rendered resolv.conf parses back identically");
        std::remove(p.c_str());
    }

    // --- abstract socket names ---------------------------------------------
    // THE property: bind and connect translate at different times, so the
    // name must be a pure function of the GUEST path. If it ever depended on
    // the host path (which differs between the overlay upper and lower) the
    // two peers would pick different names and never meet.
    {
        const std::string a = abstract_name_for("/root/.gnupg/S.gpg-agent", 42);
        const std::string b = abstract_name_for("/root/.gnupg/S.gpg-agent", 42);
        check(a == b, "same guest path + instance -> same abstract name");

        const std::string c = abstract_name_for("/root/.gnupg/S.dirmngr", 42);
        check(a != c, "different socket -> different name");

        const std::string d = abstract_name_for("/root/.gnupg/S.gpg-agent", 43);
        check(a != d, "different instance -> different name (no cross-talk)");

        // Must fit sun_path (108 bytes) with its leading NUL, even for a
        // deeply nested guest path -- truncation would silently alias two
        // different sockets onto one name.
        const std::string deep = abstract_name_for(
            "/home/user/very/deeply/nested/path/that/goes/on/and/on/for/"
            "quite/a/while/before/it/ends/socket.sock", 0xFFFFFFFFFFFFFFFFull);
        check(1 + deep.size() <= 108, "abstract name fits sun_path");
        check(deep.find("linuxity/") == 0, "namespaced so runs don't collide");
    }

    if (failures != 0) {
        std::fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    std::printf("resolver + socket namespace: ok\n");
    return 0;
}
