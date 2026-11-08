// tests/test_landlock.cpp
//
// linuxity's own Landlock rule check, for hosts whose kernel has none. Each
// case is a rule the kernel's own landlock selftests check the same way.
#include "linuxity/kernel/landlock.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>

using namespace lx::kernel::landlock;

static int fails = 0;
#define CHECK(c) do { if (!(c)) { std::fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); ++fails; } } while (0)

static Domain stack(std::vector<Layer> ls) { return std::make_shared<const std::vector<Layer>>(std::move(ls)); }

int main() {
    // no domain: everything goes
    CHECK(allows(nullptr, "/etc/passwd", kWriteFile));

    // one layer, read-only on /usr, read-write beneath /work
    Ruleset rs;
    rs.handled_fs = kReadFile | kWriteFile | kReadDir | kMakeReg;
    rs.paths = {{"/usr", kReadFile | kReadDir}, {"/work", kReadFile | kWriteFile | kReadDir | kMakeReg}};
    const Domain d = stack({{rs, 1}});
    CHECK(allows(d, "/usr/bin/ls", kReadFile));
    CHECK(!allows(d, "/usr/bin/ls", kWriteFile));
    CHECK(allows(d, "/work/a/b", kWriteFile));
    CHECK(allows(d, "/work", kMakeReg));
    CHECK(!allows(d, "/etc/passwd", kReadFile));     // no rule beneath: denied
    CHECK(!allows(d, "/workshop/x", kReadFile));     // a prefix that isn't a parent
    // an access the ruleset doesn't handle is never denied
    CHECK(allows(d, "/etc/passwd", kExecute));
    // REFER is always handled, even when not asked for
    CHECK(!allows(d, "/work/x", kRefer));

    // rules on nested dirs add up
    Ruleset nest;
    nest.handled_fs = kReadFile | kWriteFile;
    nest.paths = {{"/a", kReadFile}, {"/a/b", kWriteFile}};
    const Domain dn = stack({{nest, 2}});
    CHECK(allows(dn, "/a/b/f", kReadFile | kWriteFile));
    CHECK(!allows(dn, "/a/f", kWriteFile));

    // a second layer can only take away: both must allow
    Ruleset tight;
    tight.handled_fs = kWriteFile;
    tight.paths = {{"/work/out", kWriteFile}};
    const Domain d2 = stack({{rs, 1}, {tight, 3}});
    CHECK(allows(d2, "/work/out/f", kWriteFile));
    CHECK(!allows(d2, "/work/in/f", kWriteFile));    // layer 2 says no
    CHECK(allows(d2, "/work/in/f", kReadFile));      // layer 2 doesn't handle reads
    CHECK(!allows(d2, "/etc/f", kReadFile));         // layer 1 still says no

    // the root rule covers everything
    Ruleset all;
    all.handled_fs = kReadFile;
    all.paths = {{"/", kReadFile}};
    CHECK(allows(stack({{all, 4}}), "/any/where", kReadFile));

    // TCP ports
    Ruleset net;
    net.handled_net = kConnectTcp;
    net.ports = {{443, kConnectTcp}};
    const Domain dp = stack({{net, 5}});
    CHECK(allows_port(dp, 443, kConnectTcp));
    CHECK(!allows_port(dp, 80, kConnectTcp));
    CHECK(allows_port(dp, 80, kBindTcp));            // bind isn't handled

    // scoping: nested domains are within their parent, not the other way
    Ruleset sc;
    sc.scoped = kScopeSignal;
    const Domain outer = stack({{sc, 6}});
    const Domain inner = stack({{sc, 6}, {sc, 7}});
    const Domain other = stack({{sc, 8}});
    CHECK(scopes(outer, kScopeSignal));
    CHECK(!scopes(outer, kScopeAbstractUnix));
    CHECK(within(inner, outer));
    CHECK(within(outer, outer));
    CHECK(!within(outer, inner));
    CHECK(!within(other, outer));
    CHECK(within(outer, nullptr));                   // anyone may reach an unrestricted process's... peers
    CHECK(!within(nullptr, outer));                  // an unrestricted target is outside a domain

    if (fails) { std::fprintf(stderr, "%d failed\n", fails); return 1; }
    std::puts("landlock: all checks pass");
    return 0;
}
