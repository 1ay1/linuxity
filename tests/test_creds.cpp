// Credentials across process boundaries: the per-process credential set is
// ONE value (kernel::Creds), so a fork copies all of it, an exec keeps it, a
// login sets it by one rule, and a fork into a fresh process (macOS) carries
// it through the fork-state codec intact. Each of these was once a hand-kept
// field list, and a field missing from one of them was a guest that turned
// back into root (or kept a capability it had dropped).
#include "linuxity/abi/creds.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"
#include "linuxity/kernel/process_table.hpp"

#include <cstdio>

using namespace lx;
using kernel::Creds;
using kernel::ProcInfo;
using kernel::ProcessTable;

static int fails = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("creds: FAIL %s\n", msg); ++fails; } } while (0)

static bool same(const Creds& a, const Creds& b) {
    return a.groups == b.groups && a.groups_set == b.groups_set && a.uids == b.uids &&
           a.gids == b.gids && a.cap_eff == b.cap_eff && a.cap_prm == b.cap_prm &&
           a.cap_inh == b.cap_inh && a.cap_bnd == b.cap_bnd && a.cap_amb == b.cap_amb &&
           a.keepcaps == b.keepcaps && a.no_new_privs == b.no_new_privs && a.nice == b.nice;
}

static Creds unusual() {
    Creds c;
    c.groups = {7, 8, 9};
    c.groups_set = true;
    c.uids = {1000, 1001, 1002, 1003};
    c.gids = {2000, 2001, 2002, 2003};
    c.cap_eff = 0x5; c.cap_prm = 0x7; c.cap_inh = 0x1; c.cap_bnd = 0xff; c.cap_amb = 0x1;
    c.keepcaps = true;
    c.no_new_privs = true;
    c.nice = 5;
    return c;
}

int main() {
    // -- login: the one "start as this user" rule ----------------------------
    {
        ProcInfo p;
        abi::creds::login(p, 1000, 100, {});
        CHECK((p.uids == std::array<std::uint32_t, 4>{1000, 1000, 1000, 1000}), "login: all four uids");
        CHECK(p.groups == std::vector<std::uint32_t>{100}, "login: no groups -> just the primary gid");
        CHECK(p.cap_eff == 0 && p.cap_prm == 0, "login: a non-root user has no capabilities");
        ProcInfo r;
        abi::creds::login(r, 0, 0, {0, 10});
        CHECK(r.cap_eff == Creds::kAllCaps, "login: root keeps its capabilities");
        CHECK(r.groups == (std::vector<std::uint32_t>{0, 10}), "login: groups as given");
    }
    // -- exec keeps credentials (upsert of a new image) ----------------------
    {
        ProcessTable t;
        ProcInfo p;
        p.pid = 5;
        p.creds() = unusual();
        p.creds_given = true;
        t.upsert(p);
        ProcInfo img;                 // a new image's record: default creds
        img.pid = 5;
        img.comm = "after-exec";
        t.upsert(img);
        CHECK(same(t.find(5)->creds(), unusual()), "exec keeps every credential field");
        CHECK(t.find(5)->comm == "after-exec", "exec takes the new identity");
    }
    // -- the exec transform: set-ID applies once -----------------------------
    {
        ProcessTable t;
        ProcInfo p;
        p.pid = 6;
        abi::creds::login(p, 1000, 1000, {});
        p.exec_setuid = 0;            // path_exec found a root-owned s-bit file
        t.upsert(p);
        abi::creds::exec_happened(t, 6);
        const auto* q = t.find(6);
        CHECK(q->uids[1] == 0 && q->uids[0] == 1000, "set-uid exec: euid 0, ruid kept");
        CHECK(q->exec_setuid == abi::creds::kKeep, "the pending set-ID is consumed");
    }
    // -- fork into a fresh process: the codec carries every field ------------
    {
        host::PosixHost h;
        kernel::Kernel<host::PosixHost> parent{h};
        ProcInfo p;
        p.pid = 9;
        p.creds() = unusual();
        p.creds_given = true;
        parent.procs().upsert(p);
        const std::string blob = parent.export_fork(9);

        kernel::Kernel<host::PosixHost> child{h};
        child.import_fork(blob);
        const auto& ic = child.procs().inherited_creds();
        CHECK(ic.has_value(), "fresh-process fork: creds arrive");
        CHECK(ic && same(*ic, unusual()), "fresh-process fork: every field intact");
    }
    if (fails == 0) std::puts("creds: login, exec, set-ID and fresh-process fork all keep one credential set");
    return fails ? 1 : 0;
}
