// fsnotify: linuxity's own inotify, for hosts that can't name directory
// entries. The event semantics the guest relies on, pinned without a host:
// child events by name on a directory watch, self events, MOVED_FROM/TO
// pairs sharing a cookie, IN_ONESHOT then IGNORED, DELETE_SELF ending a
// watch, ISDIR, renamed watches following their object, and the record
// encoding (16-byte header, NUL-padded name) a guest's read() parses.
#include "linuxity/kernel/fsnotify.hpp"

#include <cstdio>
#include <cstdlib>
#include <unistd.h>

using namespace lx::kernel::fsnotify;

static int fails = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("fsnotify: FAIL %s\n", m); ++fails; } } while (0)

static std::vector<std::pair<int, std::uint32_t>> drain(Instance& in) {
    std::vector<std::pair<int, std::uint32_t>> v;
    for (const auto& r : in.queued()) v.emplace_back(r.wd, r.mask);
    std::byte buf[4096];
    (void)in.encode(buf, sizeof buf);
    return v;
}

int main() {
    // -- a directory watch names its children, in order -------------------
    {
        Instance in;
        const int wd = in.add("/w", kAllEvents, true);
        for (auto m : {kCreate, kOpen, kModify, kCloseWrite, kAttrib, kDelete})
            in.deliver({m, 0, "/w/f"});
        const auto& q = in.queued();
        CHECK(q.size() == 6, "six child events");
        CHECK(q[0].wd == wd && q[0].mask == kCreate && q[0].name == "f", "CREATE f");
        CHECK(q[5].mask == kDelete && q[5].name == "f", "DELETE f last");
        in.deliver({kCreate, 0, "/elsewhere/g"});
        CHECK(in.queued().size() == 6, "events elsewhere are not ours");
        (void)drain(in);
    }
    // -- the mask filters, ISDIR rides along ------------------------------
    {
        Instance in;
        (void)in.add("/w", kCreate, true);
        in.deliver({kModify, 0, "/w/f"});
        in.deliver({kCreate | kIsDir, 0, "/w/sub"});
        const auto& q = in.queued();
        CHECK(q.size() == 1 && q[0].mask == (kCreate | kIsDir), "only CREATE, with ISDIR");
    }
    // -- self events, DELETE_SELF ends the watch with IGNORED -------------
    {
        Instance in;
        const int top = in.add("/t", kAllEvents, true);
        const int sub = in.add("/t/sub", kAllEvents, true);
        in.deliver({kCreate, 0, "/t/sub/inner"});
        in.deliver({kDelete | kIsDir, 0, "/t/sub"});
        bool child = false, self = false, ign = false, parent = false;
        for (const auto& r : in.queued()) {
            child  |= r.wd == sub && r.mask == kCreate && r.name == "inner";
            self   |= r.wd == sub && r.mask == kDeleteSelf;
            ign    |= r.wd == sub && r.mask == kIgnored && self;
            parent |= r.wd == top && r.mask == (kDelete | kIsDir) && r.name == "sub";
        }
        CHECK(child && self && ign && parent, "nested watch, DELETE_SELF then IGNORED, DELETE|ISDIR on parent");
        in.deliver({kCreate, 0, "/t/sub/again"});
        bool after = false;
        for (const auto& r : in.queued()) after |= r.name == "again";
        CHECK(!after, "a deleted watch hears nothing more");
    }
    // -- moves pair up by cookie, across directories ------------------------
    {
        Instance in;
        const int a = in.add("/a", kAllEvents, true), b = in.add("/b", kAllEvents, true);
        const std::uint32_t c = new_cookie();
        in.deliver({kMovedFrom, c, "/a/x"});
        in.deliver({kMovedTo, c, "/b/y"});
        const auto& q = in.queued();
        CHECK(q.size() == 2 && q[0].wd == a && q[1].wd == b && q[0].cookie == c && q[1].cookie == c && c != 0,
              "MOVED_FROM/TO share a non-zero cookie");
    }
    // -- a watched file that moves keeps its watch -------------------------
    {
        Instance in;
        const int wd = in.add("/d/f", kModify, false);
        const std::uint32_t c = new_cookie();
        in.deliver({kMovedFrom, c, "/d/f"});
        in.deliver({kMovedTo, c, "/d/g"});
        (void)drain(in);
        in.deliver({kModify, 0, "/d/g"});
        CHECK(in.queued().size() == 1 && in.queued()[0].wd == wd, "the watch follows its renamed file");
    }
    // -- IN_ONESHOT fires once then IGNORED; rm_watch queues IGNORED --------
    {
        Instance in;
        const int wd = in.add("/o", kModify | kOneshot, false);
        for (int i = 0; i < 3; ++i) in.deliver({kModify, 0, "/o"});
        const auto v = drain(in);
        CHECK((v == std::vector<std::pair<int, std::uint32_t>>{{wd, kModify}, {wd, kIgnored}}), "oneshot then IGNORED");
        const int w2 = in.add("/o", kModify, false);
        CHECK(in.remove(w2) == 0 && in.queued().size() == 1 && in.queued()[0].mask == kIgnored, "rm_watch -> IGNORED");
        CHECK(in.remove(w2) == -22, "rm_watch twice is EINVAL");
    }
    // -- the record encoding a guest's read() parses ------------------------
    {
        Instance in;
        (void)in.add("/w", kAllEvents, true);
        in.deliver({kCreate, 0, "/w/abc"});
        std::byte buf[64];
        CHECK(in.encode(buf, 15) == -22, "a buffer too small for one record is EINVAL");
        const long n = in.encode(buf, sizeof buf);
        std::uint32_t len = 0;
        std::memcpy(&len, buf + 12, 4);
        CHECK(n == 16 + 4 && len == 4 && std::memcmp(buf + 16, "abc\0", 4) == 0, "16-byte header + NUL-padded name");
    }
    // -- the hub: only concerned instances get lines, in order ---------------
    {
        char tmpl[] = "/tmp/lx-fsnotify-XXXXXX";
        const std::string dir = ::mkdtemp(tmpl);
        Hub watcher, emitter;           // two processes' views of one tree
        watcher.attach(dir);
        emitter.attach(dir);
        CHECK(!emitter.active(), "nobody watching: inactive");
        const std::string id = watcher.open_instance();
        watcher.publish(id, {{kCreate | kMovedFrom | kMovedTo, true, "/w"}});
        Hub late;                       // a third process, after the watch
        late.attach(dir);
        CHECK(late.active(), "a watch anywhere makes every process active");
        emitter.emit({kCreate, 0, "/elsewhere/x"});
        emitter.emit({kCreate, 0, "/w/one"});
        emitter.emit_all({{kMovedFrom, 77, "/w/with space"}, {kMovedTo, 77, "/z/out"}});
        long long at = 0;
        const auto ev = read_log(watcher.log_path(id), at);
        CHECK(ev.size() == 3 && ev[0].path == "/w/one" && ev[1].cookie == 77 &&
              ev[1].path == "/w/with space" && ev[2].path == "/z/out",
              "only concerning events, a move's both halves, spaces kept");
        CHECK(read_log(watcher.log_path(id), at).empty(), "nothing twice");
        watcher.close_instance(id);
        ::rmdir(dir.c_str());
    }
    if (!fails) std::puts("fsnotify: names, self events, cookies, oneshot, renames, encoding and the log all hold");
    return fails ? 1 : 0;
}
