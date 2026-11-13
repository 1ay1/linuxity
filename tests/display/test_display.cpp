// tests/display/test_display.cpp -- linuxity-display's compositor core,
// driven by a scripted Wayland client over a socketpair.
//
// No libwayland: the client speaks the wire with the same generated tables
// the server uses, which also checks that encoding and decoding agree. The
// headless host composites every presented window into a PPM, so the tests
// assert on the pixels a user would see, not just on protocol traffic.
#include "core/compositor.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

namespace lx::display {
std::unique_ptr<Host> make_headless_host(std::string dump_dir);
std::unique_ptr<Host> make_host(bool) { return make_headless_host({}); }
}  // namespace lx::display

using namespace lx::display;
using namespace lx::display::proto;
namespace wire = lx::display::wire;

namespace {

int g_failures = 0;
void check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++g_failures;
}

struct Event {
    wire::ObjectId id{0};
    std::string iface, name;
    std::vector<std::int64_t> v;     // i u f o n, in order
    std::vector<std::string> s;      // strings, in order
    std::vector<std::string> a;      // arrays, in order
};

// A Wayland client in miniature.
class TestClient {
public:
    explicit TestClient(wire::Fd sock) : chan_(std::move(sock)) { types_[1] = &WlDisplay::iface; }

    wire::ObjectId make(const wire::Interface& i) {
        const wire::ObjectId id = next_++;
        types_[id] = &i;
        return id;
    }
    template <class... A>
    void req(wire::ObjectId id, std::uint16_t op, A&&... args) {
        wire::Encoder e{out_, fds_, id, op};
        (e.put(wire::wire_value(std::forward<A>(args))), ...);
        e.finish();
        (void)chan_.write_some(out_, fds_);
    }
    // Read and decode whatever the server sent.
    void poll() {
        while (chan_.read_some(in_) == wire::Channel::Io::ok) {}
        std::size_t at = 0;
        while (in_.size() - at >= 8) {
            std::uint32_t id = 0, w = 0;
            std::memcpy(&id, in_.data() + at, 4);
            std::memcpy(&w, in_.data() + at + 4, 4);
            const std::size_t size = w >> 16;
            if (in_.size() - at < size) break;
            const auto op = static_cast<std::uint16_t>(w & 0xffff);
            Event ev;
            ev.id = id;
            const auto t = types_.find(id);
            assert(t != types_.end() && "event for an object we never made");
            const wire::Message& m = t->second->events[op];
            ev.iface = t->second->name;
            ev.name = m.name;
            wire::Args args;
            const bool ok = wire::decode(m.signature, {in_.data() + at + 8, size - 8}, chan_, args);
            assert(ok);
            std::size_t k = 0, ti = 0;
            for (char c : m.signature) {
                if (c == '?') continue;
                switch (c) {
                    case 's': ev.s.emplace_back(args.opt_str(k).value_or("")); break;
                    case 'a': {
                        auto b = args.array(k);
                        ev.a.emplace_back(reinterpret_cast<const char*>(b.data()), b.size());
                        break;
                    }
                    case 'h': (void)args.take_fd(k); break;
                    case 'n':
                        // a server-created object: learn its type
                        if (ti < m.types.size() && m.types[ti]) types_[args.new_id(k)] = m.types[ti];
                        ev.v.push_back(args.u(k));
                        break;
                    default: ev.v.push_back(static_cast<std::int64_t>(c == 'i' ? args.i(k) : args.u(k))); break;
                }
                ++k;
                ++ti;
            }
            events.push_back(std::move(ev));
            at += size;
        }
        in_.erase(in_.begin(), in_.begin() + static_cast<std::ptrdiff_t>(at));
    }
    // The first unconsumed event matching, removed from the queue.
    std::optional<Event> take(const std::string& iface, const std::string& name, wire::ObjectId id = 0) {
        for (auto it = events.begin(); it != events.end(); ++it)
            if (it->iface == iface && it->name == name && (!id || it->id == id)) {
                Event e = std::move(*it);
                events.erase(it);
                return e;
            }
        return std::nullopt;
    }
    [[nodiscard]] bool has(const std::string& iface, const std::string& name, wire::ObjectId id = 0) const {
        for (const auto& e : events)
            if (e.iface == iface && e.name == name && (!id || e.id == id)) return true;
        return false;
    }
    std::vector<Event> events;

private:
    wire::Channel chan_;
    std::vector<std::byte> in_, out_;
    std::vector<int> fds_;
    std::map<wire::ObjectId, const wire::Interface*> types_;
    wire::ObjectId next_{2};
};

// Run the compositor's loop until `done` or a timeout.
bool pump(EventLoop& loop, TestClient& c, const std::function<bool()>& done, int ms = 2000) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    bool ok = false;
    auto t = loop.every(std::chrono::milliseconds(1), [&] {
        c.poll();
        if (done()) { ok = true; loop.stop(); }
        else if (std::chrono::steady_clock::now() > until) loop.stop();
    });
    loop.run();
    return ok;
}

// An shm pool of one solid-colour XRGB buffer.
struct ShmBuffer {
    int fd{-1};
    std::size_t size{0};
    ShmBuffer(int w, int h, std::uint32_t xrgb) {
        char tmpl[] = "/tmp/lxd-test-XXXXXX";
        fd = ::mkstemp(tmpl);
        ::unlink(tmpl);
        size = static_cast<std::size_t>(w) * static_cast<std::size_t>(h) * 4;
        assert(::ftruncate(fd, static_cast<off_t>(size)) == 0);
        auto* p = static_cast<std::uint32_t*>(::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
        for (std::size_t k = 0; k < size / 4; ++k) p[k] = xrgb;
        ::munmap(p, size);
    }
    ~ShmBuffer() { ::close(fd); }
};

struct Rgb { int r, g, b; };
std::optional<Rgb> ppm_pixel(const std::string& path, int x, int y, int* w_out = nullptr, int* h_out = nullptr) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::nullopt;
    std::string magic;
    int w = 0, h = 0, max = 0;
    f >> magic >> w >> h >> max;
    f.get();
    if (w_out) *w_out = w;
    if (h_out) *h_out = h;
    std::vector<unsigned char> px(static_cast<std::size_t>(w) * static_cast<std::size_t>(h) * 3);
    f.read(reinterpret_cast<char*>(px.data()), static_cast<std::streamsize>(px.size()));
    const auto* p = &px[(static_cast<std::size_t>(y) * static_cast<std::size_t>(w) + static_cast<std::size_t>(x)) * 3];
    return Rgb{p[0], p[1], p[2]};
}

// The compositor under test and one connected client.
struct Fixture {
    std::string dump;
    std::unique_ptr<Host> host;
    std::unique_ptr<Server> server;
    std::unique_ptr<Compositor> comp;
    std::unique_ptr<TestClient> c;
    std::map<std::string, std::uint32_t> globals;   // interface -> name
    wire::ObjectId registry{0}, compositor{0}, shm{0}, wm{0}, sub{0};

    Fixture() {
        char tmpl[] = "/tmp/lxd-dump-XXXXXX";
        dump = ::mkdtemp(tmpl);
        host = make_headless_host(dump);
        server = std::make_unique<Server>(host->loop());
        comp = std::make_unique<Compositor>(*server, *host);
        int sv[2];
        assert(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
        (void)server->adopt(wire::Fd{sv[0]});
        c = std::make_unique<TestClient>(wire::Fd{sv[1]});
        registry = c->make(WlRegistry::iface);
        c->req(1, WlDisplay::Req::get_registry, wire::NewId{registry});
        const auto cb = c->make(WlCallback::iface);
        c->req(1, WlDisplay::Req::sync, wire::NewId{cb});
        pump(host->loop(), *c, [&] { return c->has("wl_callback", "done", cb); });
        while (auto g = c->take("wl_registry", "global")) globals[g->s[0]] = static_cast<std::uint32_t>(g->v[0]);
        compositor = bind(WlCompositor::iface, 6);
        shm = bind(WlShm::iface, 1);
        wm = bind(XdgWmBase::iface, 6);
        sub = bind(WlSubcompositor::iface, 1);
    }
    ~Fixture() {
        c.reset();
        comp.reset();
        server.reset();
        host.reset();
        std::string cmd = "rm -rf '" + dump + "'";
        (void)std::system(cmd.c_str());
    }
    wire::ObjectId bind(const wire::Interface& i, std::uint32_t v) {
        const auto id = c->make(i);
        c->req(registry, WlRegistry::Req::bind, globals.at(std::string{i.name}), i.name, v, wire::NewId{id});
        return id;
    }
    wire::ObjectId buffer(const ShmBuffer& b, int w, int h) {
        const auto pool = c->make(WlShmPool::iface);
        c->req(shm, WlShm::Req::create_pool, wire::NewId{pool}, wire::FdArg{b.fd}, static_cast<std::int32_t>(b.size));
        const auto buf = c->make(WlBuffer::iface);
        c->req(pool, WlShmPool::Req::create_buffer, wire::NewId{buf}, 0, w, h, w * 4, WlShm::Format::xrgb8888);
        c->req(pool, WlShmPool::Req::destroy);
        return buf;
    }
    wire::ObjectId surface() {
        const auto s = c->make(WlSurface::iface);
        c->req(compositor, WlCompositor::Req::create_surface, wire::NewId{s});
        return s;
    }
    void sync() {
        const auto cb = c->make(WlCallback::iface);
        c->req(1, WlDisplay::Req::sync, wire::NewId{cb});
        pump(host->loop(), *c, [&] { return c->has("wl_callback", "done", cb); });
        (void)c->take("wl_callback", "done", cb);
    }
    // A mapped toplevel showing `buf`; returns {surface, xdg_surface, toplevel}.
    std::array<wire::ObjectId, 3> toplevel(wire::ObjectId buf, const char* title) {
        const auto s = surface();
        const auto xs = c->make(proto::XdgSurface::iface);
        c->req(wm, XdgWmBase::Req::get_xdg_surface, wire::NewId{xs}, wire::Object{s});
        const auto tl = c->make(XdgToplevel::iface);
        c->req(xs, proto::XdgSurface::Req::get_toplevel, wire::NewId{tl});
        c->req(tl, XdgToplevel::Req::set_title, title);
        c->req(s, WlSurface::Req::commit);
        pump(host->loop(), *c, [&] { return c->has("xdg_surface", "configure", xs); });
        const auto cfg = c->take("xdg_surface", "configure", xs);
        c->req(xs, proto::XdgSurface::Req::ack_configure, static_cast<std::uint32_t>(cfg->v[0]));
        c->req(s, WlSurface::Req::attach, wire::Object{buf}, 0, 0);
        c->req(s, WlSurface::Req::commit);
        sync();
        return {s, xs, tl};
    }
    [[nodiscard]] std::string dump_of(int n, const char* title) const {
        return dump + "/" + std::to_string(n) + "-" + title + ".ppm";
    }
};

// -- tests ------------------------------------------------------------------------

void test_registry() {
    Fixture f;
    for (const char* g : {"wl_compositor", "wl_subcompositor", "wl_shm", "xdg_wm_base", "wl_seat",
                          "wl_output", "wl_data_device_manager", "zxdg_decoration_manager_v1"})
        check(f.globals.contains(g), (std::string{"global "} + g).c_str());
    f.sync();
    check(f.c->has("wl_shm", "format"), "wl_shm announces formats");
}

void test_toplevel_pixels() {
    Fixture f;
    const auto out = f.bind(WlOutput::iface, 4);
    ShmBuffer red(64, 48, 0x00ff0000);
    const auto buf = f.buffer(red, 64, 48);
    auto [s, xs, tl] = f.toplevel(buf, "red");
    check(f.c->has("wl_output", "done", out), "wl_output describes itself");
    check(f.c->has("wl_buffer", "release", buf), "buffer released after commit (copied)");
    int w = 0, h = 0;
    const auto px = ppm_pixel(f.dump_of(1, "red"), 10, 10, &w, &h);
    check(px && px->r == 255 && px->g == 0 && px->b == 0, "toplevel shows its buffer's pixels");
    check(w == 64 && h == 48, "window is the buffer's size");
    const auto enter = f.c->take("wl_surface", "enter", s);
    check(enter && enter->v[0] == out, "surface entered the output it shows on");
    check(f.c->has("wl_surface", "preferred_buffer_scale", s), "surface told the output's scale");
}

void test_subsurface_and_frame() {
    Fixture f;
    ShmBuffer blue(80, 60, 0x000000ff), green(20, 20, 0x0000ff00);
    const auto root_buf = f.buffer(blue, 80, 60);
    const auto child_buf = f.buffer(green, 20, 20);
    const auto child = f.surface();
    auto [s, xs, tl] = f.toplevel(root_buf, "tree");
    const auto ss = f.c->make(WlSubsurface::iface);
    f.c->req(f.sub, WlSubcompositor::Req::get_subsurface, wire::NewId{ss}, wire::Object{child}, wire::Object{s});
    f.c->req(ss, WlSubsurface::Req::set_position, 30, 20);
    f.c->req(child, WlSurface::Req::attach, wire::Object{child_buf}, 0, 0);
    f.c->req(child, WlSurface::Req::commit);       // synchronized: waits for the parent
    const auto cb = f.c->make(WlCallback::iface);
    f.c->req(s, WlSurface::Req::frame, wire::NewId{cb});
    f.c->req(s, WlSurface::Req::commit);
    check(pump(f.host->loop(), *f.c, [&] { return f.c->has("wl_callback", "done", cb); }), "frame callback fires");
    f.sync();
    const auto in = ppm_pixel(f.dump_of(1, "tree"), 35, 25);
    const auto out = ppm_pixel(f.dump_of(1, "tree"), 5, 5);
    check(in && in->g == 255 && in->b == 0, "subsurface drawn at its position, above the parent");
    check(out && out->b == 255 && out->g == 0, "parent visible around it");
}

void test_unconfigured_buffer_is_an_error() {
    Fixture f;
    ShmBuffer px(8, 8, 0);
    const auto buf = f.buffer(px, 8, 8);
    const auto s = f.surface();
    const auto xs = f.c->make(proto::XdgSurface::iface);
    f.c->req(f.wm, XdgWmBase::Req::get_xdg_surface, wire::NewId{xs}, wire::Object{s});
    const auto tl = f.c->make(XdgToplevel::iface);
    f.c->req(xs, proto::XdgSurface::Req::get_toplevel, wire::NewId{tl});
    f.c->req(s, WlSurface::Req::attach, wire::Object{buf}, 0, 0);
    f.c->req(s, WlSurface::Req::commit);
    const bool err = pump(f.host->loop(), *f.c, [&] { return f.c->has("wl_display", "error"); });
    const auto e = f.c->take("wl_display", "error");
    check(err && e && e->v[0] == xs &&
              e->v[1] == static_cast<std::int64_t>(proto::XdgSurface::Error::unconfigured_buffer),
          "buffer before configure: xdg_surface.unconfigured_buffer");
}

void test_bad_object_is_an_error() {
    Fixture f;
    f.c->req(999, 0);
    const bool err = pump(f.host->loop(), *f.c, [&] { return f.c->has("wl_display", "error"); });
    check(err, "request to a nonexistent object: wl_display.error");
}

void test_popup_placement() {
    Fixture f;
    ShmBuffer bg(200, 100, 0x00808080), menu(60, 30, 0x00ffffff);
    const auto bg_buf = f.buffer(bg, 200, 100);
    const auto menu_buf = f.buffer(menu, 60, 30);
    auto [s, xs, tl] = f.toplevel(bg_buf, "parent");
    const auto pos = f.c->make(XdgPositioner::iface);
    f.c->req(f.wm, XdgWmBase::Req::create_positioner, wire::NewId{pos});
    f.c->req(pos, XdgPositioner::Req::set_size, 60, 30);
    f.c->req(pos, XdgPositioner::Req::set_anchor_rect, 10, 10, 40, 20);
    f.c->req(pos, XdgPositioner::Req::set_anchor, XdgPositioner::Anchor::bottom_left);
    f.c->req(pos, XdgPositioner::Req::set_gravity, XdgPositioner::Gravity::bottom_right);
    const auto ps = f.surface();
    const auto pxs = f.c->make(proto::XdgSurface::iface);
    f.c->req(f.wm, XdgWmBase::Req::get_xdg_surface, wire::NewId{pxs}, wire::Object{ps});
    const auto popup = f.c->make(XdgPopup::iface);
    f.c->req(pxs, proto::XdgSurface::Req::get_popup, wire::NewId{popup}, wire::Object{xs}, wire::Object{pos});
    f.c->req(ps, WlSurface::Req::commit);
    pump(f.host->loop(), *f.c, [&] { return f.c->has("xdg_popup", "configure", popup); });
    const auto cfg = f.c->take("xdg_popup", "configure", popup);
    check(cfg && cfg->v[0] == 10 && cfg->v[1] == 30 && cfg->v[2] == 60 && cfg->v[3] == 30,
          "popup placed at the anchor's bottom-left, growing down-right");
    const auto pcfg = f.c->take("xdg_surface", "configure", pxs);
    f.c->req(pxs, proto::XdgSurface::Req::ack_configure, static_cast<std::uint32_t>(pcfg ? pcfg->v[0] : 0));
    f.c->req(ps, WlSurface::Req::attach, wire::Object{menu_buf}, 0, 0);
    f.c->req(ps, WlSurface::Req::commit);
    f.sync();
    const auto px = ppm_pixel(f.dump + "/2-.ppm", 5, 5);
    check(px && px->r == 255 && px->g == 255 && px->b == 255, "popup maps as its own window with its pixels");
    f.c->req(popup, XdgPopup::Req::destroy);
    f.c->req(pxs, proto::XdgSurface::Req::destroy);
    f.sync();
    check(!f.c->has("wl_display", "error"), "popup torn down cleanly");
}

void test_positioner_constraints() {
    using CA = XdgPositioner::ConstraintAdjustment;
    PositionerState p;
    p.size = {100, 50};
    p.anchor_rect = {10, 10, 20, 20};
    p.anchor = XdgPositioner::Anchor::bottom_left;
    p.gravity = XdgPositioner::Gravity::bottom_right;
    check(p.place(std::nullopt) == Rect{10, 30, 100, 50}, "unconstrained placement");
    p.adjust = CA::flip_y;
    check(p.place(Rect{0, 0, 300, 75}) == Rect{10, 30, 100, 50}, "flip_y not taken when the flipped rect doesn't fit either");
    p.adjust = CA::flip_y;
    check(p.place(Rect{0, -100, 300, 175}) == Rect{10, -40, 100, 50}, "flip_y above the anchor");
    p.adjust = CA::slide_y;
    check(p.place(Rect{0, 0, 300, 60}) == Rect{10, 10, 100, 50}, "slide_y back inside");
    p.adjust = CA::slide_x;
    check(p.place(Rect{0, 0, 80, 300}) == Rect{0, 30, 100, 50}, "slide_x keeps the left edge visible");
    p.adjust = CA::resize_x;
    check(p.place(Rect{0, 0, 60, 300}) == Rect{10, 30, 50, 50}, "resize_x shrinks to fit");
}

void test_decoration_policy() {
    Fixture f;
    const auto dm = f.bind(ZxdgDecorationManagerV1::iface, 1);
    const auto s = f.surface();
    const auto xs = f.c->make(proto::XdgSurface::iface);
    f.c->req(f.wm, XdgWmBase::Req::get_xdg_surface, wire::NewId{xs}, wire::Object{s});
    const auto tl = f.c->make(XdgToplevel::iface);
    f.c->req(xs, proto::XdgSurface::Req::get_toplevel, wire::NewId{tl});
    const auto deco = f.c->make(ZxdgToplevelDecorationV1::iface);
    f.c->req(dm, ZxdgDecorationManagerV1::Req::get_toplevel_decoration, wire::NewId{deco}, wire::Object{tl});
    f.c->req(s, WlSurface::Req::commit);
    pump(f.host->loop(), *f.c, [&] { return f.c->has("xdg_surface", "configure", xs); });
    const auto d = f.c->take("zxdg_toplevel_decoration_v1", "configure", deco);
    check(d && d->v[0] == static_cast<std::int64_t>(ZxdgToplevelDecorationV1::Mode::server_side),
          "no preference: native (server-side) decorations");
    f.c->req(deco, ZxdgToplevelDecorationV1::Req::set_mode, ZxdgToplevelDecorationV1::Mode::client_side);
    pump(f.host->loop(), *f.c, [&] { return f.c->has("zxdg_toplevel_decoration_v1", "configure", deco); });
    const auto d2 = f.c->take("zxdg_toplevel_decoration_v1", "configure", deco);
    check(d2 && d2->v[0] == static_cast<std::int64_t>(ZxdgToplevelDecorationV1::Mode::client_side),
          "a client that draws its own frame gets to");
}

void test_keyboard_keymap() {
    Fixture f;
    const auto seat = f.bind(WlSeat::iface, 8);
    const auto kb = f.c->make(WlKeyboard::iface);
    f.c->req(seat, WlSeat::Req::get_keyboard, wire::NewId{kb});
    f.sync();
    check(f.c->has("wl_seat", "capabilities", seat), "seat capabilities");
    check(f.c->has("wl_keyboard", "keymap", kb), "keyboard gets an xkb keymap fd");
    check(f.c->has("wl_keyboard", "repeat_info", kb), "keyboard gets repeat info");
}

}  // namespace

int main() {
    test_registry();
    test_toplevel_pixels();
    test_subsurface_and_frame();
    test_unconfigured_buffer_is_an_error();
    test_bad_object_is_an_error();
    test_popup_placement();
    test_positioner_constraints();
    test_decoration_policy();
    test_keyboard_keymap();
    std::printf("%s (%d failure%s)\n", g_failures ? "FAILED" : "PASSED", g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
