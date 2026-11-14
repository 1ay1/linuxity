// tests/display/test_hosts.cpp -- every host backend in this build against
// the contract the compositor core relies on, plus the registry.
//
// A new backend gets these checks for free: they run for each entry of
// host_backends() that is available where the test runs. What any Host
// must do, whatever the platform:
//   * describe at least one output with a sane size and scale;
//   * attach a sink, and create a window from a spec;
//   * present a Scene (first present maps the window) and survive more;
//   * give a work area that is not empty;
//   * take every optional request without crashing (defaults are fine);
//   * run its loop and stop it, firing a deferred call and a timer.
#include "core/host_registry.hpp"
#include "core/soft_compose.hpp"

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace lx::display;

namespace {

int g_failures = 0;
void check(bool ok, const std::string& what) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) ++g_failures;
}

struct NullHostSink final : HostSink {
    void host_key(std::uint32_t, bool, std::uint32_t) override {}
    void host_modifiers(Modifiers) override {}
    void host_outputs_changed() override {}
    void host_keyboard_changed() override {}
    void host_app_active(bool) override {}
    void host_quit() override {}
};
struct NullWindowSink final : WindowSink {
    void host_configure(Size, WindowStates) override {}
    void host_close() override {}
    void host_focus(bool) override {}
    void host_pointer_motion(double, double, std::uint32_t) override {}
    void host_pointer_leave() override {}
    void host_pointer_button(PointerButton, bool, std::uint32_t) override {}
    void host_scroll(const ScrollEvent&, std::uint32_t) override {}
    void host_output(std::size_t) override {}
};

// An opaque/translucent w x h buffer of one colour.
[[nodiscard]] PixelsRef solid(int w, int h, PixelFormat f, std::uint32_t bgra_le) {
    auto p = std::make_shared<Pixels>();
    p->width = w; p->height = h; p->stride = w * 4; p->format = f;
    p->data.resize(static_cast<std::size_t>(w * h * 4));
    for (std::size_t i = 0; i < p->data.size(); i += 4) std::memcpy(&p->data[i], &bgra_le, 4);
    return p;
}

void conformance(const HostBackend& b) {
    const std::string n{b.name};
    HostConfig cfg;
    auto host = b.create(cfg);
    check(host != nullptr, n + ": create");
    if (!host) return;
    NullHostSink hsink;
    NullWindowSink sink;
    host->attach(hsink);

    const auto outs = host->outputs();
    check(!outs.empty(), n + ": at least one output");
    for (const auto& o : outs)
        check(!o.logical.empty() && o.scale >= 1 && o.pixels.w >= o.logical.w,
              n + ": output " + o.name + " has a size and a scale");

    WindowSpec spec;
    spec.title = "conformance";
    auto win = host->create_window(spec, sink);
    check(win != nullptr, n + ": create_window");
    if (!win) return;

    const PixelsRef pixels = solid(64, 48, PixelFormat::xrgb8888, 0xffff0000u);   // opaque red
    Scene s;
    s.view = {0, 0, 64, 48};
    s.geometry = s.view;
    Layer l;
    l.id = 1;
    l.rect = {0, 0, 64, 48};
    l.pixels = pixels;
    l.damage = {0, 0, 64, 48};
    s.layers.push_back(l);
    win->present(s);
    win->present(s);
    check(true, n + ": present twice");
    check(!win->work_area().empty(), n + ": a work area");

    // every optional request, defaults or not
    win->set_title("renamed");
    win->set_decorations(Decorations::client);
    win->set_size_limits({10, 10}, {0, 0});
    win->set_maximized(false);
    win->set_fullscreen(false);
    win->set_text_input(std::nullopt);
    win->request_attention();
    host->set_cursor_shape(CursorShape::default_);
    host->reset_cursor();
    (void)host->keyboard();
    (void)host->clipboard();
    host->set_has_windows(true);
    check(true, n + ": optional requests");

    // the loop: a deferred call and a timer fire, then stop returns run()
    bool deferred = false;
    int ticks = 0;
    host->loop().defer([&] { deferred = true; });
    auto timer = host->loop().every(std::chrono::milliseconds(5), [&] {
        if (++ticks >= 3) host->loop().stop();
    });
    host->loop().run();
    check(deferred && ticks >= 3, n + ": loop runs deferred calls and timers, and stops");
    win.reset();
    host->set_has_windows(false);
}

}  // namespace

int main() {
    // the registry
    const auto all = host_backends();
    check(!all.empty(), "the build has host backends");
    check(find_host("headless") != nullptr, "headless is always built");
    check(best_host() != nullptr, "there is always a host to run");
    for (std::size_t i = 1; i < all.size(); ++i)
        check(all[i - 1]->priority >= all[i]->priority, "backends are sorted by priority");
    for (const HostBackend* b : all)
        check(!b->name.empty() && !b->summary.empty() && b->create, std::string{b->name} + ": complete entry");

    // soft_compose: a half-transparent layer over an opaque one
    {
        // little-endian words: B G R A bytes. Red opaque; blue at half
        // alpha, premultiplied (b = 128, a = 128).
        const PixelsRef base = solid(2, 2, PixelFormat::xrgb8888, 0xffff0000u);
        const PixelsRef top = solid(1, 1, PixelFormat::argb8888, 0x80000080u);
        Scene s;
        s.view = {0, 0, 2, 2};
        Layer a; a.id = 1; a.rect = {0, 0, 2, 2}; a.pixels = base;
        Layer b; b.id = 2; b.rect = {1, 1, 1, 1}; b.pixels = top;
        s.layers = {a, b};
        const auto img = soft_compose(s, 2);
        check(img.width == 4 && img.height == 4, "soft_compose: scale 2 doubles the image");
        const std::uint8_t* tl = &img.bgra[0];
        const std::uint8_t* br = &img.bgra[(3 * 4 + 3) * 4];
        check(tl[2] == 255 && tl[0] == 0, "soft_compose: the base layer shows");
        check(br[0] >= 126 && br[0] <= 130 && br[2] >= 126 && br[2] <= 129, "soft_compose: premultiplied over");
    }

    for (const HostBackend* b : all) {
        if (b->available && !b->available()) {
            std::printf("skip %s (not available here)\n", std::string{b->name}.c_str());
            continue;
        }
        conformance(*b);
    }
    std::printf("%s (%d failure%s)\n", g_failures ? "FAILED" : "PASSED", g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
