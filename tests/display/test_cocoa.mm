// tests/display/test_cocoa.mm -- the macOS host against real AppKit windows.
//
// The headless tests check the compositor; this checks the platform half,
// where the coordinate systems live: a click at a point in a Linux window
// must arrive at that point, on an app-drawn (full-size content) window and
// on a native-titled one alike. (The first Cocoa host flipped y twice and
// every click landed at the mirror-image height.)
#include "core/host.hpp"

#import <AppKit/AppKit.h>

#include <cmath>
#include <cstdio>
#include <memory>
#include <vector>

namespace lx::display {
std::unique_ptr<Host> make_cocoa_host();
}
using namespace lx::display;
namespace ld = lx::display;

namespace {

int g_failures = 0;
void check(bool ok, const char* what) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++g_failures;
}

struct Sink final : WindowSink {
    double x{-1}, y{-1};
    int presses{0};
    ld::Size configured{};
    void host_configure(ld::Size s, WindowStates) override { configured = s; }
    void host_close() override {}
    void host_focus(bool) override {}
    void host_pointer_motion(double px, double py, std::uint32_t) override { x = px; y = py; }
    void host_pointer_leave() override {}
    void host_pointer_button(PointerButton, bool pressed, std::uint32_t) override { presses += pressed; }
    void host_scroll(const ScrollEvent&, std::uint32_t) override {}
    void host_output(std::size_t) override {}
};

Scene solid_scene(int w, int h) {
    auto px = std::make_shared<Pixels>();
    px->width = w;
    px->height = h;
    px->stride = w * 4;
    px->data.assign(static_cast<std::size_t>(w * h * 4), std::byte{0x80});
    Scene s;
    s.view = {0, 0, w, h};
    s.geometry = s.view;
    Layer l;
    l.id = 1;
    l.rect = s.view;
    l.pixels = px;
    l.damage = s.view;
    l.generation = 1;
    s.layers.push_back(l);
    return s;
}

// Click at view point (vx, vy) -- y down from the window content's top-left,
// as Wayland counts -- and report where the window said it was.
void click_at(NSWindow* w, double vx, double vy) {
    NSView* v = w.contentView;
    const NSPoint in_window = [v convertPoint:NSMakePoint(vx, vy) toView:nil];   // v is flipped
    NSEvent* e = [NSEvent mouseEventWithType:NSEventTypeLeftMouseDown location:in_window modifierFlags:0
                                   timestamp:0 windowNumber:w.windowNumber context:nil eventNumber:0
                                  clickCount:1 pressure:1];
    [v mouseDown:e];
}

void test_window(Host& host, Decorations deco, const char* what) {
    Sink sink;
    WindowSpec spec;
    spec.decorations = deco;
    spec.title = what;
    auto win = host.create_window(spec, sink);
    win->present(solid_scene(240, 160));
    char cfg[160];
    std::snprintf(cfg, sizeof cfg, "%s: creating and showing it asks the app for no other size (got %dx%d)", what,
                  sink.configured.w, sink.configured.h);
    check(sink.configured.w == 0 || (sink.configured.w == 240 && sink.configured.h == 160), cfg);
    NSWindow* ns = nil;
    for (NSWindow* w in NSApp.windows)
        if ([w.title isEqualToString:@(what)]) ns = w;
    check(ns != nil, "a native window exists");
    if (!ns) return;
    const NSRect content = [ns contentRectForFrameRect:ns.frame];
    check(std::lround(content.size.width) == 240 && std::lround(content.size.height) == 160,
          "its content is the scene's view size");
    click_at(ns, 30, 20);
    char msg[160];
    std::snprintf(msg, sizeof msg, "%s: a click 20pt below the top arrives at y=20 (got %.1f, %.1f)", what, sink.x, sink.y);
    check(std::fabs(sink.x - 30) < 0.01 && std::fabs(sink.y - 20) < 0.01, msg);
    click_at(ns, 200, 150);
    std::snprintf(msg, sizeof msg, "%s: near the bottom-right too (got %.1f, %.1f)", what, sink.x, sink.y);
    check(std::fabs(sink.x - 200) < 0.01 && std::fabs(sink.y - 150) < 0.01, msg);
    check(sink.presses == 2, "both presses delivered");
    check(ns.styleMask & NSWindowStyleMaskTitled, "a real titled window (system shadow, corners, edge resizing)");
    check((ns.styleMask & NSWindowStyleMaskResizable) != 0, "resizable from its edges");
}

}  // namespace

int main() {
    @autoreleasepool {
        auto host = make_cocoa_host();
        test_window(*host, Decorations::client, "app-drawn title bar");
        test_window(*host, Decorations::server, "native title bar");
        check(host->native_frames(), "the macOS host frames every window");
    }
    std::printf("%s (%d failure%s)\n", g_failures ? "FAILED" : "PASSED", g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
