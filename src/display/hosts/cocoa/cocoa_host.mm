// src/display/hosts/cocoa/cocoa_host.mm -- the macOS host: Linux apps as
// real Mac windows.
//
//   * one NSWindow per xdg_toplevel; popups (menus, tooltips) are borderless
//     child windows, so they float above their parent and move with it
//   * every surface of a window's tree is a CALayer whose contents is a
//     CGImage of the client's pixels -- Core Animation composites them on
//     the GPU, Retina scale and all; nothing is drawn in software
//   * server-side decorations are the native title bar (traffic lights,
//     double-click zoom, native fullscreen in its own Space); client-side
//     ones (GTK's headerbar) get a borderless resizable window and the
//     app's xdg_toplevel.move/resize drive the native drag
//   * keys go out as Linux evdev codes from the hardware keycode, so the
//     guest's XKB layout decides what they mean, exactly as on Linux
//
// The event loop is the main dispatch queue: AppKit must own the main
// thread, and GCD sources there give us fd readiness and timers.
#include "../../core/host.hpp"

#import <AppKit/AppKit.h>
#import <Carbon/Carbon.h>
#import <QuartzCore/QuartzCore.h>

#include <dispatch/dispatch.h>

#include <atomic>
#include <cmath>
#include <map>
#include <memory>
#include <string>
#include <vector>

using namespace lx::display;
namespace ld = lx::display;

// -- the event loop -----------------------------------------------------------------

namespace {

class GcdLoop final : public EventLoop {
    class Src final : public Source {
    public:
        explicit Src(dispatch_source_t s) : s_(s) {}
        ~Src() override {
            *alive_ = false;
            dispatch_source_cancel(s_);
        }
        std::shared_ptr<bool> alive_ = std::make_shared<bool>(true);
    private:
        dispatch_source_t s_;
    };

public:
    std::unique_ptr<Source> on_readable(int fd, Fn fn) override {
        return fd_source(DISPATCH_SOURCE_TYPE_READ, fd, std::move(fn));
    }
    std::unique_ptr<Source> on_writable(int fd, Fn fn) override {
        return fd_source(DISPATCH_SOURCE_TYPE_WRITE, fd, std::move(fn));
    }
    std::unique_ptr<Source> every(std::chrono::microseconds p, Fn fn) override {
        dispatch_source_t s = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        const auto ns = static_cast<std::int64_t>(p.count()) * 1000;
        dispatch_source_set_timer(s, dispatch_time(DISPATCH_TIME_NOW, ns), static_cast<std::uint64_t>(ns),
                                  static_cast<std::uint64_t>(ns / 20));
        return finish(s, std::move(fn));
    }
    void defer(Fn fn) override {
        auto* heap = new Fn(std::move(fn));
        dispatch_async_f(dispatch_get_main_queue(), heap, [](void* ctx) {
            std::unique_ptr<Fn> f{static_cast<Fn*>(ctx)};
            @autoreleasepool { (*f)(); }
        });
    }
    void run() override { [NSApp run]; }
    void stop() override {
        [NSApp stop:nil];
        // -stop: only takes effect after the next event
        NSEvent* e = [NSEvent otherEventWithType:NSEventTypeApplicationDefined location:NSZeroPoint
                                   modifierFlags:0 timestamp:0 windowNumber:0 context:nil subtype:0 data1:0 data2:0];
        [NSApp postEvent:e atStart:YES];
    }

private:
    std::unique_ptr<Source> fd_source(dispatch_source_type_t t, int fd, Fn fn) {
        dispatch_source_t s = dispatch_source_create(t, static_cast<uintptr_t>(fd), 0, dispatch_get_main_queue());
        return finish(s, std::move(fn));
    }
    std::unique_ptr<Source> finish(dispatch_source_t s, Fn fn) {
        auto src = std::make_unique<Src>(s);
        std::shared_ptr<bool> alive = src->alive_;
        auto f = std::make_shared<Fn>(std::move(fn));
        dispatch_source_set_event_handler(s, ^{
            if (!*alive) return;
            @autoreleasepool { (*f)(); }
        });
        dispatch_resume(s);
        return src;
    }
};

// -- keyboard: macOS virtual keycodes -> Linux evdev -----------------------------------

std::uint32_t evdev_from_mac(unsigned short k) {
    static const std::map<unsigned short, std::uint32_t> m = {
        {kVK_ANSI_A, 30}, {kVK_ANSI_S, 31}, {kVK_ANSI_D, 32}, {kVK_ANSI_F, 33}, {kVK_ANSI_H, 35},
        {kVK_ANSI_G, 34}, {kVK_ANSI_Z, 44}, {kVK_ANSI_X, 45}, {kVK_ANSI_C, 46}, {kVK_ANSI_V, 47},
        {kVK_ISO_Section, 86}, {kVK_ANSI_B, 48}, {kVK_ANSI_Q, 16}, {kVK_ANSI_W, 17}, {kVK_ANSI_E, 18},
        {kVK_ANSI_R, 19}, {kVK_ANSI_Y, 21}, {kVK_ANSI_T, 20}, {kVK_ANSI_1, 2}, {kVK_ANSI_2, 3},
        {kVK_ANSI_3, 4}, {kVK_ANSI_4, 5}, {kVK_ANSI_6, 7}, {kVK_ANSI_5, 6}, {kVK_ANSI_Equal, 13},
        {kVK_ANSI_9, 10}, {kVK_ANSI_7, 8}, {kVK_ANSI_Minus, 12}, {kVK_ANSI_8, 9}, {kVK_ANSI_0, 11},
        {kVK_ANSI_RightBracket, 27}, {kVK_ANSI_O, 24}, {kVK_ANSI_U, 22}, {kVK_ANSI_LeftBracket, 26},
        {kVK_ANSI_I, 23}, {kVK_ANSI_P, 25}, {kVK_Return, 28}, {kVK_ANSI_L, 38}, {kVK_ANSI_J, 36},
        {kVK_ANSI_Quote, 40}, {kVK_ANSI_K, 37}, {kVK_ANSI_Semicolon, 39}, {kVK_ANSI_Backslash, 43},
        {kVK_ANSI_Comma, 51}, {kVK_ANSI_Slash, 53}, {kVK_ANSI_N, 49}, {kVK_ANSI_M, 50},
        {kVK_ANSI_Period, 52}, {kVK_Tab, 15}, {kVK_Space, 57}, {kVK_ANSI_Grave, 41}, {kVK_Delete, 14},
        {kVK_Escape, 1}, {kVK_Command, 125}, {kVK_RightCommand, 126}, {kVK_Shift, 42}, {kVK_CapsLock, 58},
        {kVK_Option, 56}, {kVK_Control, 29}, {kVK_RightShift, 54}, {kVK_RightOption, 100},
        {kVK_RightControl, 97}, {kVK_Function, 464}, {kVK_F17, 187}, {kVK_ANSI_KeypadDecimal, 83},
        {kVK_ANSI_KeypadMultiply, 55}, {kVK_ANSI_KeypadPlus, 78}, {kVK_ANSI_KeypadClear, 69},
        {kVK_VolumeUp, 115}, {kVK_VolumeDown, 114}, {kVK_Mute, 113}, {kVK_ANSI_KeypadDivide, 98},
        {kVK_ANSI_KeypadEnter, 96}, {kVK_ANSI_KeypadMinus, 74}, {kVK_F18, 188}, {kVK_F19, 189},
        {kVK_ANSI_KeypadEquals, 117}, {kVK_ANSI_Keypad0, 82}, {kVK_ANSI_Keypad1, 79}, {kVK_ANSI_Keypad2, 80},
        {kVK_ANSI_Keypad3, 81}, {kVK_ANSI_Keypad4, 75}, {kVK_ANSI_Keypad5, 76}, {kVK_ANSI_Keypad6, 77},
        {kVK_ANSI_Keypad7, 71}, {kVK_F20, 190}, {kVK_ANSI_Keypad8, 72}, {kVK_ANSI_Keypad9, 73},
        {kVK_JIS_Yen, 124}, {kVK_JIS_Underscore, 89}, {kVK_JIS_KeypadComma, 95}, {kVK_F5, 63},
        {kVK_F6, 64}, {kVK_F7, 65}, {kVK_F3, 61}, {kVK_F8, 66}, {kVK_F9, 67}, {kVK_JIS_Eisu, 94},
        {kVK_F11, 87}, {kVK_JIS_Kana, 93}, {kVK_F13, 183}, {kVK_F16, 186}, {kVK_F14, 184}, {kVK_F10, 68},
        {kVK_F12, 88}, {kVK_F15, 185}, {kVK_Help, 110}, {kVK_Home, 102}, {kVK_PageUp, 104},
        {kVK_ForwardDelete, 111}, {kVK_F4, 62}, {kVK_End, 107}, {kVK_F2, 60}, {kVK_PageDown, 109},
        {kVK_F1, 59}, {kVK_LeftArrow, 105}, {kVK_RightArrow, 106}, {kVK_DownArrow, 108}, {kVK_UpArrow, 103},
        {0x6E /* kVK_ContextualMenu */, 127},
    };
    const auto it = m.find(k);
    return it == m.end() ? 0 : it->second;
}

Modifiers modifiers_from(NSEventModifierFlags f) {
    Modifiers m;
    m.shift = f & NSEventModifierFlagShift;
    m.control = f & NSEventModifierFlagControl;
    m.alt = f & NSEventModifierFlagOption;
    m.super = f & NSEventModifierFlagCommand;
    m.caps_lock = f & NSEventModifierFlagCapsLock;
    return m;
}

// The XKB layout that matches the Mac's current input source, as far as
// the common ones go; the guest's xkb data does the rest.
KeyboardInfo keyboard_from_input_source() {
    KeyboardInfo k;
    k.repeat_delay_ms = static_cast<std::int32_t>(std::lround([NSEvent keyRepeatDelay] * 1000.0));
    const double interval = [NSEvent keyRepeatInterval];
    k.repeat_rate = interval > 0 ? static_cast<std::int32_t>(std::lround(1.0 / interval)) : 25;
    TISInputSourceRef src = TISCopyCurrentKeyboardLayoutInputSource();
    if (!src) return k;
    NSString* sid = (__bridge NSString*)TISGetInputSourceProperty(src, kTISPropertyInputSourceID);
    NSString* name = sid ? [[sid componentsSeparatedByString:@"."] lastObject] : nil;
    CFRelease(src);
    if (!name) return k;
    static const std::map<std::string, std::pair<std::string, std::string>> table = {
        {"US", {"us", ""}}, {"ABC", {"us", ""}}, {"USExtended", {"us", "altgr-intl"}},
        {"USInternational-PC", {"us", "intl"}}, {"British", {"gb", "mac"}}, {"British-PC", {"gb", ""}},
        {"German", {"de", "mac"}}, {"French", {"fr", "mac"}}, {"French-PC", {"fr", ""}},
        {"Spanish", {"es", "mac"}}, {"Spanish-ISO", {"es", "mac"}}, {"Italian", {"it", "mac"}},
        {"Swedish-Pro", {"se", "mac"}}, {"Swedish", {"se", "mac"}}, {"Norwegian", {"no", "mac"}},
        {"Danish", {"dk", "mac"}}, {"Finnish", {"fi", "mac"}}, {"Dutch", {"nl", "mac"}},
        {"Portuguese", {"pt", "mac"}}, {"Brazilian", {"br", ""}}, {"SwissGerman", {"ch", "de_mac"}},
        {"SwissFrench", {"ch", "fr_mac"}}, {"Dvorak", {"us", "dvorak"}}, {"Colemak", {"us", "colemak"}},
        {"Russian", {"ru", "mac"}}, {"Polish", {"pl", ""}}, {"Czech", {"cz", ""}}, {"Turkish", {"tr", ""}},
        {"Canadian", {"ca", ""}}, {"Australian", {"us", ""}}, {"Irish", {"ie", ""}}, {"Belgian", {"be", ""}},
        {"Japanese", {"jp", ""}}, {"Korean", {"kr", ""}},
    };
    if (const auto it = table.find(name.UTF8String); it != table.end()) {
        k.layout = it->second.first;
        k.variant = it->second.second;
    }
    return k;
}

std::uint32_t now_ms() {
    return static_cast<std::uint32_t>(std::lround([[NSProcessInfo processInfo] systemUptime] * 1000.0));
}
std::uint32_t event_ms(NSEvent* e) { return static_cast<std::uint32_t>(std::lround(e.timestamp * 1000.0)); }

// -- pixels -> CGImage ------------------------------------------------------------------

CGImageRef image_from(const PixelsRef& px) {
    if (!px || px->width <= 0 || px->height <= 0) return nullptr;
    // The provider keeps the immutable pixel block alive: no copy.
    auto* hold = new PixelsRef(px);
    CGDataProviderRef prov = CGDataProviderCreateWithData(
        hold, px->data.data(), px->data.size(),
        [](void* info, const void*, size_t) { delete static_cast<PixelsRef*>(info); });
    CGBitmapInfo info;
    switch (px->format) {
        case PixelFormat::argb8888: info = kCGBitmapByteOrder32Little | kCGImageAlphaPremultipliedFirst; break;
        case PixelFormat::xrgb8888: info = kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst; break;
        case PixelFormat::abgr8888: info = kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast; break;
        default: info = kCGBitmapByteOrder32Big | kCGImageAlphaNoneSkipLast; break;
    }
    static CGColorSpaceRef srgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGImageRef img = CGImageCreate(static_cast<size_t>(px->width), static_cast<size_t>(px->height), 8, 32,
                                   static_cast<size_t>(px->stride), srgb, info, prov, nullptr, false,
                                   kCGRenderingIntentDefault);
    CGDataProviderRelease(prov);
    return img;
}

class CocoaHost;
class CocoaWindow;

}  // namespace

// -- the view: layers out, input in -------------------------------------------------------

@interface LXView : NSView
@property(nonatomic, assign) CocoaWindow* owner;
@end

@interface LXWindow : NSWindow
@property(nonatomic, assign) BOOL lxCanKey;
@end

@implementation LXWindow
- (BOOL)canBecomeKeyWindow { return self.lxCanKey; }
- (BOOL)canBecomeMainWindow { return self.lxCanKey; }
@end

@interface LXWindowDelegate : NSObject <NSWindowDelegate>
@property(nonatomic, assign) CocoaWindow* owner;
@end

namespace {

class CocoaWindow final : public HostWindow {
public:
    CocoaWindow(CocoaHost& host, const WindowSpec& spec, WindowSink& sink);
    ~CocoaWindow() override;

    void present(const Scene& s) override;
    void set_title(std::string_view t) override { win_.title = [NSString stringWithUTF8String:std::string{t}.c_str()] ?: @""; }
    void set_decorations(Decorations d) override;
    void set_size_limits(ld::Size min, ld::Size max) override;
    void set_maximized(bool on) override;
    void set_fullscreen(bool on) override;
    void minimize() override { [win_ miniaturize:nil]; }
    void begin_move() override;
    void begin_resize(std::uint32_t edges) override;
    void move_popup(ld::Point at) override;
    void activate() override { [win_ makeKeyAndOrderFront:nil]; }
    [[nodiscard]] ld::Rect work_area() const override;

    // from AppKit
    void did_resize();
    void did_change_screen();
    void did_focus(bool f) { if (sink_) sink_->host_focus(f); }
    void wants_close() { if (sink_) sink_->host_close(); }
    void fullscreen_changed(bool on) { fullscreen_ = on; send_configure(); }
    void mouse(NSEvent* e, bool down_or_up, bool pressed);
    [[nodiscard]] bool resize_drag(NSEvent* e);     // true: consumed by a client-side resize
    void scroll(NSEvent* e);
    void key(NSEvent* e, bool pressed);
    void flags(NSEvent* e);
    void mouse_exited();
    [[nodiscard]] bool is_popup() const noexcept { return kind_ == WindowSpec::Kind::popup; }
    [[nodiscard]] NSWindow* ns() const noexcept { return win_; }
    [[nodiscard]] CocoaHost& host() const noexcept { return *host_; }

private:
    void send_configure();
    void apply_style();
    [[nodiscard]] NSPoint view_point(NSEvent* e) const;
    [[nodiscard]] NSRect content_rect_for(ld::Rect view) const;

    CocoaHost* host_;
    WindowSink* sink_;
    WindowSpec::Kind kind_;
    Decorations decorations_;
    LXWindow* win_;
    LXView* view_;
    LXWindowDelegate* delegate_;
    CocoaWindow* parent_{nullptr};
    struct LayerSlot { CALayer* layer; const Pixels* shown; };
    std::map<std::uint64_t, LayerSlot> layers_;
    Scene scene_;
    bool shown_{false};
    bool fullscreen_{false};
    bool live_resize_{false};
    bool programmatic_resize_{false};
    ld::Size last_configured_;
    NSPoint popup_at_{0, 0};
    ld::Point popup_offset_;
    std::uint32_t buttons_{0};
    NSEvent* last_down_{nil};          // the press a client's move request refers to
    // a client-side resize in progress (xdg_toplevel.resize)
    std::uint32_t resize_edges_{0};
    NSRect resize_start_{};
    NSPoint resize_origin_{};
};

class CocoaClipboard final : public HostClipboard {
public:
    std::optional<std::string> text() override {
        NSString* s = [[NSPasteboard generalPasteboard] stringForType:NSPasteboardTypeString];
        if (!s) return std::nullopt;
        return std::string{s.UTF8String};
    }
    void set_text(std::string t) override {
        NSPasteboard* pb = [NSPasteboard generalPasteboard];
        [pb clearContents];
        [pb setString:[NSString stringWithUTF8String:t.c_str()] ?: @"" forType:NSPasteboardTypeString];
    }
    std::uint64_t generation() override {
        return static_cast<std::uint64_t>([[NSPasteboard generalPasteboard] changeCount]);
    }
};

class CocoaHost final : public Host {
public:
    CocoaHost();
    EventLoop& loop() override { return loop_; }
    void attach(HostSink& s) override { sink_ = &s; }
    std::vector<OutputInfo> outputs() override;
    KeyboardInfo keyboard() override { return keyboard_from_input_source(); }
    std::unique_ptr<HostWindow> create_window(const WindowSpec& spec, WindowSink& sink) override {
        return std::make_unique<CocoaWindow>(*this, spec, sink);
    }
    void set_cursor(const CursorImage& c) override;
    void reset_cursor() override {
        cursor_ = [NSCursor arrowCursor];
        hidden_ = false;
        apply_cursor();
    }
    HostClipboard* clipboard() override { return &clip_; }
    void set_has_windows(bool any) override;

    [[nodiscard]] HostSink* sink() const noexcept { return sink_; }
    void apply_cursor();
    [[nodiscard]] NSCursor* cursor() const noexcept { return cursor_; }
    [[nodiscard]] bool cursor_hidden() const noexcept { return hidden_; }
    [[nodiscard]] static std::size_t screen_index(NSScreen* s);
    // window -> CocoaWindow, for key events AppKit routes to the app
    std::map<void*, CocoaWindow*> windows;

private:
    GcdLoop loop_;
    HostSink* sink_{nullptr};
    CocoaClipboard clip_;
    NSCursor* cursor_{[NSCursor arrowCursor]};
    bool hidden_{false};
    bool cursor_hidden_by_us_{false};
};

// -- CocoaWindow --------------------------------------------------------------------------

CocoaWindow::CocoaWindow(CocoaHost& host, const WindowSpec& spec, WindowSink& sink)
    : host_(&host), sink_(&sink), kind_(spec.kind), decorations_(spec.decorations) {
    NSRect frame = NSMakeRect(0, 0, 320, 240);
    win_ = [[LXWindow alloc] initWithContentRect:frame styleMask:NSWindowStyleMaskBorderless
                                         backing:NSBackingStoreBuffered defer:NO];
    win_.releasedWhenClosed = NO;
    win_.lxCanKey = kind_ == WindowSpec::Kind::toplevel;
    win_.acceptsMouseMovedEvents = YES;
    win_.opaque = NO;
    win_.backgroundColor = NSColor.clearColor;
    win_.hasShadow = YES;
    view_ = [[LXView alloc] initWithFrame:frame];
    view_.owner = this;
    view_.wantsLayer = YES;
    view_.layer = [CALayer layer];
    view_.layer.geometryFlipped = YES;          // y down, as Wayland
    view_.layerContentsRedrawPolicy = NSViewLayerContentsRedrawNever;
    win_.contentView = view_;
    delegate_ = [LXWindowDelegate new];
    delegate_.owner = this;
    win_.delegate = delegate_;
    if (kind_ == WindowSpec::Kind::toplevel) {
        win_.title = [NSString stringWithUTF8String:spec.title.c_str()] ?: @"";
        win_.collectionBehavior = NSWindowCollectionBehaviorFullScreenPrimary | NSWindowCollectionBehaviorManaged;
        win_.tabbingMode = NSWindowTabbingModeDisallowed;
        set_size_limits(spec.min, spec.max);
    } else {
        win_.level = NSPopUpMenuWindowLevel;
        win_.hasShadow = NO;   // toolkits draw menu shadows themselves
        for (auto& [k, w] : host.windows)
            if (static_cast<HostWindow*>(w) == spec.parent) parent_ = w;
        popup_offset_ = spec.at;
    }
    apply_style();
    host.windows[(__bridge void*)win_] = this;
}

CocoaWindow::~CocoaWindow() {
    host_->windows.erase((__bridge void*)win_);
    sink_ = nullptr;
    view_.owner = nullptr;
    delegate_.owner = nullptr;
    win_.delegate = nil;
    if (parent_ && parent_->ns() && win_.parentWindow) [parent_->ns() removeChildWindow:win_];
    // a child popup of ours must not outlive its anchor visually
    for (NSWindow* c in [win_.childWindows copy]) [win_ removeChildWindow:c];
    [win_ orderOut:nil];
    [win_ close];
}

void CocoaWindow::apply_style() {
    if (kind_ == WindowSpec::Kind::popup) return;
    NSWindowStyleMask m = NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable;
    if (decorations_ == Decorations::server) m |= NSWindowStyleMaskTitled | NSWindowStyleMaskClosable;
    else m |= NSWindowStyleMaskBorderless;
    if (fullscreen_) m |= NSWindowStyleMaskFullScreen;
    const NSRect content = [win_ contentRectForFrameRect:win_.frame];
    win_.styleMask = m;
    // keep the content where it was across the change of frame
    [win_ setFrame:[win_ frameRectForContentRect:content] display:NO];
    // A client-decorated window (GTK's headerbar) draws its own shadow
    // into its surface; a native one under it would double it.
    win_.hasShadow = decorations_ == Decorations::server;
}

void CocoaWindow::set_decorations(Decorations d) {
    if (d == decorations_) return;
    decorations_ = d;
    apply_style();
}

void CocoaWindow::set_size_limits(ld::Size min, ld::Size max) {
    win_.contentMinSize = NSMakeSize(std::max(1, min.w), std::max(1, min.h));
    win_.contentMaxSize = NSMakeSize(max.w > 0 ? max.w : FLT_MAX, max.h > 0 ? max.h : FLT_MAX);
}

NSRect CocoaWindow::content_rect_for(ld::Rect view) const {
    // keep the top-left corner where it is (AppKit's origin is bottom-left)
    const NSRect cur = [win_ contentRectForFrameRect:win_.frame];
    const CGFloat top = NSMaxY(cur);
    return NSMakeRect(cur.origin.x, top - view.h, view.w, view.h);
}

void CocoaWindow::present(const Scene& s) {
    const ld::Rect old_view = scene_.view;
    scene_ = s;
    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    // layers: one per surface, back to front, reused by surface id
    std::map<std::uint64_t, LayerSlot> next;
    CALayer* root = view_.layer;
    unsigned idx = 0;
    for (const auto& l : s.layers) {
        LayerSlot slot{nil, nullptr};
        if (auto it = layers_.find(l.id); it != layers_.end()) {
            slot = it->second;
            layers_.erase(it);
        } else {
            slot.layer = [CALayer layer];
            slot.layer.anchorPoint = CGPointZero;
            slot.layer.magnificationFilter = kCAFilterNearest;
            slot.layer.contentsGravity = kCAGravityTopLeft;
        }
        CALayer* layer = slot.layer;
        layer.frame = CGRectMake(l.rect.x - s.view.x, l.rect.y - s.view.y, l.rect.w, l.rect.h);
        layer.contentsScale = l.scale;
        // unchanged content keeps its image (the same immutable block)
        if (slot.shown != l.pixels.get()) {
            layer.contents = (__bridge_transfer id)image_from(l.pixels);
            slot.shown = l.pixels.get();
        }
        if (layer.superlayer != root || root.sublayers.count <= idx || root.sublayers[idx] != layer)
            [root insertSublayer:layer atIndex:idx];
        next[l.id] = slot;
        ++idx;
    }
    for (auto& [id, slot] : layers_) [slot.layer removeFromSuperlayer];
    layers_ = std::move(next);
    [CATransaction commit];

    // size and place the window after its content
    if (kind_ == WindowSpec::Kind::popup) {
        if (!shown_ || old_view.size() != s.view.size()) move_popup(popup_offset_);
    } else if (!fullscreen_ && !(win_.styleMask & NSWindowStyleMaskFullScreen) && !win_.zoomed && !live_resize_) {
        const NSRect cur = [win_ contentRectForFrameRect:win_.frame];
        if (std::lround(cur.size.width) != s.view.w || std::lround(cur.size.height) != s.view.h || !shown_) {
            NSRect r = content_rect_for(s.view);
            if (!shown_) {
                // new windows: centred, cascading a little per window
                NSScreen* scr = NSScreen.mainScreen;
                const NSRect vf = scr.visibleFrame;
                static int cascade = 0;
                const CGFloat off = 24 * (cascade++ % 8);
                r.origin.x = NSMidX(vf) - r.size.width / 2 + off;
                r.origin.y = NSMidY(vf) - r.size.height / 2 - off;
            }
            programmatic_resize_ = true;
            [win_ setFrame:[win_ frameRectForContentRect:r] display:YES];
            programmatic_resize_ = false;
        }
    }
    if (!shown_) {
        shown_ = true;
        if (kind_ == WindowSpec::Kind::popup) {
            if (parent_) [parent_->ns() addChildWindow:win_ ordered:NSWindowAbove];
            [win_ orderFront:nil];
        } else {
            [NSApp activateIgnoringOtherApps:YES];
            [win_ makeKeyAndOrderFront:nil];
            did_change_screen();
        }
    }
}

void CocoaWindow::move_popup(ld::Point at) {
    popup_offset_ = at;
    if (!parent_) return;
    // parent view origin in screen coordinates (top-left), then down by `at`
    NSWindow* pw = parent_->ns();
    const NSRect pc = [pw contentRectForFrameRect:pw.frame];
    const CGFloat left = pc.origin.x + at.x;
    const CGFloat top = NSMaxY(pc) - at.y;
    const NSRect r = NSMakeRect(left, top - scene_.view.h, std::max(1, scene_.view.w), std::max(1, scene_.view.h));
    [win_ setFrame:r display:YES];
}

ld::Rect CocoaWindow::work_area() const {
    NSScreen* scr = win_.screen ?: (parent_ ? parent_->ns().screen : nil) ?: NSScreen.mainScreen;
    const NSRect vf = scr.visibleFrame;
    // relative to our view's top-left; for a popup, the parent's
    NSWindow* ref = parent_ ? parent_->ns() : win_;
    const NSRect c = [ref contentRectForFrameRect:ref.frame];
    const CGFloat top = NSMaxY(c);
    return ld::Rect{static_cast<std::int32_t>(std::lround(vf.origin.x - c.origin.x)),
                static_cast<std::int32_t>(std::lround(top - NSMaxY(vf))),
                static_cast<std::int32_t>(std::lround(vf.size.width)),
                static_cast<std::int32_t>(std::lround(vf.size.height))};
}

void CocoaWindow::send_configure() {
    if (!sink_ || kind_ != WindowSpec::Kind::toplevel) return;
    const NSRect c = [win_ contentRectForFrameRect:win_.frame];
    WindowStates st;
    st.activated = win_.keyWindow;
    st.maximized = win_.zoomed && !fullscreen_;
    st.fullscreen = fullscreen_;
    st.resizing = live_resize_;
    ld::Size want{static_cast<std::int32_t>(std::lround(c.size.width)), static_cast<std::int32_t>(std::lround(c.size.height))};
    // the content shows the view; ask for the window geometry that fills it
    const ld::Rect g = scene_.geometry, v = scene_.view;
    want.w -= v.w - g.w;
    want.h -= v.h - g.h;
    last_configured_ = want;
    sink_->host_configure(want, st);
}

void CocoaWindow::did_resize() {
    if (programmatic_resize_) return;
    live_resize_ = view_.inLiveResize;
    send_configure();
}

void CocoaWindow::did_change_screen() {
    if (sink_) sink_->host_output(CocoaHost::screen_index(win_.screen));
}

void CocoaWindow::set_maximized(bool on) {
    if (static_cast<bool>(win_.zoomed) != on) [win_ zoom:nil];
    send_configure();
}

void CocoaWindow::set_fullscreen(bool on) {
    if (fullscreen_ != on) [win_ toggleFullScreen:nil];
}

void CocoaWindow::begin_move() {
    // the window server drags it from here; only while the button is down
    if (last_down_ && ([NSEvent pressedMouseButtons] & 1)) [win_ performWindowDragWithEvent:last_down_];
}

// A client-side resize: AppKit has no public "resize from this edge" call,
// so the following drags resize the window (resize_drag). Event-driven, not
// a nested tracking loop: client frames must keep flowing while it runs.
void CocoaWindow::begin_resize(std::uint32_t edges) {
    if (!([NSEvent pressedMouseButtons] & 1)) return;
    resize_edges_ = edges;
    resize_start_ = win_.frame;
    resize_origin_ = NSEvent.mouseLocation;
    live_resize_ = true;
    send_configure();
}

bool CocoaWindow::resize_drag(NSEvent* e) {
    if (!resize_edges_) return false;
    if (e.type == NSEventTypeLeftMouseUp) {
        resize_edges_ = 0;
        live_resize_ = false;
        send_configure();
        buttons_ &= ~1u;
        if (sink_) sink_->host_pointer_button(PointerButton::left, false, event_ms(e));
        return true;
    }
    const NSSize mn = win_.minSize, mx = win_.maxSize;
    const NSPoint p = NSEvent.mouseLocation;
    const CGFloat dx = p.x - resize_origin_.x, dy = p.y - resize_origin_.y;
    const NSRect start = resize_start_;
    NSRect r = start;
    if (resize_edges_ & edge::right) r.size.width = start.size.width + dx;
    if (resize_edges_ & edge::left) r.size.width = start.size.width - dx;
    if (resize_edges_ & edge::bottom) r.size.height = start.size.height - dy;
    if (resize_edges_ & edge::top) r.size.height = start.size.height + dy;
    r.size.width = std::clamp(r.size.width, mn.width, mx.width);
    r.size.height = std::clamp(r.size.height, mn.height, mx.height);
    if (resize_edges_ & edge::left) r.origin.x = NSMaxX(start) - r.size.width;
    if (resize_edges_ & edge::bottom) r.origin.y = NSMaxY(start) - r.size.height;
    programmatic_resize_ = true;
    [win_ setFrame:r display:NO];
    programmatic_resize_ = false;
    send_configure();
    return true;
}

NSPoint CocoaWindow::view_point(NSEvent* e) const {
    NSPoint p = [view_ convertPoint:e.locationInWindow fromView:nil];
    return NSMakePoint(p.x, view_.bounds.size.height - p.y);   // y down
}

void CocoaWindow::mouse(NSEvent* e, bool is_button, bool pressed) {
    if (!sink_) return;
    if (resize_drag(e)) return;
    const NSPoint p = view_point(e);
    sink_->host_pointer_motion(p.x, p.y, event_ms(e));
    if (!is_button) return;
    if (pressed && e.buttonNumber == 0) last_down_ = e;
    PointerButton b = PointerButton::left;
    switch (e.buttonNumber) {
        case 0: b = PointerButton::left; break;
        case 1: b = PointerButton::right; break;
        case 2: b = PointerButton::middle; break;
        case 3: b = PointerButton::side; break;
        default: b = PointerButton::extra; break;
    }
    // Ctrl-click is a right click on a Mac
    if (b == PointerButton::left && pressed && (e.modifierFlags & NSEventModifierFlagControl) &&
        !(e.modifierFlags & NSEventModifierFlagCommand))
        b = PointerButton::right;
    const std::uint32_t bit = 1u << (static_cast<std::uint32_t>(b) - 0x110);
    if (pressed) buttons_ |= bit;
    else if (!(buttons_ & bit)) return;
    else buttons_ &= ~bit;
    sink_->host_pointer_button(b, pressed, event_ms(e));
}

void CocoaWindow::mouse_exited() {
    if (sink_ && !buttons_) sink_->host_pointer_leave();
}

void CocoaWindow::scroll(NSEvent* e) {
    if (!sink_) return;
    ScrollEvent s;
    const bool precise = e.hasPreciseScrollingDeltas;
    // AppKit's deltas are "natural" already when the user chose so; Wayland
    // wants positive = down/right content motion of the view, i.e. the
    // opposite sign of AppKit's.
    if (precise) {
        s.source = AxisSource::finger;
        s.dx = -e.scrollingDeltaX;
        s.dy = -e.scrollingDeltaY;
        s.stop = e.phase == NSEventPhaseEnded || e.phase == NSEventPhaseCancelled;
        if (e.momentumPhase != NSEventPhaseNone) s.source = AxisSource::continuous;
        if (s.dx == 0 && s.dy == 0 && !s.stop) return;
    } else {
        s.source = AxisSource::wheel;
        s.steps_x = static_cast<std::int32_t>(std::lround(-e.scrollingDeltaX * 120));
        s.steps_y = static_cast<std::int32_t>(std::lround(-e.scrollingDeltaY * 120));
        s.dx = -e.scrollingDeltaX * 15;
        s.dy = -e.scrollingDeltaY * 15;
        if (s.steps_x == 0 && s.steps_y == 0) return;
    }
    sink_->host_scroll(s, event_ms(e));
}

void CocoaWindow::key(NSEvent* e, bool pressed) {
    HostSink* hs = host_->sink();
    if (!hs) return;
    if (pressed && e.ARepeat) return;   // the client repeats (wl_keyboard.repeat_info)
    const std::uint32_t code = evdev_from_mac(e.keyCode);
    if (!code) return;
    hs->host_modifiers(modifiers_from(e.modifierFlags));
    hs->host_key(code, pressed, event_ms(e));
}

void CocoaWindow::flags(NSEvent* e) {
    HostSink* hs = host_->sink();
    if (!hs) return;
    // modifier keys arrive as flag changes; tell the client which key moved
    const std::uint32_t code = evdev_from_mac(e.keyCode);
    NSEventModifierFlags f = e.modifierFlags;
    bool down = false;
    switch (e.keyCode) {
        case kVK_Shift: case kVK_RightShift: down = f & NSEventModifierFlagShift; break;
        case kVK_Control: case kVK_RightControl: down = f & NSEventModifierFlagControl; break;
        case kVK_Option: case kVK_RightOption: down = f & NSEventModifierFlagOption; break;
        case kVK_Command: case kVK_RightCommand: down = f & NSEventModifierFlagCommand; break;
        case kVK_CapsLock:
            hs->host_key(code, true, event_ms(e));
            hs->host_key(code, false, event_ms(e));
            hs->host_modifiers(modifiers_from(f));
            return;
        default: hs->host_modifiers(modifiers_from(f)); return;
    }
    // device-dependent bits say whether THIS side is still held
    if (code) hs->host_key(code, down, event_ms(e));
    hs->host_modifiers(modifiers_from(f));
}

// -- CocoaHost ---------------------------------------------------------------------------

CocoaHost::CocoaHost() {
    [NSApplication sharedApplication];
    NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
    // A minimal menu so Cmd-Q and the app menu behave.
    NSMenu* bar = [NSMenu new];
    NSMenuItem* app = [NSMenuItem new];
    [bar addItem:app];
    NSMenu* am = [NSMenu new];
    [am addItemWithTitle:@"Hide Linux Windows" action:@selector(hide:) keyEquivalent:@"h"];
    [am addItem:[NSMenuItem separatorItem]];
    [am addItemWithTitle:@"Close Linux Windows and Quit" action:@selector(terminate:) keyEquivalent:@""];
    app.submenu = am;
    NSApp.mainMenu = bar;
    [NSApp finishLaunching];
}

std::size_t CocoaHost::screen_index(NSScreen* s) {
    NSArray<NSScreen*>* all = NSScreen.screens;
    const NSUInteger i = s ? [all indexOfObject:s] : 0;
    return i == NSNotFound ? 0 : i;
}

std::vector<OutputInfo> CocoaHost::outputs() {
    std::vector<OutputInfo> out;
    NSArray<NSScreen*>* all = NSScreen.screens;
    if (all.count == 0) return out;
    const CGFloat primary_top = NSMaxY(all[0].frame);
    for (NSScreen* s in all) {
        OutputInfo o;
        const NSRect f = s.frame;
        o.logical = {static_cast<std::int32_t>(f.origin.x), static_cast<std::int32_t>(primary_top - NSMaxY(f)),
                     static_cast<std::int32_t>(f.size.width), static_cast<std::int32_t>(f.size.height)};
        o.scale = std::max<std::int32_t>(1, static_cast<std::int32_t>(std::lround(s.backingScaleFactor)));
        o.pixels = {o.logical.w * o.scale, o.logical.h * o.scale};
        NSNumber* num = s.deviceDescription[@"NSScreenNumber"];
        const CGDirectDisplayID did = num.unsignedIntValue;
        const CGSize mm = CGDisplayScreenSize(did);
        o.physical_mm = {static_cast<std::int32_t>(mm.width), static_cast<std::int32_t>(mm.height)};
        o.make = CGDisplayIsBuiltin(did) ? "Apple" : "Unknown";
        o.model = s.localizedName.UTF8String;
        o.name = (CGDisplayIsBuiltin(did) ? "eDP-" : "DP-") + std::to_string(out.size() + 1);
        o.description = o.model;
        const double hz = s.maximumFramesPerSecond;
        o.refresh_mhz = static_cast<std::int32_t>((hz > 0 ? hz : 60) * 1000);
        out.push_back(o);
    }
    return out;
}

void CocoaHost::set_cursor(const CursorImage& c) {
    if (!c.pixels) {
        hidden_ = true;
        apply_cursor();
        return;
    }
    CGImageRef img = image_from(c.pixels);
    if (!img) return;
    const NSSize size = NSMakeSize(c.pixels->width / static_cast<CGFloat>(c.scale), c.pixels->height / static_cast<CGFloat>(c.scale));
    NSImage* ni = [[NSImage alloc] initWithCGImage:img size:size];
    CGImageRelease(img);
    cursor_ = [[NSCursor alloc] initWithImage:ni hotSpot:NSMakePoint(c.hotspot.x, c.hotspot.y)];
    hidden_ = false;
    apply_cursor();
}

void CocoaHost::apply_cursor() {
    if (hidden_ && !cursor_hidden_by_us_) { [NSCursor hide]; cursor_hidden_by_us_ = true; }
    if (!hidden_ && cursor_hidden_by_us_) { [NSCursor unhide]; cursor_hidden_by_us_ = false; }
    if (!hidden_) [cursor_ set];
    for (auto& [k, w] : windows) [w->ns() invalidateCursorRectsForView:w->ns().contentView];
}

void CocoaHost::set_has_windows(bool any) {
    NSApp.activationPolicy = any ? NSApplicationActivationPolicyRegular : NSApplicationActivationPolicyAccessory;
    if (any) [NSApp activateIgnoringOtherApps:YES];
}

}  // namespace

// -- Objective-C glue ------------------------------------------------------------------------

@implementation LXView {
    NSTrackingArea* _tracking;
}
- (BOOL)acceptsFirstResponder { return YES; }
- (BOOL)acceptsFirstMouse:(NSEvent*)e { return YES; }
- (BOOL)isFlipped { return YES; }
- (BOOL)wantsUpdateLayer { return YES; }
- (void)updateTrackingAreas {
    if (_tracking) [self removeTrackingArea:_tracking];
    _tracking = [[NSTrackingArea alloc] initWithRect:self.bounds
                                            options:NSTrackingMouseEnteredAndExited | NSTrackingMouseMoved |
                                                    NSTrackingActiveAlways | NSTrackingInVisibleRect | NSTrackingCursorUpdate
                                              owner:self userInfo:nil];
    [self addTrackingArea:_tracking];
    [super updateTrackingAreas];
}
- (void)cursorUpdate:(NSEvent*)e {
    if (self.owner && !self.owner->host().cursor_hidden()) [self.owner->host().cursor() set];
}
- (void)resetCursorRects {
    if (self.owner && !self.owner->host().cursor_hidden()) [self addCursorRect:self.bounds cursor:self.owner->host().cursor()];
}
- (void)mouseMoved:(NSEvent*)e { if (self.owner) self.owner->mouse(e, false, false); }
- (void)mouseDragged:(NSEvent*)e { if (self.owner) self.owner->mouse(e, false, false); }
- (void)rightMouseDragged:(NSEvent*)e { if (self.owner) self.owner->mouse(e, false, false); }
- (void)otherMouseDragged:(NSEvent*)e { if (self.owner) self.owner->mouse(e, false, false); }
- (void)mouseEntered:(NSEvent*)e { if (self.owner) self.owner->mouse(e, false, false); }
- (void)mouseExited:(NSEvent*)e { if (self.owner) self.owner->mouse_exited(); }
- (void)mouseDown:(NSEvent*)e { if (self.owner) self.owner->mouse(e, true, true); }
- (void)mouseUp:(NSEvent*)e { if (self.owner) self.owner->mouse(e, true, false); }
- (void)rightMouseDown:(NSEvent*)e { if (self.owner) self.owner->mouse(e, true, true); }
- (void)rightMouseUp:(NSEvent*)e { if (self.owner) self.owner->mouse(e, true, false); }
- (void)otherMouseDown:(NSEvent*)e { if (self.owner) self.owner->mouse(e, true, true); }
- (void)otherMouseUp:(NSEvent*)e { if (self.owner) self.owner->mouse(e, true, false); }
- (void)scrollWheel:(NSEvent*)e { if (self.owner) self.owner->scroll(e); }
- (void)keyDown:(NSEvent*)e { if (self.owner) self.owner->key(e, true); }
- (void)keyUp:(NSEvent*)e { if (self.owner) self.owner->key(e, false); }
- (void)flagsChanged:(NSEvent*)e { if (self.owner) self.owner->flags(e); }
// Cmd-key combos come here first: they're the app's, not AppKit's menus
- (BOOL)performKeyEquivalent:(NSEvent*)e {
    if (!self.owner || self.window.firstResponder != self) return NO;
    if (e.type == NSEventTypeKeyDown) {
        // Cmd-H stays the Mac's; everything else is the app's (with
        // Command as Control, Cmd-Q is Ctrl-Q: the app's own Quit)
        NSString* c = e.charactersIgnoringModifiers;
        const NSEventModifierFlags m = e.modifierFlags & NSEventModifierFlagDeviceIndependentFlagsMask;
        if (m == NSEventModifierFlagCommand && [c isEqualToString:@"h"]) return NO;
        self.owner->key(e, true);
        return YES;
    }
    return NO;
}
@end

@implementation LXWindowDelegate
- (void)windowDidResize:(NSNotification*)n { if (self.owner) self.owner->did_resize(); }
- (void)windowDidEndLiveResize:(NSNotification*)n { if (self.owner) self.owner->did_resize(); }
- (void)windowDidBecomeKey:(NSNotification*)n { if (self.owner) self.owner->did_focus(true); }
- (void)windowDidResignKey:(NSNotification*)n { if (self.owner) self.owner->did_focus(false); }
- (void)windowDidChangeScreen:(NSNotification*)n { if (self.owner) self.owner->did_change_screen(); }
- (void)windowDidEnterFullScreen:(NSNotification*)n { if (self.owner) self.owner->fullscreen_changed(true); }
- (void)windowDidExitFullScreen:(NSNotification*)n { if (self.owner) self.owner->fullscreen_changed(false); }
- (BOOL)windowShouldClose:(NSWindow*)w {
    if (self.owner) self.owner->wants_close();
    return NO;   // the client decides; it destroys the toplevel if it agrees
}
@end

@interface LXAppDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, assign) CocoaHost* host;
@end

@implementation LXAppDelegate
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)app {
    // The menu's Quit, or logout/shutdown: ask every Linux window to close
    // (apps may save), give the requests a moment to go out, then go.
    // Never refuse: a compositor that cancels termination blocks logout.
    if (self.host && self.host->sink()) self.host->sink()->host_quit();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        [NSApp replyToApplicationShouldTerminate:YES];
    });
    return NSTerminateLater;
}
- (void)applicationDidBecomeActive:(NSNotification*)n {
    if (self.host && self.host->sink()) self.host->sink()->host_app_active(true);
}
- (void)applicationDidResignActive:(NSNotification*)n {
    if (self.host && self.host->sink()) self.host->sink()->host_app_active(false);
}
- (void)applicationDidChangeScreenParameters:(NSNotification*)n {
    if (self.host && self.host->sink()) self.host->sink()->host_outputs_changed();
}
- (void)inputSourceChanged:(NSNotification*)n {
    if (self.host && self.host->sink()) self.host->sink()->host_keyboard_changed();
}
- (BOOL)applicationShouldHandleReopen:(NSApplication*)app hasVisibleWindows:(BOOL)flag { return YES; }
@end

namespace lx::display {

std::unique_ptr<Host> make_cocoa_host();
std::unique_ptr<Host> make_cocoa_host() {
    @autoreleasepool {
        auto h = std::make_unique<CocoaHost>();
        static LXAppDelegate* delegate = [LXAppDelegate new];
        delegate.host = h.get();
        NSApp.delegate = delegate;
        [[NSDistributedNotificationCenter defaultCenter]
            addObserver:delegate selector:@selector(inputSourceChanged:)
                   name:(__bridge NSString*)kTISNotifySelectedKeyboardInputSourceChanged object:nil];
        // AppKit drops keyUp while Command is held (it never reaches a
        // view): catch it before dispatch, or the guest sees the key stuck
        // down and auto-repeats it forever.
        CocoaHost* hp = h.get();
        [NSEvent addLocalMonitorForEventsMatchingMask:NSEventMaskKeyUp handler:^NSEvent*(NSEvent* e) {
            if (!(e.modifierFlags & NSEventModifierFlagCommand)) return e;
            if (auto it = hp->windows.find((__bridge void*)e.window); it != hp->windows.end()) {
                it->second->key(e, false);
                return nil;
            }
            return e;
        }];
        return h;
    }
}

}  // namespace lx::display
