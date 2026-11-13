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
#import <IOSurface/IOSurface.h>

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

std::uint32_t event_ms(NSEvent* e) { return static_cast<std::uint32_t>(std::lround(e.timestamp * 1000.0)); }

// -- pixels -> GPU ----------------------------------------------------------------------
//
// Each surface's layer shows an IOSurface: memory the window server
// composites from directly, no CGImage in between. The core's Pixels are
// only stable during present() (host.hpp), and Core Animation may still be
// reading the surface it showed last frame -- so each layer keeps a small
// pool. Every buffer remembers what it's missing (`stale`, the union of
// damage since it was last written); a frame takes a buffer the window
// server isn't using, copies just its stale rect, and shows it. A cursor
// blink in a terminal is a few hundred bytes; a resize is one full copy.

OSType fourcc_of(PixelFormat f) {
    switch (f) {
        case PixelFormat::argb8888:
        case PixelFormat::xrgb8888: return 'BGRA';   // B G R A in memory
        default: return 'RGBA';                      // R G B A in memory
    }
}

struct GpuBuffer {
    IOSurfaceRef surf{nullptr};
    ld::Rect stale;                // what it lacks, in buffer pixels
    ~GpuBuffer() { if (surf) CFRelease(surf); }
};

IOSurfaceRef make_iosurface(std::int32_t w, std::int32_t h, OSType fmt) {
    NSDictionary* props = @{
        (id)kIOSurfaceWidth: @(w), (id)kIOSurfaceHeight: @(h), (id)kIOSurfaceBytesPerElement: @4,
        (id)kIOSurfacePixelFormat: @(fmt),
    };
    return IOSurfaceCreate((__bridge CFDictionaryRef)props);
}

// Copy `r` of `px` into `s`.
void upload(IOSurfaceRef s, const Pixels& px, ld::Rect r) {
    if (r.empty()) return;
    IOSurfaceLock(s, 0, nullptr);
    auto* base = static_cast<std::byte*>(IOSurfaceGetBaseAddress(s));
    const std::size_t dst_stride = IOSurfaceGetBytesPerRow(s);
    const bool opaque = px.format == PixelFormat::xrgb8888 || px.format == PixelFormat::xbgr8888;
    for (std::int32_t y = r.y; y < r.y + r.h; ++y) {
        std::byte* d = base + static_cast<std::size_t>(y) * dst_stride + static_cast<std::size_t>(r.x) * 4;
        const std::byte* src = px.data.data() + static_cast<std::size_t>(y) * static_cast<std::size_t>(px.stride) +
                               static_cast<std::size_t>(r.x) * 4;
        std::memcpy(d, src, static_cast<std::size_t>(r.w) * 4);
        // x formats: the padding byte is garbage, the surface says alpha
        if (opaque)
            for (std::int32_t x = 0; x < r.w; ++x) d[static_cast<std::size_t>(x) * 4 + 3] = std::byte{0xff};
    }
    IOSurfaceUnlock(s, 0, nullptr);
}

// A one-off copy (cursors): an image that owns its bytes.
CGImageRef image_copy(const Pixels& px) {
    if (px.width <= 0 || px.height <= 0) return nullptr;
    NSData* bytes = [NSData dataWithBytes:px.data.data() length:px.data.size()];
    CGDataProviderRef prov = CGDataProviderCreateWithCFData((__bridge CFDataRef)bytes);
    CGBitmapInfo info;
    switch (px.format) {
        case PixelFormat::argb8888: info = kCGBitmapByteOrder32Little | (CGBitmapInfo)kCGImageAlphaPremultipliedFirst; break;
        case PixelFormat::xrgb8888: info = kCGBitmapByteOrder32Little | (CGBitmapInfo)kCGImageAlphaNoneSkipFirst; break;
        case PixelFormat::abgr8888: info = kCGBitmapByteOrder32Big | (CGBitmapInfo)kCGImageAlphaPremultipliedLast; break;
        default: info = kCGBitmapByteOrder32Big | (CGBitmapInfo)kCGImageAlphaNoneSkipLast; break;
    }
    static CGColorSpaceRef srgb = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    CGImageRef img = CGImageCreate(static_cast<size_t>(px.width), static_cast<size_t>(px.height), 8, 32,
                                   static_cast<size_t>(px.stride), srgb, info, prov, nullptr, false,
                                   kCGRenderingIntentDefault);
    CGDataProviderRelease(prov);
    return img;
}

class CocoaHost;
class CocoaWindow;

}  // namespace

// -- the view: layers out, input in -------------------------------------------------------

@interface LXView : NSView <NSTextInputClient>
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
    void request_attention() override { [NSApp requestUserAttention:NSInformationalRequest]; }
    void set_text_input(std::optional<ld::Rect> cursor) override;
    [[nodiscard]] ld::Rect work_area() const override;

    // input methods (NSTextInputClient, via LXView)
    void ime_insert(NSString* text);
    void ime_mark(NSString* text, NSRange sel);
    void ime_unmark();
    void ime_command();
    [[nodiscard]] bool ime_composing() const { return marked_.length > 0; }
    [[nodiscard]] NSUInteger ime_marked_length() const { return marked_.length; }
    [[nodiscard]] NSRect ime_rect() const;

    // from AppKit
    void did_resize();
    void did_change_screen();
    void did_focus(bool f) { if (sink_) sink_->host_focus(f); }
    void wants_close() { if (sink_) sink_->host_close(); }
    void quit_app() { if (sink_) sink_->host_close_app(); }
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
    struct LayerSlot {
        CALayer* layer{nil};
        std::uint64_t generation{~0ull};
        std::int32_t w{0}, h{0};
        OSType fmt{0};
        std::vector<std::unique_ptr<GpuBuffer>> pool;   // at most kPool
        GpuBuffer* shown{nullptr};
    };
    static constexpr std::size_t kPool = 3;
    void update_layer(LayerSlot& slot, const Layer& l);
    std::map<std::uint64_t, LayerSlot> layers_;
    Scene scene_;
    bool shown_{false};
    bool fullscreen_{false};
    bool live_resize_{false};
    bool programmatic_resize_{false};
    ld::Size last_configured_;
    ld::Point popup_offset_;
    std::uint32_t buttons_{0};
    NSEvent* last_down_{nil};          // the press a client's move request refers to
    // a client-side resize in progress (xdg_toplevel.resize)
    std::uint32_t resize_edges_{0};
    NSRect resize_start_{};
    NSPoint resize_origin_{};
    // input methods
    bool text_input_{false};
    ld::Rect text_cursor_{0, 0, 1, 1};
    NSString* marked_{@""};
    NSEvent* ime_event_{nil};
    bool ime_raw_{false}, ime_handled_{false};
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
    [[nodiscard]] bool native_frames() const override { return true; }
    void set_cursor(const CursorImage& c) override;
    void set_cursor_shape(CursorShape s) override;
    void bell() override;
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
    view_.layer.masksToBounds = YES;            // nothing outside the window geometry
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
    // Every toplevel is a real titled window: the window server then gives
    // it the system shadow, corner shape, edge resizing (with the resize
    // cursors), Sequoia tiling, Mission Control and minimize. An app that
    // draws its own title bar (GTK's headerbar) gets the same window with
    // the title bar made transparent and its buttons hidden -- its content
    // runs to the top edge and its own buttons do the job. The core shows
    // only the window geometry and says the edges are tiled, so the app
    // draws no shadow or resize margins of its own (host.hpp native_frames).
    const bool csd = decorations_ == Decorations::client;
    NSWindowStyleMask m = NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable |
                          NSWindowStyleMaskMiniaturizable;
    if (csd) m |= NSWindowStyleMaskFullSizeContentView;
    if (fullscreen_) m |= NSWindowStyleMaskFullScreen;
    const NSRect content = shown_ ? [win_ contentRectForFrameRect:win_.frame] : NSZeroRect;
    win_.styleMask = m;
    win_.titlebarAppearsTransparent = csd;
    win_.titleVisibility = csd ? NSWindowTitleHidden : NSWindowTitleVisible;
    for (NSWindowButton b : {NSWindowCloseButton, NSWindowMiniaturizeButton, NSWindowZoomButton})
        [win_ standardWindowButton:b].hidden = csd;
    win_.hasShadow = YES;
    // keep the content where it was across the change of frame
    if (shown_) {
        programmatic_resize_ = true;
        [win_ setFrame:[win_ frameRectForContentRect:content] display:NO];
        programmatic_resize_ = false;
    }
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
        LayerSlot slot;
        if (auto it = layers_.find(l.id); it != layers_.end()) {
            slot = std::move(it->second);
            layers_.erase(it);
        } else {
            slot.layer = [CALayer layer];
            slot.layer.anchorPoint = CGPointZero;
            slot.layer.contentsGravity = kCAGravityResize;   // the crop stretched over the rect
            slot.layer.magnificationFilter = kCAFilterLinear;
            slot.layer.minificationFilter = kCAFilterLinear;
        }
        CALayer* layer = slot.layer;
        layer.frame = CGRectMake(l.rect.x - s.view.x, l.rect.y - s.view.y, l.rect.w, l.rect.h);
        update_layer(slot, l);
        if (layer.superlayer != root || root.sublayers.count <= idx || root.sublayers[idx] != layer)
            [root insertSublayer:layer atIndex:idx];
        next[l.id] = std::move(slot);
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

void CocoaWindow::update_layer(LayerSlot& slot, const Layer& l) {
    const Pixels& px = *l.pixels;
    // which part of the buffer shows, as the layer's normalized crop
    const SourceRect src = l.source.whole()
        ? SourceRect{0, 0, static_cast<double>(px.width), static_cast<double>(px.height)} : l.source;
    slot.layer.contentsRect = CGRectMake(src.x / px.width, src.y / px.height, src.w / px.width, src.h / px.height);
    if (l.generation == slot.generation && slot.shown) return;   // nothing new
    slot.generation = l.generation;

    const OSType fmt = fourcc_of(px.format);
    if (px.width != slot.w || px.height != slot.h || fmt != slot.fmt) {
        slot.pool.clear();   // a new size: every buffer starts over
        slot.shown = nullptr;
        slot.w = px.width;
        slot.h = px.height;
        slot.fmt = fmt;
    }
    const ld::Rect all{0, 0, px.width, px.height};
    // the change, in buffer pixels, goes to every buffer's to-do list
    for (auto& b : slot.pool) b->stale = b->stale.united(l.damage);
    // a buffer the window server isn't reading (never the one on screen)
    GpuBuffer* pick = nullptr;
    for (auto& b : slot.pool)
        if (b.get() != slot.shown && !IOSurfaceIsInUse(b->surf)) { pick = b.get(); break; }
    if (!pick && slot.pool.size() < kPool) {
        auto b = std::make_unique<GpuBuffer>();
        b->surf = make_iosurface(px.width, px.height, fmt);
        b->stale = all;
        if (!b->surf) return;
        pick = b.get();
        slot.pool.push_back(std::move(b));
    }
    if (!pick) {
        // all busy (a stalled compositor): reuse the oldest rather than drop
        for (auto& b : slot.pool)
            if (b.get() != slot.shown) { pick = b.get(); break; }
        if (!pick) pick = slot.pool.front().get();
    }
    // clip and copy what this buffer lacks
    ld::Rect r = pick->stale;
    const auto x0 = std::max(0, r.x), y0 = std::max(0, r.y);
    const auto x1 = std::min(all.w, r.x + r.w), y1 = std::min(all.h, r.y + r.h);
    if (x1 > x0 && y1 > y0) upload(pick->surf, px, {x0, y0, x1 - x0, y1 - y0});
    pick->stale = {};
    slot.shown = pick;
    slot.layer.contents = (__bridge id)pick->surf;
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
    if (!sink_ || kind_ != WindowSpec::Kind::toplevel || !shown_) return;
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
    // Dragging an edge: let the app draw the new size before AppKit shows
    // the frame (a frame's budget), so content and frame move together.
    if (live_resize_ || resize_edges_) sink_->host_configure_and_wait(want, st, std::chrono::milliseconds(24));
    else sink_->host_configure(want, st);
}

void CocoaWindow::did_resize() {
    // Before the first frame the window has no size of its own: the style
    // change in the constructor resizes it (320x240 default) and AppKit
    // says so -- passing that on told apps to shrink to it.
    if (programmatic_resize_ || !shown_) return;
    live_resize_ = view_.inLiveResize;
    send_configure();
    [win_ invalidateShadow];
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

// LXView is flipped (isFlipped), so its own coordinates are already y-down
// from the top-left, as Wayland's are. Flipping again here put every click
// at the mirror-image height.
NSPoint CocoaWindow::view_point(NSEvent* e) const {
    return [view_ convertPoint:e.locationInWindow fromView:nil];
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
    const std::uint32_t code = evdev_from_mac(e.keyCode);
    const NSEventModifierFlags mods = e.modifierFlags & (NSEventModifierFlagCommand | NSEventModifierFlagControl);
    // A text field wants input methods: the press goes to the IME first.
    // What it does with it decides what the guest sees (ime_* below).
    if (pressed && text_input_ && !mods) {
        ime_event_ = e;
        ime_raw_ = false;
        ime_handled_ = false;
        [view_.inputContext handleEvent:e];
        ime_event_ = nil;
        if (!ime_handled_ || ime_raw_) {
            if (e.ARepeat || !code) return;
            hs->host_modifiers(modifiers_from(e.modifierFlags));
            hs->host_key(code, true, event_ms(e));
        }
        return;
    }
    if (pressed && e.ARepeat) return;   // the client repeats (wl_keyboard.repeat_info)
    if (!code) return;
    hs->host_modifiers(modifiers_from(e.modifierFlags));
    hs->host_key(code, pressed, event_ms(e));
}

// -- NSTextInputClient, through LXView ------------------------------------------------
//
// Plain typing stays plain: an insert of exactly the key's own characters,
// with nothing being composed, is sent as the key itself, so the guest's
// XKB layout, shortcuts and key repeat all behave as they do on Linux.
// Anything the IME made -- a composed accent, a CJK candidate, a
// press-and-hold choice -- goes as text_input commit_string.

void CocoaWindow::ime_insert(NSString* text) {
    ime_handled_ = true;
    const bool was_composing = marked_.length > 0;
    marked_ = @"";
    if (!was_composing && ime_event_ && [text isEqualToString:ime_event_.characters]) {
        ime_raw_ = true;   // the key as typed
        return;
    }
    if (HostSink* hs = host_->sink()) hs->host_text_commit(text.UTF8String ?: "");
}

void CocoaWindow::ime_mark(NSString* text, NSRange sel) {
    ime_handled_ = true;
    marked_ = [text copy];
    HostSink* hs = host_->sink();
    if (!hs) return;
    // the cursor as UTF-8 byte offsets into the composition
    auto bytes = [&](NSUInteger utf16) {
        NSString* head = [text substringToIndex:std::min<NSUInteger>(utf16, text.length)];
        return static_cast<std::int32_t>(strlen(head.UTF8String ?: ""));
    };
    hs->host_text_preedit(text.UTF8String ?: "", bytes(sel.location), bytes(sel.location + sel.length));
}

void CocoaWindow::ime_unmark() {
    if (marked_.length == 0) return;
    NSString* t = marked_;
    marked_ = @"";
    if (HostSink* hs = host_->sink()) hs->host_text_commit(t.UTF8String ?: "");
}

// A command (Return, arrows, Backspace): the key itself.
void CocoaWindow::ime_command() {
    ime_handled_ = true;
    ime_raw_ = true;
}

NSRect CocoaWindow::ime_rect() const {
    // the field's caret, in screen coordinates (the view is flipped, y down
    // like Wayland; AppKit converts)
    const ld::Rect r = text_cursor_;
    const NSRect in_view = NSMakeRect(r.x, r.y, std::max(1, r.w), std::max(1, r.h));
    return [win_ convertRectToScreen:[view_ convertRect:in_view toView:nil]];
}

void CocoaWindow::set_text_input(std::optional<ld::Rect> cursor) {
    const bool was = text_input_;
    text_input_ = cursor.has_value();
    if (cursor) text_cursor_ = *cursor;
    if (was && !text_input_) {
        marked_ = @"";
        [view_.inputContext discardMarkedText];
    }
    if (text_input_) [view_.inputContext invalidateCharacterCoordinates];
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
    // The menus every Mac app has, wired to the Linux app in front:
    //   Cmd-Q quits that app (closes its windows; it may ask to save),
    //   Cmd-W closes the window, Cmd-M minimizes, Cmd-H hides, Ctrl-Cmd-F
    //   is full screen; the Window menu lists every window and gives Cmd-`.
    // Everything else with Command goes to the app (as Control, see seat).
    NSMenu* bar = [NSMenu new];
    auto submenu = [&](NSString* title) {
        NSMenuItem* item = [NSMenuItem new];
        NSMenu* m = [[NSMenu alloc] initWithTitle:title];
        item.submenu = m;
        [bar addItem:item];
        return m;
    };
    NSMenu* am = submenu(@"Linux");
    [am addItemWithTitle:@"Hide Linux Apps" action:@selector(hide:) keyEquivalent:@"h"];
    NSMenuItem* others = [am addItemWithTitle:@"Hide Others" action:@selector(hideOtherApplications:) keyEquivalent:@"h"];
    others.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagOption;
    [am addItemWithTitle:@"Show All" action:@selector(unhideAllApplications:) keyEquivalent:@""];
    [am addItem:[NSMenuItem separatorItem]];
    [am addItemWithTitle:@"Quit App" action:@selector(lxQuitApp:) keyEquivalent:@"q"];
    [am addItemWithTitle:@"Close All Linux Windows" action:@selector(lxCloseAll:) keyEquivalent:@""];
    NSMenu* fm = submenu(@"File");
    [fm addItemWithTitle:@"Close Window" action:@selector(performClose:) keyEquivalent:@"w"];
    NSMenu* wm = submenu(@"Window");
    [wm addItemWithTitle:@"Minimize" action:@selector(performMiniaturize:) keyEquivalent:@"m"];
    [wm addItemWithTitle:@"Zoom" action:@selector(performZoom:) keyEquivalent:@""];
    NSMenuItem* fs = [wm addItemWithTitle:@"Enter Full Screen" action:@selector(toggleFullScreen:) keyEquivalent:@"f"];
    fs.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagControl;
    [wm addItem:[NSMenuItem separatorItem]];
    [wm addItemWithTitle:@"Bring All to Front" action:@selector(arrangeInFront:) keyEquivalent:@""];
    NSApp.mainMenu = bar;
    NSApp.windowsMenu = wm;   // AppKit fills in the window list and Cmd-`
    // The display server outlives its windows: every open Linux shell
    // needs it for the next GUI app. AppKit must never retire it for being
    // windowless (automatic termination) or kill it unannounced.
    [[NSProcessInfo processInfo] disableAutomaticTermination:@"serves Linux sessions"];
    [[NSProcessInfo processInfo] disableSuddenTermination];
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
        // the backing store's own factor: macOS renders "scaled" resolutions
        // at this and resamples the whole screen, so it is the right one
        o.fractional_scale = s.backingScaleFactor;
        o.pixels = {o.logical.w * o.scale, o.logical.h * o.scale};
        NSNumber* num = s.deviceDescription[@"NSScreenNumber"];
        const CGDirectDisplayID did = num.unsignedIntValue;
        const CGSize mm = CGDisplayScreenSize(did);
        o.physical_mm = {static_cast<std::int32_t>(mm.width), static_cast<std::int32_t>(mm.height)};
        o.make = CGDisplayIsBuiltin(did) ? "Apple" : "Unknown";
        o.model = s.localizedName.UTF8String;
        o.name = (CGDisplayIsBuiltin(did) ? "eDP-" : "DP-") + std::to_string(out.size() + 1);
        o.description = o.model;
        const double hz = static_cast<double>(s.maximumFramesPerSecond);
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
    CGImageRef img = image_copy(*c.pixels);
    if (!img) return;
    const NSSize size = NSMakeSize(c.pixels->width / static_cast<CGFloat>(c.scale), c.pixels->height / static_cast<CGFloat>(c.scale));
    NSImage* ni = [[NSImage alloc] initWithCGImage:img size:size];
    CGImageRelease(img);
    cursor_ = [[NSCursor alloc] initWithImage:ni hotSpot:NSMakePoint(c.hotspot.x, c.hotspot.y)];
    hidden_ = false;
    apply_cursor();
}

// The Mac's own cursor for each wp_cursor_shape name; the few it lacks get
// the nearest one it has.
NSCursor* ns_cursor(CursorShape s) {
    using S = CursorShape;
    switch (s) {
        case S::context_menu: return NSCursor.contextualMenuCursor;
        case S::pointer: return NSCursor.pointingHandCursor;
        case S::cell: case S::crosshair: return NSCursor.crosshairCursor;
        case S::text: return NSCursor.IBeamCursor;
        case S::vertical_text: return NSCursor.IBeamCursorForVerticalLayout;
        case S::alias: return NSCursor.dragLinkCursor;
        case S::copy: case S::dnd_ask: return NSCursor.dragCopyCursor;
        case S::move: case S::grab: case S::all_scroll: return NSCursor.openHandCursor;
        case S::grabbing: return NSCursor.closedHandCursor;
        case S::no_drop: case S::not_allowed: return NSCursor.operationNotAllowedCursor;
        case S::e_resize: case S::w_resize: case S::ew_resize: case S::col_resize: return NSCursor.resizeLeftRightCursor;
        case S::n_resize: case S::s_resize: case S::ns_resize: case S::row_resize: return NSCursor.resizeUpDownCursor;
        case S::ne_resize: case S::sw_resize: case S::nesw_resize:
            if (@available(macOS 15.0, *)) return [NSCursor frameResizeCursorFromPosition:NSCursorFrameResizePositionTopRight
                                                                             inDirections:NSCursorFrameResizeDirectionsAll];
            return NSCursor.crosshairCursor;
        case S::nw_resize: case S::se_resize: case S::nwse_resize:
            if (@available(macOS 15.0, *)) return [NSCursor frameResizeCursorFromPosition:NSCursorFrameResizePositionTopLeft
                                                                             inDirections:NSCursorFrameResizeDirectionsAll];
            return NSCursor.crosshairCursor;
        case S::all_resize: return NSCursor.openHandCursor;
        case S::zoom_in:
            if (@available(macOS 15.0, *)) return NSCursor.zoomInCursor;
            return NSCursor.arrowCursor;
        case S::zoom_out:
            if (@available(macOS 15.0, *)) return NSCursor.zoomOutCursor;
            return NSCursor.arrowCursor;
        default: return NSCursor.arrowCursor;   // default, help, progress, wait
    }
}

void CocoaHost::set_cursor_shape(CursorShape s) {
    cursor_ = ns_cursor(s);
    hidden_ = false;
    apply_cursor();
}

void CocoaHost::bell() { NSBeep(); }

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

// NSTextInputClient: the IME talks to us only while a guest text field asked
// for it (CocoaWindow::key decides). We hold no document, just the
// composition, so ranges are about that.
- (void)insertText:(id)s replacementRange:(NSRange)r {
    if (!self.owner) return;
    NSString* t = [s isKindOfClass:NSAttributedString.class] ? [(NSAttributedString*)s string] : (NSString*)s;
    self.owner->ime_insert(t);
}
- (void)setMarkedText:(id)s selectedRange:(NSRange)sel replacementRange:(NSRange)r {
    if (!self.owner) return;
    NSString* t = [s isKindOfClass:NSAttributedString.class] ? [(NSAttributedString*)s string] : (NSString*)s;
    self.owner->ime_mark(t, sel);
}
- (void)unmarkText { if (self.owner) self.owner->ime_unmark(); }
- (void)doCommandBySelector:(SEL)sel { if (self.owner) self.owner->ime_command(); }
- (BOOL)hasMarkedText { return self.owner && self.owner->ime_composing(); }
- (NSRange)markedRange {
    return self.owner && self.owner->ime_composing() ? NSMakeRange(0, self.owner->ime_marked_length())
                                                     : NSMakeRange(NSNotFound, 0);
}
- (NSRange)selectedRange { return NSMakeRange(self.owner ? self.owner->ime_marked_length() : 0, 0); }
- (NSArray<NSAttributedStringKey>*)validAttributesForMarkedText { return @[]; }
- (NSAttributedString*)attributedSubstringForProposedRange:(NSRange)r actualRange:(NSRangePointer)a { return nil; }
- (NSUInteger)characterIndexForPoint:(NSPoint)p { return NSNotFound; }
- (NSRect)firstRectForCharacterRange:(NSRange)r actualRange:(NSRangePointer)a {
    return self.owner ? self.owner->ime_rect() : NSZeroRect;
}
// Cmd-key combos come here first. The Mac's own window shortcuts go to the
// menus (Cmd-Q/W/M/H, Opt-Cmd-H, Ctrl-Cmd-F, Cmd-`); everything else is the
// app's (with Command as Control).
- (BOOL)performKeyEquivalent:(NSEvent*)e {
    if (!self.owner || self.window.firstResponder != self) return NO;
    if (e.type == NSEventTypeKeyDown) {
        NSString* c = e.charactersIgnoringModifiers.lowercaseString;
        const NSEventModifierFlags m = e.modifierFlags & (NSEventModifierFlagCommand | NSEventModifierFlagControl |
                                                          NSEventModifierFlagOption | NSEventModifierFlagShift);
        const NSEventModifierFlags cmd = NSEventModifierFlagCommand;
        if (m == cmd && ([c isEqualToString:@"q"] || [c isEqualToString:@"w"] || [c isEqualToString:@"m"] ||
                         [c isEqualToString:@"h"] || [c isEqualToString:@"`"]))
            return NO;
        if (m == (cmd | NSEventModifierFlagOption) && [c isEqualToString:@"h"]) return NO;
        if (m == (cmd | NSEventModifierFlagControl) && [c isEqualToString:@"f"]) return NO;
        self.owner->key(e, true);
        return YES;
    }
    return NO;
}
// The transparent title bar of an app-drawn window: its clicks are the
// app's (its headerbar is there), not AppKit's window drag.
- (BOOL)mouseDownCanMoveWindow { return NO; }
- (void)lxQuitApp:(id)sender { if (self.owner) self.owner->quit_app(); }
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
// Close every Linux window (apps may ask to save) -- but keep serving: the
// shells that opened them will open more.
- (void)lxCloseAll:(id)sender {
    if (self.host && self.host->sink()) self.host->sink()->host_quit();
}
// Only logout, restart or shutdown get here now (no menu item quits): close
// the windows, give the requests a moment to go out, then go. Never refuse:
// a compositor that cancels termination blocks logout.
- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)app {
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
