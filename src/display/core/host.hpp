// src/display/core/host.hpp -- THE platform seam of linuxity-display.
//
// The compositor core (core/*.cpp) speaks Wayland to guest clients and
// decides everything a compositor decides: surface trees, roles, configure
// sequences, popup placement, focus, input routing. It knows nothing about
// the platform it shows windows on. A Host does the platform half:
//
//   * one native window per mapped toplevel / popup  (HostWindow)
//   * pixels in, input and window-manager decisions out (WindowSink)
//   * screens, keyboard layout, cursor, clipboard
//   * the event loop everything runs on
//
// Hosts today: cocoa/ (macOS: NSWindow per toplevel, native title bars,
// Retina scale, native fullscreen) and headless/ (no windows; tests, CI).
// An Android host maps HostWindow onto an activity's SurfaceView, a Windows
// one onto an HWND; neither needs a line of core code to change.
//
// Coordinates are logical pixels (macOS points), y down. A window shows a
// "view" rectangle of its root surface's coordinate space (see Scene).
#pragma once

#include "geometry.hpp"
#include "loop.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lx::display {

// -- What windows show -------------------------------------------------------

// Memory order of one pixel, as wl_shm names it (little-endian words).
enum class PixelFormat : std::uint8_t {
    argb8888,   // B G R A, premultiplied alpha
    xrgb8888,   // B G R x
    abgr8888,   // R G B A, premultiplied alpha
    xbgr8888,   // R G B x
};

// A surface's content: the compositor's own copy of what the client drew,
// kept per surface and updated in place, only where the client said it
// changed (damage). The buffer is released at once.
//
// THE CONTRACT: the bytes are only stable during the HostWindow::present()
// (or set_cursor) call that hands them over. A host copies what it needs
// then -- just Layer::damage, into its own GPU-visible store -- and never
// keeps a pointer into them. That is what makes a terminal's keystroke
// cost a few hundred bytes, not a window's worth of pixels.
struct Pixels {
    std::int32_t width{0}, height{0}, stride{0};
    PixelFormat format{PixelFormat::argb8888};
    std::vector<std::byte> data;
};
using PixelsRef = std::shared_ptr<const Pixels>;

// A rectangle of a buffer, in buffer pixels (wp_viewport.set_source is
// fractional). Empty: the whole buffer.
struct SourceRect {
    double x{0}, y{0}, w{0}, h{0};
    [[nodiscard]] constexpr bool whole() const noexcept { return w <= 0 || h <= 0; }
    friend constexpr bool operator==(SourceRect, SourceRect) noexcept = default;
};

// One surface of a window's tree. The part `source` of `pixels` is shown
// stretched over `rect`: with no viewport that is the whole buffer at
// 1/scale, with one it is any crop at any size.
struct Layer {
    std::uint64_t id{0};       // stable for the surface's life
    Rect rect;                 // logical, in root-surface coordinates
    PixelsRef pixels;          // the surface's content (stable for the call)
    std::int32_t scale{1};     // buffer pixels per logical pixel (no viewport)
    SourceRect source;         // crop, in buffer pixels
    // What changed since the last present of this layer, in buffer pixels;
    // `generation` bumps with every change, so an unchanged layer costs
    // nothing. A host that has never seen this layer (or sees a new size)
    // copies it all.
    Rect damage;
    std::uint64_t generation{0};
    bool opaque{false};
};

struct Scene {
    Rect view;                 // what the native window's content shows
    Rect geometry;             // the window proper (xdg window geometry)
    std::vector<Layer> layers; // back to front
};

// -- Window management -------------------------------------------------------

enum class Decorations : std::uint8_t {
    client,    // the app draws its own frame (GTK, libadwaita)
    server,    // the host draws a native title bar; view == geometry
};

// xdg_toplevel.resize_edge's encoding
namespace edge {
inline constexpr std::uint32_t top = 1, bottom = 2, left = 4, right = 8;
}

struct WindowStates {
    bool activated{false}, maximized{false}, fullscreen{false}, resizing{false};
    friend constexpr bool operator==(WindowStates, WindowStates) noexcept = default;
};

enum class PointerButton : std::uint32_t { left = 0x110, right = 0x111, middle = 0x112, side = 0x113, extra = 0x114 };

enum class AxisSource : std::uint32_t { wheel = 0, finger = 1, continuous = 2 };

struct ScrollEvent {
    double dx{0}, dy{0};           // logical pixels; positive = content moves up/left (wheel down)
    std::int32_t steps_x{0}, steps_y{0};   // wheel detents in 1/120ths (wheel source only)
    AxisSource source{AxisSource::wheel};
    bool stop{false};              // finger lifted: kinetic scrolling may begin
};

// The core's side of one window: the host reports what happened to it.
class WindowSink {
public:
    virtual ~WindowSink() = default;
    // The user (or the platform) wants this size and state; 0x0 = client picks.
    virtual void host_configure(Size size, WindowStates states) = 0;
    virtual void host_close() = 0;
    virtual void host_focus(bool focused) = 0;
    // Pointer, in view coordinates.
    virtual void host_pointer_motion(double x, double y, std::uint32_t time_ms) = 0;
    virtual void host_pointer_leave() = 0;
    virtual void host_pointer_button(PointerButton b, bool pressed, std::uint32_t time_ms) = 0;
    virtual void host_scroll(const ScrollEvent& e, std::uint32_t time_ms) = 0;
    // The window now shows mostly on output `index` (of Host::outputs()).
    virtual void host_output(std::size_t index) = 0;
};

struct WindowSpec {
    enum class Kind : std::uint8_t { toplevel, popup } kind{Kind::toplevel};
    class HostWindow* parent{nullptr};   // popup: the window it hangs off
    Point at;                            // popup: its view origin, relative to the parent's
    Decorations decorations{Decorations::client};
    std::string title, app_id;
    Size min, max;                       // 0 = unbounded
};

class HostWindow {
public:
    virtual ~HostWindow() = default;
    virtual void present(const Scene& s) = 0;     // first present maps it
    virtual void set_title(std::string_view title) = 0;
    virtual void set_decorations(Decorations d) = 0;
    virtual void set_size_limits(Size min, Size max) = 0;
    virtual void set_maximized(bool on) = 0;
    virtual void set_fullscreen(bool on) = 0;
    virtual void minimize() = 0;
    virtual void begin_move() = 0;                // the pointer button is down
    virtual void begin_resize(std::uint32_t edges) = 0;
    virtual void move_popup(Point at) = 0;
    virtual void activate() = 0;
    // Ask for the user's attention without taking focus (the Dock icon
    // bounces, the taskbar entry flashes): a terminal's urgent bell, an
    // app that wanted focus it wasn't entitled to.
    virtual void request_attention() {}
    // A text field of this window has the keyboard (zwp_text_input_v3):
    // route typing through the platform's input methods (IME, dead keys,
    // press-and-hold accents) and put their candidate window by `cursor`
    // (view coordinates). nullopt: plain keys again.
    virtual void set_text_input(std::optional<Rect> cursor) { (void)cursor; }
    // The usable screen area, relative to this window's view origin.
    [[nodiscard]] virtual Rect work_area() const = 0;
};

// -- The rest of the platform ------------------------------------------------

struct OutputInfo {
    std::string name, description, make{"linuxity"}, model;
    Rect logical;                  // in the global logical space
    Size pixels;                   // native mode
    Size physical_mm;
    std::int32_t scale{1};
    double fractional_scale{0};    // e.g. 1.5; 0 = exactly `scale`
    std::int32_t refresh_mhz{60000};
    friend bool operator==(const OutputInfo&, const OutputInfo&) = default;
};

struct KeyboardInfo {
    // XKB RMLVO; clients compile it against their own xkb data
    std::string rules{"evdev"}, model{"pc105"}, layout{"us"}, variant, options;
    std::int32_t repeat_rate{25};      // per second; 0 = no repeat
    std::int32_t repeat_delay_ms{600};
};

struct Modifiers {
    bool shift{false}, control{false}, alt{false}, super{false}, caps_lock{false}, num_lock{false};
    friend constexpr bool operator==(Modifiers, Modifiers) noexcept = default;
};

struct CursorImage {
    PixelsRef pixels;              // null = hide the cursor
    std::int32_t scale{1};
    Point hotspot;                 // logical
};

// The named cursors of wp_cursor_shape_v1 (same numbering): the platform's
// own cursor art, crisp at every scale, instead of the client's bitmap.
enum class CursorShape : std::uint32_t {
    default_ = 1, context_menu, help, pointer, progress, wait, cell, crosshair, text, vertical_text,
    alias, copy, move, no_drop, not_allowed, grab, grabbing, e_resize, n_resize, ne_resize, nw_resize,
    s_resize, se_resize, sw_resize, w_resize, ew_resize, ns_resize, nesw_resize, nwse_resize,
    col_resize, row_resize, all_scroll, zoom_in, zoom_out, dnd_ask, all_resize,
};
inline constexpr std::uint32_t kLastCursorShape = static_cast<std::uint32_t>(CursorShape::all_resize);

// Text on the platform clipboard, for the guest's copy and paste.
class HostClipboard {
public:
    virtual ~HostClipboard() = default;
    [[nodiscard]] virtual std::optional<std::string> text() = 0;
    virtual void set_text(std::string text) = 0;
    // Bumps whenever someone else changes the clipboard.
    [[nodiscard]] virtual std::uint64_t generation() = 0;
};

// The core's side of the platform.
class HostSink {
public:
    virtual ~HostSink() = default;
    // Keyboard, for the window that has focus. Keys are Linux evdev codes.
    virtual void host_key(std::uint32_t evdev_code, bool pressed, std::uint32_t time_ms) = 0;
    virtual void host_modifiers(Modifiers m) = 0;
    // Input-method text for the focused text field (see
    // HostWindow::set_text_input): composition in progress, with the cursor
    // as UTF-8 byte offsets into it (-1, -1: hidden); and text to insert,
    // which replaces any composition.
    virtual void host_text_preedit(std::string text, std::int32_t cursor_begin, std::int32_t cursor_end) {
        (void)text; (void)cursor_begin; (void)cursor_end;
    }
    virtual void host_text_commit(std::string text) { (void)text; }
    virtual void host_outputs_changed() = 0;
    virtual void host_keyboard_changed() = 0;
    // The platform activated or deactivated us as a whole (popups close).
    virtual void host_app_active(bool active) = 0;
    // The user is quitting the display server (or logging out): ask the
    // apps to close their windows. The host then ends the process itself.
    virtual void host_quit() = 0;
};

class Host {
public:
    virtual ~Host() = default;
    [[nodiscard]] virtual EventLoop& loop() = 0;
    virtual void attach(HostSink& sink) = 0;
    [[nodiscard]] virtual std::vector<OutputInfo> outputs() = 0;
    [[nodiscard]] virtual KeyboardInfo keyboard() = 0;
    [[nodiscard]] virtual std::unique_ptr<HostWindow> create_window(const WindowSpec& spec, WindowSink& sink) = 0;
    virtual void set_cursor(const CursorImage& c) = 0;
    virtual void set_cursor_shape(CursorShape s) { (void)s; reset_cursor(); }
    virtual void reset_cursor() = 0;               // the platform's default arrow
    virtual void bell() {}                         // the system alert sound
    [[nodiscard]] virtual HostClipboard* clipboard() { return nullptr; }
    // Windows exist (show us in the Dock / task switcher) or not.
    virtual void set_has_windows(bool any) { (void)any; }
};

// The host this build provides (cocoa on macOS, headless elsewhere for now).
[[nodiscard]] std::unique_ptr<Host> make_host(bool headless);

}  // namespace lx::display
