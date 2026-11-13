// src/display/core/compositor.hpp -- the compositor: every Wayland object a
// desktop client needs, and the policy that ties them to host windows.
//
//   surface.cpp   wl_compositor, wl_surface, wl_region, wl_subsurface, wl_shm
//   shell.cpp     xdg_wm_base, xdg_surface/toplevel/popup/positioner,
//                 xdg-decoration -- and the bridge to HostWindow
//   seat.cpp      wl_seat, wl_pointer, wl_keyboard, wl_data_device (clipboard)
//   compositor.cpp  globals, wl_output, frame pacing, host events
#pragma once

#include "geometry.hpp"
#include "host.hpp"
#include "server.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace lx::display {

class Compositor;
class Surface;
class ShellSurface;
class Seat;

// -- Buffers ------------------------------------------------------------------

// A client's wl_shm_pool memory, mapped read-only. Shared by the pool and
// every buffer cut from it: a pool destroyed before its buffers must not
// unmap them.
struct ShmMapping {
    wire::Fd fd;
    void* base{nullptr};
    std::size_t size{0};
    ~ShmMapping();
    [[nodiscard]] bool remap(std::size_t new_size);
};

class Buffer final : public Object<proto::WlBuffer> {
public:
    // cut from a wl_shm_pool
    Buffer(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<ShmMapping> m,
           std::int32_t offset, std::int32_t w, std::int32_t h, std::int32_t stride, PixelFormat f)
        : Object(c, v, id), map_(std::move(m)), offset_(offset), w_(w), h_(h), stride_(stride), fmt_(f) {}
    // wp_single_pixel_buffer: one premultiplied colour, 1x1 (stretched by a viewport)
    Buffer(Client& c, std::uint32_t v, ObjectId id, std::array<std::uint8_t, 4> bgra)
        : Object(c, v, id), offset_(0), w_(1), h_(1), stride_(4), fmt_(PixelFormat::argb8888), solid_(bgra) {}
    // Bring `content` up to date with this buffer: only `damage` (buffer
    // pixels) when the shapes match, all of it otherwise (a new store).
    // Guarded against the client shrinking its pool under us; false if the
    // memory can't be read.
    [[nodiscard]] bool copy_into(std::shared_ptr<Pixels>& content, std::optional<Rect> damage) const;
    void release() { send(proto::WlBuffer::Ev::release); }
    [[nodiscard]] Size size() const noexcept { return {w_, h_}; }
protected:
    void request(std::uint16_t, wire::Args&) override {}
private:
    std::shared_ptr<ShmMapping> map_;
    std::int32_t offset_, w_, h_, stride_;
    PixelFormat fmt_;
    std::optional<std::array<std::uint8_t, 4>> solid_;
};

// -- Surfaces -----------------------------------------------------------------

// What a role does when its surface commits.
class SurfaceRole {
public:
    virtual ~SurfaceRole() = default;
    virtual void role_commit() = 0;
    // The surface tree under this role changed (a subsurface committed).
    virtual void role_tree_changed() { role_commit(); }
    [[nodiscard]] virtual bool role_is_sync_child() const { return false; }
    // The surface was destroyed under the role object.
    virtual void role_surface_gone() {}
};

// wp_viewport's crop and scale: source in surface coordinates before the
// crop (fractional), destination size in surface coordinates.
struct Viewport {
    std::optional<SourceRect> src;
    std::optional<Size> dst;
    friend bool operator==(const Viewport&, const Viewport&) = default;
};

// Double-buffered surface state (wl_surface's "pending" and "cached").
struct SurfaceState {
    bool attached{false};          // attach seen this cycle
    // A synchronized subsurface's cached frame: its own full copy, applied
    // on the parent's commit. Unsynchronized commits update the surface's
    // content in place instead and never set this.
    std::shared_ptr<Pixels> staged;
    bool unmap{false};             // attach(null)
    Rect damage;                   // buffer pixels, union
    bool damage_all{false};
    Point delta;
    std::optional<std::int32_t> scale;
    std::optional<std::optional<Region>> input, opaque;   // set: nullopt inner = infinite
    std::optional<Viewport> viewport;
    std::vector<std::shared_ptr<Callback>> frames;
    void merge_into(SurfaceState& dst);
};

class FractionalScale;
class ViewportObj;

// wp_fractional_scale_v1.preferred_scale, in 120ths
void send_fractional_scale(FractionalScale& f, double scale);

class Surface final : public Object<proto::WlSurface> {
public:
    Surface(Client& c, std::uint32_t v, ObjectId id, Compositor& comp);
    ~Surface() override;

    [[nodiscard]] Compositor& comp() const noexcept { return *comp_; }
    [[nodiscard]] std::uint64_t uid() const noexcept { return uid_; }
    [[nodiscard]] std::shared_ptr<Surface> self() { return std::static_pointer_cast<Surface>(shared_from_this()); }

    // committed state
    [[nodiscard]] PixelsRef pixels() const noexcept { return content_; }
    [[nodiscard]] bool mapped_content() const noexcept { return content_ != nullptr; }
    [[nodiscard]] Size size() const noexcept { return size_; }        // logical
    [[nodiscard]] std::int32_t scale() const noexcept { return scale_; }
    // the buffer region shown (the viewport's crop, in buffer pixels)
    [[nodiscard]] SourceRect source() const noexcept;
    // damage not yet shown by the host, and a counter of content changes
    [[nodiscard]] Rect unpresented_damage() const noexcept { return present_damage_; }
    [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }
    void presented() noexcept { present_damage_ = {}; }
    [[nodiscard]] bool accepts_input(double x, double y) const noexcept;
    [[nodiscard]] Point take_delta() noexcept { return std::exchange(delta_, Point{}); }

    // wp_viewport / wp_fractional_scale attach here (one each at most)
    [[nodiscard]] bool has_viewport() const noexcept { return has_viewport_; }
    void set_has_viewport(bool v) noexcept { has_viewport_ = v; }
    void set_pending_viewport(Viewport v) { pending_.viewport = std::move(v); }
    [[nodiscard]] const Viewport& pending_viewport_or_current() const noexcept {
        return pending_.viewport ? *pending_.viewport : viewport_;
    }
    [[nodiscard]] FractionalScale* fractional() const noexcept { return fractional_; }
    void set_fractional(FractionalScale* f) noexcept { fractional_ = f; }
    void set_viewport_obj(ViewportObj* v) noexcept { viewport_obj_ = v; }

    // roles
    [[nodiscard]] SurfaceRole* role() const noexcept { return role_; }
    [[nodiscard]] std::string_view role_name() const noexcept { return role_name_; }
    // Give the surface a role; false (and a protocol error posted on
    // `blame`) if it already has a different one.
    bool set_role(std::string_view name, SurfaceRole* impl, Resource& blame, std::uint32_t code);
    void clear_role_impl(SurfaceRole* impl) { if (role_ == impl) role_ = nullptr; }

    // the subsurface tree
    [[nodiscard]] const std::vector<std::weak_ptr<Surface>>& stack() const noexcept { return stack_; }
    void add_child(const std::shared_ptr<Surface>& child);
    void remove_child(const Surface* child);
    bool restack(const Surface* child, const Surface* sibling, bool above);
    [[nodiscard]] Surface* parent() const noexcept { return parent_.lock().get(); }
    void set_parent(const std::shared_ptr<Surface>& p) { parent_ = p; }
    [[nodiscard]] Point position() const noexcept { return position_; }   // relative to parent
    void set_pending_position(Point p) { pending_position_ = p; position_dirty_ = true; }
    [[nodiscard]] bool effectively_sync() const;
    void set_sync(bool s) { sync_ = s; }
    // The root of this surface's tree (itself if not a subsurface).
    [[nodiscard]] Surface* root();

    void apply_cached();    // a synchronized child, on its parent's commit

    // Outputs the surface is on (wl_surface.enter/leave), by output id;
    // `scale` is the output's, fractional (1.5, 2.0 ...).
    void set_outputs(const std::vector<std::shared_ptr<Resource>>& outputs, double scale);
    [[nodiscard]] double output_scale() const noexcept { return output_scale_; }

protected:
    void request(std::uint16_t op, wire::Args& a) override;
    void on_destroy() override;

private:
    void commit();
    [[nodiscard]] bool take_buffer(SurfaceState& st);   // the attached buffer -> content
    void apply(SurfaceState& st);
    void children_commit();
    void surface_gone_hooks();

    Compositor* comp_;
    std::uint64_t uid_;
    SurfaceState pending_, cached_;
    std::weak_ptr<Buffer> pending_buffer_;
    bool has_cached_{false};
    std::shared_ptr<Pixels> content_;  // our copy of what the client drew
    Rect present_damage_;
    std::uint64_t generation_{0};
    Viewport viewport_;
    bool has_viewport_{false};
    FractionalScale* fractional_{nullptr};
    ViewportObj* viewport_obj_{nullptr};
    double output_scale_{0};
    Size size_;
    std::int32_t scale_{1};
    std::optional<Region> input_;      // nullopt = infinite
    Point delta_;
    SurfaceRole* role_{nullptr};
    std::string role_name_;
    std::weak_ptr<Surface> parent_;
    std::vector<std::weak_ptr<Surface>> stack_, pending_stack_;   // children + self, bottom to top
    bool stack_dirty_{false};
    Point position_, pending_position_;
    bool position_dirty_{false};
    bool sync_{true};
    std::vector<std::weak_ptr<Resource>> entered_;
    std::int32_t preferred_scale_{0};
};

// -- The shell ----------------------------------------------------------------

struct PositionerState {
    Size size;
    Rect anchor_rect;
    proto::XdgPositioner::Anchor anchor{proto::XdgPositioner::Anchor::none};
    proto::XdgPositioner::Gravity gravity{proto::XdgPositioner::Gravity::none};
    std::uint32_t adjust{0};
    Point offset;
    bool reactive{false};
    // Where the popup goes (relative to the parent's window geometry),
    // kept inside `bounds` (same space) as far as `adjust` allows.
    [[nodiscard]] Rect place(std::optional<Rect> bounds) const;
};

class Toplevel;
class Popup;

// xdg_surface, and the window it becomes: implements the host's WindowSink.
class ShellSurface final : public Object<proto::XdgSurface>, public SurfaceRole, public WindowSink {
public:
    ShellSurface(Client& c, std::uint32_t v, ObjectId id, Compositor& comp, std::shared_ptr<Surface> s);
    ~ShellSurface() override;

    [[nodiscard]] Compositor& comp() const noexcept { return *comp_; }
    [[nodiscard]] Surface* surface() const noexcept { return surface_.lock().get(); }
    [[nodiscard]] HostWindow* window() const noexcept { return window_.get(); }
    [[nodiscard]] Toplevel* toplevel() const noexcept { return toplevel_; }
    [[nodiscard]] Popup* popup() const noexcept { return popup_; }
    [[nodiscard]] bool mapped() const noexcept { return window_ != nullptr; }
    [[nodiscard]] std::shared_ptr<ShellSurface> self() { return std::static_pointer_cast<ShellSurface>(shared_from_this()); }

    [[nodiscard]] Rect geometry() const;       // window geometry, root-surface space
    [[nodiscard]] Rect view() const noexcept { return scene_.view; }
    [[nodiscard]] Decorations decorations() const noexcept;

    // configure sequence
    std::uint32_t send_configure();            // xdg_surface.configure (after the role's own)
    [[nodiscard]] bool configured() const noexcept { return acked_any_; }
    [[nodiscard]] bool initial_committed() const noexcept { return initial_commit_seen_; }
    void schedule_present();
    void unmap();

    // Find the surface under view point (vx, vy); local coords out.
    [[nodiscard]] Surface* pick(double vx, double vy, double& lx, double& ly) const;
    // Where `s` sits in view coordinates (for pointer grabs).
    [[nodiscard]] std::optional<Point> origin_of(const Surface* s) const;

    // role links
    void attach_toplevel(Toplevel* t) { toplevel_ = t; }
    void attach_popup(Popup* p) { popup_ = p; }

    // SurfaceRole
    void role_commit() override;
    void role_surface_gone() override { unmap(); }

    // WindowSink
    void host_configure(Size size, WindowStates states) override;
    void host_configure_and_wait(Size size, WindowStates states, std::chrono::milliseconds budget) override;
    void host_close() override;
    void host_close_app() override;
    void host_focus(bool focused) override;
    void host_pointer_motion(double x, double y, std::uint32_t t) override;
    void host_pointer_leave() override;
    void host_pointer_button(PointerButton b, bool pressed, std::uint32_t t) override;
    void host_scroll(const ScrollEvent& e, std::uint32_t t) override;
    void host_output(std::size_t index) override;

protected:
    void request(std::uint16_t op, wire::Args& a) override;
    void on_destroy() override;

private:
    void map();
    void present_now();
    void present_scene();
    void build_scene(Scene& out, std::vector<std::weak_ptr<Surface>>& who) const;

    Compositor* comp_;
    std::weak_ptr<Surface> surface_;
    Toplevel* toplevel_{nullptr};
    Popup* popup_{nullptr};
    std::optional<Rect> geometry_, pending_geometry_;
    std::vector<std::uint32_t> sent_serials_;
    std::uint32_t last_acked_{0};
    std::uint64_t commits_{0}, commits_at_ack_{0};   // buffer commits, and how many when the last ack came
    bool acked_any_{false};
    bool initial_commit_seen_{false};
    std::unique_ptr<HostWindow> window_;
    Scene scene_;
    std::vector<std::weak_ptr<Surface>> scene_surfaces_;
    bool present_scheduled_{false};
    std::size_t output_{0};
};

class Decoration;

class Toplevel final : public Object<proto::XdgToplevel> {
public:
    Toplevel(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<ShellSurface> xs);
    [[nodiscard]] ShellSurface* xdg() const noexcept { return xdg_.lock().get(); }

    void configure();                          // toplevel.configure + xdg_surface.configure
    void initial_configure();
    void host_wants(Size size, WindowStates states);
    [[nodiscard]] const std::string& title() const noexcept { return title_; }
    [[nodiscard]] const std::string& app_id() const noexcept { return app_id_; }
    [[nodiscard]] Size min_size() const noexcept { return min_; }
    [[nodiscard]] Size max_size() const noexcept { return max_; }
    [[nodiscard]] Decorations decorations() const noexcept { return decorations_; }
    void set_decorations(Decorations d);
    void set_decoration_object(Decoration* d) { decoration_ = d; }
    [[nodiscard]] Decoration* decoration_object() const noexcept { return decoration_; }
    void on_mapped();
    [[nodiscard]] const WindowStates& states() const noexcept { return states_; }

protected:
    void request(std::uint16_t op, wire::Args& a) override;
    void on_destroy() override;

private:
    std::weak_ptr<ShellSurface> xdg_;
    std::string title_, app_id_;
    Size min_, max_;
    Size size_;                 // what we last asked for (0 = client picks)
    WindowStates states_;
    Decorations decorations_{Decorations::client};
    Decoration* decoration_{nullptr};
    bool want_maximized_{false}, want_fullscreen_{false};
};

class Popup final : public Object<proto::XdgPopup> {
public:
    Popup(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<ShellSurface> xs,
          std::shared_ptr<ShellSurface> parent, PositionerState pos);
    [[nodiscard]] ShellSurface* xdg() const noexcept { return xdg_.lock().get(); }
    [[nodiscard]] ShellSurface* parent() const noexcept { return parent_.lock().get(); }
    void configure();
    [[nodiscard]] Rect placement() const noexcept { return placement_; }
    // Where its window's view origin sits relative to the parent's view.
    [[nodiscard]] Point window_offset() const;
    void dismiss();             // popup_done
    [[nodiscard]] bool grabbing() const noexcept { return grab_; }
    void on_mapped();

protected:
    void request(std::uint16_t op, wire::Args& a) override;
    void on_destroy() override;

private:
    std::weak_ptr<ShellSurface> xdg_, parent_;
    PositionerState pos_;
    Rect placement_;
    bool grab_{false};
    bool dismissed_{false};
};

// zxdg_toplevel_decoration_v1
class Decoration final : public Object<proto::ZxdgToplevelDecorationV1> {
public:
    Decoration(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<Toplevel> t);
    void announce();            // configure(mode) per our policy and the client's wish
protected:
    void request(std::uint16_t op, wire::Args& a) override;
    void on_destroy() override;
private:
    std::weak_ptr<Toplevel> toplevel_;
    std::optional<proto::ZxdgToplevelDecorationV1::Mode> wanted_;
};

// -- Seat -----------------------------------------------------------------------

class Pointer;
class Keyboard;
class DataDevice;
class DataSource;
class CursorRole;

class Seat {
public:
    explicit Seat(Compositor& c);
    ~Seat();
    [[nodiscard]] Compositor& comp() const noexcept { return *comp_; }

    void bind(Client& c, std::uint32_t version, ObjectId id);
    void add_pointer(const std::shared_ptr<Pointer>& p);
    void add_keyboard(const std::shared_ptr<Keyboard>& k);
    void add_data_device(const std::shared_ptr<DataDevice>& d);

    // pointer, from a window
    void pointer_motion(ShellSurface& win, double vx, double vy, std::uint32_t t);
    void pointer_leave(ShellSurface& win);
    void pointer_button(ShellSurface& win, PointerButton b, bool pressed, std::uint32_t t);
    void pointer_scroll(ShellSurface& win, const ScrollEvent& e, std::uint32_t t);
    [[nodiscard]] std::uint32_t last_press_serial() const noexcept { return press_serial_; }

    // keyboard
    void key(std::uint32_t code, bool pressed, std::uint32_t t);
    void modifiers(Modifiers m);
    void release_all();                         // the host lost focus: nothing is held
    void focus_window(ShellSurface* win);         // the host focused this window (null: none)
    void refocus();                             // recompute after a popup grab change
    void keyboard_changed();                    // new layout / repeat settings

    // popup grabs
    void push_popup(const std::shared_ptr<ShellSurface>& p);
    void remove_popup(const ShellSurface* p);
    void dismiss_popups();                      // all of them, topmost first
    [[nodiscard]] bool in_popup_chain(const ShellSurface* w) const;

    // cursor
    void set_cursor(Pointer& from, std::uint32_t serial, std::shared_ptr<Surface> s, Point hotspot);
    void cursor_committed(Surface& s);
    // wp_cursor_shape: a named platform cursor, from the client under the pointer
    void set_cursor_shape(Client& from, CursorShape shape);

    // For protocol extensions that follow the keyboard (text input, the
    // primary selection): called with the old and new focused surface.
    using FocusListener = std::function<void(Surface* before, Surface* now)>;
    void add_focus_listener(FocusListener f) { focus_listeners_.push_back(std::move(f)); }
    [[nodiscard]] Surface* keyboard_focus() const { return kb_focus_.lock().get(); }
    [[nodiscard]] Surface* pointer_focus() const { return ptr_focus_.lock().get(); }
    // the latest input serial a client may cite to ask for focus
    [[nodiscard]] std::uint32_t last_input_serial() const noexcept { return std::max(press_serial_, key_serial_); }
    [[nodiscard]] std::uint32_t last_enter_serial() const noexcept { return enter_serial_; }

    // selection (clipboard)
    void set_selection(Client& from, std::shared_ptr<DataSource> src);
    void source_gone(const DataSource* src);
    void host_clipboard_check();               // pull the host's clipboard if it changed

    // a surface is going away
    void forget(Surface* s);
    // a window's root surface stopped being shown: focus moves on
    void unmapped(Surface* s);

private:
    void send_pointer_enter(Surface& s, double lx, double ly);
    void send_pointer_leave();
    void pointer_frame(Client& c);
    void keyboard_enter(Surface* s);
    void send_modifiers(Client* only = nullptr);
    void offer_selection(Client& to);
    [[nodiscard]] wire::Fd keymap_fd(std::size_t& size);
    template <class F> void each_pointer(Client& c, F&& f);
    template <class F> void each_keyboard(Client& c, F&& f);

    Compositor* comp_;
    std::vector<std::weak_ptr<Pointer>> pointers_;
    std::vector<std::weak_ptr<Keyboard>> keyboards_;
    std::vector<std::weak_ptr<DataDevice>> data_devices_;

    std::weak_ptr<Surface> ptr_focus_;
    std::weak_ptr<ShellSurface> ptr_window_;
    double ptr_x_{0}, ptr_y_{0};
    std::uint32_t buttons_down_{0};
    std::uint32_t enter_serial_{0}, press_serial_{0}, key_serial_{0};
    std::vector<FocusListener> focus_listeners_;

    std::weak_ptr<ShellSurface> focused_window_;
    std::weak_ptr<Surface> kb_focus_;
    std::vector<std::uint32_t> keys_down_;
    std::uint32_t term_shift_{0};   // a Cmd key a terminal gets as Ctrl+Shift (seat.cpp)
    Modifiers mods_;
    std::vector<std::weak_ptr<ShellSurface>> popups_;

    std::weak_ptr<Surface> cursor_surface_;
    Point cursor_hotspot_;
    // surfaces given the wl_pointer.cursor role, by surface uid
    std::vector<std::pair<std::uint64_t, std::unique_ptr<CursorRole>>> cursor_roles_;

    std::weak_ptr<DataSource> selection_;
    bool selection_from_host_{false};
    std::uint64_t host_clip_gen_{0};
    std::string keymap_text_;
    KeyboardInfo kbinfo_;
};

// -- The compositor ---------------------------------------------------------------

struct CompositorOptions {
    // macOS habit: the Command key as Control, so Cmd-C copies in Linux apps.
    bool command_is_control{false};
    // log clients, windows and their scenes to stderr
    bool verbose{false};
};

class Compositor final : public HostSink {
public:
    Compositor(Server& server, Host& host, CompositorOptions opts = {});
    ~Compositor() override;

    [[nodiscard]] Server& server() const noexcept { return *server_; }
    [[nodiscard]] Host& host() const noexcept { return *host_; }
    [[nodiscard]] Seat& seat() noexcept { return seat_; }
    [[nodiscard]] const CompositorOptions& options() const noexcept { return opts_; }
    [[nodiscard]] std::uint64_t next_uid() noexcept { return ++uid_; }

    // frame callbacks fire on the next refresh
    void queue_frame(std::shared_ptr<Callback> cb);
    // ... or now: a client blocked on its frame callback may draw at once
    void fire_frames_now() { tick(); }

    // outputs
    [[nodiscard]] const std::vector<OutputInfo>& outputs() const noexcept { return outputs_; }
    [[nodiscard]] std::vector<std::shared_ptr<Resource>> output_resources(Client& c, std::size_t index) const;
    [[nodiscard]] std::int32_t max_scale() const noexcept;

    // window bookkeeping (Dock icon, quit when idle)
    void window_mapped(ShellSurface& w);
    void window_unmapped(ShellSurface& w);
    [[nodiscard]] std::size_t window_count() const noexcept { return windows_.size(); }
    [[nodiscard]] std::vector<std::shared_ptr<ShellSurface>> windows() const;

    // HostSink
    void host_key(std::uint32_t code, bool pressed, std::uint32_t t) override;
    void host_modifiers(Modifiers m) override;
    void host_text_preedit(std::string text, std::int32_t begin, std::int32_t end) override {
        if (on_text_preedit) on_text_preedit(std::move(text), begin, end);
    }
    void host_text_commit(std::string text) override {
        if (on_text_commit) on_text_commit(std::move(text));
    }
    void host_outputs_changed() override;
    void host_keyboard_changed() override;
    void host_app_active(bool active) override;
    void host_quit() override;

    // set by the text-input extension (extras.cpp)
    std::function<void(std::string, std::int32_t, std::int32_t)> on_text_preedit;
    std::function<void(std::string)> on_text_commit;
    // which output a bound wl_output resource describes
    [[nodiscard]] std::optional<std::size_t> output_index_of(const Resource& r) const;
    // the mapped window whose tree `s` belongs to
    [[nodiscard]] ShellSurface* window_of(Surface* s) const;
    // Somewhere for an extension to keep compositor-wide state (extras.cpp)
    std::shared_ptr<void> extras;

private:
    void add_globals();
    void sync_outputs();
    void tick();

    Server* server_;
    Host* host_;
    CompositorOptions opts_;
    Seat seat_;
    std::uint64_t uid_{0};
    std::vector<OutputInfo> outputs_;
    std::vector<std::uint32_t> output_globals_;
    struct BoundOutput { std::weak_ptr<Resource> r; std::size_t index; };
    std::vector<BoundOutput> bound_outputs_;
    std::vector<std::weak_ptr<Callback>> frames_;
    std::unique_ptr<EventLoop::Source> ticker_;
    std::vector<std::weak_ptr<ShellSurface>> windows_;

    friend class OutputResource;
};

}  // namespace lx::display
