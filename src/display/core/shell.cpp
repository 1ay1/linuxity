// src/display/core/shell.cpp -- xdg-shell and xdg-decoration: windows.
//
// A toplevel or popup becomes a HostWindow when it maps (first buffer after
// the client acked a configure) and stops being one when it unmaps. From
// then on the window is a two-way street: commits flow out as Scenes, the
// host's resizes, focus and input flow back in through WindowSink.
#include "compositor.hpp"

#include <algorithm>
#include <cstdio>

namespace lx::display {

using namespace proto;

// -- positioner math ------------------------------------------------------------

namespace {

// -1 left/top, 0 center, +1 right/bottom
int horiz(std::uint32_t a) {
    switch (a) { case 3: case 5: case 6: return -1; case 4: case 7: case 8: return 1; default: return 0; }
}
int vert(std::uint32_t a) {
    switch (a) { case 1: case 5: case 7: return -1; case 2: case 6: case 8: return 1; default: return 0; }
}
std::int32_t place_axis(std::int32_t rect_pos, std::int32_t rect_len, int anchor, int gravity, std::int32_t len) {
    const std::int32_t a = anchor < 0 ? rect_pos : anchor > 0 ? rect_pos + rect_len : rect_pos + rect_len / 2;
    return gravity < 0 ? a - len : gravity > 0 ? a : a - len / 2;
}

}  // namespace

Rect PositionerState::place(std::optional<Rect> bounds) const {
    using CA = XdgPositioner::ConstraintAdjustment;
    const int ah = horiz(static_cast<std::uint32_t>(anchor)), av = vert(static_cast<std::uint32_t>(anchor));
    const int gh = horiz(static_cast<std::uint32_t>(gravity)), gv = vert(static_cast<std::uint32_t>(gravity));
    Rect r{place_axis(anchor_rect.x, anchor_rect.w, ah, gh, size.w) + offset.x,
           place_axis(anchor_rect.y, anchor_rect.h, av, gv, size.h) + offset.y, size.w, size.h};
    if (!bounds || bounds->empty()) return r;
    const Rect b = *bounds;
    auto out_x = [&b](const Rect& q) { return q.x < b.x || q.x + q.w > b.x + b.w; };
    auto out_y = [&b](const Rect& q) { return q.y < b.y || q.y + q.h > b.y + b.h; };

    if (out_x(r) && (adjust & CA::flip_x)) {
        Rect f = r;
        f.x = place_axis(anchor_rect.x, anchor_rect.w, -ah, -gh, size.w) - offset.x;
        if (!out_x(f)) r = f;
    }
    if (out_x(r) && (adjust & CA::slide_x)) {
        if (r.x + r.w > b.x + b.w) r.x = b.x + b.w - r.w;
        if (r.x < b.x) r.x = b.x;
    }
    if (out_x(r) && (adjust & CA::resize_x)) {
        const std::int32_t l = std::max(r.x, b.x), rt = std::min(r.x + r.w, b.x + b.w);
        if (rt > l) { r.x = l; r.w = rt - l; }
    }
    if (out_y(r) && (adjust & CA::flip_y)) {
        Rect f = r;
        f.y = place_axis(anchor_rect.y, anchor_rect.h, -av, -gv, size.h) - offset.y;
        if (!out_y(f)) r = f;
    }
    if (out_y(r) && (adjust & CA::slide_y)) {
        if (r.y + r.h > b.y + b.h) r.y = b.y + b.h - r.h;
        if (r.y < b.y) r.y = b.y;
    }
    if (out_y(r) && (adjust & CA::resize_y)) {
        const std::int32_t t = std::max(r.y, b.y), bt = std::min(r.y + r.h, b.y + b.h);
        if (bt > t) { r.y = t; r.h = bt - t; }
    }
    return r;
}

namespace {

class Positioner final : public Object<XdgPositioner> {
public:
    using Object::Object;
    PositionerState state;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        using R = XdgPositioner::Req;
        switch (op) {
            case R::set_size:
                if (a.i(0) <= 0 || a.i(1) <= 0) { post_error(XdgPositioner::Error::invalid_input, "size must be positive"); return; }
                state.size = {a.i(0), a.i(1)};
                break;
            case R::set_anchor_rect:
                if (a.i(2) < 0 || a.i(3) < 0) { post_error(XdgPositioner::Error::invalid_input, "negative anchor rect"); return; }
                state.anchor_rect = {a.i(0), a.i(1), a.i(2), a.i(3)};
                break;
            case R::set_anchor:
                if (a.u(0) > 8) { post_error(XdgPositioner::Error::invalid_input, "bad anchor"); return; }
                state.anchor = static_cast<XdgPositioner::Anchor>(a.u(0));
                break;
            case R::set_gravity:
                if (a.u(0) > 8) { post_error(XdgPositioner::Error::invalid_input, "bad gravity"); return; }
                state.gravity = static_cast<XdgPositioner::Gravity>(a.u(0));
                break;
            case R::set_constraint_adjustment: state.adjust = a.u(0); break;
            case R::set_offset: state.offset = {a.i(0), a.i(1)}; break;
            case R::set_reactive: state.reactive = true; break;
            default: break;   // parent_size / parent_configure: hints
        }
    }
};

class WmBase final : public Object<XdgWmBase> {
public:
    WmBase(Client& c, std::uint32_t v, ObjectId id, Compositor& comp) : Object(c, v, id), comp_(&comp) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        switch (op) {
            case XdgWmBase::Req::create_positioner: (void)client().create<Positioner>(a.new_id(0), version()); break;
            case XdgWmBase::Req::get_xdg_surface: {
                auto s = client().get<Surface>(a.obj(1));
                if (!s) { post_error(XdgWmBase::Error::role, "no such surface"); return; }
                (void)client().create<ShellSurface>(a.new_id(0), version(), *comp_, s);
                break;
            }
            default: break;   // pong: we never ping
        }
    }
private:
    Compositor* comp_;
};

class DecorationManager final : public Object<ZxdgDecorationManagerV1> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != ZxdgDecorationManagerV1::Req::get_toplevel_decoration) return;
        auto t = client().get<Toplevel>(a.obj(1));
        if (!t) return;
        if (t->decoration_object()) {
            post_error(ZxdgToplevelDecorationV1::Error::already_constructed, "toplevel already has a decoration");
            return;
        }
        if (auto d = client().create<Decoration>(a.new_id(0), 1, t)) {
            t->set_decoration_object(d.get());
            ShellSurface* xs = t->xdg();
            if (xs && xs->initial_committed()) { d->announce(); t->configure(); }
        }
    }
};

}  // namespace

void bind_shell_globals(Compositor& comp);
void bind_shell_globals(Compositor& comp) {
    comp.server().add_global<XdgWmBase>(6, [&comp](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<WmBase>(id, v, comp);
    });
    comp.server().add_global<ZxdgDecorationManagerV1>(1, [](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<DecorationManager>(id, v);
    });
}

// -- xdg_surface ------------------------------------------------------------------

ShellSurface::ShellSurface(Client& c, std::uint32_t v, ObjectId id, Compositor& comp, std::shared_ptr<Surface> s)
    : Object(c, v, id), comp_(&comp), surface_(s) {}

ShellSurface::~ShellSurface() = default;

Decorations ShellSurface::decorations() const noexcept {
    return toplevel_ ? toplevel_->decorations() : Decorations::client;
}

Rect ShellSurface::geometry() const {
    Rect extent;
    for (const auto& l : scene_.layers) extent = extent.united(l.rect);
    if (!geometry_) return extent;
    // the window geometry is clipped to the surface tree's extent
    Rect g = *geometry_;
    if (!extent.empty()) {
        const auto l = std::max(g.x, extent.x), t = std::max(g.y, extent.y);
        const auto r = std::min(g.x + g.w, extent.x + extent.w), b = std::min(g.y + g.h, extent.y + extent.h);
        if (r > l && b > t) g = {l, t, r - l, b - t};
    }
    return g;
}

std::uint32_t ShellSurface::send_configure() {
    const std::uint32_t serial = comp_->server().next_serial();
    send(proto::XdgSurface::Ev::configure, serial);
    sent_serials_.push_back(serial);
    return serial;
}

void ShellSurface::request(std::uint16_t op, wire::Args& a) {
    using R = proto::XdgSurface::Req;
    auto s = surface_.lock();
    switch (op) {
        case R::get_toplevel: {
            if (toplevel_ || popup_) { post_error(proto::XdgSurface::Error::already_constructed, "already has a role"); return; }
            if (!s || !s->set_role("xdg_toplevel", this, *this, static_cast<std::uint32_t>(XdgWmBase::Error::role))) return;
            if (auto t = client().create<Toplevel>(a.new_id(0), version(), self())) toplevel_ = t.get();
            break;
        }
        case R::get_popup: {
            if (toplevel_ || popup_) { post_error(proto::XdgSurface::Error::already_constructed, "already has a role"); return; }
            auto parent = a.obj(1) ? client().get<ShellSurface>(a.obj(1)) : nullptr;
            auto pos = client().get<Positioner>(a.obj(2));
            if (!parent) { post_error(XdgWmBase::Error::invalid_popup_parent, "popups need an xdg_surface parent"); return; }
            if (!pos || pos->state.size.empty()) { post_error(XdgWmBase::Error::invalid_positioner, "incomplete positioner"); return; }
            if (!s || !s->set_role("xdg_popup", this, *this, static_cast<std::uint32_t>(XdgWmBase::Error::role))) return;
            if (auto p = client().create<Popup>(a.new_id(0), version(), self(), parent, pos->state)) popup_ = p.get();
            break;
        }
        case R::set_window_geometry:
            if (a.i(2) <= 0 || a.i(3) <= 0) { post_error(proto::XdgSurface::Error::invalid_size, "empty geometry"); return; }
            pending_geometry_ = Rect{a.i(0), a.i(1), a.i(2), a.i(3)};
            break;
        case R::ack_configure: {
            const std::uint32_t serial = a.u(0);
            const auto it = std::find(sent_serials_.begin(), sent_serials_.end(), serial);
            if (it == sent_serials_.end()) break;   // stale or unknown: harmless
            sent_serials_.erase(sent_serials_.begin(), std::next(it));
            acked_any_ = true;
            break;
        }
        default: break;
    }
}

void ShellSurface::role_commit() {
    Surface* s = surface();
    if (!s) return;
    if (pending_geometry_) geometry_ = std::exchange(pending_geometry_, std::nullopt);
    if (!toplevel_ && !popup_) return;
    if (!initial_commit_seen_) {
        if (s->mapped_content()) {
            post_error(proto::XdgSurface::Error::unconfigured_buffer, "buffer before the first configure");
            return;
        }
        initial_commit_seen_ = true;
        if (toplevel_) toplevel_->initial_configure();
        else popup_->configure();
        return;
    }
    if (!acked_any_) {
        if (s->mapped_content())
            post_error(proto::XdgSurface::Error::unconfigured_buffer, "buffer before acking a configure");
        return;
    }
    if (s->mapped_content() && !window_) map();
    else if (!s->mapped_content() && window_) unmap();
    else if (window_) schedule_present();
}

void ShellSurface::build_scene(Scene& out, std::vector<std::weak_ptr<Surface>>& who) const {
    out.layers.clear();
    who.clear();
    auto visit = [&](auto&& self_fn, Surface& s, Point at) -> void {
        auto add_self = [&] {
            if (!s.pixels()) return;
            out.layers.push_back({s.uid(), {at.x, at.y, s.size().w, s.size().h}, s.pixels(), s.scale(), false});
            who.push_back(s.self());
        };
        if (s.stack().empty()) { add_self(); return; }
        for (const auto& w : s.stack()) {
            auto c = w.lock();
            if (!c) continue;
            if (c.get() == &s) add_self();
            else self_fn(self_fn, *c, at + c->position());
        }
    };
    if (Surface* s = surface()) visit(visit, *s, Point{});
    Rect extent;
    for (const auto& l : out.layers) extent = extent.united(l.rect);
    // keep geometry() consistent with this scene
    Rect g = extent;
    if (geometry_) {
        g = *geometry_;
        const auto l = std::max(g.x, extent.x), t = std::max(g.y, extent.y);
        const auto r = std::min(g.x + g.w, extent.x + extent.w), b = std::min(g.y + g.h, extent.y + extent.h);
        if (r > l && b > t) g = {l, t, r - l, b - t};
    }
    out.geometry = g;
    out.view = decorations() == Decorations::server ? g : extent;
}

void ShellSurface::schedule_present() {
    if (present_scheduled_ || !window_) return;
    present_scheduled_ = true;
    std::weak_ptr<Resource> weak = weak_from_this();
    comp_->server().loop().defer([weak] {
        auto r = weak.lock();
        if (!r || !r->alive()) return;
        auto* xs = static_cast<ShellSurface*>(r.get());
        xs->present_scheduled_ = false;
        xs->present_now();
    });
}

void ShellSurface::present_now() {
    if (!window_) return;
    const Rect old_view = scene_.view, old_geom = scene_.geometry;
    build_scene(scene_, scene_surfaces_);
    if (popup_ && (old_view != scene_.view || old_geom != scene_.geometry)) window_->move_popup(popup_->window_offset());
    window_->present(scene_);
}

void ShellSurface::map() {
    WindowSpec spec;
    build_scene(scene_, scene_surfaces_);
    if (toplevel_) {
        spec.kind = WindowSpec::Kind::toplevel;
        spec.decorations = toplevel_->decorations();
        spec.title = toplevel_->title();
        spec.app_id = toplevel_->app_id();
        spec.min = toplevel_->min_size();
        spec.max = toplevel_->max_size();
    } else {
        ShellSurface* parent = popup_->parent();
        if (!parent || !parent->window()) {   // a popup of nothing on screen
            popup_->dismiss();
            return;
        }
        spec.kind = WindowSpec::Kind::popup;
        spec.parent = parent->window();
        spec.at = popup_->window_offset();
    }
    window_ = comp_->host().create_window(spec, *this);
    if (comp_->options().verbose)
        std::fprintf(stderr, "linuxity-display: map %s \"%s\" view %dx%d+%d+%d, %zu layers%s\n",
                     toplevel_ ? "toplevel" : "popup", toplevel_ ? toplevel_->title().c_str() : "",
                     scene_.view.w, scene_.view.h, scene_.view.x, scene_.view.y, scene_.layers.size(),
                     window_ ? "" : " (host refused)");
    if (!window_) return;
    window_->present(scene_);
    comp_->window_mapped(*this);
    host_output(output_);
    if (toplevel_) toplevel_->on_mapped();
    else popup_->on_mapped();
}

void ShellSurface::unmap() {
    if (window_) {
        comp_->seat().remove_popup(this);
        if (Surface* s = surface()) comp_->seat().unmapped(s);
        window_.reset();
        comp_->window_unmapped(*this);
    }
    initial_commit_seen_ = false;
    acked_any_ = false;
    sent_serials_.clear();
}

Surface* ShellSurface::pick(double vx, double vy, double& lx, double& ly) const {
    const double px = vx + scene_.view.x, py = vy + scene_.view.y;
    for (std::size_t k = scene_.layers.size(); k-- > 0;) {
        const Rect& r = scene_.layers[k].rect;
        if (!r.contains(px, py)) continue;
        auto s = scene_surfaces_[k].lock();
        if (!s) continue;
        const double sx = px - r.x, sy = py - r.y;
        if (!s->accepts_input(sx, sy)) continue;
        lx = sx;
        ly = sy;
        return s.get();
    }
    return nullptr;
}

std::optional<Point> ShellSurface::origin_of(const Surface* s) const {
    for (std::size_t k = 0; k < scene_.layers.size(); ++k)
        if (scene_surfaces_[k].lock().get() == s) return scene_.layers[k].rect.origin() - scene_.view.origin();
    return std::nullopt;
}

void ShellSurface::host_configure(Size size, WindowStates states) {
    if (toplevel_) toplevel_->host_wants(size, states);
}
void ShellSurface::host_close() {
    if (toplevel_) toplevel_->send(XdgToplevel::Ev::close);
}
void ShellSurface::host_focus(bool focused) {
    if (toplevel_) {
        WindowStates st = toplevel_->states();
        st.activated = focused;
        toplevel_->host_wants({-1, -1}, st);
    }
    comp_->seat().focus_window(focused ? this : nullptr);
}
void ShellSurface::host_pointer_motion(double x, double y, std::uint32_t t) { comp_->seat().pointer_motion(*this, x, y, t); }
void ShellSurface::host_pointer_leave() { comp_->seat().pointer_leave(*this); }
void ShellSurface::host_pointer_button(PointerButton b, bool pressed, std::uint32_t t) {
    comp_->seat().pointer_button(*this, b, pressed, t);
}
void ShellSurface::host_scroll(const ScrollEvent& e, std::uint32_t t) { comp_->seat().pointer_scroll(*this, e, t); }
void ShellSurface::host_output(std::size_t index) {
    if (index >= comp_->outputs().size()) index = 0;
    output_ = index;
    Surface* s = surface();
    if (!s || comp_->outputs().empty()) return;
    s->set_outputs(comp_->output_resources(client(), index), comp_->outputs()[index].scale);
}

void ShellSurface::on_destroy() {
    unmap();
    if (Surface* s = surface()) s->clear_role_impl(this);
}

// -- xdg_toplevel ---------------------------------------------------------------

Toplevel::Toplevel(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<ShellSurface> xs)
    : Object(c, v, id), xdg_(xs) {}

void Toplevel::request(std::uint16_t op, wire::Args& a) {
    using R = XdgToplevel::Req;
    ShellSurface* xs = xdg();
    HostWindow* w = xs ? xs->window() : nullptr;
    switch (op) {
        case R::set_title:
            title_ = a.str(0);
            if (w) w->set_title(title_);
            break;
        case R::set_app_id: app_id_ = a.str(0); break;
        case R::move: if (w) w->begin_move(); break;
        case R::resize:
            if (a.u(2) > 10 || a.u(2) == 3 || a.u(2) == 7) { post_error(XdgToplevel::Error::invalid_resize_edge, "bad edge"); return; }
            if (w) w->begin_resize(a.u(2));
            break;
        case R::set_max_size:
        case R::set_min_size: {
            if (a.i(0) < 0 || a.i(1) < 0) { post_error(XdgToplevel::Error::invalid_size, "negative size"); return; }
            (op == R::set_max_size ? max_ : min_) = Size{a.i(0), a.i(1)};
            if (w) w->set_size_limits(min_, max_);
            break;
        }
        case R::set_maximized:
        case R::unset_maximized:
            want_maximized_ = op == R::set_maximized;
            if (w) w->set_maximized(want_maximized_);
            else if (xs && xs->initial_committed()) { states_.maximized = want_maximized_; configure(); }
            break;
        case R::set_fullscreen:
        case R::unset_fullscreen:
            want_fullscreen_ = op == R::set_fullscreen;
            if (w) w->set_fullscreen(want_fullscreen_);
            break;
        case R::set_minimized:
            if (w) w->minimize();
            break;
        default: break;   // set_parent, show_window_menu
    }
}

void Toplevel::initial_configure() {
    Compositor& comp = xdg()->comp();
    if (version() >= 4 && !comp.outputs().empty()) {
        const Rect wa = comp.outputs().front().logical;
        send(XdgToplevel::Ev::configure_bounds, wa.w, wa.h);
    }
    if (version() >= 5) {
        const std::uint32_t caps[] = {static_cast<std::uint32_t>(XdgToplevel::WmCapabilities::maximize),
                                      static_cast<std::uint32_t>(XdgToplevel::WmCapabilities::fullscreen),
                                      static_cast<std::uint32_t>(XdgToplevel::WmCapabilities::minimize)};
        send(XdgToplevel::Ev::wm_capabilities, wire::Array{std::as_bytes(std::span{caps})});
    }
    if (decoration_) decoration_->announce();
    configure();
}

void Toplevel::configure() {
    ShellSurface* xs = xdg();
    if (!xs) return;
    std::vector<std::uint32_t> st;
    if (states_.maximized) st.push_back(static_cast<std::uint32_t>(XdgToplevel::State::maximized));
    if (states_.fullscreen) st.push_back(static_cast<std::uint32_t>(XdgToplevel::State::fullscreen));
    if (states_.resizing) st.push_back(static_cast<std::uint32_t>(XdgToplevel::State::resizing));
    if (states_.activated) st.push_back(static_cast<std::uint32_t>(XdgToplevel::State::activated));
    // a native title bar: tell the client its edges are the platform's
    if (decorations_ == Decorations::server && version() >= 2)
        for (auto s : {XdgToplevel::State::tiled_left, XdgToplevel::State::tiled_right,
                       XdgToplevel::State::tiled_top, XdgToplevel::State::tiled_bottom})
            st.push_back(static_cast<std::uint32_t>(s));
    send(XdgToplevel::Ev::configure, size_.w, size_.h, wire::Array{std::as_bytes(std::span{st})});
    xs->send_configure();
}

void Toplevel::host_wants(Size size, WindowStates states) {
    if (size.w < 0) size = size_;   // state-only change
    if (size == size_ && states == states_) return;
    size_ = size;
    states_ = states;
    ShellSurface* xs = xdg();
    if (xs && xs->mapped()) configure();
}

void Toplevel::set_decorations(Decorations d) {
    if (decorations_ == d) return;
    decorations_ = d;
    if (ShellSurface* xs = xdg(); xs && xs->window()) {
        xs->window()->set_decorations(d);
        xs->schedule_present();
    }
}

void Toplevel::on_mapped() {
    ShellSurface* xs = xdg();
    if (!xs || !xs->window()) return;
    if (want_maximized_) xs->window()->set_maximized(true);
    if (want_fullscreen_) xs->window()->set_fullscreen(true);
}

void Toplevel::on_destroy() {
    if (decoration_) decoration_ = nullptr;
    if (ShellSurface* xs = xdg()) {
        xs->unmap();
        xs->attach_toplevel(nullptr);
    }
}

// -- xdg_popup ----------------------------------------------------------------------

Popup::Popup(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<ShellSurface> xs,
             std::shared_ptr<ShellSurface> parent, PositionerState pos)
    : Object(c, v, id), xdg_(xs), parent_(parent), pos_(pos) {}

void Popup::configure() {
    ShellSurface* xs = xdg();
    ShellSurface* p = parent();
    if (!xs) return;
    std::optional<Rect> bounds;
    if (p && p->window()) {
        // the screen's work area, in the parent's window-geometry space
        const Rect wa = p->window()->work_area();
        bounds = wa.moved(p->view().origin() - p->geometry().origin());
    }
    placement_ = pos_.place(bounds);
    send(XdgPopup::Ev::configure, placement_.x, placement_.y, placement_.w, placement_.h);
    xs->send_configure();
}

Point Popup::window_offset() const {
    ShellSurface* xs = xdg();
    ShellSurface* p = parent();
    if (!xs || !p) return {};
    return p->geometry().origin() + placement_.origin() - xs->geometry().origin() + xs->view().origin() -
           p->view().origin();
}

void Popup::request(std::uint16_t op, wire::Args& a) {
    switch (op) {
        case XdgPopup::Req::grab: grab_ = true; break;
        case XdgPopup::Req::reposition: {
            auto pos = client().get<Positioner>(a.obj(0));
            if (!pos) return;
            pos_ = pos->state;
            if (version() >= 3) send(XdgPopup::Ev::repositioned, a.u(1));
            configure();
            if (ShellSurface* xs = xdg(); xs && xs->window()) xs->window()->move_popup(window_offset());
            break;
        }
        default: break;
    }
}

void Popup::dismiss() {
    if (dismissed_) return;
    dismissed_ = true;
    send(XdgPopup::Ev::popup_done);
    if (ShellSurface* xs = xdg()) xs->unmap();
}

void Popup::on_mapped() {
    ShellSurface* xs = xdg();
    if (grab_ && xs) xs->comp().seat().push_popup(xs->self());
}

void Popup::on_destroy() {
    if (ShellSurface* xs = xdg()) {
        xs->unmap();
        xs->attach_popup(nullptr);
    }
}

// -- decorations ----------------------------------------------------------------------

Decoration::Decoration(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<Toplevel> t)
    : Object(c, v, id), toplevel_(t) {}

void Decoration::announce() {
    using Mode = ZxdgToplevelDecorationV1::Mode;
    // Policy: the client's wish; with none, native decorations.
    const Mode mode = wanted_.value_or(Mode::server_side);
    if (auto t = toplevel_.lock()) t->set_decorations(mode == Mode::server_side ? Decorations::server : Decorations::client);
    send(ZxdgToplevelDecorationV1::Ev::configure, mode);
}

void Decoration::request(std::uint16_t op, wire::Args& a) {
    using R = ZxdgToplevelDecorationV1::Req;
    if (op == R::set_mode) {
        if (a.u(0) != 1 && a.u(0) != 2) { post_error(ZxdgToplevelDecorationV1::Error::invalid_mode, "bad mode"); return; }
        wanted_ = static_cast<ZxdgToplevelDecorationV1::Mode>(a.u(0));
    } else if (op == R::unset_mode) {
        wanted_.reset();
    } else {
        return;
    }
    auto t = toplevel_.lock();
    ShellSurface* xs = t ? t->xdg() : nullptr;
    if (xs && xs->initial_committed()) {
        announce();
        t->configure();
    }
}

void Decoration::on_destroy() {
    if (auto t = toplevel_.lock()) {
        t->set_decoration_object(nullptr);
        t->set_decorations(Decorations::client);
    }
}

}  // namespace lx::display
