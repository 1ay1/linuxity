// src/display/core/scale.cpp -- sharp pixels at any scale: wp_viewporter,
// wp_fractional_scale_v1 and wp_single_pixel_buffer_v1.
//
// A 1.5x screen with only integer buffer scales means rendering at 2x and
// letting the host shrink it -- blurry text, 78% more pixels to copy. With
// fractional_scale the client learns the exact scale, renders a buffer of
// exactly the window's device pixels, and says through a viewport that the
// buffer covers its logical size. Single-pixel buffers let toolkits paint
// solid backgrounds and shadows-of-nothing with no pixels at all.
#include "compositor.hpp"

#include <cmath>

namespace lx::display {

using namespace proto;

class FractionalScale final : public Object<WpFractionalScaleV1> {
public:
    FractionalScale(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<Surface> s)
        : Object(c, v, id), surface_(s) {}
    void surface_gone() { surface_.reset(); }
protected:
    void request(std::uint16_t, wire::Args&) override {}
    void on_destroy() override {
        if (auto s = surface_.lock()) s->set_fractional(nullptr);
    }
private:
    std::weak_ptr<Surface> surface_;
};

void send_fractional_scale(FractionalScale& f, double scale) {
    if (scale <= 0) return;
    f.send(WpFractionalScaleV1::Ev::preferred_scale, static_cast<std::uint32_t>(std::lround(scale * 120.0)));
}

class ViewportObj final : public Object<WpViewport> {
public:
    ViewportObj(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<Surface> s)
        : Object(c, v, id), surface_(s) {}
    void surface_gone() { surface_.reset(); }
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        auto s = surface_.lock();
        if (op == WpViewport::Req::destroy) return;   // on_destroy unsets it
        if (!s) {
            post_error(WpViewport::Error::no_surface, "the surface is gone");
            return;
        }
        Viewport v = s->pending_viewport_or_current();
        if (op == WpViewport::Req::set_source) {
            const double x = a.f(0).value(), y = a.f(1).value(), w = a.f(2).value(), h = a.f(3).value();
            if (x == -1 && y == -1 && w == -1 && h == -1) v.src.reset();
            else if (x < 0 || y < 0 || w <= 0 || h <= 0) { post_error(WpViewport::Error::bad_value, "bad source"); return; }
            else v.src = SourceRect{x, y, w, h};
        } else if (op == WpViewport::Req::set_destination) {
            const std::int32_t w = a.i(0), h = a.i(1);
            if (w == -1 && h == -1) v.dst.reset();
            else if (w <= 0 || h <= 0) { post_error(WpViewport::Error::bad_value, "bad destination"); return; }
            else v.dst = Size{w, h};
        }
        s->set_pending_viewport(std::move(v));
    }
    void on_destroy() override {
        if (auto s = surface_.lock()) {
            s->set_pending_viewport({});
            s->set_has_viewport(false);
            s->set_viewport_obj(nullptr);
        }
    }
private:
    std::weak_ptr<Surface> surface_;
};

void Surface::surface_gone_hooks() {
    if (fractional_) fractional_->surface_gone();
    if (viewport_obj_) viewport_obj_->surface_gone();
    fractional_ = nullptr;
    viewport_obj_ = nullptr;
}

namespace {

class Viewporter final : public Object<WpViewporter> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WpViewporter::Req::get_viewport) return;
        auto s = client().get<Surface>(a.obj(1));
        if (!s) return;
        if (s->has_viewport()) { post_error(WpViewporter::Error::viewport_exists, "surface already has a viewport"); return; }
        if (auto v = client().create<ViewportObj>(a.new_id(0), 1, s)) {
            s->set_has_viewport(true);
            s->set_viewport_obj(v.get());
        }
    }
};

class FractionalScaleManager final : public Object<WpFractionalScaleManagerV1> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WpFractionalScaleManagerV1::Req::get_fractional_scale) return;
        auto s = client().get<Surface>(a.obj(1));
        if (!s) return;
        if (s->fractional()) {
            post_error(WpFractionalScaleManagerV1::Error::fractional_scale_exists, "surface already has one");
            return;
        }
        if (auto f = client().create<FractionalScale>(a.new_id(0), 1, s)) {
            s->set_fractional(f.get());
            send_fractional_scale(*f, s->output_scale());   // already on an output: say so now
        }
    }
};

class SinglePixelBufferManager final : public Object<WpSinglePixelBufferManagerV1> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WpSinglePixelBufferManagerV1::Req::create_u32_rgba_buffer) return;
        // full-range u32 channels, premultiplied: down to 8 bits, BGRA order
        auto c8 = [](std::uint32_t v) { return static_cast<std::uint8_t>(v >> 24); };
        (void)client().create<Buffer>(a.new_id(0), 1,
                                      std::array<std::uint8_t, 4>{c8(a.u(3)), c8(a.u(2)), c8(a.u(1)), c8(a.u(4))});
    }
};

}  // namespace

void bind_scale_globals(Compositor& comp);
void bind_scale_globals(Compositor& comp) {
    Server& s = comp.server();
    s.add_global<WpViewporter>(1, [](Client& c, std::uint32_t v, ObjectId id) { (void)c.create<Viewporter>(id, v); });
    s.add_global<WpFractionalScaleManagerV1>(1, [](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<FractionalScaleManager>(id, v);
    });
    s.add_global<WpSinglePixelBufferManagerV1>(1, [](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<SinglePixelBufferManager>(id, v);
    });
}

}  // namespace lx::display
