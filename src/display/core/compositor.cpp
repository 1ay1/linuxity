// src/display/core/compositor.cpp -- globals, wl_output, frame pacing, and
// the host's global events.
#include "compositor.hpp"

#include <algorithm>
#include <chrono>

namespace lx::display {

using namespace proto;

void bind_surface_globals(Compositor& comp);
void bind_shell_globals(Compositor& comp);
void bind_seat_globals(Compositor& comp);

class OutputResource final : public Object<WlOutput> {
public:
    OutputResource(Client& c, std::uint32_t v, ObjectId id, Compositor& comp, std::size_t index)
        : Object(c, v, id), comp_(&comp), index_(index) {}
    void describe(const OutputInfo& o) {
        send(WlOutput::Ev::geometry, o.logical.x, o.logical.y, o.physical_mm.w, o.physical_mm.h,
             WlOutput::Subpixel::unknown, o.make, o.model, WlOutput::Transform::normal);
        send(WlOutput::Ev::mode, WlOutput::Mode::current | WlOutput::Mode::preferred, o.pixels.w, o.pixels.h, o.refresh_mhz);
        send(WlOutput::Ev::scale, o.scale);
        send(WlOutput::Ev::name, o.name);
        send(WlOutput::Ev::description, o.description);
        send(WlOutput::Ev::done);
    }
    [[nodiscard]] std::size_t index() const noexcept { return index_; }
protected:
    void request(std::uint16_t, wire::Args&) override {}
private:
    Compositor* comp_;
    std::size_t index_;
};

Compositor::Compositor(Server& server, Host& host, CompositorOptions opts)
    : server_(&server), host_(&host), opts_(opts), seat_(*this) {
    host_->attach(*this);
    add_globals();
}

Compositor::~Compositor() {
    // Clients' objects point into us (seat, outputs): end them first.
    server_->on_client_gone = nullptr;
    server_->disconnect_all();
    ticker_.reset();
}

void Compositor::add_globals() {
    bind_surface_globals(*this);
    bind_shell_globals(*this);
    bind_seat_globals(*this);
    sync_outputs();
}

void Compositor::sync_outputs() {
    auto now = host_->outputs();
    if (now.empty()) {
        OutputInfo o;
        o.name = "HEADLESS-1";
        o.description = "linuxity headless output";
        o.logical = {0, 0, 1920, 1080};
        o.pixels = {1920, 1080};
        now.push_back(o);
    }
    if (now == outputs_) return;
    for (auto name : output_globals_) server_->remove_global(name);
    output_globals_.clear();
    outputs_ = std::move(now);
    for (std::size_t k = 0; k < outputs_.size(); ++k) {
        output_globals_.push_back(server_->add_global<WlOutput>(4, [this, k](Client& c, std::uint32_t v, ObjectId id) {
            if (k >= outputs_.size()) return;
            auto r = c.create<OutputResource>(id, v, *this, k);
            if (!r) return;
            r->describe(outputs_[k]);
            std::erase_if(bound_outputs_, [](const BoundOutput& b) { return b.r.expired(); });
            bound_outputs_.push_back({r, k});
            // windows already on this output enter it now
            for (auto& w : windows())
                if (&w->client() == &c) w->host_output(k);
        }));
    }
}

std::vector<std::shared_ptr<Resource>> Compositor::output_resources(Client& c, std::size_t index) const {
    std::vector<std::shared_ptr<Resource>> out;
    for (const auto& b : bound_outputs_)
        if (auto r = b.r.lock(); r && r->alive() && b.index == index && &r->client() == &c) out.push_back(r);
    return out;
}

std::int32_t Compositor::max_scale() const noexcept {
    std::int32_t s = 1;
    for (const auto& o : outputs_) s = std::max(s, o.scale);
    return s;
}

// -- frames ------------------------------------------------------------------------

void Compositor::queue_frame(std::shared_ptr<Callback> cb) {
    frames_.push_back(cb);
    if (ticker_) return;
    std::int32_t mhz = 60000;
    for (const auto& o : outputs_) mhz = std::max(mhz, o.refresh_mhz);
    const auto period = std::chrono::microseconds(1'000'000'000LL / std::max(mhz, 1000));
    ticker_ = server_->loop().every(period, [this] { tick(); });
}

void Compositor::tick() {
    auto due = std::move(frames_);
    frames_.clear();
    const std::uint32_t t = server_->now_ms();
    for (auto& w : due)
        if (auto cb = w.lock(); cb && cb->alive()) cb->fire(t);
    if (frames_.empty()) ticker_.reset();   // idle: no wakeups
}

// -- windows -------------------------------------------------------------------------

void Compositor::window_mapped(ShellSurface& w) {
    windows_.push_back(w.self());
    if (w.toplevel()) host_->set_has_windows(true);
}

void Compositor::window_unmapped(ShellSurface& w) {
    std::erase_if(windows_, [&w](const auto& p) { auto s = p.lock(); return !s || s.get() == &w; });
    const bool any = std::any_of(windows_.begin(), windows_.end(), [](const auto& p) {
        auto s = p.lock();
        return s && s->toplevel();
    });
    if (!any) host_->set_has_windows(false);
}

std::vector<std::shared_ptr<ShellSurface>> Compositor::windows() const {
    std::vector<std::shared_ptr<ShellSurface>> out;
    for (const auto& w : windows_)
        if (auto s = w.lock(); s && s->alive()) out.push_back(s);
    return out;
}

// -- HostSink -----------------------------------------------------------------------------

void Compositor::host_key(std::uint32_t code, bool pressed, std::uint32_t t) { seat_.key(code, pressed, t); }
void Compositor::host_modifiers(Modifiers m) { seat_.modifiers(m); }

void Compositor::host_outputs_changed() {
    sync_outputs();
    for (auto& w : windows()) w->host_output(0);
}

void Compositor::host_keyboard_changed() { seat_.keyboard_changed(); }

void Compositor::host_app_active(bool active) {
    if (!active) {
        seat_.dismiss_popups();
        seat_.release_all();
    } else {
        seat_.host_clipboard_check();
    }
}

void Compositor::host_quit() {
    // Ask every app to close its windows (they may save first). The host
    // ends the process on its own schedule; the requests go out on the
    // next flush, before it does.
    for (auto& w : windows())
        if (w->toplevel()) w->toplevel()->send(XdgToplevel::Ev::close);
}

}  // namespace lx::display
