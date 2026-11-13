// src/display/core/extras.cpp -- the protocols a modern desktop app looks
// for beyond the core, each small:
//
//   wp_cursor_shape_v1           named cursors drawn by the platform (crisp
//                                at any scale, the platform's own art)
//   zwp_primary_selection_v1     select-to-copy, middle-click paste
//   xdg_activation_v1            "focus that window" with a token; a request
//                                without a fresh user-input serial asks for
//                                attention instead of stealing focus
//   xdg_system_bell_v1           the bell, as the platform's alert
//   zwp_text_input_v3            input methods: IME composition, dead keys,
//                                press-and-hold accents (host's)
//   zxdg_output_manager_v1       logical output geometry (layout-aware apps)
//   wp_content_type_v1           accepted; a hint we don't act on yet
#include "compositor.hpp"

#include <algorithm>
#include <random>

namespace lx::display {

using namespace proto;

namespace {

// -- cursor shape ---------------------------------------------------------------------

class CursorShapeDevice final : public Object<WpCursorShapeDeviceV1> {
public:
    CursorShapeDevice(Client& c, std::uint32_t v, ObjectId id, Seat& s) : Object(c, v, id), seat_(&s) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WpCursorShapeDeviceV1::Req::set_shape) return;
        const std::uint32_t shape = a.u(1);
        if (shape < 1 || shape > kLastCursorShape) {
            post_error(WpCursorShapeDeviceV1::Error::invalid_shape, "unknown shape " + std::to_string(shape));
            return;
        }
        // stale: from before the pointer last entered (serials wrap)
        if (static_cast<std::int32_t>(a.u(0) - seat_->last_enter_serial()) < 0) return;
        seat_->set_cursor_shape(client(), static_cast<CursorShape>(shape));
    }
private:
    Seat* seat_;
};

class CursorShapeManager final : public Object<WpCursorShapeManagerV1> {
public:
    CursorShapeManager(Client& c, std::uint32_t v, ObjectId id, Seat& s) : Object(c, v, id), seat_(&s) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        // a device per wl_pointer (or tablet tool: same cursor here)
        if (op == WpCursorShapeManagerV1::Req::get_pointer || op == WpCursorShapeManagerV1::Req::get_tablet_tool_v2)
            (void)client().create<CursorShapeDevice>(a.new_id(0), version(), *seat_);
    }
private:
    Seat* seat_;
};

// -- primary selection ------------------------------------------------------------------
//
// Guest-internal: select text in one app, middle-click in another. (macOS has
// no primary selection to bridge to.)

class PrimarySource final : public Object<ZwpPrimarySelectionSourceV1> {
public:
    using Object::Object;
    std::vector<std::string> mimes;
    std::function<void(PrimarySource*)> on_gone;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == ZwpPrimarySelectionSourceV1::Req::offer) mimes.emplace_back(a.str(0));
    }
    void on_destroy() override { if (on_gone) on_gone(this); }
};

class PrimaryOffer final : public Object<ZwpPrimarySelectionOfferV1> {
public:
    PrimaryOffer(Client& c, std::uint32_t v, ObjectId id, std::weak_ptr<PrimarySource> s)
        : Object(c, v, id), source_(std::move(s)) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != ZwpPrimarySelectionOfferV1::Req::receive) return;
        auto fd = a.take_fd(1);
        if (auto s = source_.lock(); s && s->alive())
            s->send(ZwpPrimarySelectionSourceV1::Ev::send, a.str(0), wire::FdArg{fd.get()});
    }
private:
    std::weak_ptr<PrimarySource> source_;
};

struct PrimaryState;

class PrimaryDevice final : public Object<ZwpPrimarySelectionDeviceV1> {
public:
    PrimaryDevice(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<PrimaryState> st)
        : Object(c, v, id), state_(std::move(st)) {}
    void offer(const std::shared_ptr<PrimarySource>& src) {
        if (!src || !src->alive()) { send(ZwpPrimarySelectionDeviceV1::Ev::selection, wire::Null{}); return; }
        auto o = client().create_server_side<PrimaryOffer>(version(), src);
        send(ZwpPrimarySelectionDeviceV1::Ev::data_offer, wire::NewId{o->id()});
        for (const auto& m : src->mimes) o->send(ZwpPrimarySelectionOfferV1::Ev::offer, m);
        send(ZwpPrimarySelectionDeviceV1::Ev::selection, wire::Object{o->id()});
    }
protected:
    void request(std::uint16_t op, wire::Args& a) override;
private:
    std::shared_ptr<PrimaryState> state_;
};

struct PrimaryState : std::enable_shared_from_this<PrimaryState> {
    Seat* seat{nullptr};
    std::weak_ptr<PrimarySource> current;
    std::vector<std::weak_ptr<PrimaryDevice>> devices;

    void offer_to(Client& c) {
        std::erase_if(devices, [](const auto& w) { auto d = w.lock(); return !d || !d->alive(); });
        auto src = current.lock();
        for (auto& w : devices)
            if (auto d = w.lock(); &d->client() == &c) d->offer(src);
    }
    void set(Client& from, const std::shared_ptr<PrimarySource>& src) {
        if (auto old = current.lock(); old && old != src && old->alive())
            old->send(ZwpPrimarySelectionSourceV1::Ev::cancelled);
        current = src;
        if (src) {
            std::weak_ptr<PrimaryState> self = weak_from_this();
            src->on_gone = [self](PrimarySource* s) {
                auto st = self.lock();
                if (!st || st->current.lock().get() != s) return;
                st->current.reset();
                if (Surface* f = st->seat->keyboard_focus()) st->offer_to(f->client());
            };
        }
        if (Surface* f = seat->keyboard_focus()) offer_to(f->client());
        else offer_to(from);
    }
};

void PrimaryDevice::request(std::uint16_t op, wire::Args& a) {
    if (op != ZwpPrimarySelectionDeviceV1::Req::set_selection) return;
    // only the focused client may own the selection (as for the clipboard)
    Surface* f = state_->seat->keyboard_focus();
    if (f && &f->client() != &client()) return;
    state_->set(client(), a.obj(0) ? client().get<PrimarySource>(a.obj(0)) : nullptr);
}

class PrimaryManager final : public Object<ZwpPrimarySelectionDeviceManagerV1> {
public:
    PrimaryManager(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<PrimaryState> st)
        : Object(c, v, id), state_(std::move(st)) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == ZwpPrimarySelectionDeviceManagerV1::Req::create_source) {
            (void)client().create<PrimarySource>(a.new_id(0), version());
        } else if (op == ZwpPrimarySelectionDeviceManagerV1::Req::get_device) {
            if (auto d = client().create<PrimaryDevice>(a.new_id(0), version(), state_)) {
                state_->devices.push_back(d);
                if (Surface* f = state_->seat->keyboard_focus(); f && &f->client() == &client())
                    d->offer(state_->current.lock());
            }
        }
    }
private:
    std::shared_ptr<PrimaryState> state_;
};

// -- activation ---------------------------------------------------------------------------

struct ActivationState {
    // token -> was it minted against a recent input serial of the focused client
    std::map<std::string, bool> tokens;
    std::mt19937_64 rng{std::random_device{}()};
};

class ActivationToken final : public Object<XdgActivationTokenV1> {
public:
    ActivationToken(Client& c, std::uint32_t v, ObjectId id, Compositor& comp, std::shared_ptr<ActivationState> st)
        : Object(c, v, id), comp_(&comp), state_(std::move(st)) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        using R = XdgActivationTokenV1::Req;
        if (op == R::set_serial) {
            serial_ = a.u(0);
            has_serial_ = true;
        } else if (op == R::commit) {
            if (committed_) { post_error(XdgActivationTokenV1::Error::already_used, "token already committed"); return; }
            committed_ = true;
            // Entitled: the request names an input serial no older than the
            // latest one (serials wrap: compare the distance), from the
            // client that has the keyboard -- i.e. the user just clicked or
            // typed in the app asking.
            Surface* f = comp_->seat().keyboard_focus();
            const std::uint32_t age = comp_->seat().last_input_serial() - serial_;
            const bool entitled = has_serial_ && serial_ != 0 && age < 64 && f && &f->client() == &client();
            std::string tok = std::to_string(state_->rng()) + std::to_string(state_->rng());
            if (state_->tokens.size() > 256) state_->tokens.clear();
            state_->tokens[tok] = entitled;
            send(XdgActivationTokenV1::Ev::done, tok);
        }
    }
private:
    Compositor* comp_;
    std::shared_ptr<ActivationState> state_;
    std::uint32_t serial_{0};
    bool has_serial_{false}, committed_{false};
};

class Activation final : public Object<XdgActivationV1> {
public:
    Activation(Client& c, std::uint32_t v, ObjectId id, Compositor& comp, std::shared_ptr<ActivationState> st)
        : Object(c, v, id), comp_(&comp), state_(std::move(st)) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == XdgActivationV1::Req::get_activation_token) {
            (void)client().create<ActivationToken>(a.new_id(0), version(), *comp_, state_);
        } else if (op == XdgActivationV1::Req::activate) {
            const auto it = state_->tokens.find(std::string{a.str(0)});
            const bool entitled = it != state_->tokens.end() && it->second;
            if (it != state_->tokens.end()) state_->tokens.erase(it);
            ShellSurface* w = comp_->window_of(client().get<Surface>(a.obj(1)).get());
            if (!w || !w->window()) return;
            // Focus stealing is the user's call: with no fresh input behind
            // it, the window asks for attention instead (a bouncing Dock icon).
            if (entitled) w->window()->activate();
            else w->window()->request_attention();
        }
    }
private:
    Compositor* comp_;
    std::shared_ptr<ActivationState> state_;
};

// -- bell ----------------------------------------------------------------------------------

class SystemBell final : public Object<XdgSystemBellV1> {
public:
    SystemBell(Client& c, std::uint32_t v, ObjectId id, Compositor& comp) : Object(c, v, id), comp_(&comp) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != XdgSystemBellV1::Req::ring) return;
        comp_->host().bell();
        // a bell from a window you're not looking at also asks for attention
        if (ShellSurface* w = comp_->window_of(a.obj(0) ? client().get<Surface>(a.obj(0)).get() : nullptr);
            w && w->window() && w->toplevel() && !w->toplevel()->states().activated)
            w->window()->request_attention();
    }
private:
    Compositor* comp_;
};

// -- text input -------------------------------------------------------------------------------
//
// One text_input per client seat binding. The focused client's text_input
// gets enter/leave with the keyboard focus; when the app enables it (a text
// field is focused) the host routes typing through its input methods and
// the composed text comes back as preedit/commit, followed by done with the
// count of the client's commits (the protocol's serial).

class TextInput;

struct TextInputState {
    Compositor* comp{nullptr};
    std::vector<std::weak_ptr<TextInput>> inputs;
    std::weak_ptr<TextInput> active;      // enabled, on the focused surface
    std::weak_ptr<Surface> focus;
    void focus_changed(Surface* now);
    void refresh_host();
};

class TextInput final : public Object<ZwpTextInputV3> {
public:
    TextInput(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<TextInputState> st)
        : Object(c, v, id), state_(std::move(st)) {}

    bool enabled{false};
    std::optional<Rect> cursor;           // surface-local
    std::uint32_t commits{0};
    std::weak_ptr<Surface> entered;

    void preedit(const std::string& text, std::int32_t b, std::int32_t e) {
        if (text.empty()) send(ZwpTextInputV3::Ev::preedit_string, wire::Null{}, 0, 0);
        else send(ZwpTextInputV3::Ev::preedit_string, text, b, e);
        send(ZwpTextInputV3::Ev::done, commits);
    }
    void commit_text(const std::string& text) {
        send(ZwpTextInputV3::Ev::preedit_string, wire::Null{}, 0, 0);
        send(ZwpTextInputV3::Ev::commit_string, text);
        send(ZwpTextInputV3::Ev::done, commits);
    }

protected:
    void request(std::uint16_t op, wire::Args& a) override {
        using R = ZwpTextInputV3::Req;
        switch (op) {
            case R::enable: pending_enabled_ = true; pending_cursor_.reset(); break;
            case R::disable: pending_enabled_ = false; break;
            case R::set_cursor_rectangle: pending_cursor_ = Rect{a.i(0), a.i(1), a.i(2), a.i(3)}; break;
            case R::commit:
                ++commits;
                if (pending_enabled_) enabled = *pending_enabled_;
                if (pending_cursor_) cursor = pending_cursor_;
                pending_enabled_.reset();
                state_->refresh_host();
                break;
            default: break;   // surrounding text, content type, change cause: hints
        }
    }
    void on_destroy() override {
        enabled = false;
        state_->refresh_host();
    }

private:
    std::shared_ptr<TextInputState> state_;
    std::optional<bool> pending_enabled_;
    std::optional<Rect> pending_cursor_;
};

void TextInputState::focus_changed(Surface* now) {
    std::erase_if(inputs, [](const auto& w) { auto t = w.lock(); return !t || !t->alive(); });
    for (auto& w : inputs) {
        auto t = w.lock();
        auto was = t->entered.lock();
        const bool mine = now && &t->client() == &now->client();
        if (was && (!mine || was.get() != now)) {
            if (was->alive()) t->send(ZwpTextInputV3::Ev::leave, wire::Object{was->id()});
            t->entered.reset();
            t->enabled = false;   // the protocol: leaving resets the state
        }
        if (mine && t->entered.lock().get() != now) {
            t->send(ZwpTextInputV3::Ev::enter, wire::Object{now->id()});
            t->entered = now->self();
        }
    }
    focus = now ? now->self() : nullptr;
    refresh_host();
}

void TextInputState::refresh_host() {
    std::erase_if(inputs, [](const auto& w) { auto t = w.lock(); return !t || !t->alive(); });
    std::shared_ptr<TextInput> want;
    auto f = focus.lock();
    for (auto& w : inputs)
        if (auto t = w.lock(); t->enabled && f && t->entered.lock() == f) want = t;
    // tell the window that had it, and the one that has it now
    auto old = active.lock();
    active = want;
    auto win_of = [this](const std::shared_ptr<TextInput>& t) -> HostWindow* {
        if (!t) return nullptr;
        ShellSurface* w = comp->window_of(t->entered.lock().get());
        return w ? w->window() : nullptr;
    };
    if (old && old != want)
        if (HostWindow* w = win_of(old)) w->set_text_input(std::nullopt);
    if (want) {
        Surface* s = want->entered.lock().get();
        ShellSurface* sw = comp->window_of(s);
        if (!sw || !sw->window()) return;
        std::optional<Rect> r;
        if (want->cursor) {
            const auto o = sw->origin_of(s);
            r = want->cursor->moved(o.value_or(Point{}));
        }
        sw->window()->set_text_input(r.value_or(Rect{0, 0, 1, 1}));
    }
}

class TextInputManager final : public Object<ZwpTextInputManagerV3> {
public:
    TextInputManager(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<TextInputState> st)
        : Object(c, v, id), state_(std::move(st)) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != ZwpTextInputManagerV3::Req::get_text_input) return;
        auto t = client().create<TextInput>(a.new_id(0), version(), state_);
        if (!t) return;
        state_->inputs.push_back(t);
        if (auto f = state_->focus.lock(); f && &f->client() == &client()) {
            t->send(ZwpTextInputV3::Ev::enter, wire::Object{f->id()});
            t->entered = f;
        }
    }
private:
    std::shared_ptr<TextInputState> state_;
};

// -- xdg_output ------------------------------------------------------------------------------

class XdgOutput final : public Object<ZxdgOutputV1> {
public:
    using Object::Object;
    void describe(const OutputInfo& o) {
        send(ZxdgOutputV1::Ev::logical_position, o.logical.x, o.logical.y);
        send(ZxdgOutputV1::Ev::logical_size, o.logical.w, o.logical.h);
        send(ZxdgOutputV1::Ev::name, o.name);
        send(ZxdgOutputV1::Ev::description, o.description);
        if (version() < 3) send(ZxdgOutputV1::Ev::done);   // v3+: wl_output.done ends it
    }
protected:
    void request(std::uint16_t, wire::Args&) override {}
};

class XdgOutputManager final : public Object<ZxdgOutputManagerV1> {
public:
    XdgOutputManager(Client& c, std::uint32_t v, ObjectId id, Compositor& comp) : Object(c, v, id), comp_(&comp) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != ZxdgOutputManagerV1::Req::get_xdg_output) return;
        auto out = client().any(a.obj(1));
        auto x = client().create<XdgOutput>(a.new_id(0), version());
        if (!x || !out) return;
        const auto idx = comp_->output_index_of(*out);
        if (!idx || *idx >= comp_->outputs().size()) return;
        x->describe(comp_->outputs()[*idx]);
        if (version() >= 3) out->send(WlOutput::Ev::done);
    }
private:
    Compositor* comp_;
};

// -- content type -----------------------------------------------------------------------------

class ContentType final : public Object<WpContentTypeV1> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t, wire::Args&) override {}
};

class ContentTypeManager final : public Object<WpContentTypeManagerV1> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == WpContentTypeManagerV1::Req::get_surface_content_type)
            (void)client().create<ContentType>(a.new_id(0), version());
    }
};

struct Extras {
    std::shared_ptr<PrimaryState> primary = std::make_shared<PrimaryState>();
    std::shared_ptr<ActivationState> activation = std::make_shared<ActivationState>();
    std::shared_ptr<TextInputState> text = std::make_shared<TextInputState>();
};

}  // namespace

void bind_extra_globals(Compositor& comp);
void bind_extra_globals(Compositor& comp) {
    auto ex = std::make_shared<Extras>();
    comp.extras = ex;
    ex->primary->seat = &comp.seat();
    ex->text->comp = &comp;
    std::weak_ptr<Extras> wex = ex;
    comp.seat().add_focus_listener([wex](Surface* before, Surface* now) {
        auto e = wex.lock();
        if (!e) return;
        e->text->focus_changed(now);
        if (now && (!before || &before->client() != &now->client())) e->primary->offer_to(now->client());
    });
    comp.on_text_preedit = [wex](std::string text, std::int32_t b, std::int32_t e) {
        auto x = wex.lock();
        if (auto t = x ? x->text->active.lock() : nullptr) t->preedit(text, b, e);
    };
    comp.on_text_commit = [wex](std::string text) {
        auto x = wex.lock();
        if (auto t = x ? x->text->active.lock() : nullptr) t->commit_text(text);
    };

    Server& s = comp.server();
    Seat& seat = comp.seat();
    s.add_global<WpCursorShapeManagerV1>(1, [&seat](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<CursorShapeManager>(id, v, seat);
    });
    s.add_global<ZwpPrimarySelectionDeviceManagerV1>(1, [ex](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<PrimaryManager>(id, v, ex->primary);
    });
    s.add_global<XdgActivationV1>(1, [&comp, ex](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<Activation>(id, v, comp, ex->activation);
    });
    s.add_global<XdgSystemBellV1>(1, [&comp](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<SystemBell>(id, v, comp);
    });
    s.add_global<ZwpTextInputManagerV3>(1, [ex](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<TextInputManager>(id, v, ex->text);
    });
    s.add_global<ZxdgOutputManagerV1>(3, [&comp](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<XdgOutputManager>(id, v, comp);
    });
    s.add_global<WpContentTypeManagerV1>(1, [](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<ContentTypeManager>(id, v);
    });
}

}  // namespace lx::display
