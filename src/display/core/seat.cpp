// src/display/core/seat.cpp -- wl_seat: pointer, keyboard, and the
// clipboard (wl_data_device), bridged to the host's.
//
// The keymap is sent as XKB include statements (RMLVO), not a compiled
// map: every client compiles it against its own /usr/share/X11/xkb, so the
// core needs no libxkbcommon and the guest's xkb data decides the details.
// The modifier masks below are the standard real-modifier bits every such
// keymap gets (Shift Lock Control Mod1..Mod5).
#include "compositor.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <unistd.h>

namespace lx::display {

using namespace proto;

namespace {

constexpr std::uint32_t kShift = 1u << 0, kLock = 1u << 1, kControl = 1u << 2, kMod1 = 1u << 3,
                        kMod2 = 1u << 4, kMod4 = 1u << 6;

constexpr std::uint32_t KEY_LEFTCTRL = 29, KEY_RIGHTCTRL = 97, KEY_LEFTMETA = 125, KEY_RIGHTMETA = 126;

constexpr std::string_view kTextMimes[] = {"text/plain;charset=utf-8", "text/plain", "UTF8_STRING", "TEXT", "STRING"};
[[nodiscard]] bool is_text_mime(std::string_view m) {
    return std::find(std::begin(kTextMimes), std::end(kTextMimes), m) != std::end(kTextMimes);
}

// Write a string into an fd without blocking the compositor, then close it.
class FdWriter : public std::enable_shared_from_this<FdWriter> {
public:
    static void start(EventLoop& loop, wire::Fd fd, std::string data) {
        auto w = std::make_shared<FdWriter>();
        w->fd_ = std::move(fd);
        w->data_ = std::move(data);
        (void)::fcntl(w->fd_.get(), F_SETFL, ::fcntl(w->fd_.get(), F_GETFL) | O_NONBLOCK);
        w->src_ = loop.on_writable(w->fd_.get(), [w] { w->pump(); });
    }
private:
    void pump() {
        while (at_ < data_.size()) {
            const ssize_t n = ::write(fd_.get(), data_.data() + at_, data_.size() - at_);
            if (n > 0) { at_ += static_cast<std::size_t>(n); continue; }
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
            break;
        }
        auto keep = shared_from_this();
        src_.reset();   // drops the loop's reference: we end here
    }
    wire::Fd fd_;
    std::string data_;
    std::size_t at_{0};
    std::unique_ptr<EventLoop::Source> src_;
};

// Read an fd to EOF without blocking, then hand the bytes over.
class FdReader : public std::enable_shared_from_this<FdReader> {
public:
    static void start(EventLoop& loop, wire::Fd fd, std::function<void(std::string)> done) {
        auto r = std::make_shared<FdReader>();
        r->fd_ = std::move(fd);
        r->done_ = std::move(done);
        (void)::fcntl(r->fd_.get(), F_SETFL, ::fcntl(r->fd_.get(), F_GETFL) | O_NONBLOCK);
        r->src_ = loop.on_readable(r->fd_.get(), [r] { r->pump(); });
    }
private:
    void pump() {
        char buf[16384];
        for (;;) {
            const ssize_t n = ::read(fd_.get(), buf, sizeof buf);
            if (n > 0) {
                data_.append(buf, static_cast<std::size_t>(n));
                if (data_.size() > (16u << 20)) break;   // not a clipboard any more
                continue;
            }
            if (n < 0 && (errno == EAGAIN || errno == EINTR)) return;
            break;
        }
        auto keep = shared_from_this();
        src_.reset();
        if (done_) done_(std::move(data_));
    }
    wire::Fd fd_;
    std::string data_;
    std::function<void(std::string)> done_;
    std::unique_ptr<EventLoop::Source> src_;
};

}  // namespace

// -- objects ------------------------------------------------------------------

class Pointer final : public Object<WlPointer> {
public:
    Pointer(Client& c, std::uint32_t v, ObjectId id, Seat& s) : Object(c, v, id), seat_(&s) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WlPointer::Req::set_cursor) return;
        auto surf = a.obj(1) ? client().get<Surface>(a.obj(1)) : nullptr;
        seat_->set_cursor(*this, a.u(0), surf, {a.i(2), a.i(3)});
    }
private:
    Seat* seat_;
};

class Keyboard final : public Object<WlKeyboard> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t, wire::Args&) override {}
};

class Touch final : public Object<WlTouch> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t, wire::Args&) override {}
};

class SeatObj final : public Object<WlSeat> {
public:
    SeatObj(Client& c, std::uint32_t v, ObjectId id, Seat& s) : Object(c, v, id), seat_(&s) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        switch (op) {
            case WlSeat::Req::get_pointer:
                if (auto p = client().create<Pointer>(a.new_id(0), version(), *seat_)) seat_->add_pointer(p);
                break;
            case WlSeat::Req::get_keyboard:
                if (auto k = client().create<Keyboard>(a.new_id(0), version())) seat_->add_keyboard(k);
                break;
            case WlSeat::Req::get_touch: (void)client().create<Touch>(a.new_id(0), version()); break;
            default: break;
        }
    }
private:
    Seat* seat_;
};

class DataSource final : public Object<WlDataSource> {
public:
    DataSource(Client& c, std::uint32_t v, ObjectId id, Seat& s) : Object(c, v, id), seat_(&s) {}
    std::vector<std::string> mimes;
    void send_to(std::string_view mime, wire::Fd fd) { send(WlDataSource::Ev::send, mime, wire::FdArg{fd.get()}); }
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == WlDataSource::Req::offer) mimes.emplace_back(a.str(0));
    }
    void on_destroy() override { seat_->source_gone(this); }
private:
    Seat* seat_;
};

class DataOffer final : public Object<WlDataOffer> {
public:
    DataOffer(Client& c, std::uint32_t v, ObjectId id, std::weak_ptr<DataSource> src,
              std::shared_ptr<const std::string> host_text)
        : Object(c, v, id), source_(std::move(src)), host_text_(std::move(host_text)) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WlDataOffer::Req::receive) return;
        auto fd = a.take_fd(1);
        if (host_text_) {
            FdWriter::start(client().server().loop(), std::move(fd), *host_text_);
        } else if (auto s = source_.lock(); s && s->alive()) {
            s->send_to(a.str(0), std::move(fd));
        }
    }
private:
    std::weak_ptr<DataSource> source_;
    std::shared_ptr<const std::string> host_text_;
};

class DataDevice final : public Object<WlDataDevice> {
public:
    DataDevice(Client& c, std::uint32_t v, ObjectId id, Seat& s) : Object(c, v, id), seat_(&s) {}
    void offer(const std::shared_ptr<DataSource>& src, const std::shared_ptr<const std::string>& host_text,
               const std::vector<std::string>& mimes) {
        if (!src && !host_text) { send(WlDataDevice::Ev::selection, wire::Null{}); return; }
        auto o = client().create_server_side<DataOffer>(version(), src, host_text);
        send(WlDataDevice::Ev::data_offer, wire::NewId{o->id()});
        for (const auto& m : mimes) o->send(WlDataOffer::Ev::offer, m);
        send(WlDataDevice::Ev::selection, wire::Object{o->id()});
    }
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        switch (op) {
            case WlDataDevice::Req::set_selection: {
                auto src = a.obj(0) ? client().get<DataSource>(a.obj(0)) : nullptr;
                seat_->set_selection(client(), src);
                break;
            }
            case WlDataDevice::Req::start_drag: {
                // No drag and drop yet: end it before it starts.
                if (auto src = a.obj(0) ? client().get<DataSource>(a.obj(0)) : nullptr)
                    src->send(WlDataSource::Ev::cancelled);
                break;
            }
            default: break;
        }
    }
private:
    Seat* seat_;
};

class DataDeviceManager final : public Object<WlDataDeviceManager> {
public:
    DataDeviceManager(Client& c, std::uint32_t v, ObjectId id, Seat& s) : Object(c, v, id), seat_(&s) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == WlDataDeviceManager::Req::create_data_source) {
            (void)client().create<DataSource>(a.new_id(0), version(), *seat_);
        } else if (op == WlDataDeviceManager::Req::get_data_device) {
            if (auto d = client().create<DataDevice>(a.new_id(0), version(), *seat_)) seat_->add_data_device(d);
        }
    }
private:
    Seat* seat_;
};

// A surface acting as the pointer's image.
class CursorRole final : public SurfaceRole {
public:
    CursorRole(Seat& s, std::weak_ptr<Surface> surf) : seat_(&s), surf_(std::move(surf)) {}
    void role_commit() override {
        if (auto s = surf_.lock()) seat_->cursor_committed(*s);
    }
private:
    Seat* seat_;
    std::weak_ptr<Surface> surf_;
};

void bind_seat_globals(Compositor& comp);
void bind_seat_globals(Compositor& comp) {
    comp.server().add_global<WlSeat>(8, [&comp](Client& c, std::uint32_t v, ObjectId id) { comp.seat().bind(c, v, id); });
    comp.server().add_global<WlDataDeviceManager>(3, [&comp](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<DataDeviceManager>(id, v, comp.seat());
    });
}

// -- Seat ----------------------------------------------------------------------

Seat::Seat(Compositor& c) : comp_(&c) {}
Seat::~Seat() = default;

void Seat::bind(Client& c, std::uint32_t version, ObjectId id) {
    auto s = c.create<SeatObj>(id, version, *this);
    if (!s) return;
    s->send(WlSeat::Ev::capabilities, WlSeat::Capability::pointer | WlSeat::Capability::keyboard);
    s->send(WlSeat::Ev::name, "seat0");
}

template <class F>
void Seat::each_pointer(Client& c, F&& f) {
    std::erase_if(pointers_, [](const auto& w) { auto p = w.lock(); return !p || !p->alive(); });
    for (auto& w : pointers_)
        if (auto p = w.lock(); p && &p->client() == &c) f(*p);
}

template <class F>
void Seat::each_keyboard(Client& c, F&& f) {
    std::erase_if(keyboards_, [](const auto& w) { auto k = w.lock(); return !k || !k->alive(); });
    for (auto& w : keyboards_)
        if (auto k = w.lock(); k && &k->client() == &c) f(*k);
}

void Seat::add_pointer(const std::shared_ptr<Pointer>& p) {
    pointers_.push_back(p);
    // already over one of its surfaces: it needs an enter of its own
    if (auto s = ptr_focus_.lock(); s && &s->client() == &p->client()) {
        enter_serial_ = comp_->server().next_serial();
        p->send(WlPointer::Ev::enter, enter_serial_, wire::Object{s->id()}, wire::Fixed::from(ptr_x_), wire::Fixed::from(ptr_y_));
        p->send(WlPointer::Ev::frame);
    }
}

wire::Fd Seat::keymap_fd(std::size_t& size) {
    if (keymap_text_.empty()) {
        kbinfo_ = comp_->host().keyboard();
        std::string sym = "pc+" + kbinfo_.layout;
        if (!kbinfo_.variant.empty()) sym += "(" + kbinfo_.variant + ")";
        sym += "+inet(evdev)";
        keymap_text_ =
            "xkb_keymap {\n"
            "  xkb_keycodes { include \"evdev+aliases(qwerty)\" };\n"
            "  xkb_types    { include \"complete\" };\n"
            "  xkb_compat   { include \"complete\" };\n"
            "  xkb_symbols  { include \"" + sym + "\" };\n"
            "  xkb_geometry { include \"pc(pc105)\" };\n"
            "};\n";
    }
    size = keymap_text_.size() + 1;
    const char* dir = std::getenv("TMPDIR");
    std::string tmpl = std::string{dir && *dir ? dir : "/tmp"} + "/linuxity-keymap-XXXXXX";
    wire::Fd fd{::mkstemp(tmpl.data())};
    if (!fd) return fd;
    ::unlink(tmpl.c_str());
    if (::write(fd.get(), keymap_text_.c_str(), size) != static_cast<ssize_t>(size)) return wire::Fd{};
    return fd;
}

void Seat::add_keyboard(const std::shared_ptr<Keyboard>& k) {
    keyboards_.push_back(k);
    std::size_t size = 0;
    if (auto fd = keymap_fd(size))
        k->send(WlKeyboard::Ev::keymap, WlKeyboard::KeymapFormat::xkb_v1, wire::FdArg{fd.get()}, static_cast<std::uint32_t>(size));
    k->send(WlKeyboard::Ev::repeat_info, kbinfo_.repeat_rate, kbinfo_.repeat_delay_ms);
    if (auto s = kb_focus_.lock(); s && &s->client() == &k->client()) {
        k->send(WlKeyboard::Ev::enter, comp_->server().next_serial(), wire::Object{s->id()},
                wire::Array{std::as_bytes(std::span{keys_down_})});
        send_modifiers(&k->client());
    }
}

void Seat::keyboard_changed() {
    keymap_text_.clear();
    std::erase_if(keyboards_, [](const auto& w) { auto k = w.lock(); return !k || !k->alive(); });
    for (auto& w : keyboards_) {
        auto k = w.lock();
        std::size_t size = 0;
        if (auto fd = keymap_fd(size))
            k->send(WlKeyboard::Ev::keymap, WlKeyboard::KeymapFormat::xkb_v1, wire::FdArg{fd.get()}, static_cast<std::uint32_t>(size));
        k->send(WlKeyboard::Ev::repeat_info, kbinfo_.repeat_rate, kbinfo_.repeat_delay_ms);
    }
}

void Seat::add_data_device(const std::shared_ptr<DataDevice>& d) {
    data_devices_.push_back(d);
    if (auto s = kb_focus_.lock(); s && &s->client() == &d->client()) offer_selection(d->client());
}

// -- pointer ---------------------------------------------------------------------

void Seat::pointer_frame(Client& c) {
    each_pointer(c, [](Pointer& p) { p.send(WlPointer::Ev::frame); });
}

void Seat::send_pointer_enter(Surface& s, double lx, double ly) {
    ptr_focus_ = s.self();
    enter_serial_ = comp_->server().next_serial();
    each_pointer(s.client(), [&](Pointer& p) {
        p.send(WlPointer::Ev::enter, enter_serial_, wire::Object{s.id()}, wire::Fixed::from(lx), wire::Fixed::from(ly));
    });
}

void Seat::send_pointer_leave() {
    auto s = ptr_focus_.lock();
    ptr_focus_.reset();
    if (!s || !s->alive()) return;
    const std::uint32_t serial = comp_->server().next_serial();
    each_pointer(s->client(), [&](Pointer& p) { p.send(WlPointer::Ev::leave, serial, wire::Object{s->id()}); });
    pointer_frame(s->client());
}

void Seat::pointer_motion(ShellSurface& win, double vx, double vy, std::uint32_t t) {
    auto focus = ptr_focus_.lock();
    double lx = 0, ly = 0;
    if (buttons_down_ && focus && ptr_window_.lock().get() == &win) {
        // implicit grab: the pressed surface keeps the pointer
        const auto o = win.origin_of(focus.get());
        if (!o) return;
        lx = vx - o->x;
        ly = vy - o->y;
    } else {
        ptr_window_ = win.self();
        Surface* hit = win.pick(vx, vy, lx, ly);
        if (hit != focus.get()) {
            if (focus) send_pointer_leave();
            if (!hit) { comp_->host().reset_cursor(); return; }
            send_pointer_enter(*hit, lx, ly);
            ptr_x_ = lx;
            ptr_y_ = ly;
            pointer_frame(hit->client());
            return;
        }
        if (!hit) return;
    }
    ptr_x_ = lx;
    ptr_y_ = ly;
    auto s = ptr_focus_.lock();
    each_pointer(s->client(), [&](Pointer& p) {
        p.send(WlPointer::Ev::motion, t, wire::Fixed::from(lx), wire::Fixed::from(ly));
    });
    pointer_frame(s->client());
}

void Seat::pointer_leave(ShellSurface& win) {
    if (buttons_down_) return;
    if (ptr_window_.lock().get() != &win) return;
    send_pointer_leave();
    ptr_window_.reset();
}

void Seat::pointer_button(ShellSurface& win, PointerButton b, bool pressed, std::uint32_t t) {
    if (pressed && !popups_.empty() && !in_popup_chain(&win)) dismiss_popups();
    if (pressed) ++buttons_down_;
    else if (buttons_down_) --buttons_down_;
    auto s = ptr_focus_.lock();
    if (!s || !s->alive()) return;
    const std::uint32_t serial = comp_->server().next_serial();
    if (pressed) press_serial_ = serial;
    each_pointer(s->client(), [&](Pointer& p) {
        p.send(WlPointer::Ev::button, serial, t, static_cast<std::uint32_t>(b),
               pressed ? WlPointer::ButtonState::pressed : WlPointer::ButtonState::released);
    });
    pointer_frame(s->client());
}

void Seat::pointer_scroll(ShellSurface&, const ScrollEvent& e, std::uint32_t t) {
    auto s = ptr_focus_.lock();
    if (!s || !s->alive()) return;
    each_pointer(s->client(), [&](Pointer& p) {
        const auto src = e.source == AxisSource::wheel ? WlPointer::AxisSource::wheel
                         : e.source == AxisSource::finger ? WlPointer::AxisSource::finger
                                                          : WlPointer::AxisSource::continuous;
        p.send(WlPointer::Ev::axis_source, src);
        auto axis = [&](WlPointer::Axis ax, double v, std::int32_t steps) {
            if (v == 0 && steps == 0) return;
            if (e.source == AxisSource::wheel && steps) {
                if (p.version() >= 8) p.send(WlPointer::Ev::axis_value120, ax, steps);
                else p.send(WlPointer::Ev::axis_discrete, ax, steps / 120 ? steps / 120 : (steps > 0 ? 1 : -1));
            }
            p.send(WlPointer::Ev::axis, t, ax, wire::Fixed::from(v));
        };
        axis(WlPointer::Axis::vertical_scroll, e.dy, e.steps_y);
        axis(WlPointer::Axis::horizontal_scroll, e.dx, e.steps_x);
        if (e.stop) {
            p.send(WlPointer::Ev::axis_stop, t, WlPointer::Axis::vertical_scroll);
            p.send(WlPointer::Ev::axis_stop, t, WlPointer::Axis::horizontal_scroll);
        }
        p.send(WlPointer::Ev::frame);
    });
}

// -- cursor -------------------------------------------------------------------------

void Seat::set_cursor(Pointer& from, std::uint32_t, std::shared_ptr<Surface> s, Point hotspot) {
    auto focus = ptr_focus_.lock();
    if (!focus || &focus->client() != &from.client()) return;   // only the client under the pointer
    if (!s) {
        cursor_surface_.reset();
        comp_->host().set_cursor({});
        return;
    }
    if (s->role_name() != "wl_pointer.cursor") {
        auto role = std::make_unique<CursorRole>(*this, s);
        if (!s->set_role("wl_pointer.cursor", role.get(), from, static_cast<std::uint32_t>(WlPointer::Error::role)))
            return;
        cursor_roles_.emplace_back(s->uid(), std::move(role));
    }
    cursor_surface_ = s;
    cursor_hotspot_ = hotspot;
    (void)s->take_delta();
    if (s->pixels()) comp_->host().set_cursor({s->pixels(), s->scale(), hotspot});
}

void Seat::cursor_committed(Surface& s) {
    if (cursor_surface_.lock().get() != &s) return;
    cursor_hotspot_ = cursor_hotspot_ - s.take_delta();
    comp_->host().set_cursor({s.pixels(), s.scale(), cursor_hotspot_});
}

void Seat::set_cursor_shape(Client& from, CursorShape shape) {
    auto focus = ptr_focus_.lock();
    if (!focus || &focus->client() != &from) return;   // only the client under the pointer
    cursor_surface_.reset();
    comp_->host().set_cursor_shape(shape);
}

// -- keyboard ----------------------------------------------------------------------

void Seat::send_modifiers(Client* only) {
    auto s = kb_focus_.lock();
    if (!s) return;
    Client& c = only ? *only : s->client();
    Modifiers m = mods_;
    if (comp_->options().command_is_control) { m.control = m.control || m.super; m.super = false; }
    const std::uint32_t depressed = (m.shift ? kShift : 0) | (m.control ? kControl : 0) |
                                    (m.alt ? kMod1 : 0) | (m.super ? kMod4 : 0);
    const std::uint32_t locked = (m.caps_lock ? kLock : 0) | (m.num_lock ? kMod2 : 0);
    const std::uint32_t serial = comp_->server().next_serial();
    each_keyboard(c, [&](Keyboard& k) { k.send(WlKeyboard::Ev::modifiers, serial, depressed, 0u, locked, 0u); });
}

void Seat::keyboard_enter(Surface* s) {
    auto old = kb_focus_.lock();
    if (old.get() == s) return;
    if (old && old->alive()) {
        const std::uint32_t serial = comp_->server().next_serial();
        each_keyboard(old->client(), [&](Keyboard& k) { k.send(WlKeyboard::Ev::leave, serial, wire::Object{old->id()}); });
    }
    Surface* before = old && old->alive() ? old.get() : nullptr;
    if (!s) {
        kb_focus_.reset();
        for (auto& f : focus_listeners_) f(before, nullptr);
        return;
    }
    kb_focus_ = s->self();
    const std::uint32_t serial = comp_->server().next_serial();
    each_keyboard(s->client(), [&](Keyboard& k) {
        k.send(WlKeyboard::Ev::enter, serial, wire::Object{s->id()}, wire::Array{std::as_bytes(std::span{keys_down_})});
    });
    send_modifiers();
    if (!old || &old->client() != &s->client()) {
        host_clipboard_check();
        offer_selection(s->client());
    }
    for (auto& f : focus_listeners_) f(before, s);
}

void Seat::focus_window(ShellSurface* win) {
    if (win) focused_window_ = win->self();
    else focused_window_.reset();
    refocus();
}

void Seat::refocus() {
    std::erase_if(popups_, [](const auto& w) { auto p = w.lock(); return !p || !p->mapped(); });
    Surface* target = nullptr;
    if (!popups_.empty()) target = popups_.back().lock()->surface();
    else if (auto w = focused_window_.lock(); w && w->alive()) target = w->surface();
    keyboard_enter(target);
}

void Seat::key(std::uint32_t code, bool pressed, std::uint32_t t) {
    if (comp_->options().command_is_control) {
        if (code == KEY_LEFTMETA) code = KEY_LEFTCTRL;
        else if (code == KEY_RIGHTMETA) code = KEY_RIGHTCTRL;
    }
    if (pressed) {
        if (std::find(keys_down_.begin(), keys_down_.end(), code) != keys_down_.end()) return;   // host auto-repeat
        keys_down_.push_back(code);
    } else {
        // a release the client never saw pressed (an input method took
        // the press) is not news to it
        if (std::find(keys_down_.begin(), keys_down_.end(), code) == keys_down_.end()) return;
        std::erase(keys_down_, code);
    }
    auto s = kb_focus_.lock();
    if (!s || !s->alive()) return;
    const std::uint32_t serial = comp_->server().next_serial();
    if (pressed) key_serial_ = serial;
    each_keyboard(s->client(), [&](Keyboard& k) {
        k.send(WlKeyboard::Ev::key, serial, t, code, pressed ? WlKeyboard::KeyState::pressed : WlKeyboard::KeyState::released);
    });
}

void Seat::modifiers(Modifiers m) {
    if (m == mods_) return;
    mods_ = m;
    send_modifiers();
}

void Seat::release_all() {
    // We lost the platform's focus: releases won't reach us. Let the
    // focused client know nothing is held, so it stops repeating.
    auto s = kb_focus_.lock();
    if (s && s->alive()) {
        const std::uint32_t t = comp_->server().now_ms();
        for (std::uint32_t code : keys_down_) {
            const std::uint32_t serial = comp_->server().next_serial();
            each_keyboard(s->client(), [&](Keyboard& k) {
                k.send(WlKeyboard::Ev::key, serial, t, code, WlKeyboard::KeyState::released);
            });
        }
    }
    keys_down_.clear();
    modifiers(Modifiers{.caps_lock = mods_.caps_lock, .num_lock = mods_.num_lock});
}

// -- popups -------------------------------------------------------------------------

void Seat::push_popup(const std::shared_ptr<ShellSurface>& p) {
    popups_.push_back(p);
    refocus();
}

void Seat::remove_popup(const ShellSurface* p) {
    const auto before = popups_.size();
    std::erase_if(popups_, [p](const auto& w) { auto s = w.lock(); return !s || s.get() == p; });
    if (popups_.size() != before) refocus();
}

void Seat::dismiss_popups() {
    auto ps = std::move(popups_);
    popups_.clear();
    for (auto it = ps.rbegin(); it != ps.rend(); ++it)
        if (auto p = it->lock(); p && p->popup()) p->popup()->dismiss();
    refocus();
}

bool Seat::in_popup_chain(const ShellSurface* w) const {
    return std::any_of(popups_.begin(), popups_.end(), [w](const auto& p) { return p.lock().get() == w; });
}

// -- selection --------------------------------------------------------------------------

void Seat::offer_selection(Client& to) {
    std::erase_if(data_devices_, [](const auto& w) { auto d = w.lock(); return !d || !d->alive(); });
    auto src = selection_.lock();
    std::shared_ptr<const std::string> host_text;
    std::vector<std::string> mimes;
    if (src && src->alive()) {
        mimes = src->mimes;
    } else if (selection_from_host_) {
        if (HostClipboard* hc = comp_->host().clipboard())
            if (auto t = hc->text()) {
                host_text = std::make_shared<const std::string>(std::move(*t));
                mimes.assign(std::begin(kTextMimes), std::end(kTextMimes));
            }
    }
    for (auto& w : data_devices_) {
        auto d = w.lock();
        if (&d->client() != &to) continue;
        d->offer(src && src->alive() ? src : nullptr, host_text, mimes);
    }
}

void Seat::set_selection(Client& from, std::shared_ptr<DataSource> src) {
    if (auto old = selection_.lock(); old && old != src && old->alive()) old->send(WlDataSource::Ev::cancelled);
    selection_ = src;
    selection_from_host_ = false;
    // Copy it out to the host clipboard, so the Mac (or Android, or Windows)
    // can paste what a Linux app copied.
    if (src) {
        HostClipboard* hc = comp_->host().clipboard();
        const auto it = std::find_if(src->mimes.begin(), src->mimes.end(), [](const std::string& m) { return is_text_mime(m); });
        if (hc && it != src->mimes.end()) {
            int p[2];
            if (::pipe(p) == 0) {
                (void)::fcntl(p[0], F_SETFD, FD_CLOEXEC);
                (void)::fcntl(p[1], F_SETFD, FD_CLOEXEC);
                src->send_to(*it, wire::Fd{p[1]});
                FdReader::start(comp_->server().loop(), wire::Fd{p[0]}, [this, hc](std::string text) {
                    if (text.empty()) return;
                    hc->set_text(std::move(text));
                    host_clip_gen_ = hc->generation();
                });
            }
        }
    }
    if (auto f = kb_focus_.lock(); f && f->alive() && &f->client() != &from) offer_selection(f->client());
    if (auto f = kb_focus_.lock(); f && f->alive() && &f->client() == &from) offer_selection(from);
}

void Seat::source_gone(const DataSource* src) {
    if (selection_.lock().get() != src) return;
    selection_.reset();
    if (auto f = kb_focus_.lock(); f && f->alive()) offer_selection(f->client());
}

void Seat::host_clipboard_check() {
    HostClipboard* hc = comp_->host().clipboard();
    if (!hc) return;
    const std::uint64_t g = hc->generation();
    if (g == host_clip_gen_) return;
    host_clip_gen_ = g;
    // someone outside copied: that is the selection now
    if (auto old = selection_.lock(); old && old->alive()) old->send(WlDataSource::Ev::cancelled);
    selection_.reset();
    selection_from_host_ = true;
    if (auto f = kb_focus_.lock(); f && f->alive()) offer_selection(f->client());
}

// -- teardown ----------------------------------------------------------------------------

void Seat::unmapped(Surface* s) {
    auto in_tree = [s](const std::shared_ptr<Surface>& f) { return f && f->root() == s; };
    if (in_tree(ptr_focus_.lock())) { buttons_down_ = 0; send_pointer_leave(); }
    if (in_tree(kb_focus_.lock())) {
        keyboard_enter(nullptr);
        if (auto w = focused_window_.lock(); w && w->surface() == s) focused_window_.reset();
        refocus();
    }
}

void Seat::forget(Surface* s) {
    if (ptr_focus_.lock().get() == s) { ptr_focus_.reset(); buttons_down_ = 0; }
    if (kb_focus_.lock().get() == s) kb_focus_.reset();
    if (cursor_surface_.lock().get() == s) cursor_surface_.reset();
    std::erase_if(cursor_roles_, [s](const auto& e) {
        if (e.first != s->uid()) return false;
        s->clear_role_impl(e.second.get());
        return true;
    });
}

}  // namespace lx::display
