// src/display/core/surface.cpp -- wl_compositor, wl_surface, wl_region,
// wl_subcompositor/wl_subsurface and wl_shm.
//
// Buffers are copied at commit and released at once: the copy is what the
// host shows, so a client may reuse its buffer immediately (it would have to
// wait for a frame on a compositor that scans out of it) and the core never
// holds a reference into guest memory past the request that named it.
#include "compositor.hpp"

#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstring>

#include <sys/mman.h>
#include <sys/stat.h>

namespace lx::display {

using namespace proto;

// -- shm --------------------------------------------------------------------

namespace {

// A client can shrink the file behind its pool while we read it; the read
// then faults with SIGBUS. Turn that into a failed copy, not a crash.
thread_local sigjmp_buf* t_copy_jmp = nullptr;

void on_sigbus(int sig, siginfo_t*, void*) {
    if (t_copy_jmp) siglongjmp(*t_copy_jmp, 1);
    ::signal(sig, SIG_DFL);
    ::raise(sig);
}

void install_sigbus_guard() {
    static const bool once = [] {
        struct ::sigaction sa{};
        sa.sa_sigaction = on_sigbus;
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigemptyset(&sa.sa_mask);
        ::sigaction(SIGBUS, &sa, nullptr);
        return true;
    }();
    (void)once;
}

bool guarded_rows(std::byte* dst, std::size_t dst_stride, const std::byte* src, std::size_t src_stride,
                  std::size_t row_bytes, std::size_t rows) {
    install_sigbus_guard();
    sigjmp_buf jb;
    if (sigsetjmp(jb, 1) != 0) {
        t_copy_jmp = nullptr;
        return false;
    }
    t_copy_jmp = &jb;
    if (dst_stride == src_stride) {
        std::memcpy(dst, src, src_stride * rows);
    } else {
        for (std::size_t r = 0; r < rows; ++r) std::memcpy(dst + r * dst_stride, src + r * src_stride, row_bytes);
    }
    t_copy_jmp = nullptr;
    return true;
}

std::optional<PixelFormat> shm_format(std::uint32_t f) {
    switch (f) {
        case static_cast<std::uint32_t>(WlShm::Format::argb8888): return PixelFormat::argb8888;
        case static_cast<std::uint32_t>(WlShm::Format::xrgb8888): return PixelFormat::xrgb8888;
        case static_cast<std::uint32_t>(WlShm::Format::abgr8888): return PixelFormat::abgr8888;
        case static_cast<std::uint32_t>(WlShm::Format::xbgr8888): return PixelFormat::xbgr8888;
        default: return std::nullopt;
    }
}

class ShmPool final : public Object<WlShmPool> {
public:
    ShmPool(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<ShmMapping> m)
        : Object(c, v, id), map_(std::move(m)) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        switch (op) {
            case WlShmPool::Req::create_buffer: {
                const std::int32_t offset = a.i(1), w = a.i(2), h = a.i(3), stride = a.i(4);
                const auto fmt = shm_format(a.u(5));
                if (!fmt) { post_error(WlShm::Error::invalid_format, "unsupported format"); return; }
                if (w <= 0 || h <= 0 || offset < 0 || stride < w * 4 ||
                    static_cast<std::uint64_t>(offset) + static_cast<std::uint64_t>(stride) * static_cast<std::uint64_t>(h) > map_->size) {
                    post_error(WlShm::Error::invalid_stride, "buffer outside its pool");
                    return;
                }
                (void)client().create<Buffer>(a.new_id(0), 1, map_, offset, w, h, stride, *fmt);
                break;
            }
            case WlShmPool::Req::resize: {
                const std::int32_t size = a.i(0);
                if (size <= 0 || static_cast<std::size_t>(size) < map_->size) {
                    post_error(WlShm::Error::invalid_fd, "pools only grow");
                    return;
                }
                if (!map_->remap(static_cast<std::size_t>(size))) post_error(WlShm::Error::invalid_fd, "cannot map pool");
                break;
            }
            default: break;   // destroy: the buffers keep the mapping
        }
    }
private:
    std::shared_ptr<ShmMapping> map_;
};

class Shm final : public Object<WlShm> {
public:
    using Object::Object;
    void announce() {
        for (auto f : {WlShm::Format::argb8888, WlShm::Format::xrgb8888, WlShm::Format::abgr8888, WlShm::Format::xbgr8888})
            send(WlShm::Ev::format, f);
    }
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WlShm::Req::create_pool) return;
        auto fd = a.take_fd(1);
        const std::int32_t size = a.i(2);
        if (size <= 0) { post_error(WlShm::Error::invalid_fd, "bad pool size"); return; }
        auto m = std::make_shared<ShmMapping>();
        m->fd = std::move(fd);
        if (!m->remap(static_cast<std::size_t>(size))) { post_error(WlShm::Error::invalid_fd, "cannot map pool"); return; }
        (void)client().create<ShmPool>(a.new_id(0), 1, std::move(m));
    }
};

class RegionObj final : public Object<WlRegion> {
public:
    using Object::Object;
    Region region;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        const Rect r{a.i(0), a.i(1), a.i(2), a.i(3)};
        if (op == WlRegion::Req::add) region.add(r);
        else if (op == WlRegion::Req::subtract) region.subtract(r);
    }
};

}  // namespace

ShmMapping::~ShmMapping() {
    if (base) ::munmap(base, size);
}

bool ShmMapping::remap(std::size_t new_size) {
    void* p = ::mmap(nullptr, new_size, PROT_READ, MAP_SHARED, fd.get(), 0);
    if (p == MAP_FAILED) return false;
    if (base) ::munmap(base, size);
    base = p;
    size = new_size;
    return true;
}

PixelsRef Buffer::snapshot() const {
    auto px = std::make_shared<Pixels>();
    px->width = w_;
    px->height = h_;
    px->stride = w_ * 4;
    px->format = fmt_;
    const auto rows = static_cast<std::size_t>(h_);
    const auto row = static_cast<std::size_t>(w_) * 4;
    if (static_cast<std::size_t>(offset_) + static_cast<std::size_t>(stride_) * rows > map_->size) return nullptr;
    // never read past the file's current end, even if the pool says we may
    struct ::stat st{};
    if (::fstat(map_->fd.get(), &st) == 0 &&
        static_cast<std::uint64_t>(st.st_size) < static_cast<std::uint64_t>(offset_) + static_cast<std::uint64_t>(stride_) * (rows - 1) + row)
        return nullptr;
    px->data.resize(row * rows);
    const auto* src = static_cast<const std::byte*>(map_->base) + offset_;
    if (!guarded_rows(px->data.data(), row, src, static_cast<std::size_t>(stride_), row, rows)) return nullptr;
    return px;
}

// -- Surface ------------------------------------------------------------------

namespace {

// wl_subsurface: a surface positioned inside its parent's, committed with
// it (synchronized) or on its own (desynchronized).
class Subsurface final : public Object<WlSubsurface>, public SurfaceRole {
public:
    Subsurface(Client& c, std::uint32_t v, ObjectId id, std::shared_ptr<Surface> s, std::shared_ptr<Surface> parent)
        : Object(c, v, id), surface_(s), parent_(parent) {}
    void role_commit() override { notify_root(); }
    [[nodiscard]] bool role_is_sync_child() const override { return true; }
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        auto s = surface_.lock();
        auto p = parent_.lock();
        if (!s) return;
        switch (op) {
            case WlSubsurface::Req::set_position: s->set_pending_position({a.i(0), a.i(1)}); break;
            case WlSubsurface::Req::place_above:
            case WlSubsurface::Req::place_below: {
                auto sib = client().get<Surface>(a.obj(0));
                if (!p || !sib || !p->restack(s.get(), sib.get(), op == WlSubsurface::Req::place_above))
                    post_error(WlSubsurface::Error::bad_surface, "not a sibling or the parent");
                break;
            }
            case WlSubsurface::Req::set_sync: s->set_sync(true); break;
            case WlSubsurface::Req::set_desync: {
                const bool was = s->effectively_sync();
                s->set_sync(false);
                if (was && !s->effectively_sync()) s->apply_cached();
                notify_root();
                break;
            }
            default: break;
        }
    }
    void on_destroy() override {
        auto s = surface_.lock();
        if (!s) return;
        Surface* root = s->root();
        if (auto p = parent_.lock()) p->remove_child(s.get());
        s->set_parent(nullptr);
        s->clear_role_impl(this);
        if (root && root != s.get() && root->role()) root->role()->role_tree_changed();
    }
private:
    void notify_root() {
        auto s = surface_.lock();
        if (!s) return;
        Surface* root = s->root();
        if (root && root != s.get() && root->role()) root->role()->role_tree_changed();
    }
    std::weak_ptr<Surface> surface_, parent_;
};

class Subcompositor final : public Object<WlSubcompositor> {
public:
    using Object::Object;
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op != WlSubcompositor::Req::get_subsurface) return;
        auto s = client().get<Surface>(a.obj(1));
        auto p = client().get<Surface>(a.obj(2));
        if (!s || !p || s == p) { post_error(WlSubcompositor::Error::bad_surface, "bad surface"); return; }
        for (Surface* up = p.get(); up; up = up->parent())
            if (up == s.get()) { post_error(WlSubcompositor::Error::bad_parent, "parent is a descendant"); return; }
        auto sub = client().create<Subsurface>(a.new_id(0), 1, s, p);
        if (!sub) return;
        if (!s->set_role("wl_subsurface", sub.get(), *this, static_cast<std::uint32_t>(WlSubcompositor::Error::bad_surface))) return;
        s->set_parent(p);
        p->add_child(s);
    }
};

class CompositorObj final : public Object<WlCompositor> {
public:
    CompositorObj(Client& c, std::uint32_t v, ObjectId id, Compositor& comp) : Object(c, v, id), comp_(&comp) {}
protected:
    void request(std::uint16_t op, wire::Args& a) override {
        if (op == WlCompositor::Req::create_surface) (void)client().create<Surface>(a.new_id(0), version(), *comp_);
        else if (op == WlCompositor::Req::create_region) (void)client().create<RegionObj>(a.new_id(0), 1);
    }
private:
    Compositor* comp_;
};

}  // namespace

void bind_surface_globals(Compositor& comp);
void bind_surface_globals(Compositor& comp) {
    Server& s = comp.server();
    s.add_global<WlCompositor>(6, [&comp](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<CompositorObj>(id, v, comp);
    });
    s.add_global<WlSubcompositor>(1, [](Client& c, std::uint32_t v, ObjectId id) {
        (void)c.create<Subcompositor>(id, v);
    });
    s.add_global<WlShm>(1, [](Client& c, std::uint32_t v, ObjectId id) {
        if (auto shm = c.create<Shm>(id, v)) shm->announce();
    });
}

void SurfaceState::merge_into(SurfaceState& dst) {
    if (attached) { dst.attached = true; dst.pixels = std::move(pixels); }
    dst.delta = dst.delta + delta;
    if (scale) dst.scale = scale;
    if (input) dst.input = std::move(input);
    if (opaque) dst.opaque = std::move(opaque);
    for (auto& f : frames) dst.frames.push_back(std::move(f));
    *this = SurfaceState{};
}

Surface::Surface(Client& c, std::uint32_t v, ObjectId id, Compositor& comp)
    : Object(c, v, id), comp_(&comp), uid_(comp.next_uid()) {}

Surface::~Surface() = default;

bool Surface::accepts_input(double x, double y) const noexcept {
    if (!Rect{0, 0, size_.w, size_.h}.contains(x, y)) return false;
    return !input_ || input_->contains(x, y);
}

bool Surface::set_role(std::string_view name, SurfaceRole* impl, Resource& blame, std::uint32_t code) {
    if (!role_name_.empty() && role_name_ != name) {
        blame.post_error(code, "surface already has role " + role_name_);
        return false;
    }
    if (role_) {
        blame.post_error(code, "surface already has a " + role_name_ + " object");
        return false;
    }
    role_name_ = name;
    role_ = impl;
    return true;
}

void Surface::add_child(const std::shared_ptr<Surface>& child) {
    if (stack_.empty()) stack_.push_back(self());
    stack_.push_back(child);
    if (stack_dirty_) pending_stack_.push_back(child);
}

void Surface::remove_child(const Surface* child) {
    auto drop = [child](std::vector<std::weak_ptr<Surface>>& v) {
        std::erase_if(v, [child](const auto& w) { auto s = w.lock(); return !s || s.get() == child; });
    };
    drop(stack_);
    drop(pending_stack_);
}

bool Surface::restack(const Surface* child, const Surface* sibling, bool above) {
    if (!stack_dirty_) { pending_stack_ = stack_; stack_dirty_ = true; }
    auto& v = pending_stack_;
    auto find = [&v](const Surface* s) {
        return std::find_if(v.begin(), v.end(), [s](const auto& w) { return w.lock().get() == s; });
    };
    if (find(sibling) == v.end() || find(child) == v.end()) return false;
    auto moving = *find(child);
    v.erase(find(child));
    auto at = find(sibling);
    v.insert(above ? std::next(at) : at, moving);
    return true;
}

bool Surface::effectively_sync() const {
    auto p = parent_.lock();
    if (!p) return false;
    return sync_ || p->effectively_sync();
}

Surface* Surface::root() {
    Surface* s = this;
    while (Surface* p = s->parent()) s = p;
    return s;
}

void Surface::request(std::uint16_t op, wire::Args& a) {
    switch (op) {
        case WlSurface::Req::attach: {
            pending_.attached = true;
            pending_buffer_ = client().get<Buffer>(a.obj(0));
            if (version() >= 5 && (a.i(1) || a.i(2))) {
                post_error(WlSurface::Error::invalid_offset, "attach offset must be 0 since v5");
                return;
            }
            pending_.delta = pending_.delta + Point{a.i(1), a.i(2)};
            break;
        }
        case WlSurface::Req::frame:
            if (auto cb = client().create<Callback>(a.new_id(0), 1)) pending_.frames.push_back(cb);
            break;
        case WlSurface::Req::set_opaque_region:
        case WlSurface::Req::set_input_region: {
            std::optional<Region> r;
            if (a.obj(0)) {
                auto reg = client().get<RegionObj>(a.obj(0));
                if (reg) r = reg->region;
            }
            (op == WlSurface::Req::set_input_region ? pending_.input : pending_.opaque) = std::move(r);
            break;
        }
        case WlSurface::Req::set_buffer_scale:
            if (a.i(0) < 1) { post_error(WlSurface::Error::invalid_scale, "scale < 1"); return; }
            pending_.scale = a.i(0);
            break;
        case WlSurface::Req::set_buffer_transform:
            if (a.i(0) < 0 || a.i(0) > 7) post_error(WlSurface::Error::invalid_transform, "bad transform");
            break;
        case WlSurface::Req::offset:
            pending_.delta = pending_.delta + Point{a.i(0), a.i(1)};
            break;
        case WlSurface::Req::commit:
            commit();
            break;
        default: break;   // damage, damage_buffer: we copy whole buffers
    }
}

void Surface::commit() {
    // Copy the buffer now, whatever happens to the state next, and give
    // it back: the copy is ours.
    if (pending_.attached) {
        auto b = pending_buffer_.lock();
        pending_.pixels = b ? b->snapshot() : nullptr;
        if (b) b->release();
        pending_buffer_.reset();
        if (b && !pending_.pixels) {
            pending_.attached = false;   // unreadable: keep the old frame
            if (comp_->options().verbose)
                std::fprintf(stderr, "linuxity-display: wl_surface@%u: buffer %dx%d unreadable, frame dropped\n",
                             id(), b->size().w, b->size().h);
        }
    }
    if (effectively_sync()) {
        pending_.merge_into(cached_);
        has_cached_ = true;
        return;
    }
    apply(pending_);
    children_commit();
    if (role_) role_->role_commit();
}

void Surface::apply(SurfaceState& st) {
    if (st.attached) pixels_ = std::move(st.pixels);
    delta_ = delta_ + st.delta;
    if (st.scale) scale_ = *st.scale;
    if (st.input) input_ = std::move(*st.input);
    for (auto& f : st.frames) comp_->queue_frame(std::move(f));
    size_ = pixels_ ? Size{pixels_->width / scale_, pixels_->height / scale_} : Size{};
    st = SurfaceState{};
}

void Surface::apply_cached() {
    if (has_cached_) {
        apply(cached_);
        has_cached_ = false;
    }
    children_commit();
}

void Surface::children_commit() {
    if (stack_dirty_) {
        stack_ = std::move(pending_stack_);
        pending_stack_.clear();
        stack_dirty_ = false;
    }
    for (auto& w : stack_) {
        auto c = w.lock();
        if (!c || c.get() == this) continue;
        if (c->position_dirty_ || c->pending_position_ != c->position_) {
            c->position_ = c->pending_position_;
            c->position_dirty_ = false;
        }
        if (c->effectively_sync()) c->apply_cached();
    }
}

void Surface::set_outputs(const std::vector<std::shared_ptr<Resource>>& outs, std::int32_t scale) {
    for (auto& w : entered_) {
        auto o = w.lock();
        if (!o) continue;
        if (std::find(outs.begin(), outs.end(), o) == outs.end()) send(WlSurface::Ev::leave, wire::Object{o->id()});
    }
    for (auto& o : outs) {
        const bool had = std::any_of(entered_.begin(), entered_.end(), [&o](const auto& w) { return w.lock() == o; });
        if (!had) send(WlSurface::Ev::enter, wire::Object{o->id()});
    }
    entered_.assign(outs.begin(), outs.end());
    if (scale != preferred_scale_) {
        preferred_scale_ = scale;
        send(WlSurface::Ev::preferred_buffer_scale, scale);
    }
    for (auto& w : stack_)
        if (auto c = w.lock(); c && c.get() != this) c->set_outputs(outs, scale);
}

void Surface::on_destroy() {
    comp_->seat().forget(this);
    if (auto p = parent_.lock()) p->remove_child(this);
    for (auto& w : stack_)
        if (auto c = w.lock(); c && c.get() != this) c->set_parent(nullptr);
    stack_.clear();
    if (role_) role_->role_surface_gone();
    role_ = nullptr;
}

}  // namespace lx::display
