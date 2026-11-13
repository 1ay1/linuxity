// src/display/hosts/headless.cpp -- a Host with no screen.
//
// Windows are bookkeeping only; with a dump directory every present is
// composited in software and written as <dir>/<n>-<title>.ppm, so tests can
// check the pixels a client drew without a display. Also the fallback on
// hosts that have no native backend yet.
#include "headless.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <string>

namespace lx::display {

namespace {

class HeadlessWindow final : public HostWindow {
public:
    HeadlessWindow(WindowSink& sink, const WindowSpec& spec, std::string dump, int n, Rect screen, HeadlessLog* log)
        : sink_(&sink), title_(spec.title), dump_(std::move(dump)), n_(n), screen_(screen), log_(log) {}
    void present(const Scene& s) override {
        if (!shown_) {
            shown_ = true;
            sink_->host_focus(true);
        }
        if (log_)
            for (const auto& l : s.layers) log_->presents.push_back({l.id, l.damage, l.generation, l.source, l.rect});
        if (!dump_.empty()) write(s);
    }
    void request_attention() override { if (log_) ++log_->attention; }
    void set_text_input(std::optional<Rect> cursor) override { if (log_) log_->text_input = cursor; }
    void set_title(std::string_view t) override { title_ = t; }
    void set_decorations(Decorations) override {}
    void set_size_limits(Size, Size) override {}
    void set_maximized(bool on) override {
        WindowStates st;
        st.activated = true;
        st.maximized = on;
        sink_->host_configure(on ? screen_.size() : Size{}, st);
    }
    void set_fullscreen(bool on) override {
        WindowStates st;
        st.activated = true;
        st.fullscreen = on;
        sink_->host_configure(on ? screen_.size() : Size{}, st);
    }
    void minimize() override {}
    void begin_move() override {}
    void begin_resize(std::uint32_t) override {}
    void move_popup(Point) override {}
    void activate() override {
        if (log_) ++log_->activations;
        sink_->host_focus(true);
    }
    [[nodiscard]] Rect work_area() const override { return screen_; }

private:
    void write(const Scene& s) {
        const Rect v = s.view;
        if (v.empty()) return;
        std::vector<float> rgb(static_cast<std::size_t>(v.w) * static_cast<std::size_t>(v.h) * 3, 0.f);
        for (const auto& l : s.layers) {
            if (!l.pixels) continue;
            const Pixels& p = *l.pixels;
            for (int y = 0; y < l.rect.h; ++y)
                for (int x = 0; x < l.rect.w; ++x) {
                    const int dx = l.rect.x + x - v.x, dy = l.rect.y + y - v.y;
                    if (dx < 0 || dy < 0 || dx >= v.w || dy >= v.h) continue;
                    // the layer shows `source` of the buffer stretched over its rect
                    const SourceRect src = l.source.whole()
                        ? SourceRect{0, 0, static_cast<double>(p.width), static_cast<double>(p.height)} : l.source;
                    const int sx = static_cast<int>(src.x + (x + 0.5) * src.w / l.rect.w);
                    const int sy = static_cast<int>(src.y + (y + 0.5) * src.h / l.rect.h);
                    if (sx < 0 || sy < 0 || sx >= p.width || sy >= p.height) continue;
                    const auto* px = reinterpret_cast<const unsigned char*>(p.data.data()) +
                                     static_cast<std::size_t>(sy) * static_cast<std::size_t>(p.stride) + static_cast<std::size_t>(sx) * 4;
                    float r, g, b, a;
                    switch (p.format) {
                        case PixelFormat::argb8888: b = px[0]; g = px[1]; r = px[2]; a = px[3]; break;
                        case PixelFormat::xrgb8888: b = px[0]; g = px[1]; r = px[2]; a = 255; break;
                        case PixelFormat::abgr8888: r = px[0]; g = px[1]; b = px[2]; a = px[3]; break;
                        default: r = px[0]; g = px[1]; b = px[2]; a = 255; break;
                    }
                    float* d = &rgb[(static_cast<std::size_t>(dy) * static_cast<std::size_t>(v.w) + static_cast<std::size_t>(dx)) * 3];
                    const float k = 1.f - a / 255.f;   // premultiplied over
                    d[0] = r + d[0] * k;
                    d[1] = g + d[1] * k;
                    d[2] = b + d[2] * k;
                }
        }
        std::string safe;
        for (char c : title_) safe += (std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
        std::ofstream f(dump_ + "/" + std::to_string(n_) + "-" + safe + ".ppm", std::ios::binary);
        f << "P6\n" << v.w << " " << v.h << "\n255\n";
        for (float c : rgb) f.put(static_cast<char>(static_cast<unsigned char>(std::min(255.f, c))));
    }

    WindowSink* sink_;
    std::string title_, dump_;
    int n_;
    Rect screen_;
    HeadlessLog* log_;
    bool shown_{false};
};

class HeadlessHost final : public Host {
public:
    HeadlessHost(std::string dump, HeadlessLog* log) : loop_(make_poll_loop()), dump_(std::move(dump)), log_(log) {}
    EventLoop& loop() override { return *loop_; }
    void attach(HostSink& s) override { sink_ = &s; if (log_) log_->sink = &s; }
    std::vector<OutputInfo> outputs() override {
        OutputInfo o;
        o.name = "HEADLESS-1";
        o.description = "linuxity headless output";
        o.model = "headless";
        o.logical = {0, 0, 1920, 1080};
        o.fractional_scale = log_ ? log_->scale : 0;
        o.scale = o.fractional_scale > 0 ? static_cast<std::int32_t>(std::ceil(o.fractional_scale)) : 1;
        o.pixels = {1920 * o.scale, 1080 * o.scale};
        o.physical_mm = {520, 290};
        return {o};
    }
    KeyboardInfo keyboard() override { return {}; }
    std::unique_ptr<HostWindow> create_window(const WindowSpec& spec, WindowSink& sink) override {
        return std::make_unique<HeadlessWindow>(sink, spec, dump_, ++n_, Rect{0, 0, 1920, 1080}, log_);
    }
    void set_cursor(const CursorImage&) override { if (log_) log_->cursor_shape = 0; }
    void set_cursor_shape(CursorShape s) override { if (log_) log_->cursor_shape = static_cast<std::uint32_t>(s); }
    void reset_cursor() override {}
    void bell() override { if (log_) ++log_->bells; }

private:
    std::unique_ptr<EventLoop> loop_;
    std::string dump_;
    HeadlessLog* log_;
    HostSink* sink_{nullptr};
    int n_{0};
};

}  // namespace

std::unique_ptr<Host> make_headless_host(std::string dump_dir, HeadlessLog* log) {
    return std::make_unique<HeadlessHost>(std::move(dump_dir), log);
}

}  // namespace lx::display
