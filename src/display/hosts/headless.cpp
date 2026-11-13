// src/display/hosts/headless.cpp -- a Host with no screen.
//
// Windows are bookkeeping only; with a dump directory every present is
// composited in software and written as <dir>/<n>-<title>.ppm, so tests can
// check the pixels a client drew without a display. Also the fallback on
// hosts that have no native backend yet.
#include "../core/host.hpp"

#include <cstdio>
#include <fstream>
#include <string>

namespace lx::display {

namespace {

class HeadlessWindow final : public HostWindow {
public:
    HeadlessWindow(WindowSink& sink, const WindowSpec& spec, std::string dump, int n, Rect screen)
        : sink_(&sink), title_(spec.title), dump_(std::move(dump)), n_(n), screen_(screen) {}
    void present(const Scene& s) override {
        if (!shown_) {
            shown_ = true;
            sink_->host_focus(true);
        }
        if (!dump_.empty()) write(s);
    }
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
    void activate() override { sink_->host_focus(true); }
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
                    const int sx = x * l.scale, sy = y * l.scale;
                    if (sx >= p.width || sy >= p.height) continue;
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
    bool shown_{false};
};

class HeadlessHost final : public Host {
public:
    explicit HeadlessHost(std::string dump) : loop_(make_poll_loop()), dump_(std::move(dump)) {}
    EventLoop& loop() override { return *loop_; }
    void attach(HostSink& s) override { sink_ = &s; }
    std::vector<OutputInfo> outputs() override {
        OutputInfo o;
        o.name = "HEADLESS-1";
        o.description = "linuxity headless output";
        o.model = "headless";
        o.logical = {0, 0, 1920, 1080};
        o.pixels = {1920, 1080};
        o.physical_mm = {520, 290};
        return {o};
    }
    KeyboardInfo keyboard() override { return {}; }
    std::unique_ptr<HostWindow> create_window(const WindowSpec& spec, WindowSink& sink) override {
        return std::make_unique<HeadlessWindow>(sink, spec, dump_, ++n_, Rect{0, 0, 1920, 1080});
    }
    void set_cursor(const CursorImage&) override {}
    void reset_cursor() override {}

private:
    std::unique_ptr<EventLoop> loop_;
    std::string dump_;
    HostSink* sink_{nullptr};
    int n_{0};
};

}  // namespace

std::unique_ptr<Host> make_headless_host(std::string dump_dir);
std::unique_ptr<Host> make_headless_host(std::string dump_dir) { return std::make_unique<HeadlessHost>(std::move(dump_dir)); }

}  // namespace lx::display
