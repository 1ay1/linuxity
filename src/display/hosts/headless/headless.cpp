// src/display/hosts/headless/headless.cpp -- a Host with no screen.
//
// Windows are bookkeeping only; with a dump directory every present is
// composited in software and written as <dir>/<n>-<title>.ppm, so tests can
// check the pixels a client drew without a display. Also the fallback on
// hosts that have no native backend yet.
#include "headless.hpp"

#include "core/soft_compose.hpp"

#include <cctype>
#include <cstdlib>
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
        // As Cocoa does mid live-resize: wait (pumping this client) for the
        // app to draw the new size, from inside the request's handler.
        if (log_ && log_->wait_on_configure)
            sink_->host_configure_and_wait(on ? screen_.size() : Size{}, st, std::chrono::milliseconds(200));
        else
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
        const ComposedImage img = soft_compose(s);
        if (img.width == 0) return;
        std::string safe;
        for (char c : title_) safe += (std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
        (void)write_ppm(img, (dump_ + "/" + std::to_string(n_) + "-" + safe + ".ppm").c_str());
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
    [[nodiscard]] bool native_frames() const override { return log_ && log_->native_frames; }
    void attach(HostSink& s) override { sink_ = &s; if (log_) log_->sink = &s; }
    std::vector<OutputInfo> outputs() override {
        OutputInfo o;
        o.name = "HEADLESS-1";
        o.description = "linuxity headless output";
        o.model = "headless";
        o.logical = {0, 0, 1920, 1080};
        o.fractional_scale = log_ ? log_->scale : 0;
        // LINUXITY_DISPLAY_SCALE=2: present a HiDPI output, as a Retina
        // screen does -- clients then draw (and share) 4x larger buffers.
        if (o.fractional_scale <= 0)
            if (const char* s = std::getenv("LINUXITY_DISPLAY_SCALE")) o.fractional_scale = std::atof(s);
        o.scale = o.fractional_scale > 0 ? static_cast<std::int32_t>(std::ceil(o.fractional_scale)) : 1;
        o.pixels = {1920 * o.scale, 1080 * o.scale};
        o.physical_mm = {520, 290};
        return {o};
    }
    std::unique_ptr<HostWindow> create_window(const WindowSpec& spec, WindowSink& sink) override {
        return std::make_unique<HeadlessWindow>(sink, spec, dump_, ++n_, Rect{0, 0, 1920, 1080}, log_);
    }
    void set_cursor(const CursorImage&) override { if (log_) log_->cursor_shape = 0; }
    void set_cursor_shape(CursorShape s) override { if (log_) log_->cursor_shape = static_cast<std::uint32_t>(s); }
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

// The registry entry (core/host_registry.hpp). Lowest priority: what runs
// when nothing better can, and what tests and CI ask for by name.
const lx::display::HostBackend& lx_display_host_headless() {
    static const lx::display::HostBackend b{
        .name = "headless",
        .summary = "no screen; --dump DIR writes every frame as a PPM",
        .priority = 0,
        .available = [] () noexcept { return true; },
        .create = [](const lx::display::HostConfig& c) { return lx::display::make_headless_host(c.dump_dir); },
    };
    return b;
}
