// src/display/core/geometry.hpp -- points, sizes, rects and regions in
// logical (scale-independent) pixels, y down.
#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

namespace lx::display {

struct Point {
    std::int32_t x{0}, y{0};
    friend constexpr Point operator+(Point a, Point b) noexcept { return {a.x + b.x, a.y + b.y}; }
    friend constexpr Point operator-(Point a, Point b) noexcept { return {a.x - b.x, a.y - b.y}; }
    friend constexpr bool operator==(Point, Point) noexcept = default;
};

struct Size {
    std::int32_t w{0}, h{0};
    [[nodiscard]] constexpr bool empty() const noexcept { return w <= 0 || h <= 0; }
    friend constexpr bool operator==(Size, Size) noexcept = default;
};

struct Rect {
    std::int32_t x{0}, y{0}, w{0}, h{0};
    [[nodiscard]] constexpr Point origin() const noexcept { return {x, y}; }
    [[nodiscard]] constexpr Size size() const noexcept { return {w, h}; }
    [[nodiscard]] constexpr bool empty() const noexcept { return w <= 0 || h <= 0; }
    [[nodiscard]] constexpr bool contains(double px, double py) const noexcept {
        return px >= x && py >= y && px < x + w && py < y + h;
    }
    [[nodiscard]] constexpr Rect moved(Point d) const noexcept { return {x + d.x, y + d.y, w, h}; }
    [[nodiscard]] constexpr Rect united(Rect o) const noexcept {
        if (empty()) return o;
        if (o.empty()) return *this;
        const auto l = std::min(x, o.x), t = std::min(y, o.y);
        const auto r = std::max(x + w, o.x + o.w), b = std::max(y + h, o.y + o.h);
        return {l, t, r - l, b - t};
    }
    friend constexpr bool operator==(Rect, Rect) noexcept = default;
};

// wl_region: an ordered list of add/subtract rectangles. Point queries
// replay it, which is exact and cheap for the handful of rects clients send.
class Region {
public:
    void add(Rect r) { ops_.push_back({r, true}); }
    void subtract(Rect r) { ops_.push_back({r, false}); }
    [[nodiscard]] bool contains(double x, double y) const noexcept {
        bool in = false;
        for (const auto& [r, add] : ops_)
            if (r.contains(x, y)) in = add;
        return in;
    }
    [[nodiscard]] bool empty() const noexcept { return ops_.empty(); }
private:
    struct Op { Rect r; bool add; };
    std::vector<Op> ops_;
};

}  // namespace lx::display
