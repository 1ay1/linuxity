// src/display/core/soft_compose.cpp -- see soft_compose.hpp.
#include "soft_compose.hpp"

#include <algorithm>
#include <cstdio>

namespace lx::display {

namespace {

struct Rgba { float r, g, b, a; };

[[nodiscard]] Rgba texel(const Pixels& p, int sx, int sy) noexcept {
    const auto* px = reinterpret_cast<const unsigned char*>(p.data.data()) +
                     static_cast<std::size_t>(sy) * static_cast<std::size_t>(p.stride) +
                     static_cast<std::size_t>(sx) * 4;
    switch (p.format) {
        case PixelFormat::argb8888: return {float(px[2]), float(px[1]), float(px[0]), float(px[3])};
        case PixelFormat::xrgb8888: return {float(px[2]), float(px[1]), float(px[0]), 255.f};
        case PixelFormat::abgr8888: return {float(px[0]), float(px[1]), float(px[2]), float(px[3])};
        default:                    return {float(px[0]), float(px[1]), float(px[2]), 255.f};
    }
}

}  // namespace

ComposedImage soft_compose(const Scene& s, std::int32_t scale) {
    ComposedImage out;
    const Rect v = s.view;
    if (v.empty() || scale < 1) return out;
    out.width = v.w * scale;
    out.height = v.h * scale;
    std::vector<float> acc(static_cast<std::size_t>(out.width) * static_cast<std::size_t>(out.height) * 4, 0.f);
    for (const Layer& l : s.layers) {
        if (!l.pixels || l.rect.empty()) continue;
        const Pixels& p = *l.pixels;
        // the layer shows `source` of its buffer stretched over `rect`
        const SourceRect src = l.source.whole()
            ? SourceRect{0, 0, static_cast<double>(p.width), static_cast<double>(p.height)} : l.source;
        // device-pixel bounds of the layer, clipped to the view
        const int x0 = std::max(0, (l.rect.x - v.x) * scale), y0 = std::max(0, (l.rect.y - v.y) * scale);
        const int x1 = std::min(out.width, (l.rect.x + l.rect.w - v.x) * scale);
        const int y1 = std::min(out.height, (l.rect.y + l.rect.h - v.y) * scale);
        const double lw = double(l.rect.w) * scale, lh = double(l.rect.h) * scale;
        const int ox = (l.rect.x - v.x) * scale, oy = (l.rect.y - v.y) * scale;
        for (int dy = y0; dy < y1; ++dy) {
            const int sy = static_cast<int>(src.y + (dy - oy + 0.5) * src.h / lh);
            if (sy < 0 || sy >= p.height) continue;
            for (int dx = x0; dx < x1; ++dx) {
                const int sx = static_cast<int>(src.x + (dx - ox + 0.5) * src.w / lw);
                if (sx < 0 || sx >= p.width) continue;
                const Rgba t = texel(p, sx, sy);
                float* d = &acc[(static_cast<std::size_t>(dy) * static_cast<std::size_t>(out.width) +
                                 static_cast<std::size_t>(dx)) * 4];
                const float k = 1.f - t.a / 255.f;    // premultiplied over
                d[0] = t.b + d[0] * k;
                d[1] = t.g + d[1] * k;
                d[2] = t.r + d[2] * k;
                d[3] = t.a + d[3] * k;
            }
        }
    }
    out.bgra.resize(acc.size());
    std::ranges::transform(acc, out.bgra.begin(),
                           [](float c) { return static_cast<std::uint8_t>(std::clamp(c, 0.f, 255.f)); });
    return out;
}

bool write_ppm(const ComposedImage& img, const char* path) {
    std::FILE* f = std::fopen(path, "wb");
    if (!f) return false;
    std::fprintf(f, "P6\n%d %d\n255\n", img.width, img.height);
    std::vector<std::uint8_t> row(static_cast<std::size_t>(img.width) * 3);
    for (int y = 0; y < img.height; ++y) {
        const std::uint8_t* s = &img.bgra[static_cast<std::size_t>(y) * static_cast<std::size_t>(img.width) * 4];
        for (int x = 0; x < img.width; ++x) {
            row[static_cast<std::size_t>(x) * 3 + 0] = s[x * 4 + 2];
            row[static_cast<std::size_t>(x) * 3 + 1] = s[x * 4 + 1];
            row[static_cast<std::size_t>(x) * 3 + 2] = s[x * 4 + 0];
        }
        std::fwrite(row.data(), 1, row.size(), f);
    }
    return std::fclose(f) == 0;
}

}  // namespace lx::display
