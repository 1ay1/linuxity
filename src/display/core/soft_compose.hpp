// src/display/core/soft_compose.hpp -- a window's Scene as one image, in
// software.
//
// For any host that shows a window as a single bitmap -- an Android
// ANativeWindow, a Win32 DIB section, a Linux framebuffer, the headless
// dump -- instead of handing each layer to a platform compositor (as the
// Cocoa host does with CALayers). It does what the protocol says a
// compositor does: every layer's `source` crop stretched over its `rect`,
// premultiplied alpha "over", in stacking order, clipped to the view.
#pragma once

#include "host.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace lx::display {

// The composed image, premultiplied BGRA (PixelFormat::argb8888 byte order),
// `width` x `height` = the view's size times `scale`.
struct ComposedImage {
    std::int32_t width{0}, height{0};
    std::vector<std::uint8_t> bgra;      // stride = width * 4
};

// Compose `s` at `scale` device pixels per logical pixel (1 for headless,
// the output's integer scale for a HiDPI framebuffer).
[[nodiscard]] ComposedImage soft_compose(const Scene& s, std::int32_t scale = 1);

// Write `img` as a binary PPM (opaque RGB) -- a debugging aid and the
// headless host's dump format.
bool write_ppm(const ComposedImage& img, const char* path);

}  // namespace lx::display
