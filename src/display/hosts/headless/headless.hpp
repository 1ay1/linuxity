// src/display/hosts/headless/headless.hpp -- the screenless host.
//
// Also the reference backend: the smallest complete Host, and what the
// host conformance tests (tests/display/host_conformance.hpp) run against.
#pragma once

#include "core/host_registry.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace lx::display {

// What a headless host was asked to do, for tests to assert on.
struct HeadlessLog {
    double scale{0};                       // the output's scale (0: 1)
    bool native_frames{false};             // act like a desktop host that frames windows
    bool wait_on_configure{false};         // maximize waits for the redraw, re-entering the client
    HostSink* sink{nullptr};               // to inject keys and IME text
    struct Present { std::uint64_t id; Rect damage; std::uint64_t generation; SourceRect source; Rect rect; };
    std::vector<Present> presents;
    int attention{0}, activations{0}, bells{0};
    std::uint32_t cursor_shape{0};         // 0: a client bitmap (or none yet)
    std::optional<Rect> text_input;        // the host's IME is on, here
};

// dump_dir: write <dir>/<n>-<title>.ppm per present ("" = don't).
[[nodiscard]] std::unique_ptr<Host> make_headless_host(std::string dump_dir, HeadlessLog* log = nullptr);

}  // namespace lx::display
