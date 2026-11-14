// src/display/core/host_registry.hpp -- the hosts this build carries, and
// how linuxity-display picks one.
//
// A host backend is one directory under hosts/ that defines ONE function:
//
//     const lx::display::HostBackend& lx_display_host_<name>();
//
// and one CMake call, lx_display_host(<name> SOURCES ... LIBRARIES ...).
// The build generates the list of backends from those calls (host_list.inc),
// so nothing else -- not main.cpp, not this file -- names a platform. No
// static-initialization registrars either: those silently vanish when the
// linker drops an unreferenced object from a static library, and their order
// is unspecified. This list is explicit, ordered, and checked at link time.
#pragma once

#include "host.hpp"

#include <map>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace lx::display {

// What every backend may be configured with. Generic switches are fields;
// anything platform-specific travels in `params` (--host-opt key=value), so a
// new host needs no new command-line plumbing.
struct HostConfig {
    std::string dump_dir;                              // write every present as an image (headless)
    std::map<std::string, std::string, std::less<>> params;
    [[nodiscard]] std::string_view param(std::string_view key, std::string_view fallback = {}) const {
        const auto it = params.find(key);
        return it == params.end() ? fallback : std::string_view{it->second};
    }
};

struct HostBackend {
    std::string_view name;          // "cocoa", "headless", "android", "win32", ...
    std::string_view summary;       // one line, for --list-hosts
    int priority{0};                // the best AVAILABLE one wins unless one is chosen
    // Can it run here and now -- a GUI session, a display connection? Cheap,
    // and without side effects (no window, no app registration).
    bool (*available)() noexcept{nullptr};
    std::unique_ptr<Host> (*create)(const HostConfig& cfg){nullptr};
};

// Every backend linked into this binary, highest priority first.
[[nodiscard]] std::span<const HostBackend* const> host_backends();
// The one named `name`, or nullptr.
[[nodiscard]] const HostBackend* find_host(std::string_view name);
// The highest-priority backend that is available (headless always is).
[[nodiscard]] const HostBackend* best_host();

}  // namespace lx::display
