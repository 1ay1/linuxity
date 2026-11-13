// src/display/core/loop.hpp -- the event loop the compositor core runs on.
//
// The core never blocks and never owns a thread: it asks the loop to call it
// when a client socket is readable or writable, on a timer, or "soon". Each
// host backend supplies the loop that fits its platform -- Cocoa's main
// dispatch queue on macOS (UI must run there), poll(2) for headless and the
// POSIX hosts, a message loop on Windows -- so the core stays the same code.
#pragma once

#include <chrono>
#include <functional>
#include <memory>

namespace lx::display {

class EventLoop {
public:
    // Destroying a Source cancels it; safe from inside its own callback.
    class Source {
    public:
        virtual ~Source() = default;
    };
    using Fn = std::function<void()>;

    virtual ~EventLoop() = default;
    [[nodiscard]] virtual std::unique_ptr<Source> on_readable(int fd, Fn fn) = 0;
    [[nodiscard]] virtual std::unique_ptr<Source> on_writable(int fd, Fn fn) = 0;
    [[nodiscard]] virtual std::unique_ptr<Source> every(std::chrono::microseconds period, Fn fn) = 0;
    // Run fn on the loop after the current callback returns.
    virtual void defer(Fn fn) = 0;
    virtual void run() = 0;
    virtual void stop() = 0;
};

// A poll(2) loop: headless runs, and any POSIX host without a UI loop.
[[nodiscard]] std::unique_ptr<EventLoop> make_poll_loop();

}  // namespace lx::display
