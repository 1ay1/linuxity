// linuxity/env/status.hpp
//
// Machine-readable notes about what the runtime decided at startup (where
// DNS came from, how limits are enforced, which compat paths are on) and
// what happened later (ready, exit). Each is one JSON object per line on
// --status-fd, so a frontend can show them without scraping stderr. The
// human sentence still goes to stderr unless --quiet.
#pragma once

#include "linuxity/env/json.hpp"

#include <cerrno>
#include <cstdio>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace lx::env {

class Status {
public:
    void set_fd(int fd) noexcept { fd_ = fd; }
    void set_quiet(bool q) noexcept { quiet_ = q; }
    [[nodiscard]] int fd() const noexcept { return fd_; }
    [[nodiscard]] bool quiet() const noexcept { return quiet_; }

    // `fields` is a Json object already opened by the caller's builder; see
    // event() below for the usual shape.
    void emit(const std::string& line) const {
        if (fd_ < 0) return;
        std::string l = line;
        l.push_back('\n');
        const char* p = l.data();
        std::size_t n = l.size();
        while (n > 0) {
            const ::ssize_t w = ::write(fd_, p, n);
            if (w < 0) { if (errno == EINTR) continue; return; }
            p += w;
            n -= static_cast<std::size_t>(w);
        }
    }

    void say(std::string_view human) const {
        if (quiet_ || human.empty()) return;
        std::fprintf(stderr, "linuxity: %.*s\n", static_cast<int>(human.size()), human.data());
    }

    // One event: {"event": kind, ...fill...}, plus its human line.
    template <class Fill>
    void event(std::string_view kind, std::string_view human, Fill&& fill) {
        say(human);
        Json j;
        j.obj().kv("event", kind);
        if (!human.empty()) j.kv("text", human);
        fill(j);
        j.end();
        history_.push_back(j.text());
        emit(j.text());
    }
    void event(std::string_view kind, std::string_view human) {
        event(kind, human, [](Json&) {});
    }
    // every event so far, oldest first (JSON lines)
    [[nodiscard]] const std::vector<std::string>& history() const { return history_; }

private:
    int fd_{-1};
    bool quiet_{false};
    std::vector<std::string> history_;
};

// The process-wide sink. One per linuxity process, set up from the flags.
inline Status& status() {
    static Status s;
    return s;
}

}  // namespace lx::env
