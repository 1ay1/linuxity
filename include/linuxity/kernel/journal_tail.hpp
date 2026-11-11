// linuxity/kernel/journal_tail.hpp
//
// Following an append-only journal that OTHER processes also append to.
//
// The overlay keeps two journals beside the upper layer: metadata (owners,
// modes) and whiteouts (deleted lower files). Each linuxity process caches
// them in memory. Where every guest process is its own linuxity (macOS:
// fork = a new process), each cache must catch up on what the others
// appended -- or `rm f; stat f` from the next process still finds f (dpkg
// then refused to rename over a file that no longer existed).
//
// One follower for both, so the rules are spelled once:
//   - one stat(2) when nothing changed;
//   - a REPLACED journal (compaction: new inode, or shorter) is re-read whole;
//   - only COMPLETE lines are consumed, so a line another process is half-way
//     through appending is read on the next call;
//   - our own appends do NOT advance the position: another process may have
//     appended before us, and skipping to the end would lose its line. The
//     next follow() replays ours again, which is harmless (last line wins).
#pragma once

#include <sys/stat.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace lx::kernel {

class JournalTail {
public:
    void set_path(std::string p) { path_ = std::move(p); pos_ = 0; ino_ = 0; }
    [[nodiscard]] const std::string& path() const noexcept { return path_; }

    // Fold in what was appended since the last call. `reset()` is called
    // first when the journal was replaced; `line(sv)` for each new complete
    // line (without its newline). Returns the lines read.
    template <class Reset, class Line>
    std::size_t follow(Reset&& reset, Line&& line) {
        if (path_.empty()) return 0;
        struct ::stat st{};
        if (::stat(path_.c_str(), &st) != 0) return 0;
        const auto size = static_cast<long long>(st.st_size);
        const auto ino = static_cast<std::uint64_t>(st.st_ino);
        if (size == pos_ && ino == ino_) return 0;
        if (ino != ino_ || size < pos_) { reset(); pos_ = 0; }
        ino_ = ino;
        std::FILE* fp = std::fopen(path_.c_str(), "r");
        if (!fp) return 0;
        if (pos_ > 0 && std::fseek(fp, static_cast<long>(pos_), SEEK_SET) != 0) { std::fclose(fp); return 0; }
        std::size_t n = 0;
        char buf[8192];
        while (std::fgets(buf, sizeof buf, fp)) {
            std::size_t len = std::strlen(buf);
            if (len == 0 || buf[len - 1] != '\n') break;      // torn tail: not yet
            pos_ += static_cast<long long>(len);
            ++n;
            while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) --len;
            line(std::string_view{buf, len});
        }
        std::fclose(fp);
        return n;
    }

    // Read from the start (at load time).
    template <class Reset, class Line>
    std::size_t reload(Reset&& reset, Line&& line) {
        pos_ = 0; ino_ = 0;
        return follow(std::forward<Reset>(reset), std::forward<Line>(line));
    }

    // We just rewrote the journal from our own table (compaction): it is
    // already folded in, so don't read it back as someone else's.
    void adopt() {
        struct ::stat st{};
        if (::stat(path_.c_str(), &st) == 0) {
            pos_ = static_cast<long long>(st.st_size);
            ino_ = static_cast<std::uint64_t>(st.st_ino);
        }
    }

private:
    std::string path_;
    long long pos_{0};          // journal bytes already folded in
    std::uint64_t ino_{0};      // ...of this inode
};

}  // namespace lx::kernel
