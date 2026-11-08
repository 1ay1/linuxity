// linuxity/host/tmpdir.hpp
//
// Where the runtime keeps its own scratch (private /tmp, ephemeral upper,
// shm fallback, temp virtual files). /tmp where it is writable; otherwise
// $LINUXITY_TMPDIR or $TMPDIR. An Android app has no writable /tmp at all,
// so it passes its cache dir.
#pragma once

#include <cstdlib>
#include <string>
#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace lx::host {

[[nodiscard]] inline const std::string& tmp_base() {
    static const std::string base = [] {
#if defined(_WIN32)
        const char* t = std::getenv("TEMP");
        return std::string{t && *t ? t : "."};
#else
        for (const char* var : {"LINUXITY_TMPDIR", "TMPDIR"}) {
            const char* v = std::getenv(var);
            if (v && *v == '/' && ::access(v, W_OK | X_OK) == 0) {
                std::string s{v};
                while (s.size() > 1 && s.back() == '/') s.pop_back();
                return s;
            }
        }
        return std::string{"/tmp"};
#endif
    }();
    return base;
}

// tmp_base() + "/" + leaf
[[nodiscard]] inline std::string tmp_path(const std::string& leaf) { return tmp_base() + "/" + leaf; }

}  // namespace lx::host
