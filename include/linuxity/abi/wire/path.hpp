// linuxity/abi/wire/path.hpp
//
// Guest path normalization: resolving `.` and `..` textually, once.
//
// WHY THIS FILE EXISTS. The algorithm was implemented twice:
//
//   kernel/file_namespace.hpp  normalize()        in-place truncation
//   runtime/windows/sys.hpp    normalize_guest()  vector-of-components
//
// Two different implementations of the same semantics. I diffed them across
// 20 inputs -- "/..", "/a/b/../../..", "///a", "/...", "/a/..b", "/a/./././b"
// -- and they agreed on every one. That is not reassuring, it is a warning:
// two algorithms that agree today will diverge the first time someone fixes
// an edge case in one of them, and path normalization is security-relevant.
// A `..` that escapes the guest root is a sandbox hole.
//
// So it lives here, host-free, where both can call it. This is textual
// normalization ONLY -- it does not touch the filesystem and does not follow
// symlinks, which is deliberate: the caller resolves symlinks through the
// mount table afterwards, and doing it here would make the function depend on
// a host.
#pragma once

#include <string>
#include <string_view>

namespace lx::abi::wire {

// Collapse `.`, `..` and duplicate separators in an ABSOLUTE guest path.
//
// Guarantees, each pinned by a static_assert-equivalent test in test_wire:
//   * the result always starts with '/'
//   * no trailing '/' except for the root itself ("/a/" -> "/a")
//   * no empty components ("/a//b" -> "/a/b")
//   * `..` at or above the root is clamped, never escapes ("/.." -> "/")
//
// That last one is the security-relevant case: a guest path must never
// normalize to something outside the root, or the overlay translates it to a
// host path above the rootfs.
[[nodiscard]] inline std::string normalize_path(std::string_view p) {
    std::string out;
    out.reserve(p.size() + 1);
    out += '/';
    std::size_t i = 0;
    while (i < p.size()) {
        while (i < p.size() && p[i] == '/') ++i;      // skip separators
        std::size_t j = i;
        while (j < p.size() && p[j] != '/') ++j;
        if (j > i) {
            const std::string_view comp = p.substr(i, j - i);
            if (comp == ".") {
                // skip
            } else if (comp == "..") {
                // Drop the last component AND its separator, leaving "/" only
                // when we have popped back to the root. Truncating to
                // rfind('/')+1 instead would leave the slash behind, so the
                // next component would double it ("/a//b") and a later ".."
                // would strip only that empty tail.
                if (out.size() > 1) {
                    const std::size_t slash = out.rfind('/');
                    out.resize(slash == 0 ? 1 : slash);
                }
            } else {
                if (out.size() > 1) out += '/';
                out += comp;
            }
        }
        i = j;
    }
    // Trailing '/' survives only for the root itself; "/a/" -> "/a".
    if (out.size() > 1 && out.back() == '/') out.pop_back();
    return out;
}

// Absolutize `path` against `cwd`, then normalize. An empty path means the
// cwd itself, which is what the *at syscalls expect for an empty pathname
// with AT_EMPTY_PATH.
[[nodiscard]] inline std::string absolutize_path(std::string_view path,
                                                 std::string_view cwd) {
    if (path.empty()) return normalize_path(cwd);
    if (path.front() == '/') return normalize_path(path);
    std::string joined;
    joined.reserve(cwd.size() + path.size() + 1);
    joined += cwd;
    if (!joined.empty() && joined.back() != '/') joined += '/';
    joined += path;
    return normalize_path(joined);
}

} // namespace lx::abi::wire
