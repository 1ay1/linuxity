// linuxity/conform/trace_text.hpp
//
// The on-the-wire trace FORMAT: one line per observed syscall.
//
// POLICY, not a host facility -- so it lives here, written once, and every
// host parses and renders identically. That matters more than it sounds: this
// one format is used for BOTH directions,
//
//     probe stdout  --parse-->  Trace            (live, on Linux)
//     Trace         --render--> golden file      (recorded, on Linux CI)
//     golden file   --parse-->  Trace            (replayed, on macOS/Windows)
//
// so a recording is literally a captured probe run. One parser, one renderer,
// one grammar: a recording that round-trips is a recording the live path would
// have produced, and there is no second format to drift.
//
// THE GRAMMAR. Deliberately line-oriented and human-legible, because goldens
// are reviewed in diffs:
//
//     # comment / header, ignored by the parser
//     lseek = 368                      ; a success
//     lseek = -EINVAL                  ; a failure, by errno name
//     lseek = -errno(22)               ; a failure, numeric fallback
//     getdents64 = 384 | note          ; an optional label after '|'
//     getdents64 = 384 @1:61626300     ; a written buffer: @arg:hex
//
// Values are rendered by Returned::describe(), and parsed back by the inverse
// here, so the two cannot disagree about what "-EINVAL" means.
#pragma once

#include <cctype>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "linuxity/conform/observation.hpp"
#include "linuxity/conform/report.hpp"
#include "linuxity/conform/sysno_names.hpp"

namespace lx::conform {

namespace detail {

[[nodiscard]] inline std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

// Sysno by name -- the inverse of name_of, over the same generated table, so
// the two cannot disagree about a spelling.
[[nodiscard]] inline std::optional<abi::Sysno>
sysno_from_name(std::string_view n) noexcept {
    for (std::size_t i = 0; i < sysno_count; ++i) {
        const auto s = static_cast<abi::Sysno>(i);
        if (name_of(s) == n) return s;
    }
    return std::nullopt;
}

// errno by name, inverse of the renderer's table. Kept adjacent to it so a
// name added to one is visibly missing from the other.
[[nodiscard]] inline std::optional<std::int32_t>
errno_from_name(std::string_view n) noexcept {
    for (std::int32_t e = 1; e < 200; ++e) {
        const char* name = errno_name(e);
        if (name != nullptr && n == name) return e;
    }
    return std::nullopt;
}

[[nodiscard]] inline std::optional<std::int64_t>
parse_int(std::string_view s) noexcept {
    std::int64_t v = 0;
    const auto* begin = s.data();
    const auto* end = s.data() + s.size();
    const auto r = std::from_chars(begin, end, v);
    if (r.ec != std::errc{} || r.ptr != end) return std::nullopt;
    return v;
}

[[nodiscard]] inline std::optional<std::byte> hex_nibbles(char hi, char lo) noexcept {
    const auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    const int h = val(hi), l = val(lo);
    if (h < 0 || l < 0) return std::nullopt;
    return static_cast<std::byte>(static_cast<unsigned>(h * 16 + l));
}

} // namespace detail

// -- rendering -------------------------------------------------------------

// A full written buffer as hex. Unlike the report's 16-byte preview this is
// LOSSLESS, because a golden must reproduce the trace exactly.
[[nodiscard]] inline std::string render_written_exact(const Written& w) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s = "@" + std::to_string(w.arg) + ":";
    s.reserve(s.size() + w.bytes.size() * 2);
    for (const std::byte b : w.bytes) {
        const auto v = static_cast<unsigned>(b);
        s += digits[(v >> 4) & 0xF];
        s += digits[v & 0xF];
    }
    return s;
}

[[nodiscard]] inline std::string render_line(const Observation& o) {
    std::string s{name_of(o.call)};
    s += " = ";
    s += o.returned.describe();
    for (const Written& w : o.wrote) {
        s += ' ';
        s += render_written_exact(w);
    }
    if (!o.note.empty()) s += " | " + o.note;
    return s;
}

// A whole trace, with a header carrying the provenance a reader needs to
// interpret it. Comments are ignored on parse, so the header is free.
[[nodiscard]] inline std::string render_trace(const Trace& t,
                                              std::string_view provenance = {},
                                              std::string_view kernel = {}) {
    std::string s = "# linuxity conformance trace\n";
    s += "# scenario: " + t.scenario + "\n";
    if (!provenance.empty()) s += "# recorded-by: " + std::string{provenance} + "\n";
    if (!kernel.empty())     s += "# kernel: " + std::string{kernel} + "\n";
    for (const Observation& o : t.steps) s += render_line(o) + "\n";
    return s;
}

// -- parsing ---------------------------------------------------------------

// Why a trace could not be parsed. A SUM over the failure, not a bool, so a
// malformed golden reports its line rather than silently yielding a short
// trace that would then "diverge" on step_count.
struct ParseError {
    std::size_t line;
    std::string reason;

    ParseError(std::size_t l, std::string r) : line{l}, reason{std::move(r)} {}

    [[nodiscard]] std::string describe() const {
        return "line " + std::to_string(line) + ": " + reason;
    }
};

class ParsedTrace {
public:
    ParsedTrace(Trace t) : v_{std::move(t)} {}
    ParsedTrace(ParseError e) : v_{std::move(e)} {}

    template <class OnTrace, class OnError>
    [[nodiscard]] decltype(auto) match(OnTrace&& t, OnError&& e) const {
        if (const auto* tr = std::get_if<Trace>(&v_))
            return std::forward<OnTrace>(t)(*tr);
        return std::forward<OnError>(e)(std::get<ParseError>(v_));
    }

    [[nodiscard]] bool ok() const noexcept {
        return std::holds_alternative<Trace>(v_);
    }

private:
    std::variant<Trace, ParseError> v_;
};

[[nodiscard]] inline std::optional<Returned>
parse_returned(std::string_view v) noexcept {
    if (v.empty()) return std::nullopt;

    if (v.front() == '-') {
        const std::string_view rest = v.substr(1);
        // -errno(22)
        if (rest.starts_with("errno(") && rest.ends_with(")")) {
            const auto n = detail::parse_int(
                rest.substr(6, rest.size() - 7));
            if (!n) return std::nullopt;
            return Returned::failed(static_cast<std::int32_t>(*n));
        }
        // -EINVAL
        if (const auto e = detail::errno_from_name(rest))
            return Returned::failed(*e);
        // A plain negative value is a legitimate return, not an errno: the
        // renderer always spells errnos by name or as errno(N), so reaching
        // here means a real negative result.
    }
    if (const auto n = detail::parse_int(v)) return Returned::ok(*n);
    return std::nullopt;
}

[[nodiscard]] inline ParsedTrace parse_trace(std::string_view text,
                                             std::string scenario) {
    Trace t{std::move(scenario)};
    std::size_t lineno = 0;

    while (!text.empty()) {
        ++lineno;
        const auto nl = text.find('\n');
        const std::string_view raw =
            nl == std::string_view::npos ? text : text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{}
                                            : text.substr(nl + 1);

        const std::string_view line = detail::trim(raw);
        if (line.empty() || line.front() == '#') continue;

        // Split off an optional ` | note`.
        std::string_view body = line;
        std::string      note;
        if (const auto bar = body.find('|'); bar != std::string_view::npos) {
            note = std::string{detail::trim(body.substr(bar + 1))};
            body = detail::trim(body.substr(0, bar));
        }

        const auto eq = body.find('=');
        if (eq == std::string_view::npos)
            return ParseError{lineno, "expected `name = value`"};

        const std::string_view name = detail::trim(body.substr(0, eq));
        const auto call = detail::sysno_from_name(name);
        if (!call)
            return ParseError{lineno, "unknown syscall `" + std::string{name} + "`"};

        // The value runs to the first ` @` (a written buffer) if present.
        std::string_view tail = detail::trim(body.substr(eq + 1));
        std::string_view value = tail;
        std::vector<Written> wrote;

        if (const auto at = tail.find('@'); at != std::string_view::npos) {
            value = detail::trim(tail.substr(0, at));
            std::string_view bufs = tail.substr(at);
            while (!bufs.empty() && bufs.front() == '@') {
                bufs.remove_prefix(1);
                const auto colon = bufs.find(':');
                if (colon == std::string_view::npos)
                    return ParseError{lineno, "buffer needs @arg:hex"};
                const auto arg = detail::parse_int(bufs.substr(0, colon));
                if (!arg) return ParseError{lineno, "bad buffer arg index"};

                bufs.remove_prefix(colon + 1);
                const auto end = bufs.find_first_of(" \t@");
                const std::string_view hex =
                    end == std::string_view::npos ? bufs : bufs.substr(0, end);
                if (hex.size() % 2 != 0)
                    return ParseError{lineno, "buffer hex has odd length"};

                std::vector<std::byte> bytes;
                bytes.reserve(hex.size() / 2);
                for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
                    const auto b = detail::hex_nibbles(hex[i], hex[i + 1]);
                    if (!b) return ParseError{lineno, "buffer has non-hex digit"};
                    bytes.push_back(*b);
                }
                wrote.emplace_back(static_cast<int>(*arg), std::move(bytes));

                bufs = end == std::string_view::npos ? std::string_view{}
                                                     : detail::trim(bufs.substr(end));
            }
        }

        const auto ret = parse_returned(value);
        if (!ret)
            return ParseError{lineno, "bad value `" + std::string{value} + "`"};

        Observation o{*call, *ret};
        o.wrote = std::move(wrote);
        o.note = std::move(note);
        t.steps.push_back(std::move(o));
    }

    return t;
}

} // namespace lx::conform
