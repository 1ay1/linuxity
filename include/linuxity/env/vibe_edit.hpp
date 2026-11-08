// linuxity/env/vibe_edit.hpp
//
// Edits a VIBE document as TEXT, so `linuxity env set` keeps the user's
// comments, ordering and layout. vibe_emit() would rewrite the whole file
// canonically and drop every comment.
//
// It understands just enough of the grammar: `key value`, `key [ ... ]`
// (possibly over several lines) and `key {` ... `}` blocks. The caller
// re-parses the result with libvibe to confirm the edit took.
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lx::env::vibe_edit {

struct Stmt {
    std::string path;       // dotted
    std::size_t first{0};   // first line
    std::size_t last{0};    // last line (the closing brace for a block)
    bool block{false};
    int depth{0};
};

struct Scan {
    std::vector<std::string> lines;
    std::vector<Stmt> stmts;
    bool ok{true};
};

[[nodiscard]] inline bool is_ident(std::string_view s) {
    if (s.empty()) return false;
    for (const char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-'))
            return false;
    return true;
}

[[nodiscard]] inline std::string quote(std::string_view s) {
    std::string out = "\"";
    for (const char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        if (c == '\n') { out += "\\n"; continue; }
        if (c == '\t') { out += "\\t"; continue; }
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

[[nodiscard]] inline std::string key_text(std::string_view k) {
    return is_ident(k) ? std::string{k} : quote(k);
}

// Can `s` be written bare as a VIBE string (no quotes)?
[[nodiscard]] inline bool bare_string_ok(std::string_view s) {
    if (s.empty() || s == "true" || s == "false") return false;
    for (const char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.' || c == '/' || c == ':' || c == '@'))
            return false;
    // anything number-shaped would parse as a number
    std::size_t i = s[0] == '-' ? 1 : 0;
    bool digits = i < s.size(), dot = false;
    for (; i < s.size() && digits; ++i) {
        if (s[i] == '.' && !dot) { dot = true; continue; }
        digits = s[i] >= '0' && s[i] <= '9';
    }
    return !digits;
}

[[nodiscard]] inline std::string string_text(std::string_view s) {
    return bare_string_ok(s) ? std::string{s} : quote(s);
}

namespace detail {

struct Tok {
    enum Kind { word, open_brace, close_brace, open_bracket, close_bracket } kind;
    std::string text;   // unquoted for words
};

// Tokens of one line, ignoring the comment. false on an unterminated string.
inline bool tokens(std::string_view line, std::vector<Tok>& out) {
    std::size_t i = 0;
    while (i < line.size()) {
        const char c = line[i];
        if (c == ' ' || c == '\t' || c == '\r') { ++i; continue; }
        if (c == '#') break;
        if (c == '{') { out.push_back({Tok::open_brace, {}}); ++i; continue; }
        if (c == '}') { out.push_back({Tok::close_brace, {}}); ++i; continue; }
        if (c == '[') { out.push_back({Tok::open_bracket, {}}); ++i; continue; }
        if (c == ']') { out.push_back({Tok::close_bracket, {}}); ++i; continue; }
        if (c == '"') {
            std::string s;
            ++i;
            bool closed = false;
            while (i < line.size()) {
                const char d = line[i++];
                if (d == '\\' && i < line.size()) { s.push_back(line[i++]); continue; }
                if (d == '"') { closed = true; break; }
                s.push_back(d);
            }
            if (!closed) return false;
            out.push_back({Tok::word, std::move(s)});
            continue;
        }
        std::size_t j = i;
        while (j < line.size() && line[j] != ' ' && line[j] != '\t' && line[j] != '#' &&
               line[j] != '{' && line[j] != '}' && line[j] != '[' && line[j] != ']' && line[j] != '\r')
            ++j;
        out.push_back({Tok::word, std::string{line.substr(i, j - i)}});
        i = j;
    }
    return true;
}

}  // namespace detail

[[nodiscard]] inline Scan scan(std::string_view text) {
    Scan sc;
    std::size_t at = 0;
    while (at <= text.size()) {
        const auto nl = text.find('\n', at);
        sc.lines.emplace_back(text.substr(at, (nl == std::string_view::npos ? text.size() : nl) - at));
        if (nl == std::string_view::npos) break;
        at = nl + 1;
    }
    if (!sc.lines.empty() && sc.lines.back().empty()) sc.lines.pop_back();

    std::vector<std::size_t> open;   // indexes into stmts of open blocks
    std::vector<std::string> path;
    int in_array = -1;               // stmt index of an array still open
    for (std::size_t ln = 0; ln < sc.lines.size(); ++ln) {
        std::vector<detail::Tok> t;
        if (!detail::tokens(sc.lines[ln], t)) { sc.ok = false; return sc; }
        std::size_t k = 0;
        if (in_array >= 0) {
            for (; k < t.size(); ++k)
                if (t[k].kind == detail::Tok::close_bracket) {
                    sc.stmts[static_cast<std::size_t>(in_array)].last = ln;
                    in_array = -1;
                    ++k;
                    break;
                }
            if (in_array >= 0) continue;
        }
        while (k < t.size()) {
            if (t[k].kind == detail::Tok::close_brace) {
                if (open.empty()) { sc.ok = false; return sc; }
                sc.stmts[open.back()].last = ln;
                open.pop_back();
                path.pop_back();
                ++k;
                continue;
            }
            if (t[k].kind != detail::Tok::word || k + 1 >= t.size()) { sc.ok = false; return sc; }
            std::string full;
            for (const auto& p : path) full += p + ".";
            full += t[k].text;
            Stmt s{full, ln, ln, false, static_cast<int>(path.size())};
            const auto& v = t[k + 1];
            if (v.kind == detail::Tok::open_brace) {
                s.block = true;
                sc.stmts.push_back(s);
                open.push_back(sc.stmts.size() - 1);
                path.push_back(t[k].text);
                k += 2;
            } else if (v.kind == detail::Tok::open_bracket) {
                sc.stmts.push_back(s);
                std::size_t m = k + 2;
                while (m < t.size() && t[m].kind != detail::Tok::close_bracket) ++m;
                if (m < t.size()) k = m + 1;
                else { in_array = static_cast<int>(sc.stmts.size() - 1); k = t.size(); }
            } else if (v.kind == detail::Tok::word) {
                sc.stmts.push_back(s);
                k += 2;
            } else {
                sc.ok = false;
                return sc;
            }
        }
    }
    if (!open.empty() || in_array >= 0) sc.ok = false;
    return sc;
}

namespace detail {

inline std::string join(const std::vector<std::string>& lines) {
    std::string out;
    for (const auto& l : lines) { out += l; out.push_back('\n'); }
    return out;
}

inline std::string indent_of(std::string_view line) {
    std::size_t i = 0;
    while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
    return std::string{line.substr(0, i)};
}

// the "# ..." tail of a line, outside any string
inline std::string comment_of(std::string_view line) {
    bool in_str = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        if (in_str) {
            if (line[i] == '\\') ++i;
            else if (line[i] == '"') in_str = false;
        } else if (line[i] == '"') {
            in_str = true;
        } else if (line[i] == '#') {
            return std::string{line.substr(i)};
        }
    }
    return {};
}

inline std::vector<std::string> split(std::string_view p) {
    std::vector<std::string> out;
    while (true) {
        const auto d = p.find('.');
        out.emplace_back(p.substr(0, d));
        if (d == std::string_view::npos) break;
        p.remove_prefix(d + 1);
    }
    return out;
}

}  // namespace detail

// Set `path` to the already-rendered VIBE value `value` ("x", "[ a b ]",
// "true"). Returns the new text, or nullopt if the document couldn't be
// understood or `path` names a block.
[[nodiscard]] inline std::optional<std::string> set(std::string_view text, std::string_view path,
                                                    std::string_view value) {
    Scan sc = scan(text);
    if (!sc.ok) return std::nullopt;
    const auto segs = detail::split(path);

    // replace the last assignment of this path (last one wins in VIBE)
    for (auto it = sc.stmts.rbegin(); it != sc.stmts.rend(); ++it) {
        if (it->path != path) continue;
        if (it->block) return std::nullopt;
        const std::string tail = it->first == it->last ? detail::comment_of(sc.lines[it->first]) : "";
        std::string line = detail::indent_of(sc.lines[it->first]) + key_text(segs.back()) + " " +
                           std::string{value};
        if (!tail.empty()) line += "  " + tail;
        sc.lines.erase(sc.lines.begin() + static_cast<std::ptrdiff_t>(it->first) + 1,
                       sc.lines.begin() + static_cast<std::ptrdiff_t>(it->last) + 1);
        sc.lines[it->first] = std::move(line);
        return detail::join(sc.lines);
    }

    // the deepest block that already exists on the way to `path`
    std::size_t have = 0;
    const Stmt* parent = nullptr;
    for (std::size_t n = segs.size() - 1; n > 0; --n) {
        std::string pre;
        for (std::size_t i = 0; i < n; ++i) pre += (i ? "." : "") + segs[i];
        for (auto it = sc.stmts.rbegin(); it != sc.stmts.rend(); ++it)
            if (it->block && it->path == pre) { parent = &*it; break; }
        if (parent) { have = n; break; }
    }
    std::vector<std::string> add;
    const std::size_t base = parent ? static_cast<std::size_t>(parent->depth) + 1 : 0;
    for (std::size_t i = have; i + 1 < segs.size(); ++i)
        add.push_back(std::string(2 * (base + i - have), ' ') + key_text(segs[i]) + " {");
    add.push_back(std::string(2 * (base + segs.size() - 1 - have), ' ') + key_text(segs.back()) +
                  " " + std::string{value});
    for (std::size_t i = segs.size() - 1; i-- > have;)
        add.push_back(std::string(2 * (base + i - have), ' ') + "}");

    if (parent) {
        sc.lines.insert(sc.lines.begin() + static_cast<std::ptrdiff_t>(parent->last), add.begin(), add.end());
    } else {
        if (!sc.lines.empty() && !sc.lines.back().empty() && add.size() > 1) sc.lines.emplace_back();
        sc.lines.insert(sc.lines.end(), add.begin(), add.end());
    }
    return detail::join(sc.lines);
}

// Remove every assignment (or block) at `path`. nullopt if unparseable;
// the text unchanged if it wasn't there.
[[nodiscard]] inline std::optional<std::string> unset(std::string_view text, std::string_view path) {
    Scan sc = scan(text);
    if (!sc.ok) return std::nullopt;
    for (auto it = sc.stmts.rbegin(); it != sc.stmts.rend(); ++it) {
        if (it->path != path) continue;
        sc.lines.erase(sc.lines.begin() + static_cast<std::ptrdiff_t>(it->first),
                       sc.lines.begin() + static_cast<std::ptrdiff_t>(it->last) + 1);
        // stmts after this point are stale; rescan for further copies
        return unset(detail::join(sc.lines), path);
    }
    return detail::join(sc.lines);
}

}  // namespace lx::env::vibe_edit
