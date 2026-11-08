// linuxity/env/json.hpp
//
// A small JSON writer. linuxity emits JSON (schema, status events, the
// control protocol's replies) but never needs to parse it, so this is
// output-only.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace lx::env {

inline void json_escape_into(std::string& out, std::string_view s) {
    out.push_back('"');
    for (const char ch : s) {
        const auto c = static_cast<unsigned char>(ch);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(ch);
                }
        }
    }
    out.push_back('"');
}

// Builds one JSON value. Commas are inserted automatically: each container
// remembers whether it already holds an element.
class Json {
public:
    Json& obj() { open('{'); return *this; }
    Json& arr() { open('['); return *this; }
    Json& end() {
        const char c = stack_.back() == '{' ? '}' : ']';
        stack_.pop_back();
        first_.pop_back();
        out_.push_back(c);
        return *this;
    }
    Json& key(std::string_view k) {
        comma();
        json_escape_into(out_, k);
        out_.push_back(':');
        pending_key_ = true;
        return *this;
    }
    Json& str(std::string_view v) { comma(); json_escape_into(out_, v); return *this; }
    Json& num(std::int64_t v) { comma(); out_ += std::to_string(v); return *this; }
    Json& num(std::uint64_t v) { comma(); out_ += std::to_string(v); return *this; }
    Json& num(int v) { return num(static_cast<std::int64_t>(v)); }
    Json& num(double v) {
        comma();
        char buf[32];
        std::snprintf(buf, sizeof buf, "%.17g", v);
        out_ += buf;
        return *this;
    }
    Json& boolean(bool v) { comma(); out_ += v ? "true" : "false"; return *this; }
    Json& null() { comma(); out_ += "null"; return *this; }
    Json& raw(std::string_view json) { comma(); out_ += json; return *this; }

    // key + value in one call
    Json& kv(std::string_view k, std::string_view v) { return key(k).str(v); }
    Json& kv(std::string_view k, const char* v) { return key(k).str(v ? v : ""); }
    Json& kv(std::string_view k, const std::string& v) { return key(k).str(v); }
    Json& kv(std::string_view k, bool v) { return key(k).boolean(v); }
    Json& kv(std::string_view k, int v) { return key(k).num(v); }
    Json& kv(std::string_view k, std::int64_t v) { return key(k).num(v); }
    Json& kv(std::string_view k, std::uint64_t v) { return key(k).num(v); }
    Json& kv(std::string_view k, double v) { return key(k).num(v); }
    Json& kv(std::string_view k, const std::vector<std::string>& v) {
        key(k).arr();
        for (const auto& s : v) str(s);
        return end();
    }

    [[nodiscard]] const std::string& text() const { return out_; }
    [[nodiscard]] std::string take() { return std::move(out_); }

private:
    void open(char c) {
        comma();
        out_.push_back(c);
        stack_.push_back(c);
        first_.push_back(true);
    }
    void comma() {
        if (pending_key_) { pending_key_ = false; return; }
        if (first_.empty()) return;
        if (!first_.back()) out_.push_back(',');
        first_.back() = false;
    }

    std::string out_;
    std::vector<char> stack_;
    std::vector<bool> first_;
    bool pending_key_{false};
};

}  // namespace lx::env
