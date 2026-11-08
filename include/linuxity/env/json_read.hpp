// linuxity/env/json_read.hpp
//
// A small JSON reader for control requests: one object whose values are
// strings, numbers, booleans, null, arrays of those, or nested objects.
// Requests are tiny and come from our own clients, so this favours being
// short and strict over being fast.
#pragma once

#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lx::env {

struct JValue {
    enum class Kind { null, boolean, number, string, array, object } kind{Kind::null};
    bool b{false};
    double n{0};
    std::string s;
    std::vector<JValue> a;
    std::map<std::string, JValue> o;

    [[nodiscard]] const JValue* get(std::string_view k) const {
        if (kind != Kind::object) return nullptr;
        auto it = o.find(std::string{k});
        return it == o.end() ? nullptr : &it->second;
    }
    [[nodiscard]] std::string str(std::string_view k, std::string def = {}) const {
        const JValue* v = get(k);
        return v && v->kind == Kind::string ? v->s : def;
    }
    [[nodiscard]] std::int64_t num(std::string_view k, std::int64_t def = 0) const {
        const JValue* v = get(k);
        return v && v->kind == Kind::number ? static_cast<std::int64_t>(v->n) : def;
    }
    [[nodiscard]] bool flag(std::string_view k, bool def = false) const {
        const JValue* v = get(k);
        return v && v->kind == Kind::boolean ? v->b : def;
    }
    [[nodiscard]] std::vector<std::string> strs(std::string_view k) const {
        std::vector<std::string> out;
        if (const JValue* v = get(k); v && v->kind == Kind::array)
            for (const auto& e : v->a)
                if (e.kind == Kind::string) out.push_back(e.s);
        return out;
    }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> str_map(std::string_view k) const {
        std::vector<std::pair<std::string, std::string>> out;
        if (const JValue* v = get(k); v && v->kind == Kind::object)
            for (const auto& [kk, vv] : v->o)
                if (vv.kind == Kind::string) out.emplace_back(kk, vv.s);
        return out;
    }
};

class JReader {
public:
    explicit JReader(std::string_view t) : t_{t} {}

    [[nodiscard]] std::optional<JValue> parse() {
        JValue v;
        if (!value(v, 0)) return std::nullopt;
        ws();
        if (i_ != t_.size()) return std::nullopt;
        return v;
    }

private:
    void ws() {
        while (i_ < t_.size() && (t_[i_] == ' ' || t_[i_] == '\t' || t_[i_] == '\n' || t_[i_] == '\r')) ++i_;
    }
    bool lit(std::string_view w) {
        if (t_.substr(i_, w.size()) != w) return false;
        i_ += w.size();
        return true;
    }
    static void put_utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) out.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }
    bool hex4(std::uint32_t& v) {
        if (i_ + 4 > t_.size()) return false;
        v = 0;
        for (int k = 0; k < 4; ++k) {
            const char c = t_[i_++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') v |= static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= static_cast<std::uint32_t>(c - 'A' + 10);
            else return false;
        }
        return true;
    }
    bool string(std::string& out) {
        if (i_ >= t_.size() || t_[i_] != '"') return false;
        ++i_;
        while (i_ < t_.size()) {
            const char c = t_[i_++];
            if (c == '"') return true;
            if (static_cast<unsigned char>(c) < 0x20) return false;
            if (c != '\\') { out.push_back(c); continue; }
            if (i_ >= t_.size()) return false;
            const char e = t_[i_++];
            switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    std::uint32_t cp = 0;
                    if (!hex4(cp)) return false;
                    if (cp >= 0xD800 && cp < 0xDC00 && lit("\\u")) {
                        std::uint32_t lo = 0;
                        if (!hex4(lo) || lo < 0xDC00 || lo > 0xDFFF) return false;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    put_utf8(out, cp);
                    break;
                }
                default: return false;
            }
        }
        return false;
    }
    bool value(JValue& v, int depth) {
        if (depth > 16) return false;
        ws();
        if (i_ >= t_.size()) return false;
        const char c = t_[i_];
        if (c == '"') { v.kind = JValue::Kind::string; return string(v.s); }
        if (c == '{') {
            ++i_;
            v.kind = JValue::Kind::object;
            ws();
            if (i_ < t_.size() && t_[i_] == '}') { ++i_; return true; }
            while (true) {
                ws();
                std::string k;
                if (!string(k)) return false;
                ws();
                if (i_ >= t_.size() || t_[i_] != ':') return false;
                ++i_;
                JValue e;
                if (!value(e, depth + 1)) return false;
                v.o[std::move(k)] = std::move(e);
                ws();
                if (i_ < t_.size() && t_[i_] == ',') { ++i_; continue; }
                if (i_ < t_.size() && t_[i_] == '}') { ++i_; return true; }
                return false;
            }
        }
        if (c == '[') {
            ++i_;
            v.kind = JValue::Kind::array;
            ws();
            if (i_ < t_.size() && t_[i_] == ']') { ++i_; return true; }
            while (true) {
                JValue e;
                if (!value(e, depth + 1)) return false;
                v.a.push_back(std::move(e));
                ws();
                if (i_ < t_.size() && t_[i_] == ',') { ++i_; continue; }
                if (i_ < t_.size() && t_[i_] == ']') { ++i_; return true; }
                return false;
            }
        }
        if (lit("true")) { v.kind = JValue::Kind::boolean; v.b = true; return true; }
        if (lit("false")) { v.kind = JValue::Kind::boolean; v.b = false; return true; }
        if (lit("null")) { v.kind = JValue::Kind::null; return true; }
        // number
        const std::size_t start = i_;
        if (i_ < t_.size() && t_[i_] == '-') ++i_;
        while (i_ < t_.size() && ((t_[i_] >= '0' && t_[i_] <= '9') || t_[i_] == '.' ||
                                  t_[i_] == 'e' || t_[i_] == 'E' || t_[i_] == '+' || t_[i_] == '-'))
            ++i_;
        if (i_ == start) return false;
        const std::string num{t_.substr(start, i_ - start)};
        char* end = nullptr;
        v.kind = JValue::Kind::number;
        v.n = std::strtod(num.c_str(), &end);
        return end && *end == '\0';
    }

    std::string_view t_;
    std::size_t i_{0};
};

[[nodiscard]] inline std::optional<JValue> parse_json(std::string_view t) {
    return JReader{t}.parse();
}

}  // namespace lx::env
