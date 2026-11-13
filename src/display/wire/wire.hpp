// src/display/wire/wire.hpp -- the Wayland wire format, nothing else.
//
// A message is a header (object id; size << 16 | opcode) and arguments in
// 32-bit words; strings and arrays are length-prefixed and padded to 4,
// file descriptors travel out of band (SCM_RIGHTS) in argument order. The
// protocol tables (protocol/protocol.hpp, generated from the XML) describe
// every message with libwayland's signature alphabet, so decoding and
// encoding are table-driven and checked against the signature -- a handler
// never touches raw bytes.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <unistd.h>

namespace lx::display::wire {

struct Interface;

struct Message {
    std::string_view name;
    std::string_view signature;               // i u f s o n a h; '?' = nullable
    std::uint32_t since;
    bool destructor;
    std::span<const Interface* const> types;  // per argument; nullptr if untyped
};

struct Interface {
    std::string_view name;
    std::uint32_t version;
    std::span<const Message> requests;
    std::span<const Message> events;
};

using ObjectId = std::uint32_t;
inline constexpr ObjectId kFirstServerId = 0xff000000u;
inline constexpr std::size_t kMaxMessage = 4096;   // libwayland's limit, both ways
inline constexpr std::size_t kMaxFdsPerMessage = 28;

// 24.8 signed fixed point
struct Fixed {
    std::int32_t raw{0};
    [[nodiscard]] static constexpr Fixed from(double v) noexcept {
        return Fixed{static_cast<std::int32_t>(v * 256.0)};
    }
    [[nodiscard]] constexpr double value() const noexcept { return raw / 256.0; }
};

// An owned file descriptor.
class Fd {
public:
    Fd() = default;
    explicit Fd(int fd) noexcept : fd_(fd) {}
    Fd(Fd&& o) noexcept : fd_(std::exchange(o.fd_, -1)) {}
    Fd& operator=(Fd&& o) noexcept {
        if (this != &o) { reset(); fd_ = std::exchange(o.fd_, -1); }
        return *this;
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    ~Fd() { reset(); }
    void reset() noexcept { if (fd_ >= 0) ::close(fd_); fd_ = -1; }
    [[nodiscard]] int get() const noexcept { return fd_; }
    [[nodiscard]] int release() noexcept { return std::exchange(fd_, -1); }
    explicit operator bool() const noexcept { return fd_ >= 0; }
private:
    int fd_{-1};
};

// -- Decoding ----------------------------------------------------------------

enum class Type : std::uint8_t { int_, uint_, fixed, string, object, new_id, array, fd };

struct Arg {
    Type type{Type::uint_};
    bool null{false};
    std::uint32_t word{0};                 // int/uint/fixed/object/new_id
    std::string_view str;                  // string (without the NUL)
    std::span<const std::byte> bytes;      // array
    int fd{-1};                            // fd (owned by Args until taken)
};

// The decoded arguments of one request. Accessors name the argument by index
// and trust the signature (decode() already checked every type).
class Args {
public:
    Args() = default;
    Args(const Args&) = delete;
    Args& operator=(const Args&) = delete;
    ~Args() {
        for (std::size_t k = 0; k < n_; ++k)
            if (v_[k].type == Type::fd && v_[k].fd >= 0) ::close(v_[k].fd);
    }
    [[nodiscard]] std::size_t size() const noexcept { return n_; }
    [[nodiscard]] std::int32_t i(std::size_t k) const noexcept { return static_cast<std::int32_t>(v_[k].word); }
    [[nodiscard]] std::uint32_t u(std::size_t k) const noexcept { return v_[k].word; }
    [[nodiscard]] Fixed f(std::size_t k) const noexcept { return Fixed{static_cast<std::int32_t>(v_[k].word)}; }
    [[nodiscard]] ObjectId obj(std::size_t k) const noexcept { return v_[k].word; }
    [[nodiscard]] ObjectId new_id(std::size_t k) const noexcept { return v_[k].word; }
    [[nodiscard]] std::string_view str(std::size_t k) const noexcept { return v_[k].str; }
    [[nodiscard]] std::optional<std::string_view> opt_str(std::size_t k) const noexcept {
        return v_[k].null ? std::nullopt : std::optional<std::string_view>{v_[k].str};
    }
    [[nodiscard]] std::span<const std::byte> array(std::size_t k) const noexcept { return v_[k].bytes; }
    [[nodiscard]] Fd take_fd(std::size_t k) noexcept { return Fd{std::exchange(v_[k].fd, -1)}; }

    Arg& push() noexcept { return v_[n_++]; }
    [[nodiscard]] bool full() const noexcept { return n_ == v_.size(); }
private:
    std::array<Arg, 20> v_{};
    std::size_t n_{0};
};

// Pops received fds in order; owned by the connection.
class FdSource {
public:
    virtual ~FdSource() = default;
    [[nodiscard]] virtual int pop_fd() = 0;   // -1 if none queued
};

// Decode `body` per `sig`. Returns false on a malformed message (short,
// unterminated string, a non-nullable null, a missing fd).
[[nodiscard]] inline bool decode(std::string_view sig, std::span<const std::byte> body,
                                 FdSource& fds, Args& out) {
    std::size_t at = 0;
    auto word = [&](std::uint32_t& w) {
        if (at + 4 > body.size()) return false;
        std::memcpy(&w, body.data() + at, 4);
        at += 4;
        return true;
    };
    bool nullable = false;
    for (const char c : sig) {
        if (c == '?') { nullable = true; continue; }
        if (out.full()) return false;
        Arg& a = out.push();
        switch (c) {
            case 'i': a.type = Type::int_; if (!word(a.word)) return false; break;
            case 'u': a.type = Type::uint_; if (!word(a.word)) return false; break;
            case 'f': a.type = Type::fixed; if (!word(a.word)) return false; break;
            case 'o': a.type = Type::object; if (!word(a.word)) return false;
                      a.null = a.word == 0;
                      if (a.null && !nullable) return false;
                      break;
            case 'n': a.type = Type::new_id; if (!word(a.word) || a.word == 0) return false; break;
            case 's': case 'a': {
                a.type = c == 's' ? Type::string : Type::array;
                std::uint32_t len = 0;
                if (!word(len)) return false;
                if (c == 's' && len == 0) {
                    if (!nullable) return false;
                    a.null = true;
                    break;
                }
                const std::size_t padded = (static_cast<std::size_t>(len) + 3) & ~std::size_t{3};
                if (at + padded > body.size()) return false;
                const auto* p = body.data() + at;
                if (c == 's') {
                    if (p[len - 1] != std::byte{0}) return false;
                    a.str = {reinterpret_cast<const char*>(p), len - 1};
                } else {
                    a.bytes = {p, len};
                }
                at += padded;
                break;
            }
            case 'h':
                a.type = Type::fd;
                a.fd = fds.pop_fd();
                if (a.fd < 0) return false;
                break;
            default: return false;
        }
        nullable = false;
    }
    return at == body.size();
}

// -- Encoding ----------------------------------------------------------------

// Argument wrappers for events (plain integers are int/uint by C++ type).
struct Object { ObjectId id; };            // 'o' (0 = null)
struct NewId { ObjectId id; };             // 'n'
struct Array { std::span<const std::byte> bytes; };
struct FdArg { int fd; };                  // borrowed; the encoder dups it
struct Null {};                            // a null string or object

// One outgoing message under construction, appended to `out`.
class Encoder {
public:
    Encoder(std::vector<std::byte>& out, std::vector<int>& fds, ObjectId id, std::uint16_t op)
        : out_(out), fds_(fds), start_(out.size()) {
        put_word(id);
        put_word(op);   // size patched in finish()
    }
    void put(std::int32_t v) { put_word(static_cast<std::uint32_t>(v)); }
    void put(std::uint32_t v) { put_word(v); }
    void put(Fixed v) { put_word(static_cast<std::uint32_t>(v.raw)); }
    void put(Object o) { put_word(o.id); }
    void put(NewId n) { put_word(n.id); }
    void put(Null) { put_word(0); }
    void put(std::string_view s) {
        put_word(static_cast<std::uint32_t>(s.size() + 1));
        append(s.data(), s.size());
        const char nul = 0;
        append(&nul, 1);
        pad();
    }
    void put(const std::string& s) { put(std::string_view{s}); }
    void put(const char* s) { put(std::string_view{s}); }
    void put(Array a) {
        put_word(static_cast<std::uint32_t>(a.bytes.size()));
        append(a.bytes.data(), a.bytes.size());
        pad();
    }
    void put(FdArg f) { fds_.push_back(::dup(f.fd)); }
    void finish() {
        const auto size = static_cast<std::uint32_t>(out_.size() - start_);
        std::uint32_t w;
        std::memcpy(&w, out_.data() + start_ + 4, 4);
        w |= size << 16;
        std::memcpy(out_.data() + start_ + 4, &w, 4);
    }
private:
    void put_word(std::uint32_t w) { append(&w, 4); }
    void append(const void* p, std::size_t n) {
        const auto* b = static_cast<const std::byte*>(p);
        out_.insert(out_.end(), b, b + n);
    }
    void pad() { while ((out_.size() - start_) % 4) out_.push_back(std::byte{0}); }
    std::vector<std::byte>& out_;
    std::vector<int>& fds_;
    std::size_t start_;
};

// Wrap a signed or unsigned integer for the wire by its C++ type; enums
// travel as uint.
template <class T>
[[nodiscard]] constexpr auto wire_value(T v) {
    if constexpr (std::is_enum_v<T>) return static_cast<std::uint32_t>(v);
    else if constexpr (std::is_same_v<T, bool>) return static_cast<std::uint32_t>(v);
    else if constexpr (std::is_integral_v<T> && std::is_signed_v<T>) return static_cast<std::int32_t>(v);
    else if constexpr (std::is_integral_v<T>) return static_cast<std::uint32_t>(v);
    else return v;
}

}  // namespace lx::display::wire
