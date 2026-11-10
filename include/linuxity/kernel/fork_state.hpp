// linuxity/kernel/fork_state.hpp
//
// The bytes a fork carries to a FRESH process (macOS: every guest fork is a
// new linuxity, see runtime/darwin/fork.hpp). A length-prefixed record format,
// one writer and one reader, used by every kernel part that has per-process
// state to hand over (FileNamespace: cwd and fd paths; ProcessTable: the
// forking process's credentials). Both ends are the same binary, so there is
// no versioning -- only bounds checks, so a short buffer reads as zeros.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace lx::kernel::fork_state {

class Writer {
public:
    template <class T> requires std::is_trivially_copyable_v<T>
    void pod(const T& v) { out_.append(reinterpret_cast<const char*>(&v), sizeof v); }
    void str(std::string_view s) {
        pod(static_cast<std::uint32_t>(s.size()));
        out_.append(s);
    }
    template <class T> requires std::is_trivially_copyable_v<T>
    void vec(const std::vector<T>& v) {
        pod(static_cast<std::uint32_t>(v.size()));
        out_.append(reinterpret_cast<const char*>(v.data()), v.size() * sizeof(T));
    }
    [[nodiscard]] std::string take() { return std::move(out_); }
private:
    std::string out_;
};

class Reader {
public:
    explicit Reader(std::string_view in) : in_{in} {}
    template <class T> requires std::is_trivially_copyable_v<T>
    T pod() {
        T v{};
        if (at_ + sizeof v <= in_.size()) std::memcpy(&v, in_.data() + at_, sizeof v);
        at_ += sizeof v;
        return v;
    }
    std::string str() {
        const auto n = pod<std::uint32_t>();
        std::string s{in_.substr(std::min(at_, in_.size()), n)};
        at_ += n;
        return s;
    }
    template <class T> requires std::is_trivially_copyable_v<T>
    std::vector<T> vec() {
        const auto n = pod<std::uint32_t>();
        std::vector<T> v;
        if (at_ + std::size_t{n} * sizeof(T) > in_.size()) { at_ = in_.size(); return v; }
        v.resize(n);
        std::memcpy(v.data(), in_.data() + at_, std::size_t{n} * sizeof(T));
        at_ += std::size_t{n} * sizeof(T);
        return v;
    }
    [[nodiscard]] bool more() const noexcept { return at_ < in_.size(); }
private:
    std::string_view in_;
    std::size_t at_{0};
};

}  // namespace lx::kernel::fork_state
