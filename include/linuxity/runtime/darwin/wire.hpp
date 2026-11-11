// linuxity/runtime/darwin/wire.hpp
//
// Byte serialization of HvfTrap::ForkImage for the fork handoff.
//
// Every field is trivially copyable or a vector/string of trivially copyable
// elements, so the format is a flat sequence of (length, bytes) records in a
// fixed order. Both ends are the same linuxity binary (the child is spawned
// from our own executable path), so there is no version skew to tolerate --
// but lengths are still checked so a truncated message fails cleanly rather
// than reading past the buffer.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/runtime/darwin/trap.hpp"

#include <cstddef>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

namespace lx::runtime::wire {

class Writer {
public:
    template <class T>
        requires std::is_trivially_copyable_v<T>
    void pod(const T& v) { bytes(&v, sizeof v); }

    template <class T>
        requires std::is_trivially_copyable_v<T>
    void vec(const std::vector<T>& v) {
        pod(static_cast<std::uint64_t>(v.size()));
        bytes(v.data(), v.size() * sizeof(T));
    }
    void str(const std::string& s) {
        pod(static_cast<std::uint64_t>(s.size()));
        bytes(s.data(), s.size());
    }
    [[nodiscard]] std::vector<std::byte> take() { return std::move(buf_); }

private:
    void bytes(const void* p, std::size_t n) {
        auto* b = static_cast<const std::byte*>(p);
        buf_.insert(buf_.end(), b, b + n);
    }
    std::vector<std::byte> buf_;
};

class Reader {
public:
    explicit Reader(const std::vector<std::byte>& b) : buf_{b} {}

    template <class T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] bool pod(T& v) { return bytes(&v, sizeof v); }

    template <class T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] bool vec(std::vector<T>& v) {
        std::uint64_t n = 0;
        if (!pod(n) || n > (buf_.size() - at_) / std::max<std::size_t>(sizeof(T), 1))
            return false;
        v.resize(n);
        return bytes(v.data(), n * sizeof(T));
    }
    [[nodiscard]] bool str(std::string& s) {
        std::uint64_t n = 0;
        if (!pod(n) || n > buf_.size() - at_) return false;
        s.assign(reinterpret_cast<const char*>(buf_.data() + at_), n);
        at_ += n;
        return true;
    }

private:
    [[nodiscard]] bool bytes(void* p, std::size_t n) {
        if (n > buf_.size() - at_) return false;
        std::memcpy(p, buf_.data() + at_, n);
        at_ += n;
        return true;
    }
    const std::vector<std::byte>& buf_;
    std::size_t at_{0};
};

[[nodiscard]] inline std::vector<std::byte> encode(const HvfTrap::ForkImage& f) {
    Writer w;
    w.pod(f.cpu);
    w.pod(f.self); w.pod(f.parent);
    w.pod(f.child_settid); w.pod(f.clear_child_tid);
    w.pod(f.umask);
    w.vec(f.vmas);
    w.pod(f.brk); w.pod(f.arena);
    w.vec(f.fds);
    w.vec(f.fd_hosts);
    w.pod(f.sig_actions); w.pod(f.sig_mask); w.pod(f.altstack);
    w.str(f.namespace_state);
    w.pod(f.rlimits); w.str(f.environ); w.str(f.range_names);
    w.vec(f.backings);
    w.pod(f.pte_lo); w.pod(f.pte_hi);
    w.str(f.auxv);
    w.str(f.cmdline);
    return w.take();
}

[[nodiscard]] inline bool decode(const std::vector<std::byte>& b, HvfTrap::ForkImage& f) {
    Reader r{b};
    return r.pod(f.cpu) && r.pod(f.self) && r.pod(f.parent) &&
           r.pod(f.child_settid) && r.pod(f.clear_child_tid) && r.pod(f.umask) &&
           r.vec(f.vmas) && r.pod(f.brk) && r.pod(f.arena) && r.vec(f.fds) && r.vec(f.fd_hosts) &&
           r.pod(f.sig_actions) && r.pod(f.sig_mask) && r.pod(f.altstack) &&
           r.str(f.namespace_state) && r.pod(f.rlimits) && r.str(f.environ) &&
           r.str(f.range_names) && r.vec(f.backings) && r.pod(f.pte_lo) && r.pod(f.pte_hi) &&
           r.str(f.auxv) && r.str(f.cmdline);
}

} // namespace lx::runtime::wire

#endif // __APPLE__ && __aarch64__
