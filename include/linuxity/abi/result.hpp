// linuxity/abi/result.hpp
//
// The algebra of syscall outcomes.
//
// A Linux syscall, viewed denotationally, is a total function
//
//     ⟦syscall⟧ : Args → Errno + Value
//
// It never "throws" — the kernel/user boundary has no exceptions, only a
// tagged return: a non-negative value on success, or -errno on failure.
// We model that sum type precisely with `std::expected`, and we forbid the
// two summands from ever being confused by giving Errno a strong type.
#pragma once

#include <cstdint>
#include <expected>
#include <string_view>
#include <type_traits>
#include <variant>

namespace lx {

// -- Errno -----------------------------------------------------------------
// A strong enum over the Linux errno space. Because it is an enum class it
// cannot be silently mixed with a success value, a length, or an fd.
enum class Errno : std::int32_t {
    ok      = 0,
    eperm   = 1,   enoent  = 2,   esrch   = 3,   eintr   = 4,
    eio     = 5,   enxio   = 6,   e2big   = 7,   enoexec = 8,
    ebadf   = 9,   echild  = 10,  eagain  = 11,  enomem  = 12,
    eacces  = 13,  efault  = 14,  ebusy   = 16,  eexist  = 17,
    exdev   = 18,  enodev  = 19,  enotdir = 20,  eisdir  = 21,
    einval  = 22,  enfile  = 23,  emfile  = 24,  enotty  = 25,
    efbig   = 27,  enospc  = 28,  espipe  = 29,  erofs   = 30,
    emlink  = 31,  epipe   = 32,  erange  = 34,  enosys  = 38,
    enotempty = 39, eloop  = 40,  enametoolong = 36,
    enotsup = 95,
    econnrefused = 111, etimedout = 110, eaddrinuse = 98,
};

[[nodiscard]] constexpr std::string_view name(Errno e) noexcept {
    switch (e) {
        case Errno::ok:      return "OK";
        case Errno::eperm:   return "EPERM";
        case Errno::enoent:  return "ENOENT";
        case Errno::eintr:   return "EINTR";
        case Errno::eio:     return "EIO";
        case Errno::ebadf:   return "EBADF";
        case Errno::eagain:  return "EAGAIN";
        case Errno::enomem:  return "ENOMEM";
        case Errno::eacces:  return "EACCES";
        case Errno::efault:  return "EFAULT";
        case Errno::eexist:  return "EEXIST";
        case Errno::enotdir: return "ENOTDIR";
        case Errno::eisdir:  return "EISDIR";
        case Errno::einval:  return "EINVAL";
        case Errno::enosys:  return "ENOSYS";
        default:             return "E???";
    }
}

// -- Result ----------------------------------------------------------------
// Result<T> = T + Errno, the monad every subsystem operation lives in.
template <class T>
using Result = std::expected<T, Errno>;

// The unit-returning result (syscalls that only signal success/failure).
using Status = Result<std::monostate>;

// Smart constructors — read like the mathematical injections inl / inr.
template <class T>
[[nodiscard]] constexpr Result<std::remove_cvref_t<T>> ok(T&& v) {
    return Result<std::remove_cvref_t<T>>{std::forward<T>(v)};
}

[[nodiscard]] constexpr Status ok() { return Status{std::monostate{}}; }

template <class T = std::monostate>
[[nodiscard]] constexpr Result<T> err(Errno e) {
    return std::unexpected(e);
}

// -- Kernel ABI encoding ---------------------------------------------------
// The wire form the guest observes: >= 0 is the value, < 0 is -errno.
// This is the ONLY place the sum type collapses back into an int register.
[[nodiscard]] constexpr std::int64_t to_kernel(const Status& r) noexcept {
    return r ? 0 : -static_cast<std::int64_t>(r.error());
}

template <class T>
    requires std::is_integral_v<T> || std::is_enum_v<T>
[[nodiscard]] constexpr std::int64_t to_kernel(const Result<T>& r) noexcept {
    return r ? static_cast<std::int64_t>(*r)
             : -static_cast<std::int64_t>(r.error());
}

// A strong Id (Fd, Pid, ...) collapses to its raw representation on success.
template <class T>
    requires requires(T v) { v.raw(); }
[[nodiscard]] constexpr std::int64_t to_kernel(const Result<T>& r) noexcept {
    return r ? static_cast<std::int64_t>(r->raw())
             : -static_cast<std::int64_t>(r.error());
}

// -- do-notation -----------------------------------------------------------
// `LX_TRY(expr)` unwraps a Result<T> or short-circuits the enclosing
// function with the propagated Errno. The moral equivalent of Rust's `?`
// or Haskell's `<-` inside a do-block.
#define LX_TRY(expr)                                                          \
    __extension__({                                                           \
        auto&& _lx_r = (expr);                                                \
        if (!_lx_r) return ::std::unexpected(_lx_r.error());                  \
        std::move(_lx_r).value();                                             \
    })

} // namespace lx
