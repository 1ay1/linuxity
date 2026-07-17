// linuxity/host/host.hpp
//
// The host boundary.
//
// The runtime is a *portable implementation of the Linux userspace ABI*.
// It never calls the host OS directly; it calls THIS interface. Each
// platform (Linux, Darwin/iOS, Windows) supplies one implementation, and
// nothing above this line knows which one it is.
//
// The interface is deliberately tiny — the host provides only primitives
// that genuinely need a real kernel (raw memory, real threads, real clocks,
// real I/O). PIDs, /proc, signals, namespaces, mounts, futex semantics, the
// scheduler — all of that is synthesized *above* the host, in the runtime.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"

#include <concepts>
#include <cstddef>
#include <span>

namespace lx::host {

// Protection bits for a host mapping (a minimal, portable subset).
enum class Prot : unsigned { none = 0, read = 1, write = 2, exec = 4 };
[[nodiscard]] constexpr Prot operator|(Prot a, Prot b) noexcept {
    return Prot(unsigned(a) | unsigned(b));
}

// A monotonic, steady clock reading in nanoseconds since an arbitrary epoch.
struct Nanos { std::uint64_t v{}; };

// -- The host concept ------------------------------------------------------
// We express the requirement as a C++ concept rather than a virtual base so
// the runtime can be instantiated against a host with zero virtual-dispatch
// overhead, yet still be swapped freely at build time. This is static
// polymorphism used as an interface: the "type theory" pays for itself by
// making the contract machine-checkable.
template <class H>
concept Host = requires(H h, std::size_t n, void* p, Nanos t,
                        std::span<std::byte> buf) {
    // -- Raw memory: the address space the guest's mmap sits on top of.
    { h.map(n, Prot{}) }        -> std::same_as<Result<void*>>;
    { h.unmap(p, n) }           -> std::same_as<Status>;
    { h.protect(p, n, Prot{}) } -> std::same_as<Status>;

    // -- Time. Guest clocks (CLOCK_MONOTONIC etc.) are derived from these.
    { h.mono_now() }            -> std::same_as<Nanos>;
    { h.sleep_until(t) }        -> std::same_as<Status>;

    // -- Blocking host I/O against a real fd (files, sockets). The VFS maps
    //    guest paths -> these; the guest never sees a host fd.
    { h.read(0, buf) }          -> std::same_as<Result<std::size_t>>;
    { h.write(0, std::span<const std::byte>{}) }
                                -> std::same_as<Result<std::size_t>>;
    { h.close(0) }              -> std::same_as<Status>;
};

} // namespace lx::host
