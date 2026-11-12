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
#include <string>
#include <vector>

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

// -- Host path access (an OPTIONAL capability) -----------------------------
// The base Host contract is deliberately fd-only. HostFs — the backend that
// exposes a real on-disk rootfs directory as the guest's "/" — additionally
// needs to open host paths and enumerate host directories. We express that
// as a SEPARATE concept so the core stays minimal: a host that can't touch
// the filesystem (a pure-sandbox iOS build) simply doesn't model HostFiles,
// and HostFs won't compile against it — the type system states the dependency.

enum class HFileType : std::uint8_t { regular, directory, symlink, other };

// What a host stat YIELDS. ONE type for both consumers:
//
//   vfs/hostfs.hpp  -- needs type/size/mode/mtime to present a rootfs entry
//   abi/syscall.hpp -- needs the rest to answer a guest stat/statx in a
//                      single trap stop, instead of redirecting the call and
//                      stepping the guest to its syscall exit
//
// It deliberately does NOT describe a guest buffer: laying those bytes out is
// policy, owned by abi/wire/stat.hpp (which both backends static_assert
// against). A backend fills these fields from whatever its OS offers -- statx
// on Linux, stat64 on Darwin, GetFileInformationByHandleEx on Win32 -- and
// never sees a guest offset, so it cannot get one wrong.
//
// `mode` keeps its original meaning -- host PERMISSION bits (st_mode & 0777) --
// because vfs/hostfs.hpp passes it straight through to a vfs Mode without
// masking, so widening it there would leak S_IFMT type bits into the rootfs
// view. A guest stat needs the full value, so that lives in `raw_mode`.
struct HStat {
    HFileType     type{HFileType::regular};
    std::uint64_t size{};
    std::uint32_t mode{};        // host permission bits (st_mode & 0777)
    std::int64_t  mtime_ns{};    // signed: before 1970 is negative

    // Added for the single-stop stat path; defaulted so existing producers
    // and consumers are unaffected.
    std::uint32_t raw_mode{0};   // full st_mode, S_IFMT included
    std::uint64_t dev{0};
    std::uint64_t ino{0};
    std::uint64_t nlink{1};
    std::uint32_t uid{0};
    std::uint32_t gid{0};
    std::uint64_t rdev{0};
    std::int64_t  blksize{4096};
    std::int64_t  blocks{0};
    std::int64_t  atime_ns{0};
    std::int64_t  ctime_ns{0};
};

struct HDirent {
    std::string name;
    HFileType   type{};
};

template <class H>
concept HostFiles = Host<H> &&
    requires(H h, const char* path, int hfd, std::uint64_t off,
             std::span<std::byte> buf) {
    // Open a host path read-only; returns an opaque host fd (>=0).
    { h.open_path(path) }       -> std::same_as<Result<int>>;
    { h.stat_path(path) }       -> std::same_as<Result<HStat>>;
    { h.pread(hfd, off, buf) }  -> std::same_as<Result<std::size_t>>;
    { h.list_dir(path) }        -> std::same_as<Result<std::vector<HDirent>>>;
};

} // namespace lx::host
