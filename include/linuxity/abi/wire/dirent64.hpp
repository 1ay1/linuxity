// linuxity/abi/wire/dirent64.hpp
//
// `struct linux_dirent64`, encoded in exactly one place.
//
// This is a FROZEN kernel ABI struct:
//
//     struct linux_dirent64 {
//         u64  d_ino;        // inode number
//         s64  d_off;        // offset to the next dirent
//         u16  d_reclen;     // this record's length
//         u8   d_type;       // DT_*
//         char d_name[];     // NUL-terminated, record padded to 8
//     };
//
// WHY THIS FILE EXISTS. It used to be hand-encoded in three places --
// abi/syscall.hpp, runtime/darwin/trap.hpp, runtime/windows/sys.hpp -- which
// drifted into three different behaviours:
//
//            d_ino                d_type
//   portable real host inode      real DT_*
//   darwin   real host inode      real DT_*
//   windows  pos + 1  <-- bug     DT_UNKNOWN  <-- bug
//
// The positional d_ino is not cosmetic. libalpm reads the pacman database by
// enumerating /var/lib/pacman/local, then stat()ing each entry and matching
// st_ino against the d_ino it saw. A counter fails every comparison, so
// `pacman -Q` reported zero packages on a perfectly intact database. Fixing
// the portable copy left Windows broken, because there was nowhere central
// for the fix to land. Hence: one encoder, no host code, offsets asserted.
//
// Nothing about a hypervisor changes what d_ino means, so no backend has any
// business writing these bytes. Backends supply VALUES (name, ino, type) --
// readdir vs FindNextFileW is the only genuinely host-specific part -- and
// this file turns them into bytes.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include "linuxity/abi/wire/stat.hpp"   // FileType / kFileTypeMask

namespace lx::abi::wire {

// -- d_type ----------------------------------------------------------------
// The kernel's DT_* values, named once. These are ABI constants: they are the
// numbers the guest reads out of d_type, not an internal choice.
enum class DType : std::uint8_t {
    unknown = 0,
    fifo    = 1,
    chr     = 2,
    dir     = 4,
    blk     = 6,
    regular = 8,
    symlink = 10,
    sock    = 12,
};

// -- layout ----------------------------------------------------------------
inline constexpr std::size_t kDirentHeader = 19;  // 8 + 8 + 2 + 1
inline constexpr std::size_t kDirentAlign  = 8;

static_assert(kDirentHeader == 8 + 8 + 2 + 1,
              "linux_dirent64 header is u64 + s64 + u16 + u8");

// Bytes one entry occupies: the header, the name, its NUL, padded to 8.
[[nodiscard]] constexpr std::size_t dirent_reclen(std::size_t namelen) noexcept {
    return (kDirentHeader + namelen + 1 + (kDirentAlign - 1))
           & ~(kDirentAlign - 1);
}

// The one entry the ABI describes. `ino` of 0 means "no real inode" -- a
// purely synthesized node (procfs, sysfs, a virtual dir) that has no host
// file behind it; the caller decides what to substitute, because only the
// caller knows its own numbering.
struct Dirent {
    std::uint64_t    ino;
    std::int64_t     off;    // offset of the NEXT entry (usually index + 1)
    DType            type;
    std::string_view name;
};

// Encode ONE entry into `out`, little-endian, which is the only byte order
// the targeted ABIs (x86-64, aarch64 LE) use.
//
// Returns the number of bytes written, or 0 if `out` is too small -- the
// caller is mid-stream and must stop, which is exactly the getdents64
// contract (a full buffer ends the batch; it is not an error).
[[nodiscard]] inline std::size_t encode_dirent64(
        std::span<std::byte> out, const Dirent& e) noexcept {
    const std::size_t reclen = dirent_reclen(e.name.size());
    if (out.size() < reclen) return 0;

    auto put = [&](std::size_t off, std::uint64_t v, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i)
            out[off + i] = static_cast<std::byte>((v >> (8 * i)) & 0xff);
    };

    // Zero the record first: the pad bytes after the name must not leak
    // whatever the caller's buffer happened to hold.
    for (std::size_t i = 0; i < reclen; ++i) out[i] = std::byte{0};

    put(0,  e.ino, 8);                                      // d_ino
    put(8,  static_cast<std::uint64_t>(e.off), 8);          // d_off
    put(16, static_cast<std::uint64_t>(reclen), 2);         // d_reclen
    out[18] = static_cast<std::byte>(e.type);               // d_type
    for (std::size_t i = 0; i < e.name.size(); ++i)         // d_name + NUL
        out[kDirentHeader + i] = static_cast<std::byte>(e.name[i]);

    return reclen;
}

// Derive d_type from a POSIX st_mode. Host-free: S_IF* are the same numbers
// on every targeted host, and this is the mapping every backend needs when it
// has a mode but no dirent type (a DT_UNKNOWN fallback, or a synthesized node).
[[nodiscard]] constexpr DType dtype_from_mode(std::uint32_t mode) noexcept {
    // The S_IF* values are named in abi/wire/stat.hpp; this maps them onto
    // the dirent d_type space, which uses DIFFERENT numbers for the same
    // concepts (DT_DIR is 4, S_IFDIR is 0040000).
    switch (mode & kFileTypeMask) {
        case bits(FileType::dir):     return DType::dir;
        case bits(FileType::regular): return DType::regular;
        case bits(FileType::symlink): return DType::symlink;
        case bits(FileType::chr):     return DType::chr;
        case bits(FileType::blk):     return DType::blk;
        case bits(FileType::fifo):    return DType::fifo;
        case bits(FileType::sock):    return DType::sock;
        default:                      return DType::unknown;
    }
}

} // namespace lx::abi::wire
