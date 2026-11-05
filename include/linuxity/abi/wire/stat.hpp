// linuxity/abi/wire/stat.hpp
//
// Where the fields of `struct stat` and `struct statx` live, per ABI.
//
// WHY THIS FILE EXISTS. The same ABI knowledge was spelled three ways:
//
//   abi/syscall.hpp    offsets computed inline in scrub_ids():
//                        mode_off = is_statx ? 28 : (generic ? 16 : 24)
//   darwin/darwin.hpp  struct LinuxStat, asm-generic layout, st_mode @16
//   windows/win32.hpp  struct LinuxStat, x86-64 layout,      st_mode @24
//
// All three are CORRECT -- x86-64 and asm-generic/aarch64 genuinely disagree
// about `struct stat` (on aarch64 st_nlink is u32 and comes AFTER st_mode) --
// which is exactly why this is dangerous rather than merely untidy. Three
// independent copies of a layout that legitimately varies by ABI is how one
// copy drifts and starts reporting a plausible wrong mode: a guest sees
// 0644 where the file is 0755, or reads st_uid out of the padding.
//
// The two backend structs stay: a backend filling a stat buffer field-by-field
// from its host's own stat is clearer than poking offsets, and the compiler
// checks its layout. What moves HERE is the single authority they are both
// checked against, plus the offsets the portable dispatcher needs when it
// patches a buffer the HOST kernel filled (where there is no struct to use).
//
// So the rule is: these constants are the definition, and every struct that
// claims to be a guest `struct stat` static_asserts against them.
#pragma once

#include <cstddef>
#include <cstdint>

#include "linuxity/abi/sysno.hpp"   // Arch

namespace lx::abi::wire {

// -- struct stat -----------------------------------------------------------
//
// x86-64:
//   u64 st_dev; u64 st_ino; u64 st_nlink; u32 st_mode; u32 st_uid;
//   u32 st_gid; u32 pad; u64 st_rdev; i64 st_size; i64 st_blksize;
//   i64 st_blocks; timespec a/m/c; i64 unused[3];                  == 144
//
// asm-generic (aarch64): nlink is u32 and follows mode, so everything after
// st_ino shifts:
//   u64 st_dev; u64 st_ino; u32 st_mode; u32 st_nlink; u32 st_uid;
//   u32 st_gid; u64 st_rdev; u64 pad; i64 st_size; i32 st_blksize;
//   i32 pad; i64 st_blocks; timespec a/m/c; u32 unused[2];         == 128
struct StatLayout {
    std::size_t size;
    std::size_t mode;
    std::size_t uid;
    std::size_t gid;
    // Width of the st_mode field in bytes. x86-64 and asm-generic both use
    // u32 here; statx uses u16. The scrub has to know, because reading 4
    // bytes where the ABI has 2 picks up the next field.
    std::size_t mode_width;
};

inline constexpr StatLayout kStatX86_64{
    .size = 144, .mode = 24, .uid = 28, .gid = 32, .mode_width = 4,
};
inline constexpr StatLayout kStatGeneric{   // aarch64 / asm-generic
    .size = 128, .mode = 16, .uid = 24, .gid = 28, .mode_width = 4,
};

// -- struct statx ----------------------------------------------------------
// Identical on both ABIs -- it was designed as a fixed, versioned layout:
//   u32 stx_mask; u32 stx_blksize; u64 stx_attributes; u32 stx_nlink;
//   u32 stx_uid; u32 stx_gid; u16 stx_mode; u16 pad; u64 stx_ino; ...
inline constexpr StatLayout kStatx{
    .size = 256, .mode = 28, .uid = 20, .gid = 24, .mode_width = 2,
};

// The layout for a guest `struct stat` on this ABI.
[[nodiscard]] constexpr const StatLayout& stat_layout(Arch a) noexcept {
    return a == Arch::aarch64 ? kStatGeneric : kStatX86_64;
}

// Pin the relationships a reader would otherwise have to trust the comments
// for. These are the invariants that make the two layouts distinguishable,
// so if someone "fixes" one constant the build says so.
static_assert(kStatX86_64.mode == 24 && kStatX86_64.uid == 28 &&
              kStatX86_64.gid == 32);
static_assert(kStatGeneric.mode == 16 && kStatGeneric.uid == 24 &&
              kStatGeneric.gid == 28);
static_assert(kStatx.mode == 28 && kStatx.uid == 20 && kStatx.gid == 24);
// uid/gid are adjacent u32s in every one of the three layouts.
static_assert(kStatX86_64.gid - kStatX86_64.uid == 4);
static_assert(kStatGeneric.gid - kStatGeneric.uid == 4);
static_assert(kStatx.gid - kStatx.uid == 4);
// statx's mode really is narrower; this is the trap the dispatcher's scrub
// has to respect.
static_assert(kStatx.mode_width == 2 && kStatX86_64.mode_width == 4);
// The two stat layouts must NOT agree, or one of them is wrong: that they
// differ is the whole reason this file exists.
static_assert(kStatX86_64.mode != kStatGeneric.mode);
static_assert(kStatX86_64.size != kStatGeneric.size);

} // namespace lx::abi::wire
