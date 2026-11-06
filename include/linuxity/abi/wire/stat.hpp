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

// What a stat YIELDS, host-neutral.
//
// Lives HERE, in abi/, because the portable dispatcher encodes it and abi/ is
// deliberately independent of host/ (the only host header syscall.hpp includes
// is a Windows compat shim). Putting it in host::HStat -- which already
// describes a host file for vfs/hostfs.hpp -- looked like the DRY choice and
// was a layering error: it made the portable dispatcher depend on the host
// interface for one optimisation.
//
// A backend fills this from whatever its OS offers (statx on Linux, stat64 on
// Darwin, GetFileInformationByHandleEx on Win32); the dispatcher encodes it
// with the layouts below. So a backend never sees a guest offset and cannot
// get one wrong, and there is still ONE encoder per ABI shared by real and
// synthesized stats.
//
// Timestamps keep nanosecond resolution because that is what statx reports;
// truncating to seconds makes `make` see a just-written file as unchanged.
struct StatFields {
    std::uint32_t mode{0};       // full st_mode, S_IFMT included
    std::uint64_t dev{0};
    std::uint64_t ino{0};
    std::uint64_t nlink{1};
    std::uint64_t rdev{0};
    std::uint64_t size{0};
    std::int64_t  blksize{4096};
    std::int64_t  blocks{0};
    std::uint64_t atime_ns{0};
    std::uint64_t mtime_ns{0};
    std::uint64_t ctime_ns{0};
};

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
    // st_nlink, which the two ABIs disagree about in BOTH position and
    // width: u64 before st_mode on x86-64, u32 after it on asm-generic (see
    // the layouts above). Only read when a hardlink was emulated, but then
    // writing the wrong 4 or 8 bytes would corrupt st_mode or st_uid.
    std::size_t nlink;
    std::size_t nlink_width;
};

inline constexpr StatLayout kStatX86_64{
    .size = 144, .mode = 24, .uid = 28, .gid = 32, .mode_width = 4,
    .nlink = 16, .nlink_width = 8,
};
inline constexpr StatLayout kStatGeneric{   // aarch64 / asm-generic
    .size = 128, .mode = 16, .uid = 24, .gid = 28, .mode_width = 4,
    .nlink = 20, .nlink_width = 4,
};

// -- struct statx ----------------------------------------------------------
// Identical on both ABIs -- it was designed as a fixed, versioned layout:
//   u32 stx_mask; u32 stx_blksize; u64 stx_attributes; u32 stx_nlink;
//   u32 stx_uid; u32 stx_gid; u16 stx_mode; u16 pad; u64 stx_ino; ...
inline constexpr StatLayout kStatx{
    .size = 256, .mode = 28, .uid = 20, .gid = 24, .mode_width = 2,
    // statx is arch-independent, so one offset serves both ABIs. Verified
    // against the host headers: stx_nlink is u32 at 16.
    .nlink = 16, .nlink_width = 4,
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

// -- S_IF*: the file-type bits of st_mode -----------------------------------
//
// These were spelled three times: inline in write_statx, inline again in
// write_statbuf, and as bare octal literals inside dtype_from_mode. They are
// ABI (the guest's libc runs S_ISDIR on these bits), and they are OCTAL --
// writing 0040000 as 40000 decimal is a silent, plausible wrong answer, which
// is exactly why they should be typed once.
enum class FileType : std::uint32_t {
    fifo    = 0010000,
    chr     = 0020000,
    dir     = 0040000,
    blk     = 0060000,
    regular = 0100000,
    symlink = 0120000,
    sock    = 0140000,
};

inline constexpr std::uint32_t kFileTypeMask = 0170000;   // S_IFMT

[[nodiscard]] constexpr std::uint32_t bits(FileType t) noexcept {
    return static_cast<std::uint32_t>(t);
}

[[nodiscard]] constexpr bool is_type(std::uint32_t mode, FileType t) noexcept {
    return (mode & kFileTypeMask) == bits(t);
}

// Every type must fit inside the mask, and the mask must not overlap the
// permission bits (0777) or a chmod would change a file's type.
static_assert((bits(FileType::dir) & kFileTypeMask) == bits(FileType::dir));
static_assert((bits(FileType::regular) & kFileTypeMask) == bits(FileType::regular));
static_assert((bits(FileType::symlink) & kFileTypeMask) == bits(FileType::symlink));
static_assert((kFileTypeMask & 0777u) == 0,
              "the type mask must not overlap the permission bits");
// The three types linuxity synthesizes are distinct under the mask.
static_assert(bits(FileType::dir) != bits(FileType::regular));
static_assert(bits(FileType::regular) != bits(FileType::symlink));
static_assert(is_type(bits(FileType::dir) | 0755u, FileType::dir));
static_assert(!is_type(bits(FileType::regular) | 0755u, FileType::dir));

// The permission and set-id bits of st_mode -- everything OUTSIDE the type
// mask. Spelled `07777` at four sites (two in syscall.hpp's chmod paths, two
// in meta_store); it is the complement of kFileTypeMask and the two must stay
// disjoint, or a chmod would change a file's type.
//
// Note it is 07777, not 0777: the top digit carries setuid (04000), setgid
// (02000) and sticky (01000). Masking with 0777 silently strips setuid from
// every file the shadow store remembers, which is how `su` and `sudo` lose
// their privilege bits across a run.
inline constexpr std::uint32_t kPermMask = 07777;

static_assert(kPermMask == 0xfff);
static_assert((kPermMask & kFileTypeMask) == 0,
              "the permission and type masks must be disjoint");
// Together they cover exactly the low 16 bits of st_mode, with no gap: a bit
// that is in neither mask would be silently dropped by every chmod path.
static_assert((kPermMask | kFileTypeMask) == 0177777u);
// The set-id bits live in kPermMask, not outside it.
static_assert((kPermMask & 04000) == 04000, "setuid is inside the perm mask");
static_assert((kPermMask & 02000) == 02000, "setgid is inside the perm mask");
static_assert((kPermMask & 01000) == 01000, "sticky is inside the perm mask");
static_assert(kPermMask != 0777,
              "0777 would strip setuid/setgid/sticky -- use 07777");

} // namespace lx::abi::wire
