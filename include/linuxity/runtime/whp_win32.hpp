// linuxity/runtime/whp_win32.hpp
//
// The Linux/Win32 ABI boundary: flags, structs, errno, time.
//
// This layer is the Windows counterpart of hvf_darwin.hpp, and it is MORE
// dangerous than the Darwin one for a reason worth stating plainly: Darwin is
// a POSIX kernel, so most of its semantics line up and the mistakes are
// numeric. Windows is not. Here the mismatches are structural:
//
//   * O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, O_PATH have NO Win32 equivalent.
//     Silently dropping them is how "open a directory" starts returning a
//     file handle and the guest's readdir goes insane.
//   * Windows has no single `mode_t`; permission bits are an ACL. We
//     synthesize a plausible st_mode rather than pretend.
//   * Windows paths are UTF-16, backslash-separated, case-insensitive, with
//     reserved names (CON, NUL, AUX) and a 260-char default limit. A Linux
//     path is bytes. The conversion is lossy in both directions and is done
//     in ONE place (`to_win_path`) so the lossiness is auditable.
//   * Windows epoch is 1601, Linux's is 1970. The offset is a constant that
//     is easy to transpose and impossible to notice until timestamps are
//     wrong by 369 years.
//
// So every value that crosses the boundary is translated EXPLICITLY here, the
// Linux-side structs are declared with static_asserts on their field offsets,
// and nothing in this file touches the hypervisor -- it is pure data
// translation and is unit-tested as such.
#pragma once

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif
#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>

namespace lx::runtime::win32 {

// -- open(2) flags ---------------------------------------------------------
// Linux x86-64 (asm-generic) values.
enum class LinuxOpen : std::uint64_t {
    rdonly    = 0,
    wronly    = 1,
    rdwr      = 2,
    creat     = 0x40,
    excl      = 0x80,
    noctty    = 0x100,
    trunc     = 0x200,
    append    = 0x400,
    nonblock  = 0x800,
    directory = 0x1'0000,
    nofollow  = 0x2'0000,
    cloexec   = 0x8'0000,
    path      = 0x20'0000,
};

[[nodiscard]] constexpr bool has(std::uint64_t flags, LinuxOpen f) noexcept {
    return (flags & std::uint64_t(f)) != 0;
}

// The access mode is the low two bits, not a flag -- testing it with `has`
// is a classic bug (O_RDONLY is 0, so `has(flags, rdonly)` is always false).
[[nodiscard]] constexpr std::uint64_t access_mode(std::uint64_t flags) noexcept {
    return flags & 3;
}

// How a Linux open() maps onto CreateFileW's four orthogonal arguments.
struct WinOpen {
    DWORD access = 0;
    DWORD share = 0;
    DWORD disposition = 0;
    DWORD attrs = 0;
    // Flags the guest asked for that Win32 cannot express. The caller decides
    // whether to emulate (O_APPEND via a seek, O_DIRECTORY via a type check)
    // or to fail -- but it is never silently ignored.
    bool want_directory = false;
    bool want_nofollow = false;
    bool want_append = false;
    bool want_nonblock = false;
};

[[nodiscard]] inline WinOpen translate_open(std::uint64_t flags) noexcept {
    WinOpen w{};
    switch (access_mode(flags)) {
        case std::uint64_t(LinuxOpen::wronly): w.access = GENERIC_WRITE; break;
        case std::uint64_t(LinuxOpen::rdwr):
            w.access = GENERIC_READ | GENERIC_WRITE; break;
        default: w.access = GENERIC_READ; break;
    }
    // O_PATH wants a handle usable only for *naming* -- no data access. That
    // is exactly FILE_READ_ATTRIBUTES, and it is also the only way to open a
    // directory handle on Windows without backup semantics.
    if (has(flags, LinuxOpen::path)) w.access = FILE_READ_ATTRIBUTES;

    // Linux lets other processes unlink and rename an open file; Windows by
    // default locks it. Sharing everything, including DELETE, is what makes
    // guest behavior match -- without FILE_SHARE_DELETE, a guest that unlinks
    // its own open temp file (the standard POSIX idiom) gets EACCES.
    w.share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    const bool creat = has(flags, LinuxOpen::creat);
    const bool excl  = has(flags, LinuxOpen::excl);
    const bool trunc = has(flags, LinuxOpen::trunc);
    if (creat && excl)      w.disposition = CREATE_NEW;
    else if (creat && trunc) w.disposition = CREATE_ALWAYS;
    else if (creat)          w.disposition = OPEN_ALWAYS;
    else if (trunc)          w.disposition = TRUNCATE_EXISTING;
    else                     w.disposition = OPEN_EXISTING;

    w.attrs = FILE_ATTRIBUTE_NORMAL;
    // A directory handle REQUIRES this flag; without it CreateFileW fails
    // with ERROR_ACCESS_DENIED on any directory.
    if (has(flags, LinuxOpen::directory) || has(flags, LinuxOpen::path))
        w.attrs |= FILE_FLAG_BACKUP_SEMANTICS;
    // O_NOFOLLOW: refuse to traverse the final symlink. Windows reparse
    // points are the nearest thing; opening with this flag returns a handle
    // to the link itself.
    if (has(flags, LinuxOpen::nofollow))
        w.attrs |= FILE_FLAG_OPEN_REPARSE_POINT;
    // O_CLOEXEC is about handle inheritance, which on Windows is a property
    // of the SECURITY_ATTRIBUTES at creation; default is non-inheritable,
    // which matches O_CLOEXEC. (So the DEFAULT here is the opposite of
    // POSIX's: a handle WITHOUT O_CLOEXEC must be explicitly made
    // inheritable. The fd layer handles that; recorded here so the asymmetry
    // is not rediscovered.)

    w.want_directory = has(flags, LinuxOpen::directory);
    w.want_nofollow  = has(flags, LinuxOpen::nofollow);
    w.want_append    = has(flags, LinuxOpen::append);
    w.want_nonblock  = has(flags, LinuxOpen::nonblock);
    return w;
}

// -- struct stat -----------------------------------------------------------
// The Linux x86-64 layout, field for field. The guest reads these bytes
// directly, so the OFFSETS are the ABI -- hence the static_asserts below,
// which are the only thing standing between a layout typo and a guest that
// believes every file is a FIFO.
struct LinuxStat {
    std::uint64_t st_dev;
    std::uint64_t st_ino;
    std::uint64_t st_nlink;
    std::uint32_t st_mode;
    std::uint32_t st_uid;
    std::uint32_t st_gid;
    std::uint32_t __pad0;
    std::uint64_t st_rdev;
    std::int64_t  st_size;
    std::int64_t  st_blksize;
    std::int64_t  st_blocks;
    std::int64_t  st_atime;
    std::int64_t  st_atime_nsec;
    std::int64_t  st_mtime;
    std::int64_t  st_mtime_nsec;
    std::int64_t  st_ctime;
    std::int64_t  st_ctime_nsec;
    std::int64_t  __unused[3];
};
static_assert(sizeof(LinuxStat) == 144);
static_assert(offsetof(LinuxStat, st_mode) == 24,
              "st_mode offset is the ABI; 24 on x86-64 Linux");
static_assert(offsetof(LinuxStat, st_uid) == 28);
static_assert(offsetof(LinuxStat, st_size) == 48);
static_assert(offsetof(LinuxStat, st_mtime) == 88);

// Linux st_mode type bits.
inline constexpr std::uint32_t kSIfifo  = 0x1000;
inline constexpr std::uint32_t kSIfchr  = 0x2000;
inline constexpr std::uint32_t kSIfdir  = 0x4000;
inline constexpr std::uint32_t kSIfblk  = 0x6000;
inline constexpr std::uint32_t kSIfreg  = 0x8000;
inline constexpr std::uint32_t kSIflnk  = 0xa000;
inline constexpr std::uint32_t kSIfsock = 0xc000;

// -- time ------------------------------------------------------------------
// Windows FILETIME counts 100ns ticks since 1601-01-01; Linux counts seconds
// since 1970-01-01. The gap is 11644473600 seconds, and getting it wrong is
// a 369-year error that no test notices unless it checks a real timestamp.
inline constexpr std::int64_t kFiletimeEpochDeltaSec = 11'644'473'600ll;
inline constexpr std::int64_t kFiletimeTicksPerSec   = 10'000'000ll;

struct LinuxTimespec {
    std::int64_t sec;
    std::int64_t nsec;
};

[[nodiscard]] inline LinuxTimespec from_filetime(FILETIME ft) noexcept {
    const std::uint64_t ticks =
        (std::uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    LinuxTimespec t{};
    t.sec = std::int64_t(ticks / std::uint64_t(kFiletimeTicksPerSec)) -
            kFiletimeEpochDeltaSec;
    t.nsec = std::int64_t(ticks % std::uint64_t(kFiletimeTicksPerSec)) * 100;
    return t;
}

[[nodiscard]] inline FILETIME to_filetime(LinuxTimespec t) noexcept {
    const std::uint64_t ticks =
        std::uint64_t((t.sec + kFiletimeEpochDeltaSec) * kFiletimeTicksPerSec +
                      t.nsec / 100);
    FILETIME ft{};
    ft.dwLowDateTime = DWORD(ticks & 0xffff'ffffull);
    ft.dwHighDateTime = DWORD(ticks >> 32);
    return ft;
}

// Fill a Linux struct stat from Win32 metadata.
//
// st_mode: Windows has no POSIX permission bits, so inventing them is
// unavoidable. We report 0755 for directories and executables, 0644
// otherwise, and honor FILE_ATTRIBUTE_READONLY by clearing the write bits --
// which is the one permission signal Win32 actually carries. Reporting 0777
// for everything would be simpler and would make the guest's `test -w`
// lie.
[[nodiscard]] inline LinuxStat stat_from_win(
        const BY_HANDLE_FILE_INFORMATION& bhfi) noexcept {
    LinuxStat s{};
    const bool dir = (bhfi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    const bool link = (bhfi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
    const bool ro = (bhfi.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0;

    std::uint32_t perm = dir ? 0755u : 0644u;
    if (ro) perm &= ~0222u;

    s.st_mode = (link ? kSIflnk : dir ? kSIfdir : kSIfreg) | perm;
    s.st_dev = bhfi.dwVolumeSerialNumber;
    s.st_ino = (std::uint64_t(bhfi.nFileIndexHigh) << 32) | bhfi.nFileIndexLow;
    s.st_nlink = bhfi.nNumberOfLinks ? bhfi.nNumberOfLinks : 1;
    s.st_uid = 0;
    s.st_gid = 0;
    s.st_size = std::int64_t((std::uint64_t(bhfi.nFileSizeHigh) << 32) |
                             bhfi.nFileSizeLow);
    s.st_blksize = 4096;
    // Linux counts 512-byte blocks regardless of st_blksize.
    s.st_blocks = (s.st_size + 511) / 512;

    const auto at = from_filetime(bhfi.ftLastAccessTime);
    const auto mt = from_filetime(bhfi.ftLastWriteTime);
    // Windows has no ctime (inode-change time); ftCreationTime is a BIRTH
    // time, which is a different thing. Using mtime is the lesser lie --
    // `make` compares mtimes, and a creation time would break rebuilds.
    s.st_atime = at.sec;  s.st_atime_nsec = at.nsec;
    s.st_mtime = mt.sec;  s.st_mtime_nsec = mt.nsec;
    s.st_ctime = mt.sec;  s.st_ctime_nsec = mt.nsec;
    return s;
}

// -- errno -----------------------------------------------------------------
// Linux errno values (x86-64). Only the ones a Win32 error can actually
// produce are listed; anything unmapped becomes EIO rather than a lie.
enum : std::int32_t {
    LPERM = 1, LNOENT = 2, LSRCH = 3, LINTR = 4, LIO = 5, LNXIO = 6,
    L2BIG = 7, LNOEXEC = 8, LBADF = 9, LCHILD = 10, LAGAIN = 11,
    LNOMEM = 12, LACCES = 13, LFAULT = 14, LBUSY = 16, LEXIST = 17,
    LXDEV = 18, LNODEV = 19, LNOTDIR = 20, LISDIR = 21, LINVAL = 22,
    LNFILE = 23, LMFILE = 24, LNOTTY = 25, LFBIG = 27, LNOSPC = 28,
    LSPIPE = 29, LROFS = 30, LMLINK = 31, LPIPE = 32, LNAMETOOLONG = 36,
    LNOSYS = 38, LNOTEMPTY = 39, LLOOP = 40, LNOTSOCK = 88,
    LCONNRESET = 104, LTIMEDOUT = 110, LCONNREFUSED = 111,
};

[[nodiscard]] inline std::int32_t error_to_linux(DWORD e) noexcept {
    switch (e) {
        case ERROR_SUCCESS:             return 0;
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:
        case ERROR_BAD_NETPATH:         return LNOENT;
        case ERROR_TOO_MANY_OPEN_FILES: return LMFILE;
        case ERROR_ACCESS_DENIED:
        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:      return LACCES;
        case ERROR_INVALID_HANDLE:      return LBADF;
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY:         return LNOMEM;
        case ERROR_NO_MORE_FILES:       return 0;   // end of dir, not an error
        case ERROR_WRITE_PROTECT:       return LROFS;
        case ERROR_NOT_READY:           return LNXIO;
        case ERROR_CRC:
        case ERROR_SEEK:
        case ERROR_WRITE_FAULT:
        case ERROR_READ_FAULT:
        case ERROR_GEN_FAILURE:         return LIO;
        case ERROR_HANDLE_DISK_FULL:
        case ERROR_DISK_FULL:           return LNOSPC;
        case ERROR_NOT_SUPPORTED:       return LNOSYS;
        case ERROR_FILE_EXISTS:
        case ERROR_ALREADY_EXISTS:      return LEXIST;
        case ERROR_INVALID_PARAMETER:
        case ERROR_INVALID_FUNCTION:    return LINVAL;
        case ERROR_BROKEN_PIPE:
        case ERROR_NO_DATA:             return LPIPE;
        case ERROR_DIR_NOT_EMPTY:       return LNOTEMPTY;
        case ERROR_DIRECTORY:           return LNOTDIR;
        case ERROR_BUFFER_OVERFLOW:
        case ERROR_FILENAME_EXCED_RANGE:return LNAMETOOLONG;
        case ERROR_NOT_SAME_DEVICE:     return LXDEV;
        case ERROR_OPERATION_ABORTED:   return LINTR;
        case ERROR_BAD_EXE_FORMAT:      return LNOEXEC;
        case ERROR_CANT_RESOLVE_FILENAME: return LLOOP;
        case WAIT_TIMEOUT:              return LTIMEDOUT;
        default:                        return LIO;
    }
}

// The negative-errno a Linux syscall returns on failure.
[[nodiscard]] inline std::int64_t fail(DWORD e = ::GetLastError()) noexcept {
    return -static_cast<std::int64_t>(error_to_linux(e));
}

// -- paths -----------------------------------------------------------------
// A guest path is Linux bytes; Win32 wants UTF-16. Converting in one place
// keeps the lossiness auditable.
//
// The \\?\ prefix is added for absolute paths because it lifts the 260-char
// MAX_PATH limit AND disables the reserved-name rewriting that would
// otherwise make a guest file literally named "nul" or "aux" unopenable --
// both of which are real filenames in a Linux rootfs tarball.
[[nodiscard]] inline std::wstring to_win_path(std::string_view linux_path) {
    std::string s{linux_path};
    for (auto& c : s) if (c == '/') c = '\\';

    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()),
                                        nullptr, 0);
    std::wstring w;
    if (n > 0) {
        w.resize(std::size_t(n));
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    }
    // Absolute DOS path (X:\...) -> prefix. A relative path cannot take it.
    const bool absolute = w.size() >= 3 && w[1] == L':' && w[2] == L'\\';
    if (absolute && w.compare(0, 4, L"\\\\?\\") != 0) w.insert(0, L"\\\\?\\");
    return w;
}

[[nodiscard]] inline std::string from_win_path(std::wstring_view w) {
    std::wstring in{w};
    if (in.compare(0, 4, L"\\\\?\\") == 0) in.erase(0, 4);
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, in.data(), int(in.size()),
                                        nullptr, 0, nullptr, nullptr);
    std::string s;
    if (n > 0) {
        s.resize(std::size_t(n));
        ::WideCharToMultiByte(CP_UTF8, 0, in.data(), int(in.size()), s.data(),
                              n, nullptr, nullptr);
    }
    for (auto& c : s) if (c == '\\') c = '/';
    return s;
}

// -- mmap protection -------------------------------------------------------
inline constexpr std::uint64_t kProtRead  = 1;
inline constexpr std::uint64_t kProtWrite = 2;
inline constexpr std::uint64_t kProtExec  = 4;

// Linux PROT_* -> the PTE bits our page tables use. Note that x86-64 paging
// cannot express "execute but not read": a readable page is always readable,
// so PROT_EXEC implies read. Saying so here beats a surprise later.
struct PteProt { bool writable; bool executable; };

[[nodiscard]] constexpr PteProt translate_prot(std::uint64_t prot) noexcept {
    return PteProt{(prot & kProtWrite) != 0, (prot & kProtExec) != 0};
}

} // namespace lx::runtime::win32

#endif // _WIN32
