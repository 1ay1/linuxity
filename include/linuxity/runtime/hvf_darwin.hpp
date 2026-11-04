// linuxity/runtime/hvf_darwin.hpp
//
// The Linux/Darwin ABI boundary: flags, structs, errno.
//
// Both kernels implement POSIX, which makes this layer easy to get subtly
// WRONG: the names agree, so a forgotten translation compiles and runs and
// then misbehaves far from the cause. O_DIRECTORY is 0x4000 on Linux and
// 0x100000 on Darwin; Linux's struct stat puts st_mode at offset 16 and
// Darwin's at 4. A guest handed Darwin's layout decides every file is a FIFO.
//
// So every value that crosses the boundary is translated EXPLICITLY here, and
// the Linux-side structs are declared with static_asserts on their offsets.
// Nothing in this file touches the hypervisor; it is pure data translation
// and is unit-tested as such.
#pragma once

#if defined(__APPLE__)

#include <cerrno>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <cstdint>
#include <cstring>

namespace lx::runtime::darwin {

// -- open(2) flags ---------------------------------------------------------
// Linux aarch64/x86-64 asm-generic values (they agree on both).
enum class LinuxOpen : std::uint64_t {
    rdonly = 0, wronly = 1, rdwr = 2, creat = 0100, excl = 0200,
    noctty = 0400, trunc = 01000, append = 02000, nonblock = 04000,
    directory = 0200000, nofollow = 0400000, cloexec = 02000000,
    // Linux-only hints with no Darwin equivalent; dropping them is safe
    // (they affect caching/atime, never the visible result).
    directio = 040000, noatime = 01000000, path = 010000000, tmpfile = 020200000,
};

[[nodiscard]] inline int open_flags(std::uint64_t lf) noexcept {
    auto bit = [lf](LinuxOpen f) {
        return (lf & static_cast<std::uint64_t>(f)) != 0;
    };
    int df = 0;
    switch (lf & 3) {
        case 0:  df = O_RDONLY; break;
        case 1:  df = O_WRONLY; break;
        default: df = O_RDWR;   break;
    }
    if (bit(LinuxOpen::creat))     df |= O_CREAT;
    if (bit(LinuxOpen::excl))      df |= O_EXCL;
    if (bit(LinuxOpen::noctty))    df |= O_NOCTTY;
    if (bit(LinuxOpen::trunc))     df |= O_TRUNC;
    if (bit(LinuxOpen::append))    df |= O_APPEND;
    if (bit(LinuxOpen::nonblock))  df |= O_NONBLOCK;
    if (bit(LinuxOpen::directory)) df |= O_DIRECTORY;
    if (bit(LinuxOpen::nofollow))  df |= O_NOFOLLOW;
    if (bit(LinuxOpen::cloexec))   df |= O_CLOEXEC;
    return df;
}

// Darwin -> Linux, for F_GETFL: the guest must see its OWN flag values back.
[[nodiscard]] inline std::int64_t open_flags_to_linux(int df) noexcept {
    std::uint64_t lf = 0;
    switch (df & O_ACCMODE) {
        case O_WRONLY: lf = 1; break;
        case O_RDWR:   lf = 2; break;
        default:       lf = 0; break;
    }
    if (df & O_APPEND)   lf |= static_cast<std::uint64_t>(LinuxOpen::append);
    if (df & O_NONBLOCK) lf |= static_cast<std::uint64_t>(LinuxOpen::nonblock);
    return static_cast<std::int64_t>(lf);
}

// -- struct stat -----------------------------------------------------------
// The Linux aarch64 layout, field for field. The offsets are load-bearing:
// musl reads st_mode/st_size directly at these displacements.
struct LinuxStat {
    std::uint64_t st_dev;
    std::uint64_t st_ino;
    std::uint32_t st_mode;
    std::uint32_t st_nlink;
    std::uint32_t st_uid;
    std::uint32_t st_gid;
    std::uint64_t st_rdev;
    std::uint64_t pad1_;
    std::int64_t  st_size;
    std::int32_t  st_blksize;
    std::int32_t  pad2_;
    std::int64_t  st_blocks;
    std::int64_t  st_atime_sec;  std::uint64_t st_atime_nsec;
    std::int64_t  st_mtime_sec;  std::uint64_t st_mtime_nsec;
    std::int64_t  st_ctime_sec;  std::uint64_t st_ctime_nsec;
    std::uint32_t unused_[2];
};
static_assert(sizeof(LinuxStat) == 128);
static_assert(offsetof(LinuxStat, st_mode) == 16);
static_assert(offsetof(LinuxStat, st_uid) == 24);
static_assert(offsetof(LinuxStat, st_size) == 48);
static_assert(offsetof(LinuxStat, st_blocks) == 64);

// Darwin stat -> Linux stat. uid/gid are forced to root because linuxity
// presents a root-owned world; this is the same rule the ptrace backend
// applies with scrub_ids, kept here so the two backends agree.
[[nodiscard]] inline LinuxStat to_linux(const struct ::stat& s) noexcept {
    LinuxStat o{};
    o.st_dev    = static_cast<std::uint64_t>(s.st_dev);
    o.st_ino    = s.st_ino;
    o.st_mode   = s.st_mode;         // S_IF* and permission bits agree
    o.st_nlink  = s.st_nlink;
    o.st_uid    = 0;
    o.st_gid    = 0;
    o.st_rdev   = static_cast<std::uint64_t>(s.st_rdev);
    o.st_size   = s.st_size;
    o.st_blksize = s.st_blksize;
    o.st_blocks  = s.st_blocks;
    o.st_atime_sec  = s.st_atimespec.tv_sec;
    o.st_atime_nsec = static_cast<std::uint64_t>(s.st_atimespec.tv_nsec);
    o.st_mtime_sec  = s.st_mtimespec.tv_sec;
    o.st_mtime_nsec = static_cast<std::uint64_t>(s.st_mtimespec.tv_nsec);
    o.st_ctime_sec  = s.st_ctimespec.tv_sec;
    o.st_ctime_nsec = static_cast<std::uint64_t>(s.st_ctimespec.tv_nsec);
    return o;
}

// -- struct statfs ---------------------------------------------------------
// asm-generic (aarch64) layout. `df` reads f_blocks/f_bfree/f_bavail *
// f_bsize; f_type picks the filesystem name it prints.
struct LinuxStatfs {
    std::int64_t f_type, f_bsize;
    std::uint64_t f_blocks, f_bfree, f_bavail, f_files, f_ffree;
    std::int32_t f_fsid[2];
    std::int64_t f_namelen, f_frsize, f_flags;
    std::int64_t f_spare[4];
};
static_assert(sizeof(LinuxStatfs) == 120);

[[nodiscard]] inline LinuxStatfs statfs_to_linux(const struct ::statfs& s) noexcept {
    LinuxStatfs l{};
    l.f_type = 0x794c7630;             // OVERLAYFS_SUPER_MAGIC: it IS an overlay
    l.f_bsize = s.f_bsize;
    l.f_frsize = s.f_bsize;
    l.f_blocks = s.f_blocks;
    l.f_bfree = s.f_bfree;
    l.f_bavail = s.f_bavail;
    l.f_files = s.f_files;
    l.f_ffree = s.f_ffree;
    std::memcpy(l.f_fsid, &s.f_fsid, sizeof l.f_fsid);
    l.f_namelen = 255;
    return l;
}

// -- linux_dirent64 --------------------------------------------------------
// getdents64's record: { u64 ino; s64 off; u16 reclen; u8 type; char name[] }
// 8-byte aligned. Darwin's getdirentries uses a different record entirely, so
// the backend re-encodes rather than copying bytes through.
constexpr std::size_t kDirentHeader = 19;
[[nodiscard]] constexpr std::size_t dirent_reclen(std::size_t namelen) noexcept {
    return (kDirentHeader + namelen + 1 + 7) & ~std::size_t{7};
}

enum class DType : std::uint8_t {
    unknown = 0, fifo = 1, chr = 2, dir = 4, blk = 6, reg = 8, lnk = 10, sock = 12,
};
[[nodiscard]] inline DType dtype_from_mode(std::uint32_t mode) noexcept {
    switch (mode & S_IFMT) {
        case S_IFDIR:  return DType::dir;
        case S_IFREG:  return DType::reg;
        case S_IFLNK:  return DType::lnk;
        case S_IFCHR:  return DType::chr;
        case S_IFBLK:  return DType::blk;
        case S_IFIFO:  return DType::fifo;
        case S_IFSOCK: return DType::sock;
        default:       return DType::unknown;
    }
}

// -- errno -----------------------------------------------------------------
// 1..34 are identical on both kernels (EPERM..ERANGE). Past that they
// diverge, and these are the ones real programs branch on.
[[nodiscard]] inline std::int32_t errno_to_linux(int e) noexcept {
    switch (e) {
        case EDEADLK:        return 35;
        case ENAMETOOLONG:   return 36;
        case ENOLCK:         return 37;
        case ENOSYS:         return 38;
        case ENOTEMPTY:      return 39;
        case ELOOP:          return 40;
        case ENOMSG:         return 42;
        case EIDRM:          return 43;
        case ENOSTR:         return 60;
        case ENODATA:        return 61;
        case ETIME:          return 62;
        case ENOSR:          return 63;
        case EREMOTE:        return 66;
        case ENOLINK:        return 67;
        case EPROTO:         return 71;
        case EMULTIHOP:      return 72;
        case EBADMSG:        return 74;
        case EOVERFLOW:      return 75;
        case EILSEQ:         return 84;
        case EUSERS:         return 87;
        case ENOTSOCK:       return 88;
        case EDESTADDRREQ:   return 89;
        case EMSGSIZE:       return 90;
        case EPROTOTYPE:     return 91;
        case ENOPROTOOPT:    return 92;
        case EPROTONOSUPPORT:return 93;
        case ESOCKTNOSUPPORT:return 94;
        case EOPNOTSUPP:     return 95;
        case EPFNOSUPPORT:   return 96;
        case EAFNOSUPPORT:   return 97;
        case EADDRINUSE:     return 98;
        case EADDRNOTAVAIL:  return 99;
        case ENETDOWN:       return 100;
        case ENETUNREACH:    return 101;
        case ENETRESET:      return 102;
        case ECONNABORTED:   return 103;
        case ECONNRESET:     return 104;
        case ENOBUFS:        return 105;
        case EISCONN:        return 106;
        case ENOTCONN:       return 107;
        case ETIMEDOUT:      return 110;
        case ECONNREFUSED:   return 111;
        case EHOSTDOWN:      return 112;
        case EHOSTUNREACH:   return 113;
        case EALREADY:       return 114;
        case EINPROGRESS:    return 115;
        case ESTALE:         return 116;
        case EDQUOT:         return 122;
        case ECANCELED:      return 125;
        case EOWNERDEAD:     return 130;
        case ENOTRECOVERABLE:return 131;
        default:             return e <= 34 ? e : 5 /*EIO*/;
    }
}

// The negative-errno return value a Linux syscall gives on failure.
[[nodiscard]] inline std::int64_t fail() noexcept {
    return -static_cast<std::int64_t>(errno_to_linux(errno));
}

} // namespace lx::runtime::darwin

#endif // __APPLE__
