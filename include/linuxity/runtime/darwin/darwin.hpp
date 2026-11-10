// linuxity/runtime/darwin/darwin.hpp
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

#include "linuxity/abi/wire/errno_map.hpp"
#include "linuxity/abi/wire/dirent64.hpp"
#include "linuxity/abi/wire/open_flags.hpp"
#include "linuxity/abi/wire/stat.hpp"

#include <cerrno>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <cstdint>
#include <cstring>
#include <optional>

namespace lx::runtime::darwin {

// -- open(2) flags ---------------------------------------------------------
// Linux aarch64/x86-64 asm-generic values (they agree on both).
// The guest's open(2) flags. Defined ONCE in abi/wire/open_flags.hpp -- these
// are the numbers the guest's libc puts in a register, and they are NOT
// Darwin's O_* values (O_CREAT is 0x200 here, 0100 there), which is exactly
// why open_flags() below has to translate.
using LinuxOpen = abi::wire::OpenFlag;

[[nodiscard]] inline int open_flags(std::uint64_t lf) noexcept {
    // This backend's guest is aarch64, where O_DIRECTORY/O_NOFOLLOW are NOT
    // the enum's (x86-64) values: reading them off the enum made O_DIRECTORY
    // a no-op (open of a file succeeded) and turned O_DIRECT into it.
    auto bit = [lf](LinuxOpen f) {
        return abi::wire::has_for(abi::Arch::aarch64, lf, f);
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
// ...and against the ONE layout authority (abi/wire/stat.hpp), so this struct
// and the offsets the portable dispatcher pokes can never disagree. aarch64
// uses the asm-generic layout, where st_nlink is u32 and follows st_mode.
static_assert(sizeof(LinuxStat) == abi::wire::kStatGeneric.size);
static_assert(offsetof(LinuxStat, st_mode) == abi::wire::kStatGeneric.mode);
static_assert(offsetof(LinuxStat, st_uid)  == abi::wire::kStatGeneric.uid);
static_assert(offsetof(LinuxStat, st_gid)  == abi::wire::kStatGeneric.gid);
static_assert(sizeof(LinuxStat::st_mode) == abi::wire::kStatGeneric.mode_width);
static_assert(offsetof(LinuxStat, st_size) == 48);
static_assert(offsetof(LinuxStat, st_blocks) == 64);

// Darwin stat -> Linux stat. uid/gid are forced to root because linuxity
// presents a root-owned world; this is the same rule the ptrace backend
// applies with scrub_ids, kept here so the two backends agree.
// Linux's device numbers for the standard character devices. Programs check
// them: glibc's daemon() refuses /dev/null unless st_rdev == makedev(1,3)
// (ENODEV, "daemon failed") -- which broke tmux's server, sshd, and every
// daemon -- and tools test makedev(5,0) for /dev/tty. Darwin numbers them
// differently (null is 3,2), so map by the host device's IDENTITY.
[[nodiscard]] inline std::uint64_t linux_makedev(std::uint32_t maj, std::uint32_t min) noexcept {
    return (static_cast<std::uint64_t>(maj & 0xfffff000u) << 32) |
           (static_cast<std::uint64_t>(maj & 0xfffu) << 8) |
           (static_cast<std::uint64_t>(min & 0xffffff00u) << 12) | (min & 0xffu);
}
[[nodiscard]] inline std::uint64_t rdev_to_linux(dev_t host) noexcept {
    if (host == 0) return 0;
    auto rdev_of = [](const char* p) {
        struct ::stat s{};
        return ::stat(p, &s) == 0 ? s.st_rdev : static_cast<dev_t>(-1);
    };
    struct Map { dev_t dev; std::uint64_t lin; };
    static const Map table[] = {
        {rdev_of("/dev/null"), linux_makedev(1, 3)},   {rdev_of("/dev/zero"), linux_makedev(1, 5)},
        {rdev_of("/dev/random"), linux_makedev(1, 8)}, {rdev_of("/dev/urandom"), linux_makedev(1, 9)},
        {rdev_of("/dev/tty"), linux_makedev(5, 0)},    {rdev_of("/dev/ptmx"), linux_makedev(5, 2)},
    };
    for (const Map& k : table)
        if (k.dev != static_cast<dev_t>(-1) && k.dev == host) return k.lin;
    // A pty slave: Darwin's ttys major; Linux's is 136 + n/256, minor n%256.
    static const int pts_major = [] {
        struct ::stat s{};
        return ::stat("/dev/ttys000", &s) == 0 ? static_cast<int>(major(static_cast<std::uint32_t>(s.st_rdev))) : -1;
    }();
    const auto hdev = static_cast<std::uint32_t>(host);   // Darwin dev_t is a signed 32-bit
    if (pts_major >= 0 && static_cast<int>(major(hdev)) == pts_major) {
        const auto n = static_cast<std::uint32_t>(minor(hdev));
        return linux_makedev(136 + n / 256, n % 256);
    }
    return static_cast<std::uint64_t>(host);
}

[[nodiscard]] inline LinuxStat to_linux(const struct ::stat& s) noexcept {
    LinuxStat o{};
    o.st_dev    = static_cast<std::uint64_t>(s.st_dev);
    o.st_ino    = s.st_ino;
    o.st_mode   = s.st_mode;         // S_IF* and permission bits agree
    o.st_nlink  = s.st_nlink;
    o.st_uid    = 0;
    o.st_gid    = 0;
    o.st_rdev   = rdev_to_linux(s.st_rdev);
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

// -- fcntl record locks ----------------------------------------------------
// Linux `struct flock` and Darwin's differ in BOTH field order and width, so
// a byte copy produces a lock on the wrong range of the wrong file:
//
//   Linux (aarch64): { short l_type; short l_whence; off_t l_start;
//                      off_t l_len;  pid_t l_pid;   /* pad */ }
//   Darwin:          { off_t l_start; off_t l_len; pid_t l_pid;
//                      short l_type;  short l_whence; }
//
// The lock TYPES also differ: Linux F_RDLCK/WRLCK/UNLCK are 0/1/2, Darwin's
// are 1/3/2. Without this translation every lock request is EINVAL -- which
// is exactly what made `useradd` fail with "cannot lock /etc/passwd", and
// what breaks git, sqlite and dpkg/pacman databases.
struct LinuxFlock {
    std::int16_t l_type, l_whence;
    std::int64_t l_start, l_len;
    std::int32_t l_pid;
    std::int32_t pad_;
};
static_assert(sizeof(LinuxFlock) == 32);

enum class LockType : std::int16_t { read = 0, write = 1, unlock = 2 };

[[nodiscard]] inline std::optional<short> lock_type_to_darwin(std::int16_t lt) noexcept {
    switch (static_cast<LockType>(lt)) {
        case LockType::read:   return F_RDLCK;
        case LockType::write:  return F_WRLCK;
        case LockType::unlock: return F_UNLCK;
        default:               return std::nullopt;
    }
}
[[nodiscard]] inline std::int16_t lock_type_to_linux(short dt) noexcept {
    switch (dt) {
        case F_RDLCK: return static_cast<std::int16_t>(LockType::read);
        case F_WRLCK: return static_cast<std::int16_t>(LockType::write);
        default:      return static_cast<std::int16_t>(LockType::unlock);
    }
}

// NOTE: `struct flock` must be spelled with the tag -- Darwin also declares a
// FUNCTION named flock(2), and the unqualified name resolves to that.
[[nodiscard]] inline std::optional<struct ::flock> flock_to_darwin(const LinuxFlock& l) noexcept {
    const auto type = lock_type_to_darwin(l.l_type);
    if (!type) return std::nullopt;
    struct ::flock d{};
    d.l_start  = l.l_start;
    d.l_len    = l.l_len;
    d.l_pid    = l.l_pid;
    d.l_type   = *type;
    d.l_whence = l.l_whence;          // SEEK_SET/CUR/END agree (0/1/2)
    return d;
}

[[nodiscard]] inline LinuxFlock flock_to_linux(const struct ::flock& d) noexcept {
    LinuxFlock l{};
    l.l_type   = lock_type_to_linux(d.l_type);
    l.l_whence = d.l_whence;
    l.l_start  = d.l_start;
    l.l_len    = d.l_len;
    l.l_pid    = d.l_pid;
    return l;
}

// -- struct statx ----------------------------------------------------------
// The modern stat. coreutils, git and systemd prefer it and only fall back
// to fstatat if it returns ENOSYS -- but glibc caches that verdict, so a
// backend that refuses it pays the fallback cost forever AND breaks callers
// that pass AT_EMPTY_PATH (statx on an fd with no path), which has no
// fstatat equivalent.
struct LinuxStatx {
    std::uint32_t stx_mask, stx_blksize;
    std::uint64_t stx_attributes;
    std::uint32_t stx_nlink, stx_uid, stx_gid;
    std::uint16_t stx_mode, spare0_;
    std::uint64_t stx_ino, stx_size, stx_blocks, stx_attributes_mask;
    struct Ts { std::int64_t sec; std::uint32_t nsec; std::int32_t pad_; };
    Ts stx_atime, stx_btime, stx_ctime, stx_mtime;
    std::uint32_t stx_rdev_major, stx_rdev_minor;
    std::uint32_t stx_dev_major, stx_dev_minor;
    std::uint64_t stx_mnt_id, stx_dio_mem_align_pad;
    std::uint64_t spare2_[12];
};
// The offsets ARE the ABI: a field at the wrong displacement is read as a
// different field by the guest, which is far worse than an error.
static_assert(sizeof(LinuxStatx) == 256);
static_assert(offsetof(LinuxStatx, stx_mode) == 28);
// statx is ONE layout on both ABIs (it was designed versioned and fixed), so
// this is checked against the same authority the dispatcher's scrub uses.
// Note stx_mode is u16, not u32 like struct stat's -- reading 4 bytes there
// would pick up the following pad.
static_assert(offsetof(LinuxStatx, stx_mode) == abi::wire::kStatx.mode);
static_assert(offsetof(LinuxStatx, stx_uid)  == abi::wire::kStatx.uid);
static_assert(offsetof(LinuxStatx, stx_gid)  == abi::wire::kStatx.gid);
static_assert(sizeof(LinuxStatx::stx_mode) == abi::wire::kStatx.mode_width);
static_assert(offsetof(LinuxStatx, stx_ino) == 32);
static_assert(offsetof(LinuxStatx, stx_size) == 40);
static_assert(offsetof(LinuxStatx, stx_atime) == 64);
static_assert(offsetof(LinuxStatx, stx_mtime) == 112);
static_assert(offsetof(LinuxStatx, stx_dev_major) == 136);

// The STATX_* bits we can actually answer from a Darwin stat.
inline constexpr std::uint32_t kStatxBasicStats = 0x7ff;

[[nodiscard]] inline LinuxStatx statx_from_darwin(const struct ::stat& s) noexcept {
    LinuxStatx x{};
    x.stx_mask    = kStatxBasicStats;
    x.stx_blksize = static_cast<std::uint32_t>(s.st_blksize);
    x.stx_nlink   = s.st_nlink;
    x.stx_uid     = 0;                 // linuxity presents a root-owned world
    x.stx_gid     = 0;
    x.stx_mode    = static_cast<std::uint16_t>(s.st_mode);
    x.stx_ino     = s.st_ino;
    x.stx_size    = static_cast<std::uint64_t>(s.st_size);
    x.stx_blocks  = static_cast<std::uint64_t>(s.st_blocks);
    x.stx_atime   = {s.st_atimespec.tv_sec, static_cast<std::uint32_t>(s.st_atimespec.tv_nsec), 0};
    x.stx_mtime   = {s.st_mtimespec.tv_sec, static_cast<std::uint32_t>(s.st_mtimespec.tv_nsec), 0};
    x.stx_ctime   = {s.st_ctimespec.tv_sec, static_cast<std::uint32_t>(s.st_ctimespec.tv_nsec), 0};
    x.stx_btime   = {s.st_birthtimespec.tv_sec,
                     static_cast<std::uint32_t>(s.st_birthtimespec.tv_nsec), 0};
    {
        const std::uint64_t r = rdev_to_linux(s.st_rdev);
        x.stx_rdev_major = static_cast<std::uint32_t>(((r >> 8) & 0xfff) | ((r >> 32) & ~0xfffu));
        x.stx_rdev_minor = static_cast<std::uint32_t>((r & 0xff) | ((r >> 12) & ~0xffu));
    }
    x.stx_dev_major  = static_cast<std::uint32_t>((s.st_dev >> 24) & 0xff);
    x.stx_dev_minor  = static_cast<std::uint32_t>(s.st_dev & 0xffffff);
    return x;
}

// -- linux_dirent64 --------------------------------------------------------
// Darwin's getdirentries uses a different record entirely, so the backend
// re-encodes. The LAYOUT lives in abi/wire/dirent64.hpp -- one encoder for
// every host -- and these are just local names for it, kept so existing
// call sites in this backend read naturally.
using DType = abi::wire::DType;
using abi::wire::dirent_reclen;
using abi::wire::dtype_from_mode;

// -- errno -----------------------------------------------------------------
// Host errno -> the guest's number: abi/wire/errno_map.hpp, the one table
// every backend shares (this backend once kept its own copy, which the
// shared one lacked half of -- so the dispatcher said EIO where this said
// ECONNRESET for the same host error).
[[nodiscard]] inline std::int32_t errno_to_linux(int e) noexcept {
    return static_cast<std::int32_t>(abi::wire::errno_from_host(e));
}

// The negative-errno return value a Linux syscall gives on failure.
[[nodiscard]] inline std::int64_t fail() noexcept {
    return -static_cast<std::int64_t>(errno_to_linux(errno));
}

} // namespace lx::runtime::darwin

#endif // __APPLE__
