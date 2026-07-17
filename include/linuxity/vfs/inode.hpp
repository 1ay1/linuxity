// linuxity/vfs/inode.hpp
//
// The VFS vocabulary: inodes, file types, stat, and the per-filesystem
// operations concept.
//
// Real Linux layers a *common* VFS over per-filesystem operation tables.
// A dentry resolves a path to an inode; the inode carries a pointer to the
// filesystem's ops (tmpfs, ext4, procfs, ...). We mirror that exactly, but
// the "ops table" is a C++ concept instead of a struct of function pointers,
// so each backend is type-checked against the contract at compile time.
//
// This is what makes "install any distro" real: a rootfs is just a tree of
// inodes served by a HostFs backend, with procfs/sysfs/tmpfs mounted over it.
#pragma once

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/types.hpp"

#include <concepts>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>

namespace lx::vfs {

// The POSIX file kinds, as a strong enum (the S_IFMT field of st_mode).
enum class FileType : std::uint8_t {
    regular, directory, symlink, chardev, blockdev, fifo, socket,
};

// A permission/type bitset — kept strong so it never mixes with flags/fds.
enum class Mode : std::uint32_t {};
[[nodiscard]] constexpr Mode mode(std::uint32_t m) noexcept { return Mode{m}; }
[[nodiscard]] constexpr std::uint32_t bits(Mode m) noexcept {
    return static_cast<std::uint32_t>(m);
}

// The subset of struct stat the runtime tracks. Extends naturally.
struct Stat {
    Ino      ino{};
    FileType type{FileType::regular};
    Mode     mode{};
    Uid      uid{};
    Gid      gid{};
    std::uint64_t size{};
    std::uint64_t nlink{1};
    std::uint64_t mtime_ns{};
};

// Open flags (O_RDONLY, O_CREAT, ...). Strong bitset.
enum class OFlags : std::uint32_t {
    rdonly = 0, wronly = 1, rdwr = 2, accmode = 3,
    creat = 0100, excl = 0200, trunc = 01000, append = 02000,
    directory = 0200000, nonblock = 04000, cloexec = 02000000,
};
[[nodiscard]] constexpr OFlags operator|(OFlags a, OFlags b) noexcept {
    return OFlags(std::uint32_t(a) | std::uint32_t(b));
}
[[nodiscard]] constexpr bool has(OFlags set, OFlags f) noexcept {
    return (std::uint32_t(set) & std::uint32_t(f)) == std::uint32_t(f);
}
[[nodiscard]] constexpr OFlags accmode(OFlags f) noexcept {
    return OFlags(std::uint32_t(f) & std::uint32_t(OFlags::accmode));
}

// A directory entry as getdents would report it.
struct Dirent {
    std::string name;
    Ino         ino{};
    FileType    type{};
};

// -- Filesystem backend concept -------------------------------------------
// A backing store (tmpfs, hostfs, procfs) models this. The VFS resolves a
// path to (backend, ino) and then calls through here. Every method is total
// and returns a Result — errors are values, never exceptions, matching the
// kernel/user boundary. This is the per-fs "inode_operations + file_operations".
template <class F>
concept FileSystem = requires(F f, Ino ino, std::string_view name,
                              std::span<std::byte> rbuf,
                              std::span<const std::byte> wbuf,
                              std::uint64_t off, FileType ft, Mode m) {
    // Metadata.
    { f.root() }              -> std::same_as<Ino>;
    { f.stat(ino) }           -> std::same_as<Result<Stat>>;

    // Directory ops: name resolution and listing.
    { f.lookup(ino, name) }   -> std::same_as<Result<Ino>>;
    { f.create(ino, name, ft, m) } -> std::same_as<Result<Ino>>;

    // File data ops (offset-addressed, like pread/pwrite).
    { f.read_at(ino, off, rbuf) }  -> std::same_as<Result<std::size_t>>;
    { f.write_at(ino, off, wbuf) } -> std::same_as<Result<std::size_t>>;
};

} // namespace lx::vfs
