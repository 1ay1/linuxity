// linuxity/abi/fsnotify_events.hpp
//
// What a syscall MEANS to inotify, as data: which argument names the object
// (a path, or an fd), and which event it causes. The dispatcher evaluates a
// row against the call (kernel/fsnotify.hpp delivers the result); it is not
// a handler -- a call here is still answered wherever it was -- so it lives
// apart from the dispatcher's switch, which tools/intercepted.py counts.
#pragma once

#include "linuxity/abi/sysno.hpp"
#include "linuxity/kernel/fsnotify.hpp"

#include <cstdint>
#include <optional>

namespace lx::abi::fsnotify_events {

// How the call names its object.
enum class Obj : std::uint8_t {
    path,          // argument `arg` is a path (dirfd in arg-1 if `at`)
    fd,            // argument 0 is an fd with a bound guest path
    path_or_fd,    // utimensat: a NULL path means the dirfd itself
};
// Special handling a row needs beyond "this bit on that object".
enum class Kind : std::uint8_t {
    plain,         // `bit` on the object
    open,          // CREATE if O_CREAT made it, OPEN, MODIFY if O_TRUNC
    unlink,        // DELETE, ISDIR from AT_REMOVEDIR
    rename,        // MOVED_FROM on arg 1, MOVED_TO on arg 3, one cookie
    close,         // CLOSE_WRITE or CLOSE_NOWRITE by the fd's access mode
    access,        // ACCESS, not for directories (getdents isn't a read)
};
struct Row {
    Obj obj;
    int arg;
    bool at;            // arg-1 is a dirfd
    bool follow;        // a trailing symlink is followed
    std::uint32_t bit;  // the event (plain rows), with kIsDir if always a dir
    Kind kind;
    bool isdir_from_object{true};   // tag kIsDir when the object is a directory
};

[[nodiscard]] constexpr std::optional<Row> row_of(Sysno sc) noexcept {
    namespace fn = kernel::fsnotify;
    using S = Sysno;
    switch (sc) {
        case S::openat: case S::openat2: return Row{Obj::path, 1, true, true, 0, Kind::open};
        case S::mkdirat:   return Row{Obj::path, 1, true, false, fn::kCreate | fn::kIsDir, Kind::plain, false};
        case S::mknodat:   return Row{Obj::path, 1, true, false, fn::kCreate, Kind::plain, false};
        case S::symlinkat: return Row{Obj::path, 2, true, false, fn::kCreate, Kind::plain, false};
        case S::linkat:    return Row{Obj::path, 3, true, false, fn::kCreate, Kind::plain, false};
        case S::unlinkat:  return Row{Obj::path, 1, true, false, fn::kDelete, Kind::unlink, false};
        case S::renameat: case S::renameat2: return Row{Obj::path, 1, true, false, 0, Kind::rename};
        case S::fchmodat: case S::fchownat:  return Row{Obj::path, 1, true, true, fn::kAttrib, Kind::plain};
        case S::utimensat: return Row{Obj::path_or_fd, 1, true, true, fn::kAttrib, Kind::plain};
        case S::setxattr: case S::removexattr:   return Row{Obj::path, 0, false, true, fn::kAttrib, Kind::plain};
        case S::lsetxattr: case S::lremovexattr: return Row{Obj::path, 0, false, false, fn::kAttrib, Kind::plain};
        case S::fchmod: case S::fchown: case S::fsetxattr: case S::fremovexattr:
            return Row{Obj::fd, 0, false, false, fn::kAttrib, Kind::plain};
        case S::truncate:  return Row{Obj::path, 0, false, true, fn::kModify, Kind::plain, false};
        case S::ftruncate: case S::fallocate:
        case S::write: case S::writev: case S::pwrite64: case S::pwritev: case S::pwritev2:
            return Row{Obj::fd, 0, false, false, fn::kModify, Kind::plain, false};
        case S::read: case S::readv: case S::pread64: case S::preadv: case S::preadv2:
            return Row{Obj::fd, 0, false, false, fn::kAccess, Kind::access, false};
        case S::close:     return Row{Obj::fd, 0, false, false, 0, Kind::close};
        default:           return std::nullopt;
    }
}

}  // namespace lx::abi::fsnotify_events
