// linuxity/host/win_posix.hpp
//
// The POSIX-shaped corners the Win32 CRT does not have.
//
// The core (abi/, kernel/, vfs/, loader/) is host-agnostic by design, but
// "host-agnostic" was established against two POSIX kernels. Windows is the
// first host that is not POSIX, and it exposes a handful of genuine gaps:
//
//   mkdir(path, mode)  MinGW's CRT declares mkdir(path) -- one argument. The
//                      mode is meaningless without POSIX permission bits.
//   S_ISLNK            No POSIX symlinks, so the CRT omits the macro.
//   O_CLOEXEC          Handle inheritance is a SECURITY_ATTRIBUTES property,
//                      not an open flag; non-inheritable is already the
//                      default, which is what O_CLOEXEC asks for.
//   O_DIRECTORY, O_NOFOLLOW, O_PATH, O_NONBLOCK
//                      No equivalent in the CRT's open(); the real Win32
//                      mapping lives in runtime/whp_win32.hpp, which uses
//                      CreateFileW directly.
//
// Rather than sprinkle #ifdef _WIN32 through the core -- which is how a
// portable core stops being readable, and then stops being portable -- every
// gap is closed HERE, once, with the semantics spelled out. Included early
// (before the core headers) so the declarations are in scope.
//
// This header is a NO-OP on every non-Windows host.
#pragma once

#if defined(_WIN32)

#include <direct.h>
#include <io.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cerrno>

// -- mkdir -----------------------------------------------------------------
// The CRT's mkdir takes no mode. Windows has no POSIX permission bits to
// apply it to (permissions are ACLs, inherited from the parent), so the mode
// is accepted and deliberately DISCARDED -- an honest no-op rather than a
// silently wrong chmod.
//
// This is a real overload in the GLOBAL namespace rather than a macro, so
// that both `mkdir(p, m)` and `::mkdir(p, m)` resolve -- a function-like
// macro mangles the qualified form into `::::lx::...`. The CRT's
// 1-argument ::mkdir keeps working alongside it by overload resolution.
#if !defined(LX_WIN_MKDIR_DEFINED)
#define LX_WIN_MKDIR_DEFINED 1
inline int mkdir(const char* path, unsigned /*mode*/) noexcept {
    return ::_mkdir(path);
}
#endif

// -- lstat -----------------------------------------------------------------
// No POSIX symlinks on Win32, so lstat and stat would return the same thing.
// Provided so the core's "don't follow the final link" calls compile; the
// distinction is restored in the Win32 host backend, which queries reparse
// points through GetFileAttributesW.
#if !defined(LX_WIN_LSTAT_DEFINED)
#define LX_WIN_LSTAT_DEFINED 1
inline int lstat(const char* path, struct ::stat* st) noexcept {
    return ::stat(path, st);
}
#endif

// -- readlink --------------------------------------------------------------
// No POSIX symlinks, so nothing is ever a link: EINVAL is exactly what
// readlink(2) returns for a non-symlink, which makes this the correct answer
// rather than a stub. (Reparse-point resolution, where it is wanted, goes
// through the Win32 host backend.)
#if !defined(LX_WIN_READLINK_DEFINED)
#define LX_WIN_READLINK_DEFINED 1
inline long readlink(const char* /*path*/, char* /*buf*/, unsigned long /*n*/) noexcept {
    errno = EINVAL;
    return -1;
}
#endif

// -- dirent d_type ---------------------------------------------------------
// MinGW's struct dirent carries no d_type. DT_UNKNOWN is the POSIX-blessed
// "ask with stat instead" value, and every correct readdir caller already
// handles it -- so defining the constants and reporting UNKNOWN keeps the
// core's fast path compiling while routing Windows down its stat fallback.
#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK    10
#define DT_SOCK   12
#endif

// -- stat type macros ------------------------------------------------------
// The CRT defines _S_IFDIR/_S_IFREG/_S_IFCHR but no link type and not all of
// the S_IS* predicates.
#ifndef S_IFLNK
#define S_IFLNK 0xa000
#endif
#ifndef S_ISLNK
// There are no POSIX symlinks on Win32, so this is always false. NTFS
// reparse points are queried through the Win32 host backend, not here.
#define S_ISLNK(m) (0)
#endif
#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#endif
#ifndef S_ISREG
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#endif
#ifndef S_ISCHR
#define S_ISCHR(m) (((m) & _S_IFMT) == _S_IFCHR)
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(m) (0)
#endif
#ifndef S_ISBLK
#define S_ISBLK(m) (0)
#endif
#ifndef S_ISSOCK
#define S_ISSOCK(m) (0)
#endif

// -- open flags ------------------------------------------------------------
// Flags the CRT's open() cannot express. Defined as 0 so they compose
// harmlessly with |, each with the reason it is safe to be a no-op.
#ifndef O_CLOEXEC
// Win32 handles are non-inheritable by default -- already O_CLOEXEC's effect.
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
// The CRT cannot open a directory at all; the WHP backend uses CreateFileW
// with FILE_FLAG_BACKUP_SEMANTICS instead (see whp_win32.hpp).
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_PATH
#define O_PATH 0
#endif
#ifndef O_NONBLOCK
// Win32 file handles are synchronous unless opened OVERLAPPED; the fd layer
// emulates non-blocking semantics above this line.
#define O_NONBLOCK 0
#endif
#ifndef O_NOCTTY
// No controlling terminals to acquire.
#define O_NOCTTY 0
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

// -- permission bits -------------------------------------------------------
// The CRT has _S_IREAD/_S_IWRITE only. The guest's mode_t is carried in the
// meta store rather than on the host inode, so these exist to let mode
// arithmetic in the core compile.
#ifndef S_IRWXU
#define S_IRWXU 0700
#define S_IRUSR 0400
#define S_IWUSR 0200
#define S_IXUSR 0100
#endif
#ifndef S_IRWXG
#define S_IRWXG 0070
#define S_IRGRP 0040
#define S_IWGRP 0020
#define S_IXGRP 0010
#endif
#ifndef S_IRWXO
#define S_IRWXO 0007
#define S_IROTH 0004
#define S_IWOTH 0002
#define S_IXOTH 0001
#endif
#ifndef S_ISUID
#define S_ISUID 04000
#define S_ISGID 02000
#define S_ISVTX 01000
#endif

#endif // _WIN32
