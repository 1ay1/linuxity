// linuxity/host/dirent_type.hpp
//
// `struct dirent::d_type`, portably.
//
// d_type is a BSD/Linux extension, not POSIX. Linux and Darwin have it (it is
// the fast path that avoids an lstat per directory entry); MinGW's struct
// dirent does not. Rather than #ifdef the readdir loop -- which is hot, and
// which already has a correct DT_UNKNOWN fallback for filesystems that do not
// report a type -- detect the member and report DT_UNKNOWN when it is absent.
//
// That routes Windows down the lstat path the loop ALREADY implements for
// XFS/NFS, so there is one code path instead of two, and no behavior to
// re-verify: a host without d_type looks exactly like a filesystem without
// d_type.
#pragma once

#include <dirent.h>
#include <type_traits>

#include "linuxity/host/win_posix.hpp"

namespace lx::host {

template <class D>
concept HasDType = requires(const D& d) { d.d_type; };

// The entry's type, or DT_UNKNOWN when the host cannot say.
template <class D>
[[nodiscard]] inline int dirent_type_of(const D* e) noexcept {
    if constexpr (HasDType<D>) return int(e->d_type);
    else                       { (void)e; return DT_UNKNOWN; }
}

} // namespace lx::host

// Unqualified spelling for the core's readdir loops.
template <class D>
[[nodiscard]] inline int dirent_type(const D* e) noexcept {
    return ::lx::host::dirent_type_of(e);
}
