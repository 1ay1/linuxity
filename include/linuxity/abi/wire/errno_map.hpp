// linuxity/abi/wire/errno_map.hpp
//
// Host errno -> guest Errno, in one place.
//
// The guest's errno numbers are ABI: `-ENOENT` must be -2 in the register no
// matter which host noticed the failure. The TRANSLATION, though, is policy
// over a host value, and it was duplicated and lossy:
//
//   * PosixHost::from_errno mapped 6 values and sent everything else to EIO.
//   * PosixHost::read/write ignored errno entirely and returned EIO always.
//   * each kernel-less backend carried its own partial table.
//
// Collapsing to EIO is not harmless. A guest that gets EIO instead of ENOSPC
// reports "I/O error" for a full disk; instead of EPIPE it fails to notice a
// closed pipe and loops; instead of EAGAIN on a non-blocking fd it treats a
// would-block as a hard failure. These are the errors programs BRANCH on.
//
// So: one table, covering the errno space linuxity can actually encounter.
// Host-free -- it maps from the host's <cerrno> values, which every targeted
// host defines, to our own strong enum.
#pragma once

#include <cerrno>

#include "linuxity/abi/result.hpp"

namespace lx::abi::wire {

// Map a host `errno` to the guest's Errno.
//
// The fallback is EIO, but it is now genuinely the last resort rather than
// the common case. A value arriving here unmapped means a host reported
// something this table has not seen; prefer adding it over widening the
// fallback's reach.
[[nodiscard]] inline Errno errno_from_host(int e) noexcept {
    switch (e) {
        case 0:            return Errno::ok;
        case EPERM:        return Errno::eperm;
        case ENOENT:       return Errno::enoent;
        case ESRCH:        return Errno::esrch;
        case EINTR:        return Errno::eintr;
        case EIO:          return Errno::eio;
        case ENXIO:        return Errno::enxio;
        case E2BIG:        return Errno::e2big;
        case ENOEXEC:      return Errno::enoexec;
        case EBADF:        return Errno::ebadf;
        case ECHILD:       return Errno::echild;
        case EAGAIN:       return Errno::eagain;
        case ENOMEM:       return Errno::enomem;
        case EACCES:       return Errno::eacces;
        case EFAULT:       return Errno::efault;
        case EBUSY:        return Errno::ebusy;
        case EEXIST:       return Errno::eexist;
        case EXDEV:        return Errno::exdev;
        case ENODEV:       return Errno::enodev;
        case ENOTDIR:      return Errno::enotdir;
        case EISDIR:       return Errno::eisdir;
        case EINVAL:       return Errno::einval;
        case ENFILE:       return Errno::enfile;
        case EMFILE:       return Errno::emfile;
        case ENOTTY:       return Errno::enotty;
        case EFBIG:        return Errno::efbig;
        case ENOSPC:       return Errno::enospc;
        case ESPIPE:       return Errno::espipe;
        case EROFS:        return Errno::erofs;
        case EMLINK:       return Errno::emlink;
        case EPIPE:        return Errno::epipe;
        case ERANGE:       return Errno::erange;
        case ENAMETOOLONG: return Errno::enametoolong;
        case ENOSYS:       return Errno::enosys;
        case ENOTEMPTY:    return Errno::enotempty;
        case ELOOP:        return Errno::eloop;
        case ECONNREFUSED: return Errno::econnrefused;
        case ETIMEDOUT:    return Errno::etimedout;
        case EADDRINUSE:   return Errno::eaddrinuse;
        case ENOMSG:       return Errno::enomsg;
        case EIDRM:        return Errno::eidrm;
        case EPROTONOSUPPORT: return Errno::eprotonosupport;
#ifdef ENOTSUP
        case ENOTSUP:      return Errno::enotsup;
#endif
#if defined(EOPNOTSUPP) && (!defined(ENOTSUP) || EOPNOTSUPP != ENOTSUP)
        case EOPNOTSUPP:   return Errno::enotsup;
#endif
        default:           return Errno::eio;
    }
}

} // namespace lx::abi::wire
