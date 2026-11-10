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
#ifdef ENODATA
        case ENODATA:      return Errno::enodata;
#endif
        case EPROTONOSUPPORT: return Errno::eprotonosupport;
#ifdef ENOTSUP
        case ENOTSUP:      return Errno::enotsup;
#endif
#if defined(EOPNOTSUPP) && (!defined(ENOTSUP) || EOPNOTSUPP != ENOTSUP)
        case EOPNOTSUPP:   return Errno::enotsup;
#endif
#ifdef ETXTBSY
        case ETXTBSY: return Errno::etxtbsy;
#endif
#ifdef EDOM
        case EDOM: return Errno::edom;
#endif
#ifdef EDEADLK
        case EDEADLK: return Errno::edeadlk;
#endif
#ifdef ENOLCK
        case ENOLCK: return Errno::enolck;
#endif
#ifdef ENOSTR
        case ENOSTR: return Errno::enostr;
#endif
#ifdef ETIME
        case ETIME: return Errno::etime;
#endif
#ifdef ENOSR
        case ENOSR: return Errno::enosr;
#endif
#ifdef EREMOTE
        case EREMOTE: return Errno::eremote;
#endif
#ifdef ENOLINK
        case ENOLINK: return Errno::enolink;
#endif
#ifdef EPROTO
        case EPROTO: return Errno::eproto;
#endif
#ifdef EMULTIHOP
        case EMULTIHOP: return Errno::emultihop;
#endif
#ifdef EBADMSG
        case EBADMSG: return Errno::ebadmsg;
#endif
#ifdef EOVERFLOW
        case EOVERFLOW: return Errno::eoverflow;
#endif
#ifdef EILSEQ
        case EILSEQ: return Errno::eilseq;
#endif
#ifdef EUSERS
        case EUSERS: return Errno::eusers;
#endif
#ifdef ENOTSOCK
        case ENOTSOCK: return Errno::enotsock;
#endif
#ifdef EDESTADDRREQ
        case EDESTADDRREQ: return Errno::edestaddrreq;
#endif
#ifdef EMSGSIZE
        case EMSGSIZE: return Errno::emsgsize;
#endif
#ifdef EPROTOTYPE
        case EPROTOTYPE: return Errno::eprototype;
#endif
#ifdef ENOPROTOOPT
        case ENOPROTOOPT: return Errno::enoprotoopt;
#endif
#ifdef ESOCKTNOSUPPORT
        case ESOCKTNOSUPPORT: return Errno::esocktnosupport;
#endif
#ifdef EPFNOSUPPORT
        case EPFNOSUPPORT: return Errno::epfnosupport;
#endif
#ifdef EAFNOSUPPORT
        case EAFNOSUPPORT: return Errno::eafnosupport;
#endif
#ifdef EADDRNOTAVAIL
        case EADDRNOTAVAIL: return Errno::eaddrnotavail;
#endif
#ifdef ENETDOWN
        case ENETDOWN: return Errno::enetdown;
#endif
#ifdef ENETUNREACH
        case ENETUNREACH: return Errno::enetunreach;
#endif
#ifdef ENETRESET
        case ENETRESET: return Errno::enetreset;
#endif
#ifdef ECONNABORTED
        case ECONNABORTED: return Errno::econnaborted;
#endif
#ifdef ECONNRESET
        case ECONNRESET: return Errno::econnreset;
#endif
#ifdef ENOBUFS
        case ENOBUFS: return Errno::enobufs;
#endif
#ifdef EISCONN
        case EISCONN: return Errno::eisconn;
#endif
#ifdef ENOTCONN
        case ENOTCONN: return Errno::enotconn;
#endif
#ifdef ESHUTDOWN
        case ESHUTDOWN: return Errno::eshutdown;
#endif
#ifdef EHOSTDOWN
        case EHOSTDOWN: return Errno::ehostdown;
#endif
#ifdef EHOSTUNREACH
        case EHOSTUNREACH: return Errno::ehostunreach;
#endif
#ifdef EALREADY
        case EALREADY: return Errno::ealready;
#endif
#ifdef EINPROGRESS
        case EINPROGRESS: return Errno::einprogress;
#endif
#ifdef ESTALE
        case ESTALE: return Errno::estale;
#endif
#ifdef EDQUOT
        case EDQUOT: return Errno::edquot;
#endif
#ifdef ECANCELED
        case ECANCELED: return Errno::ecanceled;
#endif
#ifdef EOWNERDEAD
        case EOWNERDEAD: return Errno::eownerdead;
#endif
#ifdef ENOTRECOVERABLE
        case ENOTRECOVERABLE: return Errno::enotrecoverable;
#endif
        default:           return Errno::eio;
    }
}

} // namespace lx::abi::wire
