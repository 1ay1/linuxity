// linuxity/host/entropy.hpp
//
// Cryptographic random bytes, one call, every host.
//
// WHY THIS FILE EXISTS. Entropy was fetched five different ways:
//
//   vfs/procfs.hpp          ::arc4random_buf     <-- in a PORTABLE header
//   runtime/darwin/load.hpp ::arc4random_buf
//   runtime/darwin/trap.hpp ::arc4random_buf
//   runtime/windows/api.hpp whp_random_bytes (RtlGenRandom)
//   runtime/posix_hostcalls ::getentropy
//
// The first one broke the Windows build. `arc4random_buf` is BSD/glibc-only
// and mingw has no such symbol, so `/proc/sys/kernel/random/uuid` -- a
// perfectly portable piece of procfs synthesis -- could not compile on
// Windows at all. CI had been failing on it before this work started.
//
// That is the duplication biting in its most ordinary form: the portable
// layer reached for whatever the author's host happened to provide.
//
// SECURITY, not convenience. This must be the real host CSPRNG. The guest's
// AT_RANDOM seeds its stack-protector canary and pointer guard, and
// /proc/sys/kernel/random/uuid is read by systemd tooling and Python's uuid
// module. A fixed or rand()-derived value would make every guest's canary
// identical, silently destroying the mitigation the guest believes it has --
// and it would look like it worked.
#pragma once

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#  include <windows.h>
#else
#  include <cerrno>
#  include <unistd.h>
#endif

namespace lx::host {

// Fill `buf` with `len` cryptographically random bytes. Returns false only if
// the host CSPRNG is genuinely unavailable -- callers must treat that as an
// error rather than falling back to something weaker.
[[nodiscard]] inline bool random_bytes(void* buf, std::size_t len) noexcept {
    if (len == 0) return true;
#if defined(_WIN32)
    // RtlGenRandom, exposed as SystemFunction036. It is what the Windows CRT
    // uses underneath and needs no CryptoAPI handle; resolved dynamically
    // because it has no public header declaration.
    using RtlGenRandomFn = BOOLEAN(WINAPI*)(PVOID, ULONG);
    static const RtlGenRandomFn gen = [] {
        HMODULE m = ::LoadLibraryW(L"advapi32.dll");
        return m ? reinterpret_cast<RtlGenRandomFn>(
                       reinterpret_cast<void*>(
                           ::GetProcAddress(m, "SystemFunction036")))
                 : nullptr;
    }();
    if (!gen) return false;
    // ULONG is 32-bit, so a huge request has to be chunked.
    auto* p = static_cast<unsigned char*>(buf);
    while (len > 0) {
        const ULONG chunk = static_cast<ULONG>(len > 0x1000'0000u ? 0x1000'0000u : len);
        if (gen(p, chunk) == FALSE) return false;
        p += chunk;
        len -= chunk;
    }
    return true;
#else
    // getentropy() is the portable spelling on glibc, musl and Darwin alike,
    // and unlike arc4random_buf it is declared everywhere we target. It caps
    // at 256 bytes per call, hence the loop.
    auto* p = static_cast<unsigned char*>(buf);
    while (len > 0) {
        const std::size_t chunk = len < 256 ? len : 256;
        if (::getentropy(p, chunk) != 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += chunk;
        len -= chunk;
    }
    return true;
#endif
}

} // namespace lx::host
