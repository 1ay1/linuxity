// linuxity/host/environ.hpp
//
// The process environment block, declared once.
//
// POSIX says `environ` exists but no header has to declare it: glibc does
// in <unistd.h> under _GNU_SOURCE, Darwin's <unistd.h> never does (it wants
// _NSGetEnviron() from a shared library, but a plain executable may use the
// symbol), and MSVC calls it _environ. Each user wrote its own `extern`,
// and the one that didn't (the conform runner, via ::environ) only built on
// glibc. Ask here instead.
#pragma once

#if defined(_WIN32)
#include <stdlib.h>
#else
extern "C" char** environ;
#endif

namespace lx::host {

[[nodiscard]] inline char** host_environ() noexcept {
#if defined(_WIN32)
    return _environ;
#else
    return ::environ;
#endif
}

}  // namespace lx::host
