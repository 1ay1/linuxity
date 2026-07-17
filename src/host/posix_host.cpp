// Compile-time proof that the POSIX host satisfies the Host concept.
#include "linuxity/host/posix_host.hpp"
namespace lx::host { static_assert(Host<PosixHost>); }
