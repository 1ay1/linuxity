// Proves the authority boundary — the line between our virtual world and
// host-delegated capabilities — behaves faithfully, entirely at compile time.
#include "linuxity/kernel/authority.hpp"

using namespace lx;
using namespace lx::kernel;

// -- Realm classification is total and correct. ---------------------------
static_assert(is_virtual(Cap::VfsNamespace));
static_assert(is_virtual(Cap::Futex));
static_assert(is_virtual(Cap::PidNamespace));
static_assert(is_virtual(Cap::Uname));
static_assert(!is_virtual(Cap::SysAdmin));
static_assert(!is_virtual(Cap::LoadKernelModule));
static_assert(!is_virtual(Cap::RawEthernet));

// -- The iOS sandbox: a complete virtual world, zero delegated authority. --
constexpr Grants ios = ios_sandbox();

// Every virtual capability is granted — we back it ourselves.
static_assert(ios.has(Cap::VfsNamespace));
static_assert(ios.has(Cap::ProcFs));
static_assert(ios.has(Cap::Futex));
static_assert(ios.has(Cap::PidNamespace));
static_assert(ios.require(Cap::Uname).has_value());

// No host-delegated capability is granted.
static_assert(!ios.has(Cap::SysAdmin));
static_assert(!ios.has(Cap::MountRealDevice));
static_assert(!ios.has(Cap::RawEthernet));

// The errno distinction is faithful to Linux: a privilege-gated facility
// reads EPERM; a structurally-absent one reads ENOSYS.
static_assert(!ios.require(Cap::SysAdmin).has_value());
static_assert(ios.require(Cap::SysAdmin).error() == Errno::eperm);
static_assert(ios.require(Cap::MountRealDevice).error() == Errno::eperm);
static_assert(ios.require(Cap::LoadKernelModule).error() == Errno::enosys);
static_assert(ios.require(Cap::KernelTracing).error() == Errno::enosys);

// -- A privileged Linux host passes several delegated caps straight through.
constexpr Grants linux = privileged_linux();
static_assert(linux.has(Cap::MountRealDevice));
static_assert(linux.has(Cap::RawEthernet));
static_assert(linux.has(Cap::SysAdmin));
static_assert(linux.require(Cap::MountRealDevice).has_value());

// But even a privileged host can't do what has nowhere to happen.
static_assert(!linux.has(Cap::LoadKernelModule));
static_assert(linux.require(Cap::LoadKernelModule).error() == Errno::enosys);

// Virtual caps remain granted regardless of host — they never touch the line.
static_assert(linux.has(Cap::Futex) && ios.has(Cap::Futex));

int main() { return 0; } // all assertions already checked by the compiler
