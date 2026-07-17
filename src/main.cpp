// linuxity — a portable, type-theoretic implementation of the Linux
// userspace ABI. This entry point wires the three layers together:
//
//     Host  ──►  Kernel (subsystem product)  ──►  Syscall ABI  ──►  guest
//
// and issues a few syscalls "as a guest would" to prove the plumbing.
#include "linuxity/abi/syscall.hpp"
#include "linuxity/host/posix_host.hpp"
#include "linuxity/kernel/kernel.hpp"

#include <cstdio>
#include <cstring>

int main() {
    using namespace lx;

    // 1. Pick a host for this platform. On iOS/Darwin this line is the only
    //    thing that changes — the rest of the stack is host-agnostic.
    host::PosixHost hw;

    // 2. Build the kernel on top of it. Kernel<PosixHost> is checked at
    //    compile time to model Vfs && Process && Memory.
    kernel::Kernel<host::PosixHost> k{hw};
    static_assert(kernel::IsKernel<decltype(k)>,
                  "the concrete kernel must model every subsystem");

    // 3. The syscall dispatcher: ABI numbers -> typed subsystem methods.
    abi::Syscalls sys{k};

    auto say = [&](const char* s) {
        abi::Regs r;
        r.nr     = static_cast<std::uint64_t>(abi::Nr::write);
        r.arg[0] = 1; // stdout
        r.arg[1] = reinterpret_cast<std::uint64_t>(s);
        r.arg[2] = std::strlen(s);
        // NOTE: real guest_bytes() would translate arg[1]; the demo write
        // path forwards straight to the host, so we exercise it directly.
        std::span<const std::byte> bytes{reinterpret_cast<const std::byte*>(s),
                                         std::strlen(s)};
        (void)r;
        (void)k.write(Fd{1}, bytes);
    };

    say("linuxity: portable Linux userspace ABI\n");

    // getpid(2), routed through the ABI dispatcher like a real guest call.
    abi::Regs gp;
    gp.nr = static_cast<std::uint64_t>(abi::Nr::getpid);
    std::int64_t pid = sys.dispatch(gp);
    std::printf("guest getpid() -> %lld\n", static_cast<long long>(pid));

    // An unimplemented syscall returns -ENOSYS, honestly.
    abi::Regs bad; bad.nr = 999999;
    std::int64_t rc = sys.dispatch(bad);
    std::printf("guest syscall(999999) -> %lld (-ENOSYS=%d)\n",
                static_cast<long long>(rc), -int(Errno::enosys));
    return 0;
}
