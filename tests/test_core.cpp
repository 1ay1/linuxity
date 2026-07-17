// Self-contained assertions over the runtime's type algebra and a mock
// kernel — no host, no OS. Proves the abstractions compose without a real
// platform underneath, which is exactly what makes the design portable.
#include "linuxity/abi/result.hpp"
#include "linuxity/abi/syscall.hpp"
#include "linuxity/abi/types.hpp"

#include <cassert>
#include <cstdio>

using namespace lx;

// -- A pure, host-free mock kernel that models every subsystem. -----------
struct MockKernel {
    Pid pid{Pid{42}};
    std::size_t last_write{};

    // Process
    Pid self() const noexcept { return pid; }
    Result<Pid> fork() { return ok(Pid{7}); }
    Status kill(Pid p, Signal) { return p ? ok() : err(Errno::einval); }

    // Vfs
    Result<kernel::Open> open(std::string_view, kernel::OFlags, kernel::Mode) {
        return err<kernel::Open>(Errno::enoent);
    }
    Result<std::size_t> read(Fd, std::span<std::byte>) { return ok(std::size_t{0}); }
    Result<std::size_t> write(Fd, std::span<const std::byte> b) {
        last_write = b.size(); return ok(b.size());
    }
    Status close(Fd f) { return f ? ok() : err(Errno::ebadf); }

    // Memory
    Result<UAddr> mmap(UAddr, std::size_t) { return ok(uaddr(0x1000)); }
    Status munmap(UAddr, std::size_t) { return ok(); }
    Result<UAddr> brk(UAddr a) { return ok(a); }
};
static_assert(kernel::IsKernel<MockKernel>, "mock must model the kernel");

int main() {
    // Strong types don't collide: Fd and Pid are distinct types.
    static_assert(!std::is_same_v<Fd, Pid>);

    // Result monad + kernel encoding.
    Result<int> good = ok(5);
    Result<int> bad  = err<int>(Errno::einval);
    assert(to_kernel(good) == 5);
    assert(to_kernel(bad) == -22);

    // LX_TRY propagation.
    auto chain = [](bool fail) -> Result<int> {
        int v = LX_TRY(fail ? err<int>(Errno::eio) : ok(10));
        return ok(v + 1);
    };
    assert(chain(false).value() == 11);
    assert(!chain(true).has_value() && chain(true).error() == Errno::eio);

    // Dispatch getpid through the ABI against the mock kernel. The new
    // dispatcher decodes an arch-specific number into a canonical Sysno, so
    // we feed it the x86-64 number for getpid (39) with Arch::x86_64.
    struct NullMem {
        Status copy_in(UAddr, std::span<std::byte>) const { return ok(); }
        Status copy_out(UAddr, std::span<const std::byte>) const { return ok(); }
    } mem;
    MockKernel mk;
    abi::Syscalls sys{mk, mem, abi::Arch::x86_64};

    abi::Regs r; r.nr = 39; // x86-64 getpid
    assert(sys.dispatch(r).ret == 42);

    abi::Regs e; e.nr = 60; e.arg[0] = 7; // x86-64 exit(7)
    auto o = sys.dispatch(e);
    assert(o.exited && o.exit_code == 7);

    // An unrecognized/real syscall is FORWARDED to the host kernel (the
    // dispatcher only virtualizes identity/lifecycle; everything else runs
    // natively in the guest). So we get forward=true, not ENOSYS.
    abi::Regs u; u.nr = 424242;
    assert(sys.dispatch(u).forward);

    // getuid is virtualized to root (0).
    abi::Regs g; g.nr = 102; // x86-64 getuid
    assert(sys.dispatch(g).ret == 0 && !sys.dispatch(g).forward);

    std::puts("all runtime type-algebra tests passed");
    return 0;
}
