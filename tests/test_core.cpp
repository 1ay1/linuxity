// Self-contained assertions over the runtime's type algebra and a mock
// kernel — no host, no OS. Proves the abstractions compose without a real
// platform underneath, which is exactly what makes the design portable.
#include "linuxity/abi/result.hpp"
#include "linuxity/abi/syscall.hpp"
#include "linuxity/abi/types.hpp"

#include <cassert>
#include <cstdio>

using namespace lx;

// Read a fate without reaching for a flag. These are the test-side spelling of
// "what did the dispatcher decide": ask the sum which arm it is.
[[nodiscard]] static std::int64_t virt_ret(const abi::Outcome& o) {
    const auto* v = o.get_if<abi::Virtualize>();
    assert(v && "expected a virtualized value");
    return v->ret;
}
[[nodiscard]] static bool is_forward(const abi::Outcome& o) {
    return o.get_if<abi::Forward>() != nullptr;
}

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

    // The filesystem namespace (mount table + cwd + fd table).
    kernel::FileNamespace fns{};
    kernel::FileNamespace& files() noexcept { return fns; }

    // The virtual process table /proc (and readlink /proc/self/exe) reads.
    kernel::ProcessTable ptab{};
    kernel::ProcessTable& procs() noexcept { return ptab; }
    const kernel::ProcessTable& procs() const noexcept { return ptab; }

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
    assert(virt_ret(sys.dispatch(r)) == 42);

    // exit/exit_group are FORWARDED: the task actually terminates in the
    // kernel and the trap reaps it (multi-process: only the root's exit ends
    // the whole run), so the dispatcher reports forward, not a virtual exit.
    abi::Regs e; e.nr = 60; e.arg[0] = 7; // x86-64 exit(7)
    assert(is_forward(sys.dispatch(e)));

    // An unrecognized/real syscall is FORWARDED to the host kernel (the
    // dispatcher only virtualizes identity/lifecycle; everything else runs
    // natively in the guest). So we get a Forward fate, not ENOSYS.
    abi::Regs u; u.nr = 424242;
    assert(is_forward(sys.dispatch(u)));

    // getuid is virtualized to root (0).
    abi::Regs g; g.nr = 102; // x86-64 getuid
    assert(virt_ret(sys.dispatch(g)) == 0 && !is_forward(sys.dispatch(g)));

    // The termios2 ioctls are rewritten to their classic equivalents. Android's
    // SELinux ioctl whitelist allows TCGETS/TCSETS on a pty slave but not
    // these, and glibc >= 2.42 uses only these -- so without the rewrite every
    // tcgetattr/tcsetattr on a pty fails EACCES and `tty` says "not a tty".
    // Asserted here rather than in the live test because a host that PERMITS
    // termios2 (x86-64 Linux) gives the same answer either way: only the
    // dispatcher's choice of fate shows the downgrade really happens.
    auto downgrades_to = [&](std::uint64_t req, std::uint64_t want,
                             bool want_widen) {
        abi::Regs io; io.nr = 16;            // x86-64 ioctl
        io.arg[0] = 3; io.arg[1] = req; io.arg[2] = 0x7000;
        const auto out = sys.dispatch(io);
        const auto* ar = out.template get_if<abi::ArgRewrite>();
        assert(ar && "a termios2 ioctl must become an ArgRewrite");
        assert(ar->arg == 1 && "the REQUEST register is the one to replace");
        assert(ar->to == want);
        const bool widens = ar->convert ==
            abi::ArgRewrite::Convert::termios_to_termios2;
        assert(widens == want_widen &&
               "only the getter needs c_ispeed/c_ospeed appended");
    };
    downgrades_to(0x802c542a, 0x5401, true);    // TCGETS2  -> TCGETS
    downgrades_to(0x402c542b, 0x5402, false);   // TCSETS2  -> TCSETS
    downgrades_to(0x402c542c, 0x5403, false);   // TCSETSW2 -> TCSETSW
    downgrades_to(0x402c542d, 0x5404, false);   // TCSETSF2 -> TCSETSF

    // The classic ones are already allowed everywhere, so they just forward.
    {
        abi::Regs io; io.nr = 16; io.arg[0] = 3; io.arg[1] = 0x5401;
        assert(is_forward(sys.dispatch(io)));
    }

    std::puts("all runtime type-algebra tests passed");
    return 0;
}
