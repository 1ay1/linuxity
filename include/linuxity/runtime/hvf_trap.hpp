// linuxity/runtime/hvf_trap.hpp
//
// The macOS trap backend: run a Linux aarch64 guest on Apple Silicon.
//
// On Linux the ptrace backend borrows the HOST kernel: the guest is a real
// child process, and syscalls linuxity doesn't virtualize are FORWARDED to
// the host kernel, which already speaks Linux. On macOS there is no such
// kernel to borrow. XNU does not implement the Linux ABI, so EVERY guest
// syscall must be serviced by linuxity itself.
//
// So the guest doesn't get a host process; it gets a bare VM:
//
//   * Hypervisor.framework gives us an EL1/EL0 address space with no guest
//     kernel in it. We map one flat chunk of host anonymous memory as guest
//     physical memory (IPA 0..mem_size) and build 3-level page tables inside
//     it, so the guest runs with the MMU on at EL0.
//   * The guest's own instructions execute BARE on the CPU — this is an
//     aarch64 rootfs on an aarch64 host, no translation, native speed.
//   * `svc #0` from EL0 traps to our EL1 vector stub, which immediately
//     `hvc`s out to the hypervisor, i.e. to us. We decode x8/x0..x5 into
//     abi::Regs, hand them to abi::Syscalls, write the result into x0, and
//     resume at ELR_EL1. Exactly the SyscallTrap contract the Cpu loop in
//     runtime/trap.hpp already drives on Linux.
//
// Consequences of having no host kernel underneath, and how we answer them:
//
//   FORWARD    — there is nothing to forward to. On this backend `forward()`
//                means "emulate it against the macOS host": file I/O becomes
//                real Darwin pread/pwrite on the translated host path, and
//                memory syscalls (mmap/brk/mprotect) are served by our own
//                guest-physical allocator. See hvf_sys.hpp.
//   REDIRECT   — the path rewrite the dispatcher asks for is applied in our
//                own syscall emulation, not poked into guest memory. There is
//                no race (nothing else can run while we're stopped).
//   fork/clone — Hypervisor.framework refuses to operate in a forked child
//                (hv_vm_create returns HV_BAD_ARGUMENT there). Verified on
//                macOS 27: the VM must be TORN DOWN before fork(2) and
//                re-created on both sides, which works because guest physical
//                memory is ordinary COW anonymous memory. See fork_guest().
//   zeroing     — host writes into mapped guest memory ARE visible to the
//                guest, but mmap(MAP_FIXED) over it silently detaches the
//                guest's view (the IPA still points at the old pages). So a
//                fresh guest page is cleared with madvise(MADV_ZERO), never
//                by remapping. Verified on macOS 27.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/abi/result.hpp"
#include "linuxity/abi/syscall.hpp"
#include "linuxity/runtime/hvf_darwin.hpp"
#include "linuxity/runtime/hvf_mem.hpp"
#include "linuxity/runtime/hvf_regs.hpp"
#include "linuxity/runtime/hvf_vma.hpp"
#include "linuxity/runtime/trap.hpp"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <time.h>
#include <stdlib.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace lx::runtime {

// -- Guest physical memory layout -----------------------------------------
// A single contiguous IPA region. The low 2 MiB is the hypervisor-private
// area (page tables + the EL1 vector stub) mapped EL1-only, so guest user
// code can neither read nor write it. Everything above is the guest's.
struct HvfLayout {
    static constexpr std::uint64_t page       = 0x1000;
    static constexpr std::uint64_t l1_table   = 0x1000;   // 3-level walk root
    static constexpr std::uint64_t l2_table   = 0x2000;
    static constexpr std::uint64_t l3_tables  = 0x3000;   // one per 2 MiB
    static constexpr std::uint64_t vectors    = 0x10000;  // VBAR_EL1
    static constexpr std::uint64_t priv_end   = 0x200000; // first guest page
    // Where the guest's own objects live. This backend identity-maps guest
    // VA == guest physical address (TCR T0SZ=25 gives a 39-bit VA space, and
    // the MMU is on only so EL0 can be unprivileged and W^X per page), so
    // every address below is an offset into the one memory region. ELF images
    // load at their own p_vaddr, the brk heap grows up from the image end,
    // and mmap grows DOWN from just below the stack so the two meet in the
    // middle exactly as on a real process.
    //
    // The stack therefore sits at the TOP OF GUEST RAM, not at Linux's usual
    // 0x7fff_ffff_f000: with VA == GPA an address above mem_size has no
    // translation. A guest that only reads sp (every real program) cannot
    // tell the difference.
    static constexpr std::uint64_t stack_guard = 0x10000;   // below mem top
};

// The EL1 exception vector stub. ARM requires 16 entries of 0x80 bytes each;
// every one of them does the same thing: `hvc #<index>` so the hypervisor
// (us) sees which vector fired, then never returns — we always resume the
// guest by writing PC/CPSR ourselves.
inline void write_vector_stub(std::uint8_t* mem) {
    for (int v = 0; v < 16; ++v) {
        std::uint32_t hvc = 0xD4000002u | (static_cast<std::uint32_t>(v) << 5);
        std::memcpy(mem + HvfLayout::vectors + static_cast<std::size_t>(v) * 0x80,
                    &hvc, 4);
    }
}

// Build a 3-level page table that identity-maps [0, mapped) with 4 KiB pages.
// The private area below priv_end is EL1-only (AP=0b00); everything else is
// EL0 read/write/execute (AP=0b01). We deliberately do NOT set PXN/UXN per
// region: linuxity relies on the GUEST's own mprotect bookkeeping for W^X,
// and a JIT inside the guest expects to be able to make pages executable.
inline void build_page_tables(std::uint8_t* mem, std::uint64_t mapped) {
    auto put64 = [mem](std::uint64_t at, std::uint64_t v) {
        std::memcpy(mem + at, &v, 8);
    };
    // Block/table descriptor bits: AF(10) | SH=inner(8..9) | AP(6..7) |
    // AttrIndx=0(2..4) | type.
    constexpr std::uint64_t kAf = 1ull << 10, kSh = 3ull << 8;
    put64(HvfLayout::l1_table, HvfLayout::l2_table | 3);
    std::uint64_t l3 = HvfLayout::l3_tables;
    for (std::uint64_t base = 0; base < mapped; base += (1ull << 21)) {
        std::uint64_t l2i = (base >> 21) & 0x1ff;
        put64(HvfLayout::l2_table + l2i * 8, l3 | 3);
        for (std::uint64_t off = 0; off < (1ull << 21); off += HvfLayout::page) {
            std::uint64_t pa = base + off;
            std::uint64_t ap = pa < HvfLayout::priv_end ? 0ull : 1ull;
            put64(l3 + ((off >> 12) & 0x1ff) * 8, pa | kAf | kSh | (ap << 6) | 3);
        }
        l3 += HvfLayout::page;
    }
}

// -- The virtual machine ---------------------------------------------------
// Owns guest physical memory and the single vCPU. Hypervisor.framework
// permits exactly one VM per process, which is why fork support is a
// teardown/rebuild rather than a second instance.
//
// Non-copyable, non-movable: the hv_vcpu_exit_t* the framework hands back
// points into VM-owned state, so the object's address is part of its
// identity. Pinning it is the honest encoding of that constraint.
class HvfVm {
public:
    HvfVm() = default;
    HvfVm(const HvfVm&) = delete;
    HvfVm& operator=(const HvfVm&) = delete;
    HvfVm(HvfVm&&) = delete;
    HvfVm& operator=(HvfVm&&) = delete;
    ~HvfVm() {
        teardown();
        if (base_) ::munmap(base_, size_);
    }

    [[nodiscard]] Status init(std::uint64_t mem_size) {
        // Round up to a 2 MiB block so the L3 page-table loop covers whole
        // blocks, and clamp to the 36-bit IPA the hardware exposes.
        constexpr std::uint64_t kBlock = 1ull << 21;
        size_ = (mem_size + kBlock - 1) & ~(kBlock - 1);
        if (size_ > (1ull << 36)) return err(Errno::einval);
        void* p = ::mmap(nullptr, size_, PROT_READ | PROT_WRITE,
                         MAP_ANON | MAP_PRIVATE, -1, 0);
        if (p == MAP_FAILED) return err(Errno::enomem);
        base_ = static_cast<std::byte*>(p);
        return attach();
    }

    // -- Memory -----------------------------------------------------------
    [[nodiscard]] GuestRam ram() const noexcept {
        return GuestRam{base_, size_, HvfLayout::priv_end};
    }
    [[nodiscard]] std::uint64_t mem_size() const noexcept { return size_; }

    // Clear a guest range. MUST be MADV_ZERO and never mmap(MAP_FIXED):
    // remapping replaces the host pages while the guest's IPA translation
    // still points at the OLD ones, so the guest silently keeps reading
    // stale data. Verified on macOS 27.
    void zero(std::uint64_t gpa, std::size_t n) noexcept {
        auto win = ram().at(gpa, n);
        if (win.empty()) return;
#if defined(MADV_ZERO)
        if (::madvise(win.data(), win.size(), MADV_ZERO) == 0) return;
#endif
        std::memset(win.data(), 0, win.size());
    }

    // Publish freshly written guest code. The host wrote it through a data
    // mapping; the guest will FETCH it, and on arm64 those are separate
    // caches with no coherency guarantee.
    void publish_code(std::uint64_t gpa, std::size_t n) const noexcept {
        auto win = ram().at(gpa, n);
        if (!win.empty()) ::sys_icache_invalidate(win.data(), win.size());
    }

    // -- Execution --------------------------------------------------------
    void set_entry(std::uint64_t pc, std::uint64_t sp) noexcept {
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, sp);
        ::hv_vcpu_set_reg(cpu_, HV_REG_PC, pc);
        ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, 0);   // EL0t, DAIF clear
    }

    // Run until the guest traps, returning its register snapshot. HV_EXIT
    // reasons other than EXCEPTION (vtimer, cancel) are not guest events, so
    // they surface as EINTR for the caller to retry.
    [[nodiscard]] Result<GuestRegs> run() {
        if (::hv_vcpu_run(cpu_) != HV_SUCCESS) return err<GuestRegs>(Errno::eio);
        if (exit_->reason != HV_EXIT_REASON_EXCEPTION)
            return err<GuestRegs>(Errno::eintr);
        return ok(read_regs(cpu_));
    }

    void set_result(const GuestRegs& r, std::int64_t ret) noexcept {
        write_return(cpu_, r, ret);
    }

    // -- fork(2) ----------------------------------------------------------
    // Hypervisor.framework refuses to operate in a forked child: hv_vm_create
    // returns HV_BAD_ARGUMENT (0xfae94002) there and the inherited handle is
    // dead. Verified on macOS 27. But guest RAM is ordinary COW anonymous
    // memory, so a guest fork is:
    //
    //     teardown() -> ::fork() -> attach() on BOTH sides
    //
    // The child inherits an exact copy-on-write image of guest memory, which
    // IS fork(2) semantics for the guest, and each side rebuilds its own VM
    // over its own copy. Registers are carried across explicitly because
    // destroying the vCPU discards them.
    void teardown() noexcept {
        if (cpu_live_) { ::hv_vcpu_destroy(cpu_); cpu_live_ = false; }
        if (vm_live_)  { ::hv_vm_destroy();       vm_live_  = false; }
    }
    [[nodiscard]] Status rebuild() { return attach(); }
    void restore(const GuestRegs& r, std::uint64_t sp, std::uint64_t tls) noexcept {
        for (std::size_t i = 0; i < r.x.size(); ++i)
            ::hv_vcpu_set_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + i), r.x[i]);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, sp);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, tls);
        ::hv_vcpu_set_reg(cpu_, HV_REG_PC, r.elr);
        ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, r.spsr);
    }
    [[nodiscard]] std::uint64_t sp() const noexcept {
        std::uint64_t v = 0;
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_SP_EL0, &v);
        return v;
    }
    [[nodiscard]] std::uint64_t tls() const noexcept {
        std::uint64_t v = 0;
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, &v);
        return v;
    }
    void set_tls(std::uint64_t v) noexcept {
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, v);
    }

private:
    // Create VM + vCPU over the existing memory and put the machine into
    // "Linux userspace" state: MMU on, EL0 unprivileged, vectors installed.
    // Runs at init and again after every fork.
    [[nodiscard]] Status attach() {
        build_page_tables(reinterpret_cast<std::uint8_t*>(base_), size_);
        write_vector_stub(reinterpret_cast<std::uint8_t*>(base_));
        ::sys_icache_invalidate(base_ + HvfLayout::vectors, 16 * 0x80);

        if (::hv_vm_create(nullptr) != HV_SUCCESS) return err(Errno::enodev);
        vm_live_ = true;
        const auto flags = static_cast<hv_memory_flags_t>(
            HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
        if (::hv_vm_map(base_, 0, size_, flags) != HV_SUCCESS)
            return err(Errno::enomem);
        if (::hv_vcpu_create(&cpu_, &exit_, nullptr) != HV_SUCCESS)
            return err(Errno::enodev);
        cpu_live_ = true;

        auto sr = [this](hv_sys_reg_t r, std::uint64_t v) {
            ::hv_vcpu_set_sys_reg(cpu_, r, v);
        };
        sr(HV_SYS_REG_VBAR_EL1, HvfLayout::vectors);
        sr(HV_SYS_REG_MAIR_EL1, 0xff);               // Attr0 = Normal WB
        // TCR_EL1: T0SZ=25 (39-bit VA) | EPD1 | 4 KiB granule | inner
        // shareable | Normal-WB walks | TBI0 (libc pointer tagging) |
        // IPS=36-bit.
        sr(HV_SYS_REG_TCR_EL1, 25ull | (1ull << 8) | (1ull << 10)
                                     | (3ull << 12) | (1ull << 23)
                                     | (1ull << 32));
        sr(HV_SYS_REG_TTBR0_EL1, HvfLayout::l1_table);
        sr(HV_SYS_REG_CPACR_EL1, 3ull << 20);        // FP/SIMD usable at EL0
        // SCTLR_EL1: M | C | I (MMU + caches) | SA/SA0 | nTWI/nTWE | SPAN,
        // plus the RES1 bits. Caches ON matters: libc issues DC/IC
        // maintenance and relies on normal memory ordering.
        sr(HV_SYS_REG_SCTLR_EL1, 0x30d0199dull);
        return ok();
    }

    std::byte* base_{nullptr};
    std::uint64_t size_{0};
    hv_vcpu_t cpu_{};
    hv_vcpu_exit_t* exit_{nullptr};
    bool vm_live_{false}, cpu_live_{false};
};

// -- The trap backend ------------------------------------------------------
// Models runtime::SyscallTrap, so the SAME Cpu loop that drives ptrace on
// Linux drives this. Every difference follows from one fact: there is no
// host Linux kernel beneath us.
//
//   next()      reads the register snapshot once (nine hypervisor calls),
//               not once per accessor.
//   resume()    writes x0 + PC + PSTATE: three calls, the minimum. No
//               syscall ran, so unlike ptrace there is nothing to neutralize.
//   forward()   cannot mean "let the kernel do it". It emulates against
//               Darwin: memory from the VMA map, I/O via real Darwin calls.
//               Anything unimplemented returns ENOSYS, which libc handles;
//               a plausible-looking wrong answer would corrupt it silently.
//   redirect()  needs no guest write at all -- we hold the translated host
//               path as a std::string. The ptrace backend must poke it into
//               guest memory for the host kernel to read, which is where its
//               check-then-use race lives. Structurally absent here.
class HvfTrap {
public:
    explicit HvfTrap(HvfVm& vm) noexcept : vm_{vm} {}

    // The loader has already written the image and stack into guest RAM, so
    // starting is just placing the entry state. `image_end` seeds the heap.
    [[nodiscard]] Status start(UAddr entry, UAddr sp) {
        if (value(entry)) vm_.set_entry(value(entry), value(sp));
        return ok();
    }

    void set_arena(std::uint64_t image_end, std::uint64_t stack_floor) {
        as_.reset(image_end, stack_floor);
    }

    // Record a region the LOADER mapped directly into guest RAM (ELF
    // segments, the stack). Without this the VMA map doesn't know they
    // exist, and the guest's own mprotect on them -- which glibc's ld.so
    // does to apply RELRO right before transferring control -- fails ENOMEM
    // and the program dies with "cannot apply additional memory protection
    // after relocation".
    void adopt(std::uint64_t begin, std::uint64_t end, GuestProt prot) {
        as_.adopt({AddressSpace::page_down(begin), AddressSpace::page_up(end),
                   prot, /*anonymous=*/false});
    }

    [[nodiscard]] Result<bool> next(TrapFrame& f) {
        constexpr std::uint64_t kEcSvc64 = 0x15;
        for (;;) {
            if (exited_) return ok(false);
            auto regs = vm_.run();
            if (!regs) {
                if (regs.error() == Errno::eintr) continue;   // vtimer/cancel
                return err<bool>(regs.error());
            }
            regs_ = *regs;
            if (regs_.ec() != kEcSvc64) return ok(report_fault());
            // aarch64 Linux: nr in x8, args x0..x5.
            f.regs.nr = regs_.nr();
            for (std::size_t i = 0; i < 6; ++i) f.regs.arg[i] = regs_.arg(i);
            f.pc = regs_.elr;
            return ok(true);
        }
    }

    [[nodiscard]] Status resume(std::int64_t ret) {
        vm_.set_result(regs_, ret);
        return ok();
    }

    [[nodiscard]] bool exited() const noexcept { return exited_; }
    [[nodiscard]] int exit_code() const noexcept { return code_; }

    [[nodiscard]] Result<std::int64_t> forward() {
        return complete(service(nullptr, nullptr));
    }

    // On ptrace, forward_sync exists only to observe the real return value at
    // the syscall-exit stop (dup fd mirroring). We always have it immediately.
    template <class F>
    [[nodiscard]] Result<std::int64_t> forward_sync(F&& observe) {
        std::int64_t rc = service(nullptr, nullptr);
        observe(rc);
        return complete(rc);
    }

    // `post` observes the result inside the stopped window (the dispatcher
    // uses it to scrub a stat buffer's owner before the guest can read it).
    // Accepts any invocable OR nullptr, so a caller that doesn't care pays
    // nothing: the branch is resolved at compile time.
    template <class F = std::nullptr_t>
    [[nodiscard]] Result<std::int64_t> redirect(int, const std::string& host_path,
                                                F post = nullptr, int = -1,
                                                const std::string& host_path2 = {}) {
        std::int64_t rc = service(&host_path,
                                  host_path2.empty() ? nullptr : &host_path2);
        if constexpr (std::is_invocable_v<F, std::int64_t>) post(rc);
        return complete(rc);
    }

    [[nodiscard]] const AddressSpace& address_space() const noexcept { return as_; }

private:
    [[nodiscard]] Result<std::int64_t> complete(std::int64_t rc) {
        LX_TRY(resume(rc));
        return ok(rc);
    }

    // A non-SVC exception is a genuine guest fault. On Linux this would be a
    // SIGSEGV/SIGILL delivered to the guest; until signal delivery exists,
    // end the run with the shell's 128+signal convention and say why --
    // resuming would spin forever on the faulting instruction.
    [[nodiscard]] bool report_fault() {
        const char* kind = "exception";
        int sig = 11;                                  // SIGSEGV
        switch (regs_.ec()) {
            case 0x24: case 0x25: kind = "data abort";        break;
            case 0x20: case 0x21: kind = "instruction abort"; break;
            case 0x26: kind = "SP alignment fault";           break;
            case 0x0e: kind = "illegal execution state"; sig = 4; break;
            case 0x00: kind = "undefined instruction";   sig = 4; break;
            default: break;
        }
        const Vma* v = as_.find(regs_.far);
        std::fprintf(stderr,
            "linuxity: guest %s at pc=%#llx addr=%#llx (%s) esr=%#llx\n",
            kind, static_cast<unsigned long long>(regs_.elr),
            static_cast<unsigned long long>(regs_.far),
            v ? "mapped" : "UNMAPPED",
            static_cast<unsigned long long>(regs_.esr));
        exited_ = true;
        code_ = 128 + sig;
        return false;
    }

    // -- The Darwin service routine ---------------------------------------
    // Dispatch is split by CONCERN rather than one long switch: memory, fd
    // I/O, and path operations have different inputs (the VMA map, a guest
    // fd, a translated host path) and different failure modes. Each handler
    // returns std::nullopt when the syscall isn't one of its own, so adding a
    // group never touches the others.
    [[nodiscard]] std::int64_t service(const std::string* path,
                                       const std::string* path2) {
        const auto sc = abi::decode(abi::Arch::aarch64, regs_.nr());
        if (auto r = do_process(sc))        return *r;
        if (auto r = do_memory(sc))         return *r;
        if (auto r = do_io(sc))             return *r;
        if (auto r = do_path(sc, path, path2)) return *r;
        return -38;                                     // ENOSYS, honestly
    }

    using Maybe = std::optional<std::int64_t>;

    [[nodiscard]] Maybe do_process(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1), a2 = regs_.arg(2);
        const GuestRam ram = vm_.ram();
        switch (sc) {
            case S::exit:
            case S::exit_group:
                exited_ = true;
                code_ = static_cast<int>(a0 & 0xff);
                return 0;

            // Thread/signal state libc installs at startup. There is no host
            // task to carry it and nothing reads it back on this backend.
            case S::set_tid_address: case S::rt_sigaction:
            case S::rt_sigprocmask:  case S::sigaltstack:
                return 0;

            // -- getrandom(buf, len, flags). glibc's startup REQUIRES this
            //    for its stack guard and malloc's randomization; an ENOSYS
            //    here aborts the program. Darwin has arc4random_buf, which
            //    is the same cryptographic contract.
            case S::getrandom: {
                auto win = ram.clamp(a0, a1);
                if (win.empty()) return -14;
                ::arc4random_buf(win.data(), win.size());
                return static_cast<std::int64_t>(win.size());
            }

            // -- clock_gettime(clkid, timespec*). Both kernels agree on the
            //    struct (two 64-bit words) and on CLOCK_REALTIME=0 /
            //    MONOTONIC=1, so only the clock id needs mapping.
            case S::clock_gettime: {
                ::clockid_t id = CLOCK_REALTIME;
                switch (a0) {
                    case 1: case 5: id = CLOCK_MONOTONIC;        break;
                    case 2: case 3: id = CLOCK_PROCESS_CPUTIME_ID; break;
                    default:        id = CLOCK_REALTIME;         break;
                }
                struct ::timespec ts{};
                if (::clock_gettime(id, &ts) < 0) return darwin::fail();
                struct LinuxTimespec { std::int64_t sec; std::int64_t nsec; };
                LinuxTimespec out{ts.tv_sec, ts.tv_nsec};
                return ram.put(a1, out) ? 0 : -14;
            }

            // -- prlimit64(pid, res, new*, old*). Report the host's limit
            //    for the one that matters (RLIMIT_STACK/NOFILE drive libc's
            //    buffer sizing); setting is accepted as a no-op.
            case S::prlimit64: {
                if (a2) return 0;                 // a set: accept silently
                struct LinuxRlimit { std::uint64_t cur, max; };
                LinuxRlimit out{~std::uint64_t{0}, ~std::uint64_t{0}};
                if (a1 == 3) {                    // RLIMIT_STACK
                    out.cur = 8ull << 20;
                } else if (a1 == 7) {             // RLIMIT_NOFILE
                    out.cur = out.max = 1024;
                }
                return ram.put(regs_.arg(3), out) ? 0 : -14;
            }

            default:
                return std::nullopt;
        }
    }

    [[nodiscard]] Maybe do_memory(abi::Sysno sc) {
        using S = abi::Sysno;
        const std::uint64_t a0 = regs_.arg(0), a1 = regs_.arg(1),
                            a2 = regs_.arg(2), a3 = regs_.arg(3);
        switch (sc) {
            case S::brk:
                return static_cast<std::int64_t>(as_.set_brk(a0));
            case S::mmap: {
                constexpr std::uint64_t kFixed = 0x10, kAnon = 0x20;
                const bool anon = (a3 & kAnon) != 0;
                const std::uint64_t len = AddressSpace::page_up(a1);
                std::uint64_t at = as_.map(a0, a1, prot_from_linux(a2),
                                           (a3 & kFixed) != 0, anon);
                if (at == AddressSpace::kFail) return -12;          // ENOMEM
                auto win = vm_.ram().at(at, len);
                if (win.empty()) return -12;

                if (anon) {
                    // A fresh anonymous mapping must read as zero -- and for
                    // an ANON map the guest asked for the whole page span, so
                    // clearing to the page-rounded end is correct here.
                    vm_.zero(at, len);
                    return static_cast<std::int64_t>(at);
                }

                // File-backed. Read what the file actually has, then zero the
                // remainder of the mapping.
                //
                // The zeroing is NOT optional, and it is the subtlety that
                // cost the most debugging here. ld.so loads a library in
                // layers: first one big PROT_NONE reservation, then each
                // PT_LOAD MAP_FIXED over it with a length rounded up to the
                // segment's MEMORY size -- which exceeds its FILE size
                // whenever the segment has a .bss tail. Linux satisfies the
                // excess with zero-filled pages; a backend that just preads
                // leaves whatever the previous layer wrote there. For glibc's
                // libc.so.6 that means the text map's bytes stay visible in
                // the data segment's tail, and the guest loads an ELF header
                // where a GOT pointer belongs -- faulting on 0x...464c4587,
                // which is "\x7fELF" read as an address.
                //
                // Note `a1` (the requested length), not `len` (page-rounded):
                // segments SHARE pages. libc's data segment starts at vaddr
                // 0x1bd090, 0x90 bytes into a page the text segment already
                // covers, so rounding up here would wipe a neighbour.
                const int ffd = static_cast<int>(regs_.arg(4));
                const auto foff = static_cast<off_t>(regs_.arg(5));
                auto n = ::pread(ffd, win.data(), a1, foff);
                if (n < 0) return darwin::fail();
                const auto got = static_cast<std::uint64_t>(n);
                if (got < a1) {
                    auto tail = vm_.ram().at(at + got, a1 - got);
                    if (!tail.empty()) std::memset(tail.data(), 0, tail.size());
                }
                // The mapping may be an executable segment written through the
                // host's data view; publish it to the instruction stream.
                if (has(prot_from_linux(a2), GuestProt::exec))
                    vm_.publish_code(at, len);
                return static_cast<std::int64_t>(at);
            }
            case S::munmap:
                as_.unmap(a0, a1);
                return 0;
            case S::mprotect:
                // Tracked in the VMA map but NOT enforced in the page tables:
                // the stage-1 tables are built RWX once, and per-page
                // reprotection would need a table walk plus TLB maintenance
                // on every call. Recorded so /proc/self/maps is truthful and
                // so enforcement can be added without an ABI change.
                return as_.protect(a0, a1, prot_from_linux(a2)) ? 0 : -12;
            default:
                return std::nullopt;
        }
    }

    [[nodiscard]] Maybe do_io(abi::Sysno sc) {
        using S = abi::Sysno;
        const auto fd = static_cast<int>(regs_.arg(0));
        const std::uint64_t a1 = regs_.arg(1), a2 = regs_.arg(2), a3 = regs_.arg(3);
        const GuestRam ram = vm_.ram();
        switch (sc) {
            case S::read: {
                auto win = ram.clamp(a1, a2);
                if (win.empty()) return -14;                        // EFAULT
                auto n = ::read(fd, win.data(), win.size());
                return n < 0 ? darwin::fail() : n;
            }
            case S::write: {
                auto win = ram.clamp(a1, a2);
                if (win.empty()) return -14;
                auto n = ::write(fd, win.data(), win.size());
                return n < 0 ? darwin::fail() : n;
            }
            case S::pread64: {
                auto win = ram.clamp(a1, a2);
                if (win.empty()) return -14;
                auto n = ::pread(fd, win.data(), win.size(), static_cast<off_t>(a3));
                return n < 0 ? darwin::fail() : n;
            }
            case S::pwrite64: {
                auto win = ram.clamp(a1, a2);
                if (win.empty()) return -14;
                auto n = ::pwrite(fd, win.data(), win.size(), static_cast<off_t>(a3));
                return n < 0 ? darwin::fail() : n;
            }
            case S::readv: case S::writev:
                return do_vector(sc == S::writev, fd, a1, a2);
            case S::lseek: {
                auto off = ::lseek(fd, static_cast<off_t>(a1), static_cast<int>(a2));
                return off < 0 ? darwin::fail() : off;
            }
            case S::close:
                return ::close(fd) < 0 ? darwin::fail() : 0;
            case S::fstat: {
                struct ::stat st{};
                if (::fstat(fd, &st) < 0) return darwin::fail();
                return ram.put(a1, darwin::to_linux(st)) ? 0 : -14;
            }
            case S::ftruncate:
                return ::ftruncate(fd, static_cast<off_t>(a1)) < 0
                           ? darwin::fail() : 0;
            default:
                return std::nullopt;
        }
    }

    // readv/writev: one Darwin call per entry. Building a host iovec array
    // would need every guest base translated and bounds-checked anyway, and
    // real vectors are short (musl's stdio uses two).
    [[nodiscard]] std::int64_t do_vector(bool writing, int fd,
                                         std::uint64_t vec, std::uint64_t cnt) {
        const GuestRam ram = vm_.ram();
        std::int64_t total = 0;
        constexpr std::uint64_t kIovMax = 1024;
        for (std::uint64_t i = 0; i < std::min(cnt, kIovMax); ++i) {
            GuestIovec iov{};
            if (!ram.get(vec + i * sizeof(GuestIovec), iov)) return total ? total : -14;
            if (iov.len == 0) continue;
            auto win = ram.clamp(iov.base, iov.len);
            if (win.empty()) return total ? total : -14;
            auto n = writing ? ::write(fd, win.data(), win.size())
                             : ::read(fd, win.data(), win.size());
            if (n < 0) return total ? total : darwin::fail();
            total += n;
            if (static_cast<std::uint64_t>(n) < win.size()) break;  // short
        }
        return total;
    }

    [[nodiscard]] Maybe do_path(abi::Sysno sc, const std::string* path,
                                const std::string* path2) {
        using S = abi::Sysno;
        const GuestRam ram = vm_.ram();
        const std::uint64_t a2 = regs_.arg(2), a3 = regs_.arg(3);
        switch (sc) {
            case S::open: case S::openat: {
                if (!path) return -2;                               // ENOENT
                const bool at = sc == S::openat;
                const std::uint64_t lflags = at ? a2 : regs_.arg(1);
                const std::uint64_t lmode  = at ? a3 : a2;
                int fd = ::open(path->c_str(), darwin::open_flags(lflags),
                                static_cast<mode_t>(lmode));
                return fd < 0 ? darwin::fail() : fd;
            }
            case S::newfstatat: {
                if (!path) return -2;
                constexpr std::uint64_t kNoFollow = 0x100;   // AT_SYMLINK_NOFOLLOW
                struct ::stat st{};
                int rc = (a3 & kNoFollow) ? ::lstat(path->c_str(), &st)
                                          : ::stat(path->c_str(), &st);
                if (rc < 0) return darwin::fail();
                return ram.put(a2, darwin::to_linux(st)) ? 0 : -14;
            }
            case S::faccessat: case S::faccessat2:
                if (!path) return -2;
                return ::access(path->c_str(), static_cast<int>(a2)) < 0
                           ? darwin::fail() : 0;
            case S::readlinkat: {
                if (!path) return -2;
                auto win = ram.clamp(a2, a3);
                if (win.empty()) return -14;
                auto n = ::readlink(path->c_str(),
                                    reinterpret_cast<char*>(win.data()), win.size());
                return n < 0 ? darwin::fail() : n;
            }
            case S::mkdirat:
                if (!path) return -2;
                return ::mkdir(path->c_str(), static_cast<mode_t>(a2)) < 0
                           ? darwin::fail() : 0;
            case S::unlinkat: {
                if (!path) return -2;
                constexpr std::uint64_t kRemoveDir = 0x200;        // AT_REMOVEDIR
                int rc = (a2 & kRemoveDir) ? ::rmdir(path->c_str())
                                           : ::unlink(path->c_str());
                return rc < 0 ? darwin::fail() : 0;
            }
            case S::renameat: case S::renameat2:
                if (!path || !path2) return -2;
                return ::rename(path->c_str(), path2->c_str()) < 0
                           ? darwin::fail() : 0;
            case S::linkat:
                if (!path || !path2) return -2;
                return ::link(path->c_str(), path2->c_str()) < 0
                           ? darwin::fail() : 0;
            case S::symlinkat:
                // The link TEXT is guest data, not a host path: only the
                // destination is translated.
                if (!path2) return -2;
                return ::symlink(ram.cstr(regs_.arg(0)).c_str(), path2->c_str()) < 0
                           ? darwin::fail() : 0;
            case S::fchmodat:
                if (!path) return -2;
                return ::chmod(path->c_str(), static_cast<mode_t>(a2)) < 0
                           ? darwin::fail() : 0;
            case S::truncate:
                if (!path) return -2;
                return ::truncate(path->c_str(), static_cast<off_t>(regs_.arg(1))) < 0
                           ? darwin::fail() : 0;
            default:
                return std::nullopt;
        }
    }

    HvfVm& vm_;
    AddressSpace as_;
    GuestRegs regs_{};
    bool exited_{false};
    int code_{0};
};

// -- Guest memory accessor (abi::GuestMem) --------------------------------
// The payoff of hv_vm_map sharing pages: copy_in/copy_out are a bounds-checked
// memcpy against live guest RAM. The ptrace backend needs process_vm_readv
// into another process, with a PTRACE_PEEKDATA word-at-a-time fallback when a
// buffer straddles an unmapped page -- and a TOCTOU window besides.
class HvfMem {
public:
    explicit HvfMem(const HvfVm& vm) noexcept : vm_{vm} {}

    [[nodiscard]] Status copy_in(UAddr src, std::span<std::byte> dst) const {
        auto win = vm_.ram().at(value(src), dst.size());
        if (win.empty() && !dst.empty()) return err(Errno::efault);
        std::memcpy(dst.data(), win.data(), dst.size());
        return ok();
    }

    [[nodiscard]] Status copy_out(UAddr dst, std::span<const std::byte> src) const {
        auto win = vm_.ram().at(value(dst), src.size());
        if (win.empty() && !src.empty()) return err(Errno::efault);
        std::memcpy(win.data(), src.data(), src.size());
        return ok();
    }

private:
    const HvfVm& vm_;
};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
