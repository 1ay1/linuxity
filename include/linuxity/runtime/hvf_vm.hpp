// linuxity/runtime/hvf_vm.hpp
//
// The kernel-less virtual machine: guest physical memory, page tables, the
// EL1 vector stub and the vCPU. No syscall knowledge lives here -- this is
// the "CPU + RAM" that the trap backend (hvf_trap.hpp) and the program
// loader (hvf_load.hpp) both build on, which is why it is its own header:
// exec needs the loader, the trap needs exec, and both need the VM.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/abi/result.hpp"
#include "linuxity/runtime/hvf_mem.hpp"
#include "linuxity/runtime/hvf_regs.hpp"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>

namespace lx::runtime {

// -- Guest physical memory layout -----------------------------------------
// One contiguous IPA region. The bottom is hypervisor-private (exception
// vectors + page tables), mapped EL1-only so guest code can neither read nor
// write it. Everything from priv_end up belongs to the guest.
//
//   0x0000_0000  vectors        (VBAR_EL1, 2 KiB used)
//   0x0000_1000  L1 table       (one page: covers 512 GiB, i.e. all of it)
//   0x0000_2000  L2 tables      (one page per GiB of guest RAM)
//   ...          L3 tables      (one page per 2 MiB of guest RAM)
//   priv_end     first guest page
//
// The table area is SIZED from the RAM size rather than fixed: at 4 KiB
// granule, mapping N bytes needs N/2MiB L3 pages plus N/1GiB L2 pages. A
// fixed layout silently breaks at 1 GiB -- the L2 index wraps and the top
// gigabyte (where the stack lives) aliases the bottom, while the L3 tables
// grow over the vectors -- and the guest's first svc then jumps into garbage
// and spins forever. Computing it makes that impossible.
struct HvfLayout {
    static constexpr std::uint64_t page       = 0x1000;
    static constexpr std::uint64_t vectors    = 0x0000;   // VBAR_EL1 (2 KiB-aligned)
    static constexpr std::uint64_t l1_table   = 0x1000;
    static constexpr std::uint64_t l2_tables  = 0x2000;
    static constexpr std::uint64_t gib        = 1ull << 30;
    static constexpr std::uint64_t block      = 1ull << 21;   // 2 MiB per L3 table

    [[nodiscard]] static constexpr std::uint64_t n_l2(std::uint64_t ram) noexcept {
        return (ram + gib - 1) / gib;
    }
    [[nodiscard]] static constexpr std::uint64_t l3_tables(std::uint64_t ram) noexcept {
        return l2_tables + n_l2(ram) * page;
    }
    // First guest-owned address: past the tables, rounded to a 2 MiB block so
    // the private area is whole L3 tables (no shared page between EL1-only
    // and EL0 mappings).
    [[nodiscard]] static constexpr std::uint64_t priv_end(std::uint64_t ram) noexcept {
        const std::uint64_t end = l3_tables(ram) + (ram / block) * page;
        return (end + block - 1) & ~(block - 1);
    }

    // The stack sits at the TOP of guest RAM (VA == GPA, so there is no
    // translation above mem_size); a guest only ever reads sp, so it can't
    // tell this from Linux's 0x7fff_ffff_f000.
    static constexpr std::uint64_t stack_guard = 0x10000;
};

// The guest address-space plan above the private area: the stack at the top
// of RAM with room to grow (Linux's default RLIMIT_STACK, which is what
// prlimit64 reports), and the mmap arena everything below that.
struct ExecArena {
    static constexpr std::uint64_t stack_reserve = 8ull << 20;
    [[nodiscard]] static constexpr std::uint64_t mmap_top(std::uint64_t mem_size) noexcept {
        return mem_size - HvfLayout::stack_guard - stack_reserve - (1ull << 20);
    }
};

// The EL1 exception vector stub. ARM requires 16 entries of 0x80 bytes each;
// every one does the same thing: `hvc #<index>` so the hypervisor (us) sees
// which vector fired. We always resume the guest by writing PC/CPSR
// ourselves, so the stub never returns.
inline void write_vector_stub(std::uint8_t* mem) {
    for (int v = 0; v < 16; ++v) {
        std::uint32_t hvc = 0xD4000002u | (static_cast<std::uint32_t>(v) << 5);
        std::memcpy(mem + HvfLayout::vectors + static_cast<std::size_t>(v) * 0x80,
                    &hvc, 4);
    }
}

// Build a 3-level, 4 KiB-granule identity map of [0, ram). The private area
// below priv_end is EL1-only (AP=0b00); the rest is EL0 read/write/execute
// (AP=0b01). Not setting UXN per region is deliberate: mprotect is tracked
// in the VMA map, and a JIT in the guest needs to make pages executable.
inline void build_page_tables(std::uint8_t* mem, std::uint64_t ram) {
    auto put64 = [mem](std::uint64_t at, std::uint64_t v) {
        std::memcpy(mem + at, &v, 8);
    };
    constexpr std::uint64_t kTable = 3, kPage = 3;
    constexpr std::uint64_t kAf = 1ull << 10, kSh = 3ull << 8;
    const std::uint64_t priv = HvfLayout::priv_end(ram);

    // L1: one entry per GiB -> that GiB's L2 table.
    for (std::uint64_t g = 0; g < HvfLayout::n_l2(ram); ++g)
        put64(HvfLayout::l1_table + g * 8,
              (HvfLayout::l2_tables + g * HvfLayout::page) | kTable);

    // L2 -> L3 -> pages.
    std::uint64_t l3 = HvfLayout::l3_tables(ram);
    for (std::uint64_t base = 0; base < ram; base += HvfLayout::block) {
        const std::uint64_t g   = base / HvfLayout::gib;
        const std::uint64_t l2i = (base >> 21) & 0x1ff;
        put64(HvfLayout::l2_tables + g * HvfLayout::page + l2i * 8, l3 | kTable);
        for (std::uint64_t off = 0; off < HvfLayout::block; off += HvfLayout::page) {
            const std::uint64_t pa = base + off;
            const std::uint64_t ap = pa < priv ? 0ull : 1ull;
            put64(l3 + (off >> 12) * 8, pa | kAf | kSh | (ap << 6) | kPage);
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

    // Fork child: adopt a parent's copy-on-write RAM snapshot (already
    // mapped, see hvf_fork.hpp) as this VM's guest memory, and bring the VM
    // up in this FRESH process -- one whose Hypervisor.framework has never
    // run, so there is no inherited helper-thread state to trip over.
    [[nodiscard]] Status init_from(void* ram, std::uint64_t size) {
        base_ = static_cast<std::byte*>(ram);
        size_ = size;
        return attach();
    }
    [[nodiscard]] std::byte* raw_base() const noexcept { return base_; }

    // -- Memory -----------------------------------------------------------
    [[nodiscard]] GuestRam ram() const noexcept {
        return GuestRam{base_, size_, HvfLayout::priv_end(size_)};
    }
    [[nodiscard]] std::uint64_t mem_size() const noexcept { return size_; }

    // Clear a guest range, touching NO byte outside [gpa, gpa+n).
    //
    // Two hardware facts make this subtle on Apple Silicon:
    //
    //  * mmap(MAP_FIXED) over guest RAM is forbidden: it replaces the host
    //    pages while the guest's IPA translation still points at the OLD
    //    ones, so the guest keeps reading stale data (verified, macOS 27).
    //  * madvise(MADV_ZERO) works at HOST page granularity, which is 16 KiB,
    //    while the guest uses 4 KiB pages. A 4 KiB MADV_ZERO silently zeroes
    //    the whole surrounding 16 KiB host page (verified: zeroing
    //    [0x6000,0x7000) also wiped 0x4000..0x8000). That destroyed up to
    //    12 KiB of neighbouring guest memory on every anonymous mmap and
    //    .bss clear -- e.g. libc data a moment before relocation, which made
    //    RELR relocation produce libc_base instead of libc_base+offset and
    //    the guest load its own ELF header as a pointer ("\x7fELF" faults).
    //
    // So: MADV_ZERO only the 16 KiB-aligned interior (cheap, no page touch),
    // and memset the unaligned head and tail.
    void zero(std::uint64_t gpa, std::size_t n) noexcept {
        auto win = ram().at(gpa, n);
        if (win.empty()) return;
        static const std::uint64_t kHostPage =
            static_cast<std::uint64_t>(::getpagesize());
        const auto base = reinterpret_cast<std::uintptr_t>(win.data());
        const std::uintptr_t lo = (base + kHostPage - 1) & ~(kHostPage - 1);
        const std::uintptr_t hi = (base + n) & ~(kHostPage - 1);
#if defined(MADV_ZERO)
        if (hi > lo &&
            ::madvise(reinterpret_cast<void*>(lo), hi - lo, MADV_ZERO) == 0) {
            std::memset(win.data(), 0, lo - base);                  // head
            std::memset(reinterpret_cast<void*>(hi), 0, base + n - hi); // tail
            return;
        }
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

    // The COMPLETE user-visible CPU state. Destroying a vCPU discards every
    // register, and a guest fork must resume BOTH sides bit-exactly -- so this
    // includes the FP/SIMD file (q0..q31, FPCR, FPSR), which glibc's memcpy
    // and every compiler-vectorized loop keep live across a syscall. Saving
    // only the GPRs (the obvious version) corrupts the parent's floating
    // point state on every fork.
    struct CpuState {
        std::uint64_t x[31]{};
        std::uint64_t pc{}, cpsr{}, sp_el0{}, tpidr_el0{}, tpidrro_el0{};
        std::uint64_t fpcr{}, fpsr{};
        hv_simd_fp_uchar16_t q[32]{};
    };
    [[nodiscard]] CpuState save() const noexcept {
        CpuState s;
        for (int i = 0; i < 31; ++i)
            ::hv_vcpu_get_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + i), &s.x[i]);
        ::hv_vcpu_get_reg(cpu_, HV_REG_PC, &s.pc);
        ::hv_vcpu_get_reg(cpu_, HV_REG_CPSR, &s.cpsr);
        ::hv_vcpu_get_reg(cpu_, HV_REG_FPCR, &s.fpcr);
        ::hv_vcpu_get_reg(cpu_, HV_REG_FPSR, &s.fpsr);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_SP_EL0, &s.sp_el0);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, &s.tpidr_el0);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_TPIDRRO_EL0, &s.tpidrro_el0);
        for (int i = 0; i < 32; ++i)
            ::hv_vcpu_get_simd_fp_reg(cpu_, static_cast<hv_simd_fp_reg_t>(HV_SIMD_FP_REG_Q0 + i), &s.q[i]);
        return s;
    }
    void load(const CpuState& s) noexcept {
        for (int i = 0; i < 31; ++i)
            ::hv_vcpu_set_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + i), s.x[i]);
        ::hv_vcpu_set_reg(cpu_, HV_REG_PC, s.pc);
        ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, s.cpsr);
        ::hv_vcpu_set_reg(cpu_, HV_REG_FPCR, s.fpcr);
        ::hv_vcpu_set_reg(cpu_, HV_REG_FPSR, s.fpsr);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, s.sp_el0);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, s.tpidr_el0);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDRRO_EL0, s.tpidrro_el0);
        for (int i = 0; i < 32; ++i)
            ::hv_vcpu_set_simd_fp_reg(cpu_, static_cast<hv_simd_fp_reg_t>(HV_SIMD_FP_REG_Q0 + i), s.q[i]);
    }

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
    void set_sp(std::uint64_t v) noexcept {
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, v);
    }
    void set_x(int i, std::uint64_t v) noexcept {
        ::hv_vcpu_set_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + i), v);
    }
    [[nodiscard]] hv_vcpu_t vcpu() const noexcept { return cpu_; }

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

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
