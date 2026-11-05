// linuxity/runtime/hvf_vm.hpp
//
// The kernel-less virtual machine: guest physical memory, page tables, the
// EL1 vector stub, and vCPUs.
//
// The split here is the one Hypervisor.framework forces and that SMP needs:
//
//   HvfMachine -- guest RAM + the address translation that makes it a Linux
//                 userspace address space. Exactly one per process (the
//                 framework allows one hv_vm), shared by every vCPU.
//   HvfCpu     -- one vCPU: its register file and its run loop. Created ON
//                 and used ONLY FROM its own host thread; the framework ties
//                 a vcpu to the thread that created it, so a guest thread IS
//                 a host thread, scheduled by XNU across the real cores.
//
// No syscall knowledge lives here. This is the "CPU + RAM" layer that the
// trap backend (hvf_trap.hpp) and the loader (hvf_load.hpp) build on.
#pragma once

#if defined(__APPLE__) && defined(__aarch64__)

#include "linuxity/abi/result.hpp"
#include "linuxity/runtime/hvf_fastcall.hpp"
#include "linuxity/runtime/hvf_mem.hpp"
#include "linuxity/runtime/hvf_regs.hpp"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

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
    // 512 syscall numbers x {value, live}, plus the handler's scratch.
    static constexpr std::uint64_t fastcall_bytes = 512 * 16 + 64;
    // The in-guest syscall table (hvf_fastcall.hpp). It sits right after the
    // L2 tables, inside the EL1-only private area, so a guest can neither
    // read it nor forge an entry.
    [[nodiscard]] static constexpr std::uint64_t fastcall(std::uint64_t ram) noexcept {
        return l2_tables + n_l2(ram) * page;
    }
    static constexpr std::uint64_t l1_table   = 0x1000;
    static constexpr std::uint64_t l2_tables  = 0x2000;
    static constexpr std::uint64_t gib        = 1ull << 30;
    static constexpr std::uint64_t block      = 1ull << 21;   // 2 MiB per L3 table

    [[nodiscard]] static constexpr std::uint64_t n_l2(std::uint64_t ram) noexcept {
        return (ram + gib - 1) / gib;
    }
    // The classic NON-PIE (ET_EXEC) load address. An ET_EXEC program's
    // p_vaddr is absolute -- it cannot be relocated -- and the aarch64
    // toolchain default is 0x400000. gcc and anything built -no-pie land
    // there, so the EL1-only private area must stay clear of it.
    static constexpr std::uint64_t nonpie_base = 0x40'0000;      // 4 MiB
    // Room for a large fixed-address image (text+data+bss) above that.
    // Up to 128 MiB: big toolchain binaries are non-PIE too (cc1plus is a
    // 42 MiB fixed image at 0x400000), and 28 MiB was not enough.
    static constexpr std::uint64_t nonpie_size = 0x7c0'0000;      // 124 MiB

    // The L3 array (one page per 2 MiB of RAM) starts ABOVE the reserved
    // non-PIE window rather than immediately after the L2 pages. Putting it
    // low made priv_end ~0x600000 at 2 GiB, which covered 0x400000: loading
    // gcc then failed ENOMEM (ram().at() refuses the private span) -- the
    // package installed fine and every `gcc` exec died with errno 12.
    //
    // It must stay a single ascending run, because build_page_tables()
    // assigns these pages sequentially as it walks RAM from 0 upward.
    //
    // The floor only applies when RAM can afford it. A tiny VM (the 2 MiB
    // capability probe) has no room to reserve 32 MiB, and forcing it there
    // put priv_end past the end of RAM -- the program base then pointed
    // outside memory and the loader walked off the mapping.
    [[nodiscard]] static constexpr std::uint64_t l3_tables(std::uint64_t ram) noexcept {
        const std::uint64_t after_l2 = l2_tables + n_l2(ram) * page
                                     + fastcall_bytes;
        const std::uint64_t floor    = nonpie_base + nonpie_size;
        // Need the window itself plus the table array plus a block to spare.
        // Below 1 GiB keep the compact layout (tests, probes): reserving a
        // 128 MiB hole there would squeeze the PIE/interp/mmap arena.
        if (ram < gib || ram < floor + (ram / block) * page + block) return after_l2;
        return after_l2 > floor ? after_l2 : floor;
    }
    // First guest-owned address: past the tables, rounded to a 2 MiB block so
    // the private area is whole L3 tables (no shared page between EL1-only
    // and EL0 mappings).
    [[nodiscard]] static constexpr std::uint64_t priv_end(std::uint64_t ram) noexcept {
        const std::uint64_t end = l3_tables(ram) + (ram / block) * page;
        return (end + block - 1) & ~(block - 1);
    }

    // The guest-owned hole below the table array that a fixed-address
    // ET_EXEC image loads into. Empty unless the floor actually applied
    // (see l3_tables): on a tiny VM there is no reserved window.
    [[nodiscard]] static constexpr bool has_nonpie_window(std::uint64_t ram) noexcept {
        return l3_tables(ram) >= nonpie_base + nonpie_size;
    }
    // The EL1-only table range that sits ABOVE the window, i.e. inside what
    // a non-PIE program's brk/mmap arena would otherwise cover. Callers
    // reserve it in the VMA map so the heap can never grow into it.
    [[nodiscard]] static constexpr std::uint64_t tables_lo(std::uint64_t ram) noexcept {
        return has_nonpie_window(ram) ? nonpie_base + nonpie_size : priv_end(ram);
    }
    [[nodiscard]] static constexpr bool is_nonpie_window(std::uint64_t a) noexcept {
        return a >= nonpie_base && a < nonpie_base + nonpie_size;
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
//
// Vector 8 (lower EL, AArch64, synchronous -- i.e. every guest syscall) is
// the exception: it gets the fast-path handler, which answers the pure
// syscalls in-guest and falls through to the same `hvc #8` for the rest.
inline void write_vector_stub(std::byte* mem, std::uint64_t ram) {
    for (int v = 0; v < 16; ++v) {
        const std::uint32_t hvc = 0xD4000002u | (static_cast<std::uint32_t>(v) << 5);
        std::memcpy(mem + HvfLayout::vectors + static_cast<std::size_t>(v) * 0x80,
                    &hvc, 4);
    }
    auto* v8 = reinterpret_cast<std::uint32_t*>(mem + HvfLayout::vectors + 8 * 0x80);
    const std::uint64_t tbl = HvfLayout::fastcall(ram);
    (void)fastcall::emit_handler(v8, tbl);
    std::memset(mem + tbl, 0, HvfLayout::fastcall_bytes);
}

// Build a 3-level, 4 KiB-granule identity map of [0, ram). The private area
// below priv_end is EL1-only (AP=0b00); the rest is EL0 read/write/execute
// (AP=0b01). Not setting UXN per region is deliberate: mprotect is tracked
// in the VMA map, and a JIT in the guest needs to make pages executable.
inline void build_page_tables(std::byte* mem, std::uint64_t ram) {
    auto put64 = [mem](std::uint64_t at, std::uint64_t v) {
        std::memcpy(mem + at, &v, 8);
    };
    constexpr std::uint64_t kTable = 3, kPage = 3;
    constexpr std::uint64_t kAf = 1ull << 10, kSh = 3ull << 8;
    const std::uint64_t priv = HvfLayout::priv_end(ram);
    const bool nonpie_win    = HvfLayout::has_nonpie_window(ram);

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
            // EL1-only below priv_end, EXCEPT the non-PIE window: that hole
            // sits below the table array but belongs to the guest, so a
            // fixed-address ET_EXEC image can both load and execute there.
            const std::uint64_t ap =
                (pa < priv && !(nonpie_win && HvfLayout::is_nonpie_window(pa)))
                    ? 0ull : 1ull;
            put64(l3 + (off >> 12) * 8, pa | kAf | kSh | (ap << 6) | kPage);
        }
        l3 += HvfLayout::page;
    }
}

// -- The machine: guest RAM shared by every vCPU ---------------------------
//
// Non-copyable and non-movable: hv_vm is a process-global resource and vCPUs
// hold a reference to this object, so its address is part of its identity.
class HvfMachine {
public:
    HvfMachine() = default;
    HvfMachine(const HvfMachine&) = delete;
    HvfMachine& operator=(const HvfMachine&) = delete;
    HvfMachine(HvfMachine&&) = delete;
    HvfMachine& operator=(HvfMachine&&) = delete;
    ~HvfMachine() {
        if (vm_live_) ::hv_vm_destroy();
        if (owns_ram_ && base_) ::munmap(base_, size_);
    }

    [[nodiscard]] Status init(std::uint64_t mem_size) {
        constexpr std::uint64_t kBlock = HvfLayout::block;
        size_ = (mem_size + kBlock - 1) & ~(kBlock - 1);
        if (size_ > (1ull << 36)) return err(Errno::einval);   // 36-bit IPA
        // Guest RAM lives in an anonymous SHARED mapping, not MAP_PRIVATE.
        // Two things need that:
        //   * futex. os_sync_wait_on_address's SHARED flags require memory
        //     that is genuinely shared, which is what a Linux process-shared
        //     futex (a pthread mutex in shared memory, and every futex in a
        //     multi-process guest) means.
        //   * threads. A guest thread is a host thread in THIS process, so
        //     it already shares the mapping -- but keeping one representation
        //     for both cases means fork and threads can't disagree.
        // A forked child still gets copy-on-write semantics: the Mach memory
        // entry it receives is a COW snapshot (see hvf_fork.hpp), so sharing
        // here does not leak writes across a guest fork.
        int fd = -1;
        char tmpl[] = "/tmp/linuxity-ram-XXXXXX";
        fd = ::mkstemp(tmpl);
        if (fd < 0) return err(Errno::enomem);
        ::unlink(tmpl);
        if (::ftruncate(fd, static_cast<off_t>(size_)) != 0) { ::close(fd); return err(Errno::enomem); }
        void* p = ::mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        ::close(fd);
        if (p == MAP_FAILED) return err(Errno::enomem);
        base_ = static_cast<std::byte*>(p);
        owns_ram_ = true;
        return attach();
    }

    // Fork child: adopt the parent's copy-on-write RAM snapshot (already
    // mapped, see hvf_fork.hpp) as this machine's guest memory, in a FRESH
    // process whose Hypervisor.framework has never run.
    // Create the VM with NO memory yet. A zygote does this while parked, so
    // the hv_vm_create (and the vCPU it then makes) are off the fork's
    // critical path; init_from() later just maps the snapshot in.
    [[nodiscard]] Status prewarm() {
        if (vm_live_) return ok();
        if (::hv_vm_create(nullptr) != HV_SUCCESS) return err(Errno::enodev);
        vm_live_ = true;
        return ok();
    }

    [[nodiscard]] Status init_from(void* ram, std::uint64_t size) {
        base_ = static_cast<std::byte*>(ram);
        size_ = size;
        owns_ram_ = false;          // the Mach entry mapping owns it
        // The snapshot is the PARENT's RAM, page tables and vectors included:
        // the same layout (same size) builds byte-identical tables. Rewriting
        // them here touched every L3 page (4 MiB for 2 GiB), forcing a COW
        // copy of each -- 0.8 ms of every fork for no change. Skip it.
        return attach(/*build_tables=*/false);
    }

    // -- Memory -----------------------------------------------------------
    [[nodiscard]] GuestRam ram() const noexcept {
        const bool win = HvfLayout::has_nonpie_window(size_);
        return GuestRam{base_, size_, HvfLayout::priv_end(size_),
                        win ? HvfLayout::nonpie_base : 0,
                        win ? HvfLayout::nonpie_base + HvfLayout::nonpie_size : 0};
    }
    // Let a syscall be answered IN-GUEST with a constant (see
    // hvf_fastcall.hpp): no VM exit, ~32 ns instead of ~930.
    void set_fastcall(int nr, std::uint64_t value) noexcept {
        if (nr < 0 || static_cast<std::size_t>(nr) >= fastcall::kMaxNr || !base_) return;
        auto* t = reinterpret_cast<fastcall::Entry*>(base_ + HvfLayout::fastcall(size_));
        t[nr].value = value;
        std::atomic_thread_fence(std::memory_order_release);
        t[nr].live = 1;
    }
    void clear_fastcall(int nr) noexcept {
        if (nr < 0 || static_cast<std::size_t>(nr) >= fastcall::kMaxNr || !base_) return;
        reinterpret_cast<fastcall::Entry*>(base_ + HvfLayout::fastcall(size_))[nr].live = 0;
    }
    void clear_all_fastcalls() noexcept {
        if (base_) std::memset(base_ + HvfLayout::fastcall(size_), 0, HvfLayout::fastcall_bytes);
    }
    // The handler's private scratch (the live signal mask).
    [[nodiscard]] fastcall::Scratch* fastcall_scratch() const noexcept {
        if (!base_) return nullptr;
        return reinterpret_cast<fastcall::Scratch*>(
            base_ + HvfLayout::fastcall(size_) + fastcall::kScratchOff);
    }
    // Let rt_sigprocmask run in-guest against that scratch word.
    void enable_sigprocmask_fastcall(int nr) noexcept {
        if (nr < 0 || static_cast<std::size_t>(nr) >= fastcall::kMaxNr || !base_) return;
        auto* t = reinterpret_cast<fastcall::Entry*>(base_ + HvfLayout::fastcall(size_));
        t[nr].value = HvfLayout::fastcall(size_) + fastcall::kScratchOff;
        std::atomic_thread_fence(std::memory_order_release);
        t[nr].live = fastcall::kSigprocmask;
    }

    [[nodiscard]] std::uint64_t mem_size() const noexcept { return size_; }
    [[nodiscard]] std::byte* raw_base() const noexcept { return base_; }

    // Zero one host-page-aligned run: MADV_ZERO where allowed (plain anon
    // RAM), mach_vm_write from a zero region on a COW snapshot (where
    // MADV_ZERO is ENOTSUP), memset as a last resort.
    static void zero_run(std::uintptr_t at, std::size_t n) noexcept {
#if defined(MADV_ZERO)
        if (::madvise(reinterpret_cast<void*>(at), n, MADV_ZERO) == 0) return;
#endif
        static constexpr std::size_t kSrc = 16u << 20;
        static void* const src = [] {
            void* z = ::mmap(nullptr, kSrc, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
            return z == MAP_FAILED ? nullptr : z;
        }();
        if (src && n >= (1u << 20)) {
            bool ok = true;
            for (std::size_t off = 0; ok && off < n; off += kSrc)
                ok = ::mach_vm_write(::mach_task_self(), at + off,
                                     reinterpret_cast<vm_offset_t>(src),
                                     static_cast<mach_msg_type_number_t>(std::min(kSrc, n - off)))
                     == KERN_SUCCESS;
            if (ok) return;
        }
        std::memset(reinterpret_cast<void*>(at), 0, n);
    }

    // Clear a guest range, touching NO byte outside [gpa, gpa+n).
    //
    // Two hardware facts make this subtle on Apple Silicon:
    //
    //  * mmap(MAP_FIXED) over guest RAM is forbidden: it replaces the host
    //    pages while the guest's IPA translation still points at the OLD
    //    ones, so the guest keeps reading stale data (verified, macOS 27).
    //  * madvise(MADV_ZERO) works at HOST page granularity -- 16 KiB on
    //    Apple Silicon -- while the guest uses 4 KiB pages. A 4 KiB
    //    MADV_ZERO silently zeroes the surrounding 16 KiB host page
    //    (verified: zeroing [0x6000,0x7000) also wiped 0x4000..0x8000),
    //    destroying up to 12 KiB of neighbouring guest memory on every
    //    anonymous mmap and .bss clear. That corrupted libc's data a moment
    //    before relocation, so RELR produced libc_base instead of
    //    libc_base+offset and the guest loaded its own ELF header as a
    //    pointer ("\x7fELF" faults).
    //
    // So: MADV_ZERO only the host-page-aligned interior (cheap, no page
    // touched), and memset the unaligned head and tail.
    void zero(std::uint64_t gpa, std::size_t n) noexcept {
        static constexpr std::size_t kZeroSrc = 16u << 20;   // one zero region, reused
        auto win = ram().at(gpa, n);
        if (win.empty()) return;
        static const std::uintptr_t host_page =
            static_cast<std::uintptr_t>(::getpagesize());
        const auto base = reinterpret_cast<std::uintptr_t>(win.data());
        const std::uintptr_t lo = (base + host_page - 1) & ~(host_page - 1);
        const std::uintptr_t hi = (base + win.size()) & ~(host_page - 1);
        // Skip pages that were never touched. Most of an exec'ing process's
        // VMAs are mostly untouched (an 8 MiB stack with a few dirty pages,
        // library .bss), and a page with no physical backing already reads
        // as zero. mincore (~0.02 us/page) finds the ones that exist; only
        // those runs are zeroed. On a fork child's COW snapshot this avoids
        // copying the untouched pages just to clear them: 2.5 ms of every
        // exec, measured. A failing mincore falls through to the old path.
        if (hi > lo) {
            const std::size_t npages = (hi - lo) / host_page;
            std::vector<char> vec(npages);
            if (::mincore(reinterpret_cast<void*>(lo), hi - lo, vec.data()) == 0) {
                constexpr char kHas = MINCORE_INCORE | MINCORE_PAGED_OUT;
                for (std::size_t i = 0; i < npages;) {
                    if (!(vec[i] & kHas)) { ++i; continue; }
                    std::size_t j = i;
                    while (j < npages && (vec[j] & kHas)) ++j;
                    zero_run(lo + i * host_page, (j - i) * host_page);
                    i = j;
                }
                if (lo > base) std::memset(win.data(), 0, lo - base);
                if (base + win.size() > hi)
                    std::memset(reinterpret_cast<void*>(hi), 0, base + win.size() - hi);
                return;
            }
        }
#if defined(MADV_ZERO)
        if (hi > lo &&
            ::madvise(reinterpret_cast<void*>(lo), hi - lo, MADV_ZERO) == 0) {
            std::memset(win.data(), 0, lo - base);
            std::memset(reinterpret_cast<void*>(hi), 0, base + win.size() - hi);
            return;
        }
        if (hi > lo) {
            // MADV_ZERO is refused (ENOTSUP) on a fork child's RAM: that is
            // a mach_vm_map of a COW memory entry, not plain anonymous
            // memory. memset there COPIES every page out of the snapshot
            // first (13 MB at each exec = 2.2 ms). mach_vm_write from a
            // zero region lets the VM system do it a page at a time: 0.35 ms
            // for the same range, and verified (tools/.. zr5) to be seen by
            // the GUEST through its existing IPA mapping, unlike the
            // MAP_FIXED remap noted above. Same 16 KiB host-page rule.
            static void* const zero_src = [] {
                void* z = ::mmap(nullptr, kZeroSrc, PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
                return z == MAP_FAILED ? nullptr : z;
            }();
            bool ok = zero_src != nullptr;
            for (std::uintptr_t at = lo; ok && at < hi; at += kZeroSrc) {
                const std::size_t n = std::min<std::size_t>(kZeroSrc, hi - at);
                ok = ::mach_vm_write(::mach_task_self(), at,
                                     reinterpret_cast<vm_offset_t>(zero_src),
                                     static_cast<mach_msg_type_number_t>(n)) == KERN_SUCCESS;
            }
            if (ok) {
                std::memset(win.data(), 0, lo - base);
                std::memset(reinterpret_cast<void*>(hi), 0, base + win.size() - hi);
                return;
            }
        }
#endif
        std::memset(win.data(), 0, win.size());
    }

    // Publish freshly written guest code: the host wrote it through a data
    // mapping, the guest will FETCH it, and on arm64 those are separate
    // caches with no coherency guarantee.
    void publish_code(std::uint64_t gpa, std::size_t n) const noexcept {
        auto win = ram().at(gpa, n);
        if (!win.empty()) ::sys_icache_invalidate(win.data(), win.size());
    }

private:
    [[nodiscard]] Status attach(bool build_tables = true) {
        if (build_tables) {
            build_page_tables(base_, size_);
            write_vector_stub(base_, size_);
            ::sys_icache_invalidate(base_ + HvfLayout::vectors, 16 * 0x80);
        }

        if (!vm_live_) {
            if (::hv_vm_create(nullptr) != HV_SUCCESS) return err(Errno::enodev);
            vm_live_ = true;
        }
        const auto flags = static_cast<hv_memory_flags_t>(
            HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
        if (::hv_vm_map(base_, 0, size_, flags) != HV_SUCCESS)
            return err(Errno::enomem);
        return ok();
    }

    std::byte* base_{nullptr};
    std::uint64_t size_{0};
    bool vm_live_{false};
    bool owns_ram_{false};
};

// -- One vCPU --------------------------------------------------------------
//
// MUST be created on, and only ever used from, the host thread that will run
// it: Hypervisor.framework binds a vcpu to its creating thread. That is also
// exactly what we want for SMP -- one guest thread per host thread, so XNU
// schedules guest threads across the physical cores.
class HvfCpu {
public:
    HvfCpu() = default;
    HvfCpu(const HvfCpu&) = delete;
    HvfCpu& operator=(const HvfCpu&) = delete;
    ~HvfCpu() { if (live_) ::hv_vcpu_destroy(cpu_); }

    // Bring this vCPU up in "Linux userspace" state: MMU on, EL0
    // unprivileged, our vector stub installed.
    [[nodiscard]] Status create() {
        if (::hv_vcpu_create(&cpu_, &exit_, nullptr) != HV_SUCCESS)
            return err(Errno::enodev);
        live_ = true;
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
        // CNTKCTL_EL1: EL0VCTEN | EL0PCTEN -- let EL0 read CNTVCT_EL0/CNTFRQ
        // directly, as Linux does. This is what makes the vDSO's
        // clock_gettime a few instructions instead of a VM exit (~1 us), and
        // it un-breaks any guest that reads the counter itself (JITs, Go's
        // runtime, benchmark harnesses): before, `mrs x0, cntvct_el0` raised
        // an undefined-instruction exception and killed the program.
        sr(HV_SYS_REG_CNTKCTL_EL1, 0x3ull);
        // CNTVCT_EL0 = mach_absolute_time() - vtimer_offset. Zero offset makes
        // the guest's counter THE host's absolute time -- identical in every
        // vCPU, every thread and every fork child (each a fresh VM whose
        // counter would otherwise restart). The vDSO's tick->ns mapping is
        // then a constant, computed once per exec, valid forever.
        (void)::hv_vcpu_set_vtimer_offset(cpu_, 0);
        return ok();
    }

    [[nodiscard]] bool live() const noexcept { return live_; }
    [[nodiscard]] hv_vcpu_t handle() const noexcept { return cpu_; }

    // -- Execution --------------------------------------------------------
    void set_entry(std::uint64_t pc, std::uint64_t sp) noexcept {
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, sp);
        ::hv_vcpu_set_reg(cpu_, HV_REG_PC, pc);
        ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, 0);   // EL0t, DAIF clear
    }

    // Run until the guest traps, returning its register snapshot. HV_EXIT
    // reasons other than EXCEPTION (vtimer, hv_vcpus_exit) are not guest
    // events, so they surface as EINTR for the caller to retry.
    [[nodiscard]] Result<GuestRegs> run() {
        if (::hv_vcpu_run(cpu_) != HV_SUCCESS) return err<GuestRegs>(Errno::eio);
        if (exit_->reason != HV_EXIT_REASON_EXCEPTION)
            return err<GuestRegs>(Errno::eintr);
        return ok(read_regs(cpu_));
    }

    void set_result(const GuestRegs& r, std::int64_t ret) noexcept {
        write_return(cpu_, r, ret);
    }

    // -- Full user-visible state ------------------------------------------
    // Includes the FP/SIMD file (q0..q31, FPCR, FPSR): glibc's memcpy and
    // every vectorized loop keep those live across a syscall, so a fork or
    // thread-start that saves only the GPRs corrupts floating point state.
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
            ::hv_vcpu_get_simd_fp_reg(
                cpu_, static_cast<hv_simd_fp_reg_t>(HV_SIMD_FP_REG_Q0 + i), &s.q[i]);
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
            ::hv_vcpu_set_simd_fp_reg(
                cpu_, static_cast<hv_simd_fp_reg_t>(HV_SIMD_FP_REG_Q0 + i), s.q[i]);
    }

    [[nodiscard]] std::uint64_t sp() const noexcept { return sys(HV_SYS_REG_SP_EL0); }
    [[nodiscard]] std::uint64_t tls() const noexcept { return sys(HV_SYS_REG_TPIDR_EL0); }
    void set_sp(std::uint64_t v) noexcept { ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, v); }
    void set_tls(std::uint64_t v) noexcept { ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, v); }
    void set_x(int i, std::uint64_t v) noexcept {
        ::hv_vcpu_set_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + i), v);
    }

    // Force this vCPU out of hv_vcpu_run from ANOTHER thread. The only
    // cross-thread operation the framework permits, and the basis of both
    // signal delivery and thread-group exit.
    void kick() noexcept {
        if (!live_) return;
        hv_vcpu_t v = cpu_;
        ::hv_vcpus_exit(&v, 1);
    }

private:
    [[nodiscard]] std::uint64_t sys(hv_sys_reg_t r) const noexcept {
        std::uint64_t v = 0;
        ::hv_vcpu_get_sys_reg(cpu_, r, &v);
        return v;
    }

    hv_vcpu_t cpu_{};
    hv_vcpu_exit_t* exit_{nullptr};
    bool live_{false};
};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
