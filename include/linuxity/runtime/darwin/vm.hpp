// linuxity/runtime/darwin/vm.hpp
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
#include "linuxity/runtime/darwin/inguest.hpp"
#include "linuxity/runtime/darwin/mem.hpp"
#include "linuxity/runtime/darwin/regs.hpp"

#include <Hypervisor/Hypervisor.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

namespace lx::runtime {

// -- The guest address space ---------------------------------------------
//
// Linux gives a process a 47/48-bit address space and memory on first
// touch, and programs lean on both: Firefox reserves eleven 16 GiB PROT_NONE
// regions at startup (SpiderMonkey's and WebAssembly's guard regions) and
// commits pieces of them later. When guest VA was an identity map of RAM
// (VA == GPA, 2-4 GiB), every one of those reservations was ENOMEM and the
// browser came up as a blank 122x38 window. Three address spaces meet here:
//
//   guest VA -- what the program sees: [0, 2^46).
//   host VA  -- `window_`: a sparse 2^46-byte MAP_SHARED reservation, the
//               backing store of the guest's address space. Guest address
//               A is host address window_+A, always, so the kernel side
//               reads and writes guest memory with no translation, and
//               untouched memory costs nothing anywhere.
//   IPA      -- guest-"physical": what Hypervisor.framework can map, 36
//               bits on an M1 (hv_vm_config_get_max_ipa_size). Too small to
//               map the window, so it is a CACHE of it: 2 MiB slots, each
//               showing one 2 MiB chunk of the window, filled when the guest
//               first touches the chunk and evicted (oldest first) when the
//               slots run out. A guest can use far more memory than the IPA
//               space; it only pays a refault for chunks it stops touching.
//
// The stage-1 page tables are a cache as well -- of the VMA map, which is
// the one truth about what may be accessed (see HvfTrap::fill_prot). A
// chunk's 512 entries are computed when it is populated, rewritten when
// mmap/mprotect/munmap change the map, and simply dropped at exec. Every
// fault is checked against the truth: a stale or missing entry is repaired
// and the instruction retried; only a fault the VMA map agrees with becomes
// a signal.
//
// IPA layout:
//   0x0000_0000  vectors + TLB-flush stub (VBAR_EL1)
//   0x0000_1000  in-guest syscall answers (darwin/inguest.hpp)
//   0x0000_3000  L0 table
//   2 MiB        one L3 table page per slot, then the L1/L2 table pool
//   slots_ipa_   the slots, 2 MiB each, up to the top of the IPA space
// Guest VA [0, 2 MiB) is an EL1-only block over the first IPA chunk, so the
// vectors run with the MMU on and EL0 sees no page there (the NULL guard).
struct HvfLayout {
    static constexpr std::uint64_t page           = 0x1000;
    static constexpr std::uint64_t chunk          = 1ull << 21;   // one slot / one L3 table
    static constexpr std::uint64_t vectors        = 0x0000;       // VBAR_EL1 (2 KiB-aligned)
    static constexpr std::uint64_t tlb_flush_stub = 0x0800;       // right after the 16 vectors
    static constexpr std::uint64_t answers        = 0x1000;       // 512 syscalls x {value, live}
    static constexpr std::uint64_t answers_bytes  = 512 * 16;
    static constexpr std::uint64_t l0_table       = answers + answers_bytes;
    static constexpr std::uint64_t tables         = chunk;
    // The first guest-owned address. ET_EXEC programs load at their fixed
    // p_vaddr: lld's default is 0x200000, GNU ld's 0x400000.
    static constexpr std::uint64_t floor          = chunk;
    // Where a PIE program goes. Above every fixed-address image we know of
    // (cc1plus: 42 MiB at 0x400000), below everything else.
    static constexpr std::uint64_t program_base   = 0x800'0000;
    // Unmapped room above the stack, as Linux keeps above 0x7fff_ffff_f000.
    static constexpr std::uint64_t stack_guard    = 0x10000;
};
static_assert(HvfLayout::l0_table + HvfLayout::page <= HvfLayout::chunk,
              "the private page set must fit the EL1-only block at VA 0");

// The address-space plan: the stack at the top of guest VA (an 8 MiB VMA,
// Linux's default RLIMIT_STACK), 1 GiB of unmapped room below it that the
// mmap arena never hands out, the vDSO just under that, and the arena
// everything below.
struct ExecArena {
    static constexpr std::uint64_t stack_reserve = 8ull << 20;    // the initial stack VMA
    static constexpr std::uint64_t stack_room    = 1ull << 30;    // what it may grow into
    [[nodiscard]] static constexpr std::uint64_t mmap_top(std::uint64_t va_top) noexcept {
        return va_top - HvfLayout::stack_guard - stack_room - (1ull << 20);
    }
};

// Stage-1 descriptors, 4 KiB granule.
namespace pte {
inline constexpr std::uint64_t kTable = 3, kPage = 3, kBlock = 1;
inline constexpr std::uint64_t kAf = 1ull << 10, kSh = 3ull << 8;
inline constexpr std::uint64_t kPxn = 1ull << 53, kUxn = 1ull << 54;
inline constexpr std::uint64_t kAddr = 0x0000'ffff'ffff'f000ull;
// A guest page with Linux protection bits (1 read, 2 write, 4 exec). AP[2:1]
// 01 is read/write, 11 read-only, 00 no EL0 data access (exec-only); a page
// with no access at all is no entry, so touching it is a translation fault.
// Write implies read: arm64 has no write-only pages, nor does Linux on it.
[[nodiscard]] constexpr std::uint64_t page(std::uint64_t ipa, std::uint8_t prot) noexcept {
    if (!(prot & 7)) return 0;
    const bool r = prot & 1, w = prot & 2, x = prot & 4;
    const std::uint64_t ap = !r && !w ? 0 : (w ? 1 : 3);
    return ipa | kAf | kSh | (ap << 6) | kPxn | (x ? 0 : kUxn) | kPage;
}
} // namespace pte

// Set once by HvfMachine (before any vCPU exists) and read by HvfCpu::create.
inline std::atomic<unsigned> g_va_bits{46}, g_ipa_bits{36};

// TLB-flush accounting, for reusing an evicted slot (HvfMachine::take_slot).
// A flush is numbered when a vCPU enters the flush stub and recorded as done
// when the stub has run; the stub's `tlbi vmalle1is` is broadcast, so ONE
// completed flush that began after an eviction clears every vCPU's view of
// the evicted chunk.
inline std::atomic<std::uint64_t> g_flush_begun{0}, g_flush_done{0};

// The EL1 exception vector stub. ARM requires 16 entries of 0x80 bytes each;
// every one does the same thing: `hvc #<index>` so the hypervisor (us) sees
// which vector fired. We always resume the guest by writing PC/CPSR
// ourselves, so the stub never returns.
//
// Vector 8 (lower EL, AArch64, synchronous -- i.e. every guest syscall) is
// the exception: it gets the in-guest handler, which answers the pure
// syscalls in-guest and falls through to the same `hvc #8` for the rest.
inline void write_vector_stub(std::byte* mem) {
    for (int v = 0; v < 16; ++v) {
        const std::uint32_t hvc = 0xD4000002u | (static_cast<std::uint32_t>(v) << 5);
        std::memcpy(mem + HvfLayout::vectors + static_cast<std::size_t>(v) * 0x80,
                    &hvc, 4);
    }
    auto* v8 = reinterpret_cast<std::uint32_t*>(mem + HvfLayout::vectors + 8 * 0x80);
    (void)inguest::emit_handler(v8, HvfLayout::answers, 8);
    std::memset(mem + HvfLayout::answers, 0, HvfLayout::answers_bytes);
    // Past the 16 vectors (0x800), the TLB-flush stub: after the host edits
    // the guest's page tables (mprotect), the vCPU enters here at EL1 and
    // drops every cached translation -- broadcast, so every vCPU of the VM
    // -- then returns to the guest through ELR_EL1/SPSR_EL1.
    const std::uint32_t flush[] = {
        0xD508831Fu,     // tlbi vmalle1is
        0xD5033B9Fu,     // dsb  ish
        0xD5033FDFu,     // isb
        0xD69F03E0u,     // eret
    };
    std::memcpy(mem + HvfLayout::tlb_flush_stub, flush, sizeof flush);
}

// -- The machine: the guest address space shared by every vCPU -------------
//
// Non-copyable and non-movable: hv_vm is a process-global resource and vCPUs
// hold a reference to this object, so its address is part of its identity.
class HvfMachine {
public:
    // A run of guest VA a fork must carry to the child (HvfTrap::fork_extents).
    struct Extent { std::uint64_t lo, hi; };
    enum class Populate {
        mapped,     // the chunk is now in the VM; the guest may retry
        present,    // it already was: the fault was a stale entry, or a race
        busy,       // no slot until a TLB flush completes: flush, then retry
        failed,     // not guest memory, or the hypervisor refused
    };

    HvfMachine() = default;
    HvfMachine(const HvfMachine&) = delete;
    HvfMachine& operator=(const HvfMachine&) = delete;
    HvfMachine(HvfMachine&&) = delete;
    HvfMachine& operator=(HvfMachine&&) = delete;
    ~HvfMachine() {
        if (vm_live_) ::hv_vm_destroy();
        for (std::size_t s = 0; s < slabs_.size(); ++s)
            if (slabs_[s])
                (void)::mach_vm_deallocate(::mach_task_self(),
                                           reinterpret_cast<mach_vm_address_t>(window_) + (s << kSlabBits), kSlab);
        if (priv_) ::munmap(priv_, priv_bytes_);
    }

    // Create the VM with an empty address space. A zygote does this while
    // parked, so the hv_vm_create, the window and the vCPU it then makes are
    // all off the fork's critical path. Idempotent.
    [[nodiscard]] Status prewarm() {
        if (vm_live_) return ok();
        std::uint32_t ipa = 36;
        if (::hv_vm_config_get_max_ipa_size(&ipa) != HV_SUCCESS || ipa < 36) ipa = 36;
        ipa = std::min<std::uint32_t>(ipa, 48);
        hv_vm_config_t cfg = ::hv_vm_config_create();
        if (cfg) (void)::hv_vm_config_set_ipa_size(cfg, ipa);
        const hv_return_t created = ::hv_vm_create(cfg);
        if (cfg) ::os_release(cfg);
        if (created != HV_SUCCESS) return err(Errno::enodev);
        vm_live_ = true;
        ipa_bits_ = ipa;
        g_ipa_bits.store(ipa);
        if (auto st = reserve_window(); !st) return st;
        return build_private();
    }

    // A fresh process: the empty space is all it needs.
    [[nodiscard]] Status init() { return prewarm(); }

    // Fork, parent side: copy-on-write snapshots of `ext`, one send right
    // each (mach_make_memory_entry_64 + MAP_MEM_VM_COPY: no page is copied
    // until one side writes it). Empty on failure.
    [[nodiscard]] std::vector<mach_port_t> snapshot(const std::vector<Extent>& ext) const {
        std::vector<mach_port_t> out;
        out.reserve(ext.size());
        for (const Extent& e : ext) {
            memory_object_size_t n = e.hi - e.lo;
            mach_port_t p = MACH_PORT_NULL;
            if (!ensure(e.lo, e.hi - e.lo) ||
                ::mach_make_memory_entry_64(::mach_task_self(), &n,
                    reinterpret_cast<memory_object_offset_t>(window_ + e.lo),
                    VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_COPY, &p, MACH_PORT_NULL)
                    != KERN_SUCCESS) {
                for (mach_port_t q : out) ::mach_port_deallocate(::mach_task_self(), q);
                return {};
            }
            out.push_back(p);
        }
        return out;
    }

    // Fork, child side: the parent's snapshots, each at its own guest VA. The
    // page tables are NOT carried: they are a cache, and this process's are
    // rebuilt as the guest touches its memory.
    [[nodiscard]] Status init_child(const std::vector<Extent>& ext,
                                    const std::vector<mach_port_t>& ports) {
        if (auto st = prewarm(); !st) return st;
        if (ext.size() != ports.size()) return err(Errno::einval);
        for (const Extent& e : ext) note_touched(e.lo, e.hi - e.lo);
        Status st = ok();
        for (std::size_t i = 0; i < ext.size(); ++i) {
            // the slab first (it is mapped OVER anything there), then the
            // snapshot over its part of the slab
            if (!ensure(ext[i].lo, ext[i].hi - ext[i].lo)) st = err(Errno::enomem);
            auto at = reinterpret_cast<mach_vm_address_t>(window_ + ext[i].lo);
            if (st && ::mach_vm_map(::mach_task_self(), &at, ext[i].hi - ext[i].lo, 0,
                                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, ports[i], 0,
                                    /*copy=*/FALSE, VM_PROT_READ | VM_PROT_WRITE,
                                    VM_PROT_READ | VM_PROT_WRITE, VM_INHERIT_NONE) != KERN_SUCCESS)
                st = err(Errno::enomem);
            ::mach_port_deallocate(::mach_task_self(), ports[i]);
        }
        return st;
    }

    // -- Memory -----------------------------------------------------------
    [[nodiscard]] GuestRam ram() const noexcept {
        return GuestRam{window_, va_top_, HvfLayout::floor, this, &HvfMachine::ensure_cb};
    }
    // Let a syscall be answered IN-GUEST with a constant (see
    // darwin/inguest.hpp): no VM exit, ~32 ns instead of ~930.
    void set_guest_answer(int nr, std::uint64_t value) noexcept {
        if (nr < 0 || static_cast<std::size_t>(nr) >= inguest::kMaxNr || !priv_) return;
        auto* t = reinterpret_cast<inguest::Entry*>(priv_ + HvfLayout::answers);
        t[nr].value = value;
        std::atomic_thread_fence(std::memory_order_release);
        t[nr].live = 1;
    }
    void clear_guest_answer(int nr) noexcept {
        if (nr < 0 || static_cast<std::size_t>(nr) >= inguest::kMaxNr || !priv_) return;
        reinterpret_cast<inguest::Entry*>(priv_ + HvfLayout::answers)[nr].live = 0;
    }
    void clear_all_guest_answers() noexcept {
        if (priv_) std::memset(priv_ + HvfLayout::answers, 0, HvfLayout::answers_bytes);
    }

    // The top of guest VA (2^46 unless the host refused a window that big).
    [[nodiscard]] std::uint64_t mem_size() const noexcept { return va_top_; }
    // Chunks currently in the VM, and how many it can hold at once.
    [[nodiscard]] std::size_t populated() const {
        std::lock_guard l{mu_};
        return slot_of_.size();
    }
    [[nodiscard]] std::size_t slots() const noexcept { return nslots_; }
    // Wait out a back_shared/evict in progress: they hold mu_ while a chunk
    // is out of the VM, and a vCPU that touched it meanwhile took a stage-2
    // fault that only needs retrying once they are done.
    void settle() const { std::lock_guard l{mu_}; }

    // Zero one host-page-aligned run: MADV_ZERO where allowed (plain anon
    // memory), mach_vm_write from a zero region on a COW snapshot (where
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

    // Clear a guest range, touching NO byte outside [va, va+n).
    //
    // madvise(MADV_ZERO) works at HOST page granularity -- 16 KiB on Apple
    // Silicon -- while the guest uses 4 KiB pages. A 4 KiB MADV_ZERO
    // silently zeroes the surrounding 16 KiB host page, destroying up to 12
    // KiB of neighbouring guest memory (that once corrupted libc's data a
    // moment before relocation). So: zero only the host-page-aligned
    // interior that way, and memset the unaligned head and tail.
    //
    // Pages that were never touched are skipped: they already read as zero,
    // and on a fork child's COW snapshot writing them would copy each one.
    void zero(std::uint64_t va, std::size_t n) noexcept {
        if (!n || va >= va_top_) return;
        n = std::min<std::uint64_t>(n, va_top_ - va);
        // Slab by slab: a slab never mapped holds nothing to clear, and
        // mapping it just to look would cost a slab per reservation.
        for (std::uint64_t at = va, end = va + n; at < end;) {
            const std::uint64_t s = at >> kSlabBits;
            const std::uint64_t stop = std::min(end, (s + 1) << kSlabBits);
            if (__atomic_load_n(&slabs_[s], __ATOMIC_ACQUIRE)) zero_mapped(at, stop - at);
            at = stop;
        }
    }
    // Small ranges: clear the touched host pages in place (mincore finds
    // them; a fork child's COW pages it never touched are not copied).
    // Large ones: swap in fresh memory, one map entry whatever the size --
    // a 16 GiB MAP_FIXED over a live mapping costs microseconds, not a
    // mincore walk of four million pages.
    static constexpr std::uint64_t kZeroInPlace = 64ull << 20;
    void zero_mapped(std::uint64_t va, std::size_t n) noexcept {
        std::byte* const data = window_ + va;
        const std::uintptr_t hp = host_page();
        const auto base = reinterpret_cast<std::uintptr_t>(data);
        const std::uintptr_t lo = (base + hp - 1) & ~(hp - 1);
        const std::uintptr_t hi = (base + n) & ~(hp - 1);
        if (hi <= lo) { std::memset(data, 0, n); return; }
        std::memset(data, 0, lo - base);
        std::memset(reinterpret_cast<void*>(hi), 0, base + n - hi);
        if (hi - lo > kZeroInPlace) {
            (void)fresh(va + (lo - base), hi - lo);
            return;
        }
        const std::size_t npages = (hi - lo) / hp;
        std::vector<char> vec(npages);
        if (::mincore(reinterpret_cast<void*>(lo), hi - lo, vec.data()) != 0) {
            zero_run(lo, hi - lo);
            return;
        }
        constexpr char kHas = MINCORE_INCORE | MINCORE_PAGED_OUT;
        for (std::size_t i = 0; i < npages;) {
            if (!(vec[i] & kHas)) { ++i; continue; }
            std::size_t j = i;
            while (j < npages && (vec[j] & kHas)) ++j;
            zero_run(lo + i * hp, (j - i) * hp);
            i = j;
        }
    }

    // Give the host back the memory behind [va, va+n), which the guest no
    // longer maps (munmap). Only whole host pages inside the range go, so no
    // neighbouring mapping loses a byte; they come back as zero pages. This
    // is what makes a guest's munmap lower its footprint, as on Linux.
    void discard(std::uint64_t va, std::uint64_t n) noexcept {
        const std::uint64_t hp = host_page();
        const std::uint64_t lo = (va + hp - 1) & ~(hp - 1), hi = std::min(va_top_, (va + n) & ~(hp - 1));
        // only where a slab exists: elsewhere nothing was ever allocated
        for (std::uint64_t at = lo; at < hi;) {
            const std::uint64_t s = at >> kSlabBits;
            const std::uint64_t stop = std::min(hi, (s + 1) << kSlabBits);
            if (__atomic_load_n(&slabs_[s], __ATOMIC_ACQUIRE)) (void)fresh(at, stop - at);
            at = stop;
        }
    }
    // Replace [va, va+n) (host-page aligned, inside mapped slabs) with fresh
    // zero memory: one Mach named entry, so one map entry however large --
    // MAP_ANON would split it into 128 MiB pieces. Slots showing the range
    // leave the VM for the swap, as in back_shared.
    bool fresh(std::uint64_t va, std::uint64_t n) noexcept {
        std::lock_guard l{mu_};
        const auto hit = populated_in(va, va + n);
        for (const auto& [c, s] : hit) (void)::hv_vm_unmap(slot_ipa(s), HvfLayout::chunk);
        const bool ok = fresh_unlocked(va, n);
        bool evicted = false;
        for (const auto& [c, s] : hit)
            if (::hv_vm_map(window_ + (c << 21), slot_ipa(s), HvfLayout::chunk, kRwx) != HV_SUCCESS) {
                evict(s);
                evicted = true;
            }
        if (evicted) seal_evictions();
        return ok;
    }

    // Publish freshly written guest code: the host wrote it through a data
    // mapping, the guest will FETCH it, and on arm64 those are separate
    // caches with no coherency guarantee.
    void publish_code(std::uint64_t va, std::size_t n) const noexcept {
        auto win = ram().at(va, n);
        if (!win.empty()) ::sys_icache_invalidate(win.data(), win.size());
    }

    // -- Shared pages -------------------------------------------------------
    // Back [va, va+n) with `fd` at `off`, MAP_SHARED: the guest then reads
    // and writes the object's own pages, so every process that maps it
    // (another guest process, a fork child, read()/write() on the file)
    // sees the same bytes at once -- MAP_SHARED, for real. fd < 0 puts fresh
    // zero memory there instead.
    //
    // A host mapping replaced under a live VM keeps the guest translating to
    // the OLD pages (hv_vm_map captures the objects), so every slot showing
    // the range leaves the VM for the swap and comes back: a guest thread
    // touching it meanwhile takes a stage-2 fault, which waits on mu_ and
    // retries. va, n and off must be host-page aligned (16 KiB).
    [[nodiscard]] static std::uintptr_t host_page() noexcept {
        static const std::uintptr_t p = static_cast<std::uintptr_t>(::getpagesize());
        return p;
    }
    [[nodiscard]] bool back_shared(std::uint64_t va, std::uint64_t n, int fd, std::int64_t off) noexcept {
        const std::uintptr_t hp = host_page();
        if ((va | n) & (hp - 1) || (off & static_cast<std::int64_t>(hp - 1)) || !n) return false;
        auto win = ram().at(va, n);
        if (win.empty()) return false;
        std::lock_guard l{mu_};
        const auto hit = populated_in(va, va + n);
        for (const auto& [c, s] : hit) (void)::hv_vm_unmap(slot_ipa(s), HvfLayout::chunk);
        constexpr int kRw = PROT_READ | PROT_WRITE;
        void* got = fd >= 0
            ? ::mmap(win.data(), n, kRw, MAP_SHARED | MAP_FIXED, fd, off)
            : ::mmap(win.data(), n, kRw, MAP_SHARED | MAP_ANON | MAP_FIXED, -1, 0);
        const bool ok = got == win.data();
        if (!ok)        // keep the range usable: plain zero memory
            (void)::mmap(win.data(), n, kRw, MAP_SHARED | MAP_ANON | MAP_FIXED, -1, 0);
        bool back = true;
        bool evicted = false;
        for (const auto& [c, s] : hit)
            if (::hv_vm_map(window_ + (c << 21), slot_ipa(s), HvfLayout::chunk, kRwx) != HV_SUCCESS) {
                evict(s);                              // refaults later
                back = false;
                evicted = true;
            }
        if (evicted) seal_evictions();
        return ok && back;
    }

    // -- Page tables ----------------------------------------------------------
    // `perms(lo, hi, out)` fills out[i] with the Linux protection of the
    // guest page lo + i*4096, for [lo, hi) inside one chunk: the caller's
    // view of the truth (HvfTrap::fill_prot), consulted under mu_.

    // Bring the chunk holding `va` into the VM. The caller retries the
    // faulting instruction on mapped/present, and on busy after a flush.
    template <class Perms>
    [[nodiscard]] Populate populate(std::uint64_t va, Perms&& perms) {
        const std::uint64_t c = va >> 21;
        if (!c || va >= va_top_ || !priv_) return Populate::failed;
        if (!ensure(c << 21, HvfLayout::chunk)) return Populate::failed;
        std::lock_guard l{mu_};
        if (slot_of_.count(c)) return Populate::present;
        const std::uint32_t s = take_slot();
        if (s == kNoSlot) return Populate::busy;
        const std::uint64_t ipa = slot_ipa(s);
        const std::uint64_t l2 = l2_for(c << 21, /*create=*/true);
        if (!l2 || ::hv_vm_map(window_ + (c << 21), ipa, HvfLayout::chunk, kRwx) != HV_SUCCESS) {
            free_slots_.push_back(s);
            return Populate::failed;
        }
        std::uint8_t prot[512];
        perms(c << 21, (c + 1) << 21, prot);
        auto* l3 = table(l3_ipa(s));
        for (std::uint64_t i = 0; i < 512; ++i) l3[i] = pte::page(ipa + i * HvfLayout::page, prot[i]);
        // the entries before the link: a walk that sees the link sees them
        put(table(l2) + (c & 0x1ff), l3_ipa(s) | pte::kTable);
        slot_of_.emplace(c, s);
        chunk_of_[s] = c;
        fifo_.push_back({s, c});
        touched_insert(c);
        return Populate::mapped;
    }

    // Recompute the entries of [va, va+n) wherever its chunks are in the VM
    // (elsewhere there is nothing to update: they are computed when
    // populated). True if any entry was rewritten -- the caller must then
    // flush the guest's TLB (HvfCpu::flush_tlb_on_entry) before it runs.
    template <class Perms>
    bool refresh(std::uint64_t va, std::uint64_t n, Perms&& perms) {
        const std::uint64_t lo = va & ~(HvfLayout::page - 1);
        const std::uint64_t hi = std::min(va_top_, (va + n + HvfLayout::page - 1) & ~(HvfLayout::page - 1));
        if (hi <= lo || !priv_) return false;
        std::lock_guard l{mu_};
        bool any = false;
        std::uint8_t prot[512];
        for (const auto& [c, s] : populated_in(lo, hi)) {
            const std::uint64_t plo = std::max(lo, c << 21), phi = std::min(hi, (c + 1) << 21);
            perms(plo, phi, prot);
            auto* l3 = table(l3_ipa(s));
            const std::uint64_t ipa = slot_ipa(s);
            for (std::uint64_t p = plo; p < phi; p += HvfLayout::page) {
                const std::uint64_t i = (p >> 12) & 0x1ff;
                put(l3 + i, pte::page(ipa + i * HvfLayout::page, prot[(p - plo) >> 12]));
            }
            any = true;
        }
        return any;
    }

    // A fork's extents: `want` (the address space's live ranges, host-page
    // aligned) cut down to the chunks that may hold data, merged into runs.
    [[nodiscard]] std::vector<Extent> touched_extents(const std::vector<Extent>& want) const {
        std::vector<std::uint64_t> cs;
        {
            std::lock_guard l{touched_mu_};
            cs.assign(touched_.begin(), touched_.end());
        }
        std::sort(cs.begin(), cs.end());
        std::vector<Extent> out;
        std::size_t k = 0;
        for (const Extent& e : want) {
            const std::uint64_t c0 = e.lo >> 21, c1 = (e.hi - 1) >> 21;
            k = static_cast<std::size_t>(std::lower_bound(cs.begin(), cs.end(), c0) - cs.begin());
            for (; k < cs.size() && cs[k] <= c1; ++k) {
                const std::uint64_t lo = std::max(e.lo, cs[k] << 21);
                const std::uint64_t hi = std::min(e.hi, (cs[k] + 1) << 21);
                if (!out.empty() && out.back().hi == lo) out.back().hi = hi;
                else out.push_back({lo, hi});
            }
        }
        return out;
    }
    // The host is about to write guest memory directly (a loader, read(2)
    // into a buffer, a signal frame): what it writes must survive a fork.
    void note_touched(std::uint64_t va, std::uint64_t n) const {
        if (!n || va >= va_top_) return;
        const std::uint64_t c0 = va >> 21, c1 = (std::min(va + n, va_top_) - 1) >> 21;
        std::lock_guard l{touched_mu_};
        for (std::uint64_t c = c0; c <= c1; ++c) touched_.insert(c);
    }
    void touched_insert(std::uint64_t c) const {
        std::lock_guard l{touched_mu_};
        touched_.insert(c);
    }

    // execve: the old image's memory and translations go, all of them. The
    // caller flushes the TLB before the guest runs again, and exec is single
    // threaded, so no vCPU can use a stale translation before that flush --
    // which is why the slots and table pages are reusable at once. `old` is
    // every range the old image could have touched (HvfTrap::fork_extents):
    // replacing just those with fresh memory costs microseconds, where
    // replacing the whole 64 TiB window walks all of it (11 ms and up).
    void reset_space(const std::vector<Extent>& old) noexcept {
        std::lock_guard l{mu_};
        for (const auto& [c, s] : slot_of_) {
            (void)::hv_vm_unmap(slot_ipa(s), HvfLayout::chunk);
            chunk_of_[s] = kNoChunk;
        }
        slot_of_.clear();
        fifo_.clear();
        quarantine_.clear();
        unsealed_.clear();
        {
            std::lock_guard tl{touched_mu_};
            touched_.clear();
        }
        free_slots_.clear();
        for (std::uint32_t s = nslots_; s-- > 0;) free_slots_.push_back(s);
        std::memset(priv_ + HvfLayout::l0_table, 0, HvfLayout::page);
        pool_next_ = pool_base_;
        (void)map_private_block();
        for (const Extent& e : old)
            for (std::uint64_t at = e.lo, end = std::min(e.hi, va_top_); at < end;) {
                const std::uint64_t s = at >> kSlabBits;
                const std::uint64_t stop = std::min(end, (s + 1) << kSlabBits);
                if (slabs_[s]) (void)fresh_unlocked(at, stop - at);
                at = stop;
            }
    }
    // [va, va+n) -> fresh zero memory, nothing populated over it (callers:
    // reset_space, under mu_ with every slot already out of the VM).
    bool fresh_unlocked(std::uint64_t va, std::uint64_t n) noexcept {
        memory_object_size_t sz = n;
        mach_port_t e = MACH_PORT_NULL;
        if (::mach_make_memory_entry_64(::mach_task_self(), &sz, 0,
                MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE, &e, MACH_PORT_NULL) != KERN_SUCCESS)
            return false;
        mach_vm_address_t at = reinterpret_cast<mach_vm_address_t>(window_ + va);
        const bool ok = ::mach_vm_map(::mach_task_self(), &at, n, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, e, 0,
                                      FALSE, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                                      VM_INHERIT_NONE) == KERN_SUCCESS;
        ::mach_port_deallocate(::mach_task_self(), e);
        return ok;
    }

private:
    static constexpr std::uint32_t kNoSlot = ~std::uint32_t{0};
    static constexpr std::uint64_t kNoChunk = ~std::uint64_t{0};
    static constexpr auto kRwx = static_cast<hv_memory_flags_t>(HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);

    // The biggest window the host grants, from 2^46 down. One per process:
    // two 64 TiB reservations do not fit the host's 47-bit user space, but a
    // fork child is a fresh process with its own.
    //
    // Reserving 64 TiB costs what its map entries cost, and XNU makes many:
    // plain anonymous memory is split into 128 MiB entries (ANON_CHUNK_SIZE),
    // half a million of them -- 65 ms to create, as much to tear down at
    // exit, on every guest process. A single named entry tops out at 2^45,
    // and two of them still cost 5 ms per process exit. So the window is
    // NOT reserved: it is a fixed host range (host processes map nothing
    // that high: libraries and heaps live below 1 TiB) populated in 8 GiB
    // SLABS, each one Mach named entry created on first use -- a typical
    // process touches four or five (image, heap, libraries, stack), for
    // ~30 us. Every host-side access goes through GuestRam, whose ensure
    // hook maps a slab before handing out a pointer into it.
    static constexpr unsigned kSlabBits = 33;
    static constexpr std::uint64_t kSlab = 1ull << kSlabBits;
    [[nodiscard]] Status reserve_window() {
        constexpr std::uint64_t kBase = 1ull << 44;          // 16 TiB
        for (unsigned bits = 46; bits >= 39; --bits) {
            mach_vm_address_t probe = kBase;
            // the range must be free: claim nothing, just look
            mach_vm_size_t sz = 0;
            vm_region_basic_info_data_64_t info{};
            mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t obj = MACH_PORT_NULL;
            const bool clear = ::mach_vm_region(::mach_task_self(), &probe, &sz, VM_REGION_BASIC_INFO_64,
                                                reinterpret_cast<vm_region_info_t>(&info), &cnt, &obj) != KERN_SUCCESS
                               || probe >= kBase + (1ull << bits);
            if (!clear) continue;
            window_ = reinterpret_cast<std::byte*>(kBase);
            va_top_ = 1ull << bits;
            va_bits_ = bits;
            g_va_bits.store(bits);
            slabs_.assign(static_cast<std::size_t>(va_top_ >> kSlabBits), 0);
            return ok();
        }
        return err(Errno::enomem);
    }
    // Map the slabs under [va, va+n). Lock-free on the hot path (slab
    // already there); creation serializes on slab_mu_.
    [[nodiscard]] bool ensure(std::uint64_t va, std::uint64_t n) const noexcept {
        if (!n || va >= va_top_) return n == 0;
        const std::uint64_t last = std::min(va + n, va_top_) - 1;
        for (std::uint64_t s = va >> kSlabBits; s <= last >> kSlabBits; ++s)
            if (!__atomic_load_n(&slabs_[s], __ATOMIC_ACQUIRE) && !make_slab(s)) return false;
        return true;
    }
    // GuestRam's hook: a host pointer into guest memory is about to be used
    // (read or written -- it can't tell), so the chunks may hold data a fork
    // must carry. Huge spans (a bounds probe over a reservation) are not
    // recorded chunk by chunk: those are never written whole.
    static bool ensure_cb(const void* self, std::uint64_t va, std::uint64_t n) {
        const auto* m = static_cast<const HvfMachine*>(self);
        if (!m->ensure(va, n)) return false;
        if (n <= kNoteMax) m->note_touched(va, n);
        return true;
    }
    static constexpr std::uint64_t kNoteMax = 256ull << 20;
    [[nodiscard]] bool make_slab(std::uint64_t s) const noexcept {
        std::lock_guard l{slab_mu_};
        if (slabs_[s]) return true;
        memory_object_size_t n = kSlab;
        mach_port_t e = MACH_PORT_NULL;
        if (::mach_make_memory_entry_64(::mach_task_self(), &n, 0,
                MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE, &e, MACH_PORT_NULL) != KERN_SUCCESS)
            return false;
        mach_vm_address_t at = reinterpret_cast<mach_vm_address_t>(window_) + (s << kSlabBits);
        // OVERWRITE: a fork child's snapshot extents may already sit here;
        // they are re-laid over the fresh slab by the caller (init_child).
        const kern_return_t kr = ::mach_vm_map(::mach_task_self(), &at, kSlab, 0,
                                               VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, e, 0, FALSE,
                                               VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE,
                                               VM_INHERIT_NONE);
        ::mach_port_deallocate(::mach_task_self(), e);
        if (kr != KERN_SUCCESS) return false;
        __atomic_store_n(&slabs_[s], std::uint8_t{1}, __ATOMIC_RELEASE);
        return true;
    }

    // Size the IPA plan, then build the private pages and map them.
    [[nodiscard]] Status build_private() {
        const std::uint64_t ipa_top = 1ull << ipa_bits_;
        // Every L1 and L2 table the VA space could ever need: tables are
        // never freed (bounded, and a freed table could be reached through a
        // stale walk cache), so the pool must hold them all.
        const std::uint64_t pool_pages = (1ull << (va_bits_ - 30)) + (1ull << (va_bits_ - 39)) + 1;
        auto end_of = [&](std::uint64_t n) {
            const std::uint64_t pool_end = HvfLayout::tables + (n + pool_pages) * HvfLayout::page;
            const std::uint64_t slots = (pool_end + HvfLayout::chunk - 1) & ~(HvfLayout::chunk - 1);
            return slots + n * HvfLayout::chunk;
        };
        std::uint64_t n = std::min<std::uint64_t>((ipa_top - HvfLayout::tables) / (HvfLayout::chunk + HvfLayout::page),
                                                  1u << 20);
        while (n && end_of(n) > ipa_top) --n;
        if (const char* e = std::getenv("LINUXITY_VM_SLOTS"))     // tests: force eviction
            n = std::clamp<std::uint64_t>(std::strtoull(e, nullptr, 10), 4, n);
        if (n < 4) return err(Errno::enomem);
        nslots_ = static_cast<std::uint32_t>(n);
        pool_base_ = pool_next_ = HvfLayout::tables + n * HvfLayout::page;
        pool_end_ = pool_base_ + pool_pages * HvfLayout::page;
        priv_bytes_ = (pool_end_ + HvfLayout::chunk - 1) & ~(HvfLayout::chunk - 1);
        slots_ipa_ = priv_bytes_;
        void* p = ::mmap(nullptr, priv_bytes_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (p == MAP_FAILED) return err(Errno::enomem);
        priv_ = static_cast<std::byte*>(p);
        write_vector_stub(priv_);
        ::sys_icache_invalidate(priv_ + HvfLayout::vectors, 16 * 0x80 + 16);
        if (!map_private_block()) return err(Errno::enomem);
        if (::hv_vm_map(priv_, 0, priv_bytes_, kRwx) != HV_SUCCESS) return err(Errno::enomem);
        chunk_of_.assign(nslots_, kNoChunk);
        free_slots_.clear();
        for (std::uint32_t s = nslots_; s-- > 0;) free_slots_.push_back(s);
        return ok();
    }

    // VA [0, 2 MiB) -> IPA [0, 2 MiB): EL1-only (AP=00), executable at EL1
    // only (UXN), as one block entry.
    [[nodiscard]] bool map_private_block() {
        const std::uint64_t l2 = l2_for(0, /*create=*/true);
        if (!l2) return false;
        put(table(l2), 0 | pte::kAf | pte::kSh | pte::kUxn | pte::kBlock);
        return true;
    }

    [[nodiscard]] std::uint64_t* table(std::uint64_t ipa) const noexcept {
        return reinterpret_cast<std::uint64_t*>(priv_ + ipa);
    }
    static void put(std::uint64_t* e, std::uint64_t v) noexcept {
        __atomic_store_n(e, v, __ATOMIC_RELEASE);
    }
    [[nodiscard]] std::uint64_t slot_ipa(std::uint32_t s) const noexcept {
        return slots_ipa_ + static_cast<std::uint64_t>(s) * HvfLayout::chunk;
    }
    [[nodiscard]] static std::uint64_t l3_ipa(std::uint32_t s) noexcept {
        return HvfLayout::tables + static_cast<std::uint64_t>(s) * HvfLayout::page;
    }
    // The L2 table whose entries cover `va`'s GiB, creating the L1 and L2
    // tables on the way if asked; 0 if absent (or the pool is exhausted).
    [[nodiscard]] std::uint64_t l2_for(std::uint64_t va, bool create) {
        std::uint64_t at = HvfLayout::l0_table;
        for (const unsigned shift : {39u, 30u}) {
            std::uint64_t* e = table(at) + ((va >> shift) & 0x1ff);
            if (!(*e & 1)) {
                if (!create || pool_next_ >= pool_end_) return 0;
                const std::uint64_t t = pool_next_;
                pool_next_ += HvfLayout::page;
                std::memset(priv_ + t, 0, HvfLayout::page);
                put(e, t | pte::kTable);
            }
            at = *e & pte::kAddr;
        }
        return at;
    }
    // The populated chunks overlapping [lo, hi), as (chunk, slot).
    [[nodiscard]] std::vector<std::pair<std::uint64_t, std::uint32_t>>
    populated_in(std::uint64_t lo, std::uint64_t hi) const {
        std::vector<std::pair<std::uint64_t, std::uint32_t>> out;
        if (hi <= lo) return out;
        const std::uint64_t c0 = lo >> 21, c1 = (hi - 1) >> 21;
        if (c1 - c0 + 1 > slot_of_.size()) {          // a huge range: walk the slots instead
            for (const auto& [c, s] : slot_of_)
                if (c >= c0 && c <= c1) out.emplace_back(c, s);
        } else {
            for (std::uint64_t c = c0; c <= c1; ++c)
                if (auto it = slot_of_.find(c); it != slot_of_.end()) out.emplace_back(c, it->second);
        }
        return out;
    }

    // A free slot, evicting the oldest chunks if there is none. Evicted
    // slots wait in quarantine until a TLB flush that began after their
    // eviction has completed: until then some vCPU may still hold a
    // translation to them, and reusing one would show it ANOTHER chunk.
    [[nodiscard]] std::uint32_t take_slot() {
        if (free_slots_.empty()) release_quarantine();
        if (free_slots_.empty() && quarantine_.size() < nslots_ / 32 + 1) {
            for (std::size_t n = nslots_ / 16 + 1; n && !fifo_.empty();) {
                const auto [s, c] = fifo_.front();
                fifo_.pop_front();
                if (chunk_of_[s] != c) continue;       // evicted earlier
                evict(s);
                --n;
            }
            seal_evictions();
            release_quarantine();
        }
        if (free_slots_.empty()) return kNoSlot;
        const std::uint32_t s = free_slots_.back();
        free_slots_.pop_back();
        return s;
    }
    void release_quarantine() {
        const std::uint64_t done = g_flush_done.load(std::memory_order_acquire);
        std::erase_if(quarantine_, [&](const std::pair<std::uint32_t, std::uint64_t>& q) {
            if (q.second > done) return false;
            free_slots_.push_back(q.first);
            return true;
        });
    }
    // Unlink the chunk FIRST, then take it out of the VM: no new walk can
    // reach the slot, and the unmap drops what the TLB held of it.
    void evict(std::uint32_t s) {
        const std::uint64_t c = chunk_of_[s];
        if (c == kNoChunk) return;
        if (const std::uint64_t l2 = l2_for(c << 21, /*create=*/false))
            put(table(l2) + (c & 0x1ff), 0);
        (void)::hv_vm_unmap(slot_ipa(s), HvfLayout::chunk);
        chunk_of_[s] = kNoChunk;
        slot_of_.erase(c);
        unsealed_.push_back(s);
    }
    // Ticket the slots just evicted: the next flush to BEGIN from now on
    // starts after their entries were gone, so its completion frees them.
    // (Taken after the unlinks -- a ticket taken before could match a
    // flush that ran while a walk could still cache the old entry.)
    void seal_evictions() {
        std::atomic_thread_fence(std::memory_order_seq_cst);
        const std::uint64_t ticket = g_flush_begun.load(std::memory_order_acquire) + 1;
        for (std::uint32_t s : unsealed_) quarantine_.emplace_back(s, ticket);
        unsealed_.clear();
    }

    std::byte* window_{nullptr};        // guest VA backing store
    std::uint64_t va_top_{0};
    mutable std::vector<std::uint8_t> slabs_;     // which 8 GiB slabs are mapped
    mutable std::mutex slab_mu_;
    unsigned va_bits_{0}, ipa_bits_{36};
    std::byte* priv_{nullptr};          // IPA [0, priv_bytes_)
    std::uint64_t priv_bytes_{0};
    std::uint64_t pool_base_{0}, pool_next_{0}, pool_end_{0};
    std::uint64_t slots_ipa_{0};
    std::uint32_t nslots_{0};
    bool vm_live_{false};

    mutable std::mutex mu_;
    std::unordered_map<std::uint64_t, std::uint32_t> slot_of_;    // chunk -> slot
    std::vector<std::uint64_t> chunk_of_;                         // slot -> chunk
    std::vector<std::uint32_t> free_slots_;
    std::deque<std::pair<std::uint32_t, std::uint64_t>> fifo_;    // (slot, chunk), oldest first
    std::vector<std::pair<std::uint32_t, std::uint64_t>> quarantine_;   // (slot, flush ticket)
    std::vector<std::uint32_t> unsealed_;                         // evicted, not yet ticketed
    // Every chunk that may hold data: populated in the VM since the last
    // exec, written by the host (ensure_touched), or received from a fork
    // parent. A fork snapshots only these -- a Mach COW snapshot costs ~9 ms
    // per GiB COVERED, touched or not, and Firefox reserves 176 GiB.
    mutable std::unordered_set<std::uint64_t> touched_;
    mutable std::mutex touched_mu_;     // a leaf lock: taken under mu_ too
};

// -- The vCPU budget ---------------------------------------------------------
//
// Hypervisor.framework allows a VM 64 vCPUs (hv_vm_get_max_vcpu_count), and
// every guest thread runs on one -- but Linux programs run hundreds of
// threads: Firefox's thread pools, Go, the JVM. Most of them, most of the
// time, sit blocked in a syscall, where a thread needs no vCPU at all.
//
// So the vCPUs are a budget. HvfCpu::create() takes a slot (waiting for one
// if none is free), the destructor gives it back, and a thread about to
// block in a syscall while slots are scarce parks: its full CPU state is
// saved, the vCPU destroyed and the slot handed to whoever waits; it takes a
// slot again (waiting if it must) and rebuilds the vCPU when the syscall
// returns. With slots to spare nothing parks, so ordinary programs pay
// nothing; a 500-thread program runs with at most `capacity` on CPUs at a
// time -- which is what any machine with fewer cores than threads does.
struct VcpuBudget {
    std::mutex mu;
    std::condition_variable cv;
    int capacity{0};
    int in_use{0};
    int waiting{0};

    void init_locked() {
        if (capacity) return;
        std::uint32_t max = 0;
        if (::hv_vm_get_max_vcpu_count(&max) != HV_SUCCESS || max < 4) max = 64;
        capacity = static_cast<int>(max) - 2;   // headroom for the framework's own
    }
    void acquire() {
        std::unique_lock l{mu};
        init_locked();
        ++waiting;
        cv.wait(l, [this] { return in_use < capacity; });
        --waiting;
        ++in_use;
    }
    void release() {
        {
            std::lock_guard l{mu};
            if (in_use > 0) --in_use;
        }
        cv.notify_one();
    }
    // Worth parking for: past half the budget, or anyone waiting. Half, not
    // "nearly full": a thread that blocked before parking began keeps its
    // vCPU until it wakes, so at most half can ever be pinned that way and
    // the other half always circulates.
    [[nodiscard]] bool scarce() {
        std::lock_guard l{mu};
        init_locked();
        return waiting > 0 || in_use * 2 >= capacity;
    }
};
inline VcpuBudget g_vcpus;

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
    ~HvfCpu() { destroy(); }

    // Give the vCPU back while this thread blocks (see VcpuBudget): its
    // state is kept here and restored by unpark(), which may wait for a
    // slot. Only from the owning thread, outside hv_vcpu_run.
    void park() {
        if (!live_) return;
        parked_state_ = save();
        destroy();
    }
    // False only if the framework refuses a vCPU even with a slot held.
    [[nodiscard]] bool unpark() {
        if (live_ || !parked_state_) return live_;
        if (!create()) return false;
        // out of parked_state_ FIRST: while it is set, load() only edits the
        // kept copy (that is what makes load() safe on a parked thread)
        const CpuState s = std::move(*parked_state_);
        parked_state_.reset();
        restore_el1_ = true;     // the SAME thread coming back: all of it
        load(s);
        restore_el1_ = false;
        return true;
    }
    [[nodiscard]] bool parked() const noexcept { return parked_state_.has_value(); }

    // Bring this vCPU up in "Linux userspace" state: MMU on, EL0
    // unprivileged, our vector stub installed.
    [[nodiscard]] Status create() {
        g_vcpus.acquire();
        if (::hv_vcpu_create(&cpu_, &exit_, nullptr) != HV_SUCCESS) {
            g_vcpus.release();
            return err(Errno::enodev);
        }
        {
            std::lock_guard l{kick_mu_};
            live_ = true;
        }
        auto sr = [this](hv_sys_reg_t r, std::uint64_t v) {
            ::hv_vcpu_set_sys_reg(cpu_, r, v);
        };
        sr(HV_SYS_REG_VBAR_EL1, HvfLayout::vectors);
        sr(HV_SYS_REG_MAIR_EL1, 0xff);               // Attr0 = Normal WB
        // TCR_EL1: T0SZ = 64 - VA bits (a 4-level walk from L0) | Normal-WB
        // walks | inner shareable | 4 KiB granule | EPD1 | TBI0 (libc
        // pointer tagging) | IPS = the VM's IPA size.
        const unsigned va = g_va_bits.load(), ipa = g_ipa_bits.load();
        const std::uint64_t ips = ipa <= 32 ? 0 : ipa <= 36 ? 1 : ipa <= 40 ? 2
                                : ipa <= 42 ? 3 : ipa <= 44 ? 4 : 5;
        sr(HV_SYS_REG_TCR_EL1, (64ull - va) | (1ull << 8) | (1ull << 10)
                                     | (3ull << 12) | (1ull << 23)
                                     | (1ull << 37) | (ips << 32));
        sr(HV_SYS_REG_TTBR0_EL1, HvfLayout::l0_table);
        sr(HV_SYS_REG_CPACR_EL1, 3ull << 20);        // FP/SIMD usable at EL0
        // SCTLR_EL1: M | C | I (MMU + caches) | SA/SA0 | nTWI/nTWE | SPAN,
        // plus the RES1 bits. Caches ON matters: libc issues DC/IC
        // maintenance and relies on normal memory ordering.
        // UCT (15) and UCI (26), as Linux sets them: EL0 may read CTR_EL0
        // and clean/invalidate by VA (DC CVAU/CIVAC, IC IVAU). That is the
        // whole of __clear_cache, which every JIT runs after writing code
        // (Mesa's llvmpipe, V8, LuaJIT); without them `mrs x, ctr_el0`
        // trapped and the program died with SIGSEGV at the read.
        sr(HV_SYS_REG_SCTLR_EL1, 0x30d0199dull | (1ull << 15) | (1ull << 26));
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
    // The guest's page tables changed: drop its TLB before it runs again.
    // The stub's `tlbi vmalle1is` is inner-shareable, so ONE vCPU entering
    // it flushes every vCPU of the VM.
    void flush_tlb_on_entry() noexcept { flush_pending_ = true; }

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
        const bool detour = flush_pending_;
        std::uint64_t ticket = 0;
        if (flush_pending_) {
            ticket = g_flush_begun.fetch_add(1, std::memory_order_acq_rel) + 1;
            // Enter at EL1 on the flush stub, which erets to the guest's
            // real PC/PSTATE (parked in ELR_EL1/SPSR_EL1): its translations
            // are rebuilt from the edited tables before it runs one insn.
            flush_pending_ = false;
            std::uint64_t pc = 0, cpsr = 0;
            ::hv_vcpu_get_reg(cpu_, HV_REG_PC, &pc);
            ::hv_vcpu_get_reg(cpu_, HV_REG_CPSR, &cpsr);
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_ELR_EL1, pc);
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SPSR_EL1, cpsr);
            ::hv_vcpu_set_reg(cpu_, HV_REG_PC, HvfLayout::tlb_flush_stub);
            ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, 0x3c5);       // EL1h, DAIF masked
        }
        if (::hv_vcpu_run(cpu_) != HV_SUCCESS) return err<GuestRegs>(Errno::eio);
        if (exit_->reason != HV_EXIT_REASON_EXCEPTION) {
            unwind_el1(detour);
            if (ticket && !flush_pending_) flush_done(ticket);
            return err<GuestRegs>(Errno::eintr);
        }
        if (ticket) flush_done(ticket);    // any exception exit: the stub has run
        // Most exits arrive through the guest's EL1 vectors, which `hvc` out
        // with ESR_EL1/ELR_EL1 describing the EL0 event. A STAGE-2 abort does
        // not: the host refused the page behind guest RAM (a shared file
        // mapping touched past the file's end -- SIGBUS on Linux), and the
        // exception came straight to us with its own syndrome. Present it
        // as the guest data abort it is, so the trap reports a fault with a
        // real address instead of reading stale EL1 state (pc=0, "undefined
        // instruction").
        if (const std::uint64_t ec = exit_->exception.syndrome >> 26; ec == 0x24 || ec == 0x20) {
            GuestRegs r = read_regs(cpu_);
            ::hv_vcpu_get_reg(cpu_, HV_REG_PC, &r.elr);
            ::hv_vcpu_get_reg(cpu_, HV_REG_CPSR, &r.spsr);
            r.esr = exit_->exception.syndrome;
            stage2_far_ = exit_->exception.virtual_address;
            stage2_ipa_ = exit_->exception.physical_address;
            return ok(r);
        }
        stage2_far_.reset();
        return ok(read_regs(cpu_));
    }

    void set_result(const GuestRegs& r, std::int64_t ret) noexcept {
        write_return(cpu_, r, ret);
    }
    // The guest's EL0 stack pointer, cheaply (one register).
    [[nodiscard]] std::uint64_t sp_el0() const noexcept {
        std::uint64_t v = 0;
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_SP_EL0, &v);
        return v;
    }
    // Resume at the faulting instruction itself (a fault that was repaired:
    // a chunk populated, a stale entry rewritten). r.elr/r.spsr are the
    // EL0 context for both kinds of abort.
    void retry(const GuestRegs& r) noexcept {
        ::hv_vcpu_set_reg(cpu_, HV_REG_PC, r.elr);
        ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, r.spsr);
    }

    // FAR_EL1, fetched only when a caller actually needs it -- see the note
    // on read_regs(). Valid only for an abort.
    [[nodiscard]] std::uint64_t fault_address() const noexcept {
        if (stage2_far_) return *stage2_far_;
        return ::lx::runtime::fault_address(cpu_);
    }
    // The last fault was the HOST refusing guest-physical memory (stage 2),
    // not the guest's own tables: the IPA it touched.
    [[nodiscard]] std::optional<std::uint64_t> stage2_ipa() const noexcept {
        if (!stage2_far_) return std::nullopt;
        return stage2_ipa_;
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
        // EL1 context: a vCPU stopped inside one of our EL1 paths (the
        // in-guest syscall handler, a vector stub) resumes into it, and
        // that code relies on these. A rebuilt vCPU (VcpuBudget parking)
        // would otherwise wake with them zeroed.
        std::uint64_t sp_el1{}, elr_el1{}, spsr_el1{}, tpidr_el1{}, esr_el1{}, far_el1{};
        bool el1{false};   // carried (save() from a live vCPU); thread starts leave them
    };

    [[nodiscard]] CpuState save() const noexcept {
        if (parked_state_) return *parked_state_;   // parked: the kept state is the CPU
        CpuState s;
        for (unsigned i = 0; i < 31; ++i)
            ::hv_vcpu_get_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + i), &s.x[i]);
        ::hv_vcpu_get_reg(cpu_, HV_REG_PC, &s.pc);
        ::hv_vcpu_get_reg(cpu_, HV_REG_CPSR, &s.cpsr);
        ::hv_vcpu_get_reg(cpu_, HV_REG_FPCR, &s.fpcr);
        ::hv_vcpu_get_reg(cpu_, HV_REG_FPSR, &s.fpsr);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_SP_EL0, &s.sp_el0);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, &s.tpidr_el0);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_TPIDRRO_EL0, &s.tpidrro_el0);
        for (unsigned i = 0; i < 32; ++i)
            ::hv_vcpu_get_simd_fp_reg(
                cpu_, static_cast<hv_simd_fp_reg_t>(HV_SIMD_FP_REG_Q0 + i), &s.q[i]);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_SP_EL1, &s.sp_el1);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_ELR_EL1, &s.elr_el1);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_SPSR_EL1, &s.spsr_el1);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL1, &s.tpidr_el1);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_ESR_EL1, &s.esr_el1);
        ::hv_vcpu_get_sys_reg(cpu_, HV_SYS_REG_FAR_EL1, &s.far_el1);
        s.el1 = true;
        return s;
    }

    void load(const CpuState& s) noexcept {
        if (parked_state_) { *parked_state_ = s; return; }
        for (unsigned i = 0; i < 31; ++i)
            ::hv_vcpu_set_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + i), s.x[i]);
        ::hv_vcpu_set_reg(cpu_, HV_REG_PC, s.pc);
        ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, s.cpsr);
        ::hv_vcpu_set_reg(cpu_, HV_REG_FPCR, s.fpcr);
        ::hv_vcpu_set_reg(cpu_, HV_REG_FPSR, s.fpsr);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, s.sp_el0);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, s.tpidr_el0);
        ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDRRO_EL0, s.tpidrro_el0);
        for (unsigned i = 0; i < 32; ++i)
            ::hv_vcpu_set_simd_fp_reg(
                cpu_, static_cast<hv_simd_fp_reg_t>(HV_SIMD_FP_REG_Q0 + i), s.q[i]);
        if (s.el1 && restore_el1_) {
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL1, s.sp_el1);
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_ELR_EL1, s.elr_el1);
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SPSR_EL1, s.spsr_el1);
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL1, s.tpidr_el1);
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_ESR_EL1, s.esr_el1);
            ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_FAR_EL1, s.far_el1);
        }
    }

    [[nodiscard]] std::uint64_t sp() const noexcept { return sys(HV_SYS_REG_SP_EL0); }
    [[nodiscard]] std::uint64_t tls() const noexcept { return sys(HV_SYS_REG_TPIDR_EL0); }
    void set_sp(std::uint64_t v) noexcept { ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_SP_EL0, v); }
    void set_tls(std::uint64_t v) noexcept { ::hv_vcpu_set_sys_reg(cpu_, HV_SYS_REG_TPIDR_EL0, v); }
    void set_x(int i, std::uint64_t v) noexcept {
        ::hv_vcpu_set_reg(cpu_, static_cast<hv_reg_t>(HV_REG_X0 + static_cast<unsigned>(i)), v);
    }

    // Force this vCPU out of hv_vcpu_run from ANOTHER thread. The only
    // cross-thread operation the framework permits, and the basis of both
    // signal delivery and thread-group exit.
    void kick() noexcept {
        // signals blocked: a host signal's handler kicks too (kick_all), and
        // hv_vcpus_exit re-entered on one thread aborts the process
        ::sigset_t all, old;
        sigfillset(&all);
        ::pthread_sigmask(SIG_BLOCK, &all, &old);
        {
            std::lock_guard l{kick_mu_};   // not mid-park: a destroyed handle may be reused
            if (live_) {
                hv_vcpu_t v = cpu_;
                ::hv_vcpus_exit(&v, 1);
            }
        }
        ::pthread_sigmask(SIG_SETMASK, &old, nullptr);
    }

private:
    static void flush_done(std::uint64_t ticket) noexcept {
        std::uint64_t cur = g_flush_done.load(std::memory_order_relaxed);
        while (cur < ticket &&
               !g_flush_done.compare_exchange_weak(cur, ticket, std::memory_order_acq_rel)) {}
    }
    void destroy() noexcept {
        if (!live_) return;
        {
            std::lock_guard l{kick_mu_};
            live_ = false;
        }
        ::hv_vcpu_destroy(cpu_);
        g_vcpus.release();
    }
    // A kick (hv_vcpus_exit) can cancel the run while the vCPU is inside
    // one of OUR EL1 detours on the vectors page: the TLB-flush stub, the
    // in-guest syscall handler at VBAR+0x400, or a vector's `hvc` not yet
    // taken. Whoever handles the interruption -- a signal frame, a fork's
    // register snapshot, the next run's own flush detour -- reads PC/CPSR
    // as the GUEST's, so leave the vCPU there instead of mid-detour.
    // Otherwise a SIGALRM landing mid-handler saved pc=0x400 as the
    // interrupted context and sigreturn resumed EL0 at the vectors page
    // (SIGILL, "undefined instruction at pc=0x400"), and a second flush
    // detour parked the stub's own address in ELR_EL1 (pc=0x800).
    // Every unwind re-runs or completes work that has no side effect yet.
    void unwind_el1(bool detour) noexcept {
        std::uint64_t pc = 0, cpsr = 0;
        ::hv_vcpu_get_reg(cpu_, HV_REG_PC, &pc);
        ::hv_vcpu_get_reg(cpu_, HV_REG_CPSR, &cpsr);
        if ((cpsr & 0xc) == 0 || pc >= HvfLayout::page) return;   // at EL0
        std::uint64_t elr = sys(HV_SYS_REG_ELR_EL1);
        const std::uint64_t spsr = sys(HV_SYS_REG_SPSR_EL1);
        if (pc >= HvfLayout::tlb_flush_stub) {
            flush_pending_ = detour || flush_pending_;   // may not have run
        } else if (pc >= HvfLayout::vectors + 8 * 0x80 &&
                   pc < HvfLayout::vectors + 9 * 0x80) {
            const std::uint64_t entry = HvfLayout::vectors + 8 * 0x80;
            if ((sys(HV_SYS_REG_ESR_EL1) >> 26) == 0x15) {
                // An svc in the in-guest handler. At the eret the answer is
                // in x0 -- finish it; before, x0 is untouched and the svc
                // simply runs again (x16/x17 are scratch by the ABI).
                if (pc != entry + inguest::kEretOffset) elr -= 4;
            } else if (pc > entry) {
                // A fault on its way out: the handler parked the guest's x16
                // in TPIDR_EL1 and may have overwritten it since.
                ::hv_vcpu_set_reg(cpu_, HV_REG_X16, sys(HV_SYS_REG_TPIDR_EL1));
            }
        }
        // Any other vector: ELR is the faulting/next instruction already.
        ::hv_vcpu_set_reg(cpu_, HV_REG_PC, elr);
        ::hv_vcpu_set_reg(cpu_, HV_REG_CPSR, spsr);
    }

    [[nodiscard]] std::uint64_t sys(hv_sys_reg_t r) const noexcept {
        std::uint64_t v = 0;
        ::hv_vcpu_get_sys_reg(cpu_, r, &v);
        return v;
    }

    hv_vcpu_t cpu_{};
    hv_vcpu_exit_t* exit_{nullptr};
    bool live_{false};
    std::mutex kick_mu_;
    std::optional<CpuState> parked_state_;
    bool restore_el1_{false};
    bool flush_pending_{false};
    // FAR of the last stage-2 abort (run()); FAR_EL1 is stale for those.
    std::optional<std::uint64_t> stage2_far_;
    std::uint64_t stage2_ipa_{0};
};

} // namespace lx::runtime

#endif // __APPLE__ && __aarch64__
