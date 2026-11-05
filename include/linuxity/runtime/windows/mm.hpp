// linuxity/runtime/windows/mm.hpp
//
// The guest's memory syscalls: mmap, munmap, mprotect, brk, mremap.
//
// On the ptrace backend these forward to the host kernel, which owns the
// guest's address space. Here there IS no host kernel for the guest: we own
// its address space, so we must implement them.
//
// Three pieces, and the split matters:
//
//   FrameAllocator  guest-PHYSICAL page allocation. A bitmap over the RAM we
//                   got from WHvMapGpaRange. This is the "physical memory" a
//                   real kernel's buddy allocator hands out.
//   VmaMap          guest-VIRTUAL bookkeeping (runtime/shared/address_space.hpp, shared
//                   with the macOS backend because the semantics are
//                   identical -- that header is deliberately host-agnostic).
//   WhpMm           glues them: pick a VA, allocate frames, install PTEs.
//
// WHY NOT IDENTITY-MAP EVERYTHING. The loader identity-maps (GVA == GPA)
// because an ELF's p_vaddr is fixed and it keeps image loading trivial. But
// mmap cannot: a guest asking for 1 GiB of anonymous memory on a 256 MiB
// guest must get it ONLY if it actually touches less than that, and Linux's
// overcommit means `malloc(1GB)` succeeding is normal. So mmap allocates
// frames LAZILY -- the VMA is recorded and PTEs are installed on demand when
// the guest faults. That is what makes a real glibc work: it maps large
// arenas and touches a fraction.
//
// THE FAULT PATH IS THEREFORE LOAD-BEARING. A WHvRunVpExitReasonMemoryAccess
// exit inside a known VMA is a soft fault to be filled, not a SIGSEGV. Only
// an access with no VMA behind it is a real fault. Conflating the two gives
// you either a guest that segfaults on its own heap, or one where a genuine
// null dereference silently allocates a page.
#pragma once

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))

#include "linuxity/abi/wire/mmap.hpp"
#include "linuxity/abi/result.hpp"
#include "linuxity/runtime/shared/address_space.hpp"
#include "linuxity/runtime/windows/mem.hpp"
#include "linuxity/runtime/windows/vm.hpp"
#include "linuxity/runtime/windows/win32.hpp"

#include <algorithm>
#include <cstdint>
#include <vector>

namespace lx::runtime {

// Linux mmap flags. Defined ONCE in abi/wire/mmap.hpp -- these were spread
// over this file, win32.hpp and an inline redeclaration in darwin/trap.hpp.
// The names stay so call sites read unchanged.
inline constexpr std::uint64_t kMapShared    = abi::wire::bits(abi::wire::MapFlag::shared);
inline constexpr std::uint64_t kMapPrivate   = abi::wire::bits(abi::wire::MapFlag::priv);
inline constexpr std::uint64_t kMapFixed     = abi::wire::bits(abi::wire::MapFlag::fixed);
inline constexpr std::uint64_t kMapAnonymous = abi::wire::bits(abi::wire::MapFlag::anonymous);
inline constexpr std::uint64_t kMapNoReserve = abi::wire::bits(abi::wire::MapFlag::noreserve);
inline constexpr std::uint64_t kMapStack     = abi::wire::bits(abi::wire::MapFlag::stack);

// -- Guest physical frame allocator ---------------------------------------
// A bitmap over the pages of guest RAM. Simple and deliberately so: the
// interesting correctness lives in the VMA map above it, and a bitmap makes
// "is this frame free" answerable without walking anything.
class FrameAllocator {
public:
    void init(std::uint64_t ram_bytes, std::uint64_t reserved_below,
              std::uint64_t reserved_above) {
        pages_ = ram_bytes >> kPageShift;
        bits_.assign((pages_ + 63) / 64, 0);
        // Everything below the guest floor (page tables, GDT) and above the
        // table arena is permanently taken.
        reserve_range(0, reserved_below);
        if (reserved_above < ram_bytes)
            reserve_range(reserved_above, ram_bytes);
        low_hint_ = reserved_below >> kPageShift;
    }

    // Mark [beg, end) as in use, so the loader's identity-mapped image is
    // never handed out again by mmap.
    void reserve_range(std::uint64_t beg, std::uint64_t end) {
        for (std::uint64_t p = beg >> kPageShift;
             p < ((end + kPageMask) >> kPageShift) && p < pages_; ++p)
            set(p);
    }

    // One free frame, or 0 (which is never a valid guest frame here, since
    // the page tables live at gpa 0).
    [[nodiscard]] std::uint64_t alloc() {
        for (std::uint64_t p = low_hint_; p < pages_; ++p)
            if (!test(p)) { set(p); low_hint_ = p + 1; return p << kPageShift; }
        // Wrap: a long-running guest frees and reallocates, so starting over
        // from the floor is required, not optional.
        for (std::uint64_t p = 0; p < low_hint_ && p < pages_; ++p)
            if (!test(p)) { set(p); return p << kPageShift; }
        return 0;
    }

    void free(std::uint64_t gpa) {
        const std::uint64_t p = gpa >> kPageShift;
        if (p < pages_) {
            clear(p);
            if (p < low_hint_) low_hint_ = p;
        }
    }

    [[nodiscard]] std::uint64_t free_pages() const noexcept {
        std::uint64_t n = 0;
        for (std::uint64_t p = 0; p < pages_; ++p) if (!test(p)) ++n;
        return n;
    }
    [[nodiscard]] std::uint64_t total_pages() const noexcept { return pages_; }

private:
    void set(std::uint64_t p)   { bits_[p >> 6] |=  (1ull << (p & 63)); }
    void clear(std::uint64_t p) { bits_[p >> 6] &= ~(1ull << (p & 63)); }
    [[nodiscard]] bool test(std::uint64_t p) const {
        return (bits_[p >> 6] >> (p & 63)) & 1;
    }

    std::uint64_t pages_{0};
    std::uint64_t low_hint_{0};
    std::vector<std::uint64_t> bits_;
};

// -- The memory manager ---------------------------------------------------
class WhpMm {
public:
    WhpMm(WhpMachine& vm) noexcept : vm_{vm} {}

    // `image_end` is where the program image stops: brk starts there, and the
    // mmap arena is placed above it but below the stack.
    void init(std::uint64_t image_end, std::uint64_t mmap_top) {
        const std::uint64_t ram = vm_.ram().size();
        frames_.init(ram, kGuestFloor, vm_.table_arena_base());
        // The loader's image is identity-mapped, so those frames are taken.
        frames_.reserve_range(0, image_end);

        // AddressSpace owns ALL the virtual bookkeeping: brk growth (with
        // the ceiling_above subtlety that keeps malloc from falling back to
        // mmap for everything), top-down gap placement, and the VMA
        // splitting that munmap of a range's middle requires. We deliberately
        // do not reimplement any of it -- this class only adds the physical
        // half (frames + PTEs) that the macOS backend gets from hv_vm_map.
        space_.reset((image_end + kPageMask) & ~kPageMask, mmap_top & ~kPageMask);
        brk_floor_ = (image_end + kPageMask) & ~kPageMask;
    }

    // Record a region the LOADER mapped, not us (ELF segments, the startup
    // stack). It must appear in the VMA map even though it sits below the
    // mmap arena, because the guest will call mprotect and munmap on it.
    //
    // This is not bookkeeping for its own sake. ld.so maps each shared
    // object writable, applies relocations, then mprotects .text and .rodata
    // read-only -- and AddressSpace::protect refuses a range that is not
    // fully covered by VMAs. Without adoption that mprotect fails with
    // ENOMEM and glibc aborts with "cannot apply additional memory
    // protection after relocation", which is a confusing way to be told the
    // VMA map has a hole in it.
    void adopt(std::uint64_t begin, std::uint64_t end, GuestProt prot,
               bool anonymous) {
        if (end <= begin) return;
        space_.adopt(Vma{begin & ~kPageMask, (end + kPageMask) & ~kPageMask,
                         prot, anonymous});
    }

    [[nodiscard]] std::uint64_t brk_current() const noexcept { return space_.brk(); }
    [[nodiscard]] const AddressSpace& space() const noexcept { return space_; }
    [[nodiscard]] FrameAllocator& frames() noexcept { return frames_; }

    // -- brk(2) ------------------------------------------------------------
    // brk(0) reports the break; brk(addr) moves it. glibc's malloc uses brk
    // for small allocations, so this is on the path of every program.
    //
    // Growth is LAZY: AddressSpace records the new break and the pages are
    // backed on first touch. Eagerly allocating here would make a program
    // that grows its heap by 64 MiB and uses 8 KiB fail on a small guest.
    [[nodiscard]] std::uint64_t do_brk(std::uint64_t addr) {
        const std::uint64_t before = space_.brk();
        const std::uint64_t now = space_.set_brk(addr);
        if (now < before) {
            // Shrinking: hand the frames back.
            unmap_range(page_up(now), page_up(before) - page_up(now));
        }
        return now;
    }

    // -- mmap(2) -----------------------------------------------------------
    // Anonymous and file-backed private mappings. Returns a guest address or
    // a negative errno.
    //
    // File-backed mappings are populated EAGERLY by reading the file, because
    // we have no page cache to fault against -- ld.so mmaps each shared
    // object's segments, so this is the path that makes dynamic linking work.
    // Anonymous mappings stay lazy (overcommit), which is what lets a real
    // glibc map large arenas on a small guest.
    [[nodiscard]] std::int64_t do_mmap(std::uint64_t addr, std::uint64_t len,
                                       std::uint64_t prot, std::uint64_t flags,
                                       HANDLE file, std::uint64_t offset) {
        if (len == 0) return -win32::LINVAL;
        const GuestProt gp = prot_from_linux(prot);
        const bool fixed = (flags & kMapFixed) != 0;
        const bool anon = (flags & kMapAnonymous) != 0 || file == nullptr;

        if (fixed) unmap_range(page_down(addr), page_up(len));

        const std::uint64_t at = space_.map(addr, len, gp, fixed, anon);
        if (at == AddressSpace::kFail) return -win32::LNOMEM;
        len = page_up(len);

        if (!anon) {
            // Back it now and fill from the file. Mapped writable first
            // because we are about to write it, then dropped to the
            // requested protection -- the same two-phase trick the ELF
            // loader uses, and for the same reason.
            if (!back_range(at, len, /*writable=*/true, has(gp, GuestProt::exec))) {
                space_.unmap(at, len);
                return -win32::LNOMEM;
            }
            if (!fill_from_file(at, len, file, offset)) {
                unmap_range(at, len);
                space_.unmap(at, len);
                return -win32::LIO;
            }
            if (!has(gp, GuestProt::write))
                (void)reprotect(at, len, false, has(gp, GuestProt::exec));
        }
        return std::int64_t(at);
    }

    // -- munmap(2) ---------------------------------------------------------
    [[nodiscard]] std::int64_t do_munmap(std::uint64_t addr, std::uint64_t len) {
        if (len == 0 || (addr & kPageMask)) return -win32::LINVAL;
        len = page_up(len);
        unmap_range(addr, len);
        space_.unmap(addr, len);
        return 0;
    }

    // -- mprotect(2) -------------------------------------------------------
    // ld.so calls this on every shared object: it maps the image writable,
    // applies relocations, then drops write on .text and .rodata. A no-op
    // mprotect would leave every library page writable -- the W^X hole again,
    // this time in the dynamic path.
    [[nodiscard]] std::int64_t do_mprotect(std::uint64_t addr, std::uint64_t len,
                                           std::uint64_t prot) {
        if (addr & kPageMask) return -win32::LINVAL;
        len = page_up(len);
        const GuestProt gp = prot_from_linux(prot);
        if (!space_.protect(addr, len, gp)) return -win32::LNOMEM;
        if (!reprotect(addr, len, has(gp, GuestProt::write),
                       has(gp, GuestProt::exec)))
            return -win32::LNOMEM;
        return 0;
    }

    // -- The soft-fault path ----------------------------------------------
    // A memory-access exit inside a known VMA is a page we promised but have
    // not backed yet (lazy anonymous memory, or a lazily grown brk). Fill it
    // and resume. Returns false if there is no VMA behind it -- a genuine
    // SIGSEGV.
    //
    // Conflating these two is the bug that gives you either a guest that
    // segfaults on its own heap, or one where a null dereference silently
    // allocates a page. So the VMA lookup is the sole arbiter.
    [[nodiscard]] bool handle_fault(std::uint64_t gva) {
        const std::uint64_t page = page_down(gva);
        GuestProt gp;
        if (const Vma* v = space_.find(page)) {
            gp = v->prot;
        } else if (is_in_brk(page)) {
            // Inside the lazily grown heap, which AddressSpace tracks as a
            // break VALUE rather than a VMA -- so it needs its own arm here.
            gp = GuestProt(unsigned(GuestProt::read) | unsigned(GuestProt::write));
        } else {
            return false;   // no mapping behind it: a genuine SIGSEGV
        }
        return back_range(page, kPageSize, has(gp, GuestProt::write),
                          has(gp, GuestProt::exec));
    }

    // Report free guest memory, for /proc/meminfo and sysinfo(2).
    [[nodiscard]] std::uint64_t free_bytes() const noexcept {
        return frames_.free_pages() << kPageShift;
    }

private:
    [[nodiscard]] static std::uint64_t page_up(std::uint64_t a) noexcept {
        return (a + kPageMask) & ~kPageMask;
    }
    [[nodiscard]] static std::uint64_t page_down(std::uint64_t a) noexcept {
        return a & ~kPageMask;
    }

    // Is `page` inside the heap -- i.e. at or above the heap floor and below
    // the current break? Both bounds matter: without the lower one, every
    // unmapped address below the heap would look like a heap page and a null
    // dereference would silently allocate instead of faulting.
    [[nodiscard]] bool is_in_brk(std::uint64_t page) const noexcept {
        return page >= brk_floor_ && page < page_up(space_.brk());
    }

    // Back [base, base+len) with fresh frames and install PTEs. Frames are
    // zeroed, because a guest must never see another mapping's bytes -- that
    // is both an information leak and a source of nondeterminism.
    [[nodiscard]] bool back_range(std::uint64_t base, std::uint64_t len,
                                  bool writable, bool executable) {
        for (std::uint64_t off = 0; off < len; off += kPageSize) {
            const std::uint64_t gva = base + off;
            if (vm_.mmu().translate(gva).present) continue;   // already backed
            const std::uint64_t frame = frames_.alloc();
            if (frame == 0) return false;
            if (auto z = vm_.ram().at_table(frame, kPageSize); !z.empty())
                std::memset(z.data(), 0, kPageSize);
            if (!vm_.map_page_at(gva, frame, writable, executable)) {
                frames_.free(frame);
                return false;
            }
        }
        return true;
    }

    void unmap_range(std::uint64_t base, std::uint64_t len) {
        for (std::uint64_t off = 0; off < len; off += kPageSize) {
            const std::uint64_t gva = base + off;
            const auto w = vm_.mmu().translate(gva);
            if (!w.present) continue;
            // Never recycle a frame belonging to the identity-mapped image:
            // those were reserved at init and are not ours to hand out.
            if (w.gpa != gva) frames_.free(w.gpa);
            vm_.unmap_page(gva);
        }
    }

    [[nodiscard]] bool reprotect(std::uint64_t base, std::uint64_t len,
                                 bool writable, bool executable) {
        for (std::uint64_t off = 0; off < len; off += kPageSize) {
            const std::uint64_t gva = base + off;
            const auto w = vm_.mmu().translate(gva);
            if (!w.present) continue;   // unbacked; prot lives in the VMA
            if (!vm_.map_page_at(gva, w.gpa, writable, executable)) return false;
        }
        return true;
    }

    [[nodiscard]] bool fill_from_file(std::uint64_t base, std::uint64_t len,
                                      HANDLE file, std::uint64_t offset) {
        LARGE_INTEGER pos{};
        pos.QuadPart = LONGLONG(offset);
        if (!::SetFilePointerEx(file, pos, nullptr, FILE_BEGIN)) return false;
        for (std::uint64_t off = 0; off < len; off += kPageSize) {
            auto win = vm_.mem().at(base + off, kPageSize);
            if (win.empty()) continue;
            DWORD got = 0;
            if (!::ReadFile(file, win.data(), DWORD(win.size()), &got, nullptr))
                return false;
            if (got == 0) break;        // EOF: the rest stays zero
        }
        return true;
    }

    WhpMachine& vm_;
    FrameAllocator frames_;
    AddressSpace space_;
    std::uint64_t brk_floor_{0};
};

} // namespace lx::runtime

#endif // _WIN32 && x86-64
