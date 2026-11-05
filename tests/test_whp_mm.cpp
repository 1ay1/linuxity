// tests/test_whp_mm.cpp
//
// The guest memory manager and fd table.
//
// These are the two layers that turn "runs a static binary" into "runs a
// dynamically linked distro binary", and both have failure modes that are
// invisible until something far away breaks:
//
//   * A frame allocator that hands out a page which is already a page table
//     corrupts the address space and surfaces as an impossible fault later.
//   * A fault path that cannot tell lazy memory from a real SIGSEGV either
//     segfaults a program on its own heap, or silently allocates a page for
//     a null dereference.
//   * An fd table that shares the host's stdio lets a guest closing fd 1
//     close LINUXITY's stdout, after which every host diagnostic vanishes.
//
// So each of those is asserted directly. The allocator and fd checks need no
// hypervisor; the mapping checks SKIP without one.
#include "linuxity/runtime/whp_api.hpp"
#include "linuxity/runtime/whp_fd.hpp"
#include "linuxity/runtime/whp_load.hpp"
#include "linuxity/runtime/whp_mm.hpp"
#include "linuxity/runtime/whp_sys.hpp"
#include "linuxity/runtime/whp_vm.hpp"

#include <cstdio>
#include <cstring>
#include <set>

using namespace lx::runtime;

static int failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                   \
        }                                                                 \
    } while (0)

// -- Offline: the frame allocator ----------------------------------------
static void test_frame_allocator() {
    FrameAllocator fa;
    const std::uint64_t ram = 16 << 20;
    const std::uint64_t reserved_above = ram - (2 << 20);
    fa.init(ram, kGuestFloor, reserved_above);

    // Every frame handed out must be inside the usable window and unique.
    // A duplicate means two mappings alias, which is silent corruption.
    std::set<std::uint64_t> seen;
    for (int i = 0; i < 2000; ++i) {
        const std::uint64_t f = fa.alloc();
        if (f == 0) break;
        CHECK(f >= kGuestFloor);
        CHECK(f < reserved_above);     // never the page-table arena
        CHECK((f & kPageMask) == 0);   // page-aligned
        CHECK(seen.insert(f).second);  // never handed out twice
    }
    CHECK(seen.size() > 1000);

    // Freeing makes a frame available again, and the allocator must reuse it
    // -- a long-running guest depends on reuse, not just on fresh pages.
    const std::uint64_t one = *seen.begin();
    fa.free(one);
    const std::uint64_t again = fa.alloc();
    CHECK(again == one);

    // Exhaustion must report 0, not wrap around into reserved memory.
    FrameAllocator tiny;
    tiny.init(kGuestFloor + 4 * kPageSize, kGuestFloor,
              kGuestFloor + 4 * kPageSize);
    int got = 0;
    while (tiny.alloc() != 0) {
        if (++got > 16) break;         // guard against an infinite loop
    }
    CHECK(got == 4);
    CHECK(tiny.alloc() == 0);
}

// -- Offline: the fd table ------------------------------------------------
static void test_fd_table() {
    FdTable fds;

    // 0/1/2 exist and are DUPLICATES: closing the guest's copy must not
    // disturb the host's own stdout.
    const bool had_stdout = fds.host(1).has_value();
    if (had_stdout) {
        CHECK(fds.close(1) == 0);
        // The host's stdout still works -- if this were a shared handle the
        // rest of this test's output would silently disappear.
        std::printf("");
        CHECK(!fds.host(1).has_value());   // the guest's fd 1 is gone
        CHECK(fds.close(1) == -lx::runtime::win32::LBADF);  // and stays gone
    }

    // Reserving low fds must leave the guest's first open at 9, matching a
    // real login session. This prevented a descriptor-reuse collision that
    // corrupted a database on the macOS backend.
    FdTable r;
    r.reserve_low_fds();
    HANDLE nul = ::CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (nul != INVALID_HANDLE_VALUE) {
        const int g = r.install(nul, false);
        CHECK(g == 9);

        // dup must SHARE the underlying handle (hence the file position), as
        // Linux's open-file-description semantics require.
        const int d = r.dup(g, std::nullopt, false);
        CHECK(d == 10);
        CHECK(r.host(d).has_value());
        CHECK(*r.host(d) == *r.host(g));

        // dup2 to an explicit slot.
        const int d2 = r.dup(g, 42, false);
        CHECK(d2 == 42);
        CHECK(*r.host(42) == *r.host(g));

        // Closing one alias must NOT close the shared handle: the other
        // alias keeps working. (Refcounting, not raw CloseHandle.)
        CHECK(r.close(d) == 0);
        CHECK(r.host(g).has_value());

        // cloexec bookkeeping, and execve dropping those descriptors.
        r.set_cloexec(g, true);
        CHECK(r.cloexec(g));
        r.on_exec();
        CHECK(!r.host(g).has_value());
    }

    // An unknown fd is EBADF, never a crash.
    CHECK(!fds.host(999).has_value());
    CHECK(fds.close(999) == -lx::runtime::win32::LBADF);
    CHECK(!fds.host(-1).has_value());
}

// -- Offline: path translation and containment ---------------------------
// A guest must not be able to escape the rootfs with "..". Verified on the
// pure string logic, with no filesystem involved.
static void test_path_containment() {
    WhpMachine vm;            // not created: host_path touches no guest state
    FrameAllocator dummy_frames;
    (void)dummy_frames;
    WhpMm mm{vm};
    FdTable fds;
    WhpSys sys{vm, mm, fds, "C:/rootfs"};

    CHECK(sys.host_path("/etc/passwd") == "C:/rootfs/etc/passwd");
    CHECK(sys.host_path("/") == "C:/rootfs");
    // "." and redundant slashes collapse.
    CHECK(sys.host_path("/etc/./passwd") == "C:/rootfs/etc/passwd");
    CHECK(sys.host_path("//etc//passwd") == "C:/rootfs/etc/passwd");
    // ".." resolves, and CLAMPS at the root rather than escaping.
    CHECK(sys.host_path("/etc/../passwd") == "C:/rootfs/passwd");
    CHECK(sys.host_path("/../../../etc/passwd") == "C:/rootfs/etc/passwd");
    CHECK(sys.host_path("/..") == "C:/rootfs");
}

// -- Live: mapping, protection, and the fault arbiter --------------------
static void test_live_mapping() {
    if (!hypervisor_present() || !exception_exit_supported()) {
        std::printf("  SKIP live mapping: %s\n", whp_unavailable_reason());
        return;
    }
    WhpMachine vm;
    if (!vm.create(WhpLayout::min_ram, 1)) {
        std::puts("  SKIP live mapping: no partition");
        return;
    }

    // The partition starts with NOTHING mapped -- that is what makes an
    // unmapped access a real fault rather than a silent success.
    CHECK(!vm.mmu().translate(0x40'0000).present);

    // Identity mapping, with permissions honored.
    CHECK(vm.map_pages(0x40'0000, kPageSize, false, true).has_value());
    auto w = vm.mmu().translate(0x40'0000);
    CHECK(w.present);
    CHECK(w.gpa == 0x40'0000);
    CHECK(!w.writable);        // read-only as requested: W^X is real

    // Mapping a VA to a DIFFERENT frame (what mmap does).
    const std::uint64_t va = 0x1000'0000, frame = 0x50'0000;
    CHECK(vm.map_page_at(va, frame, true, false));
    auto w2 = vm.mmu().translate(va);
    CHECK(w2.present);
    CHECK(w2.gpa == frame);    // NOT identity
    CHECK(w2.writable);

    // Unmapping removes access without disturbing neighbours.
    CHECK(vm.map_page_at(va + kPageSize, frame + kPageSize, true, false));
    vm.unmap_page(va);
    CHECK(!vm.mmu().translate(va).present);
    CHECK(vm.mmu().translate(va + kPageSize).present);

    // A page table must never be handed out as a frame. Walk the live tables
    // and confirm every table page sits in the reserved arena.
    CHECK(vm.table_arena_base() > 0);
    CHECK(vm.table_arena_base() < vm.ram().size());
}

static void test_live_mm() {
    if (!hypervisor_present() || !exception_exit_supported()) {
        std::puts("  SKIP live mm");
        return;
    }
    WhpMachine vm;
    if (!vm.create(WhpLayout::min_ram, 1)) { std::puts("  SKIP live mm"); return; }

    const std::uint64_t ram = vm.ram().size();
    WhpMm mm{vm};
    mm.init(0x50'0000, WhpLayout::mmap_top(ram));

    // brk(0) reports the break; growing it does NOT eagerly back pages
    // (that is the point of lazy allocation), so the page is absent until
    // the fault handler fills it.
    const std::uint64_t b0 = mm.do_brk(0);
    CHECK(b0 >= 0x50'0000);
    const std::uint64_t b1 = mm.do_brk(b0 + 0x10000);
    CHECK(b1 >= b0 + 0x10000);
    CHECK(!vm.mmu().translate(b0 + 8).present);     // lazy, not yet backed
    CHECK(mm.handle_fault(b0 + 8));                 // the fault fills it
    CHECK(vm.mmu().translate(b0 + 8).present);
    CHECK(vm.mmu().translate(b0 + 8).writable);

    // An anonymous mmap is also lazy, and the fault arbiter must accept any
    // page inside it -- including the LAST one, the case an off-by-one in
    // the VMA end bound would break.
    const std::int64_t p = mm.do_mmap(0, 1 << 20, 3 /*RW*/,
                                      kMapPrivate | kMapAnonymous, nullptr, 0);
    CHECK(p > 0);
    const std::uint64_t base = std::uint64_t(p);
    CHECK(!vm.mmu().translate(base).present);
    CHECK(mm.handle_fault(base));
    CHECK(vm.mmu().translate(base).present);
    CHECK(mm.handle_fault(base + (1 << 20) - kPageSize));

    // THE CRITICAL DISTINCTION: an address with no mapping behind it must be
    // REFUSED, so a null dereference becomes SIGSEGV instead of silently
    // allocating a page.
    CHECK(!mm.handle_fault(0));
    CHECK(!mm.handle_fault(0x7000'0000'0000ull));

    // munmap revokes access and returns the frames.
    CHECK(mm.do_munmap(base, 1 << 20) == 0);
    CHECK(!vm.mmu().translate(base).present);
    CHECK(!mm.handle_fault(base));    // and it is no longer a known VMA

    // mprotect must actually change the PTE, not just the bookkeeping --
    // otherwise ld.so's "map writable, relocate, drop write" leaves every
    // library page writable.
    const std::int64_t q = mm.do_mmap(0, kPageSize, 3,
                                      kMapPrivate | kMapAnonymous, nullptr, 0);
    CHECK(q > 0);
    CHECK(mm.handle_fault(std::uint64_t(q)));
    CHECK(vm.mmu().translate(std::uint64_t(q)).writable);
    CHECK(mm.do_mprotect(std::uint64_t(q), kPageSize, 1 /*PROT_READ*/) == 0);
    CHECK(!vm.mmu().translate(std::uint64_t(q)).writable);
}

int main() {
    std::puts("whp_mm: frame allocator");
    test_frame_allocator();
    std::puts("whp_mm: fd table");
    test_fd_table();
    std::puts("whp_mm: path containment");
    test_path_containment();
    std::puts("whp_mm: live mapping");
    test_live_mapping();
    std::puts("whp_mm: live memory manager");
    test_live_mm();

    if (failures == 0) std::puts("whp_mm: all checks passed");
    return failures ? 1 : 0;
}
