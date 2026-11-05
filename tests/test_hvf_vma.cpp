// tests/test_hvf_vma.cpp
//
// The guest address-space interval map. Pure logic -- no hypervisor, no
// Darwin, no Windows -- so it runs on EVERY host, and both kernel-less
// backends (HVF, WHP) depend on exactly these semantics.
#include "linuxity/runtime/hvf_vma.hpp"

#include <cstdio>
#include <cstdlib>

using namespace lx::runtime;

static int failures = 0;
#define CHECK(cond)                                                            \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

constexpr std::uint64_t kPage = AddressSpace::kPageSize;

int main() {
    // -- placement is top-down, and successive maps stack downward ---------
    {
        AddressSpace as;
        as.reset(0x100000, 0x200000);
        auto a = as.map(0, kPage, GuestProt::read, false, true);
        auto b = as.map(0, kPage, GuestProt::read, false, true);
        CHECK(a == 0x200000 - kPage);
        CHECK(b == a - kPage);
        CHECK(as.mapped_bytes() == 2 * kPage);
        // Adjacent, same prot => coalesced into ONE vma.
        CHECK(as.vmas().size() == 1);
    }

    // -- the bug a flat map has: unmapping the MIDDLE must split -----------
    {
        AddressSpace as;
        as.reset(0x100000, 0x400000);
        auto base = as.map(0, 8 * kPage, GuestProt::read | GuestProt::write,
                           false, true);
        CHECK(base != AddressSpace::kFail);
        as.unmap(base + 2 * kPage, 2 * kPage);          // punch a hole
        CHECK(as.vmas().size() == 2);
        CHECK(as.mapped_bytes() == 6 * kPage);
        CHECK(as.find(base) != nullptr);
        CHECK(as.find(base + 2 * kPage) == nullptr);    // the hole
        CHECK(as.find(base + 4 * kPage) != nullptr);
        // And the freed hole is REUSED, not leaked.
        auto reuse = as.map(0, 2 * kPage, GuestProt::read, false, true);
        CHECK(reuse == base + 2 * kPage);
    }

    // -- mprotect of a sub-range splits into three ------------------------
    {
        AddressSpace as;
        as.reset(0x100000, 0x400000);
        auto base = as.map(0, 6 * kPage, GuestProt::read | GuestProt::write,
                           false, true);
        CHECK(as.protect(base + 2 * kPage, 2 * kPage, GuestProt::read));
        CHECK(as.vmas().size() == 3);
        CHECK(as.find(base)->prot == (GuestProt::read | GuestProt::write));
        CHECK(as.find(base + 2 * kPage)->prot == GuestProt::read);
        CHECK(as.find(base + 4 * kPage)->prot == (GuestProt::read | GuestProt::write));
        // Re-protecting back to the original merges them again.
        CHECK(as.protect(base + 2 * kPage, 2 * kPage,
                         GuestProt::read | GuestProt::write));
        CHECK(as.vmas().size() == 1);
        // mprotect across a hole is ENOMEM (false), not silent success.
        as.unmap(base + 2 * kPage, kPage);
        CHECK(!as.protect(base, 6 * kPage, GuestProt::read));
    }

    // -- MAP_FIXED clobbers whatever was there ----------------------------
    {
        AddressSpace as;
        as.reset(0x100000, 0x400000);
        std::uint64_t want = 0x200000;
        auto a = as.map(want, 4 * kPage, GuestProt::read, true, true);
        CHECK(a == want);
        auto b = as.map(want + kPage, kPage, GuestProt::exec, true, true);
        CHECK(b == want + kPage);
        CHECK(as.find(want + kPage)->prot == GuestProt::exec);
        CHECK(as.mapped_bytes() == 4 * kPage);     // clobbered, not doubled
        // Fixed outside the arena fails rather than corrupting the map.
        CHECK(as.map(0x900000, kPage, GuestProt::read, true, true)
              == AddressSpace::kFail);
    }

    // -- brk grows up and stops at the lowest mapping ---------------------
    {
        AddressSpace as;
        as.reset(0x100000, 0x400000);
        CHECK(as.brk() == 0x100000);
        CHECK(as.set_brk(0x110000) == 0x110000);
        CHECK(as.set_brk(0) == 0x110000);              // query
        CHECK(as.set_brk(0x100) == 0x110000);          // below floor: refused
        auto m = as.map(0, kPage, GuestProt::read, false, true);
        CHECK(as.set_brk(m + kPage) == 0x110000);      // would collide
    }

    // -- exhaustion is reported, and recovers after unmap -----------------
    {
        AddressSpace as;
        as.reset(0x100000, 0x100000 + 4 * kPage);
        auto a = as.map(0, 4 * kPage, GuestProt::read, false, true);
        CHECK(a != AddressSpace::kFail);
        CHECK(as.map(0, kPage, GuestProt::read, false, true) == AddressSpace::kFail);
        as.unmap(a, kPage);
        CHECK(as.map(0, kPage, GuestProt::read, false, true) == a);
    }

    // -- churn: 2000 map/unmap cycles must not leak address space ---------
    {
        AddressSpace as;
        as.reset(0x100000, 0x100000 + 256 * kPage);
        for (int i = 0; i < 2000; ++i) {
            auto p = as.map(0, 3 * kPage, GuestProt::read | GuestProt::write,
                            false, true);
            CHECK(p != AddressSpace::kFail);
            if (p == AddressSpace::kFail) break;
            as.unmap(p + kPage, kPage);        // partial: the hard case
            as.unmap(p, kPage);
            as.unmap(p + 2 * kPage, kPage);
        }
        CHECK(as.mapped_bytes() == 0);
        CHECK(as.vmas().empty());
    }

    if (failures == 0) std::puts("hvf_vma: all checks passed");
    return failures ? 1 : 0;
}
